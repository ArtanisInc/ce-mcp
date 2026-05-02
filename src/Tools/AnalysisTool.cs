using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using CEMCP;
using CESDK.Classes;
using CESDK.Utils;
using ModelContextProtocol.Server;

namespace Tools
{
    [McpServerToolType]
    public class AnalysisTool
    {
        private const int MaxReadBytes = 65536;
        private const int MaxStringLength = 65536;
        private const int MaxPointerChainDepth = 32;
        private const int MaxReferenceResults = 5000;

        private AnalysisTool() { }

        [
            McpServerTool(Name = "read_pointer_chain"),
            Description(
                "Resolve a pointer chain (base + deref + offsets). Returns the value at the final address (supports bytes, integers, floats, doubles, and strings)."
            )
        ]
        public static object ReadPointerChain(
            [Description("Base address expression (e.g. 'module+0x123', '0x7FF...', symbol)")]
                string baseAddress,
            [Description("Offsets as comma/space-separated hex/dec (e.g. '0x10,0x20,0x8')")]
                string offsets,
            [Description(
                "Final read type: 'address', 'pointer', 'bytes', 'int32', 'int64', 'float', 'double', 'string'"
            )]
                string finalReadType = "address",
            [Description("Number of bytes to read if finalReadType is 'bytes'")]
                string? byteCount = null,
            [Description("Maximum length of string to read if finalReadType is 'string'")]
                string? maxLength = null,
            [Description("Whether the string is UTF-16/Wide (true/false)")]
                string wideChar = "false"
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (!ValidationHelper.IsProcessAttached())
                        return new { success = false, error = "No process is currently opened. Use openProcess() first." };

                    if (string.IsNullOrWhiteSpace(baseAddress))
                        return new { success = false, error = "baseAddress is required" };

                    if (!ValidationHelper.TryResolveAddress(baseAddress, out var current))
                        return new { success = false, error = "Unable to resolve baseAddress" };

                    var resolvedBase = current;

                    var offsetList = ParseOffsets(offsets);
                    if (offsetList.Count > MaxPointerChainDepth)
                    {
                        return new
                        {
                            success = false,
                            error = $"Pointer chain too deep (max {MaxPointerChainDepth})",
                        };
                    }

                    var steps = new List<object>(offsetList.Count);

                    foreach (var offset in offsetList)
                    {
                        var pointerValue = MemoryAccess.ReadPointer(current);
                        var next = checked(pointerValue + offset);
                        steps.Add(
                            new
                            {
                                address = $"0x{current:X}",
                                pointer = $"0x{pointerValue:X}",
                                offset = $"0x{offset:X}",
                                next = $"0x{next:X}",
                            }
                        );
                        current = next;
                    }

                    var readType = finalReadType.Trim().ToLowerInvariant();
                    object? value = readType switch
                    {
                        "address" => null,
                        "pointer" => $"0x{MemoryAccess.ReadPointer(current):X}",
                        "bytes" => ReadBytes(current, byteCount),
                        "int32" or "integer" or "int" => MemoryAccess.ReadInteger(current),
                        "int64" or "qword" or "long" => MemoryAccess.ReadQword(current),
                        "float" => MemoryAccess.ReadFloat(current),
                        "double" => MemoryAccess.ReadDouble(current),
                        "string" => ReadString(current, maxLength, wideChar),
                        _ => throw new NotSupportedException(
                            $"Unsupported finalReadType: {finalReadType}"
                        ),
                    };

                    return new
                    {
                        success = true,
                        baseAddress = baseAddress,
                        resolvedBaseAddress = $"0x{resolvedBase:X}",
                        steps,
                        finalAddress = $"0x{current:X}",
                        finalReadType = readType,
                        value,
                    };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "generate_signature"),
            Description(
                "Generate an exact bounded AOB signature for an address. The returned signature is not globally unique unless 'uniqueVerified' is true."
            )
        ]
        public static object GenerateSignature(
            [Description("Address expression to generate signature for")] string address
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (!ValidationHelper.IsProcessAttached())
                        return new { success = false, error = "No process is currently opened. Use openProcess() first." };

                    if (!ValidationHelper.TryResolveAddress(address, out var addr))
                        return new { success = false, error = "Unable to resolve address" };

                    var signature = TryGenerateBoundedExactSignature(addr);
                    if (signature is null)
                    {
                        return new
                        {
                            success = true,
                            found = false,
                            address = $"0x{addr:X}",
                            signature = (string?)null,
                            offset = 0,
                        };
                    }

                    return new
                    {
                        success = true,
                        found = true,
                        address = $"0x{addr:X}",
                        signature,
                        offset = 0,
                        method = "bounded_exact_aob",
                        uniqueVerified = false,
                        warning = "Generated from local bytes only; uniqueness was not verified.",
                    };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "get_rtti_classname"),
            Description("Retrieve the RTTI (Runtime Type Information) class name for a C++ object address.")
        ]
        public static object GetRttiClassname(
            [Description("Address expression pointing to a C++ object (usually its vtable or the instance itself)")] string address
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (!ValidationHelper.IsProcessAttached())
                        return new { success = false, error = "No process is currently opened. Use openProcess() first." };

                    if (!ValidationHelper.TryResolveAddress(address, out var addr))
                        return new { success = false, error = "Unable to resolve address" };

                    var className = MemoryAccess.GetRTTIClassName(addr);
                    if (string.IsNullOrEmpty(className))
                    {
                        return new
                        {
                            success = true,
                            found = false,
                            address = $"0x{addr:X}",
                            className = (string?)null,
                        };
                    }

                    return new
                    {
                        success = true,
                        address = $"0x{addr:X}",
                        found = true,
                        className,
                    };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "find_call_references"),
            Description(
                "Scans for CALL rel32 instructions (E8) that target the given address. Useful for finding what code calls a specific function."
            )
        ]
        public static object FindCallReferences(
            [Description("Target address expression (e.g. '0x...', 'module+0x123', symbol)")]
                string targetAddress,
            [Description("Start address for scan (default: 0)")] string startAddress = "0",
            [Description("Stop address for scan (default: FFFFFFFFFFFFFFFF)")]
                string stopAddress = "FFFFFFFFFFFFFFFF",
            [Description("Protection flags (default: +X to scan executable memory)")]
                string protectionFlags = "+X",
            [Description("Maximum number of results to return (max 5000)")] int maxResults = 2000
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (!ValidationHelper.IsProcessAttached())
                        return new { success = false, error = "No process is currently opened. Use openProcess() first." };

                    if (string.IsNullOrWhiteSpace(targetAddress))
                        return new { success = false, error = "targetAddress is required" };

                    if (!ValidationHelper.TryResolveAddress(targetAddress, out var target))
                        return new { success = false, error = "Unable to resolve targetAddress" };

                    if (!ValidationHelper.TryResolveAddress(startAddress, out var start))
                        return new { success = false, error = "Unable to resolve startAddress" };
                    if (!ValidationHelper.TryResolveAddress(stopAddress, out var stop))
                        return new { success = false, error = "Unable to resolve stopAddress" };

                    if (start > stop)
                        (start, stop) = (stop, start);

                    if (maxResults <= 0)
                        maxResults = 1;
                    if (maxResults > MaxReferenceResults)
                        maxResults = MaxReferenceResults;

                    var candidates = ScanAobWithinRequestedRange(
                        "E8 ?? ?? ?? ??",
                        start,
                        stop,
                        protectionFlags,
                        0,
                        string.Empty
                    );

                    var indirectCandidates = ScanAobWithinRequestedRange(
                        "FF 15 ?? ?? ?? ??",
                        start,
                        stop,
                        protectionFlags,
                        0,
                        string.Empty
                    );

                    var results = new List<object>(Math.Min(maxResults, 128));

                    foreach (var callSite in candidates)
                    {
                        if (callSite < start || callSite > stop)
                            continue;

                        try
                        {
                            // rel32 is signed and is relative to the next instruction (callSite + 5)
                            var rel = MemoryAccess.ReadInteger(checked(callSite + 1));
                            if (!TryComputeSignedTarget(callSite, 5, rel, out var dest))
                                continue;
                            if (dest != target)
                                continue;

                            results.Add(
                                new
                                {
                                    kind = "rel32",
                                    callSite = $"0x{callSite:X}",
                                    target = $"0x{target:X}",
                                }
                            );

                            if (results.Count >= maxResults)
                                break;
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Debug.WriteLine(ex);
                            continue;
                        }
                    }

                    // Indirect call patterns.
                    // FF 15 disp32: x64 CALL qword ptr [RIP+disp32]
                    // FF 15 imm32:  x86 CALL dword ptr [imm32]
                    foreach (var callSite in indirectCandidates)
                    {
                        if (results.Count >= maxResults)
                            break;

                        if (callSite < start || callSite > stop)
                            continue;

                        try
                        {
                            var imm = MemoryAccess.ReadInteger(checked(callSite + 2));

                            // Try x64 RIP-relative form: pointer address is relative to the next instruction (callSite + 6)
                            if (TryComputeSignedTarget(callSite, 6, imm, out var pointerAddrRip))
                            {
                                try
                                {
                                    var ptr = MemoryAccess.ReadPointer(pointerAddrRip);
                                    if (ptr == target)
                                    {
                                        results.Add(
                                            new
                                            {
                                                kind = "indirect",
                                                via = "rip",
                                                callSite = $"0x{callSite:X}",
                                                pointerAddress = $"0x{pointerAddrRip:X}",
                                                target = $"0x{target:X}",
                                            }
                                        );
                                        continue;
                                    }
                                }
                                catch (Exception ex)
                                {
                                    System.Diagnostics.Debug.WriteLine(ex);
                                }
                            }

                            // Try x86 absolute form: pointer address is the imm32 value (treated as unsigned)
                            var pointerAddrAbs = unchecked((ulong)(uint)imm);
                            try
                            {
                                var ptr = MemoryAccess.ReadPointer(pointerAddrAbs);
                                if (ptr == target)
                                {
                                    results.Add(
                                        new
                                        {
                                            kind = "indirect",
                                            via = "abs32",
                                            callSite = $"0x{callSite:X}",
                                            pointerAddress = $"0x{pointerAddrAbs:X}",
                                            target = $"0x{target:X}",
                                        }
                                    );
                                }
                            }
                            catch (Exception ex)
                            {
                                System.Diagnostics.Debug.WriteLine(ex);
                            }
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Debug.WriteLine(ex);
                        }
                    }

                    return new
                    {
                        success = true,
                        target = $"0x{target:X}",
                        start = $"0x{start:X}",
                        stop = $"0x{stop:X}",
                        protectionFlags,
                        scannedRange = !IsWholeProcessRange(start, stop),
                        count = results.Count,
                        results,
                    };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "find_references"),
            Description(
                "Scans memory for raw pointers to an address. Useful for finding data structures or static pointers that reference an object."
            )
        ]
        public static object FindReferences(
            [Description("Target address expression (e.g. '0x...', 'module+0x123', symbol)")]
                string targetAddress,
            [Description("Pointer size in bytes: 'auto', '4', or '8'")] string pointerSize = "auto",
            [Description("Start address for scan (default: 0)")] string startAddress = "0",
            [Description("Stop address for scan (default: FFFFFFFFFFFFFFFF)")]
                string stopAddress = "FFFFFFFFFFFFFFFF",
            [Description("Protection flags (default: +W-C to scan writable memory)")] string protectionFlags = "+W-C",
            [Description("Maximum number of results to return (max 5000)")] int maxResults = 2000
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (!ValidationHelper.IsProcessAttached())
                        return new { success = false, error = "No process is currently opened. Use openProcess() first." };

                    if (string.IsNullOrWhiteSpace(targetAddress))
                        return new { success = false, error = "targetAddress is required" };
                    if (!ValidationHelper.TryResolveAddress(targetAddress, out var target))
                        return new { success = false, error = "Unable to resolve targetAddress" };

                    if (!ValidationHelper.TryResolveAddress(startAddress, out var start))
                        return new { success = false, error = "Unable to resolve startAddress" };
                    if (!ValidationHelper.TryResolveAddress(stopAddress, out var stop))
                        return new { success = false, error = "Unable to resolve stopAddress" };

                    if (start > stop)
                        (start, stop) = (stop, start);

                    if (maxResults <= 0)
                        maxResults = 1;
                    if (maxResults > MaxReferenceResults)
                        maxResults = MaxReferenceResults;

                    int ps = ResolvePointerSize(pointerSize, target);
                    if (ps != 4 && ps != 8)
                        return new { success = false, error = "pointerSize must be auto/4/8" };

                    var pattern = BuildPointerAobPattern(target, ps);
                    var candidates = ScanAobWithinRequestedRange(
                        pattern,
                        start,
                        stop,
                        protectionFlags,
                        0,
                        string.Empty
                    );

                    var results = new List<string>(Math.Min(maxResults, 256));
                    foreach (var addr in candidates)
                    {
                        if (addr < start || addr > stop)
                            continue;

                        results.Add($"0x{addr:X}");
                        if (results.Count >= maxResults)
                            break;
                    }

                    return new
                    {
                        success = true,
                        target = $"0x{target:X}",
                        pointerSize = ps,
                        pattern,
                        start = $"0x{start:X}",
                        stop = $"0x{stop:X}",
                        protectionFlags,
                        scannedRange = !IsWholeProcessRange(start, stop),
                        count = results.Count,
                        results,
                    };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        private static int ResolvePointerSize(string pointerSize, ulong target)
        {
            var ps = (pointerSize ?? "").Trim().ToLowerInvariant();
            if (ps == "4")
                return 4;
            if (ps == "8")
                return 8;

            // auto: prefer asking CE when available; fall back to target value heuristic.
            try
            {
                return SymbolManager.TargetIs64Bit() ? 8 : 4;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(ex);
            }

            return target > uint.MaxValue ? 8 : 4;
        }

        private static string BuildPointerAobPattern(ulong address, int pointerSize)
        {
            // Little-endian pointer bytes.
            Span<byte> bytes = stackalloc byte[pointerSize];
            for (int i = 0; i < pointerSize; i++)
                bytes[i] = (byte)((address >> (8 * i)) & 0xFF);

            return string.Join(" ", bytes.ToArray().Select(b => b.ToString("X2")));
        }

        private static List<ulong> ScanAobWithinRequestedRange(
            string pattern,
            ulong start,
            ulong stop,
            string? protectionFlags,
            int alignmentType,
            string? alignmentParam
        )
        {
            if (IsWholeProcessRange(start, stop))
            {
                return AobScanner.Scan(
                    pattern,
                    protectionFlags,
                    alignmentType,
                    alignmentParam
                );
            }

            return AobScanner.ScanRange(
                start,
                stop,
                pattern,
                protectionFlags,
                alignmentType,
                alignmentParam
            );
        }

        private static bool IsWholeProcessRange(ulong start, ulong stop) =>
            start == 0 && stop == ulong.MaxValue;

        [
            McpServerTool(Name = "get_instruction_info"),
            Description(
                "Retrieves detailed information about the instruction at a specific address, including its size, raw bytes, disassembly, and branch target (if it's a jump or call)."
            )
        ]
        public static object GetInstructionInfo(
            [Description("Instruction address expression (e.g. '0x...', 'module+0x123', symbol)")]
                string address
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (!ValidationHelper.IsProcessAttached())
                        return new { success = false, error = "No process is currently opened. Use openProcess() first." };

                    if (string.IsNullOrWhiteSpace(address))
                        return new { success = false, error = "address is required" };
                    if (!ValidationHelper.TryResolveAddress(address, out var addr))
                        return new { success = false, error = "Unable to resolve address" };

                    int size;
                    try
                    {
                        size = Disassembler.GetInstructionSize(addr);
                        if (size < 0)
                            size = 0;
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine(ex);
                        size = 0;
                    }

                    byte[] bytes = [];
                    if (size > 0 && size <= 32)
                    {
                        try
                        {
                            bytes = MemoryAccess.ReadBytes(addr, size);
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Debug.WriteLine(ex);
                            bytes = [];
                        }
                    }

                    string? disasm = null;
                    try
                    {
                        disasm = Disassembler.Disassemble(addr);
                        if (string.IsNullOrWhiteSpace(disasm) && bytes.Length > 0)
                        {
                            var hex = string.Join(" ", bytes.Select(static b => b.ToString("X2")));
                            disasm = Disassembler.DisassembleBytes(hex, addr);
                        }
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine(ex);
                    }

                    var asmText = ExtractAsmText(disasm ?? "");
                    SplitAsm(asmText, out var mnemonic, out var operands);

                    object? branch = null;
                    if (TryComputeRelativeBranchTarget(addr, bytes, out var target, out var kind))
                    {
                        branch = new { kind, target = $"0x{target:X}" };
                    }

                    return new
                    {
                        success = true,
                        address = $"0x{addr:X}",
                        size,
                        bytes = bytes.Length > 0 ? Convert.ToHexString(bytes) : "",
                        disasm = disasm ?? "",
                        asm = asmText,
                        mnemonic,
                        operands,
                        branch,
                    };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        private static string ExtractAsmText(string disasm)
        {
            if (string.IsNullOrWhiteSpace(disasm))
                return "";

            // Many CE builds format as: "ADDRESS - BYTES - asm"; keep last segment.
            var parts = disasm.Split(" - ");
            if (parts.Length >= 2)
                return parts[^1].Trim();
            return disasm.Trim();
        }

        private static string? TryGenerateBoundedExactSignature(ulong address)
        {
            const int SignatureBytes = 16;

            byte[] bytes;
            try
            {
                bytes = MemoryAccess.ReadBytes(address, SignatureBytes);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(ex);
                return null;
            }

            if (bytes.Length < 4)
                return null;

            return string.Join(" ", bytes.Select(static b => b.ToString("X2")));
        }

        private static void SplitAsm(string asm, out string mnemonic, out string operands)
        {
            mnemonic = "";
            operands = "";

            if (string.IsNullOrWhiteSpace(asm))
                return;

            var trimmed = asm.Trim();
            var idx = trimmed.IndexOf(' ');
            if (idx < 0)
            {
                mnemonic = trimmed;
                return;
            }

            mnemonic = trimmed[..idx].Trim();
            operands = trimmed[(idx + 1)..].Trim();
        }

        private static bool TryComputeRelativeBranchTarget(
            ulong address,
            byte[] bytes,
            out ulong target,
            out string kind
        )
        {
            target = 0;
            kind = "";

            if (bytes.Length < 2)
                return false;

            // CALL rel32: E8 xx xx xx xx
            if (bytes.Length >= 5 && bytes[0] == 0xE8)
            {
                int rel = BitConverter.ToInt32(bytes, 1);
                if (!TryComputeSignedTarget(address, 5, rel, out target))
                    return false;
                kind = "call";
                return true;
            }

            // JMP rel32: E9 xx xx xx xx
            if (bytes.Length >= 5 && bytes[0] == 0xE9)
            {
                int rel = BitConverter.ToInt32(bytes, 1);
                if (!TryComputeSignedTarget(address, 5, rel, out target))
                    return false;
                kind = "jmp";
                return true;
            }

            // JMP rel8: EB xx
            if (bytes[0] == 0xEB)
            {
                sbyte rel = unchecked((sbyte)bytes[1]);
                if (!TryComputeSignedTarget(address, 2, rel, out target))
                    return false;
                kind = "jmp";
                return true;
            }

            // Jcc rel8: 70-7F xx
            if (bytes[0] >= 0x70 && bytes[0] <= 0x7F)
            {
                sbyte rel = unchecked((sbyte)bytes[1]);
                if (!TryComputeSignedTarget(address, 2, rel, out target))
                    return false;
                kind = "jcc";
                return true;
            }

            // Jcc rel32: 0F 80-8F xx xx xx xx
            if (bytes.Length >= 6 && bytes[0] == 0x0F && bytes[1] >= 0x80 && bytes[1] <= 0x8F)
            {
                int rel = BitConverter.ToInt32(bytes, 2);
                if (!TryComputeSignedTarget(address, 6, rel, out target))
                    return false;
                kind = "jcc";
                return true;
            }

            return false;
        }

        private static bool TryComputeSignedTarget(
            ulong address,
            int instructionLength,
            long relativeOffset,
            out ulong target
        )
        {
            target = 0;
            try
            {
                var baseAddr = checked((long)address);
                var dest = checked(baseAddr + instructionLength + relativeOffset);
                if (dest < 0)
                    return false;
                target = unchecked((ulong)dest);
                return true;
            }
            catch (OverflowException ex)
            {
                System.Diagnostics.Debug.WriteLine(ex);
                return false;
            }
        }

        private static List<ulong> ParseOffsets(string offsets)
        {
            if (string.IsNullOrWhiteSpace(offsets))
                return [];

            var parts = offsets.Split(
                [',', ' ', '\t', '\r', '\n'],
                StringSplitOptions.RemoveEmptyEntries
            );

            var list = new List<ulong>(parts.Length);
            foreach (var part in parts)
            {
                if (!ValidationHelper.TryResolveAddress(part, out var value))
                    throw new ArgumentException($"Invalid offset: {part}");
                list.Add(value);
            }
            return list;
        }

        private static object ReadBytes(ulong address, string? byteCount)
        {
            if (string.IsNullOrEmpty(byteCount) || !int.TryParse(byteCount, out var bc) || bc <= 0)
                throw new ArgumentException("byteCount is required for bytes and must be > 0");
            if (bc > MaxReadBytes)
                throw new ArgumentException($"byteCount too large (max {MaxReadBytes})");
            return MemoryAccess.ReadBytes(address, bc);
        }

        private static object ReadString(ulong address, string? maxLength, string wideChar)
        {
            if (string.IsNullOrEmpty(maxLength) || !int.TryParse(maxLength, out var ml) || ml <= 0)
                throw new ArgumentException("maxLength is required for string and must be > 0");
            if (ml > MaxStringLength)
                throw new ArgumentException($"maxLength too large (max {MaxStringLength})");
            bool isWide = wideChar.Equals("true", StringComparison.OrdinalIgnoreCase);
            return MemoryAccess.ReadString(address, ml, isWide);
        }

        private static long CoerceLong(object? value)
        {
            if (value == null)
                return 0;

            return value switch
            {
                long l => l,
                int i => i,
                short s => s,
                byte b => b,
                double d => (long)d,
                float f => (long)f,
                string str when long.TryParse(str, out var parsed) => parsed,
                _ => Convert.ToInt64(value, CultureInfo.InvariantCulture),
            };
        }
    }
}
