using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using CEMCP;
using CESDK.Classes;
using ModelContextProtocol.Server;

namespace Tools
{
    /// <summary>
    /// Memory view tools for inspecting memory layout, disassembly, and memory regions.
    /// Provides the AI with a "view" of the target process memory similar to CE's Memory View window.
    /// </summary>
    [McpServerToolType]
    public class MemoryViewTool
    {
        private const string AddressRequired = "Address is required";
        private const int DefaultMemoryRegionLimit = 200;
        private const int MaxMemoryRegionLimit = 1000;

        private MemoryViewTool() { }

        [McpServerTool(Name = "disassemble_range_detailed"), Description(
            "Disassemble a range of instructions starting at an address. " +
            "Returns parsed instructions with address, bytes, opcode, and comments.")]
        public static object DisassembleRangeDetailed(
            [Description("Start address expression (e.g. '0x401000' or 'game.exe+1000')")] string address,
            [Description("Number of instructions to disassemble (default: 20, max: 200)")] int count = 20)
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (!ValidationHelper.IsProcessAttached())
                        return new { success = false, error = "No process is currently opened. Use openProcess() first." };

                    if (string.IsNullOrWhiteSpace(address))
                        return new { success = false, error = AddressRequired };

                    if (count < 1) count = 1;
                    if (count > 200) count = 200;

                    if (!ValidationHelper.TryResolveAddress(address, out ulong resolvedAddr))
                        return new { success = false, error = $"Could not resolve address: {address}" };

                    ulong currentAddr = resolvedAddr;
                    var instructions = new List<object>();

                    for (int i = 0; i < count; i++)
                    {
                        var disasm = Disassembler.Disassemble(currentAddr);
                        var size = Disassembler.GetInstructionSize(currentAddr);
                        if (string.IsNullOrWhiteSpace(disasm))
                            disasm = DisassembleBytesAt(currentAddr, size);

                        if (string.IsNullOrEmpty(disasm))
                            break;

                        var parsed = Disassembler.SplitDisassembledString(disasm);
                        var comment = Disassembler.GetComment(currentAddr);

                        instructions.Add(new
                        {
                            address = $"0x{currentAddr:X}",
                            bytes = parsed.Bytes,
                            opcode = parsed.Opcode,
                            extra = parsed.Extra,
                            comment = string.IsNullOrEmpty(comment) ? null : comment,
                            size
                        });

                        currentAddr += (ulong)size;
                    }

                    var symbolName = AddressResolver.GetNameFromAddress(resolvedAddr);
                    return new
                    {
                        success = true,
                        startAddress = $"0x{resolvedAddr:X}",
                        symbol = symbolName,
                        instructionCount = instructions.Count,
                        instructions
                    };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [McpServerTool(Name = "get_function_range"), Description(
            "Get the estimated start and end address of a function containing the given address.")]
        public static object GetFunctionRange(
            [Description("Address inside the function as hex string or symbol name")] string address)
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (!ValidationHelper.IsProcessAttached())
                        return new { success = false, error = "No process is currently opened. Use openProcess() first." };

                    if (string.IsNullOrWhiteSpace(address))
                        return new { success = false, error = AddressRequired };

                    if (!ValidationHelper.TryResolveAddress(address, out ulong resolvedAddr))
                        return new { success = false, error = $"Could not resolve address: {address}" };

                    var (start, end) = Disassembler.GetFunctionRange(resolvedAddr);
                    var symbolName = AddressResolver.GetNameFromAddress(start);

                    return new
                    {
                        success = true,
                        startAddress = $"0x{start:X}",
                        endAddress = $"0x{end:X}",
                        size = end - start,
                        symbol = symbolName
                    };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [McpServerTool(Name = "disassemble_bytes"), Description("Disassembles raw hex bytes into assembly instructions.")]
        public static object DisassembleBytes(
            [Description("Hex byte string to disassemble (e.g. '90 90 CC')")] string hexBytes,
            [Description("Address to use for relative address calculations")] string? address = null)
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(hexBytes))
                        return new { success = false, error = "Hex bytes are required" };

                    ulong addr = 0;
                    if (!string.IsNullOrEmpty(address))
                    {
                        if (!ValidationHelper.TryResolveAddress(address, out addr))
                            addr = 0;
                    }

                    var result = Disassembler.DisassembleBytes(hexBytes, addr);
                    return new { success = true, result };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [McpServerTool(Name = "enum_memory_regions"), Description(
            "Enumerates target process memory regions with pagination. Defaults to committed regions and a bounded page to avoid huge MCP responses.")]
        public static object EnumMemoryRegions(
            [Description("Filter by state: 'committed' (default), 'reserved', 'free', or 'all'")] string filter = "committed",
            [Description("Zero-based page offset after filtering")] int offset = 0,
            [Description("Maximum regions to return. Default 200, max 1000 unless allow_large_result=true")] int limit = DefaultMemoryRegionLimit,
            [Description("Only include regions whose size is at least this many bytes")] ulong min_size = 0,
            [Description("Optional protection filter, e.g. 'execute', 'write', 'readwrite', 'noaccess'")] string? protection = null,
            [Description("If true, returns counts/page metadata without the region list")] bool summary_only = false,
            [Description("Explicitly allow returning every matching region when limit <= 0")] bool allow_large_result = false)
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (!ValidationHelper.IsProcessAttached())
                        return new { success = false, error = "No process is currently opened. Use openProcess() first." };

                    if (offset < 0)
                        return new { success = false, error = "offset must be >= 0" };

                    var requestedLimit = NormalizeRegionLimit(limit, allow_large_result);
                    var filtered = MemoryRegions
                        .EnumMemoryRegions()
                        .Where(r => MatchesStateFilter(r.State, filter))
                        .Where(r => r.RegionSize >= min_size)
                        .Where(r => MatchesProtectionFilter(r.Protect, protection))
                        .ToList();

                    var total = filtered.Count;
                    var page = requestedLimit.HasValue
                        ? filtered.Skip(offset).Take(requestedLimit.Value).ToList()
                        : filtered.Skip(offset).ToList();

                    var result = summary_only
                        ? new List<object>()
                        : page.Select(r => new
                        {
                            baseAddress = $"0x{r.BaseAddress:X}",
                            regionSize = r.RegionSize,
                            regionSizeHex = $"0x{r.RegionSize:X}",
                            protect = ProtectToString(r.Protect),
                            protectRaw = r.Protect,
                            state = StateToString(r.State),
                            stateRaw = r.State,
                            type = TypeToString(r.Type),
                            typeRaw = r.Type
                        }).ToList<object>();

                    var nextOffset = offset + page.Count;
                    return new
                    {
                        success = true,
                        total,
                        count = result.Count,
                        offset,
                        limit = requestedLimit,
                        hasMore = nextOffset < total,
                        nextOffset = nextOffset < total ? nextOffset : (int?)null,
                        filter = NormalizeStateFilter(filter),
                        minSize = min_size,
                        protection,
                        summaryOnly = summary_only,
                        regions = result
                    };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        private static int? NormalizeRegionLimit(int limit, bool allowLargeResult)
        {
            if (limit <= 0)
                return allowLargeResult ? null : DefaultMemoryRegionLimit;

            return allowLargeResult ? limit : Math.Min(limit, MaxMemoryRegionLimit);
        }

        private static string NormalizeStateFilter(string? filter) =>
            string.IsNullOrWhiteSpace(filter) ? "committed" : filter.Trim().ToLowerInvariant();

        private static bool MatchesStateFilter(int state, string? filter)
        {
            return NormalizeStateFilter(filter) switch
            {
                "all" => true,
                "reserved" => state == 0x2000,
                "free" => state == 0x10000,
                "committed" => state == 0x1000,
                _ => state == 0x1000,
            };
        }

        private static bool MatchesProtectionFilter(int protect, string? protection)
        {
            if (string.IsNullOrWhiteSpace(protection))
                return true;

            var normalized = protection.Trim().ToLowerInvariant().Replace("_", "");
            return normalized switch
            {
                "noaccess" => protect == 0x01,
                "readonly" or "read" => protect is 0x02 or 0x20,
                "readwrite" or "write" => protect is 0x04 or 0x08 or 0x40 or 0x80,
                "execute" => (protect & 0xF0) != 0,
                "executeread" => protect == 0x20,
                "executereadwrite" or "executewrite" => protect == 0x40,
                _ => true,
            };
        }

        [McpServerTool(Name = "get_memory_protection"), Description("Retrieves the memory protection flags (read, write, execute) for a given address.")]
        public static object GetMemoryProtection(
            [Description("Memory address expression")] string address)
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (!ValidationHelper.IsProcessAttached())
                        return new { success = false, error = "No process is currently opened. Use openProcess() first." };

                    if (string.IsNullOrWhiteSpace(address))
                        return new { success = false, error = AddressRequired };

                    if (!ValidationHelper.TryResolveAddress(address, out ulong resolvedAddr))
                        return new { success = false, error = $"Could not resolve address: {address}" };

                    var prot = MemoryRegions.GetMemoryProtection(resolvedAddr);
                    return new
                    {
                        success = true,
                        address = $"0x{resolvedAddr:X}",
                        read = prot.Read,
                        write = prot.Write,
                        execute = prot.Execute
                    };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [McpServerTool(Name = "set_comment"), Description("Sets a comment at a memory address, visible in Cheat Engine's Memory View.")]
        public static object SetComment(
            [Description("Memory address expression")] string address,
            [Description("Comment text to set")] string comment)
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (!ValidationHelper.IsProcessAttached())
                        return new { success = false, error = "No process is currently opened. Use openProcess() first." };

                    if (string.IsNullOrWhiteSpace(address))
                        return new { success = false, error = AddressRequired };

                    if (!ValidationHelper.TryResolveAddress(address, out ulong resolvedAddr))
                        return new { success = false, error = $"Could not resolve address: {address}" };

                    Disassembler.SetComment(resolvedAddr, comment);
                    return new { success = true, address = $"0x{resolvedAddr:X}" };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        private static string ProtectToString(int protect)
        {
            return protect switch
            {
                0x01 => "NOACCESS",
                0x02 => "READONLY",
                0x04 => "READWRITE",
                0x08 => "WRITECOPY",
                0x10 => "EXECUTE",
                0x20 => "EXECUTE_READ",
                0x40 => "EXECUTE_READWRITE",
                0x80 => "EXECUTE_WRITECOPY",
                _ => $"0x{protect:X}"
            };
        }

        private static string StateToString(int state)
        {
            return state switch
            {
                0x1000 => "MEM_COMMIT",
                0x2000 => "MEM_RESERVE",
                0x10000 => "MEM_FREE",
                _ => $"0x{state:X}"
            };
        }

        private static string TypeToString(int type)
        {
            return type switch
            {
                0x20000 => "MEM_PRIVATE",
                0x40000 => "MEM_MAPPED",
                0x1000000 => "MEM_IMAGE",
                _ => $"0x{type:X}"
            };
        }

        private static string? DisassembleBytesAt(ulong address, int size)
        {
            if (size <= 0 || size > 32)
                return null;

            var bytes = MemoryAccess.ReadBytes(address, size);
            if (bytes.Length == 0)
                return null;

            var hex = string.Join(" ", bytes.Select(static b => b.ToString("X2")));
            return Disassembler.DisassembleBytes(hex, address);
        }
    }
}
