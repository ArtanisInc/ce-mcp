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
            "Enumerates all memory regions of the target process, showing base address, size, and protection flags.")]
        public static object EnumMemoryRegions(
            [Description("Filter by state: 'committed' (default), 'reserved', 'free', or 'all'")] string filter = "committed")
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (!ValidationHelper.IsProcessAttached())
                        return new { success = false, error = "No process is currently opened. Use openProcess() first." };

                    var regions = MemoryRegions.EnumMemoryRegions();

                    var filtered = filter?.ToLower() switch
                    {
                        "all" => regions,
                        "reserved" => regions.Where(r => r.State == 0x2000).ToList(),
                        "free" => regions.Where(r => r.State == 0x10000).ToList(),
                        _ => regions.Where(r => r.State == 0x1000).ToList() // committed
                    };

                    var result = filtered.Select(r => new
                    {
                        baseAddress = $"0x{r.BaseAddress:X}",
                        regionSize = r.RegionSize,
                        regionSizeHex = $"0x{r.RegionSize:X}",
                        protect = ProtectToString(r.Protect),
                        state = StateToString(r.State),
                        type = TypeToString(r.Type)
                    }).ToList();

                    return new { success = true, count = result.Count, regions = result };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
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
