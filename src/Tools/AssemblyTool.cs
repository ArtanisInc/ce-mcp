using System;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using CEMCP;
using CESDK.Classes;
using ModelContextProtocol.Server;

namespace Tools
{
    /// <summary>
    /// Assembly and instruction management tools.
    /// </summary>
    [McpServerToolType]
    public class AssemblyTool
    {
        private AssemblyTool() { }

        [
            McpServerTool(Name = "disassemble"),
            Description("Disassembles a single instruction at the given address, or retrieves the instruction's size.")
        ]
        public static object Disassemble(
            [Description("Memory address expression (e.g. '0x1234ABCD', 'module+0x123', symbol)")]
                string address,
            [Description("Type of request: 'disassemble' (default) or 'get-instruction-size'")]
                string requestType = "disassemble"
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (!ValidationHelper.IsProcessAttached())
                        return new { success = false, error = "No process is currently opened. Use openProcess() first." };

                    if (string.IsNullOrWhiteSpace(address))
                        return new { success = false, error = "Address parameter is required" };

                    if (!ValidationHelper.TryResolveAddress(address, out ulong addr))
                        return new { success = false, error = "Unable to resolve address" };

                    string result = requestType.ToLower() switch
                    {
                        "get-instruction-size" => Disassembler.GetInstructionSize(addr).ToString(),
                        "disassemble" or "" => DisassembleAt(addr) ?? "Failed to disassemble",
                        _ => throw new NotSupportedException(
                            $"Unsupported request type: {requestType}"
                        ),
                    };

                    return new { success = true, result };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "resolve_address"),
            Description(
                "Resolves a complex address expression (symbols, module offsets, pointer math) to its absolute numeric address."
            )
        ]
        public static object ResolveAddress(
            [Description("Address expression to resolve (e.g. 'game.exe+1A0', '[0x123]+10', 'MainForm')")] string addressString,
            [Description("Whether to resolve as a local address (true/false)")]
                string local = "false"
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(addressString))
                        return new { success = false, error = "Address string is required" };

                    bool isLocal = local.Equals("true", StringComparison.OrdinalIgnoreCase);
                    var address = AddressResolver.GetAddressSafe(addressString, isLocal);
                    return new
                    {
                        success = true,
                        address = address.HasValue ? $"0x{address.Value:X}" : "0",
                    };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [McpServerTool(Name = "auto_assemble"), Description("Executes an Auto Assemble (AA) script. Supports full AA syntax including alloc, label, define, and code injection.")]
        public static object AutoAssemble(
            [Description("Auto Assemble script content")] string script,
            [Description("Whether to target the current process (true) or Cheat Engine itself (false)")]
                string targetSelf = "true"
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(script))
                        return new { success = false, error = "Script parameter is required" };

                    bool isSelf = targetSelf.Equals("true", StringComparison.OrdinalIgnoreCase);
                    var disableInfo = AutoAssembler.AutoAssemble(script, isSelf);
                    return new { success = true, disableInfo };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "auto_assemble_check"),
            Description("Validates an Auto Assemble script for syntax errors without executing it.")
        ]
        public static object AutoAssembleCheck(
            [Description("Auto Assemble script content")] string script,
            [Description("Whether to target the current process (true) or Cheat Engine itself (false)")]
                string targetSelf = "true"
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(script))
                        return new { success = false, error = "Script parameter is required" };

                    bool isSelf = targetSelf.Equals("true", StringComparison.OrdinalIgnoreCase);
                    AutoAssembler.AutoAssembleCheck(script, isSelf);
                    return new { success = true };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "generate_api_hook_script"),
            Description("Generates a standard API hook template for the given target address and hook function.")
        ]
        public static object GenerateAPIHookScript(
            [Description("Address or symbol of the API to hook")] string address,
            [Description("Address or symbol of the hook function")] string hookFunction
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(address))
                        return new { success = false, error = "Address parameter is required" };

                    if (string.IsNullOrWhiteSpace(hookFunction))
                        return new
                        {
                            success = false,
                            error = "HookFunction parameter is required",
                        };

                    string script = AutoAssembler.GenerateAPIHookScript(address, hookFunction);
                    return new { success = true, script };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "assemble"),
            Description("Assembles an instruction string into its corresponding hex bytes at a specific address.")
        ]
        public static object Assemble(
            [Description("Memory address to assemble at (e.g. '0x1234ABCD')")] string address,
            [Description("Instruction string (e.g. 'mov eax,1')")] string instruction
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (!ValidationHelper.IsProcessAttached())
                        return new { success = false, error = "No process is currently opened. Use openProcess() first." };

                    if (string.IsNullOrWhiteSpace(address))
                        return new { success = false, error = "Address parameter is required" };
                    if (string.IsNullOrWhiteSpace(instruction))
                        return new { success = false, error = "Instruction parameter is required" };

                    if (!ValidationHelper.TryResolveAddress(address, out ulong addr))
                        return new { success = false, error = "Unable to resolve address" };

                    var bytes = AutoAssembler.Assemble(instruction, (long)addr);

                    if (bytes == null || bytes.Length == 0)
                        return new { success = false, error = "Failed to assemble instruction" };

                    return new { success = true, bytes = Convert.ToHexString(bytes) };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "disassemble_range"),
            Description("Disassembles a contiguous range of instructions starting from the given address.")
        ]
        public static object DisassembleRange(
            [Description("Starting memory address expression")] string startAddress,
            [Description("Number of instructions to disassemble (default: 10)")] int count = 10
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (!ValidationHelper.IsProcessAttached())
                        return new { success = false, error = "No process is currently opened. Use openProcess() first." };

                    if (string.IsNullOrWhiteSpace(startAddress))
                        return new { success = false, error = "StartAddress parameter is required" };

                    if (!ValidationHelper.TryResolveAddress(startAddress, out ulong addr))
                        return new { success = false, error = "Unable to resolve start address" };

                    var instructions = new System.Collections.Generic.List<object>();
                    ulong currentAddr = addr;

                    for (int i = 0; i < count; i++)
                    {
                        var size = Disassembler.GetInstructionSize(currentAddr);
                        var disasm = Disassembler.Disassemble(currentAddr);
                        if (string.IsNullOrWhiteSpace(disasm))
                            disasm = DisassembleBytesAt(currentAddr, size);

                        instructions.Add(new
                        {
                            address = $"0x{currentAddr:X}",
                            disassembly = disasm ?? "???",
                            size = size
                        });

                        currentAddr += (ulong)size;
                    }

                    return new { success = true, instructions };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
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

        private static string? DisassembleAt(ulong address, int? knownSize = null)
        {
            var disasm = Disassembler.Disassemble(address);
            if (!string.IsNullOrWhiteSpace(disasm))
                return disasm;

            var size = knownSize ?? Disassembler.GetInstructionSize(address);
            return DisassembleBytesAt(address, size);
        }

        [
            McpServerTool(Name = "get_previous_opcodes"),
            Description("Returns the instructions preceding a given address by estimating opcode boundaries.")
        ]
        public static object GetPreviousOpcodes(
            [Description("Target memory address expression")] string address,
            [Description("Number of preceding instructions to return (default: 5)")] int count = 5
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (!ValidationHelper.IsProcessAttached())
                        return new { success = false, error = "No process is currently opened. Use openProcess() first." };

                    if (string.IsNullOrWhiteSpace(address))
                        return new { success = false, error = "Address parameter is required" };

                    if (!ValidationHelper.TryResolveAddress(address, out ulong addr))
                        return new { success = false, error = "Unable to resolve address" };

                    var instructions = new System.Collections.Generic.List<object>();
                    ulong currentAddr = addr;

                    for (int i = 0; i < count; i++)
                    {
                        var prevAddr = Disassembler.GetPreviousOpcode(currentAddr);
                        if (prevAddr == 0 || prevAddr == currentAddr) break;

                        currentAddr = prevAddr;

                        var size = Disassembler.GetInstructionSize(currentAddr);
                        var disasm = DisassembleAt(currentAddr, size) ?? "???";

                        instructions.Insert(0, new
                        {
                            address = $"0x{currentAddr:X}",
                            disassembly = disasm,
                            size = size
                        });
                    }

                    return new { success = true, instructions };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "get_name_from_address"),
            Description("Retrieves the symbol name or module+offset for a given absolute address.")
        ]
        public static object GetNameFromAddress(
            [Description("Numeric address or expression to look up")] string address
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (!ValidationHelper.IsProcessAttached())
                        return new { success = false, error = "No process is currently opened. Use openProcess() first." };

                    if (string.IsNullOrWhiteSpace(address))
                        return new { success = false, error = "Address parameter is required" };

                    if (!ValidationHelper.TryResolveAddress(address, out ulong addr))
                        return new { success = false, error = "Unable to resolve address" };

                    var name = AddressResolver.GetNameFromAddress(addr);
                    return new { success = true, name };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }
    }
}
