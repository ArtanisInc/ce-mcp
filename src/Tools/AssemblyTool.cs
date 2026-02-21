using System;
using System.ComponentModel;
using CEMCP;
using CESDK.Classes;
using ModelContextProtocol.Server;

namespace Tools
{
    /// <summary>
    /// Disassembly and address resolution tools.
    /// </summary>
    [McpServerToolType]
    public class AssemblyTool
    {
        private AssemblyTool() { }

        [
            McpServerTool(Name = "disassemble"),
            Description("Disassemble instructions or get instruction size at a memory address")
        ]
        public static object Disassemble(
            [Description("Memory address as hex string (e.g. '0x1234ABCD')")] string address,
            string requestType = ""
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(address))
                        return new { success = false, error = "Address parameter is required" };

                    if (!TryParseAddress(address, out ulong addr))
                        return new { success = false, error = "Invalid address format" };

                    string result = requestType.ToLower() switch
                    {
                        "get-instruction-size" => Disassembler.GetInstructionSize(addr).ToString(),
                        "disassemble" or "" => Disassembler.Disassemble(addr)?.ToString()
                            ?? "Failed to disassemble",
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
                "Resolve an address from a string expression (supports symbols, module+offset, etc.)"
            )
        ]
        public static object ResolveAddress(
            [Description("Address string expression to resolve")] string addressString,
            [Description("Whether to resolve as local address ('true' or 'false')")]
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

        [McpServerTool(Name = "auto_assemble"), Description("Execute an auto-assemble script")]
        public static object AutoAssemble(
            [Description("Auto-assemble script content")] string script,
            [Description("Whether to target the current process ('true' or 'false')")]
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
            Description("Check if an auto-assemble script is valid")
        ]
        public static object AutoAssembleCheck(
            [Description("Auto-assemble script content")] string script,
            [Description("Whether to target the current process ('true' or 'false')")]
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
            Description("Generate an API hook script")
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

        private static bool TryParseAddress(string address, out ulong result) =>
            ulong.TryParse(
                address.Replace("0x", "").Replace("0X", ""),
                System.Globalization.NumberStyles.HexNumber,
                null,
                out result
            );
    }
}
