using System;
using System.ComponentModel;
using CEMCP;
using CESDK.Classes;
using ModelContextProtocol.Server;

namespace Tools
{
    /// <summary>
    /// Tools for executing custom Lua scripts.
    /// </summary>
    [McpServerToolType]
    public class LuaExecutionTool
    {
        private LuaExecutionTool() { }

        [
            McpServerTool(Name = "execute_lua"),
            Description(
                "Executes an arbitrary Lua script in Cheat Engine's internal environment. "
                    + "WARNING: Only use this as a last resort if no other specialized tool is available. "
                    + "Returns are automatically serialized. Use 'return value' to pass data back."
            )
        ]
        public static object ExecuteLua(
            [Description("The Lua code to execute.")] string script
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(script))
                        return new { success = false, error = "Script parameter is required" };

                    var result = LuaExecutor.Execute(script);

                    if (!result.HasValue)
                        return new
                        {
                            success = true,
                            result = (object?)null,
                            message = "Executed successfully (no return value)",
                        };

                    if (result.ReturnCount == 1)
                        return new { success = true, result = result.Value };

                    return new { success = true, results = result.Values };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }
    }
}
