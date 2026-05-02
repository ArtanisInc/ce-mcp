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
    /// <summary>
    /// Debugger tools for controlling execution and inspecting state.
    /// WARNING: Using these tools will halt the target process during breakpoints.
    /// </summary>
    [McpServerToolType]
    public class DebuggerTool
    {
        private DebuggerTool() { }

        [
            McpServerTool(Name = "debugger_start"),
            Description("Attaches Cheat Engine's debugger to the target process.")
        ]
        public static object StartDebugger([Description("Internal debug interface to use (default: 0)")] string debugInterface = "0")
        {
            return CeLuaGate.Run<object>(() =>
            {
                if (!ValidationHelper.IsProcessAttached())
                    return new
                    {
                        success = false,
                        error = "No process is attached. Please open a process first.",
                    };

                try
                {
                    if (!int.TryParse(debugInterface, out var di))
                        return new { success = false, error = "Invalid debugInterface format" };

                    bool success = AdvancedDebugger.StartDebugger(di);
                    return new { success };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "debugger_stop"),
            Description("Detaches the debugger and allows the process to run normally.")
        ]
        public static object StopDebugger()
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    bool success = AdvancedDebugger.StopDebugger();
                    return new { success };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "debugger_set_breakpoint"),
            Description(
                "Sets a blocking (halt-on-hit) breakpoint. The process will stop until 'debugger_continue' is called. " +
                "For non-blocking logging, use 'trace_set_breakpoint' instead."
            )
        ]
        public static object SetBreakpoint(
            [Description("Memory address expression to break on")] string address,
            [Description("Size of the breakpoint region in bytes (default: 1)")] string size = "1",
            [Description("Event that triggers the break: 'execute', 'access', or 'write'")] string trigger = "execute",
            [Description("Internal method: 'auto', 'debugregister' (hardware), 'exception', or 'int3' (software)")] string method = "auto"
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                if (!ValidationHelper.IsProcessAttached())
                    return new { success = false, error = "No process is attached." };

                try
                {
                    if (!AdvancedDebugger.IsDebugging())
                    {
                        return new
                        {
                            success = false,
                            error = "Debugger is not active. Call debugger_start first.",
                        };
                    }

                    if (!ValidationHelper.TryResolveAddress(address, out ulong addr))
                        return new { success = false, error = "Unable to resolve address" };

                    if (!int.TryParse(size, out var sz))
                        return new { success = false, error = "Invalid size format" };

                    if (sz <= 0)
                        return new { success = false, error = "Size must be > 0" };

                    BreakpointTrigger triggerEnum = trigger.ToLower() switch
                    {
                        "execute" => BreakpointTrigger.Execute,
                        "access" => BreakpointTrigger.Access,
                        "write" => BreakpointTrigger.Write,
                        _ => throw new ArgumentException($"Unsupported trigger: {trigger}"),
                    };

                    BreakpointMethod methodEnum = method.ToLower() switch
                    {
                        "auto" => BreakpointMethod.Auto,
                        "debugregister" => BreakpointMethod.DebugRegister,
                        "exception" => BreakpointMethod.Exception,
                        "int3" or "int32" => BreakpointMethod.Int3,
                        _ => throw new ArgumentException($"Unsupported method: {method}"),
                    };

                    if (
                        methodEnum == BreakpointMethod.DebugRegister
                        && triggerEnum != BreakpointTrigger.Execute
                        && sz is not (1 or 2 or 4 or 8)
                    )
                    {
                        return new
                        {
                            success = false,
                            error = "Hardware breakpoints require size 1, 2, 4, or 8",
                        };
                    }

                    bool success = AdvancedDebugger.SetBreakpoint(
                        (long)addr,
                        sz,
                        triggerEnum,
                        methodEnum
                    );
                    return new { success };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "debugger_remove_breakpoint"),
            Description("Deletes the blocking breakpoint at the specified address.")
        ]
        public static object RemoveBreakpoint(
            [Description("Memory address expression")] string address
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (!ValidationHelper.TryResolveAddress(address, out ulong addr))
                        return new { success = false, error = "Unable to resolve address" };

                    bool success = AdvancedDebugger.RemoveBreakpoint((long)addr);
                    return new { success };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "debugger_get_breakpoints"),
            Description("Returns a list of all active numeric addresses where breakpoints are set.")
        ]
        public static object GetBreakpoints()
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    var breakpoints = AdvancedDebugger.GetBreakpointList();
                    var hexBreakpoints = breakpoints.Select(b => $"0x{b:X}").ToList();
                    return new { success = true, breakpoints = hexBreakpoints };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "debugger_clear_breakpoints"),
            Description("Removes all active blocking breakpoints from the debugger.")
        ]
        public static object ClearBreakpoints()
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    var breakpoints = AdvancedDebugger.GetBreakpointList();
                    var removed = new List<string>();
                    var errors = new List<string>();

                    foreach (var bp in breakpoints)
                    {
                        try
                        {
                            if (AdvancedDebugger.RemoveBreakpoint(bp))
                                removed.Add($"0x{bp:X}");
                            else
                                errors.Add($"0x{bp:X}: remove failed");
                        }
                        catch (Exception ex)
                        {
                            errors.Add($"0x{bp:X}: {ex.Message}");
                        }
                    }

                    return new
                    {
                        success = true,
                        removedCount = removed.Count,
                        removed,
                        errors,
                    };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "debugger_continue"),
            Description("Resumes execution of a process that is currently halted at a breakpoint.")
        ]
        public static object Continue([Description("Resume method: 'run' (default), 'stepinto', or 'stepover'")] string method = "run")
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    ContinueMethod methodEnum = method.ToLower() switch
                    {
                        "run" => ContinueMethod.Run,
                        "stepinto" => ContinueMethod.StepInto,
                        "stepover" => ContinueMethod.StepOver,
                        _ => throw new ArgumentException($"Unsupported continue method: {method}"),
                    };

                    bool success = AdvancedDebugger.ContinueFromBreakpoint(methodEnum);
                    return new { success };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "debugger_get_context"),
            Description("Retrieves the current CPU register values for a halted process (EAX/RAX, EBX/RBX, etc.).")
        ]
        public static object GetContext()
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    var context = AdvancedDebugger.GetContext();
                    return new { success = true, context };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [McpServerTool(Name = "debugger_set_register"), Description("Modifies a CPU register value for a halted process.")]
        public static object SetRegister(
            [Description("Name of the register to modify (e.g. 'EAX', 'RAX', 'RIP')")] string register, 
            [Description("New numeric value or expression to set")] string value)
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(register))
                        return new { success = false, error = "Register name is required" };

                    if (string.IsNullOrWhiteSpace(value))
                        return new { success = false, error = "Value is required" };

                    if (!ValidationHelper.TryResolveAddress(value, out ulong val))
                        return new { success = false, error = "Unable to resolve register value" };

                    AdvancedDebugger.SetRegister(register, (long)val);
                    return new { success = true };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "debugger_status"),
            Description("Returns the current status: whether the debugger is attached and whether the process is currently halted.")
        ]
        public static object GetStatus()
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    bool isDebugging = AdvancedDebugger.IsDebugging();
                    bool isBroken = AdvancedDebugger.IsBroken();
                    return new
                    {
                        success = true,
                        isDebugging,
                        isBroken,
                    };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }
    }
}
