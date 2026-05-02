using System;
using System.ComponentModel;
using CEMCP;
using CESDK.Classes;
using ModelContextProtocol.Server;

namespace Tools
{
    /// <summary>
    /// Tools for controlling target process time/speed.
    /// </summary>
    [McpServerToolType]
    public class SpeedhackTool
    {
        private SpeedhackTool() { }

        [McpServerTool(Name = "set_speedhack"), Description("Enables speedhack and sets the execution speed multiplier.")]
        public static object SetSpeedhack([Description("Speed multiplier (e.g. 1.0 for normal, 2.0 for double speed, 0.5 for half speed)")] float speed)
        {
            return CeLuaGate.Run<object>(() =>
            {
                if (!ValidationHelper.IsProcessAttached())
                    return new
                    {
                        success = false,
                        error = "No process is attached. Please open a process first using 'open_process' tool.",
                    };

                try
                {
                    Speedhack.SetSpeed(speed);
                    return new { success = true, speed };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [McpServerTool(Name = "get_speedhack"), Description("Returns the current speedhack multiplier.")]
        public static object GetSpeedhack()
        {
            return CeLuaGate.Run<object>(() =>
            {
                if (!ValidationHelper.IsProcessAttached())
                    return new
                    {
                        success = false,
                        error = "No process is attached. Please open a process first using 'open_process' tool.",
                    };

                try
                {
                    float speed = Speedhack.GetSpeed();
                    return new { success = true, speed };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }
    }
}
