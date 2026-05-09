using System;
using System.ComponentModel;
using System.Globalization;
using CEMCP;
using CESDK.Classes;
using CESDK.Utils;
using ModelContextProtocol.Server;

namespace Tools
{
    /// <summary>
    /// Trace breakpoint tools for non-blocking execution and data logging.
    /// </summary>
    [McpServerToolType]
    public sealed class TraceBreakpointTool
    {
        private const int MaxHardwareBreakpoints = 4;
        private const int MaxStackDepth = 128;
        private const int MaxHitsReturn = 2000;
        private const int MaxHitsStoredPerId = 5000;
        private const int DefaultTraceMaxHits = 1000;
        private const int MaxTraceMaxHits = 100000;
        private const int MaxTraceMinIntervalMs = 60000;

        private TraceBreakpointTool() { }

        [
            McpServerTool(Name = "trace_set_breakpoint"),
            Description(
                "Sets a non-blocking hardware execution breakpoint. Hits are logged to an internal buffer and the process continues automatically. Retrieve hits using 'trace_get_hits'."
            )
        ]
        public static object SetTraceBreakpoint(
            [Description("Memory address expression to trace")] string address,
            [Description("Optional identifier for this trace session (default: hex address)")]
                string? id = null,
            [Description("Whether to log CPU register values (true/false)")] bool capture_registers = true,
            [Description("Whether to log stack contents (true/false)")] bool capture_stack = false,
            [Description("Number of stack values to log (max 128)")] int stack_depth = 16,
            [Description("Maximum hits before auto-disabling the breakpoint (1-100000, default 1000)")]
                int max_hits = DefaultTraceMaxHits,
            [Description("Minimum milliseconds between logged hits (0-60000, default 0). Skipped hits still continue immediately.")]
                int min_interval_ms = 0
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

                    var resolvedId = string.IsNullOrWhiteSpace(id) ? $"0x{addr:X}" : id.Trim();
                    if (capture_stack && (stack_depth < 0 || stack_depth > MaxStackDepth))
                    {
                        return new
                        {
                            success = false,
                            error = $"stack_depth must be between 0 and {MaxStackDepth}",
                        };
                    }
                    if (max_hits <= 0 || max_hits > MaxTraceMaxHits)
                        return new
                        {
                            success = false,
                            error = $"max_hits must be between 1 and {MaxTraceMaxHits}",
                        };
                    if (min_interval_ms < 0 || min_interval_ms > MaxTraceMinIntervalMs)
                        return new
                        {
                            success = false,
                            error = $"min_interval_ms must be between 0 and {MaxTraceMinIntervalMs}",
                        };

                    // LuaExecutor truncates arrays beyond MaxTableEntries; avoid returning
                    // stack arrays that exceed the serializer limit.
                    var effectiveStackDepth = capture_stack
                        ? Math.Min(stack_depth, LuaExecutor.MaxTableEntries)
                        : 0;

                    EnsureTraceTables();

                    var existingCount = GetTraceBreakpointCount();
                    if (!HasTraceBreakpoint(resolvedId) && existingCount >= MaxHardwareBreakpoints)
                    {
                        return new
                        {
                            success = false,
                            error = "No free hardware breakpoint slots (max 4 debug registers)",
                        };
                    }

                    EnsureDebuggerStarted();

                    // Best-effort remove any existing breakpoint at same address.
                    _ = AdvancedDebugger.RemoveBreakpoint((long)addr);

                    var callback = BuildTraceCallbackLua(
                        resolvedId,
                        addr,
                        "hardware_execute",
                        capture_registers,
                        capture_stack,
                        effectiveStackDepth,
                        maxHits: max_hits,
                        minIntervalMs: min_interval_ms
                    );

                    var (ok, method, warning) = SetBreakpointWithFallbacks(
                        addr,
                        1,
                        BreakpointTrigger.Execute,
                        callback,
                        allowSoftwareFallback: true
                    );

                    if (!ok)
                        return new
                        {
                            success = false,
                            error = "Failed to set breakpoint with debug-register, auto, and INT3 fallback methods",
                        };

                    UpsertTraceBreakpoint(
                        resolvedId,
                        addr,
                        "execute",
                        method,
                        1,
                        max_hits,
                        min_interval_ms
                    );

                    return new
                    {
                        success = true,
                        id = resolvedId,
                        address = $"0x{addr:X}",
                        method,
                        warning,
                        max_hits,
                        min_interval_ms,
                    };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "trace_set_data_breakpoint"),
            Description(
                "Sets a non-blocking hardware data breakpoint (watchpoint). Logs hits when memory at the address is accessed or modified."
            )
        ]
        public static object SetTraceDataBreakpoint(
            [Description("Memory address expression to watch")] string address,
            [Description("Optional identifier for this trace session (default: hex address)")]
                string? id = null,
            [Description("Type of access to trigger on: 'r' (read), 'w' (write), or 'rw' (both)")] string access_type = "w",
            [Description("Region size in bytes (1, 2, 4, or 8)")] int size = 4,
            [Description("Whether to log the value in memory at the time of hit (true/false)")] bool capture_value = true,
            [Description("Maximum hits before auto-disabling the breakpoint (1-100000, default 1000)")]
                int max_hits = DefaultTraceMaxHits,
            [Description("Minimum milliseconds between logged hits (0-60000, default 0). Skipped hits still continue immediately.")]
                int min_interval_ms = 0
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

                    var resolvedId = string.IsNullOrWhiteSpace(id) ? $"0x{addr:X}" : id.Trim();

                    if (size is not (1 or 2 or 4 or 8))
                        return new
                        {
                            success = false,
                            error = "Hardware breakpoint size must be 1, 2, 4, or 8",
                        };

                    var at = (access_type ?? "w").Trim().ToLowerInvariant();
                    if (at is not ("r" or "w" or "rw"))
                        return new
                        {
                            success = false,
                            error = "access_type must be 'r', 'w', or 'rw'",
                        };
                    if (max_hits <= 0 || max_hits > MaxTraceMaxHits)
                        return new
                        {
                            success = false,
                            error = $"max_hits must be between 1 and {MaxTraceMaxHits}",
                        };
                    if (min_interval_ms < 0 || min_interval_ms > MaxTraceMinIntervalMs)
                        return new
                        {
                            success = false,
                            error = $"min_interval_ms must be between 0 and {MaxTraceMinIntervalMs}",
                        };

                    EnsureTraceTables();

                    var existingCount = GetTraceBreakpointCount();
                    if (!HasTraceBreakpoint(resolvedId) && existingCount >= MaxHardwareBreakpoints)
                    {
                        return new
                        {
                            success = false,
                            error = "No free hardware breakpoint slots (max 4 debug registers)",
                        };
                    }

                    EnsureDebuggerStarted();

                    // Best-effort remove any existing breakpoint at same address.
                    _ = AdvancedDebugger.RemoveBreakpoint((long)addr);

                    var trigger = at == "w" ? BreakpointTrigger.Write : BreakpointTrigger.Access;
                    var callback = BuildTraceCallbackLua(
                        resolvedId,
                        addr,
                        $"hardware_data_{at}",
                        captureRegisters: true,
                        captureStack: false,
                        stackDepth: 0,
                        accessType: at,
                        dataSize: size,
                        captureValue: capture_value,
                        maxHits: max_hits,
                        minIntervalMs: min_interval_ms
                    );

                    var (ok, method, warning) = SetBreakpointWithFallbacks(
                        addr,
                        size,
                        trigger,
                        callback,
                        allowSoftwareFallback: false
                    );

                    if (!ok)
                        return new
                        {
                            success = false,
                            error = "Failed to set data breakpoint with debug-register and auto methods. Data breakpoints require hardware debug-register support.",
                        };

                    UpsertTraceBreakpoint(
                        resolvedId,
                        addr,
                        $"data_{at}",
                        method,
                        size,
                        max_hits,
                        min_interval_ms
                    );

                    return new
                    {
                        success = true,
                        id = resolvedId,
                        address = $"0x{addr:X}",
                        access_type = at,
                        method,
                        size,
                        warning,
                        max_hits,
                        min_interval_ms,
                    };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "trace_remove_breakpoint"),
            Description("Removes a previously set trace breakpoint by its ID.")
        ]
        public static object RemoveTraceBreakpoint([Description("The unique ID of the trace breakpoint to remove")] string id)
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(id))
                        return new { success = false, error = "id is required" };

                    EnsureTraceTables();

                    var addr = GetTraceBreakpointAddress(id);
                    if (!addr.HasValue)
                        return new { success = false, error = "Breakpoint not found" };

                    _ = AdvancedDebugger.RemoveBreakpoint((long)addr.Value);
                    RemoveTraceBreakpointState(id);

                    return new { success = true, id };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "trace_list_breakpoints"),
            Description("Lists all active trace breakpoints and their configurations.")
        ]
        public static object ListTraceBreakpoints()
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    EnsureTraceTables();
                    var result = LuaExecutor
                        .Execute(
                            @"
                            local bps = __ce_mcp_trace_breakpoints or {}
                            local out = {}
                            for id, bp in pairs(bps) do
                              local copy = {}
                              for k, v in pairs(bp) do copy[k] = v end
                              if bp.address then
                                copy.address = string.format('0x%X', bp.address)
                                copy.addressNumeric = bp.address
                              end
                              out[id] = copy
                            end
                            return out
                            "
                        )
                        .Value;
                    return new { success = true, breakpoints = result };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "trace_clear_all_breakpoints"),
            Description("Removes all active trace breakpoints and clears all logged hit buffers.")
        ]
        public static object ClearAllTraceBreakpoints()
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    var removed = ClearAllTraceBreakpointsUnsafe();
                    return new { success = true, removed };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        internal static int ClearAllTraceBreakpointsUnsafe()
        {
            EnsureTraceTables();

            var script =
                @"
                local bps = __ce_mcp_trace_breakpoints or {}
                local removed = 0
                for _, bp in pairs(bps) do
                  if bp and bp.address then
                    pcall(function() debug_removeBreakpoint(bp.address) end)
                    removed = removed + 1
                  end
                end
                __ce_mcp_trace_breakpoints = {}
                __ce_mcp_trace_hits = {}
                return removed
            ";

            var removed = LuaExecutor.Execute(script).Value;
            if (removed is int i)
                return i;
            if (removed is long l)
                return checked((int)l);
            if (removed is double d)
                return checked((int)d);
            return Convert.ToInt32(removed ?? 0, CultureInfo.InvariantCulture);
        }

        [
            McpServerTool(Name = "trace_get_hits"),
            Description(
                "Retrieves logged hits for one or all trace breakpoints. Hits include timestamps, registers, and stack data if configured."
            )
        ]
        public static object GetTraceHits(
            [Description("ID of the trace breakpoint to check, or null for all")] string? id = null, 
            [Description("Whether to clear the hit buffer after reading (true/false)")] bool clear = false, 
            [Description("Maximum number of hits to return in one call (default: 100)")] int max = 100)
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    EnsureTraceTables();

                    if (max <= 0 || max > MaxHitsReturn)
                        return new
                        {
                            success = false,
                            error = $"max must be between 1 and {MaxHitsReturn}",
                        };

                    // LuaExecutor truncates arrays beyond MaxTableEntries; clamp to keep
                    // the returned 'hits' list stable and avoid array->dict shape changes.
                    max = Math.Min(max, LuaExecutor.MaxTableEntries);

                    var idLit = id == null ? "nil" : ToLuaStringLiteral(id);
                    var clearLit = clear ? "true" : "false";

                    var script =
                        $@"
                        local id = {idLit}
                        local clear = {clearLit}
                        local max = {max}
                        local hitsTable = __ce_mcp_trace_hits or {{}}

                        local function tail_slice(list)
                          local count = #list
                          local start = 1
                          if count > max then start = count - max + 1 end
                          local out = {{}}
                          for i=start, count do out[#out+1] = list[i] end
                          return count, out
                        end

                        -- When clear=true, consume hits FIFO (oldest-first) and only remove
                        -- what we return. This avoids losing hits when the serializer limit
                        -- caps the returned list.
                        local function consume_fifo(list, n)
                          local count = #list
                          local take = n
                          if take > count then take = count end
                          local out = {{}}
                          for i=1, take do out[#out+1] = list[i] end
                          local remaining = {{}}
                          for i=take+1, count do remaining[#remaining+1] = list[i] end
                          return count, out, remaining
                        end

                        if id ~= nil then
                          local list = hitsTable[id] or {{}}
                          local mode = clear and 'consume_fifo' or 'tail_slice'
                          local count, out
                          if clear then
                            count, out, list = consume_fifo(list, max)
                            hitsTable[id] = list
                          else
                            count, out = tail_slice(list)
                          end
                          __ce_mcp_trace_hits = hitsTable
                          return {{ success=true, id=id, count=count, returned=#out, hits=out, mode=mode, serializer_max={LuaExecutor.MaxTableEntries}, max=max }}
                        else
                          local mode = clear and 'consume_fifo' or 'tail_slice'
                          if clear then
                            local ids = {{}}
                            local total = 0
                            for k, list in pairs(hitsTable) do
                              ids[#ids+1] = k
                              total = total + #list
                            end
                            table.sort(ids)

                            local budget = max
                            local out = {{}}
                            local returned_by_id = {{}}

                            for _, bid in ipairs(ids) do
                              if budget <= 0 then break end
                              local list = hitsTable[bid] or {{}}
                              local count = #list
                              if count > 0 then
                                local take = budget
                                if take > count then take = count end
                                returned_by_id[bid] = take
                                for i=1, take do out[#out+1] = list[i] end
                                local remaining = {{}}
                                for i=take+1, count do remaining[#remaining+1] = list[i] end
                                hitsTable[bid] = remaining
                                budget = budget - take
                              end
                            end

                            __ce_mcp_trace_hits = hitsTable
                            return {{ success=true, id=nil, count=total, returned=#out, returned_by_id=returned_by_id, hits=out, mode=mode, serializer_max={LuaExecutor.MaxTableEntries}, max=max }}
                          else
                            local combined = {{}}
                            for _, list in pairs(hitsTable) do
                              for i=1, #list do combined[#combined+1] = list[i] end
                            end
                            local count, out = tail_slice(combined)
                            return {{ success=true, id=nil, count=count, returned=#out, hits=out, mode=mode, serializer_max={LuaExecutor.MaxTableEntries}, max=max }}
                          end
                        end
                    ";

                    var result = LuaExecutor.Execute(script).Value;
                    return result ?? new { success = false, error = "No response" };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        private static void EnsureDebuggerStarted()
        {
            if (AdvancedDebugger.IsDebugging())
                return;

            _ = AdvancedDebugger.StartDebugger(0);
        }


        private static void EnsureTraceTables()
        {
            LuaExecutor.Execute(
                "__ce_mcp_trace_breakpoints = __ce_mcp_trace_breakpoints or {}; __ce_mcp_trace_hits = __ce_mcp_trace_hits or {}; return true"
            );
        }

        private static int GetTraceBreakpointCount()
        {
            var script =
                @"
                local bps = __ce_mcp_trace_breakpoints or {}
                local c = 0
                for _ in pairs(bps) do c = c + 1 end
                return c
            ";
            var res = LuaExecutor.Execute(script).Value;
            return res is int i ? i : Convert.ToInt32(res, CultureInfo.InvariantCulture);
        }

        private static bool HasTraceBreakpoint(string id)
        {
            var script =
                $@"return (__ce_mcp_trace_breakpoints or {{}})[{ToLuaStringLiteral(id)}] ~= nil";
            var res = LuaExecutor.Execute(script).Value;
            return res is bool b && b;
        }

        private static ulong? GetTraceBreakpointAddress(string id)
        {
            var script =
                $@"
                local bp = (__ce_mcp_trace_breakpoints or {{}})[{ToLuaStringLiteral(id)}]
                if bp and bp.address then return bp.address end
                return nil
            ";
            var res = LuaExecutor.Execute(script).Value;
            if (res is null)
                return null;

            if (res is long l)
                return unchecked((ulong)l);
            if (res is int i)
                return unchecked((ulong)i);
            if (res is double d)
                return unchecked((ulong)d);

            return Convert.ToUInt64(res, CultureInfo.InvariantCulture);
        }

        private static void UpsertTraceBreakpoint(
            string id,
            ulong address,
            string type,
            string method,
            int size,
            int maxHits,
            int minIntervalMs
        )
        {
            var script =
                $@"
                local id = {ToLuaStringLiteral(id)}
                __ce_mcp_trace_breakpoints = __ce_mcp_trace_breakpoints or {{}}
                __ce_mcp_trace_hits = __ce_mcp_trace_hits or {{}}
                __ce_mcp_trace_breakpoints[id] = {{
                  id = id,
                  address = {address},
                  addressHex = {ToLuaStringLiteral($"0x{address:X}")},
                  type = {ToLuaStringLiteral(type)},
                  method = {ToLuaStringLiteral(method)},
                  size = {size},
                  max_hits = {maxHits},
                  min_interval_ms = {minIntervalMs},
                  total_hits = 0,
                  skipped_hits = 0,
                  disabled = false
                }}
                __ce_mcp_trace_hits[id] = __ce_mcp_trace_hits[id] or {{}}
                return true
            ";
            _ = LuaExecutor.Execute(script);
        }

        private static void RemoveTraceBreakpointState(string id)
        {
            var script =
                $@"
                local id = {ToLuaStringLiteral(id)}
                if __ce_mcp_trace_breakpoints then __ce_mcp_trace_breakpoints[id] = nil end
                if __ce_mcp_trace_hits then __ce_mcp_trace_hits[id] = nil end
                return true
            ";
            _ = LuaExecutor.Execute(script);
        }

        private static string BuildTraceCallbackLua(
            string id,
            ulong address,
            string breakpointType,
            bool captureRegisters,
            bool captureStack,
            int stackDepth,
            string? accessType = null,
            int? dataSize = null,
            bool captureValue = false,
            int maxHits = DefaultTraceMaxHits,
            int minIntervalMs = 0
        )
        {
            var idLit = ToLuaStringLiteral(id);
            var bpTypeLit = ToLuaStringLiteral(breakpointType);
            var captureRegsLit = captureRegisters ? "true" : "false";
            var captureStackLit = captureStack ? "true" : "false";

            var accessTypeLit = string.IsNullOrWhiteSpace(accessType)
                ? "nil"
                : ToLuaStringLiteral(accessType.Trim());
            var sizeLit = dataSize.HasValue
                ? dataSize.Value.ToString(CultureInfo.InvariantCulture)
                : "nil";
            var captureValueLit = captureValue ? "true" : "false";
            var hitCapLit = MaxHitsStoredPerId.ToString(CultureInfo.InvariantCulture);
            var maxHitsLit = maxHits.ToString(CultureInfo.InvariantCulture);
            var minIntervalSecondsLit = (minIntervalMs / 1000.0).ToString(CultureInfo.InvariantCulture);

            return $@"
                local id = {idLit}
                local addr = {address}
                local access_type = {accessTypeLit}
                local data_size = {sizeLit}
                local capture_value = {captureValueLit}
                local max_hits = {maxHitsLit}
                local min_interval_seconds = {minIntervalSecondsLit}

                __ce_mcp_trace_breakpoints = __ce_mcp_trace_breakpoints or {{}}
                local bp = __ce_mcp_trace_breakpoints[id] or {{}}
                bp.total_hits = (bp.total_hits or 0) + 1
                __ce_mcp_trace_breakpoints[id] = bp

                local function continue_process()
                  pcall(function() debug_continueFromBreakpoint(co_run) end)
                end

                if max_hits > 0 and bp.total_hits > max_hits then
                  bp.disabled = true
                  bp.disabled_reason = 'max_hits'
                  bp.disabled_at_hit = bp.total_hits
                  pcall(function() debug_removeBreakpoint(addr) end)
                  continue_process()
                  return 1
                end

                if min_interval_seconds > 0 then
                  local now = os.clock()
                  local last = bp.last_log_clock
                  if last ~= nil and (now - last) < min_interval_seconds then
                    bp.skipped_hits = (bp.skipped_hits or 0) + 1
                    continue_process()
                    return 1
                  end
                  bp.last_log_clock = now
                end

                local is64 = false
                pcall(function() is64 = targetIs64Bit() end)

                local hit = {{
                  id = id,
                  address = string.format('0x%X', addr),
                  timestamp = os.time(),
                  hit_number = bp.total_hits,
                  skipped_hits = bp.skipped_hits or 0,
                  max_hits = max_hits,
                  min_interval_ms = {minIntervalMs},
                  breakpoint_type = {bpTypeLit},
                  arch = is64 and 'x64' or 'x86'
                }}

                if access_type ~= nil then hit.access_type = access_type end
                if data_size ~= nil then hit.size = data_size end

                __ce_mcp_trace_hits = __ce_mcp_trace_hits or {{}}
                __ce_mcp_trace_hits[id] = __ce_mcp_trace_hits[id] or {{}}

                if {captureRegsLit} or {captureStackLit} then
                  pcall(function() debug_getContext(false) end)
                end

                if {captureRegsLit} then
                  if is64 then
                    hit.registers = {{
                      RAX=RAX, RBX=RBX, RCX=RCX, RDX=RDX,
                      RSI=RSI, RDI=RDI, RBP=RBP, RSP=RSP, RIP=RIP,
                      R8=R8, R9=R9, R10=R10, R11=R11, R12=R12, R13=R13, R14=R14, R15=R15
                    }}
                  else
                    hit.registers = {{
                      EAX=EAX, EBX=EBX, ECX=ECX, EDX=EDX,
                      ESI=ESI, EDI=EDI, EBP=EBP, ESP=ESP, EIP=EIP
                    }}
                  end
                end

                pcall(function()
                  if is64 then
                    hit.instruction_pointer = string.format('0x%X', RIP or 0)
                  else
                    hit.instruction_pointer = string.format('0x%X', EIP or 0)
                  end
                end)

                if {captureStackLit} and {stackDepth} > 0 then
                  local sp = is64 and (RSP or 0) or (ESP or 0)
                  local step = is64 and 8 or 4
                  local out = {{}}
                  for i=0, {stackDepth}-1 do
                    local a = sp + (i*step)
                    local ok, v = pcall(function()
                      if is64 then return readQword(a) else return readInteger(a) end
                    end)
                    if ok and v then
                      out[#out+1] = {{ address = string.format('0x%X', a), value = string.format('0x%X', v) }}
                    end
                  end
                  hit.stack = out
                end

                if capture_value and data_size ~= nil and data_size > 0 then
                  local function readValueHex(a, sz)
                    local ok, bytes = pcall(function() return readBytes(a, sz, true) end)
                    if not ok or type(bytes) ~= 'table' then return nil end
                    local parts = {{}}
                    for i=1, #bytes do
                      parts[#parts+1] = string.format('%02X', bytes[i] or 0)
                    end
                    return table.concat(parts, ' ')
                  end
                  hit.value = readValueHex(addr, data_size)
                end

                pcall(function()
                  local ip = RIP or EIP
                  if ip then hit.instruction = disassemble(ip) end
                end)

                table.insert(__ce_mcp_trace_hits[id], hit)

                -- Keep only the last N hits to avoid unbounded memory growth.
                -- Drop oldest-first.
                local cap = {hitCapLit}
                local list = __ce_mcp_trace_hits[id]
                local overflow = #list - cap
                if overflow > 0 then
                  for i=1, overflow do table.remove(list, 1) end
                end

                continue_process()
                return 1
            ";
        }

        private static (bool ok, string method, string? warning) SetBreakpointWithFallbacks(
            ulong address,
            int size,
            BreakpointTrigger trigger,
            string callback,
            bool allowSoftwareFallback
        )
        {
            if (
                TrySetBreakpoint(
                    address,
                    size,
                    trigger,
                    BreakpointMethod.DebugRegister,
                    callback
                )
            )
            {
                return (true, "hardware_debug_register", null);
            }

            _ = AdvancedDebugger.RemoveBreakpoint((long)address);

            if (TrySetBreakpoint(address, size, trigger, BreakpointMethod.Auto, callback))
            {
                return (
                    true,
                    "auto",
                    "Hardware debug-register breakpoint failed; Cheat Engine auto-selected a fallback method."
                );
            }

            if (!allowSoftwareFallback)
                return (false, "", null);

            _ = AdvancedDebugger.RemoveBreakpoint((long)address);

            if (TrySetBreakpoint(address, size, trigger, BreakpointMethod.Int3, callback))
            {
                return (
                    true,
                    "software_int3",
                    "Hardware and auto breakpoint methods failed; using INT3 software breakpoint, which temporarily patches target code."
                );
            }

            return (false, "", null);
        }

        private static bool TrySetBreakpoint(
            ulong address,
            int size,
            BreakpointTrigger trigger,
            BreakpointMethod method,
            string callback
        )
        {
            try
            {
                return AdvancedDebugger.SetBreakpoint(
                    (long)address,
                    size,
                    trigger,
                    method,
                    callback
                );
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(ex);
                return false;
            }
        }

        private static string ToLuaStringLiteral(string value)
        {
            var escaped = value
                .Replace("\\", "\\\\", StringComparison.Ordinal)
                .Replace("'", "\\'", StringComparison.Ordinal)
                .Replace("\r", "\\r", StringComparison.Ordinal)
                .Replace("\n", "\\n", StringComparison.Ordinal)
                .Replace("\t", "\\t", StringComparison.Ordinal);
            return $"'{escaped}'";
        }
    }
}
