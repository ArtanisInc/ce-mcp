# Cheat Engine MCP Server

Cheat Engine MCP Server is a Windows x64 Cheat Engine plugin that exposes Cheat Engine
capabilities as Model Context Protocol (MCP) tools over Server-Sent Events (SSE).

It is intended for authorized debugging, memory inspection, reverse-engineering workflows,
and automation around a locally running Cheat Engine instance.

[![FOSSA](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fhedgehogform%2Fce-mcp.svg?type=large&issueType=license)](https://app.fossa.com/projects/git%2Bgithub.com%2Fhedgehogform%2Fce-mcp?ref=badge_large&issueType=license)

## What it provides

- **MCP over SSE** at `http://localhost:6300/sse`.
- **Single Cheat Engine plugin DLL**: build `ce-mcp.dll` and load it from Cheat Engine.
- **Token-based access control** via the configuration window or `MCP_AUTH_TOKEN`.
- **Stable JSON tool responses** for process, memory, scan, symbol, disassembly, debugger, and tracing workflows.
- **CESDK bridge** over Cheat Engine's Lua API, with wrappers for memory access, scans, modules, symbols, debugger, and CE objects.
- **Safety-oriented fallbacks** for CE-version differences, including bounded scan behavior when CE does not expose a region-specific AOB API.

## Requirements

- Windows.
- Cheat Engine 7.6.2 or newer.
- .NET 10.0 SDK to build from source.
- .NET 10.0 desktop/runtime components available to Cheat Engine.
- A local MCP client that supports SSE.

> [!IMPORTANT]
> Cheat Engine installations may ship with a `ce.runtimeconfig.json` targeting an older
> .NET runtime. If the plugin fails to load with a .NET runtime error, update Cheat Engine's
> runtime config to target .NET 10.0 and include `Microsoft.AspNetCore.App`.

Example runtime config:

```json
{
  "runtimeOptions": {
    "tfm": "net10.0",
    "frameworks": [
      {
        "name": "Microsoft.NETCore.App",
        "version": "10.0.0",
        "rollForward": "latestMajor"
      },
      {
        "name": "Microsoft.WindowsDesktop.App",
        "version": "10.0.0",
        "rollForward": "latestMajor"
      },
      {
        "name": "Microsoft.AspNetCore.App",
        "version": "10.0.0",
        "rollForward": "latestMajor"
      }
    ]
  }
}
```

## Build

```powershell
git submodule update --init --recursive
dotnet build CeMCP.sln -c Release
```

The plugin DLL is produced at:

```text
bin/x64/Release/net10.0-windows/ce-mcp.dll
```

## Install in Cheat Engine

1. Build or download `ce-mcp.dll`.
2. Copy it into Cheat Engine's plugin directory.
3. Start Cheat Engine.
4. Enable the plugin from Cheat Engine's plugin manager.
5. Configure an MCP token from the plugin configuration UI, or set `MCP_AUTH_TOKEN`.

## MCP client configuration

Basic SSE configuration:

```json
{
  "mcpServers": {
    "cheat-engine": {
      "url": "http://localhost:6300/sse"
    }
  }
}
```

If your MCP client supports headers, send:

```text
Authorization: Bearer <token>
```

If it does not support custom headers, use:

```text
http://localhost:6300/sse?token=<token>
```

## Security model

This plugin exposes powerful Cheat Engine primitives: Lua execution, memory read/write,
auto-assemble, debugger operations, and breakpoint tracing. Treat access to the MCP endpoint
as equivalent to local administrative debugging access.

Security defaults:

- A token is required unless explicitly configured otherwise for local development.
- Non-loopback binding is refused by default.
- To bind outside loopback, set `MCP_ALLOW_NON_LOOPBACK=true` and use a strong token.
- Generated tokens are not printed if configuration persistence fails.

## Architecture

```text
MCP client
  -> SSE endpoint (:6300/sse)
  -> ASP.NET Core MCP server
  -> Tool classes in src/Tools
  -> CESDK managed wrappers
  -> Cheat Engine Lua API
  -> Target process
```

Key components:

- `src/McpServer.cs` - plugin server lifecycle.
- `src/ServerConfig.cs` - endpoint, token, and binding configuration.
- `src/Tools/*.cs` - MCP tool surface.
- `CESDK/src/Classes/*.cs` - managed wrappers around Cheat Engine Lua and CE objects.

## MCP tools

### Process and modules

| Tool                   | Purpose                                                     |
| ---------------------- | ----------------------------------------------------------- |
| `get_process_list`     | List running processes.                                     |
| `open_process`         | Attach Cheat Engine to a process by name or PID.            |
| `list_modules`         | List modules for the current or specified process.          |
| `enum_modules`         | Enumerate modules with base, size, bitness, and path.       |
| `get_module_size`      | Return the size of a loaded module.                         |
| `list_memory_regions`  | List memory regions from the process tool surface.          |
| `enum_memory_regions`  | Enumerate memory regions with protection/state/type fields. |
| `get_pointer_size`     | Get or set pointer size used by CE for the target.          |
| `reinitialize_symbols` | Reload/re-parse symbols.                                    |
| `enable_symbols`       | Enable Windows or kernel symbol support.                    |
| `get_symbol_info`      | Return symbol metadata.                                     |

### Address resolution and symbols

| Tool                    | Purpose                                                  |
| ----------------------- | -------------------------------------------------------- |
| `resolve_address`       | Resolve CE address expressions to numeric addresses.     |
| `get_name_from_address` | Convert an address to symbol/module text when available. |
| `get_rtti_classname`    | Resolve RTTI class names for C++ objects when available. |

### Memory access

| Tool                    | Purpose                                                        |
| ----------------------- | -------------------------------------------------------------- |
| `read_memory`           | Read bytes, integers, floats, doubles, and strings.            |
| `write_memory`          | Write bytes, integers, floats, doubles, and strings.           |
| `read_pointer_chain`    | Resolve pointer chains and read final values.                  |
| `allocate_memory`       | Allocate executable target memory.                             |
| `deallocate_memory`     | Free allocated target memory.                                  |
| `set_full_access`       | Change a region to read/write/execute.                         |
| `set_memory_protection` | Set explicit read/write/execute flags and verify actual flags. |
| `get_memory_protection` | Read actual memory protection flags.                           |
| `checksum_memory`       | Hash a memory region with MD5, SHA1, or SHA256.                |

### Scanning

| Tool                           | Purpose                                                                        |
| ------------------------------ | ------------------------------------------------------------------------------ |
| `aob_scan`                     | Scan for an Array of Bytes pattern.                                            |
| `memory_scan`                  | Start an exact/typed memory scan (`vtDword`, `vtString`, `vtByteArray`, etc.). |
| `get_scan_results`             | Retrieve results from a background scan.                                       |
| `reset_memory_scan`            | Reset the main or named scanner.                                               |
| `cleanup_independent_scanners` | Destroy named independent scanners.                                            |
| `generate_signature`           | Generate a bounded exact AOB signature; uniqueness is reported explicitly.     |
| `find_references`              | Scan a bounded range for raw pointers to an address.                           |
| `find_call_references`         | Scan a bounded range for direct/indirect CALL references.                      |

### Disassembly and assembly

| Tool                         | Purpose                                                           |
| ---------------------------- | ----------------------------------------------------------------- |
| `disassemble`                | Disassemble one instruction or get its size.                      |
| `disassemble_range`          | Disassemble a sequence of instructions.                           |
| `disassemble_range_detailed` | Return parsed instruction details.                                |
| `disassemble_bytes`          | Disassemble raw bytes.                                            |
| `get_instruction_info`       | Return address, size, bytes, mnemonic, operands, and branch info. |
| `get_previous_opcodes`       | Estimate previous instruction boundaries.                         |
| `get_function_range`         | Estimate function start/end around an address.                    |
| `assemble`                   | Assemble one instruction into bytes.                              |
| `auto_assemble_check`        | Validate an Auto Assemble script.                                 |
| `auto_assemble`              | Execute an Auto Assemble script.                                  |
| `generate_api_hook_script`   | Generate a CE API hook script template.                           |
| `set_comment`                | Set a Memory View comment.                                        |

### Debugger and trace

| Tool                          | Purpose                                                          |
| ----------------------------- | ---------------------------------------------------------------- |
| `debugger_start`              | Start CE's debugger for the current process.                     |
| `debugger_stop`               | Stop the debugger.                                               |
| `debugger_status`             | Return current debugger state.                                   |
| `debugger_set_breakpoint`     | Set a debugger breakpoint.                                       |
| `debugger_remove_breakpoint`  | Remove one debugger breakpoint.                                  |
| `debugger_clear_breakpoints`  | Remove debugger breakpoints.                                     |
| `debugger_get_breakpoints`    | List debugger breakpoints.                                       |
| `debugger_continue`           | Continue from a break.                                           |
| `debugger_get_context`        | Read CPU context.                                                |
| `debugger_set_register`       | Set a CPU register value.                                        |
| `trace_set_breakpoint`        | Set a non-blocking execution trace breakpoint.                   |
| `trace_set_data_breakpoint`   | Set a non-blocking hardware data breakpoint.                     |
| `trace_list_breakpoints`      | List trace breakpoints; addresses include hex and numeric forms. |
| `trace_get_hits`              | Retrieve captured trace hits.                                    |
| `trace_remove_breakpoint`     | Remove one trace breakpoint.                                     |
| `trace_clear_all_breakpoints` | Clear trace breakpoints and hit buffers.                         |

### Cheat table/address list

| Tool                   | Purpose                                                             |
| ---------------------- | ------------------------------------------------------------------- |
| `get_address_list`     | List active cheat table records.                                    |
| `add_memory_record`    | Add a record, including pointer records with offsets.               |
| `update_memory_record` | Update description, address, type, offsets, value, or active state. |
| `delete_memory_record` | Delete a record by ID, index, or description.                       |
| `clear_address_list`   | Remove all records.                                                 |

### Utility and runtime

| Tool             | Purpose                                                            |
| ---------------- | ------------------------------------------------------------------ |
| `execute_lua`    | Execute Lua in Cheat Engine. Use only for trusted local workflows. |
| `convert_string` | Convert ANSI/UTF-8 or compute MD5.                                 |
| `get_speedhack`  | Read CE speedhack state.                                           |
| `set_speedhack`  | Enable/disable or set CE speedhack speed.                          |

## Scan behavior notes

- `AOBScan` in Cheat Engine is process-wide. Tools that accept `startAddress` and
  `stopAddress` must not silently fall back to global scans.
- `AOBScanRegion` is not available in every Cheat Engine build. When unavailable,
  bounded scans use a safe fallback strategy.
- Small and medium bounded ranges use a direct `readBytes` fallback.
- Very large bounded ranges avoid unexpected long manual scans and prefer CE's `MemScan`
  path where applicable.
- `generate_signature` returns an exact local signature and reports `uniqueVerified`.
  If `uniqueVerified` is `false`, do not treat the signature as globally unique.

## Development

```powershell
dotnet build CeMCP.sln -c Release
dotnet test CeMCP.sln -c Release --no-build
```

The project treats warnings as errors. Keep changes small and verify against a live Cheat
Engine instance when touching tool behavior.

## License

See [LICENSE](LICENSE).
