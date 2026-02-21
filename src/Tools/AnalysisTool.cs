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

        private AnalysisTool() { }

        [
            McpServerTool(Name = "read_pointer_chain"),
            Description(
                "Resolve a pointer chain (base + deref + offsets) and optionally read a value at the final address"
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
            string? byteCount = null,
            string? maxLength = null,
            string wideChar = "false"
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    ProcessValidator.EnsureProcessOpen("read_pointer_chain");

                    if (string.IsNullOrWhiteSpace(baseAddress))
                        return new { success = false, error = "baseAddress is required" };

                    if (!TryResolveAddress(baseAddress, out var current))
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
                "Generate a unique AOB signature for an address using Cheat Engine getUniqueAOB"
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
                    ProcessValidator.EnsureProcessOpen("generate_signature");

                    if (!TryResolveAddress(address, out var addr))
                        return new { success = false, error = "Unable to resolve address" };

                    var script = $"return getUniqueAOB(0x{addr:X})";
                    var result = LuaExecutor.Execute(script);

                    if (result.ReturnCount == 0)
                        return new { success = false, error = "getUniqueAOB returned no values" };

                    if (result.ReturnCount == 1)
                    {
                        return new
                        {
                            success = true,
                            address = $"0x{addr:X}",
                            signature = result.Value?.ToString() ?? "",
                            offset = 0,
                        };
                    }

                    var values = result.Values ?? new List<object?>();
                    var signature = values.ElementAtOrDefault(0)?.ToString() ?? "";
                    var offset = CoerceLong(values.ElementAtOrDefault(1));

                    return new
                    {
                        success = true,
                        address = $"0x{addr:X}",
                        signature,
                        offset,
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
            Description("Get RTTI class name for an object address (getRTTIClassName)")
        ]
        public static object GetRttiClassname(
            [Description("Address expression pointing to a C++ object")] string address
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    ProcessValidator.EnsureProcessOpen("get_rtti_classname");

                    if (!TryResolveAddress(address, out var addr))
                        return new { success = false, error = "Unable to resolve address" };

                    var script = $"return getRTTIClassName(0x{addr:X})";
                    var result = LuaExecutor.Execute(script);

                    return new
                    {
                        success = true,
                        address = $"0x{addr:X}",
                        className = result.Value?.ToString() ?? "",
                    };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
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
                if (!TryParseNumber(part, out var value))
                    throw new ArgumentException($"Invalid offset: {part}");
                list.Add(value);
            }
            return list;
        }

        private static bool TryResolveAddress(string address, out ulong resolved)
        {
            resolved = 0;
            if (TryParseNumber(address, out resolved))
                return true;

            var val = AddressResolver.GetAddressSafe(address, false);
            if (!val.HasValue || val.Value <= 0)
                return false;

            resolved = unchecked((ulong)val.Value);
            return true;
        }

        private static bool TryParseNumber(string text, out ulong value)
        {
            value = 0;
            var trimmed = text.Trim();
            if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                return ulong.TryParse(
                    trimmed[2..],
                    NumberStyles.HexNumber,
                    CultureInfo.InvariantCulture,
                    out value
                );
            }

            if (
                ulong.TryParse(
                    trimmed,
                    NumberStyles.Integer,
                    CultureInfo.InvariantCulture,
                    out value
                )
            )
                return true;

            return ulong.TryParse(
                trimmed,
                NumberStyles.HexNumber,
                CultureInfo.InvariantCulture,
                out value
            );
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
