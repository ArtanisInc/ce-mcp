using System;
using System.ComponentModel;
using System.Linq;
using CEMCP;
using CESDK.Classes;
using ModelContextProtocol.Server;

namespace Tools
{
    /// <summary>
    /// Memory read and write tools.
    /// </summary>
    [McpServerToolType]
    public class MemoryTool
    {
        private const int MaxReadBytes = 65536;
        private const int MaxWriteBytes = 65536;
        private const int MaxStringLength = 65536;

        private MemoryTool() { }

        /// <summary>
        /// Checks if a process is currently attached in Cheat Engine.
        /// </summary>
        private static bool IsProcessAttached()
        {
            int pid = Process.GetOpenedProcessID();
            return pid > 0;
        }

        [
            McpServerTool(Name = "read_memory"),
            Description("Read memory at the given address with the specified data type")
        ]
        public static object ReadMemory(
            [Description("Memory address as a hex string (e.g. '0x1234ABCD')")] string address,
            [Description("Data type: 'bytes', 'int32', 'int64', 'float', 'string'")]
                string dataType,
            string? byteCount = null,
            string? maxLength = null,
            string wideChar = "false"
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                if (!IsProcessAttached())
                    return new
                    {
                        success = false,
                        error = "No process is attached. Please open a process first using 'open_process' tool.",
                    };
                try
                {
                    if (string.IsNullOrWhiteSpace(address))
                        return new { success = false, error = "Address parameter is required" };

                    if (string.IsNullOrWhiteSpace(dataType))
                        return new { success = false, error = "DataType parameter is required" };

                    if (!TryParseAddress(address, out ulong addr))
                        return new { success = false, error = "Invalid address format" };

                    bool isWide = wideChar.Equals("true", StringComparison.OrdinalIgnoreCase);

                    object value = dataType.ToLower() switch
                    {
                        "bytes" => !string.IsNullOrEmpty(byteCount)
                        && int.TryParse(byteCount, out var bc)
                        && bc > 0
                        && bc <= MaxReadBytes
                            ? MemoryAccess.ReadBytes(addr, bc)
                            : throw new ArgumentException(
                                $"ByteCount is required for bytes and must be between 1 and {MaxReadBytes}"
                            ),

                        "integer" or "int32" or "int" => MemoryAccess.ReadInteger(addr),
                        "qword" or "int64" or "long" => MemoryAccess.ReadQword(addr),
                        "float" => MemoryAccess.ReadFloat(addr),
                        "double" => MemoryAccess.ReadDouble(addr),
                        "byte" => MemoryAccess.ReadByte(addr),
                        "int16" or "short" => MemoryAccess.ReadSmallInteger(addr),

                        "string" => !string.IsNullOrEmpty(maxLength)
                        && int.TryParse(maxLength, out var ml)
                        && ml > 0
                        && ml <= MaxStringLength
                            ? MemoryAccess.ReadString(addr, ml, isWide)
                            : throw new ArgumentException(
                                $"MaxLength is required for string and must be between 1 and {MaxStringLength}"
                            ),

                        _ => throw new NotSupportedException($"Unsupported data type: {dataType}"),
                    };

                    return new { success = true, value };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "write_memory"),
            Description("Write a value to memory at the given address")
        ]
        public static object WriteMemory(
            [Description("Memory address as hex string (e.g. '0x1234ABCD')")] string address,
            [Description("Data type: 'bytes', 'int32', 'int64', 'float', 'string'")]
                string dataType,
            [Description("Value to write (format depends on dataType)")] string value,
            string? maxLength = null,
            string wideChar = "false"
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                if (!IsProcessAttached())
                    return new
                    {
                        success = false,
                        error = "No process is attached. Please open a process first using 'open_process' tool.",
                    };

                try
                {
                    if (string.IsNullOrWhiteSpace(address))
                        return new { success = false, error = "Address parameter is required" };

                    if (string.IsNullOrWhiteSpace(dataType))
                        return new { success = false, error = "DataType parameter is required" };

                    if (string.IsNullOrWhiteSpace(value))
                        return new { success = false, error = "Value parameter is required" };

                    if (!TryParseAddress(address, out ulong addr))
                        return new { success = false, error = "Invalid address format" };

                    bool isWide = wideChar.Equals("true", StringComparison.OrdinalIgnoreCase);
                    int? ml =
                        !string.IsNullOrEmpty(maxLength)
                        && int.TryParse(maxLength, out var parsedMl)
                            ? parsedMl
                            : (int?)null;

                    if (ml.HasValue && (ml.Value <= 0 || ml.Value > MaxStringLength))
                    {
                        return new
                        {
                            success = false,
                            error = $"MaxLength must be between 1 and {MaxStringLength}",
                        };
                    }

                    object written = dataType.ToLower() switch
                    {
                        "bytes" => WriteBytes(addr, value),
                        "integer" or "int32" or "int" => WriteInt32(addr, value),
                        "qword" or "int64" or "long" => WriteInt64(addr, value),
                        "float" => WriteFloat(addr, value),
                        "double" => WriteDouble(addr, value),
                        "byte" => WriteByte(addr, value),
                        "int16" or "short" => WriteInt16(addr, value),
                        "string" => WriteString(addr, value, ml, isWide),
                        _ => throw new NotSupportedException($"Unsupported data type: {dataType}"),
                    };

                    return new { success = true, value = written };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "allocate_memory"),
            Description("Allocate memory in the target process")
        ]
        public static object AllocateMemory(string? preferredAddress = null, int size = 4096)
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    ulong prefAddr = 0;
                    if (
                        !string.IsNullOrEmpty(preferredAddress)
                        && !TryParseAddress(preferredAddress, out prefAddr)
                    )
                        return new { success = false, error = "Invalid preferred address format" };

                    long address = MemoryAllocator.AllocateMemory(
                        size,
                        prefAddr != 0 ? (long)prefAddr : null
                    );
                    return new { success = true, address = $"0x{address:X}" };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "deallocate_memory"),
            Description("Deallocate memory in the target process")
        ]
        public static object DeAllocate(string address, int size = 0)
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(address))
                        return new { success = false, error = "Address parameter is required" };

                    if (!TryParseAddress(address, out ulong addr))
                        return new { success = false, error = "Invalid address format" };

                    MemoryAllocator.DeAllocate((long)addr, size);
                    return new { success = true };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "set_memory_protection"),
            Description("Set memory protection for a region")
        ]
        public static object SetMemoryProtection(
            string address,
            int size,
            bool readable = true,
            bool writable = true,
            bool executable = false
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

                    MemoryAllocator.SetMemoryProtection(
                        (long)addr,
                        size,
                        readable,
                        writable,
                        executable
                    );
                    return new { success = true };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "set_full_access"),
            Description("Set full access (RWX) for a memory region")
        ]
        public static object FullAccess(string address, int size)
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(address))
                        return new { success = false, error = "Address parameter is required" };

                    if (!TryParseAddress(address, out ulong addr))
                        return new { success = false, error = "Invalid address format" };

                    MemoryAllocator.FullAccess((long)addr, size);
                    return new { success = true };
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

        private static object WriteBytes(ulong address, string value)
        {
            var bytes = value
                .Split([' ', ','], StringSplitOptions.RemoveEmptyEntries)
                .Select(b => Convert.ToByte(b, 16))
                .ToArray();

            if (bytes.Length == 0)
                throw new ArgumentException("Value must contain at least one byte");
            if (bytes.Length > MaxWriteBytes)
                throw new ArgumentException($"Too many bytes (max {MaxWriteBytes})");

            MemoryAccess.WriteBytes(address, bytes);
            return bytes;
        }

        private static object WriteByte(ulong address, string value)
        {
            var b = Convert.ToByte(value);
            MemoryAccess.WriteByte(address, b);
            return b;
        }

        private static object WriteInt16(ulong address, string value)
        {
            if (!short.TryParse(value, out short v))
                throw new ArgumentException("Value must be a valid int16");
            MemoryAccess.WriteSmallInteger(address, v);
            return v;
        }

        private static object WriteInt32(ulong address, string value)
        {
            if (!int.TryParse(value, out int v))
                throw new ArgumentException("Value must be a valid integer");
            MemoryAccess.WriteInteger(address, v);
            return v;
        }

        private static object WriteInt64(ulong address, string value)
        {
            if (!long.TryParse(value, out long v))
                throw new ArgumentException("Value must be a valid long");
            MemoryAccess.WriteQword(address, v);
            return v;
        }

        private static object WriteFloat(ulong address, string value)
        {
            if (!float.TryParse(value, out float v))
                throw new ArgumentException("Value must be a valid float");
            MemoryAccess.WriteFloat(address, v);
            return v;
        }

        private static object WriteDouble(ulong address, string value)
        {
            if (!double.TryParse(value, out double v))
                throw new ArgumentException("Value must be a valid double");
            MemoryAccess.WriteDouble(address, v);
            return v;
        }

        private static object WriteString(
            ulong address,
            string value,
            int? maxLength,
            bool wideChar
        )
        {
            string text = value;

            if (maxLength.HasValue && (maxLength.Value <= 0 || maxLength.Value > MaxStringLength))
                throw new ArgumentException($"MaxLength must be between 1 and {MaxStringLength}");

            if (maxLength.HasValue && text.Length > maxLength.Value)
                text = text[..maxLength.Value];

            if (text.Length > MaxStringLength)
                text = text[..MaxStringLength];

            MemoryAccess.WriteString(address, text, wideChar);
            return text;
        }
    }
}
