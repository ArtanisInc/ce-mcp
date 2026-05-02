using System;
using System.ComponentModel;
using System.Linq;
using System.Security.Cryptography;
using CEMCP;
using CESDK.Classes;
using ModelContextProtocol.Server;

namespace Tools
{
    /// <summary>
    /// Tools for reading, writing, and allocating memory in the target process.
    /// </summary>
    [McpServerToolType]
    public class MemoryTool
    {
        private const int MaxReadBytes = 65536;
        private const int MaxWriteBytes = 65536;
        private const int MaxStringLength = 65536;
        private const int MaxChecksumBytes = 64 * 1024 * 1024;

        private MemoryTool() { }

        [
            McpServerTool(Name = "read_memory"),
            Description("Reads data of various types (integers, floats, strings, or raw bytes) from the target process memory.")
        ]
        public static object ReadMemory(
            [Description("Memory address expression to read from")] string address,
            [Description("Data type to read: 'bytes', 'int32', 'int64', 'float', 'double', 'string', 'byte', 'short'")]
                string dataType,
            [Description("Number of bytes to read (only for 'bytes' type, max 65536)")] string? byteCount = null,
            [Description("Maximum number of characters to read (only for 'string' type, max 65536)")] string? maxLength = null,
            [Description("Whether to read as a UTF-16/Wide string (true/false)")] string wideChar = "false"
        )
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
                    if (string.IsNullOrWhiteSpace(address))
                        return new { success = false, error = "Address parameter is required" };

                    if (string.IsNullOrWhiteSpace(dataType))
                        return new { success = false, error = "DataType parameter is required" };

                    if (!ValidationHelper.TryResolveAddress(address, out ulong addr))
                        return new { success = false, error = "Invalid address format" };

                    bool isWide = wideChar.Equals("true", StringComparison.OrdinalIgnoreCase);

                    var normalizedDataType = dataType.Trim().ToLowerInvariant();
                    if (normalizedDataType == "bytes")
                    {
                        if (
                            string.IsNullOrEmpty(byteCount)
                            || !int.TryParse(byteCount, out var bc)
                            || bc <= 0
                            || bc > MaxReadBytes
                        )
                        {
                            throw new ArgumentException(
                                $"ByteCount is required for bytes and must be between 1 and {MaxReadBytes}"
                            );
                        }

                        var bytes = MemoryAccess.ReadBytes(addr, bc);
                        return new
                        {
                            success = true,
                            value = BytesToHex(bytes),
                            bytes,
                            count = bytes.Length,
                            requestedCount = bc,
                        };
                    }

                    object value = normalizedDataType switch
                    {
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
            Description("Writes data of various types into the target process memory. WARNING: Use with caution as incorrect writes can crash the target.")
        ]
        public static object WriteMemory(
            [Description("Memory address expression to write to")] string address,
            [Description("Data type to write: 'bytes', 'int32', 'int64', 'float', 'double', 'string', 'byte', 'short'")]
                string dataType,
            [Description("Value to write, formatted appropriately for the selected type")] string value,
            [Description("Maximum length (only for 'string' type)")] string? maxLength = null,
            [Description("Whether to write as a UTF-16/Wide string (true/false)")] string wideChar = "false"
        )
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
                    if (string.IsNullOrWhiteSpace(address))
                        return new { success = false, error = "Address parameter is required" };

                    if (string.IsNullOrWhiteSpace(dataType))
                        return new { success = false, error = "DataType parameter is required" };

                    if (string.IsNullOrWhiteSpace(value))
                        return new { success = false, error = "Value parameter is required" };

                    if (!ValidationHelper.TryResolveAddress(address, out ulong addr))
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
            McpServerTool(Name = "checksum_memory"),
            Description("Calculates a cryptographic hash (MD5, SHA1, or SHA256) of a memory region. Useful for verifying integrity or identifying code versions.")
        ]
        public static object ChecksumMemory(
            [Description("Start address expression")] string address,
            [Description("Number of bytes to include in the hash (max 64MB)")] int length,
            [Description("Hashing algorithm to use: 'md5', 'sha1', or 'sha256' (default)")] string algorithm = "sha256",
            [Description("Internal buffer size for reading (default: 65536)")] int chunkSize = MaxReadBytes,
            [Description("Whether to read from Cheat Engine's local memory instead of the target process (true/false)")]
                string local = "false"
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                if (
                    !ValidationHelper.IsProcessAttached()
                    && !local.Equals("true", StringComparison.OrdinalIgnoreCase)
                )
                {
                    return new
                    {
                        success = false,
                        error = "No process is attached. Please open a process first using 'open_process' tool.",
                    };
                }

                try
                {
                    if (string.IsNullOrWhiteSpace(address))
                        return new { success = false, error = "Address parameter is required" };

                    if (length <= 0)
                        return new { success = false, error = "Length must be > 0" };
                    if (length > MaxChecksumBytes)
                    {
                        return new
                        {
                            success = false,
                            error = $"Length too large (max {MaxChecksumBytes} bytes)",
                        };
                    }

                    if (chunkSize <= 0)
                        return new { success = false, error = "ChunkSize must be > 0" };
                    if (chunkSize > MaxReadBytes)
                        chunkSize = MaxReadBytes;

                    if (!ValidationHelper.TryResolveAddress(address, out ulong addr))
                        return new { success = false, error = "Unable to resolve address" };

                    bool isLocal = local.Equals("true", StringComparison.OrdinalIgnoreCase);
                    var algo = (algorithm ?? "").Trim().ToLowerInvariant();

                    // Fast-path: use CE's md5memory to avoid transferring bytes.
                    if (!isLocal && (algo == "md5"))
                    {
                        try
                        {
                            var probe = LuaExecutor.Execute("return type(md5memory)=='function'");
                            if (probe.Value is bool hasMd5Memory && hasMd5Memory)
                            {
                                var luaRes = LuaExecutor.Execute(
                                    $"return md5memory(0x{addr:X}, {length})"
                                );

                                var md5 = luaRes.Value?.ToString() ?? "";
                                if (!string.IsNullOrWhiteSpace(md5))
                                {
                                    return new
                                    {
                                        success = true,
                                        algorithm = "md5",
                                        address = $"0x{addr:X}",
                                        length,
                                        checksum = md5.Trim().ToLowerInvariant(),
                                    };
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Debug.WriteLine(ex);
                        }

                        // Fall back to managed hashing when md5memory is unavailable.
                    }

                    using var hasher = algo switch
                    {
                        "md5" => IncrementalHash.CreateHash(HashAlgorithmName.MD5),
                        "sha1" => IncrementalHash.CreateHash(HashAlgorithmName.SHA1),
                        "sha256" or "" => IncrementalHash.CreateHash(HashAlgorithmName.SHA256),
                        _ => throw new ArgumentException($"Unsupported algorithm: {algorithm}"),
                    };

                    int remaining = length;
                    ulong current = addr;
                    while (remaining > 0)
                    {
                        int readCount = Math.Min(remaining, chunkSize);
                        byte[] bytes = isLocal
                            ? MemoryAccess.ReadBytesLocal(current, readCount)
                            : MemoryAccess.ReadBytes(current, readCount);
                        hasher.AppendData(bytes);
                        remaining -= readCount;
                        current = checked(current + (ulong)readCount);
                    }

                    var hash = hasher.GetHashAndReset();
                    var checksum = Convert.ToHexString(hash).ToLowerInvariant();

                    return new
                    {
                        success = true,
                        algorithm = algo == "" ? "sha256" : algo,
                        address = $"0x{addr:X}",
                        length,
                        checksum,
                    };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "allocate_memory"),
            Description("Allocates a new region of executable memory in the target process.")
        ]
        public static object AllocateMemory(
            [Description("Optional address where memory should ideally be allocated")] string? preferredAddress = null, 
            [Description("Number of bytes to allocate (default: 4096)")] int size = 4096)
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    ulong prefAddr = 0;
                    if (
                        !string.IsNullOrEmpty(preferredAddress)
                        && !ValidationHelper.TryResolveAddress(preferredAddress, out prefAddr)
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
            Description("Frees a previously allocated memory region in the target process.")
        ]
        public static object DeAllocate(
            [Description("Start address of the region to free")] string address, 
            [Description("Size of the region (use 0 for auto-detection if supported)")] int size = 0)
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(address))
                        return new { success = false, error = "Address parameter is required" };

                    if (!ValidationHelper.TryResolveAddress(address, out ulong addr))
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
            Description("Changes the protection flags for a memory region in the target process.")
        ]
        public static object SetMemoryProtection(
            [Description("Start address of the region")] string address,
            [Description("Size of the region in bytes")] int size,
            [Description("Enable read access (true/false)")] bool readable = true,
            [Description("Enable write access (true/false)")] bool writable = true,
            [Description("Enable execute access (true/false)")] bool executable = false
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(address))
                        return new { success = false, error = "Address parameter is required" };

                    if (!ValidationHelper.TryResolveAddress(address, out ulong addr))
                        return new { success = false, error = "Invalid address format" };

                    if (size <= 0)
                        return new { success = false, error = "Size must be > 0" };

                    bool changed = readable && writable && executable
                        ? MemoryAllocator.FullAccess((long)addr, size)
                        : MemoryAllocator.SetMemoryProtection(
                            (long)addr,
                            size,
                            readable,
                            writable,
                            executable
                        );

                    var verified = MemoryRegions.GetMemoryProtection(addr);
                    bool matches =
                        (!readable || verified.Read)
                        && (!writable || verified.Write)
                        && (!executable || verified.Execute)
                        && (readable || !verified.Read)
                        && (writable || !verified.Write)
                        && (executable || !verified.Execute);

                    return new
                    {
                        success = matches,
                        requested = new { read = readable, write = writable, execute = executable },
                        actual = new { read = verified.Read, write = verified.Write, execute = verified.Execute },
                        warning = !changed && matches
                            ? "Cheat Engine returned false, but verification shows protection already matches the requested flags."
                            : changed && !matches
                                ? "Cheat Engine reported success, but verification shows protection did not match the requested flags."
                                : null,
                    };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "set_full_access"),
            Description("Changes protection of a region to Read/Write/Execute (RWX).")
        ]
        public static object FullAccess(
            [Description("Start address of the region")] string address, 
            [Description("Size of the region in bytes")] int size)
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(address))
                        return new { success = false, error = "Address parameter is required" };

                    if (!ValidationHelper.TryResolveAddress(address, out ulong addr))
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

        private static string BytesToHex(byte[] bytes) =>
            string.Join(" ", bytes.Select(static b => b.ToString("X2")));

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
