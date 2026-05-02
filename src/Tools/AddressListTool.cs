using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using CEMCP;
using CESDK.Classes;
using ModelContextProtocol.Server;
using static CESDK.CESDK;

namespace Tools
{
    /// <summary>
    /// Tools for managing Cheat Engine's Address List (cheat table entries).
    /// </summary>
    [McpServerToolType]
    public class AddressListTool
    {
        private AddressListTool() { }

        [
            McpServerTool(Name = "get_address_list"),
            Description("Retrieves all memory records currently in the active Cheat Engine address list (cheat table).")
        ]
        public static object GetAddressList()
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    var records = Synchronize(() =>
                    {
                        using var al = new AddressList();
                        var result = new List<object>();
                        for (int i = 0; i < al.Count; i++)
                        {
                            var r = al.GetMemoryRecord(i);
                            result.Add(
                                new
                                {
                                    id = r.ID,
                                    index = r.Index,
                                    description = r.Description,
                                    address = r.Address,
                                    value = r.Value,
                                    active = r.Active,
                                    offsets = GetOffsetsString(r),
                                }
                            );
                        }
                        return result;
                    });

                    return new
                    {
                        success = true,
                        count = records.Count,
                        records,
                    };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "add_memory_record"),
            Description("Adds a new memory record to the cheat table. Supports pointers with multiple offsets.")
        ]
        public static object AddMemoryRecord(
            [Description("Description for the memory record (label in the UI)")] string description = "New Entry",
            [Description("Base memory address or expression")] string address = "0",
            [Description(
                "Variable type: 'vtByte', 'vtWord', 'vtDword', 'vtQword', 'vtSingle', 'vtDouble', 'vtString', 'vtByteArray', 'vtCustom', 'vtPointer'"
            )]
                string varType = "vtDword",
            [Description("Initial value to set for the record")] string value = "0",
            [Description("Offsets as comma-separated hex/dec (e.g. '0x10, 0x20') if this is a pointer")]
                string offsets = ""
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    object? errorResult = null;
                    var record = Synchronize(() =>
                    {
                        using var al = new AddressList();
                        var r = al.CreateMemoryRecord();
                        r.Description = description;
                        r.Address = address;

                        if (Enum.TryParse<VariableType>(varType, true, out var vt))
                        {
                            r.VarType = vt;
                        }
                        else
                        {
                            errorResult = new { success = false, error = $"Invalid varType: {varType}" };
                            return null;
                        }

                        if (!string.IsNullOrEmpty(offsets))
                        {
                            var offsetList = ParseOffsets(offsets);
                            r.OffsetCount = offsetList.Count;
                            for (int i = 0; i < offsetList.Count; i++)
                            {
                                r.SetOffset(i, offsetList[i]);
                            }
                        }

                        // Setting Value may attempt to write memory / interpret value and can fail
                        // depending on target state / permissions. Do not fail the record creation.
                        string? valueError = null;
                        if (!string.IsNullOrEmpty(value))
                        {
                            try
                            {
                                r.Value = value;
                            }
                            catch (Exception ex)
                            {
                                valueError = ex.Message;
                            }
                        }

                        string? currentValue = null;
                        if (valueError == null)
                        {
                            try
                            {
                                currentValue = r.Value;
                            }
                            catch
                            {
                                currentValue = null;
                            }
                        }
                        return (object)new
                        {
                            id = r.ID,
                            description = r.Description,
                            address = r.Address,
                            offsets = GetOffsetsString(r),
                            value = currentValue,
                            valueSet = valueError == null,
                            valueError,
                        };
                    });

                    if (errorResult != null) return errorResult;

                    return new { success = true, record };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

#pragma warning disable S107 // Methods should not have too many parameters
        [
            McpServerTool(Name = "update_memory_record"),
            Description("Updates an existing memory record. Can modify description, address, type, value, and active state.")
        ]
        public static object UpdateMemoryRecord(
            [Description("Numeric ID of the record to update")] string id = "",
            [Description("0-based index of the record in the list")] string index = "",
            [Description("Exact description of the record to update")] string description = "",
            [Description("New description to set")] string newDescription = "",
            [Description("New memory address expression to set")] string newAddress = "",
            [Description("New variable type to set")] string newVarType = "",
            [Description("New value to write")] string newValue = "",
            [Description("Whether the record should be active/frozen (true/false)")] string active = "",
            [Description("New offsets as comma-separated hex/dec if this is a pointer")] string newOffsets = ""
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    object? errorResult = null;
                    var result = Synchronize(() =>
                    {
                        using var al = new AddressList();

                        int? targetId =
                            !string.IsNullOrEmpty(id) && int.TryParse(id, out var parsedId)
                                ? parsedId
                                : (int?)null;
                        int? targetIndex =
                            !string.IsNullOrEmpty(index) && int.TryParse(index, out var parsedIdx)
                                ? parsedIdx
                                : (int?)null;

                        var r = FindRecord(al, targetId, targetIndex, description);
                        if (r == null)
                            return null;

                        if (!string.IsNullOrEmpty(newDescription))
                            r.Description = newDescription;
                        if (!string.IsNullOrEmpty(newAddress))
                            r.Address = newAddress;
                        if (!string.IsNullOrEmpty(newVarType))
                        {
                            if (Enum.TryParse<VariableType>(newVarType, true, out var vt))
                            {
                                r.VarType = vt;
                            }
                            else
                            {
                                errorResult = new { success = false, error = $"Invalid varType: {newVarType}" };
                                return null;
                            }
                        }
                        if (!string.IsNullOrEmpty(newOffsets))
                        {
                            var offsetList = ParseOffsets(newOffsets);
                            r.OffsetCount = offsetList.Count;
                            for (int i = 0; i < offsetList.Count; i++)
                            {
                                r.SetOffset(i, offsetList[i]);
                            }
                        }
                        if (!string.IsNullOrEmpty(newValue))
                        {
                            try
                            {
                                r.Value = newValue;
                            }
                            catch (Exception ex)
                            {
                                // Don't fail other edits (e.g. description/address). Return the warning.
                                return new
                                {
                                    id = r.ID,
                                    description = r.Description,
                                    address = r.Address,
                                    offsets = GetOffsetsString(r),
                                    value = (string?)null,
                                    active = r.Active,
                                    valueSet = false,
                                    valueError = ex.Message,
                                };
                            }
                        }
                        if (!string.IsNullOrEmpty(active))
                        {
                            if (bool.TryParse(active, out var isActive))
                                r.Active = isActive;
                        }

                        return (object)new
                        {
                            id = r.ID,
                            description = r.Description,
                            address = r.Address,
                            offsets = GetOffsetsString(r),
                            value = r.Value,
                            active = r.Active,
                            valueSet = true,
                            valueError = (string?)null,
                        };
                    });

                    if (errorResult != null) return errorResult;
                    if (result == null)
                        return new { success = false, error = "Record not found" };

                    return new { success = true, record = result };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }
#pragma warning restore S107

        [
            McpServerTool(Name = "delete_memory_record"),
            Description("Deletes a specific memory record from the cheat table list.")
        ]
        public static object DeleteMemoryRecord(
            [Description("Numeric ID of the record to delete")] string id = "",
            [Description("0-based index of the record to delete")] string index = "",
            [Description("Exact description of the record to delete")] string description = ""
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    var found = Synchronize(() =>
                    {
                        using var al = new AddressList();

                        int? targetId =
                            !string.IsNullOrEmpty(id) && int.TryParse(id, out var parsedId)
                                ? parsedId
                                : (int?)null;
                        int? targetIndex =
                            !string.IsNullOrEmpty(index) && int.TryParse(index, out var parsedIdx)
                                ? parsedIdx
                                : (int?)null;

                        var r = FindRecord(al, targetId, targetIndex, description);
                        if (r == null)
                            return false;

                        al.DeleteMemoryRecord(r);
                        return true;
                    });

                    if (!found)
                        return new { success = false, error = "Record not found" };

                    return new { success = true };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        [
            McpServerTool(Name = "clear_address_list"),
            Description("Removes all entries from the active Cheat Engine address list (cheat table).")
        ]
        public static object ClearAddressList()
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    Synchronize(() =>
                    {
                        using var al = new AddressList();
                        al.Clear();
                    });
                    return new { success = true };
                }
                catch (Exception ex)
                {
                    return new { success = false, error = ex.Message };
                }
            });
        }

        private static MemoryRecord? FindRecord(
            AddressList al,
            int? id,
            int? index,
            string? description
        )
        {
            if (id.HasValue)
                return al.GetMemoryRecordByID(id.Value);
            if (index.HasValue)
                return al.GetMemoryRecord(index.Value);
            if (!string.IsNullOrEmpty(description))
            {
                // CE's getMemoryRecordByDescription may return nil on some setups
                // (e.g. cache not built yet). Fall back to manual scan.
                var direct = al.GetMemoryRecordByDescription(description);
                if (direct != null)
                    return direct;

                // Some CE builds require rebuilding the description cache before
                // getMemoryRecordByDescription starts returning results.
                try
                {
                    al.RebuildDescriptionCache();
                }
                catch (Exception ex)
                {
                    // ignore and fall back to manual scan
                    System.Diagnostics.Debug.WriteLine(ex);
                }

                direct = al.GetMemoryRecordByDescription(description);
                if (direct != null)
                    return direct;

                var count = al.Count;
                for (int i = 0; i < count; i++)
                {
                    MemoryRecord r;
                    try
                    {
                        r = al.GetMemoryRecord(i);
                    }
                    catch
                    {
                        continue;
                    }

                    if (
                        string.Equals(
                            r.Description,
                            description,
                            StringComparison.OrdinalIgnoreCase
                        )
                    )
                        return r;
                }

                return null;
            }

            throw new ArgumentException("Provide id, index, or description to find the record");
        }

        private static string GetOffsetsString(MemoryRecord r)
        {
            int count = r.OffsetCount;
            if (count <= 0)
                return "";

            var offsets = new List<string>(count);
            for (int i = 0; i < count; i++)
            {
                offsets.Add($"0x{r.GetOffset(i):X}");
            }
            return string.Join(",", offsets);
        }

        private static List<long> ParseOffsets(string offsets)
        {
            if (string.IsNullOrWhiteSpace(offsets))
                return new List<long>();

            var parts = offsets.Split(
                new[] { ',', ' ', '\t', '\r', '\n' },
                StringSplitOptions.RemoveEmptyEntries
            );

            var list = new List<long>(parts.Length);
            foreach (var part in parts)
            {
                if (!TryParseNumber(part, out var value))
                    throw new ArgumentException($"Invalid offset: {part}");
                list.Add(value);
            }
            return list;
        }

        private static bool TryParseNumber(string text, out long value)
        {
            value = 0;
            var trimmed = text.Trim();
            if (string.IsNullOrEmpty(trimmed))
                return false;

            int sign = 1;
            if (trimmed.StartsWith("-"))
            {
                sign = -1;
                trimmed = trimmed.Substring(1).Trim();
            }
            else if (trimmed.StartsWith("+"))
            {
                trimmed = trimmed.Substring(1).Trim();
            }

            bool success;
            if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                success = long.TryParse(
                    trimmed[2..],
                    NumberStyles.HexNumber,
                    CultureInfo.InvariantCulture,
                    out value
                );
            }
            else
            {
                success =
                    long.TryParse(
                        trimmed,
                        NumberStyles.Integer,
                        CultureInfo.InvariantCulture,
                        out value
                    )
                    || long.TryParse(
                        trimmed,
                        NumberStyles.HexNumber,
                        CultureInfo.InvariantCulture,
                        out value
                    );
            }

            if (success)
            {
                value *= sign;
            }
            return success;
        }
    }
}
