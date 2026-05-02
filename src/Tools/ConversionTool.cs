using System;
using System.ComponentModel;
using CEMCP;
using CESDK.Classes;
using ModelContextProtocol.Server;

namespace Tools
{
    /// <summary>
    /// Tools for data conversion and hashing.
    /// </summary>
    [McpServerToolType]
    public class ConversionTool
    {
        private ConversionTool() { }

        [
            McpServerTool(Name = "convert_string"),
            Description("Converts strings between different encoding formats or generates a hash. Supported: 'md5', 'ansitoutf8', 'utf8toansi'.")
        ]
        public static object ConvertString(
            [Description("The string to convert")] string input,
            [Description("The target conversion type: 'md5', 'ansitoutf8', or 'utf8toansi'")]
                string conversionType
        )
        {
            return CeLuaGate.Run<object>(() =>
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(input))
                        return new { success = false, error = "Input is required" };

                    if (string.IsNullOrWhiteSpace(conversionType))
                        return new { success = false, error = "Conversion type is required" };

                    string result = conversionType.ToLower() switch
                    {
                        "md5" => Converter.StringToMD5(input),
                        "ansitoutf8" => Converter.AnsiToUtf8(input),
                        "utf8toansi" => Converter.Utf8ToAnsi(input),
                        _ => throw new NotSupportedException(
                            $"Unsupported conversion type: {conversionType}"
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
    }
}
