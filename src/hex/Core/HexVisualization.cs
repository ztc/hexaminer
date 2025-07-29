using System;
using System.Linq;
using System.Text;

namespace ZTC.Hexaminer.Core
{
    public static class HexVisualization
    {
        public static string FormatHexDump(byte[] data, int offset = 0, int bytesPerLine = 16)
        {
            var sb = new StringBuilder();
            int pos = offset;
            
            for (int i = 0; i < data.Length; i += bytesPerLine)
            {
                int lineLength = Math.Min(bytesPerLine, data.Length - i);
                byte[] line = new byte[lineLength];
                Array.Copy(data, i, line, 0, lineLength);

                var hex = BitConverter.ToString(line).Replace("-", " ").ToLower();
                hex = hex.PadRight(bytesPerLine * 3 - 1);

                var ascii = new StringBuilder();
                foreach (byte b in line)
                {
                    ascii.Append(b >= 32 && b <= 126 ? (char)b : '.');
                }

                sb.AppendLine($"{pos:x8}  {hex}  {ascii}");
                pos += lineLength;
            }

            return sb.ToString();
        }

        public static string HighlightStructures(byte[] data, AnalysisResult result, int bytesPerLine = 16)
        {
            var sb = new StringBuilder();
            var highlights = result.Structures.ToDictionary(s => s.Offset, s => s);
            
            for (int i = 0; i < data.Length; i += bytesPerLine)
            {
                int lineLength = Math.Min(bytesPerLine, data.Length - i);
                byte[] line = new byte[lineLength];
                Array.Copy(data, i, line, 0, lineLength);

                var hex = new StringBuilder();
                for (int j = 0; j < lineLength; j++)
                {
                    if (highlights.ContainsKey(i + j))
                    {
                        hex.Append($"[{line[j]:x2}]");
                    }
                    else
                    {
                        hex.Append($" {line[j]:x2} ");
                    }
                }

                var ascii = new StringBuilder();
                foreach (byte b in line)
                {
                    ascii.Append(b >= 32 && b <= 126 ? (char)b : '.');
                }

                sb.AppendLine($"{i:x8}  {hex}  {ascii}");
            }

            return sb.ToString();
        }

        public static void PrintColorizedHexDump(byte[] data, int offset = 0, int bytesPerLine = 16)
        {
            int pos = offset;
            
            for (int i = 0; i < data.Length; i += bytesPerLine)
            {
                int lineLength = Math.Min(bytesPerLine, data.Length - i);
                byte[] line = new byte[lineLength];
                Array.Copy(data, i, line, 0, lineLength);

                // Print offset
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"{pos:X8}  ");

                // Print hex bytes with colors
                for (int j = 0; j < lineLength; j++)
                {
                    byte b = line[j];
                    SetByteColor(b);
                    Console.Write($"{b:X2} ");
                }

                // Pad hex section if line is short
                for (int j = lineLength; j < bytesPerLine; j++)
                {
                    Console.Write("   ");
                }

                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write(" ");

                // Print ASCII with colors
                for (int j = 0; j < lineLength; j++)
                {
                    byte b = line[j];
                    SetByteColor(b);
                    char c = (b >= 32 && b <= 126) ? (char)b : '.';
                    Console.Write(c);
                }

                Console.ResetColor();
                Console.WriteLine();
                pos += lineLength;
            }
        }

        private static void SetByteColor(byte b)
        {
            if (b >= 65 && b <= 90) // A-Z uppercase letters
            {
                Console.ForegroundColor = ConsoleColor.Green;
            }
            else if (b >= 97 && b <= 122) // a-z lowercase letters  
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
            }
            else if (b >= 48 && b <= 57) // 0-9 digits
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
            }
            else if (b == 32) // Space
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
            }
            else if ((b >= 33 && b <= 47) || (b >= 58 && b <= 64) || (b >= 91 && b <= 96) || (b >= 123 && b <= 126)) // Symbols/punctuation
            {
                Console.ForegroundColor = ConsoleColor.Magenta;
            }
            else if (b == 0) // Null bytes
            {
                Console.ForegroundColor = ConsoleColor.DarkRed;
            }
            else if (b >= 1 && b <= 31) // Control characters
            {
                Console.ForegroundColor = ConsoleColor.Red;
            }
            else if (b >= 127 && b <= 159) // Extended control characters
            {
                Console.ForegroundColor = ConsoleColor.DarkYellow;
            }
            else // Extended ASCII/binary
            {
                Console.ForegroundColor = ConsoleColor.Blue;
            }
        }
    }
}