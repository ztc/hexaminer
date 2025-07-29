using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace ZTC.Hexaminer.Core
{
    public static class DataPatterns
    {
        public static List<PatternMatch> FindStringPatterns(byte[] data, int minLength = 4)
        {
            var matches = new List<PatternMatch>();
            var currentString = new List<byte>();
            int startOffset = -1;

            for (int i = 0; i < data.Length; i++)
            {
                byte b = data[i];
                
                if (IsPrintableAscii(b))
                {
                    if (currentString.Count == 0)
                        startOffset = i;
                    currentString.Add(b);
                }
                else
                {
                    if (currentString.Count >= minLength)
                    {
                        matches.Add(new PatternMatch
                        {
                            Type = "ASCII String",
                            Offset = startOffset,
                            Length = currentString.Count,
                            Value = System.Text.Encoding.ASCII.GetString(currentString.ToArray())
                        });
                    }
                    currentString.Clear();
                }
            }

            if (currentString.Count >= minLength)
            {
                matches.Add(new PatternMatch
                {
                    Type = "ASCII String",
                    Offset = startOffset,
                    Length = currentString.Count,
                    Value = System.Text.Encoding.ASCII.GetString(currentString.ToArray())
                });
            }

            return matches;
        }

        public static List<PatternMatch> FindEmailPatterns(byte[] data)
        {
            var text = System.Text.Encoding.ASCII.GetString(data);
            var emailRegex = new Regex(@"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b");
            var matches = new List<PatternMatch>();

            foreach (Match match in emailRegex.Matches(text))
            {
                matches.Add(new PatternMatch
                {
                    Type = "Email Address",
                    Offset = match.Index,
                    Length = match.Length,
                    Value = match.Value
                });
            }

            return matches;
        }

        public static List<PatternMatch> FindURLPatterns(byte[] data)
        {
            var text = System.Text.Encoding.ASCII.GetString(data);
            var urlRegex = new Regex(@"https?://[^\s<>""{}|\\^`\[\]]+");
            var matches = new List<PatternMatch>();

            foreach (Match match in urlRegex.Matches(text))
            {
                matches.Add(new PatternMatch
                {
                    Type = "URL",
                    Offset = match.Index,
                    Length = match.Length,
                    Value = match.Value
                });
            }

            return matches;
        }

        public static List<PatternMatch> FindCreditCardPatterns(byte[] data)
        {
            var text = System.Text.Encoding.ASCII.GetString(data);
            var ccRegex = new Regex(@"\b(?:\d{4}[-\s]?){3}\d{4}\b");
            var matches = new List<PatternMatch>();

            foreach (Match match in ccRegex.Matches(text))
            {
                if (IsValidCreditCard(match.Value.Replace("-", "").Replace(" ", "")))
                {
                    matches.Add(new PatternMatch
                    {
                        Type = "Credit Card Number",
                        Offset = match.Index,
                        Length = match.Length,
                        Value = match.Value
                    });
                }
            }

            return matches;
        }

        public static List<PatternMatch> FindEntropyAnomalies(byte[] data, int windowSize = 256)
        {
            var matches = new List<PatternMatch>();
            
            for (int i = 0; i <= data.Length - windowSize; i += windowSize / 2)
            {
                var window = data.Skip(i).Take(windowSize).ToArray();
                double entropy = CalculateEntropy(window);
                
                if (entropy > 7.5)
                {
                    matches.Add(new PatternMatch
                    {
                        Type = "High Entropy (Possible Encryption/Compression)",
                        Offset = i,
                        Length = windowSize,
                        Value = $"Entropy: {entropy:F2}"
                    });
                }
                else if (entropy < 1.0)
                {
                    matches.Add(new PatternMatch
                    {
                        Type = "Low Entropy (Repetitive Data)",
                        Offset = i,
                        Length = windowSize,
                        Value = $"Entropy: {entropy:F2}"
                    });
                }
            }

            return matches;
        }

        private static bool IsPrintableAscii(byte b)
        {
            return b >= 32 && b <= 126;
        }

        private static bool IsValidCreditCard(string number)
        {
            if (string.IsNullOrEmpty(number) || number.Length < 13 || number.Length > 19)
                return false;

            int sum = 0;
            bool alternate = false;
            
            for (int i = number.Length - 1; i >= 0; i--)
            {
                if (!char.IsDigit(number[i]))
                    return false;
                    
                int digit = int.Parse(number[i].ToString());
                
                if (alternate)
                {
                    digit *= 2;
                    if (digit > 9)
                        digit -= 9;
                }
                
                sum += digit;
                alternate = !alternate;
            }
            
            return sum % 10 == 0;
        }

        private static double CalculateEntropy(byte[] data)
        {
            var frequencies = new int[256];
            foreach (byte b in data)
                frequencies[b]++;

            double entropy = 0.0;
            int length = data.Length;
            
            for (int i = 0; i < 256; i++)
            {
                if (frequencies[i] > 0)
                {
                    double probability = (double)frequencies[i] / length;
                    entropy -= probability * Math.Log2(probability);
                }
            }

            return entropy;
        }
    }

    public class PatternMatch
    {
        public string Type { get; set; }
        public int Offset { get; set; }
        public int Length { get; set; }
        public string Value { get; set; }
    }
}