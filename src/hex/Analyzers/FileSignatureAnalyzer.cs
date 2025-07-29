using System;
using System.Collections.Generic;
using System.Linq;
using ZTC.Hexaminer.Core;

namespace ZTC.Hexaminer.Analyzers
{
    public class FileSignatureAnalyzer : IDataAnalyzer
    {
        public string Name => "File Signature Analyzer";
        public string Description => "Identifies file types by magic number signatures";

        private static readonly Dictionary<string, (byte[] signature, int offset, string description)> Signatures = 
            new Dictionary<string, (byte[], int, string)>
            {
                ["PNG"] = (new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }, 0, "PNG Image"),
                ["JPEG"] = (new byte[] { 0xFF, 0xD8, 0xFF }, 0, "JPEG Image"),
                ["GIF87"] = (new byte[] { 0x47, 0x49, 0x46, 0x38, 0x37, 0x61 }, 0, "GIF87a Image"),
                ["GIF89"] = (new byte[] { 0x47, 0x49, 0x46, 0x38, 0x39, 0x61 }, 0, "GIF89a Image"),
                ["PDF"] = (new byte[] { 0x25, 0x50, 0x44, 0x46 }, 0, "PDF Document"),
                ["ZIP"] = (new byte[] { 0x50, 0x4B, 0x03, 0x04 }, 0, "ZIP Archive"),
                ["ZIP_EMPTY"] = (new byte[] { 0x50, 0x4B, 0x05, 0x06 }, 0, "Empty ZIP Archive"),
                ["RAR"] = (new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00 }, 0, "RAR Archive"),
                ["7Z"] = (new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C }, 0, "7-Zip Archive"),
                ["SQLITE"] = (new byte[] { 0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00 }, 0, "SQLite Database"),
                ["MP3"] = (new byte[] { 0x49, 0x44, 0x33 }, 0, "MP3 Audio (ID3v2)"),
                ["MP3_MPEG"] = (new byte[] { 0xFF, 0xFB }, 0, "MP3 Audio (MPEG)"),
                ["WAV"] = (new byte[] { 0x52, 0x49, 0x46, 0x46 }, 0, "WAV Audio"),
                ["AVI"] = (new byte[] { 0x52, 0x49, 0x46, 0x46 }, 0, "AVI Video"),
                ["MZ"] = (new byte[] { 0x4D, 0x5A }, 0, "MS-DOS/Windows Executable"),
                ["ELF"] = (new byte[] { 0x7F, 0x45, 0x4C, 0x46 }, 0, "ELF Executable"),
                ["MACH_O_32"] = (new byte[] { 0xFE, 0xED, 0xFA, 0xCE }, 0, "Mach-O 32-bit"),
                ["MACH_O_64"] = (new byte[] { 0xFE, 0xED, 0xFA, 0xCF }, 0, "Mach-O 64-bit"),
                ["CLASS"] = (new byte[] { 0xCA, 0xFE, 0xBA, 0xBE }, 0, "Java Class File"),
                ["TAR"] = (new byte[] { 0x75, 0x73, 0x74, 0x61, 0x72 }, 257, "TAR Archive"),
                ["GZIP"] = (new byte[] { 0x1F, 0x8B }, 0, "GZIP Compressed"),
                ["BZ2"] = (new byte[] { 0x42, 0x5A, 0x68 }, 0, "BZIP2 Compressed"),
                ["XZ"] = (new byte[] { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 }, 0, "XZ Compressed"),
                ["GGUF"] = (new byte[] { 0x47, 0x47, 0x55, 0x46  }, 0, "GGUF GPT-Generated Unified Format"),
                ["EWF-E01"] = (new byte[] { 0x45, 0x57, 0x46, 0x01 }, 0, "Expert Witness Format E01"),
                ["EWF-AD1"] = (new byte[] { 0x45, 0x57, 0x46, 0x02 }, 0, "Expert Witness Format AD1"),
                ["EWF-S01"] = (new byte[] { 0x45, 0x57, 0x46, 0x03 }, 0, "Expert Witness Format S01"),
                ["EWF-S02"] = (new byte[] { 0x45, 0x57, 0x46, 0x04 }, 0, "Expert Witness Format S02"),
                ["VMDK"] = (new byte[] { 0x4B, 0x44, 0x4D, 0x56 }, 0, "VMware Virtual Disk"),
                ["VHD"] = (new byte[] { 0xEB, 0x00, 0x00, 0x00 }, 0, "Virtual Hard Disk"),
                ["ISO"] = (new byte[] { 0x43, 0x44, 0x30, 0x30 }, 32769, "ISO9660 CD/DVD Image"),
            };

        public bool CanAnalyze(byte[] data, int offset = 0)
        {
            return data.Length > offset;
        }

        public AnalysisResult Analyze(byte[] data, int offset = 0, int length = -1)
        {
            var result = new AnalysisResult
            {
                AnalyzerName = Name,
                DataType = "File Signature Detection",
                Offset = offset,
                Confidence = 0.0
            };

            var matches = new List<string>();
            
            foreach (var sig in Signatures)
            {
                var (signature, sigOffset, description) = sig.Value;
                int checkOffset = offset + sigOffset;
                
                if (checkOffset + signature.Length <= data.Length)
                {
                    bool match = true;
                    for (int i = 0; i < signature.Length; i++)
                    {
                        if (data[checkOffset + i] != signature[i])
                        {
                            match = false;
                            break;
                        }
                    }
                    
                    if (match)
                    {
                        matches.Add(sig.Key);
                        result.Structures.Add(new DataStructure
                        {
                            Name = $"{sig.Key} Signature",
                            Offset = checkOffset,
                            Size = signature.Length,
                            Type = "File Signature",
                            Value = description
                        });
                    }
                }
            }

            if (matches.Any())
            {
                result.Confidence = 0.9;
                result.Properties["Detected_Formats"] = matches;
                result.Properties["Primary_Format"] = matches.First();
            }
            else
            {
                result.Properties["Status"] = "No known file signatures detected";
            }

            return result;
        }
    }
}