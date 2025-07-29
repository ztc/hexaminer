using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using ZTC.Hexaminer.Core;

namespace ZTC.Hexaminer.Analyzers
{
    public class ELFAnalyzer : IDataAnalyzer
    {
        public string Name => "ELF (Executable and Linkable Format) Analyzer";
        public string Description => "Analyzes Linux/Unix ELF binaries";

        public bool CanAnalyze(byte[] data, int offset = 0)
        {
            if (data.Length < offset + 4) return false;
            
            return data[offset] == 0x7F && 
                   data[offset + 1] == 0x45 && 
                   data[offset + 2] == 0x4C && 
                   data[offset + 3] == 0x46;
        }

        public AnalysisResult Analyze(byte[] data, int offset = 0, int length = -1)
        {
            var result = new AnalysisResult
            {
                AnalyzerName = Name,
                DataType = "ELF File",
                Offset = offset,
                Confidence = 0.95
            };

            using var stream = new MemoryStream(data, offset, length == -1 ? data.Length - offset : length);
            using var reader = new HexBinaryReader(stream, true);

            try
            {
                ReadELFHeader(reader, result);
            }
            catch (Exception ex)
            {
                result.Properties["Error"] = ex.Message;
                result.Confidence = 0.3;
            }

            return result;
        }

        private void ReadELFHeader(HexBinaryReader reader, AnalysisResult result)
        {
            var header = new Dictionary<string, object>();
            
            byte[] magic = reader.ReadBytes(4);
            header["Magic"] = Encoding.ASCII.GetString(magic);
            
            byte elfClass = reader.ReadByte();
            header["Class"] = elfClass == 1 ? "32-bit" : elfClass == 2 ? "64-bit" : "Unknown";
            
            byte dataEncoding = reader.ReadByte();
            header["Data"] = dataEncoding == 1 ? "Little Endian" : dataEncoding == 2 ? "Big Endian" : "Unknown";
            
            header["Version"] = reader.ReadByte();
            header["OS/ABI"] = reader.ReadByte();
            header["ABI_Version"] = reader.ReadByte();
            
            reader.ReadBytes(7);
            
            header["Type"] = reader.ReadUInt16LE();
            header["Machine"] = reader.ReadUInt16LE();
            header["Version2"] = reader.ReadUInt32LE();

            bool is64Bit = elfClass == 2;
            if (is64Bit)
            {
                header["Entry"] = reader.ReadUInt64LE();
                header["ProgramHeaderOffset"] = reader.ReadUInt64LE();
                header["SectionHeaderOffset"] = reader.ReadUInt64LE();
            }
            else
            {
                header["Entry"] = reader.ReadUInt32LE();
                header["ProgramHeaderOffset"] = reader.ReadUInt32LE();
                header["SectionHeaderOffset"] = reader.ReadUInt32LE();
            }

            header["Flags"] = reader.ReadUInt32LE();
            header["HeaderSize"] = reader.ReadUInt16LE();
            header["ProgramHeaderEntrySize"] = reader.ReadUInt16LE();
            header["ProgramHeaderCount"] = reader.ReadUInt16LE();
            header["SectionHeaderEntrySize"] = reader.ReadUInt16LE();
            header["SectionHeaderCount"] = reader.ReadUInt16LE();
            header["SectionHeaderStringIndex"] = reader.ReadUInt16LE();

            result.Structures.Add(new DataStructure
            {
                Name = "ELF Header",
                Offset = 0,
                Size = is64Bit ? 64 : 52,
                Type = "Elf64_Ehdr or Elf32_Ehdr"
            });

            result.Properties["ELF_Header"] = header;
        }
    }
}