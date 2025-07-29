using System;
using System.Collections.Generic;
using System.IO;
using ZTC.Hexaminer.Core;

namespace ZTC.Hexaminer.Analyzers
{
    public class PEAnalyzer : IDataAnalyzer
    {
        public string Name => "PE (Portable Executable) Analyzer";
        public string Description => "Analyzes Windows PE files (EXE, DLL)";

        public bool CanAnalyze(byte[] data, int offset = 0)
        {
            if (data.Length < offset + 64) return false;
            
            return data[offset] == 0x4D && data[offset + 1] == 0x5A;
        }

        public AnalysisResult Analyze(byte[] data, int offset = 0, int length = -1)
        {
            var result = new AnalysisResult
            {
                AnalyzerName = Name,
                DataType = "PE File",
                Offset = offset,
                Confidence = 0.95
            };

            using var stream = new MemoryStream(data, offset, length == -1 ? data.Length - offset : length);
            using var reader = new HexBinaryReader(stream, true);

            try
            {
                var dosHeader = ReadDOSHeader(reader, result);
                if (dosHeader.ContainsKey("e_lfanew"))
                {
                    reader.Seek((uint)dosHeader["e_lfanew"], SeekOrigin.Begin);
                    ReadPEHeader(reader, result);
                }
            }
            catch (Exception ex)
            {
                result.Properties["Error"] = ex.Message;
                result.Confidence = 0.3;
            }

            return result;
        }

        private Dictionary<string, object> ReadDOSHeader(HexBinaryReader reader, AnalysisResult result)
        {
            var dosHeader = new Dictionary<string, object>();
            
            dosHeader["e_magic"] = reader.ReadUInt16LE();
            dosHeader["e_cblp"] = reader.ReadUInt16LE();
            dosHeader["e_cp"] = reader.ReadUInt16LE();
            dosHeader["e_crlc"] = reader.ReadUInt16LE();
            dosHeader["e_cparhdr"] = reader.ReadUInt16LE();
            dosHeader["e_minalloc"] = reader.ReadUInt16LE();
            dosHeader["e_maxalloc"] = reader.ReadUInt16LE();
            dosHeader["e_ss"] = reader.ReadUInt16LE();
            dosHeader["e_sp"] = reader.ReadUInt16LE();
            dosHeader["e_csum"] = reader.ReadUInt16LE();
            dosHeader["e_ip"] = reader.ReadUInt16LE();
            dosHeader["e_cs"] = reader.ReadUInt16LE();
            dosHeader["e_lfarlc"] = reader.ReadUInt16LE();
            dosHeader["e_ovno"] = reader.ReadUInt16LE();

            reader.Seek(60, SeekOrigin.Begin);
            dosHeader["e_lfanew"] = reader.ReadUInt32LE();

            result.Structures.Add(new DataStructure
            {
                Name = "DOS Header",
                Offset = 0,
                Size = 64,
                Type = "IMAGE_DOS_HEADER"
            });

            result.Properties["DOS_Header"] = dosHeader;
            return dosHeader;
        }

        private void ReadPEHeader(HexBinaryReader reader, AnalysisResult result)
        {
            uint peSignature = reader.ReadUInt32LE();
            if (peSignature != 0x00004550) return;

            var fileHeader = new Dictionary<string, object>
            {
                ["Machine"] = reader.ReadUInt16LE(),
                ["NumberOfSections"] = reader.ReadUInt16LE(),
                ["TimeDateStamp"] = reader.ReadUInt32LE(),
                ["PointerToSymbolTable"] = reader.ReadUInt32LE(),
                ["NumberOfSymbols"] = reader.ReadUInt32LE(),
                ["SizeOfOptionalHeader"] = reader.ReadUInt16LE(),
                ["Characteristics"] = reader.ReadUInt16LE()
            };

            result.Structures.Add(new DataStructure
            {
                Name = "PE File Header",
                Offset = (int)reader.Position - 24,
                Size = 24,
                Type = "IMAGE_FILE_HEADER"
            });

            result.Properties["File_Header"] = fileHeader;
        }
    }
}