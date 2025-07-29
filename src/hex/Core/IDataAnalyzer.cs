using System;
using System.Collections.Generic;

namespace ZTC.Hexaminer.Core
{
    public interface IDataAnalyzer
    {
        string Name { get; }
        string Description { get; }
        bool CanAnalyze(byte[] data, int offset = 0);
        AnalysisResult Analyze(byte[] data, int offset = 0, int length = -1);
    }

    public class AnalysisResult
    {
        public string AnalyzerName { get; set; }
        public string DataType { get; set; }
        public int Offset { get; set; }
        public int Length { get; set; }
        public Dictionary<string, object> Properties { get; set; } = new Dictionary<string, object>();
        public List<DataStructure> Structures { get; set; } = new List<DataStructure>();
        public double Confidence { get; set; }
    }

    public class DataStructure
    {
        public string Name { get; set; }
        public int Offset { get; set; }
        public int Size { get; set; }
        public string Type { get; set; }
        public object Value { get; set; }
        public List<DataStructure> Children { get; set; } = new List<DataStructure>();
    }
}