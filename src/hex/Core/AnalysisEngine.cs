using System;
using System.Collections.Generic;
using System.Linq;
using ZTC.Hexaminer.Analyzers;

namespace ZTC.Hexaminer.Core
{
    public class AnalysisEngine
    {
        private readonly List<IDataAnalyzer> _analyzers;

        public AnalysisEngine()
        {
            _analyzers = new List<IDataAnalyzer>
            {
                new FileSignatureAnalyzer(),
                new PEAnalyzer(),
                new ELFAnalyzer()
            };
        }

        public void RegisterAnalyzer(IDataAnalyzer analyzer)
        {
            _analyzers.Add(analyzer);
        }

        public List<AnalysisResult> AnalyzeData(byte[] data, int offset = 0, int length = -1)
        {
            var results = new List<AnalysisResult>();
            
            foreach (var analyzer in _analyzers)
            {
                try
                {
                    if (analyzer.CanAnalyze(data, offset))
                    {
                        var result = analyzer.Analyze(data, offset, length);
                        if (result != null)
                        {
                            results.Add(result);
                        }
                    }
                }
                catch (Exception ex)
                {
                    var errorResult = new AnalysisResult
                    {
                        AnalyzerName = analyzer.Name,
                        DataType = "Error",
                        Offset = offset,
                        Confidence = 0.0
                    };
                    errorResult.Properties["Error"] = ex.Message;
                    results.Add(errorResult);
                }
            }

            return results.OrderByDescending(r => r.Confidence).ToList();
        }

        public AnalysisResult GetBestMatch(byte[] data, int offset = 0, int length = -1)
        {
            var results = AnalyzeData(data, offset, length);
            return results.FirstOrDefault();
        }

        public List<DataStructure> ExtractStructures(byte[] data, int offset = 0, int length = -1)
        {
            var results = AnalyzeData(data, offset, length);
            var structures = new List<DataStructure>();
            
            foreach (var result in results)
            {
                structures.AddRange(result.Structures);
            }

            return structures.OrderBy(s => s.Offset).ToList();
        }
    }
}