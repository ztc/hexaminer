using System;
using ZTC.Hexaminer.Core;

namespace ZTC.Hexaminer.Plugins
{
    public interface IPlugin
    {
        string Name { get; }
        string Version { get; }
        string Author { get; }
        string Description { get; }
        
        void Initialize();
        void Shutdown();
    }

    public interface IAnalyzerPlugin : IPlugin
    {
        IDataAnalyzer CreateAnalyzer();
    }

    public interface IVisualizationPlugin : IPlugin
    {
        string RenderVisualization(AnalysisResult result, byte[] data);
    }

    public interface IExportPlugin : IPlugin
    {
        string[] SupportedFormats { get; }
        void ExportResults(AnalysisResult[] results, string format, string outputPath);
    }
}