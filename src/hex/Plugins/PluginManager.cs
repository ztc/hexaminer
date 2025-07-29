using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using ZTC.Hexaminer.Core;

namespace ZTC.Hexaminer.Plugins
{
    public class PluginManager
    {
        private readonly List<IPlugin> _loadedPlugins;
        private readonly List<IAnalyzerPlugin> _analyzerPlugins;
        private readonly List<IVisualizationPlugin> _visualizationPlugins;
        private readonly List<IExportPlugin> _exportPlugins;

        public PluginManager()
        {
            _loadedPlugins = new List<IPlugin>();
            _analyzerPlugins = new List<IAnalyzerPlugin>();
            _visualizationPlugins = new List<IVisualizationPlugin>();
            _exportPlugins = new List<IExportPlugin>();
        }

        public void LoadPluginsFromDirectory(string pluginDirectory)
        {
            if (!Directory.Exists(pluginDirectory))
                return;

            var dllFiles = Directory.GetFiles(pluginDirectory, "*.dll", SearchOption.AllDirectories);
            
            foreach (var dllFile in dllFiles)
            {
                try
                {
                    LoadPluginFromAssembly(dllFile);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to load plugin from {dllFile}: {ex.Message}");
                }
            }
        }

        public void LoadPluginFromAssembly(string assemblyPath)
        {
            var assembly = Assembly.LoadFrom(assemblyPath);
            var pluginTypes = assembly.GetTypes()
                .Where(t => t.IsClass && !t.IsAbstract && typeof(IPlugin).IsAssignableFrom(t));

            foreach (var pluginType in pluginTypes)
            {
                try
                {
                    var plugin = (IPlugin)Activator.CreateInstance(pluginType);
                    RegisterPlugin(plugin);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to instantiate plugin {pluginType.Name}: {ex.Message}");
                }
            }
        }

        public void RegisterPlugin(IPlugin plugin)
        {
            try
            {
                plugin.Initialize();
                _loadedPlugins.Add(plugin);

                if (plugin is IAnalyzerPlugin analyzerPlugin)
                    _analyzerPlugins.Add(analyzerPlugin);

                if (plugin is IVisualizationPlugin visualizationPlugin)
                    _visualizationPlugins.Add(visualizationPlugin);

                if (plugin is IExportPlugin exportPlugin)
                    _exportPlugins.Add(exportPlugin);

                Console.WriteLine($"Loaded plugin: {plugin.Name} v{plugin.Version} by {plugin.Author}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to initialize plugin {plugin.Name}: {ex.Message}");
            }
        }

        public List<IDataAnalyzer> GetAnalyzers()
        {
            var analyzers = new List<IDataAnalyzer>();
            
            foreach (var plugin in _analyzerPlugins)
            {
                try
                {
                    var analyzer = plugin.CreateAnalyzer();
                    if (analyzer != null)
                        analyzers.Add(analyzer);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to create analyzer from plugin {plugin.Name}: {ex.Message}");
                }
            }

            return analyzers;
        }

        public List<IVisualizationPlugin> GetVisualizationPlugins()
        {
            return new List<IVisualizationPlugin>(_visualizationPlugins);
        }

        public List<IExportPlugin> GetExportPlugins()
        {
            return new List<IExportPlugin>(_exportPlugins);
        }

        public IExportPlugin GetExportPlugin(string format)
        {
            return _exportPlugins.FirstOrDefault(p => 
                p.SupportedFormats.Contains(format, StringComparer.OrdinalIgnoreCase));
        }

        public void UnloadAllPlugins()
        {
            foreach (var plugin in _loadedPlugins)
            {
                try
                {
                    plugin.Shutdown();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error shutting down plugin {plugin.Name}: {ex.Message}");
                }
            }

            _loadedPlugins.Clear();
            _analyzerPlugins.Clear();
            _visualizationPlugins.Clear();
            _exportPlugins.Clear();
        }

        public List<IPlugin> GetLoadedPlugins()
        {
            return new List<IPlugin>(_loadedPlugins);
        }
    }
}