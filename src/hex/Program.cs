using System;
using System.CommandLine;
using System.CommandLine.Binding;
using System.IO;
using System.Linq;
using ZTC.Hexaminer.Core;
using ZTC.Hexaminer.Plugins;

namespace ZTC.Hexaminer
{
    class Program
    {
        static void Main(string[] args)
        {
            var rootCommand = new RootCommand("Hexaminer - Digital Forensics Data Exploitation Tool")
            {
                CreateAnalyzeCommand(),
                CreateDumpCommand(),
                CreatePatternsCommand(),
                CreatePluginsCommand()
            };

            rootCommand.Invoke(args);
        }

        private static Command CreateAnalyzeCommand()
        {
            var fileArg = new Argument<FileInfo>("file", "File to analyze").ExistingOnly();
            var offsetOpt = new Option<int>("--offset", () => 0, "Starting offset");
            var lengthOpt = new Option<int>("--length", () => -1, "Length to analyze (-1 for entire file)");
            var verboseOpt = new Option<bool>("--verbose", "Show detailed analysis");

            var analyzeCommand = new Command("analyze", "Analyze binary data and detect file formats")
            {
                fileArg,
                offsetOpt,
                lengthOpt,
                verboseOpt
            };

            analyzeCommand.SetHandler(async (FileInfo file, int offset, int length, bool verbose) =>
            {
                byte[] data;
                using (var fileStream = new FileStream(file.FullName, FileMode.Open, FileAccess.Read))
                {
                    if (offset >= fileStream.Length)
                    {
                        Console.WriteLine($"❌ Error: Offset {offset} is beyond file size {fileStream.Length}");
                        return;
                    }

                    fileStream.Seek(offset, SeekOrigin.Begin);
                    
                    // For analysis, limit to a reasonable size to avoid memory issues (default 10MB for full file analysis)
                    var maxAnalysisSize = 10 * 1024 * 1024; // 10MB
                    var availableBytes = (int)Math.Min(fileStream.Length - offset, int.MaxValue);
                    var bytesToRead = length == -1 ? Math.Min(availableBytes, maxAnalysisSize) : Math.Min(length, availableBytes);
                    
                    data = new byte[bytesToRead];
                    await fileStream.ReadAsync(data, 0, bytesToRead);
                    
                    if (length == -1 && bytesToRead < fileStream.Length - offset)
                    {
                        Console.WriteLine($"📊 Note: Large file detected. Analyzing first {bytesToRead:N0} bytes of {fileStream.Length:N0} byte file.");
                    }
                }
                
                var engine = new AnalysisEngine();
                var results = engine.AnalyzeData(data, 0, data.Length);

                Console.WriteLine($"\n🔍 === Analysis Results for {file.Name} ===");
                foreach (var result in results)
                {
                    Console.WriteLine($"\n🧬 Analyzer: {result.AnalyzerName}");
                    Console.WriteLine($"📄 Data Type: {result.DataType}");
                    Console.WriteLine($"🎯 Confidence: {result.Confidence:P1}");
                    
                    if (verbose)
                    {
                        foreach (var prop in result.Properties)
                        {
                            Console.WriteLine($"  {prop.Key}: {prop.Value}");
                        }
                        
                        if (result.Structures.Any())
                        {
                            Console.WriteLine("  🏗️  Structures:");
                            foreach (var structure in result.Structures)
                            {
                                Console.WriteLine($"    📍 {structure.Name} @ 0x{structure.Offset:X} ({structure.Size} bytes)");
                            }
                        }
                    }
                }
            }, fileArg, offsetOpt, lengthOpt, verboseOpt);

            return analyzeCommand;
        }

        private static Command CreateDumpCommand()
        {
            var fileArg = new Argument<FileInfo>("file", "File to dump").ExistingOnly();
            var offsetOpt = new Option<int>("--offset", () => 0, "Starting offset");
            var lengthOpt = new Option<int>("--length", () => 512, "Number of bytes to dump");
            var widthOpt = new Option<int>("--width", () => 16, "Bytes per line");

            var dumpCommand = new Command("dump", "Display hex dump of file")
            {
                fileArg,
                offsetOpt,
                lengthOpt,
                widthOpt
            };

            dumpCommand.SetHandler(async (FileInfo file, int offset, int length, int width) =>
            {
                byte[] data;
                using (var fileStream = new FileStream(file.FullName, FileMode.Open, FileAccess.Read))
                {
                    if (offset >= fileStream.Length)
                    {
                        Console.WriteLine($"❌ Error: Offset {offset} is beyond file size {fileStream.Length}");
                        return;
                    }

                    fileStream.Seek(offset, SeekOrigin.Begin);
                    
                    var bytesToRead = Math.Min(length, (int)(fileStream.Length - offset));
                    data = new byte[bytesToRead];
                    await fileStream.ReadAsync(data, 0, bytesToRead);
                }
                
                Console.WriteLine($"\n🔢 === Hex Dump: {file.Name} ===");
                HexVisualization.PrintColorizedHexDump(data, offset, width);
            }, fileArg, offsetOpt, lengthOpt, widthOpt);

            return dumpCommand;
        }

        private static Command CreatePatternsCommand()
        {
            var fileArg = new Argument<FileInfo>("file", "File to analyze").ExistingOnly();
            var stringsOpt = new Option<bool>("--strings", "Find ASCII strings");
            var emailsOpt = new Option<bool>("--emails", "Find email addresses");
            var urlsOpt = new Option<bool>("--urls", "Find URLs");
            var entropyOpt = new Option<bool>("--entropy", "Find entropy anomalies");
            var allOpt = new Option<bool>("--all", "Find all patterns");

            var patternsCommand = new Command("patterns", "Find interesting data patterns")
            {
                fileArg,
                stringsOpt,
                emailsOpt,
                urlsOpt,
                entropyOpt,
                allOpt
            };

            patternsCommand.SetHandler(async (FileInfo file, bool strings, bool emails, bool urls, bool entropy, bool all) =>
            {
                byte[] data;
                using (var fileStream = new FileStream(file.FullName, FileMode.Open, FileAccess.Read))
                {
                    // For pattern analysis, we'll limit to a reasonable size to avoid memory issues
                    var maxSize = Math.Min(fileStream.Length, 100 * 1024 * 1024); // 100MB max
                    data = new byte[maxSize];
                    await fileStream.ReadAsync(data, 0, (int)maxSize);
                }
                
                Console.WriteLine($"\n🔍 === Pattern Analysis: {file.Name} ===");

                if (all || strings)
                {
                    var stringMatches = DataPatterns.FindStringPatterns(data);
                    Console.WriteLine($"\n📝 Found {stringMatches.Count} ASCII strings:");
                    foreach (var match in stringMatches.Take(20))
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.Write($"  0x{match.Offset:X8}: ");
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.WriteLine($"{match.Value}");
                        Console.ResetColor();
                    }
                }

                if (all || emails)
                {
                    var emailMatches = DataPatterns.FindEmailPatterns(data);
                    Console.WriteLine($"\n📧 Found {emailMatches.Count} email addresses:");
                    foreach (var match in emailMatches)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.Write($"  0x{match.Offset:X8}: ");
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.WriteLine($"{match.Value}");
                        Console.ResetColor();
                    }
                }

                if (all || urls)
                {
                    var urlMatches = DataPatterns.FindURLPatterns(data);
                    Console.WriteLine($"\n🌐 Found {urlMatches.Count} URLs:");
                    foreach (var match in urlMatches)
                    {
                        Console.ForegroundColor = ConsoleColor.Blue;
                        Console.Write($"  0x{match.Offset:X8}: ");
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.WriteLine($"{match.Value}");
                        Console.ResetColor();
                    }
                }

                if (all || entropy)
                {
                    var entropyMatches = DataPatterns.FindEntropyAnomalies(data);
                    Console.WriteLine($"\n🔢 Found {entropyMatches.Count} entropy anomalies:");
                    foreach (var match in entropyMatches)
                    {
                        Console.ForegroundColor = ConsoleColor.Magenta;
                        Console.Write($"  0x{match.Offset:X8}: ");
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.WriteLine($"{match.Type} - {match.Value}");
                        Console.ResetColor();
                    }
                }
            }, fileArg, stringsOpt, emailsOpt, urlsOpt, entropyOpt, allOpt);

            return patternsCommand;
        }

        private static Command CreatePluginsCommand()
        {
            var pluginsCommand = new Command("plugins", "Manage plugins")
            {
                new Command("list", "List loaded plugins"),
                new Command("load", "Load plugins from directory")
                {
                    new Argument<DirectoryInfo>("directory", "Plugin directory")
                }
            };

            return pluginsCommand;
        }
    }

}
