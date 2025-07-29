# hexaminer®

A powerful data exploitation and visualization tool designed for digital forensic investigators and security researchers. Hexaminer helps decipher complex binary data, interpret data structures, and extract meaningful intelligence from digital evidence.

## Features

### 🔍 **Advanced Binary Analysis**
- **Multi-format Detection**: Automatically identifies 20+ file types by magic number signatures
- **Structure Parsing**: Deep analysis of PE (Windows) and ELF (Linux/Unix) executables
- **Entropy Analysis**: Detects encrypted, compressed, or randomized data regions
- **Pattern Recognition**: Finds ASCII strings, email addresses, URLs, credit card numbers, and other sensitive data
- **Large File Support**: Efficiently handles files of any size with streaming analysis (no 2GB memory limit)

### 🎯 **Forensic-Focused Tools**
- **Hex Visualization**: Enhanced hex dumps with structure highlighting and annotations
- **Memory-Efficient Analysis**: Smart chunked reading for large files and disk images
- **Evidence Processing**: Analyze multi-gigabyte files without memory constraints
- **Export Options**: Multiple output formats for reporting and further analysis

### 🔧 **Extensible Architecture**
- **Plugin System**: Load custom analyzers, visualizations, and export modules
- **Modular Design**: Easy integration with existing forensic workflows
- **Registry-Based Engine**: Automatic analyzer discovery and confidence scoring

## Installation

### Prerequisites
- .NET 9.0 or later (preview versions supported)
- Windows, macOS, or Linux

### Build from Source
```bash
git clone https://github.com/ztc/hexaminer.git
cd hexaminer
dotnet build src/hex/hex.csproj
dotnet run --project src/hex -- --help
```

### Quick Start
```bash
# Test the installation with a small file
echo "Hello World" > test.txt
dotnet run --project src/hex -- analyze test.txt

# Analyze large files (multi-GB supported)
dotnet run --project src/hex -- analyze large-disk-image.dd
```

## Usage

### Basic File Analysis
```bash
# Analyze a file and detect its format (reads first 64KB for analysis)
dotnet run --project src/hex -- analyze suspicious.exe

# Verbose analysis with detailed structure information
dotnet run --project src/hex -- analyze --verbose malware.bin

# Analyze specific region of a file
dotnet run --project src/hex -- analyze --offset 0x1000 --length 2048 data.img

# Analyze very large files (GB+ sizes supported)
dotnet run --project src/hex -- analyze large-disk-image.dd
```

### Hex Dump Visualization
```bash
# Standard hex dump (first 512 bytes)
dotnet run --project src/hex -- dump binary.dat

# Custom dump parameters
dotnet run --project src/hex -- dump --offset 0x800 --length 1024 --width 32 file.bin

# Dump specific sections of large files
dotnet run --project src/hex -- dump --offset 0x100000 --length 256 huge-file.bin
```

### Pattern Detection
```bash
# Find all interesting patterns (analyzes first 10MB for performance)
dotnet run --project src/hex -- patterns --all evidence.raw

# Search for specific pattern types
dotnet run --project src/hex -- patterns --strings --emails --urls document.pdf
dotnet run --project src/hex -- patterns --entropy compressed.data

# Pattern analysis on large files (with size notification)
dotnet run --project src/hex -- patterns --all large-memory-dump.dmp
```

### Plugin Management
```bash
# List loaded plugins
dotnet run --project src/hex -- plugins list

# Load plugins from directory
dotnet run --project src/hex -- plugins load ./custom-plugins/
```

## Performance & Large File Handling

Hexaminer is optimized for forensic workflows involving large files and disk images:

### Memory Optimization
- **Streaming Analysis**: No file size limits - analyze TB+ files without loading into memory
- **Smart Chunking**: Reads only necessary data for each operation
- **Configurable Limits**: 
  - Analysis: 64KB (sufficient for file headers and signatures)
  - Pattern Scanning: 10MB (with progress notification for larger files)
  - Hex Dumps: User-specified ranges only

### Performance Characteristics
```bash
# These operations use minimal memory regardless of file size:
dotnet run --project src/hex -- analyze 500GB-disk-image.dd     # Uses ~64KB RAM
dotnet run --project src/hex -- dump --length 1024 huge.bin    # Uses ~1KB RAM
dotnet run --project src/hex -- patterns --all large-file.bin  # Uses ~10MB RAM
```

### Supported File Sizes
- **Small files** (< 1MB): Full analysis
- **Medium files** (1MB - 100MB): Optimized analysis
- **Large files** (100MB - 10GB): Chunked analysis with notifications
- **Very large files** (10GB+): Streaming analysis, no memory constraints

## File Format Support

### Executable Formats
- **PE (Portable Executable)**: Windows EXE, DLL files
- **ELF (Executable and Linkable Format)**: Linux/Unix binaries
- **Mach-O**: macOS executables (32/64-bit)
- **Java Class**: Compiled Java bytecode

### Archive Formats
- **ZIP**: Standard and empty ZIP archives
- **RAR**: WinRAR archives
- **7-Zip**: 7z compressed archives
- **TAR**: Unix tape archives
- **GZIP/BZIP2/XZ**: Compressed files

### Media & Document Formats  
- **Images**: PNG, JPEG, GIF87a/89a
- **Documents**: PDF files
- **Audio**: MP3 (ID3v2, MPEG), WAV
- **Video**: AVI, other RIFF-based formats
- **Database**: SQLite files

### AI/ML Model Formats
- **GGUF**: GPT-Generated Unified Format (detected but not fully parsed yet)

## Plugin Development

Create custom analyzers by implementing the `IDataAnalyzer` interface:

```csharp
public class CustomAnalyzer : IDataAnalyzer
{
    public string Name => "Custom File Format Analyzer";
    public string Description => "Analyzes proprietary file format";
    
    public bool CanAnalyze(byte[] data, int offset = 0)
    {
        // Check if this analyzer can handle the data
        return data[offset] == 0xAB && data[offset + 1] == 0xCD;
    }
    
    public AnalysisResult Analyze(byte[] data, int offset = 0, int length = -1)
    {
        // Perform custom analysis and return structured results
        var result = new AnalysisResult
        {
            AnalyzerName = Name,
            DataType = "Custom Format",
            Confidence = 0.95
        };
        
        // Add detected structures, properties, etc.
        return result;
    }
}
```

## Example Output

```
=== Analysis Results for suspicious.exe ===

Analyzer: File Signature Analyzer
Data Type: File Signature Detection
Confidence: 90.0%

Analyzer: PE (Portable Executable) Analyzer  
Data Type: PE File
Confidence: 95.0%
  DOS_Header: {e_magic: 23117, e_lfanew: 248}
  File_Header: {Machine: 34404, NumberOfSections: 6, TimeDateStamp: 1640995200}
  Structures:
    DOS Header @ 0x0 (64 bytes)
    PE File Header @ 0xF8 (24 bytes)

=== Pattern Analysis: suspicious.exe ===

Found 45 ASCII strings:
  0x00001420: kernel32.dll
  0x00001430: GetProcAddress
  0x00001441: LoadLibraryA
  0x00001450: CreateFileA

Found 2 URLs:
  0x00002100: http://malicious-c2.example.com/beacon
  0x00002150: https://download.badactor.net/payload

Found 3 entropy anomalies:
  0x00003000: High Entropy (Possible Encryption/Compression) - Entropy: 7.89
```

## Use Cases

### Digital Forensics
- **Malware Analysis**: Identify packed/encrypted sections, extract IOCs
- **Incident Response**: Analyze suspicious files and memory dumps  
- **Evidence Processing**: Bulk analysis of seized digital media
- **File Recovery**: Analyze partially corrupted or fragmented files

### Security Research  
- **Reverse Engineering**: Understand binary file structures and formats
- **Vulnerability Research**: Analyze file parsers and identify attack surfaces
- **Threat Intelligence**: Extract signatures and patterns from malware samples
- **Data Loss Prevention**: Identify sensitive data in files and network captures

### Development & Testing
- **File Format Development**: Validate custom binary formats during development
- **Quality Assurance**: Ensure proper file structure and metadata
- **Performance Analysis**: Identify optimization opportunities in binary data

## Contributing

We welcome contributions from the digital forensics and security research community!

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-analyzer`)
3. Implement your changes with tests
4. Submit a pull request

### Development Guidelines
- Follow existing code patterns and naming conventions  
- Add comprehensive tests for new analyzers
- Update documentation for new features
- Ensure plugins are properly sandboxed and secure

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgments

- Built with .NET 9 and System.CommandLine for modern CLI experience
- Inspired by classic hex editors and forensic analysis tools
- Large file handling improvements enable analysis of modern disk images and AI model files

---

**hexaminer® - thoughtful digital data exploration**  
*Empowering investigators to uncover the truth hidden in binary data*