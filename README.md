# YARA Rules Repository

A collection of YARA rules for detecting various types of software, malware, and indicators of compromise. This repository uses YARA-X, the next-generation YARA engine written in Rust.

## Repository Structure

```
.
├── rules/                    # Main directory for YARA rules
│   ├── malware/             # Malware-specific detection rules
│   ├── packers/             # Rules for detecting packers and protectors
│   ├── compilers/           # Rules for detecting compiler artifacts
│   ├── installers/          # Rules for detecting installers
│   └── indicators/          # General IOCs and indicators
├── docs/                    # Documentation and usage guides
└── tests/                   # Test files and sample binaries
```

## Installation

### Installing YARA-X

There are several ways to install YARA-X:

1. **Using Homebrew (macOS)**:
   ```bash
   brew install yara-x
   ```

2. **Using pre-built binaries**:
   Download the latest release from [YARA-X releases](https://github.com/VirusTotal/yara-x/releases) and unzip to your preferred location.

3. **Building from source**:
   ```bash
   git clone https://github.com/VirusTotal/yara-x 
   cd yara-x
   cargo install --path cli
   ```

## Usage

### Basic Scanning

```bash
# Scan a single file
yr rules/compilers/Detect_Go_GOMAXPROCS.yara /path/to/file

# Scan a directory recursively
yr -r rules/compilers/Detect_Go_GOMAXPROCS.yara /path/to/directory
```

### Advanced Features

YARA-X supports several advanced features:

```bash
# Show detailed match information
yr -d rules/compilers/Detect_Go_GOMAXPROCS.yara /path/to/file

# Show only matching files
yr -m rules/compilers/Detect_Go_GOMAXPROCS.yara /path/to/file

# Show rule metadata
yr --metadata rules/compilers/Detect_Go_GOMAXPROCS.yara
```

## Rule Writing

YARA-X rules follow the same syntax as YARA, with some enhancements. Key differences include:

- Improved performance and memory efficiency
- Better error handling and reporting
- Enhanced module support
- Modern Rust-based implementation

For detailed information about writing rules, see the [YARA-X documentation](https://virustotal.github.io/yara-x/docs/writing-rules/).

## Rule Categories

- **Malware**: Rules for detecting malicious software
- **Packers**: Rules for detecting software packers and protectors
- **Compilers**: Rules for detecting compiler artifacts and build tools
- **Installers**: Rules for detecting various installer types
- **Indicators**: General indicators of compromise and suspicious patterns

## Contributing

1. Fork the repository
2. Create a new branch for your feature
3. Add your rules in the appropriate category
4. Include tests if possible
5. Submit a pull request

## License

This project is licensed under CC BY-NC 4.0 - see the individual rule files for specific licensing information.
