# YARA-X Features and Differences

This document outlines the key features and differences between YARA-X and classic YARA.

## Key Features

### Performance Improvements
- Faster rule matching through optimized Rust implementation
- Better memory management
- Improved string matching algorithms

### Enhanced Modules
- PE module improvements for better Windows binary analysis
- ELF module for Linux binary analysis
- Mach-O module for macOS binary analysis
- .NET module for managed code analysis
- Additional utility modules (hash, math, string, time)

### Better Error Handling
- More detailed error messages
- Better validation of rule syntax
- Improved reporting of rule compilation issues

## Differences from Classic YARA

### Rule Syntax
- YARA-X maintains compatibility with classic YARA rules
- Some new features and optimizations are available
- Better handling of undefined values

### Module Usage
- Enhanced module capabilities
- Better error reporting for module operations
- More consistent module behavior

### Configuration
- Uses TOML configuration file
- More granular control over scanning behavior
- Better logging and output options

## Best Practices

1. **Rule Writing**
   - Use the new string matching optimizations
   - Leverage enhanced module capabilities
   - Take advantage of better error reporting

2. **Performance**
   - Use appropriate thread count for your system
   - Set reasonable file size limits
   - Enable only needed modules

3. **Testing**
   - Test rules with both positive and negative samples
   - Use the detailed output mode for debugging
   - Validate rule behavior with different file types

## Resources

- [Official YARA-X Documentation](https://virustotal.github.io/yara-x/docs/)
- [YARA-X GitHub Repository](https://github.com/VirusTotal/yara-x)
- [YARA-X vs YARA Comparison](https://virustotal.github.io/yara-x/docs/intro/yara-x-vs-yara/) 