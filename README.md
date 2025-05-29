# Secure Coding Assistant

A VS Code extension that helps identify and fix security vulnerabilities in your code through static analysis and AI-powered code review.

## Features

- 🔍 **Code Scanning**: Scan selected code, entire files, or complete folders for security vulnerabilities
- 🔐 **Multiple LLM Providers**: Support for OpenAI, Anthropic, Google, and custom LLM providers
- 🛡️ **Security Analysis**: Detects various security issues including:
  - Hardcoded cryptographic hashes
  - Hardcoded credentials and secrets
  - Insecure cryptographic implementations
  - SQL injection vulnerabilities
  - Cross-site scripting (XSS)
  - Command injection
  - Path traversal
  - Insecure deserialization
  - Insecure direct object references
  - Security misconfiguration

## Installation

1. Open VS Code
2. Go to the Extensions view (Ctrl+Shift+X)
3. Search for "Secure Coding Assistant"
4. Click Install

## Usage

### Configuration

1. Set your preferred LLM provider in VS Code settings:
   - Open Settings (Ctrl+,)
   - Search for "Secure Coding Assistant"
   - Select your preferred provider (OpenAI, Anthropic, Google, or Custom)

2. Add your API keys:
   - Use the command palette (Ctrl+Shift+P)
   - Search for "Secure Coding: Add [Provider] API Key"
   - Enter your API key when prompted

### Commands

- **Scan Selection**: Right-click selected code and choose "Secure Coding: Scan Selection"
- **Scan File**: Right-click a file in the explorer and choose "Secure Coding: Scan File"
- **Scan Folder**: Right-click a folder in the explorer and choose "Secure Coding: Scan Folder"
- **Show Output**: View detailed scan results in the output channel

## Supported File Types

- TypeScript/JavaScript (.ts, .js)
- Python (.py)
- Java (.java)
- C/C++ (.c, .cpp)
- Go (.go)
- Rust (.rs)
- PHP (.php)
- Ruby (.rb)
- C# (.cs)
- Swift (.swift)
- Kotlin (.kt)
- Objective-C (.m)
- Header files (.h, .hpp)
- Configuration files (.json, .yaml, .yml)
- Web files (.html, .css, .scss, .less)
- Shell scripts (.sh, .ps1, .bat)

## Requirements

- Visual Studio Code 1.85.0 or higher
- API keys for your chosen LLM provider(s)

## Extension Settings

- `secureCodingAssistant.preferredLlm`: Choose your preferred LLM provider
- `secureCodingAssistant.openai.model`: Configure OpenAI model
- `secureCodingAssistant.openai.systemPrompt`: Customize system prompt
- `secureCodingAssistant.openai.userPrompt`: Customize user prompt

## Known Issues

- Large files may take longer to scan
- Some complex security patterns may require manual review
- Custom LLM providers must follow OpenAI-compatible API format

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/oyesanyf/magicAIcode/blob/main/LICENSE) file for details.

## Acknowledgments

- OpenAI for GPT models
- Anthropic for Claude models
- Google for Gemini models
- VS Code team for the excellent extension API
