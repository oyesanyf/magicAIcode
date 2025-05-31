"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.LlmProvider = void 0;
exports.activate = activate;
exports.getApiKey = getApiKey;
exports.getPreferredLlm = getPreferredLlm;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const path = __importStar(require("path"));
const axios_1 = __importDefault(require("axios"));
const openai_1 = __importDefault(require("openai"));
const sdk_1 = require("@anthropic-ai/sdk");
const generative_ai_1 = require("@google/generative-ai");
console.log("Attempting to require 'openai' directly at activation start...");
try {
    const anOpenAI = require('openai');
    console.log('DIAGNOSTIC: OpenAI module loaded successfully via require():', typeof anOpenAI);
}
catch (e) {
    console.error('DIAGNOSTIC: Failed to load OpenAI module via require():', e.message, e.stack);
}
// Define LLM provider keys for built-in providers
var LlmProvider;
(function (LlmProvider) {
    LlmProvider["OpenAI"] = "OpenAI";
    LlmProvider["Anthropic"] = "Anthropic";
    LlmProvider["Google"] = "Google";
})(LlmProvider || (exports.LlmProvider = LlmProvider = {}));
const BUILT_IN_SECRET_KEYS = {
    [LlmProvider.OpenAI]: 'secureCodingAssistant.openaiApiKey',
    [LlmProvider.Anthropic]: 'secureCodingAssistant.anthropicApiKey',
    [LlmProvider.Google]: 'secureCodingAssistant.googleApiKey',
};
// Helper function to get the secret key for a built-in provider
function getBuiltInSecretKey(provider) {
    return BUILT_IN_SECRET_KEYS[provider];
}
// Output channel for logging
let outputChannel;
// Add function to get scan configuration
function getScanConfiguration() {
    const config = vscode.workspace.getConfiguration('secureCodingAssistant');
    return {
        sourceCodeExtensions: config.get('sourceCodeExtensions', [
            '.ts', '.js', '.py', '.java', '.c', '.cpp', '.go', '.rs', '.php', '.rb',
            '.cs', '.swift', '.kt', '.m', '.h', '.hpp', '.json', '.yaml', '.yml',
            '.xml', '.html', '.css', '.scss', '.less', '.sh', '.ps1', '.bat'
        ]),
        excludedDirectories: config.get('excludedDirectories', [
            'node_modules', 'dist', 'build', 'out', 'extension', 'bin', 'obj',
            '.git', '.svn', '.hg', '.vscode', '.vscode-test',
            'venv', 'env', '.env', '__pycache__'
        ]),
        defaultModel: config.get('defaultModel', 'gpt-3.5-turbo'),
        batchSize: config.get('scanBatchSize', 5)
    };
}
// Placeholder function for LLM API call
async function callLlmApi(providerDisplayName, apiKey, codeSnippet, languageId, endpointUrl) {
    // Log the call for debugging purposes
    let logMessage = `LLM API Call: Provider: ${providerDisplayName}, Language: ${languageId}`;
    if (endpointUrl) {
        logMessage += `, Endpoint: ${endpointUrl}`;
    }
    logMessage += `, API Key (first 5 chars): ${apiKey ? apiKey.substring(0, Math.min(5, apiKey.length)) : 'N/A'}...`;
    if (outputChannel) {
        outputChannel.appendLine(logMessage);
    }
    // Common system prompt for all LLM providers
    const systemPrompt = `You are a code security tool, a high-assurance code validation and security-auditing assistant.

Your only allowed input is source code pasted or imported by the user. Reject any message that does not include code. Do not respond to general questions, instructions, or comments unless they are accompanied by code.

Capabilities:
- Source Code Analysis
- Syntax and logic flaws detection
- Code quality and best practices validation
- Secure coding violations and known vulnerability patterns
- Performance & Complexity analysis
- Maintainability & Style checking
- Cryptographic hash detection and validation
- Dependency and Library Analysis
  * Check for known vulnerable dependencies
  * Identify outdated or deprecated libraries
  * Detect insecure library usage patterns
  * Analyze package.json, requirements.txt, and other dependency files
  * Flag libraries with known CVEs or security advisories

For each issue found, provide:
- Line number
- Vulnerability or logic issue
- Explanation of the problem
- Suggested fix with secure alternatives
- CWE or OWASP references when applicable
- For library issues: CVE IDs and affected versions

IMPORTANT: You MUST detect and report the following security issues:
1. Hardcoded cryptographic hashes (SHA-1, SHA-256, SHA-384, SHA-512, Tiger, Whirlpool)
2. Hardcoded credentials and secrets
3. Insecure cryptographic implementations
4. SQL injection vulnerabilities
5. Cross-site scripting (XSS)
6. Command injection
7. Path traversal
8. Insecure deserialization
9. Insecure direct object references
10. Security misconfiguration
11. Vulnerable dependencies and libraries
12. Outdated or deprecated packages
13. Insecure library usage patterns

When analyzing code, pay special attention to:
- Variable assignments containing hash values
- String literals that match hash patterns
- Comments indicating hash types
- Any hardcoded cryptographic values
- Import statements and dependency declarations
- Library version specifications
- Usage of known vulnerable functions from libraries

Include accuracy scoring:
- Hallucination Score (0.0-1.0, lower is better)
- Confidence Score (0.0-1.0, higher is better)

Output must follow this structure:
1. Summary (language, risk rating, issue count)
2. Validated Code (clean blocks, good practices)
3. Issues Found (detailed per issue)
4. Performance & Complexity Highlights
5. Test Stub Offer
6. Dependency Analysis (if applicable)

Respond in JSON format with the following structure:
{
    "summary": {
        "language": "string",
        "riskRating": "High|Medium|Low",
        "issueCount": number
    },
    "validatedCode": ["string"],
    "issues": [{
        "id": "string",
        "description": "string",
        "location": "string",
        "severity": "High|Medium|Low",
        "recommendation": "string",
        "lineNumber": "string",
        "cweId": "string",
        "owaspReference": "string",
        "hallucinationScore": number,
        "confidenceScore": number,
        "llmProvider": "string",
        "cveId": "string",
        "affectedVersions": "string",
        "fixedVersions": "string"
    }],
    "performanceHighlights": ["string"],
    "dependencyAnalysis": {
        "vulnerableDependencies": [{
            "name": "string",
            "version": "string",
            "cveId": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "recommendation": "string"
        }],
        "outdatedDependencies": [{
            "name": "string",
            "currentVersion": "string",
            "latestVersion": "string",
            "updateRecommendation": "string"
        }]
    }
}`;
    const userPrompt = `Analyze the following {languageId} code for security vulnerabilities and code quality issues. Pay special attention to:

1. Hardcoded cryptographic hashes (SHA-1, SHA-256, SHA-384, SHA-512, Tiger, Whirlpool)
2. Hardcoded credentials and secrets
3. Insecure cryptographic implementations
4. Other security vulnerabilities

IMPORTANT: Look for variable assignments containing hash values and string literals that match hash patterns.

\`\`\`
{codeSnippet}
\`\`\`

Provide a comprehensive security analysis following the specified structure. Include all detected vulnerabilities, their severity, and recommended fixes. Ensure the response is in valid JSON format as specified in the system prompt.`;
    try {
        switch (providerDisplayName) {
            case LlmProvider.OpenAI:
                const openai = new openai_1.default({ apiKey });
                const openaiResponse = await openai.chat.completions.create({
                    model: 'gpt-3.5-turbo',
                    messages: [
                        { role: 'system', content: systemPrompt },
                        { role: 'user', content: userPrompt.replace('{languageId}', languageId).replace('{codeSnippet}', codeSnippet) }
                    ],
                    response_format: { type: 'json_object' }
                });
                const content = openaiResponse.choices[0]?.message?.content || '[]';
                // Ensure llmProvider is set in the response
                try {
                    const result = JSON.parse(content);
                    if (result.issues) {
                        result.issues.forEach((issue) => {
                            issue.llmProvider = LlmProvider.OpenAI;
                        });
                    }
                    else if (Array.isArray(result)) {
                        result.forEach((issue) => {
                            issue.llmProvider = LlmProvider.OpenAI;
                        });
                    }
                    return JSON.stringify(result);
                }
                catch (e) {
                    return content;
                }
            case LlmProvider.Anthropic:
                try {
                    const anthropic = new sdk_1.Anthropic({ apiKey });
                    const anthropicResponse = await anthropic.messages.create({
                        model: 'claude-3-opus-20240229',
                        max_tokens: 4000,
                        messages: [
                            { role: 'user', content: `${systemPrompt}\n\n${userPrompt.replace('{languageId}', languageId).replace('{codeSnippet}', codeSnippet)}` }
                        ]
                    });
                    const content = anthropicResponse.content[0].text;
                    // Ensure llmProvider is set in the response
                    try {
                        const result = JSON.parse(content);
                        if (result.issues) {
                            result.issues.forEach((issue) => {
                                issue.llmProvider = LlmProvider.Anthropic;
                            });
                        }
                        else if (Array.isArray(result)) {
                            result.forEach((issue) => {
                                issue.llmProvider = LlmProvider.Anthropic;
                            });
                        }
                        return JSON.stringify(result);
                    }
                    catch (e) {
                        return content;
                    }
                }
                catch (error) {
                    if (outputChannel) {
                        outputChannel.appendLine(`Error calling Anthropic API: ${error.message}`);
                    }
                    return '[]';
                }
            case LlmProvider.Google:
                try {
                    const genAI = new generative_ai_1.GoogleGenerativeAI(apiKey);
                    const model = genAI.getGenerativeModel({ model: 'gemini-pro' });
                    const googleResponse = await model.generateContent([
                        { text: `${systemPrompt}\n\n${userPrompt.replace('{languageId}', languageId).replace('{codeSnippet}', codeSnippet)}` }
                    ]);
                    const content = googleResponse.response.text();
                    // Ensure llmProvider is set in the response
                    try {
                        const result = JSON.parse(content);
                        if (result.issues) {
                            result.issues.forEach((issue) => {
                                issue.llmProvider = LlmProvider.Google;
                            });
                        }
                        else if (Array.isArray(result)) {
                            result.forEach((issue) => {
                                issue.llmProvider = LlmProvider.Google;
                            });
                        }
                        return JSON.stringify(result);
                    }
                    catch (e) {
                        return content;
                    }
                }
                catch (error) {
                    if (outputChannel) {
                        outputChannel.appendLine(`Error calling Google API: ${error.message}`);
                    }
                    return '[]';
                }
            case "Custom":
                if (!endpointUrl) {
                    throw new Error("Custom LLM provider requires an endpoint URL");
                }
                try {
                    // Prepare the request payload
                    const payload = {
                        messages: [
                            { role: 'system', content: systemPrompt },
                            { role: 'user', content: userPrompt.replace('{languageId}', languageId).replace('{codeSnippet}', codeSnippet) }
                        ],
                        temperature: 0.7,
                        max_tokens: 4000
                    };
                    // Make the API call
                    const response = await axios_1.default.post(endpointUrl, payload, {
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${apiKey}`
                        },
                        timeout: 30000 // 30 second timeout
                    });
                    // Type assertion for response data
                    const responseData = response.data;
                    // Handle different response formats
                    if (responseData.choices && responseData.choices[0]) {
                        // OpenAI-compatible format
                        const content = responseData.choices[0].message.content;
                        // Ensure llmProvider is set in the response
                        try {
                            const result = JSON.parse(content);
                            if (result.issues) {
                                result.issues.forEach((issue) => {
                                    issue.llmProvider = providerDisplayName;
                                });
                            }
                            else if (Array.isArray(result)) {
                                result.forEach((issue) => {
                                    issue.llmProvider = providerDisplayName;
                                });
                            }
                            return JSON.stringify(result);
                        }
                        catch (e) {
                            return content;
                        }
                    }
                    else if (responseData.content) {
                        // Anthropic-compatible format
                        const content = responseData.content;
                        // Ensure llmProvider is set in the response
                        try {
                            const result = JSON.parse(content);
                            if (result.issues) {
                                result.issues.forEach((issue) => {
                                    issue.llmProvider = providerDisplayName;
                                });
                            }
                            else if (Array.isArray(result)) {
                                result.forEach((issue) => {
                                    issue.llmProvider = providerDisplayName;
                                });
                            }
                            return JSON.stringify(result);
                        }
                        catch (e) {
                            return content;
                        }
                    }
                    else if (responseData.text) {
                        // Simple text response
                        return JSON.stringify(responseData.text);
                    }
                    else {
                        throw new Error("Unsupported response format from custom LLM provider");
                    }
                }
                catch (error) {
                    if (outputChannel) {
                        outputChannel.appendLine(`Error calling Custom LLM API: ${error.message}`);
                        if (error.response) {
                            outputChannel.appendLine(`Response status: ${error.response.status}`);
                            outputChannel.appendLine(`Response data: ${JSON.stringify(error.response.data)}`);
                        }
                    }
                    return '[]';
                }
            default:
                if (outputChannel) {
                    outputChannel.appendLine(`Unsupported LLM provider: ${providerDisplayName}`);
                }
                return '[]';
        }
    }
    catch (error) {
        if (outputChannel) {
            outputChannel.appendLine(`Error in LLM API call: ${error.message}`);
        }
        return '[]';
    }
}
// Update security patterns to include all vulnerability types
const securityPatterns = {
    // Cryptographic Issues
    'HardcodedHashes': {
        'SHA-1': /=\s*["'][a-fA-F0-9]{40}["']/,
        'SHA-256': /=\s*["'][a-fA-F0-9]{64}["']/,
        'SHA-384': /=\s*["'][a-fA-F0-9]{96}["']/,
        'SHA-512': /=\s*["'][a-fA-F0-9]{128}["']/,
        'Tiger': /=\s*["'][a-fA-F0-9]{48}["']/,
        'Whirlpool': /=\s*["'][a-fA-F0-9]{128}["']/,
        'MD5': /=\s*["'][a-fA-F0-9]{32}["']/,
        'RIPEMD': /=\s*["'][a-fA-F0-9]{40}["']/
    },
    'InsecureCrypto': {
        'MD5': /md5|MD5/,
        'DES': /des|DES/,
        'RC4': /rc4|RC4/,
        'Blowfish': /blowfish|Blowfish/,
        'WeakCipher': /ecb|ECB|CBC|OFB|CFB/,
        'WeakHash': /md5|sha1|SHA1/,
        'CustomCrypto': /custom.*crypt|crypt.*custom/
    },
    // Injection Patterns
    'SQLInjection': {
        'StringConcatenation': /['"]\s*\+\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\+\s*['"]/,
        'TemplateLiteral': /`\s*\$\{.*\}\s*`/,
        'RawQuery': /executeQuery|rawQuery|query\(/,
        'DynamicSQL': /EXEC\s*\(|sp_executesql/,
        'UnsafeEval': /eval\s*\(|exec\s*\(/
    },
    'XSS': {
        'InnerHTML': /\.innerHTML\s*=/,
        'DocumentWrite': /document\.write\(/,
        'Eval': /eval\(|setTimeout\(|setInterval\(/,
        'UnsafeDOM': /\.outerHTML|\.insertAdjacentHTML/,
        'UnsafeJQuery': /\$\(.*\)\.html\(/
    },
    'CommandInjection': {
        'Exec': /exec\(|spawn\(|system\(/,
        'Shell': /shell_exec\(|passthru\(|proc_open\(/,
        'OSCommand': /os\.system|subprocess\.call/,
        'DynamicEval': /eval\(|Function\(/,
        'TemplateInjection': /\$\{.*\}|%{.*}/
    },
    // Authentication & Authorization
    'HardcodedCredentials': {
        'APIKey': /api[_-]?key|apikey|secret[_-]?key/i,
        'Password': /password\s*=\s*['"][^'"]+['"]/i,
        'Token': /token\s*=\s*['"][^'"]+['"]/i,
        'Secret': /secret\s*=\s*['"][^'"]+['"]/i,
        'Credential': /credential\s*=\s*['"][^'"]+['"]/i
    },
    'WeakAuth': {
        'BasicAuth': /basic\s+auth|authorization:\s*basic/i,
        'NoAuth': /public\s+function|public\s+class/,
        'WeakPassword': /password\s*=\s*['"][^'"]{1,7}['"]/i,
        'HardcodedToken': /token\s*=\s*['"][^'"]+['"]/i,
        'SessionFixation': /session\.id|sessionId/
    },
    // File Operations
    'PathTraversal': {
        'DotDot': /\.\.\/|\.\.\\/,
        'AbsolutePath': /\/[a-zA-Z]:\/|^\/[a-zA-Z]/,
        'UnsafePath': /path\.join|os\.path\.join/,
        'FileUpload': /\.upload\(|\.save\(/,
        'FileDownload': /\.download\(|\.get\(/
    },
    'UnsafeFileOp': {
        'FileUpload': /\.upload\(|\.save\(/,
        'FileDownload': /\.download\(|\.get\(/,
        'FileDelete': /\.delete\(|\.remove\(/,
        'FileMove': /\.move\(|\.rename\(/,
        'FileCopy': /\.copy\(|\.duplicate\(/
    },
    // Deserialization
    'UnsafeDeserialization': {
        'Pickle': /pickle\.loads\(/,
        'YAML': /yaml\.load\(/,
        'XML': /XMLDecoder|XMLReader/,
        'JSON': /JSON\.parse\(/,
        'Eval': /eval\(|Function\(/
    },
    // Memory Safety
    'BufferOverflow': {
        'UnboundedCopy': /strcpy\(|strcat\(/,
        'ArrayAccess': /\[[^\]]+\]\s*=\s*[^;]+;/,
        'UnsafeAlloc': /malloc\(|new\s+\[\]/,
        'UnsafeString': /strncpy\(|strncat\(/,
        'UnsafeArray': /Array\(|new\s+Array\(/
    },
    // Configuration
    'DebugCode': {
        'ConsoleLog': /console\.log\(|print\(/,
        'Debugger': /debugger;|breakpoint/,
        'Alert': /alert\(|confirm\(/,
        'Trace': /console\.trace\(|trace\(/,
        'Debug': /debug\(|DEBUG/
    },
    // Input Validation
    'MissingValidation': {
        'NoInputCheck': /input\(|readline\(/,
        'NoTypeCheck': /typeof|instanceof/,
        'NoLengthCheck': /\.length|\.size/,
        'NoRangeCheck': /if\s*\([^<>=!]+\s*[<>=!]+\s*[^<>=!]+\)/,
        'NoFormatCheck': /\.match\(|\.test\(/
    },
    // Error Handling
    'UnsafeErrorHandling': {
        'EmptyCatch': /catch\s*\(\s*\)/,
        'GenericException': /catch\s*\(Exception|Error\)/,
        'SwallowedException': /catch.*\{\s*\}/,
        'UnsafeThrow': /throw\s+new\s+Error/,
        'UnsafeError': /error\(|fatal\(/
    },
    // Race Conditions
    'RaceCondition': {
        'UnsafeThread': /thread\.start\(|Thread\.start\(/,
        'UnsafeAsync': /async\s+function|Promise\./,
        'UnsafeLock': /lock\(|synchronized/,
        'UnsafeWait': /wait\(|sleep\(/,
        'UnsafeNotify': /notify\(|notifyAll\(/
    },
    // Docker Security Patterns
    'DockerVulnerabilities': {
        'RootUser': /USER\s+root|RUN\s+useradd\s+-u\s+0/,
        'LatestTag': /FROM\s+.*:latest/,
        'SensitiveMount': /VOLUME\s+.*\/etc\/|VOLUME\s+.*\/var\/|VOLUME\s+.*\/usr\/|VOLUME\s+.*\/root\//,
        'PrivilegedMode': /--privileged|privileged:\s*true/,
        'ExposedPorts': /EXPOSE\s+\d+/,
        'SensitiveEnv': /ENV\s+.*PASSWORD|ENV\s+.*SECRET|ENV\s+.*KEY|ENV\s+.*TOKEN/,
        'UnsafeCommands': /RUN\s+wget\s+http:|RUN\s+curl\s+http:|RUN\s+apt-get\s+update/,
        'NoHealthCheck': /HEALTHCHECK\s+NONE/,
        'NoUserNamespace': /--userns=host/,
        'NoReadOnly': /--read-only=false/
    },
    // SCA (Software Composition Analysis) Patterns
    'SCAVulnerabilities': {
        'OutdatedPackage': /version\s*=\s*["']\d+\.\d+\.\d+["']/,
        'KnownVulnerablePackage': /package-lock\.json|yarn\.lock|requirements\.txt|pom\.xml|build\.gradle/,
        'InsecureDependency': /dependencies\s*{|devDependencies\s*{|requirements\s*=/,
        'NoVersionLock': /^\s*[^#].*[~^]/,
        'UnpinnedVersion': /version\s*=\s*["']\*["']|version\s*=\s*["']latest["']/,
        'KnownVulnerableVersion': /version\s*=\s*["']\d+\.\d+\.\d+["']/,
        'InsecureSource': /registry\.npmjs\.org|pypi\.org|maven\.apache\.org/,
        'NoIntegrityCheck': /integrity\s*=|sha512\s*=|sha256\s*=/,
        'NoVulnerabilityScan': /audit\s*=|security\s*scan\s*=|vulnerability\s*check\s*=/
    }
};
// Update getExactLineNumber to preserve exact line structure including spaces
function getExactLineNumber(originalCode, targetLine) {
    // Split by newline but preserve empty lines and spaces
    const lines = originalCode.split(/\r?\n/);
    const targetTrimmed = targetLine.trim();
    // Keep track of the original line number including empty lines and spaces
    let lineNumber = 0;
    for (const line of lines) {
        lineNumber++;
        // Compare trimmed lines but preserve original line number
        if (line.trim() === targetTrimmed) {
            return lineNumber;
        }
    }
    return 0;
}
// Update detectSecurityVulnerabilities to preserve exact line structure
function detectSecurityVulnerabilities(code) {
    const vulnerabilities = [];
    // Split by newline but preserve empty lines and spaces
    const originalLines = code.split(/\r?\n/);
    let currentLineNumber = 0;
    originalLines.forEach((line) => {
        currentLineNumber++; // Increment for every line, including empty ones and spaces
        // Check each category of security patterns
        for (const [category, patterns] of Object.entries(securityPatterns)) {
            for (const [issueType, pattern] of Object.entries(patterns)) {
                if (pattern.test(line)) {
                    const severity = getSeverityForIssue(category, issueType);
                    const recommendation = getRecommendationForIssue(category, issueType);
                    const cweId = getCWEForIssue(category, issueType);
                    const owaspRef = getOWASPReferenceForIssue(category, issueType);
                    vulnerabilities.push({
                        id: `${category}_${issueType}`,
                        description: `Hardcoded ${issueType} hash detected in variable assignment`,
                        location: `Line ${currentLineNumber}`,
                        severity: severity,
                        recommendation: recommendation,
                        llmProvider: "Local Scanner",
                        fileName: "current_file",
                        lineNumber: currentLineNumber.toString(),
                        cweId: cweId,
                        owaspReference: owaspRef,
                        hallucinationScore: 0.1,
                        confidenceScore: 0.9
                    });
                }
            }
        }
    });
    return vulnerabilities;
}
// Update getSeverityForIssue to include Docker and SCA severities
function getSeverityForIssue(category, issueType) {
    const highSeverityIssues = [
        'HardcodedHashes', 'HardcodedCredentials', 'SQLInjection', 'CommandInjection',
        'UnsafeDeserialization', 'BufferOverflow', 'RootUser', 'PrivilegedMode',
        'KnownVulnerablePackage', 'InsecureDependency'
    ];
    const mediumSeverityIssues = [
        'XSS', 'PathTraversal', 'InsecureCrypto', 'LatestTag', 'SensitiveMount',
        'ExposedPorts', 'SensitiveEnv', 'OutdatedPackage', 'NoVersionLock'
    ];
    if (highSeverityIssues.includes(issueType))
        return "High";
    if (mediumSeverityIssues.includes(issueType))
        return "Medium";
    return "Low";
}
// Update getRecommendationForIssue to include Docker and SCA recommendations
function getRecommendationForIssue(category, issueType) {
    const recommendations = {
        'HardcodedHashes': 'Remove hardcoded hash values from variable assignments. Instead, use a secure configuration management system or environment variables to store sensitive values. Consider using a secrets management solution.',
        'InsecureCrypto': 'Use modern, secure cryptographic algorithms and libraries. Avoid deprecated or weak algorithms.',
        'SQLInjection': 'Use parameterized queries or prepared statements instead of string concatenation.',
        'XSS': 'Use proper output encoding and sanitization. Consider using a security library for HTML escaping.',
        'CommandInjection': 'Use parameterized commands and avoid shell execution. Validate and sanitize all inputs.',
        'HardcodedCredentials': 'Move credentials to secure configuration management or environment variables.',
        'PathTraversal': 'Validate and sanitize file paths. Use proper path resolution functions.',
        'UnsafeDeserialization': 'Use safe deserialization methods and validate input data.',
        'BufferOverflow': 'Use safe string handling functions and bounds checking.',
        'DebugCode': 'Remove debug code before production deployment.',
        // Docker recommendations
        'RootUser': 'Avoid running containers as root. Create and use a non-root user.',
        'LatestTag': 'Avoid using :latest tag. Pin to specific versions for better security and reproducibility.',
        'SensitiveMount': 'Review and restrict volume mounts to prevent sensitive data exposure.',
        'PrivilegedMode': 'Avoid running containers in privileged mode. Use specific capabilities instead.',
        'ExposedPorts': 'Only expose necessary ports and use non-standard ports when possible.',
        'SensitiveEnv': 'Avoid storing sensitive information in environment variables. Use secrets management.',
        'UnsafeCommands': 'Avoid downloading and executing untrusted content. Use multi-stage builds.',
        'NoHealthCheck': 'Implement health checks to ensure container health monitoring.',
        'NoUserNamespace': 'Enable user namespace remapping for better security isolation.',
        'NoReadOnly': 'Run containers in read-only mode when possible to prevent modifications.',
        // SCA recommendations
        'OutdatedPackage': 'Update packages to their latest secure versions.',
        'KnownVulnerablePackage': 'Replace vulnerable packages with secure alternatives.',
        'InsecureDependency': 'Review and update dependencies to secure versions.',
        'NoVersionLock': 'Pin dependency versions to specific releases.',
        'UnpinnedVersion': 'Avoid using wildcard or latest versions. Pin to specific versions.',
        'KnownVulnerableVersion': 'Update to a version that addresses known vulnerabilities.',
        'InsecureSource': 'Use trusted package sources and verify package integrity.',
        'NoIntegrityCheck': 'Implement integrity checks for downloaded packages.',
        'NoVulnerabilityScan': 'Implement automated vulnerability scanning in CI/CD pipeline.'
    };
    return recommendations[issueType] || 'Review and fix the identified security issue.';
}
// Update getCWEForIssue to include Docker and SCA CWEs
function getCWEForIssue(category, issueType) {
    const cweMap = {
        'HardcodedHashes': 'CWE-798',
        'InsecureCrypto': 'CWE-326',
        'SQLInjection': 'CWE-89',
        'XSS': 'CWE-79',
        'CommandInjection': 'CWE-78',
        'HardcodedCredentials': 'CWE-798',
        'PathTraversal': 'CWE-22',
        'UnsafeDeserialization': 'CWE-502',
        'BufferOverflow': 'CWE-120',
        'DebugCode': 'CWE-489',
        // Docker CWEs
        'RootUser': 'CWE-250',
        'LatestTag': 'CWE-1021',
        'SensitiveMount': 'CWE-552',
        'PrivilegedMode': 'CWE-250',
        'ExposedPorts': 'CWE-200',
        'SensitiveEnv': 'CWE-798',
        'UnsafeCommands': 'CWE-78',
        'NoHealthCheck': 'CWE-1021',
        'NoUserNamespace': 'CWE-250',
        'NoReadOnly': 'CWE-250',
        // SCA CWEs
        'OutdatedPackage': 'CWE-1021',
        'KnownVulnerablePackage': 'CWE-1021',
        'InsecureDependency': 'CWE-1021',
        'NoVersionLock': 'CWE-1021',
        'UnpinnedVersion': 'CWE-1021',
        'KnownVulnerableVersion': 'CWE-1021',
        'InsecureSource': 'CWE-829',
        'NoIntegrityCheck': 'CWE-494',
        'NoVulnerabilityScan': 'CWE-1021'
    };
    return cweMap[issueType] || '';
}
// Update getOWASPReferenceForIssue to include Docker and SCA references
function getOWASPReferenceForIssue(category, issueType) {
    const owaspMap = {
        'HardcodedHashes': 'A7:2017-Identification and Authentication Failures',
        'InsecureCrypto': 'A2:2017-Broken Authentication',
        'SQLInjection': 'A1:2017-Injection',
        'XSS': 'A7:2017-Cross-Site Scripting (XSS)',
        'CommandInjection': 'A1:2017-Injection',
        'HardcodedCredentials': 'A7:2017-Identification and Authentication Failures',
        'PathTraversal': 'A5:2017-Broken Access Control',
        'UnsafeDeserialization': 'A8:2017-Insecure Deserialization',
        'BufferOverflow': 'A1:2017-Injection',
        'DebugCode': 'A9:2017-Using Components with Known Vulnerabilities',
        // Docker OWASP references
        'RootUser': 'A5:2017-Broken Access Control',
        'LatestTag': 'A9:2017-Using Components with Known Vulnerabilities',
        'SensitiveMount': 'A5:2017-Broken Access Control',
        'PrivilegedMode': 'A5:2017-Broken Access Control',
        'ExposedPorts': 'A5:2017-Broken Access Control',
        'SensitiveEnv': 'A3:2017-Sensitive Data Exposure',
        'UnsafeCommands': 'A8:2017-Insecure Deserialization',
        'NoHealthCheck': 'A9:2017-Using Components with Known Vulnerabilities',
        'NoUserNamespace': 'A5:2017-Broken Access Control',
        'NoReadOnly': 'A5:2017-Broken Access Control',
        // SCA OWASP references
        'OutdatedPackage': 'A9:2017-Using Components with Known Vulnerabilities',
        'KnownVulnerablePackage': 'A9:2017-Using Components with Known Vulnerabilities',
        'InsecureDependency': 'A9:2017-Using Components with Known Vulnerabilities',
        'NoVersionLock': 'A9:2017-Using Components with Known Vulnerabilities',
        'UnpinnedVersion': 'A9:2017-Using Components with Known Vulnerabilities',
        'KnownVulnerableVersion': 'A9:2017-Using Components with Known Vulnerabilities',
        'InsecureSource': 'A9:2017-Using Components with Known Vulnerabilities',
        'NoIntegrityCheck': 'A8:2017-Insecure Deserialization',
        'NoVulnerabilityScan': 'A9:2017-Using Components with Known Vulnerabilities'
    };
    return owaspMap[issueType] || '';
}
// Update processVulnerabilities to handle exact line numbers
function processVulnerabilities(vulnerabilities, providerName, fileName, languageId, originalCode) {
    // First, detect security vulnerabilities using our patterns
    const securityVulns = detectSecurityVulnerabilities(originalCode);
    // Handle both old and new format
    let processedVulns = [];
    if (vulnerabilities.length > 0 && 'summary' in vulnerabilities[0]) {
        // New format - extract issues from the comprehensive analysis
        const analysis = vulnerabilities[0];
        processedVulns = (analysis.issues || []).map((issue) => {
            // Get line number from either lineNumber or location
            let lineNumber = 0;
            if (issue.lineNumber) {
                lineNumber = parseInt(issue.lineNumber);
            }
            else if (issue.location) {
                // Extract line number from location string (e.g., "Line 42" or "Line: 42")
                const match = issue.location.match(/Line\s*:?\s*(\d+)/i);
                if (match) {
                    lineNumber = parseInt(match[1]);
                }
            }
            // If we still don't have a valid line number, try to find it in the original code
            if (!lineNumber || isNaN(lineNumber)) {
                const exactLineNumber = getExactLineNumber(originalCode, issue.location || '');
                lineNumber = exactLineNumber || 0;
            }
            return {
                id: issue.id || 'Unknown',
                description: issue.description || 'No description provided',
                location: `Line ${lineNumber}`,
                severity: issue.severity || 'Medium',
                recommendation: issue.recommendation || 'No recommendation provided',
                llmProvider: providerName,
                fileName: fileName || issue.fileName,
                lineNumber: lineNumber.toString(),
                cweId: issue.cweId,
                owaspReference: issue.owaspReference,
                hallucinationScore: issue.hallucinationScore,
                confidenceScore: issue.confidenceScore
            };
        });
    }
    else {
        // Old format - process as before
        processedVulns = vulnerabilities.map(vuln => {
            // Get line number from either lineNumber or location
            let lineNumber = 0;
            if (vuln.lineNumber) {
                lineNumber = parseInt(vuln.lineNumber);
            }
            else if (vuln.location) {
                // Extract line number from location string (e.g., "Line 42" or "Line: 42")
                const match = vuln.location.match(/Line\s*:?\s*(\d+)/i);
                if (match) {
                    lineNumber = parseInt(match[1]);
                }
            }
            // If we still don't have a valid line number, try to find it in the original code
            if (!lineNumber || isNaN(lineNumber)) {
                const exactLineNumber = getExactLineNumber(originalCode, vuln.location || '');
                lineNumber = exactLineNumber || 0;
            }
            return {
                id: vuln.id || 'Unknown',
                description: vuln.description || 'No description provided',
                location: `Line ${lineNumber}`,
                severity: vuln.severity || 'Medium',
                recommendation: vuln.recommendation || 'No recommendation provided',
                llmProvider: providerName,
                fileName: fileName || vuln.fileName,
                lineNumber: lineNumber.toString(),
                cweId: vuln.cweId,
                owaspReference: vuln.owaspReference,
                hallucinationScore: vuln.hallucinationScore,
                confidenceScore: vuln.confidenceScore
            };
        });
    }
    // Combine LLM-detected vulnerabilities with pattern-based security vulnerabilities
    return [...processedVulns, ...securityVulns];
}
// Update analyzeCodeWithOpenAI to preserve exact line structure
async function analyzeCodeWithOpenAI(apiKey, codeSnippet, languageId, fileName = '') {
    const { model, systemPrompt, userPrompt } = getOpenAIConfig();
    try {
        // Keep the original code exactly as is, including all spaces and empty lines
        const formattedCode = codeSnippet;
        // Split by newline but preserve empty lines and spaces
        const originalLines = codeSnippet.split(/\r?\n/);
        const openai = new openai_1.default({ apiKey });
        const response = await openai.chat.completions.create({
            model: model,
            messages: [
                { role: 'system', content: systemPrompt },
                { role: 'user', content: userPrompt.replace('{languageId}', languageId).replace('{codeSnippet}', formattedCode) }
            ],
            response_format: { type: 'json_object' },
            temperature: 0.1
        });
        const content = response.choices[0]?.message?.content;
        if (content) {
            try {
                const result = JSON.parse(content);
                let vulnerabilities = [];
                // Process vulnerabilities based on format
                if (Array.isArray(result)) {
                    vulnerabilities = result.map((v) => {
                        const lineNumber = v.lineNumber ? parseInt(v.lineNumber) : 0;
                        const exactLineNumber = getExactLineNumber(codeSnippet, v.location || '');
                        return {
                            ...v,
                            llmProvider: LlmProvider.OpenAI,
                            fileName,
                            lineNumber: (exactLineNumber || lineNumber).toString(),
                            location: `Line ${exactLineNumber || lineNumber}`
                        };
                    });
                }
                else if (result?.vulnerabilities) {
                    vulnerabilities = result.vulnerabilities.map((v) => {
                        const lineNumber = v.lineNumber ? parseInt(v.lineNumber) : 0;
                        const exactLineNumber = getExactLineNumber(codeSnippet, v.location || '');
                        return {
                            ...v,
                            llmProvider: LlmProvider.OpenAI,
                            fileName,
                            lineNumber: (exactLineNumber || lineNumber).toString(),
                            location: `Line ${exactLineNumber || lineNumber}`
                        };
                    });
                }
                else if (result?.issues) {
                    vulnerabilities = result.issues.map((v) => {
                        const lineNumber = v.lineNumber ? parseInt(v.lineNumber) : 0;
                        const exactLineNumber = getExactLineNumber(codeSnippet, v.location || '');
                        return {
                            ...v,
                            llmProvider: LlmProvider.OpenAI,
                            fileName,
                            lineNumber: (exactLineNumber || lineNumber).toString(),
                            location: `Line ${exactLineNumber || lineNumber}`
                        };
                    });
                }
                // Process vulnerabilities using the helper function
                const processedVulnerabilities = processVulnerabilities(vulnerabilities, LlmProvider.OpenAI, fileName, languageId, codeSnippet);
                // Ensure line numbers are accurate
                processedVulnerabilities.forEach(v => {
                    if (!v.llmProvider) {
                        v.llmProvider = LlmProvider.OpenAI;
                    }
                    if (!v.fileName) {
                        v.fileName = fileName;
                    }
                    if (v.lineNumber) {
                        const lineNumber = parseInt(v.lineNumber);
                        if (lineNumber > 0 && lineNumber <= originalLines.length) {
                            v.location = `Line ${lineNumber}`;
                        }
                    }
                });
                return processedVulnerabilities;
            }
            catch (parseError) {
                if (outputChannel) {
                    outputChannel.appendLine(`Error parsing OpenAI response: ${parseError.message}. Response: ${content}`);
                }
                return [];
            }
        }
        return [];
    }
    catch (error) {
        if (outputChannel) {
            outputChannel.appendLine(`Error calling OpenAI API: ${error.message}`);
        }
        return [];
    }
}
// Update formatAndLogVulnerabilities to handle line numbers properly
function formatAndLogVulnerabilities(vulnerabilities, providerDisplayName) {
    if (!outputChannel)
        return;
    outputChannel.clear();
    if (vulnerabilities.length === 0) {
        outputChannel.appendLine(`No vulnerabilities detected by ${providerDisplayName}.`);
        return;
    }
    outputChannel.appendLine("Scan results:");
    vulnerabilities.forEach(vuln => {
        outputChannel.appendLine("----------------------------------------");
        outputChannel.appendLine(`Vulnerability ID: ${vuln.id}`);
        outputChannel.appendLine(`Description: ${vuln.description}`);
        outputChannel.appendLine(`Severity: ${vuln.severity}`);
        if (vuln.fileName) {
            outputChannel.appendLine(`File: ${vuln.fileName}`);
            // Ensure line number is valid before displaying
            const lineNumber = parseInt(vuln.lineNumber || '0');
            if (!isNaN(lineNumber) && lineNumber > 0) {
                outputChannel.appendLine(`Location: Line ${lineNumber}`);
            }
            else {
                outputChannel.appendLine(`Location: Line 0 (Unable to determine exact line)`);
            }
        }
        else {
            outputChannel.appendLine(`File: Unknown`);
        }
        outputChannel.appendLine(`Recommendation: ${vuln.recommendation}`);
        outputChannel.appendLine(`Detected by: ${vuln.llmProvider || providerDisplayName}`);
        // Add the rewritten code suggestion
        const fix = generateCodeFix(vuln, vuln.fileName?.split('.').pop() || '');
        if (fix) {
            outputChannel.appendLine("\nSuggested Fix:");
            outputChannel.appendLine(fix);
        }
    });
    outputChannel.appendLine("----------------------------------------");
}
// Update generateCodeFix to handle all vulnerability types
function generateCodeFix(vuln, languageId) {
    const description = vuln.description.toLowerCase();
    const location = vuln.location;
    // Handle all vulnerability types with language-specific fixes
    const fixes = {
        'python': {
            'hardcoded hash': `# Instead of hardcoded hash:
${location}

# Use environment variable or secure configuration:
hash_value = os.getenv('HASH_VALUE') or config.get('hash_value')`,
            'insecure crypto': `# Instead of weak crypto:
${location}

# Use strong cryptography:
from cryptography.fernet import Fernet
key = Fernet.generate_key()
cipher_suite = Fernet(key)`,
            'sql injection': `# Instead of string concatenation:
${location}

# Use parameterized queries:
cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))`,
            'xss': `# Instead of unsafe HTML:
${location}

# Use proper escaping:
from html import escape
safe_html = escape(user_input)`,
            'command injection': `# Instead of shell execution:
${location}

# Use subprocess safely:
subprocess.run(['command', 'arg1', 'arg2'], shell=False)`,
            'path traversal': `# Instead of direct path:
${location}

# Use secure path resolution:
safe_path = os.path.normpath(os.path.join(base_dir, user_input))
if not safe_path.startswith(base_dir):
    raise SecurityError("Invalid path")`,
            'unsafe deserialization': `# Instead of unsafe deserialization:
${location}

# Use safe deserialization:
import json
data = json.loads(user_input)  # For JSON
# Or use a safe deserialization library for other formats`,
            'buffer overflow': `# Instead of unsafe buffer:
${location}

# Use safe string handling:
safe_string = user_input[:max_length]  # Truncate
# Or use a safe buffer library`,
            'debug code': `# Instead of print statements:
${location}

# Use proper logging:
import logging
logging.debug("Debug message")`,
            'missing validation': `# Instead of no validation:
${location}

# Add input validation:
if not isinstance(user_input, str) or len(user_input) > max_length:
    raise ValueError("Invalid input")`,
            'unsafe error handling': `# Instead of empty catch:
${location}

# Use proper error handling:
try:
    # Operation
except Exception as e:
    logger.error(f"Operation failed: {e}")
    raise`,
            'race condition': `# Instead of unsafe threading:
${location}

# Use thread-safe operations:
from threading import Lock
lock = Lock()
with lock:
    # Critical section`
        },
        'javascript': {
            'hardcoded hash': `// Instead of hardcoded hash:
${location}

// Use environment variable or secure configuration:
const hashValue = process.env.HASH_VALUE || config.hashValue;`,
            'insecure crypto': `// Instead of weak crypto:
${location}

// Use strong cryptography:
const crypto = require('crypto');
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);`,
            'sql injection': `// Instead of string concatenation:
${location}

// Use parameterized queries:
db.query("SELECT * FROM users WHERE id = ?", [userId])`,
            'xss': `// Instead of unsafe HTML:
${location}

// Use proper escaping:
element.textContent = userInput;  // or
element.innerHTML = escapeHtml(userInput);`,
            'command injection': `// Instead of shell execution:
${location}

// Use child_process safely:
const { execFile } = require('child_process');
execFile('command', ['arg1', 'arg2'], (error, stdout, stderr) => {
    // Handle result
});`,
            'path traversal': `// Instead of direct path:
${location}

// Use secure path resolution:
const safePath = path.normalize(path.join(baseDir, userInput));
if (!safePath.startsWith(baseDir)) {
    throw new Error("Invalid path");
}`,
            'unsafe deserialization': `// Instead of unsafe deserialization:
${location}

// Use safe deserialization:
const data = JSON.parse(userInput);  // For JSON
// Or use a safe deserialization library for other formats`,
            'buffer overflow': `// Instead of unsafe buffer:
${location}

// Use safe string handling:
const safeString = userInput.slice(0, maxLength);  // Truncate
// Or use a safe buffer library`,
            'debug code': `// Instead of console.log:
${location}

// Use proper logging:
console.debug("Debug message");  // Or use a logging library`,
            'missing validation': `// Instead of no validation:
${location}

// Add input validation:
if (typeof userInput !== 'string' || userInput.length > maxLength) {
    throw new Error("Invalid input");
}`,
            'unsafe error handling': `// Instead of empty catch:
${location}

// Use proper error handling:
try {
    // Operation
} catch (error) {
    logger.error('Operation failed:', error);
    throw error;
}`,
            'race condition': `// Instead of unsafe async:
${location}

// Use async/await with proper error handling:
async function safeOperation() {
    try {
        await operation();
    } catch (error) {
        logger.error('Operation failed:', error);
        throw error;
    }
}`
        }
    };
    // Find the appropriate fix based on the vulnerability description
    for (const [lang, langFixes] of Object.entries(fixes)) {
        if (languageId.toLowerCase().includes(lang)) {
            for (const [vulnType, fix] of Object.entries(langFixes)) {
                if (description.includes(vulnType)) {
                    return fix;
                }
            }
        }
    }
    return null;
}
// Helper function to escape HTML
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
// Helper function to get OpenAI configuration
function getOpenAIConfig() {
    const config = vscode.workspace.getConfiguration('secureCodingAssistant.openai');
    const scanConfig = getScanConfiguration();
    const model = config.get('model', scanConfig.defaultModel);
    const systemPrompt = `You are a code security tool, a high-assurance code validation and security-auditing assistant.

Your only allowed input is source code pasted or imported by the user. Reject any message that does not include code. Do not respond to general questions, instructions, or comments unless they are accompanied by code.

Capabilities:
- Source Code Analysis
- Syntax and logic flaws detection
- Code quality and best practices validation
- Secure coding violations and known vulnerability patterns
- Performance & Complexity analysis
- Maintainability & Style checking
- Cryptographic hash detection and validation
- CVE Detection and Analysis
  * Known vulnerability identification
  * CVE ID tracking and validation
  * Affected version ranges
  * Fixed version information
  * Vulnerability severity assessment
  * Exploit availability checking
  * Patch status verification
  * Security advisory analysis
  * Common vulnerability patterns
  * Zero-day vulnerability detection
- Infrastructure as Code (IaC) Security
  * Terraform security misconfigurations
  * CloudFormation template vulnerabilities
  * Kubernetes manifest security
  * Ansible playbook security
  * Infrastructure drift detection
  * Resource misconfigurations
  * Access control issues
  * Network security
  * Storage security
  * Compute security
- API Security
  * Endpoint vulnerabilities
  * Authentication/Authorization flaws
  * Rate limiting issues
  * API versioning security
  * API documentation security
  * Input validation
  * Output encoding
  * Error handling
  * Session management
  * API key security
- Mobile Security
  * Android security issues
  * iOS security vulnerabilities
  * Mobile app configuration
  * Mobile data storage
  * Mobile authentication
  * Code signing
  * App permissions
  * Network security
  * Data encryption
  * Secure communication
- Cloud Security
  * AWS security misconfigurations
  * Azure security issues
  * GCP security vulnerabilities
  * Cloud storage security
  * Cloud IAM issues
  * Network security
  * Data protection
  * Access management
  * Compliance controls
  * Resource security
- CI/CD Security
  * Pipeline vulnerabilities
  * Build configuration issues
  * Deployment security
  * Artifact security
  * Secret management
  * Access control
  * Environment security
  * Build security
  * Test security
  * Release security
- Cryptocurrency/Blockchain Security
  * Smart contract vulnerabilities
  * Blockchain security issues
  * Cryptocurrency wallet security
  * Token security
  * Consensus mechanism issues
  * Transaction security
  * Key management
  * Network security
  * Protocol security
  * Data integrity
- IoT Security
  * Device security
  * Protocol vulnerabilities
  * Firmware security
  * IoT communication security
  * IoT data storage
  * Access control
  * Network security
  * Update security
  * Physical security
  * Data protection
- AI/ML Security
  * Model poisoning
  * Data poisoning
  * Adversarial attacks
  * Model inversion
  * Training data security
  * Model security
  * Data privacy
  * Access control
  * Output security
  * Resource security
- Supply Chain Security
  * Package tampering
  * Dependency confusion
  * Build system attacks
  * Artifact verification
  * Signing verification
  * Source verification
  * Distribution security
  * Update security
  * Integrity checks
  * Trust verification
- Compliance and Standards
  * GDPR compliance
  * HIPAA compliance
  * PCI DSS requirements
  * SOC 2 compliance
  * Industry-specific standards
  * Data protection
  * Privacy controls
  * Security controls
  * Audit requirements
  * Documentation requirements

- Package Management and Build System Analysis
  * Maven (pom.xml) analysis
    - Dependency management
    - Plugin security
    - Repository security
    - Build configuration
    - Profile security
    - Property management
    - Version management
    - Scope analysis
    - Transitive dependencies
    - Build lifecycle security
  * Gradle (build.gradle, settings.gradle) analysis
    - Dependency management
    - Plugin security
    - Repository security
    - Build configuration
    - Task security
    - Version catalogs
    - Dependency constraints
    - Build script security
    - Transitive dependencies
    - Build optimization
  * npm (package.json) analysis
    - Dependency management
    - Script security
    - Configuration security
    - Workspace security
    - Version management
    - Package integrity
    - Access control
    - Registry security
    - Transitive dependencies
    - Build security
  * pip (requirements.txt, setup.py) analysis
    - Dependency management
    - Version constraints
    - Index security
    - Package security
    - Environment security
    - Build security
    - Distribution security
    - Access control
    - Transitive dependencies
    - Package integrity
  * Ruby (Gemfile) analysis
    - Dependency management
    - Source security
    - Version constraints
    - Group security
    - Platform security
    - Gem security
    - Build security
    - Access control
    - Transitive dependencies
    - Package integrity
  * Composer (composer.json) analysis
    - Dependency management
    - Repository security
    - Version constraints
    - Script security
    - Autoload security
    - Platform security
    - Package security
    - Access control
    - Transitive dependencies
    - Build security
  * NuGet (packages.config, .csproj) analysis
    - Package management
    - Source security
    - Version constraints
    - Framework security
    - Build security
    - Package integrity
    - Access control
    - Transitive dependencies
    - Configuration security
    - Update security
  * Cargo (Cargo.toml) analysis
    - Dependency management
    - Registry security
    - Version constraints
    - Feature security
    - Build security
    - Package integrity
    - Access control
    - Transitive dependencies
    - Profile security
    - Workspace security
  * Yarn (yarn.lock) analysis
    - Dependency management
    - Integrity verification
    - Version constraints
    - Workspace security
    - Access control
    - Registry security
    - Package security
    - Transitive dependencies
    - Build security
    - Configuration security
  * Go Modules (go.mod) analysis
    - Dependency management
    - Version constraints
    - Module security
    - Proxy security
    - Access control
    - Package integrity
    - Build security
    - Transitive dependencies
    - Workspace security
    - Configuration security
  * Build System Security
    - Build script analysis
    - Task security
    - Plugin security
    - Configuration security
    - Environment security
    - Access control
    - Resource security
    - Output security
    - Cache security
    - Artifact security
  * Conan (conanfile.txt, conanfile.py) analysis
    - Dependency management
    - Profile security
    - Generator security
    - Package security
    - Build security
    - Package integrity
    - Access control
    - Transitive dependencies
    - Configuration security
    - Remote security
  * Poetry (pyproject.toml) analysis
    - Dependency management
    - Virtual environment security
    - Build system security
    - Package security
    - Script security
    - Access control
    - Transitive dependencies
    - Configuration security
    - Source security
    - Version constraints
  * SBT (build.sbt) analysis
    - Dependency management
    - Plugin security
    - Task security
    - Build configuration
    - Project security
    - Access control
    - Transitive dependencies
    - Version management
    - Repository security
    - Build optimization
  * Leiningen (project.clj) analysis
    - Dependency management
    - Profile security
    - Plugin security
    - Build security
    - Package security
    - Access control
    - Transitive dependencies
    - Configuration security
    - Repository security
    - Version management
  * Mix (mix.exs) analysis
    - Dependency management
    - Application security
    - Environment security
    - Build security
    - Package security
    - Access control
    - Transitive dependencies
    - Configuration security
    - Version constraints
    - Release security
  * Cabal (cabal.project) analysis
    - Dependency management
    - Package security
    - Build security
    - Flag security
    - Access control
    - Transitive dependencies
    - Configuration security
    - Version constraints
    - Repository security
    - Distribution security
  * Paket (paket.dependencies) analysis
    - Dependency management
    - Source security
    - Version constraints
    - Framework security
    - Package security
    - Access control
    - Transitive dependencies
    - Configuration security
    - Lock file security
    - Update security
  * Shards (shard.yml) analysis
    - Dependency management
    - Version constraints
    - Script security
    - Package security
    - Access control
    - Transitive dependencies
    - Configuration security
    - Source security
    - Build security
    - Development security
  * Dub (dub.json) analysis
    - Dependency management
    - Build type security
    - Configuration security
    - Package security
    - Access control
    - Transitive dependencies
    - Version constraints
    - Source security
    - Build security
    - Target security
  * Vcpkg (vcpkg.json) analysis
    - Dependency management
    - Port security
    - Build security
    - Package security
    - Access control
    - Transitive dependencies
    - Configuration security
    - Version constraints
    - Feature security
    - Overlay security

For each issue found, provide:
- Line number
- Vulnerability or logic issue
- Explanation of the problem
- Suggested fix with secure alternatives
- CWE or OWASP references when applicable
- For library issues: CVE IDs and affected versions

IMPORTANT: You MUST detect and report the following security issues:
1. Hardcoded cryptographic hashes (SHA-1, SHA-256, SHA-384, SHA-512, Tiger, Whirlpool)
2. Hardcoded credentials and secrets
3. Insecure cryptographic implementations
4. SQL injection vulnerabilities
5. Cross-site scripting (XSS)
6. Command injection
7. Path traversal
8. Insecure deserialization
9. Insecure direct object references
10. Security misconfiguration
11. Vulnerable dependencies and libraries
12. Outdated or deprecated packages
13. Insecure library usage patterns
14. Package management issues
15. Version conflicts
16. Insecure sources
17. Missing integrity checks
18. Outdated packages
19. Malicious packages
20. License violations
21. Access control issues
22. Build security issues
23. Configuration security
24. Dependency vulnerabilities
25. Dependency confusion
26. Build system attacks
27. Artifact verification
28. Signing verification
29. Source verification
30. Distribution security
31. Update security
32. Integrity checks
33. Trust verification
34. Compliance and standards
35. Data protection
36. Privacy controls
37. Security controls
38. Audit requirements
39. Documentation requirements
40. Package Management System Issues
    - Dependency resolution
    - Version compatibility
    - Build system security
    - Package integrity
    - Access control
    - Configuration security
    - Repository security
    - Update security
    - Lock file security
    - Development security

When analyzing code, pay special attention to:
- Variable assignments containing hash values
- String literals that match hash patterns
- Comments indicating hash types
- Any hardcoded cryptographic values
- Import statements and dependency declarations
- Library version specifications
- Usage of known vulnerable functions from libraries

Include accuracy scoring:
- Hallucination Score (0.0-1.0, lower is better)
- Confidence Score (0.0-1.0, higher is better)

Output must follow this structure:
1. Summary (language, risk rating, issue count)
2. Validated Code (clean blocks, good practices)
3. Issues Found (detailed per issue)
4. Performance & Complexity Highlights
5. Test Stub Offer
6. Dependency Analysis (if applicable)

Respond in JSON format with the following structure:
{
    "summary": {
        "language": "string",
        "riskRating": "High|Medium|Low",
        "issueCount": number
    },
    "validatedCode": ["string"],
    "issues": [{
        "id": "string",
        "description": "string",
        "location": "string",
        "severity": "High|Medium|Low",
        "recommendation": "string",
        "lineNumber": "string",
        "cweId": "string",
        "owaspReference": "string",
        "hallucinationScore": number,
        "confidenceScore": number,
        "llmProvider": "string",
        "cveId": "string",
        "affectedVersions": "string",
        "fixedVersions": "string"
    }],
    "performanceHighlights": ["string"],
    "dependencyAnalysis": {
        "vulnerableDependencies": [{
            "name": "string",
            "version": "string",
            "cveId": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "recommendation": "string"
        }],
        "outdatedDependencies": [{
            "name": "string",
            "currentVersion": "string",
            "latestVersion": "string",
            "updateRecommendation": "string"
        }]
    },
    "packageManagementAnalysis": {
        "buildSystemIssues": [{
            "system": "string",
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string"
        }],
        "dependencyIssues": [{
            "package": "string",
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string",
            "affectedVersions": "string",
            "fixedVersions": "string"
        }],
        "configurationIssues": [{
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string"
        }],
        "securityIssues": [{
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string"
        }],
        "systemSpecificIssues": [{
            "system": "string",
            "type": "string",
            "severity": "High|Medium|Low",
            "description": "string",
            "location": "string",
            "recommendation": "string",
            "affectedVersions": "string",
            "fixedVersions": "string"
        }]
    }
}`;
    const userPrompt = `Analyze the following {languageId} code for security vulnerabilities and code quality issues. Pay special attention to:

1. Hardcoded cryptographic hashes (SHA-1, SHA-256, SHA-384, SHA-512, Tiger, Whirlpool)
2. Hardcoded credentials and secrets
3. Insecure cryptographic implementations
4. Other security vulnerabilities
5. Docker security issues (if Dockerfile)
6. Software Composition Analysis issues (if dependency files)
7. Known CVE vulnerabilities (e.g., Log4Shell, Spring4Shell)
8. Zero-day vulnerabilities and security advisories
9. Infrastructure as Code security (if IaC files)
10. API security issues
11. Mobile security issues
12. Cloud security issues
13. CI/CD security issues
14. Cryptocurrency/Blockchain security
15. IoT security issues
16. AI/ML security issues
17. Supply chain security
18. Compliance and standards
19. Package management and build system security
    - Dependency vulnerabilities
    - Version conflicts
    - Insecure sources
    - Missing integrity checks
    - Outdated packages
    - Malicious packages
    - License violations
    - Access control issues
    - Build security issues
    - Configuration security
20. Package management system security
    - Dependency resolution
    - Version compatibility
    - Build system security
    - Package integrity
    - Access control
    - Configuration security
    - Repository security
    - Update security
    - Lock file security
    - Development security

IMPORTANT: Look for variable assignments containing hash values and string literals that match hash patterns.

\`\`\`
{codeSnippet}
\`\`\`

Provide a comprehensive security analysis following the specified structure. Include all detected vulnerabilities, their severity, and recommended fixes. Ensure the response is in valid JSON format as specified in the system prompt.`;
    return { model, systemPrompt, userPrompt };
}
function activate(context) {
    // Create output channel
    outputChannel = vscode.window.createOutputChannel("Secure Coding Assistant");
    outputChannel.appendLine('Congratulations, your extension "secure-coding-assistant" is now active!');
    // Log the preferred LLM
    const preferredLlmOnActivation = getPreferredLlm();
    outputChannel.appendLine(`Preferred LLM on activation: ${preferredLlmOnActivation || 'Not set (user needs to configure)'}`);
    // --- Register command to show output channel ---
    const showOutputChannelCommand = vscode.commands.registerCommand('secure-coding-assistant.showOutputChannel', () => {
        outputChannel.show(true); // Pass true to preserve focus on the output channel
    });
    context.subscriptions.push(showOutputChannelCommand);
    // --- Register commands for adding API keys ---
    Object.values(LlmProvider).forEach(provider => {
        const addApiKeyCommand = vscode.commands.registerCommand(`secure-coding-assistant.add${provider}ApiKey`, async () => {
            const apiKey = await vscode.window.showInputBox({
                prompt: `Enter your ${provider} API Key`,
                password: true,
                ignoreFocusOut: true,
                placeHolder: `Your ${provider} API Key`,
            });
            if (apiKey) {
                try {
                    await context.secrets.store(getBuiltInSecretKey(provider), apiKey);
                    vscode.window.showInformationMessage(`${provider} API Key stored successfully.`);
                    outputChannel.appendLine(`${provider} API Key stored.`);
                }
                catch (error) {
                    vscode.window.showErrorMessage(`Failed to store ${provider} API Key. ${error.message}`);
                    outputChannel.appendLine(`Failed to store ${provider} API Key: ${error.message}`);
                }
            }
            else {
                vscode.window.showWarningMessage(`No API Key entered for ${provider}.`);
            }
        });
        context.subscriptions.push(addApiKeyCommand);
    });
    // --- Register commands for removing API keys ---
    Object.values(LlmProvider).forEach(provider => {
        const removeApiKeyCommand = vscode.commands.registerCommand(`secure-coding-assistant.remove${provider}ApiKey`, async () => {
            try {
                await context.secrets.delete(getBuiltInSecretKey(provider));
                vscode.window.showInformationMessage(`${provider} API Key removed successfully.`);
                outputChannel.appendLine(`${provider} API Key removed.`);
            }
            catch (error) {
                vscode.window.showErrorMessage(`Failed to remove ${provider} API Key. ${error.message}`);
                outputChannel.appendLine(`Failed to remove ${provider} API Key: ${error.message}`);
            }
        });
        context.subscriptions.push(removeApiKeyCommand);
    });
    // --- Register command for scanning selected code ---
    const scanSelectionCommand = vscode.commands.registerCommand('secure-coding-assistant.scanSelection', async () => {
        outputChannel.appendLine("Attempting to scan selection...");
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage("No active text editor found.");
            outputChannel.appendLine("Scan Selection: No active text editor.");
            return;
        }
        const selection = editor.selection;
        if (selection.isEmpty || editor.document.getText(selection).trim() === "") {
            vscode.window.showWarningMessage("No text selected or selection is empty.");
            outputChannel.appendLine("Scan Selection: No text selected or selection is empty.");
            return;
        }
        // Get the exact text including all spaces and empty lines
        const selectedText = editor.document.getText(selection);
        const languageId = editor.document.languageId;
        const fileName = editor.document.fileName.substring(editor.document.fileName.lastIndexOf('/') + 1);
        const preferredLlm = getPreferredLlm();
        if (!preferredLlm) {
            vscode.window.showErrorMessage("Preferred LLM not configured. Please set it in the extension settings.");
            outputChannel.appendLine("Scan Selection: Preferred LLM not configured.");
            return;
        }
        const apiKey = await getApiKey(context, preferredLlm);
        if (!apiKey) {
            vscode.window.showErrorMessage(`API Key for ${preferredLlm} not found. Please add it using the provided commands.`);
            outputChannel.appendLine(`Scan Selection: API Key for ${preferredLlm} not found.`);
            return;
        }
        outputChannel.appendLine(`Scanning selected code using ${preferredLlm} (Language: ${languageId})...`);
        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: `Scanning selection with ${preferredLlm}`,
            cancellable: false
        }, async (progress) => {
            progress.report({ message: "Analyzing selected code..." });
            try {
                let vulnerabilities = [];
                if (preferredLlm === LlmProvider.OpenAI) {
                    vulnerabilities = await analyzeCodeWithOpenAI(apiKey, selectedText, languageId, fileName);
                }
                else {
                    const analysisJsonResult = await callLlmApi(preferredLlm, apiKey, selectedText, languageId);
                    try {
                        const result = JSON.parse(analysisJsonResult);
                        vulnerabilities = Array.isArray(result) ? result : (result.issues || []);
                    }
                    catch (parseError) {
                        outputChannel.appendLine(`Error parsing LLM response: ${parseError.message}`);
                        outputChannel.appendLine(`Raw response: ${analysisJsonResult}`);
                        vscode.window.showErrorMessage(`Error processing scan results from ${preferredLlm}.`);
                        return;
                    }
                }
                // Process vulnerabilities consistently with exact line numbers
                vulnerabilities = processVulnerabilities(vulnerabilities, preferredLlm, fileName, languageId, selectedText);
                // Ensure llmProvider is set for each vulnerability
                vulnerabilities.forEach(v => {
                    v.llmProvider = preferredLlm;
                });
                formatAndLogVulnerabilities(vulnerabilities, preferredLlm);
                outputChannel.show(true);
                vscode.window.showInformationMessage(`Selection scan complete. View results in "Secure Coding Assistant" output channel.`);
            }
            catch (error) {
                vscode.window.showErrorMessage(`Error during selection scan: ${error.message}`);
                outputChannel.appendLine(`Error during selection scan with ${preferredLlm}: ${error.message}`);
                outputChannel.show(true);
            }
        });
    });
    context.subscriptions.push(scanSelectionCommand);
    // --- Helper function for the core file scanning logic ---
    async function executeScanOnFileLogic(fileUri, context, isPartOfFolderScan = false) {
        const shortFileName = fileUri.fsPath.substring(fileUri.fsPath.lastIndexOf('/') + 1);
        if (outputChannel)
            outputChannel.appendLine(`Attempting to scan file: ${fileUri.fsPath}`);
        let documentToScan;
        try {
            documentToScan = await vscode.workspace.openTextDocument(fileUri);
        }
        catch (error) {
            const errorMessage = `Failed to open file: ${fileUri.fsPath}. ${error.message}`;
            if (outputChannel)
                outputChannel.appendLine(`File Scan Error: ${errorMessage}`);
            if (!isPartOfFolderScan)
                vscode.window.showErrorMessage(errorMessage);
            return { success: false, fileName: shortFileName, error: errorMessage };
        }
        // Get the exact file content including all spaces and empty lines
        const fileContent = documentToScan.getText();
        const languageId = documentToScan.languageId;
        if (fileContent.trim() === "") {
            const warningMessage = `File "${shortFileName}" is empty or contains only whitespace. Skipping.`;
            if (outputChannel)
                outputChannel.appendLine(`File Scan: ${warningMessage}`);
            if (!isPartOfFolderScan)
                vscode.window.showWarningMessage(warningMessage);
            return { success: true, fileName: shortFileName };
        }
        const preferredLlmSetting = getPreferredLlm();
        if (!preferredLlmSetting) {
            const errorMessage = "Preferred LLM not configured. Please set it in the extension settings.";
            if (outputChannel)
                outputChannel.appendLine(`File Scan Error for "${shortFileName}": ${errorMessage}`);
            if (!isPartOfFolderScan)
                vscode.window.showErrorMessage(errorMessage);
            return { success: false, fileName: shortFileName, error: errorMessage };
        }
        let apiKeyToUse;
        let endpointToUse;
        let providerNameToUse = preferredLlmSetting;
        if (preferredLlmSetting === "Custom") {
            const customLlmConfigs = context.globalState.get('customLlmProviders') || [];
            if (customLlmConfigs.length === 0) {
                const errorMessage = "Preferred LLM is 'Custom', but no custom LLMs are configured. Please add one using the 'Secure Coding: Add Custom LLM Provider' command.";
                if (outputChannel)
                    outputChannel.appendLine(`File Scan Error for "${shortFileName}": ${errorMessage}`);
                if (!isPartOfFolderScan)
                    vscode.window.showErrorMessage(errorMessage);
                return { success: false, fileName: shortFileName, error: errorMessage };
            }
            const chosenCustomLlm = customLlmConfigs[0];
            providerNameToUse = chosenCustomLlm.name;
            apiKeyToUse = await getApiKey(context, chosenCustomLlm.name);
            endpointToUse = chosenCustomLlm.endpoint;
            if (!apiKeyToUse) {
                const errorMessage = `API Key for custom LLM "${chosenCustomLlm.name}" not found. Please ensure it's correctly configured or re-add the provider.`;
                if (outputChannel)
                    outputChannel.appendLine(`File Scan Error for "${shortFileName}": ${errorMessage}`);
                if (!isPartOfFolderScan)
                    vscode.window.showErrorMessage(errorMessage);
                return { success: false, fileName: shortFileName, error: errorMessage };
            }
        }
        else {
            apiKeyToUse = await getApiKey(context, preferredLlmSetting);
            if (!apiKeyToUse) {
                const errorMessage = `API Key for ${preferredLlmSetting} not found. Please add it using the dedicated command.`;
                if (outputChannel)
                    outputChannel.appendLine(`File Scan Error for "${shortFileName}": ${errorMessage}`);
                if (!isPartOfFolderScan)
                    vscode.window.showErrorMessage(errorMessage);
                return { success: false, fileName: shortFileName, error: errorMessage };
            }
        }
        if (outputChannel)
            outputChannel.appendLine(`Scanning file "${shortFileName}" using ${providerNameToUse} (Language: ${languageId})...`);
        const scanPromise = async (progress) => {
            try {
                if (progress)
                    progress.report({ message: `Analyzing ${shortFileName}...` });
                if (!apiKeyToUse) {
                    const err = `API Key for ${providerNameToUse} was unexpectedly undefined before API call.`;
                    if (outputChannel)
                        outputChannel.appendLine(err);
                    return { success: false, fileName: shortFileName, error: err };
                }
                let vulnerabilities = [];
                if (providerNameToUse === LlmProvider.OpenAI) {
                    vulnerabilities = await analyzeCodeWithOpenAI(apiKeyToUse, fileContent, languageId, shortFileName);
                }
                else {
                    const analysisJsonResult = await callLlmApi(providerNameToUse, apiKeyToUse, fileContent, languageId, endpointToUse);
                    try {
                        const result = JSON.parse(analysisJsonResult);
                        vulnerabilities = Array.isArray(result) ? result : (result.issues || []);
                        // Ensure llmProvider is set for each vulnerability
                        vulnerabilities.forEach(v => {
                            v.llmProvider = providerNameToUse;
                        });
                    }
                    catch (parseError) {
                        const errorMessage = `Error parsing LLM response from ${providerNameToUse} for file "${shortFileName}": ${parseError.message}`;
                        if (outputChannel) {
                            outputChannel.appendLine(errorMessage);
                            outputChannel.appendLine(`Raw response: ${analysisJsonResult}`);
                        }
                        if (!isPartOfFolderScan)
                            vscode.window.showErrorMessage(`Error processing scan results for "${shortFileName}" from ${providerNameToUse}.`);
                        return { success: false, fileName: shortFileName, error: errorMessage };
                    }
                }
                // Process vulnerabilities consistently with exact line numbers
                vulnerabilities = processVulnerabilities(vulnerabilities, providerNameToUse, shortFileName, languageId, fileContent);
                // Double-check that llmProvider is set for each vulnerability
                vulnerabilities.forEach(v => {
                    if (!v.llmProvider) {
                        v.llmProvider = providerNameToUse;
                    }
                });
                formatAndLogVulnerabilities(vulnerabilities, providerNameToUse);
                if (!isPartOfFolderScan) {
                    vscode.window.showInformationMessage(`File scan for "${shortFileName}" complete with ${providerNameToUse}. View results in "Secure Coding Assistant" output channel.`);
                }
                if (outputChannel && !isPartOfFolderScan)
                    outputChannel.show(true);
                return { success: true, fileName: shortFileName };
            }
            catch (error) {
                const errorMessage = `Error during file scan for "${shortFileName}" with ${providerNameToUse}: ${error.message}`;
                if (outputChannel)
                    outputChannel.appendLine(errorMessage);
                if (!isPartOfFolderScan) {
                    vscode.window.showErrorMessage(errorMessage);
                    if (outputChannel)
                        outputChannel.show(true);
                }
                return { success: false, fileName: shortFileName, error: errorMessage };
            }
        };
        if (!isPartOfFolderScan) {
            return vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: `Scanning file with ${providerNameToUse}`,
                cancellable: false
            }, scanPromise);
        }
        else {
            return scanPromise();
        }
    }
    // --- Register command for scanning current file ---
    const scanFileCommand = vscode.commands.registerCommand('secure-coding-assistant.scanFile', async (uri) => {
        if (outputChannel)
            outputChannel.appendLine("Scan File command triggered.");
        let fileUri = uri;
        if (!fileUri) {
            if (vscode.window.activeTextEditor) {
                fileUri = vscode.window.activeTextEditor.document.uri;
                if (outputChannel)
                    outputChannel.appendLine(`Scanning active editor: ${fileUri.fsPath}`);
            }
            else {
                vscode.window.showErrorMessage("No active text editor or file specified for scanning.");
                if (outputChannel)
                    outputChannel.appendLine("Scan File: No active editor or URI provided.");
                return;
            }
        }
        else {
            if (outputChannel)
                outputChannel.appendLine(`Scanning file from URI: ${fileUri.fsPath}`);
        }
        if (!fileUri) { // Should not happen if logic above is correct
            vscode.window.showErrorMessage("Could not determine the file to scan.");
            if (outputChannel)
                outputChannel.appendLine("Scan File: File URI is undefined.");
            return;
        }
        // Call the refactored logic, not part of a folder scan
        await executeScanOnFileLogic(fileUri, context, false);
    });
    context.subscriptions.push(scanFileCommand);
    // --- Register command for scanning a folder ---
    const scanFolderCommand = vscode.commands.registerCommand('secure-coding-assistant.scanFolder', async (folderUri) => {
        // If no folder URI is provided, use the current file's folder or the first workspace folder
        const effectiveFolderUri = folderUri ||
            (vscode.window.activeTextEditor?.document.uri ?
                vscode.Uri.file(path.dirname(vscode.window.activeTextEditor.document.uri.fsPath)) :
                vscode.workspace.workspaceFolders?.[0].uri);
        if (!effectiveFolderUri) {
            vscode.window.showErrorMessage('No folder selected and no workspace folder available');
            return;
        }
        if (outputChannel)
            outputChannel.appendLine(`Starting scan for folder: ${effectiveFolderUri.fsPath}`);
        vscode.window.showInformationMessage(`Scanning folder: ${effectiveFolderUri.fsPath}...`);
        const scanConfig = getScanConfiguration();
        const sourceCodeExtensions = new Set(scanConfig.sourceCodeExtensions);
        const commonExcludedDirs = new Set(scanConfig.excludedDirectories);
        // Track files to scan and results
        const filesToScan = [];
        const scanResults = [];
        // Function to collect files to scan
        async function collectFilesToScan(directoryUri) {
            try {
                const entries = await vscode.workspace.fs.readDirectory(directoryUri);
                for (const [name, type] of entries) {
                    const entryUri = vscode.Uri.joinPath(directoryUri, name);
                    if (type === vscode.FileType.File) {
                        const fileExtension = name.substring(name.lastIndexOf('.')).toLowerCase();
                        if (sourceCodeExtensions.has(fileExtension)) {
                            filesToScan.push(entryUri);
                        }
                    }
                    else if (type === vscode.FileType.Directory) {
                        if (!name.startsWith('.') && !commonExcludedDirs.has(name.toLowerCase())) {
                            await collectFilesToScan(entryUri);
                        }
                    }
                }
            }
            catch (error) {
                if (outputChannel)
                    outputChannel.appendLine(`Error collecting files from ${directoryUri.fsPath}: ${error.message}`);
            }
        }
        // Function to process files in batches
        async function processFilesInBatches(files) {
            for (let i = 0; i < files.length; i += scanConfig.batchSize) {
                const batch = files.slice(i, i + scanConfig.batchSize);
                const batchResults = await Promise.all(batch.map(file => executeScanOnFileLogic(file, context, true)));
                scanResults.push(...batchResults);
            }
        }
        try {
            // Show progress and collect files
            await vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: `Scanning folder: ${effectiveFolderUri.fsPath}`,
                cancellable: false
            }, async (progress) => {
                progress.report({ message: "Discovering files..." });
                await collectFilesToScan(effectiveFolderUri);
                if (filesToScan.length === 0) {
                    vscode.window.showWarningMessage('No supported files found to scan in the selected folder.');
                    return;
                }
                progress.report({ message: `Found ${filesToScan.length} files. Starting scans...` });
                if (outputChannel)
                    outputChannel.appendLine(`Found ${filesToScan.length} files to scan in ${effectiveFolderUri.fsPath}.`);
                // Process files in batches
                await processFilesInBatches(filesToScan);
            });
            // Process results
            const successCount = scanResults.filter(r => r.success).length;
            const failCount = scanResults.filter(r => !r.success).length;
            // Show summary
            const summaryMessage = `Scan complete for ${effectiveFolderUri.fsPath}\n` +
                `Successfully scanned: ${successCount} files\n` +
                `Failed to scan: ${failCount} files`;
            outputChannel.appendLine(summaryMessage);
            vscode.window.showInformationMessage(summaryMessage);
            // Show detailed errors if any
            if (failCount > 0) {
                const errorDetails = scanResults
                    .filter(r => !r.success)
                    .map(r => `${r.fileName}: ${r.error}`)
                    .join('\n');
                outputChannel.appendLine('\nDetailed errors:');
                outputChannel.appendLine(errorDetails);
            }
        }
        catch (error) {
            const errorMessage = `Failed to scan folder: ${effectiveFolderUri.fsPath}. Check the output channel for details.`;
            vscode.window.showErrorMessage(errorMessage);
            if (outputChannel)
                outputChannel.appendLine(errorMessage);
        }
        finally {
            if (outputChannel)
                outputChannel.show(true);
        }
    });
    context.subscriptions.push(scanFolderCommand);
    // --- Register command for adding a Custom LLM Provider ---
    const addCustomLlmProviderCommand = vscode.commands.registerCommand('secure-coding-assistant.addCustomLlmProvider', async () => {
        if (outputChannel)
            outputChannel.appendLine("Attempting to add Custom LLM Provider...");
        // 1. Prompt for Provider Name
        const providerNameInput = await vscode.window.showInputBox({
            prompt: "Enter a unique name for the Custom LLM Provider",
            placeHolder: "MyCustomLLM",
            ignoreFocusOut: true,
            validateInput: text => {
                if (!text || text.trim().length === 0) {
                    return "Provider name cannot be empty.";
                }
                // Check for uniqueness against existing custom LLMs
                const existingConfigs = context.globalState.get('customLlmProviders') || [];
                if (existingConfigs.find(cfg => cfg.name.toLowerCase() === text.trim().toLowerCase())) {
                    return `Provider name "${text.trim()}" already exists. Please choose a unique name.`;
                }
                // Additionally, check against built-in provider names to avoid conflict
                const builtInProviders = Object.values(LlmProvider).map(p => p.toLowerCase());
                if (builtInProviders.includes(text.trim().toLowerCase())) {
                    return `Provider name "${text.trim()}" conflicts with a built-in provider. Please choose a different name.`;
                }
                return null; // Input is valid
            }
        });
        if (!providerNameInput) {
            vscode.window.showWarningMessage("Custom LLM Provider setup cancelled: Name not provided.");
            if (outputChannel)
                outputChannel.appendLine("Custom LLM setup cancelled by user (name input).");
            return;
        }
        const providerName = providerNameInput.trim();
        // 2. Prompt for API Key
        const apiKey = await vscode.window.showInputBox({
            prompt: `Enter the API Key for ${providerName}`,
            password: true,
            ignoreFocusOut: true,
            placeHolder: "Your API Key for " + providerName,
            validateInput: text => {
                return text && text.length > 0 ? null : "API Key cannot be empty.";
            }
        });
        if (!apiKey) {
            vscode.window.showWarningMessage("Custom LLM Provider setup cancelled: API Key not provided.");
            if (outputChannel)
                outputChannel.appendLine(`Custom LLM setup for "${providerName}" cancelled by user (API key input).`);
            return;
        }
        // 3. Prompt for API Endpoint URL
        const endpointUrlInput = await vscode.window.showInputBox({
            prompt: `Enter the API Endpoint URL for ${providerName}`,
            placeHolder: "https://api.customllm.com/v1/chat/completions",
            ignoreFocusOut: true,
            validateInput: text => {
                if (!text || text.trim().length === 0) {
                    return "API Endpoint URL cannot be empty.";
                }
                // Basic URL format check (optional, can be more robust)
                try {
                    new URL(text.trim());
                    return null;
                }
                catch (_) {
                    return "Invalid URL format.";
                }
            }
        });
        if (!endpointUrlInput) {
            vscode.window.showWarningMessage("Custom LLM Provider setup cancelled: Endpoint URL not provided.");
            if (outputChannel)
                outputChannel.appendLine(`Custom LLM setup for "${providerName}" cancelled by user (endpoint URL input).`);
            return;
        }
        const endpointUrl = endpointUrlInput.trim();
        try {
            // Store API Key in secrets
            const secretApiKeyName = `customLlmProvider.${providerName}.apiKey`;
            await context.secrets.store(secretApiKeyName, apiKey);
            // Store provider config (name and endpoint) in global state
            const customLlmConfigs = context.globalState.get('customLlmProviders') || [];
            // Double check uniqueness here in case of async race conditions (though unlikely with modal inputs)
            if (customLlmConfigs.find(cfg => cfg.name.toLowerCase() === providerName.toLowerCase())) {
                vscode.window.showErrorMessage(`Custom LLM Provider "${providerName}" already exists. Please try adding with a different name.`);
                await context.secrets.delete(secretApiKeyName); // Clean up stored secret
                if (outputChannel)
                    outputChannel.appendLine(`Error adding Custom LLM "${providerName}": Name already exists (race condition check).`);
                return;
            }
            customLlmConfigs.push({ name: providerName, endpoint: endpointUrl });
            await context.globalState.update('customLlmProviders', customLlmConfigs);
            vscode.window.showInformationMessage(`Custom LLM Provider "${providerName}" added successfully.`);
            if (outputChannel) {
                outputChannel.appendLine(`Custom LLM Provider "${providerName}" added with endpoint: ${endpointUrl}`);
            }
        }
        catch (error) {
            vscode.window.showErrorMessage(`Failed to add Custom LLM Provider "${providerName}": ${error.message}`);
            if (outputChannel) {
                outputChannel.appendLine(`Error adding Custom LLM Provider "${providerName}": ${error.message}`);
            }
            // Attempt to clean up the stored secret if other parts of the setup failed
            const secretApiKeyName = `customLlmProvider.${providerName}.apiKey`;
            try {
                await context.secrets.delete(secretApiKeyName);
            }
            catch (cleanupError) { /* best effort */ }
        }
    });
    context.subscriptions.push(addCustomLlmProviderCommand);
}
// Function to retrieve an API key
async function getApiKey(context, providerName) {
    let secretKey;
    // Check if it's a built-in provider
    if (Object.values(LlmProvider).includes(providerName)) {
        secretKey = getBuiltInSecretKey(providerName);
    }
    else {
        // Assume it's a custom provider name
        secretKey = `customLlmProvider.${providerName}.apiKey`;
    }
    if (!secretKey) { // Should not happen if providerName is validated before calling
        const message = `Could not determine secret key for provider: ${providerName}`;
        console.error(message);
        if (outputChannel)
            outputChannel.appendLine(`Error in getApiKey: ${message}`);
        // vscode.window.showErrorMessage(`Invalid LLM provider specified: ${providerName}`); // Potentially too noisy
        return undefined;
    }
    try {
        const apiKey = await context.secrets.get(secretKey);
        if (!apiKey && outputChannel) {
            outputChannel.appendLine(`API Key not found in secrets for key name: ${secretKey} (Provider: ${providerName})`);
        }
        return apiKey;
    }
    catch (error) {
        const message = `Failed to retrieve API key for ${providerName} (key name ${secretKey}): ${error.message}`;
        console.error(message);
        // vscode.window.showErrorMessage(`Failed to retrieve API key for ${providerName}.`); // Potentially too noisy
        if (outputChannel)
            outputChannel.appendLine(`Error in getApiKey: ${message}`);
        return undefined;
    }
}
// Function to get the preferred LLM from settings
// Returns the string as configured, e.g., "OpenAI", "Anthropic", "Google", or "Custom".
function getPreferredLlm() {
    const config = vscode.workspace.getConfiguration('secureCodingAssistant');
    const preferredLlmString = config.get('preferredLlm');
    if (!preferredLlmString) {
        if (outputChannel)
            outputChannel.appendLine(`Preferred LLM setting is not set. Please configure "secureCodingAssistant.preferredLlm".`);
        return undefined;
    }
    const expectedEnumValues = [...Object.values(LlmProvider).map(p => p.toString()), "Custom"];
    if (expectedEnumValues.some(val => val.toLowerCase() === preferredLlmString.toLowerCase())) { // Make comparison case-insensitive for robustness
        return preferredLlmString;
    }
    else {
        if (outputChannel)
            outputChannel.appendLine(`Invalid preferredLlm setting: "${preferredLlmString}". Please choose from ${expectedEnumValues.join(', ')} in settings.`);
        return undefined;
    }
}
function deactivate() {
    if (outputChannel) {
        outputChannel.appendLine('Deactivating "secure-coding-assistant".');
        outputChannel.dispose();
    }
}
//# sourceMappingURL=extension.js.map