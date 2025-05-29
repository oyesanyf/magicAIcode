import * as vscode from 'vscode';
import * as path from 'path';
import axios from 'axios';
import OpenAI from 'openai';
import { Anthropic } from '@anthropic-ai/sdk';
import { GoogleGenerativeAI } from '@google/generative-ai';

console.log("Attempting to require 'openai' directly at activation start...");
try {
    const anOpenAI = require('openai');
    console.log('DIAGNOSTIC: OpenAI module loaded successfully via require():', typeof anOpenAI);
} catch (e: any) {
    console.error('DIAGNOSTIC: Failed to load OpenAI module via require():', e.message, e.stack);
}

// Define LLM provider keys for built-in providers
export enum LlmProvider {
    OpenAI = 'OpenAI',
    Anthropic = 'Anthropic',
    Google = 'Google',
}

// For configuration, "Custom" is also a valid choice.
export type PreferredLlmType = LlmProvider | 'Custom';


const BUILT_IN_SECRET_KEYS: Record<LlmProvider, string> = {
    [LlmProvider.OpenAI]: 'secureCodingAssistant.openaiApiKey',
    [LlmProvider.Anthropic]: 'secureCodingAssistant.anthropicApiKey',
    [LlmProvider.Google]: 'secureCodingAssistant.googleApiKey',
};

// Helper function to get the secret key for a built-in provider
function getBuiltInSecretKey(provider: LlmProvider): string {
    return BUILT_IN_SECRET_KEYS[provider];
}

// Output channel for logging
let outputChannel: vscode.OutputChannel;

// Interface for Vulnerability
interface Vulnerability {
    id: string;
    description: string;
    location: string;
    severity: "High" | "Medium" | "Low";
    recommendation: string;
    llmProvider: string;
    fileName?: string;
    lineNumber?: string;
    cweId?: string;
    owaspReference?: string;
    hallucinationScore?: number;
    confidenceScore?: number;
}

// Interface for Custom LLM Provider configuration
interface CustomLlmConfig {
    name: string;
    endpoint: string;
}

// Placeholder function for LLM API call
async function callLlmApi(
    providerDisplayName: string,
    apiKey: string,
    codeSnippet: string,
    languageId: string,
    endpointUrl?: string
): Promise<string> {
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

For each issue found, provide:
- Line number
- Vulnerability or logic issue
- Explanation of the problem
- Suggested fix with secure alternatives
- CWE or OWASP references when applicable

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

When analyzing code, pay special attention to:
- Variable assignments containing hash values
- String literals that match hash patterns
- Comments indicating hash types
- Any hardcoded cryptographic values

Include accuracy scoring:
- Hallucination Score (0.0-1.0, lower is better)
- Confidence Score (0.0-1.0, higher is better)

Output must follow this structure:
1. Summary (language, risk rating, issue count)
2. Validated Code (clean blocks, good practices)
3. Issues Found (detailed per issue)
4. Performance & Complexity Highlights
5. Test Stub Offer

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
        "llmProvider": "string"
    }],
    "performanceHighlights": ["string"]
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
                const openai = new OpenAI({ apiKey });
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
                        result.issues.forEach((issue: any) => {
                            issue.llmProvider = LlmProvider.OpenAI;
                        });
                    } else if (Array.isArray(result)) {
                        result.forEach((issue: any) => {
                            issue.llmProvider = LlmProvider.OpenAI;
                        });
                    }
                    return JSON.stringify(result);
                } catch (e) {
                    return content;
                }

            case LlmProvider.Anthropic:
                try {
                    const anthropic = new Anthropic({ apiKey });
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
                            result.issues.forEach((issue: any) => {
                                issue.llmProvider = LlmProvider.Anthropic;
                            });
                        } else if (Array.isArray(result)) {
                            result.forEach((issue: any) => {
                                issue.llmProvider = LlmProvider.Anthropic;
                            });
                        }
                        return JSON.stringify(result);
                    } catch (e) {
                        return content;
                    }
                } catch (error: any) {
                    if (outputChannel) {
                        outputChannel.appendLine(`Error calling Anthropic API: ${error.message}`);
                    }
                    return '[]';
                }

            case LlmProvider.Google:
                try {
                    const genAI = new GoogleGenerativeAI(apiKey);
                    const model = genAI.getGenerativeModel({ model: 'gemini-pro' });
                    const googleResponse = await model.generateContent([
                        { text: `${systemPrompt}\n\n${userPrompt.replace('{languageId}', languageId).replace('{codeSnippet}', codeSnippet)}` }
                    ]);
                    const content = googleResponse.response.text();
                    // Ensure llmProvider is set in the response
                    try {
                        const result = JSON.parse(content);
                        if (result.issues) {
                            result.issues.forEach((issue: any) => {
                                issue.llmProvider = LlmProvider.Google;
                            });
                        } else if (Array.isArray(result)) {
                            result.forEach((issue: any) => {
                                issue.llmProvider = LlmProvider.Google;
                            });
                        }
                        return JSON.stringify(result);
                    } catch (e) {
                        return content;
                    }
                } catch (error: any) {
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
                    const response = await axios.post(endpointUrl, payload, {
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${apiKey}`
                        },
                        timeout: 30000 // 30 second timeout
                    });

                    // Type assertion for response data
                    const responseData = response.data as {
                        choices?: Array<{ message: { content: string } }>;
                        content?: string;
                        text?: string;
                    };

                    // Handle different response formats
                    if (responseData.choices && responseData.choices[0]) {
                        // OpenAI-compatible format
                        const content = responseData.choices[0].message.content;
                        // Ensure llmProvider is set in the response
                        try {
                            const result = JSON.parse(content);
                            if (result.issues) {
                                result.issues.forEach((issue: any) => {
                                    issue.llmProvider = providerDisplayName;
                                });
                            } else if (Array.isArray(result)) {
                                result.forEach((issue: any) => {
                                    issue.llmProvider = providerDisplayName;
                                });
                            }
                            return JSON.stringify(result);
                        } catch (e) {
                            return content;
                        }
                    } else if (responseData.content) {
                        // Anthropic-compatible format
                        const content = responseData.content;
                        // Ensure llmProvider is set in the response
                        try {
                            const result = JSON.parse(content);
                            if (result.issues) {
                                result.issues.forEach((issue: any) => {
                                    issue.llmProvider = providerDisplayName;
                                });
                            } else if (Array.isArray(result)) {
                                result.forEach((issue: any) => {
                                    issue.llmProvider = providerDisplayName;
                                });
                            }
                            return JSON.stringify(result);
                        } catch (e) {
                            return content;
                        }
                    } else if (responseData.text) {
                        // Simple text response
                        return JSON.stringify(responseData.text);
                    } else {
                        throw new Error("Unsupported response format from custom LLM provider");
                    }
                } catch (error: any) {
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
    } catch (error: any) {
        if (outputChannel) {
            outputChannel.appendLine(`Error in LLM API call: ${error.message}`);
        }
        return '[]';
    }
}

// Helper function to get OpenAI configuration
function getOpenAIConfig(): { model: string; systemPrompt: string; userPrompt: string } {
    const config = vscode.workspace.getConfiguration('secureCodingAssistant.openai');
    const model = config.get<string>('model', "gpt-3.5-turbo");
    
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

For each issue found, provide:
- Line number
- Vulnerability or logic issue
- Explanation of the problem
- Suggested fix with secure alternatives
- CWE or OWASP references when applicable

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

When analyzing code, pay special attention to:
- Variable assignments containing hash values
- String literals that match hash patterns
- Comments indicating hash types
- Any hardcoded cryptographic values

Include accuracy scoring:
- Hallucination Score (0.0-1.0, lower is better)
- Confidence Score (0.0-1.0, higher is better)

Output must follow this structure:
1. Summary (language, risk rating, issue count)
2. Validated Code (clean blocks, good practices)
3. Issues Found (detailed per issue)
4. Performance & Complexity Highlights
5. Test Stub Offer

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
        "llmProvider": "string"
    }],
    "performanceHighlights": ["string"]
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

    return { model, systemPrompt, userPrompt };
}

// Add comprehensive security detection patterns
const securityPatterns = {
    // Cryptographic Issues
    'HardcodedHashes': {
        'SHA-1': /=\s*["'][a-fA-F0-9]{40}["']/,
        'SHA-256': /=\s*["'][a-fA-F0-9]{64}["']/,
        'SHA-384': /=\s*["'][a-fA-F0-9]{96}["']/,
        'SHA-512': /=\s*["'][a-fA-F0-9]{128}["']/,
        'Tiger': /=\s*["'][a-fA-F0-9]{48}["']/,
        'Whirlpool': /=\s*["'][a-fA-F0-9]{128}["']/
    },
    'InsecureCrypto': {
        'MD5': /md5|MD5/,
        'DES': /des|DES/,
        'RC4': /rc4|RC4/,
        'Blowfish': /blowfish|Blowfish/,
        'WeakCipher': /ecb|ECB|CBC|OFB|CFB/
    },
    // Injection Patterns
    'SQLInjection': {
        'StringConcatenation': /['"]\s*\+\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\+\s*['"]/,
        'TemplateLiteral': /`\s*\$\{.*\}\s*`/,
        'RawQuery': /executeQuery|rawQuery|query\(/
    },
    'XSS': {
        'InnerHTML': /\.innerHTML\s*=/,
        'DocumentWrite': /document\.write\(/,
        'Eval': /eval\(|setTimeout\(|setInterval\(/
    },
    'CommandInjection': {
        'Exec': /exec\(|spawn\(|system\(/,
        'Shell': /shell_exec\(|passthru\(|proc_open\(/
    },
    // Authentication & Authorization
    'HardcodedCredentials': {
        'APIKey': /api[_-]?key|apikey|secret[_-]?key/i,
        'Password': /password\s*=\s*['"][^'"]+['"]/i,
        'Token': /token\s*=\s*['"][^'"]+['"]/i
    },
    'WeakAuth': {
        'BasicAuth': /basic\s+auth|authorization:\s*basic/i,
        'NoAuth': /public\s+function|public\s+class/
    },
    // File Operations
    'PathTraversal': {
        'DotDot': /\.\.\/|\.\.\\/,
        'AbsolutePath': /\/[a-zA-Z]:\/|^\/[a-zA-Z]/
    },
    'UnsafeFileOp': {
        'FileUpload': /\.upload\(|\.save\(/,
        'FileDownload': /\.download\(|\.get\(/
    },
    // Deserialization
    'UnsafeDeserialization': {
        'Pickle': /pickle\.loads\(/,
        'YAML': /yaml\.load\(/,
        'XML': /XMLDecoder|XMLReader/
    },
    // Memory Safety
    'BufferOverflow': {
        'UnboundedCopy': /strcpy\(|strcat\(/,
        'ArrayAccess': /\[[^\]]+\]\s*=\s*[^;]+;/
    },
    // Configuration
    'DebugCode': {
        'ConsoleLog': /console\.log\(|print\(/,
        'Debugger': /debugger;|breakpoint/
    }
};

// Function to detect security vulnerabilities
function detectSecurityVulnerabilities(code: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const lines = code.split('\n');

    lines.forEach((line, index) => {
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
                        location: line.trim(),
                        severity: severity,
                        recommendation: recommendation,
                        llmProvider: "Local Scanner",
                        fileName: "current_file",
                        lineNumber: (index + 1).toString(),
                        cweId: cweId,
                        owaspReference: owaspRef,
                        hallucinationScore: 0.1, // Low hallucination score for pattern-based detection
                        confidenceScore: 0.9 // High confidence for pattern-based detection
                    });
                }
            }
        }
    });

    return vulnerabilities;
}

// Helper function to determine severity
function getSeverityForIssue(category: string, issueType: string): "High" | "Medium" | "Low" {
    const highSeverityIssues = [
        'HardcodedHashes', 'HardcodedCredentials', 'SQLInjection', 'CommandInjection',
        'UnsafeDeserialization', 'BufferOverflow'
    ];
    const mediumSeverityIssues = [
        'XSS', 'PathTraversal', 'InsecureCrypto'
    ];

    if (highSeverityIssues.includes(issueType)) return "High";
    if (mediumSeverityIssues.includes(issueType)) return "Medium";
    return "Low";
}

// Helper function to get recommendations
function getRecommendationForIssue(category: string, issueType: string): string {
    const recommendations: Record<string, string> = {
        'HardcodedHashes': 'Remove hardcoded hash values from variable assignments. Instead, use a secure configuration management system or environment variables to store sensitive values. Consider using a secrets management solution.',
        'InsecureCrypto': 'Use modern, secure cryptographic algorithms and libraries. Avoid deprecated or weak algorithms.',
        'SQLInjection': 'Use parameterized queries or prepared statements instead of string concatenation.',
        'XSS': 'Use proper output encoding and sanitization. Consider using a security library for HTML escaping.',
        'CommandInjection': 'Use parameterized commands and avoid shell execution. Validate and sanitize all inputs.',
        'HardcodedCredentials': 'Move credentials to secure configuration management or environment variables.',
        'PathTraversal': 'Validate and sanitize file paths. Use proper path resolution functions.',
        'UnsafeDeserialization': 'Use safe deserialization methods and validate input data.',
        'BufferOverflow': 'Use safe string handling functions and bounds checking.',
        'DebugCode': 'Remove debug code before production deployment.'
    };

    return recommendations[issueType] || 'Review and fix the identified security issue.';
}

// Helper function to get CWE IDs
function getCWEForIssue(category: string, issueType: string): string {
    const cweMap: Record<string, string> = {
        'HardcodedHashes': 'CWE-798',
        'InsecureCrypto': 'CWE-326',
        'SQLInjection': 'CWE-89',
        'XSS': 'CWE-79',
        'CommandInjection': 'CWE-78',
        'HardcodedCredentials': 'CWE-798',
        'PathTraversal': 'CWE-22',
        'UnsafeDeserialization': 'CWE-502',
        'BufferOverflow': 'CWE-120',
        'DebugCode': 'CWE-489'
    };

    return cweMap[issueType] || '';
}

// Helper function to get OWASP references
function getOWASPReferenceForIssue(category: string, issueType: string): string {
    const owaspMap: Record<string, string> = {
        'HardcodedHashes': 'A7:2017-Identification and Authentication Failures',
        'InsecureCrypto': 'A2:2017-Broken Authentication',
        'SQLInjection': 'A1:2017-Injection',
        'XSS': 'A7:2017-Cross-Site Scripting (XSS)',
        'CommandInjection': 'A1:2017-Injection',
        'HardcodedCredentials': 'A7:2017-Identification and Authentication Failures',
        'PathTraversal': 'A5:2017-Broken Access Control',
        'UnsafeDeserialization': 'A8:2017-Insecure Deserialization',
        'BufferOverflow': 'A1:2017-Injection',
        'DebugCode': 'A9:2017-Using Components with Known Vulnerabilities'
    };

    return owaspMap[issueType] || '';
}

// Update processVulnerabilities to include the new security detection
function processVulnerabilities(
    vulnerabilities: any[],
    providerName: string,
    fileName: string,
    languageId: string
): Vulnerability[] {
    // First, detect security vulnerabilities using our patterns
    const securityVulns = detectSecurityVulnerabilities(vulnerabilities[0]?.codeSnippet || '');
    
    // Handle both old and new format
    let processedVulns: Vulnerability[] = [];
    if (vulnerabilities.length > 0 && 'summary' in vulnerabilities[0]) {
        // New format - extract issues from the comprehensive analysis
        const analysis = vulnerabilities[0];
        processedVulns = (analysis.issues || []).map((issue: any) => {
            const processedVuln: Vulnerability = {
                id: issue.id || 'Unknown',
                description: issue.description || 'No description provided',
                location: issue.location || 'Unknown location',
                severity: issue.severity || 'Medium',
                recommendation: issue.recommendation || 'No recommendation provided',
                llmProvider: providerName,
                fileName: fileName || issue.fileName,
                lineNumber: issue.lineNumber,
                cweId: issue.cweId,
                owaspReference: issue.owaspReference,
                hallucinationScore: issue.hallucinationScore,
                confidenceScore: issue.confidenceScore
            };

            return processedVuln;
        });
    } else {
        // Old format - process as before
        processedVulns = vulnerabilities.map(vuln => {
            const processedVuln: Vulnerability = {
                id: vuln.id || 'Unknown',
                description: vuln.description || 'No description provided',
                location: vuln.location || 'Unknown location',
                severity: vuln.severity || 'Medium',
                recommendation: vuln.recommendation || 'No recommendation provided',
                llmProvider: providerName,
                fileName: fileName || vuln.fileName,
                lineNumber: vuln.lineNumber,
                cweId: vuln.cweId,
                owaspReference: vuln.owaspReference,
                hallucinationScore: vuln.hallucinationScore,
                confidenceScore: vuln.confidenceScore
            };

            return processedVuln;
        });
    }

    // Combine LLM-detected vulnerabilities with pattern-based security vulnerabilities
    return [...processedVulns, ...securityVulns];
}

// Update analyzeCodeWithOpenAI to include better code formatting
async function analyzeCodeWithOpenAI(
    apiKey: string,
    codeSnippet: string,
    languageId: string,
    fileName: string = ''
): Promise<Vulnerability[]> {
    const { model, systemPrompt, userPrompt } = getOpenAIConfig();

    try {
        // Format the code snippet to ensure proper line breaks and indentation
        const formattedCode = codeSnippet
            .split('\n')
            .map(line => line.trim())
            .filter(line => line.length > 0)
            .join('\n');

        const openai = new OpenAI({ apiKey });
        const response = await openai.chat.completions.create({
            model: model,
            messages: [
                { role: 'system', content: systemPrompt },
                { role: 'user', content: userPrompt.replace('{languageId}', languageId).replace('{codeSnippet}', formattedCode) }
            ],
            response_format: { type: 'json_object' },
            temperature: 0.1 // Lower temperature for more deterministic results
        });

        const content = response.choices[0]?.message?.content;
        if (content) {
            try {
                const result = JSON.parse(content);
                let vulnerabilities: Vulnerability[] = [];
                
                // Check if the result itself is the array or if it's nested under a key
                if (Array.isArray(result)) {
                    vulnerabilities = result.map((v: any) => ({ ...v, llmProvider: LlmProvider.OpenAI, fileName }));
                } else if (result && typeof result === 'object' && Array.isArray(result.vulnerabilities)) {
                    vulnerabilities = result.vulnerabilities.map((v: any) => ({ ...v, llmProvider: LlmProvider.OpenAI, fileName }));
                } else if (result && typeof result === 'object' && Array.isArray(result.issues)) {
                    vulnerabilities = result.issues.map((v: any) => ({ ...v, llmProvider: LlmProvider.OpenAI, fileName }));
                } else {
                    if (outputChannel) {
                        outputChannel.appendLine(`OpenAI response is not in the expected format: ${content}`);
                    }
                    return [];
                }

                // Process vulnerabilities using the helper function
                const processedVulnerabilities = processVulnerabilities(vulnerabilities, LlmProvider.OpenAI, fileName, languageId);
                
                // Double-check that llmProvider is set for each vulnerability
                processedVulnerabilities.forEach(v => {
                    if (!v.llmProvider) {
                        v.llmProvider = LlmProvider.OpenAI;
                    }
                    if (!v.fileName) {
                        v.fileName = fileName;
                    }
                });
                
                return processedVulnerabilities;
            } catch (parseError: any) {
                if (outputChannel) {
                    outputChannel.appendLine(`Error parsing OpenAI response: ${parseError.message}. Response: ${content}`);
                }
                return [];
            }
        } else {
            if (outputChannel) {
                outputChannel.appendLine("OpenAI returned an empty response.");
            }
            return [];
        }
    } catch (error: any) {
        if (outputChannel) {
            outputChannel.appendLine(`Error calling OpenAI API: ${error.message}`);
        }
        return [];
    }
}

// Helper function to generate code fixes based on vulnerability type
function generateCodeFix(vuln: Vulnerability, languageId: string): string | null {
    const description = vuln.description.toLowerCase();
    const location = vuln.location;

    if (description.includes('sql injection')) {
        if (languageId === 'python') {
            return `# Instead of:
${location}

# Use parameterized query:
cur.execute("SELECT * FROM USER WHERE NAME = ?", (name,))`;
        } else if (languageId === 'javascript' || languageId === 'typescript') {
            return `// Instead of:
${location}

// Use parameterized query:
db.query("SELECT * FROM USER WHERE NAME = ?", [name])`;
        }
    } else if (description.includes('xss')) {
        if (languageId === 'html') {
            return `<!-- Instead of:
${location}

<!-- Use proper escaping:
<div>${escapeHtml('userInput')}</div>`;
        }
    } else if (description.includes('command injection')) {
        if (languageId === 'python') {
            return `# Instead of:
${location}

# Use subprocess with shell=False:
subprocess.run(['command', 'arg1', 'arg2'], shell=False)`;
        }
    }

    return null;
}

// Helper function to escape HTML
function escapeHtml(unsafe: string): string {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function formatAndLogVulnerabilities(vulnerabilities: Vulnerability[], providerDisplayName: string) {
    if (!outputChannel) return;
    outputChannel.clear(); // Consider if this should always happen or be more conditional
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
        // Use the actual file name from the vulnerability object
        if (vuln.fileName) {
            if (vuln.lineNumber) {
                outputChannel.appendLine(`File: ${vuln.fileName}:${vuln.lineNumber}`);
            } else {
                outputChannel.appendLine(`File: ${vuln.fileName}`);
            }
        } else {
            outputChannel.appendLine(`File: Unknown`);
        }
        outputChannel.appendLine(`Location: ${vuln.location}`);
        outputChannel.appendLine(`Recommendation: ${vuln.recommendation}`);
        outputChannel.appendLine(`Detected by: ${vuln.llmProvider || providerDisplayName}`);
    });
    outputChannel.appendLine("----------------------------------------");
}


export function activate(context: vscode.ExtensionContext) {
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
                } catch (error: any) {
                    vscode.window.showErrorMessage(`Failed to store ${provider} API Key. ${error.message}`);
                    outputChannel.appendLine(`Failed to store ${provider} API Key: ${error.message}`);
                }
            } else {
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
            } catch (error: any) {
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
                let vulnerabilities: Vulnerability[] = [];
                if (preferredLlm === LlmProvider.OpenAI) {
                    vulnerabilities = await analyzeCodeWithOpenAI(apiKey, selectedText, languageId, fileName);
                } else {
                    const analysisJsonResult = await callLlmApi(preferredLlm, apiKey, selectedText, languageId);
                    try {
                        const result = JSON.parse(analysisJsonResult);
                        vulnerabilities = Array.isArray(result) ? result : (result.issues || []);
                    } catch (parseError: any) {
                        outputChannel.appendLine(`Error parsing LLM response: ${parseError.message}`);
                        outputChannel.appendLine(`Raw response: ${analysisJsonResult}`);
                        vscode.window.showErrorMessage(`Error processing scan results from ${preferredLlm}.`);
                        return;
                    }
                }
                
                // Process vulnerabilities consistently
                vulnerabilities = processVulnerabilities(vulnerabilities, preferredLlm, fileName, languageId);
                
                // Ensure llmProvider is set for each vulnerability
                vulnerabilities.forEach(v => {
                    v.llmProvider = preferredLlm;
                });
                
                formatAndLogVulnerabilities(vulnerabilities, preferredLlm);
                outputChannel.show(true);
                vscode.window.showInformationMessage(`Selection scan complete. View results in "Secure Coding Assistant" output channel.`);

            } catch (error: any) {
                vscode.window.showErrorMessage(`Error during selection scan: ${error.message}`);
                outputChannel.appendLine(`Error during selection scan with ${preferredLlm}: ${error.message}`);
                outputChannel.show(true);
            }
        });
    });
    context.subscriptions.push(scanSelectionCommand);

    // --- Helper function for the core file scanning logic ---
    async function executeScanOnFileLogic(
        fileUri: vscode.Uri,
        context: vscode.ExtensionContext,
        isPartOfFolderScan: boolean = false
    ): Promise<{ success: boolean; fileName: string; error?: string }> {
        const shortFileName = fileUri.fsPath.substring(fileUri.fsPath.lastIndexOf('/') + 1);
        if (outputChannel) outputChannel.appendLine(`Attempting to scan file: ${fileUri.fsPath}`);

        let documentToScan: vscode.TextDocument;
        try {
            documentToScan = await vscode.workspace.openTextDocument(fileUri);
        } catch (error: any) {
            const errorMessage = `Failed to open file: ${fileUri.fsPath}. ${error.message}`;
            if (outputChannel) outputChannel.appendLine(`File Scan Error: ${errorMessage}`);
            if (!isPartOfFolderScan) vscode.window.showErrorMessage(errorMessage);
            return { success: false, fileName: shortFileName, error: errorMessage };
        }

        const fileContent = documentToScan.getText();
        const languageId = documentToScan.languageId;

        if (fileContent.trim() === "") {
            const warningMessage = `File "${shortFileName}" is empty or contains only whitespace. Skipping.`;
            if (outputChannel) outputChannel.appendLine(`File Scan: ${warningMessage}`);
            if (!isPartOfFolderScan) vscode.window.showWarningMessage(warningMessage);
            return { success: true, fileName: shortFileName };
        }

        const preferredLlmSetting = getPreferredLlm();
        if (!preferredLlmSetting) {
            const errorMessage = "Preferred LLM not configured. Please set it in the extension settings.";
            if (outputChannel) outputChannel.appendLine(`File Scan Error for "${shortFileName}": ${errorMessage}`);
            if (!isPartOfFolderScan) vscode.window.showErrorMessage(errorMessage);
            return { success: false, fileName: shortFileName, error: errorMessage };
        }

        let apiKeyToUse: string | undefined;
        let endpointToUse: string | undefined;
        let providerNameToUse: string = preferredLlmSetting;

        if (preferredLlmSetting === "Custom") {
            const customLlmConfigs = context.globalState.get<CustomLlmConfig[]>('customLlmProviders') || [];
            if (customLlmConfigs.length === 0) {
                const errorMessage = "Preferred LLM is 'Custom', but no custom LLMs are configured. Please add one using the 'Secure Coding: Add Custom LLM Provider' command.";
                if (outputChannel) outputChannel.appendLine(`File Scan Error for "${shortFileName}": ${errorMessage}`);
                if (!isPartOfFolderScan) vscode.window.showErrorMessage(errorMessage);
                return { success: false, fileName: shortFileName, error: errorMessage };
            }
            const chosenCustomLlm = customLlmConfigs[0];
            providerNameToUse = chosenCustomLlm.name;
            apiKeyToUse = await getApiKey(context, chosenCustomLlm.name);
            endpointToUse = chosenCustomLlm.endpoint;

            if (!apiKeyToUse) {
                const errorMessage = `API Key for custom LLM "${chosenCustomLlm.name}" not found. Please ensure it's correctly configured or re-add the provider.`;
                if (outputChannel) outputChannel.appendLine(`File Scan Error for "${shortFileName}": ${errorMessage}`);
                if (!isPartOfFolderScan) vscode.window.showErrorMessage(errorMessage);
                return { success: false, fileName: shortFileName, error: errorMessage };
            }
        } else {
            apiKeyToUse = await getApiKey(context, preferredLlmSetting);

            if (!apiKeyToUse) {
                const errorMessage = `API Key for ${preferredLlmSetting} not found. Please add it using the dedicated command.`;
                if (outputChannel) outputChannel.appendLine(`File Scan Error for "${shortFileName}": ${errorMessage}`);
                if (!isPartOfFolderScan) vscode.window.showErrorMessage(errorMessage);
                return { success: false, fileName: shortFileName, error: errorMessage };
            }
        }

        if (outputChannel) outputChannel.appendLine(`Scanning file "${shortFileName}" using ${providerNameToUse} (Language: ${languageId})...`);

        const scanPromise = async (progress?: vscode.Progress<{ message?: string; increment?: number }>): Promise<{ success: boolean; fileName: string; error?: string }> => {
            try {
                if (progress) progress.report({ message: `Analyzing ${shortFileName}...` });
                if (!apiKeyToUse) {
                    const err = `API Key for ${providerNameToUse} was unexpectedly undefined before API call.`;
                    if (outputChannel) outputChannel.appendLine(err);
                    return { success: false, fileName: shortFileName, error: err };
                }

                let vulnerabilities: Vulnerability[] = [];
                if (providerNameToUse === LlmProvider.OpenAI) {
                    vulnerabilities = await analyzeCodeWithOpenAI(apiKeyToUse, fileContent, languageId, shortFileName);
                } else {
                    const analysisJsonResult = await callLlmApi(providerNameToUse, apiKeyToUse, fileContent, languageId, endpointToUse);
                    try {
                        const result = JSON.parse(analysisJsonResult);
                        vulnerabilities = Array.isArray(result) ? result : (result.issues || []);
                        // Ensure llmProvider is set for each vulnerability
                        vulnerabilities.forEach(v => {
                            v.llmProvider = providerNameToUse;
                        });
                    } catch (parseError: any) {
                        const errorMessage = `Error parsing LLM response from ${providerNameToUse} for file "${shortFileName}": ${parseError.message}`;
                        if (outputChannel) {
                            outputChannel.appendLine(errorMessage);
                            outputChannel.appendLine(`Raw response: ${analysisJsonResult}`);
                        }
                        if (!isPartOfFolderScan) vscode.window.showErrorMessage(`Error processing scan results for "${shortFileName}" from ${providerNameToUse}.`);
                        return { success: false, fileName: shortFileName, error: errorMessage };
                    }
                }

                // Process vulnerabilities consistently
                vulnerabilities = processVulnerabilities(vulnerabilities, providerNameToUse, shortFileName, languageId);
                
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
                if (outputChannel && !isPartOfFolderScan) outputChannel.show(true);
                return { success: true, fileName: shortFileName };

            } catch (error: any) {
                const errorMessage = `Error during file scan for "${shortFileName}" with ${providerNameToUse}: ${error.message}`;
                if (outputChannel) outputChannel.appendLine(errorMessage);
                if (!isPartOfFolderScan) {
                    vscode.window.showErrorMessage(errorMessage);
                    if (outputChannel) outputChannel.show(true);
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
        } else {
            return scanPromise();
        }
    }

    // --- Register command for scanning current file ---
    const scanFileCommand = vscode.commands.registerCommand('secure-coding-assistant.scanFile', async (uri?: vscode.Uri) => {
        if (outputChannel) outputChannel.appendLine("Scan File command triggered.");
        let fileUri: vscode.Uri | undefined = uri;

        if (!fileUri) {
            if (vscode.window.activeTextEditor) {
                fileUri = vscode.window.activeTextEditor.document.uri;
                if (outputChannel) outputChannel.appendLine(`Scanning active editor: ${fileUri.fsPath}`);
            } else {
                vscode.window.showErrorMessage("No active text editor or file specified for scanning.");
                if (outputChannel) outputChannel.appendLine("Scan File: No active editor or URI provided.");
                return;
            }
        } else {
            if (outputChannel) outputChannel.appendLine(`Scanning file from URI: ${fileUri.fsPath}`);
        }

        if (!fileUri) { // Should not happen if logic above is correct
            vscode.window.showErrorMessage("Could not determine the file to scan.");
            if (outputChannel) outputChannel.appendLine("Scan File: File URI is undefined.");
            return;
        }
        // Call the refactored logic, not part of a folder scan
        await executeScanOnFileLogic(fileUri, context, false);
    });
    context.subscriptions.push(scanFileCommand);

    // --- Register command for scanning a folder ---
    const scanFolderCommand = vscode.commands.registerCommand('secure-coding-assistant.scanFolder', async (folderUri?: vscode.Uri) => {
        // If no folder URI is provided, use the current file's folder or the first workspace folder
        const effectiveFolderUri = folderUri || 
            (vscode.window.activeTextEditor?.document.uri ? 
                vscode.Uri.file(path.dirname(vscode.window.activeTextEditor.document.uri.fsPath)) : 
                vscode.workspace.workspaceFolders?.[0].uri);

        if (!effectiveFolderUri) {
            vscode.window.showErrorMessage('No folder selected and no workspace folder available');
            return;
        }

        if (outputChannel) outputChannel.appendLine(`Starting scan for folder: ${effectiveFolderUri.fsPath}`);
        vscode.window.showInformationMessage(`Scanning folder: ${effectiveFolderUri.fsPath}...`);

        // Define supported file extensions and excluded directories
        const sourceCodeExtensions = new Set([
            '.ts', '.js', '.py', '.java', '.c', '.cpp', '.go', '.rs', '.php', '.rb',
            '.cs', '.swift', '.kt', '.m', '.h', '.hpp', '.json', '.yaml', '.yml',
            '.xml', '.html', '.css', '.scss', '.less', '.sh', '.ps1', '.bat'
        ]);

        const commonExcludedDirs = new Set([
            'node_modules', 'dist', 'build', 'out', 'extension', 'bin', 'obj', 
            '.git', '.svn', '.hg', '.vscode', '.vscode-test', 
            'venv', 'env', '.env', '__pycache__'
        ]);

        // Track files to scan and results
        const filesToScan: vscode.Uri[] = [];
        const scanResults: { success: boolean; fileName: string; error?: string }[] = [];

        // Function to collect files to scan
        async function collectFilesToScan(directoryUri: vscode.Uri) {
            try {
                const entries = await vscode.workspace.fs.readDirectory(directoryUri);
                for (const [name, type] of entries) {
                    const entryUri = vscode.Uri.joinPath(directoryUri, name);
                    
                    if (type === vscode.FileType.File) {
                        const fileExtension = name.substring(name.lastIndexOf('.')).toLowerCase();
                        if (sourceCodeExtensions.has(fileExtension)) {
                            filesToScan.push(entryUri);
                        }
                    } else if (type === vscode.FileType.Directory) {
                        if (!name.startsWith('.') && !commonExcludedDirs.has(name.toLowerCase())) {
                            await collectFilesToScan(entryUri);
                        }
                    }
                }
            } catch (error: any) {
                if (outputChannel) outputChannel.appendLine(`Error collecting files from ${directoryUri.fsPath}: ${error.message}`);
            }
        }

        // Function to process files in batches
        async function processFilesInBatches(files: vscode.Uri[], batchSize: number = 5) {
            for (let i = 0; i < files.length; i += batchSize) {
                const batch = files.slice(i, i + batchSize);
                const batchResults = await Promise.all(
                    batch.map(file => executeScanOnFileLogic(file, context, true))
                );
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
                if (outputChannel) outputChannel.appendLine(`Found ${filesToScan.length} files to scan in ${effectiveFolderUri.fsPath}.`);

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

        } catch (error: any) {
            const errorMessage = `Failed to scan folder: ${effectiveFolderUri.fsPath}. Check the output channel for details.`;
            vscode.window.showErrorMessage(errorMessage);
            if (outputChannel) outputChannel.appendLine(errorMessage);
        } finally {
            if (outputChannel) outputChannel.show(true);
        }
    });
    context.subscriptions.push(scanFolderCommand);

    // --- Register command for adding a Custom LLM Provider ---
    const addCustomLlmProviderCommand = vscode.commands.registerCommand('secure-coding-assistant.addCustomLlmProvider', async () => {
        if (outputChannel) outputChannel.appendLine("Attempting to add Custom LLM Provider...");

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
                const existingConfigs = context.globalState.get<CustomLlmConfig[]>('customLlmProviders') || [];
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
            if (outputChannel) outputChannel.appendLine("Custom LLM setup cancelled by user (name input).");
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
            if (outputChannel) outputChannel.appendLine(`Custom LLM setup for "${providerName}" cancelled by user (API key input).`);
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
                } catch (_) {
                    return "Invalid URL format.";
                }
            }
        });

        if (!endpointUrlInput) {
            vscode.window.showWarningMessage("Custom LLM Provider setup cancelled: Endpoint URL not provided.");
            if (outputChannel) outputChannel.appendLine(`Custom LLM setup for "${providerName}" cancelled by user (endpoint URL input).`);
            return;
        }
        const endpointUrl = endpointUrlInput.trim();

        try {
            // Store API Key in secrets
            const secretApiKeyName = `customLlmProvider.${providerName}.apiKey`;
            await context.secrets.store(secretApiKeyName, apiKey);

            // Store provider config (name and endpoint) in global state
            const customLlmConfigs = context.globalState.get<CustomLlmConfig[]>('customLlmProviders') || [];
            
            // Double check uniqueness here in case of async race conditions (though unlikely with modal inputs)
            if (customLlmConfigs.find(cfg => cfg.name.toLowerCase() === providerName.toLowerCase())) {
                vscode.window.showErrorMessage(`Custom LLM Provider "${providerName}" already exists. Please try adding with a different name.`);
                await context.secrets.delete(secretApiKeyName); // Clean up stored secret
                if (outputChannel) outputChannel.appendLine(`Error adding Custom LLM "${providerName}": Name already exists (race condition check).`);
                return;
            }

            customLlmConfigs.push({ name: providerName, endpoint: endpointUrl });
            await context.globalState.update('customLlmProviders', customLlmConfigs);

            vscode.window.showInformationMessage(`Custom LLM Provider "${providerName}" added successfully.`);
            if (outputChannel) {
                outputChannel.appendLine(`Custom LLM Provider "${providerName}" added with endpoint: ${endpointUrl}`);
            }

        } catch (error: any) {
            vscode.window.showErrorMessage(`Failed to add Custom LLM Provider "${providerName}": ${error.message}`);
            if (outputChannel) {
                outputChannel.appendLine(`Error adding Custom LLM Provider "${providerName}": ${error.message}`);
            }
            // Attempt to clean up the stored secret if other parts of the setup failed
            const secretApiKeyName = `customLlmProvider.${providerName}.apiKey`;
            try { await context.secrets.delete(secretApiKeyName); } catch (cleanupError) { /* best effort */ }
        }
    });
    context.subscriptions.push(addCustomLlmProviderCommand);
}

// Function to retrieve an API key
export async function getApiKey(context: vscode.ExtensionContext, providerName: string): Promise<string | undefined> {
    let secretKey: string | undefined;

    // Check if it's a built-in provider
    if (Object.values(LlmProvider).includes(providerName as LlmProvider)) {
        secretKey = getBuiltInSecretKey(providerName as LlmProvider);
    } else {
        // Assume it's a custom provider name
        secretKey = `customLlmProvider.${providerName}.apiKey`;
    }

    if (!secretKey) { // Should not happen if providerName is validated before calling
        const message = `Could not determine secret key for provider: ${providerName}`;
        console.error(message);
        if (outputChannel) outputChannel.appendLine(`Error in getApiKey: ${message}`);
        // vscode.window.showErrorMessage(`Invalid LLM provider specified: ${providerName}`); // Potentially too noisy
        return undefined;
    }

    try {
        const apiKey = await context.secrets.get(secretKey);
        if (!apiKey && outputChannel) {
            outputChannel.appendLine(`API Key not found in secrets for key name: ${secretKey} (Provider: ${providerName})`);
        }
        return apiKey;
    } catch (error: any) {
        const message = `Failed to retrieve API key for ${providerName} (key name ${secretKey}): ${error.message}`;
        console.error(message);
        // vscode.window.showErrorMessage(`Failed to retrieve API key for ${providerName}.`); // Potentially too noisy
        if (outputChannel) outputChannel.appendLine(`Error in getApiKey: ${message}`);
        return undefined;
    }
}

// Function to get the preferred LLM from settings
// Returns the string as configured, e.g., "OpenAI", "Anthropic", "Google", or "Custom".

export function getPreferredLlm(): string | undefined {
    const config = vscode.workspace.getConfiguration('secureCodingAssistant');
    const preferredLlmString = config.get<string>('preferredLlm');

    if (!preferredLlmString) {
        if (outputChannel) outputChannel.appendLine(`Preferred LLM setting is not set. Please configure "secureCodingAssistant.preferredLlm".`);
        return undefined;
    }

    const expectedEnumValues = [...Object.values(LlmProvider).map(p => p.toString()), "Custom"];

    if (expectedEnumValues.some(val => val.toLowerCase() === preferredLlmString.toLowerCase())) { // Make comparison case-insensitive for robustness
        return preferredLlmString;
    } else {
        if (outputChannel) outputChannel.appendLine(`Invalid preferredLlm setting: "${preferredLlmString}". Please choose from ${expectedEnumValues.join(', ')} in settings.`);
        return undefined;
    }
}




export function deactivate() {
    if (outputChannel) {
        outputChannel.appendLine('Deactivating "secure-coding-assistant".');
        outputChannel.dispose();
    }
}
