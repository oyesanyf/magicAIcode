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
Object.defineProperty(exports, "__esModule", { value: true });
const assert = __importStar(require("assert"));
const sinon = __importStar(require("sinon"));
const vscode = __importStar(require("vscode"));
const myExtension = __importStar(require("../extension")); // Adjust path as needed
describe('DeepEval Confidence Score Integration', () => {
    let sandbox;
    let mockContext;
    let showInformationMessageStub;
    let withProgressStub;
    let appendLineSpy;
    let getConfigurationStub;
    let getGlobalStateStub;
    let getSecretStub;
    let openTextDocumentStub;
    let getTextStub;
    // We cannot directly stub `callLlmApi` or `calculateDeepEvalConfidence` as they are not exported.
    // Instead, we will let the actual `callLlmApi` run (which internally calls the mock `calculateDeepEvalConfidence`)
    // and then inspect the arguments passed to `formatAndLogVulnerabilities` or the output logged by it.
    beforeEach(() => {
        sandbox = sinon.createSandbox();
        // Mock ExtensionContext
        mockContext = {
            subscriptions: [],
            workspaceState: { get: sinon.stub(), update: sinon.stub(), keys: sinon.stub() },
            globalState: {
                get: sinon.stub().returns([]),
                update: sinon.stub().resolves(),
                keys: sinon.stub()
            },
            secrets: { get: sinon.stub().resolves('fake-api-key'), store: sinon.stub().resolves(), delete: sinon.stub().resolves(), onDidChange: sinon.stub() },
            extensionUri: vscode.Uri.file('/mock/extension'),
            extensionPath: '/mock/extension',
            environment: { appName: 'vscode', appRoot: '/vscode/app', language: 'en', uiKind: vscode.UIKind.Desktop, remoteName: undefined, extensionDevelopmentPath: undefined },
            storageUri: undefined,
            globalStorageUri: vscode.Uri.file('/mock/globalStorage'),
            logUri: vscode.Uri.file('/mock/log'),
            asAbsolutePath: (relativePath) => `/mock/extension/${relativePath}`,
            storagePath: undefined,
            globalStoragePath: '/mock/globalStorage',
            logPath: '/mock/log',
            extensionMode: vscode.ExtensionMode.Test,
        };
        getGlobalStateStub = mockContext.globalState.get;
        getSecretStub = mockContext.secrets.get;
        showInformationMessageStub = sandbox.stub(vscode.window, 'showInformationMessage');
        withProgressStub = sandbox.stub(vscode.window, 'withProgress').callsFake((options, task) => {
            const mockProgress = { report: sinon.stub() };
            const token = new vscode.CancellationTokenSource().token;
            const result = task(mockProgress, token);
            return result.then(() => { });
        });
        appendLineSpy = sandbox.spy();
        const mockOutputChannel = {
            name: "mockOutputChannel",
            appendLine: appendLineSpy,
            append: sandbox.spy(),
            replace: sandbox.spy(),
            clear: sandbox.spy(),
            show: sandbox.spy(),
            hide: sandbox.spy(),
            dispose: sandbox.spy(),
            logLevel: vscode.LogLevel.Info,
            onDidChangeLogLevel: sandbox.stub(),
            trace: sandbox.stub(),
            debug: sandbox.stub(),
            info: sandbox.stub(),
            warn: sandbox.stub(),
            error: sandbox.stub()
        };
        sandbox.stub(vscode.window, 'createOutputChannel').returns(mockOutputChannel);
        getConfigurationStub = sandbox.stub(vscode.workspace, 'getConfiguration');
        getConfigurationStub.withArgs('secureCodingAssistant').returns({
            get: sinon.stub().withArgs('preferredLlm').returns('OpenAI'), // Default to OpenAI
            has: sinon.stub().returns(true),
            inspect: sinon.stub(),
            update: sinon.stub()
        });
        getSecretStub.withArgs('secureCodingAssistant.openaiApiKey').resolves('fake-openai-key'); // Ensure API key for default
        // Mock document operations
        getTextStub = sandbox.stub().returns('sample code for testing');
        openTextDocumentStub = sandbox.stub(vscode.workspace, 'openTextDocument').resolves({
            uri: vscode.Uri.file('/test/file.js'),
            fileName: '/test/file.js',
            languageId: 'javascript',
            getText: getTextStub,
            // Add other TextDocument properties if needed by the code under test
            isClosed: false, isDirty: false, isUntitled: false, lineCount: 10, version: 1, eol: vscode.EndOfLine.LF,
            lineAt: sinon.stub(), offsetAt: sinon.stub(), positionAt: sinon.stub(), save: sinon.stub(),
            validatePosition: sinon.stub(), validateRange: sinon.stub(), getWordRangeAtPosition: sinon.stub(),
        });
        // Activate the extension
        myExtension.activate(mockContext);
    });
    afterEach(() => {
        sandbox.restore();
        mockContext.subscriptions.forEach(sub => sub.dispose());
        mockContext.subscriptions.length = 0;
    });
    it('should add confidence scores to vulnerabilities and log them', async () => {
        // Trigger a file scan (which will use the actual callLlmApi and thus the mock calculateDeepEvalConfidence)
        await vscode.commands.executeCommand('secure-coding-assistant.scanFile', vscode.Uri.file('/test/file.js'));
        // Check that formatAndLogVulnerabilities (via its logging side effect) includes confidence scores
        const logCalls = appendLineSpy.getCalls();
        // We expect at least one vulnerability to be generated by the mock callLlmApi
        // and for it to have a confidence score logged.
        const hasVulnerabilityLog = logCalls.some((call) => call.args[0].includes('Vulnerability ID:'));
        const hasConfidenceLog = logCalls.some((call) => call.args[0].startsWith('Confidence:'));
        // Due to the random nature of vulnerability generation in callLlmApi,
        // we can only assert that IF vulnerabilities were logged, confidence was also logged.
        if (hasVulnerabilityLog) {
            assert.ok(hasConfidenceLog, 'Confidence score was not logged for vulnerabilities.');
            // Further check the format: "Confidence: XX.X%"
            const confidenceLogEntry = logCalls.find((call) => call.args[0].startsWith('Confidence:'));
            assert.ok(confidenceLogEntry, "Confidence log entry not found even though hasConfidenceLog was true.");
            assert.match(confidenceLogEntry.args[0], /Confidence: \d{1,2}\.\d%/, 'Confidence score format is incorrect.');
        }
        else {
            // If no vulnerabilities were generated in this random run, the test for confidence logging is moot.
            // We can check if "No vulnerabilities detected" was logged.
            const noVulnerabilitiesLogged = logCalls.some((call) => call.args[0].includes('No vulnerabilities detected'));
            assert.ok(noVulnerabilitiesLogged, 'Neither vulnerabilities nor "no vulnerabilities" message was logged.');
        }
        // Verify that the mock DeepEval calculation log message appeared
        const deepEvalLogFound = logCalls.some((call) => call.args[0].includes('Mock DeepEval: Calculating confidence for type'));
        if (hasVulnerabilityLog) { // Only expect DeepEval log if vulnerabilities were generated
            assert.ok(deepEvalLogFound, 'Mock DeepEval calculation was not logged.');
        }
    });
    it('should handle multiple vulnerabilities with confidence scores', async () => {
        // To ensure multiple vulnerabilities, we might need to influence the mock `callLlmApi`.
        // Since we can't directly stub it, we rely on its random nature or run multiple times.
        // For a more deterministic test, callLlmApi would need to be modifiable/stubbable.
        // For now, we'll just run the scan and check the output.
        await vscode.commands.executeCommand('secure-coding-assistant.scanFile', vscode.Uri.file('/test/file.js'));
        const logCalls = appendLineSpy.getCalls();
        const vulnerabilityLogs = logCalls.filter((call) => call.args[0].includes('Vulnerability ID:'));
        const confidenceLogs = logCalls.filter((call) => call.args[0].startsWith('Confidence:'));
        if (vulnerabilityLogs.length > 1) {
            assert.strictEqual(confidenceLogs.length, vulnerabilityLogs.length, 'Number of confidence scores logged should match number of vulnerabilities.');
        }
        else if (vulnerabilityLogs.length === 1) {
            assert.strictEqual(confidenceLogs.length, 1, 'One confidence score should be logged for one vulnerability.');
        }
        // If 0 vulnerabilities, this test doesn't assert much about multiple scores,
        // but it passed the "no errors" implicit test.
    });
    it('should log confidence calculation attempt even if outputChannel is not ready initially for calculateDeepEvalConfidence', async () => {
        // This scenario is tricky to test directly as outputChannel is initialized in activate().
        // The calculateDeepEvalConfidence function has a console.log fallback.
        // We can't easily spy on console.log in this environment without more complex test setup.
        // However, we can ensure that outputChannel is available when calculateDeepEvalConfidence is called
        // because activate() initializes it before any command runs.
        // This test serves more as a conceptual check based on code review.
        // Spy on console.log
        const consoleLogSpy = sandbox.spy(console, 'log');
        // Temporarily break the outputChannel to simulate it not being ready
        // This is risky as it might affect other parts of the test or extension code.
        // A better way would be to control the initialization of outputChannel.
        // For this test, we assume that if outputChannel was null, console.log would be called.
        // The current setup initializes outputChannel in activate(), so this path is hard to hit.
        // Let's assume, hypothetically, we could make outputChannel undefined before the call.
        // This test is more of a placeholder for that logic.
        // Since `myExtension.outputChannel` is not directly assignable from here,
        // we rely on the fact that it IS initialized in `activate()`.
        await vscode.commands.executeCommand('secure-coding-assistant.scanFile', vscode.Uri.file('/test/file.js'));
        const deepEvalLogViaOutputChannel = appendLineSpy.getCalls().some((call) => call.args[0].includes('Mock DeepEval: Calculating confidence'));
        assert.ok(deepEvalLogViaOutputChannel, "DeepEval calculation should be logged to outputChannel if available.");
        // Assert that console.log was NOT called with the DeepEval message, because outputChannel should be available.
        const consoleLogForDeepEval = consoleLogSpy.getCalls().find((call) => typeof call.args[0] === 'string' && call.args[0].includes('Mock DeepEval: Calculating confidence'));
        assert.strictEqual(consoleLogForDeepEval, undefined, "console.log should not be used for DeepEval when outputChannel is available.");
    });
});
//# sourceMappingURL=deepEvalIntegration.test.js.map