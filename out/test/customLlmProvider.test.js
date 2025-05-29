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
describe('Add Custom LLM Provider Functionality (`secure-coding-assistant.addCustomLlmProvider`)', () => {
    let sandbox;
    let mockContext;
    let showInputBoxStub;
    let showInformationMessageStub;
    let showWarningMessageStub;
    let showErrorMessageStub;
    let secretsStoreStub;
    let secretsDeleteStub;
    let globalStateGetStub;
    let globalStateUpdateStub;
    let appendLineSpy;
    beforeEach(() => {
        sandbox = sinon.createSandbox();
        // Mock ExtensionContext
        secretsStoreStub = sandbox.stub();
        secretsDeleteStub = sandbox.stub();
        globalStateGetStub = sandbox.stub();
        globalStateUpdateStub = sandbox.stub();
        mockContext = {
            subscriptions: [],
            secrets: {
                store: secretsStoreStub.resolves(),
                get: sandbox.stub().resolves(), // Not directly used by add command, but good to have
                delete: secretsDeleteStub.resolves(),
                onDidChange: sandbox.stub()
            },
            globalState: {
                get: globalStateGetStub,
                update: globalStateUpdateStub.resolves(),
                keys: sandbox.stub().returns([])
            },
            // Add other necessary ExtensionContext properties if your activate function uses them
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
        // Stub vscode window methods
        showInputBoxStub = sandbox.stub(vscode.window, 'showInputBox');
        showInformationMessageStub = sandbox.stub(vscode.window, 'showInformationMessage');
        showWarningMessageStub = sandbox.stub(vscode.window, 'showWarningMessage');
        showErrorMessageStub = sandbox.stub(vscode.window, 'showErrorMessage');
        // Spy on outputChannel.appendLine
        appendLineSpy = sandbox.spy(); // Will be set up in activate
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
        // Activate the extension to register commands
        // This is essential as the command is registered within activate()
        myExtension.activate(mockContext);
    });
    afterEach(() => {
        sandbox.restore();
        // Dispose of any subscriptions made during activation
        mockContext.subscriptions.forEach(sub => sub.dispose());
        mockContext.subscriptions.length = 0;
    });
    it('should successfully add a new custom LLM provider', async () => {
        globalStateGetStub.withArgs('customLlmProviders').returns([]); // No existing providers
        showInputBoxStub.onFirstCall().callsFake((options) => {
            if (options.value === 'MyTestLLM') {
                return Promise.resolve('MyTestLLM');
            }
        });
        showInputBoxStub.onSecondCall().callsFake((options) => {
            if (options.value === 'test-api-key') {
                return Promise.resolve('test-api-key');
            }
        });
        showInputBoxStub.onThirdCall().callsFake((options) => {
            if (options.value === 'https://custom.api/v1') {
                return Promise.resolve('https://custom.api/v1');
            }
        });
        await vscode.commands.executeCommand('secure-coding-assistant.addCustomLlmProvider');
        assert.ok(secretsStoreStub.calledOnceWith('customLlmProvider.MyTestLLM.apiKey', 'test-api-key'), 'API key not stored correctly');
        const expectedGlobalState = [{ name: 'MyTestLLM', endpoint: 'https://custom.api/v1' }];
        assert.ok(globalStateUpdateStub.calledOnceWith('customLlmProviders', sinon.match(expectedGlobalState)), 'Global state not updated correctly');
        assert.ok(showInformationMessageStub.calledOnceWith('Custom LLM Provider "MyTestLLM" added successfully.'), 'Success message not shown');
        assert.ok(appendLineSpy.calledWith(sinon.match(/Custom LLM Provider "MyTestLLM" added/)), 'Log message not found');
    });
    it('should handle user cancellation at provider name input', async () => {
        showInputBoxStub.onFirstCall().resolves(undefined); // User cancels name input
        await vscode.commands.executeCommand('secure-coding-assistant.addCustomLlmProvider');
        assert.ok(secretsStoreStub.notCalled, 'secrets.store should not be called');
        assert.ok(globalStateUpdateStub.notCalled, 'globalState.update should not be called');
        assert.ok(showWarningMessageStub.calledOnceWith('Custom LLM Provider setup cancelled: Name not provided.'), 'Cancellation warning not shown');
    });
    it('should handle user cancellation at API key input', async () => {
        showInputBoxStub.onFirstCall().resolves('MyTestLLM');
        showInputBoxStub.onSecondCall().resolves(undefined); // User cancels API key input
        await vscode.commands.executeCommand('secure-coding-assistant.addCustomLlmProvider');
        assert.ok(secretsStoreStub.notCalled, 'secrets.store should not be called on API key cancel');
        assert.ok(globalStateUpdateStub.notCalled, 'globalState.update should not be called on API key cancel');
        assert.ok(showWarningMessageStub.calledOnceWith('Custom LLM Provider setup cancelled: API Key not provided.'), 'API key cancellation warning not shown');
    });
    it('should handle user cancellation at endpoint URL input', async () => {
        showInputBoxStub.onFirstCall().resolves('MyTestLLM');
        showInputBoxStub.onSecondCall().resolves('test-api-key');
        showInputBoxStub.onThirdCall().resolves(undefined); // User cancels endpoint URL input
        await vscode.commands.executeCommand('secure-coding-assistant.addCustomLlmProvider');
        assert.ok(secretsStoreStub.notCalled, 'secrets.store should not be called on endpoint cancel');
        assert.ok(globalStateUpdateStub.notCalled, 'globalState.update should not be called on endpoint cancel');
        assert.ok(showWarningMessageStub.calledOnceWith('Custom LLM Provider setup cancelled: Endpoint URL not provided.'), 'Endpoint URL cancellation warning not shown');
    });
    it('should fail if provider name is empty', async () => {
        // The validation is part of showInputBox options, so we need to simulate it being called
        // and then the command logic reacting to an empty string if validation somehow passed (or wasn't perfect).
        // The current implementation relies on validateInput. If validateInput returns an error message, showInputBox returns undefined.
        showInputBoxStub.onFirstCall().callsFake((options) => {
            if (!options.validateInput) {
                return Promise.resolve('');
            }
            const validationResult = options.validateInput('');
            if (validationResult)
                return Promise.resolve(undefined);
            return Promise.resolve('');
        });
        await vscode.commands.executeCommand('secure-coding-assistant.addCustomLlmProvider');
        assert.ok(showWarningMessageStub.calledWith('Custom LLM Provider setup cancelled: Name not provided.'), "Warning for empty name not shown.");
        assert.ok(secretsStoreStub.notCalled, 'secrets.store should not be called');
    });
    it('should fail if API key is empty', async () => {
        showInputBoxStub.onFirstCall().resolves('MyTestLLM');
        showInputBoxStub.onSecondCall().callsFake((options) => {
            if (!options.validateInput) {
                return Promise.resolve('');
            }
            const validationResult = options.validateInput('');
            if (validationResult)
                return Promise.resolve(undefined);
            return Promise.resolve('');
        });
        await vscode.commands.executeCommand('secure-coding-assistant.addCustomLlmProvider');
        assert.ok(showWarningMessageStub.calledWith('Custom LLM Provider setup cancelled: API Key not provided.'), "Warning for empty API key not shown.");
        assert.ok(secretsStoreStub.notCalled);
    });
    it('should fail if endpoint URL is empty', async () => {
        showInputBoxStub.onFirstCall().resolves('MyTestLLM');
        showInputBoxStub.onSecondCall().resolves('test-api-key');
        showInputBoxStub.onThirdCall().callsFake((options) => {
            if (!options.validateInput) {
                return Promise.resolve('');
            }
            const validationResult = options.validateInput('');
            if (validationResult)
                return Promise.resolve(undefined);
            return Promise.resolve('');
        });
        await vscode.commands.executeCommand('secure-coding-assistant.addCustomLlmProvider');
        assert.ok(showWarningMessageStub.calledWith('Custom LLM Provider setup cancelled: Endpoint URL not provided.'), "Warning for empty endpoint not shown.");
        assert.ok(secretsStoreStub.notCalled);
    });
    it('should fail if provider name is a duplicate of an existing custom LLM', async () => {
        globalStateGetStub.withArgs('customLlmProviders').returns([{ name: 'ExistingLLM', endpoint: 'http://old.api' }]);
        showInputBoxStub.onFirstCall().callsFake((options) => {
            if (!options.validateInput) {
                return Promise.resolve('ExistingLLM');
            }
            const validationResult = options.validateInput('ExistingLLM');
            if (validationResult)
                return Promise.resolve(undefined);
            return Promise.resolve('ExistingLLM');
        });
        await vscode.commands.executeCommand('secure-coding-assistant.addCustomLlmProvider');
        // Expect a warning because the input prompt's validation should prevent submission, leading to cancellation.
        assert.ok(showWarningMessageStub.calledWith('Custom LLM Provider setup cancelled: Name not provided.'), "Duplicate name should lead to cancellation or specific error message.");
        assert.ok(secretsStoreStub.notCalled);
        assert.ok(globalStateUpdateStub.notCalled);
    });
    it('should fail if provider name conflicts with a built-in provider', async () => {
        globalStateGetStub.withArgs('customLlmProviders').returns([]);
        showInputBoxStub.onFirstCall().callsFake((options) => {
            if (!options.validateInput) {
                return Promise.resolve('OpenAI');
            }
            const validationResult = options.validateInput('OpenAI');
            if (validationResult)
                return Promise.resolve(undefined);
            return Promise.resolve('OpenAI');
        });
        await vscode.commands.executeCommand('secure-coding-assistant.addCustomLlmProvider');
        assert.ok(showWarningMessageStub.calledWith('Custom LLM Provider setup cancelled: Name not provided.'), "Built-in name conflict should lead to cancellation.");
        assert.ok(secretsStoreStub.notCalled);
    });
    it('should fail if endpoint URL is invalid', async () => {
        globalStateGetStub.withArgs('customLlmProviders').returns([]);
        showInputBoxStub.onFirstCall().resolves('MyValidLLM');
        showInputBoxStub.onSecondCall().resolves('valid-key');
        showInputBoxStub.onThirdCall().callsFake((options) => {
            if (!options.validateInput) {
                return Promise.resolve('invalid-url');
            }
            const validationResult = options.validateInput('invalid-url');
            if (validationResult)
                return Promise.resolve(undefined);
            return Promise.resolve('invalid-url');
        });
        await vscode.commands.executeCommand('secure-coding-assistant.addCustomLlmProvider');
        assert.ok(showWarningMessageStub.calledWith('Custom LLM Provider setup cancelled: Endpoint URL not provided.'), "Invalid URL should lead to cancellation.");
        assert.ok(secretsStoreStub.notCalled);
    });
    it('should handle error during secrets.store and attempt to clean up', async () => {
        globalStateGetStub.withArgs('customLlmProviders').returns([]);
        showInputBoxStub.onFirstCall().resolves('ErrorLLM');
        showInputBoxStub.onSecondCall().resolves('error-key');
        showInputBoxStub.onThirdCall().resolves('https://error.api/v1');
        secretsStoreStub.rejects(new Error('Failed to store secret'));
        await vscode.commands.executeCommand('secure-coding-assistant.addCustomLlmProvider');
        assert.ok(showErrorMessageStub.calledWith('Failed to add Custom LLM Provider "ErrorLLM": Failed to store secret'), 'Error message for storage failure not shown');
        assert.ok(secretsDeleteStub.calledOnceWith('customLlmProvider.ErrorLLM.apiKey'), 'Cleanup of secret not attempted on store failure');
        assert.ok(globalStateUpdateStub.notCalled, 'Global state should not be updated if secret storing fails');
    });
    it('should handle error during globalState.update and attempt to clean up secret', async () => {
        globalStateGetStub.withArgs('customLlmProviders').returns([]);
        showInputBoxStub.onFirstCall().resolves('ErrorStateLLM');
        showInputBoxStub.onSecondCall().resolves('error-state-key');
        showInputBoxStub.onThirdCall().resolves('https://errorstate.api/v1');
        secretsStoreStub.resolves(); // Store succeeds
        globalStateUpdateStub.rejects(new Error('Failed to update global state')); // Update fails
        await vscode.commands.executeCommand('secure-coding-assistant.addCustomLlmProvider');
        assert.ok(showErrorMessageStub.calledWith('Failed to add Custom LLM Provider "ErrorStateLLM": Failed to update global state'), 'Error message for global state failure not shown');
        assert.ok(secretsDeleteStub.calledOnceWith('customLlmProvider.ErrorStateLLM.apiKey'), 'Cleanup of secret not attempted on global state update failure');
    });
});
//# sourceMappingURL=customLlmProvider.test.js.map