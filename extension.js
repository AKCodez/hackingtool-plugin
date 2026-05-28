const vscode = require('vscode');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');

let outputChannel;
let extensionPath;
let toolsData;

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
    extensionPath = context.extensionPath;
    outputChannel = vscode.window.createOutputChannel('HackingTool');
    
    console.log('HackingTool extension is now active');

    // Load tools data
    loadToolsData();

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('hackingtool.preflight', runPreflight),
        vscode.commands.registerCommand('hackingtool.searchTools', searchTools),
        vscode.commands.registerCommand('hackingtool.runTool', runToolCommand),
        vscode.commands.registerCommand('hackingtool.showEnvironment', showEnvironment),
        vscode.commands.registerCommand('hackingtool.refreshTools', refreshTools),
        vscode.commands.registerCommand('hackingtool.toolExplorer.refresh', () => {
            loadToolsData();
            toolExplorerProvider.refresh();
        }),
        vscode.commands.registerCommand('hackingtool.toolExplorer.runTool', runToolFromExplorer),
        vscode.commands.registerCommand('hackingtool.toolExplorer.showInfo', showToolInfo)
    );

    // Create tree view
    const toolExplorerProvider = new ToolExplorerProvider();
    vscode.window.createTreeView('hackingtoolToolExplorer', {
        treeDataProvider: toolExplorerProvider
    });

    // Register Copilot Language Model Tools
    try {
        if (typeof vscode.lm?.registerTool === 'function') {
            context.subscriptions.push(
                vscode.lm.registerTool('hackingtool_preflight', new PreflightTool()),
                vscode.lm.registerTool('hackingtool_search',    new SearchTool()),
                vscode.lm.registerTool('hackingtool_run',       new RunTool())
            );
            console.log('[HackingTool] LM tools registered: hackingtool_preflight, hackingtool_search, hackingtool_run');
        } else {
            console.warn('[HackingTool] vscode.lm.registerTool not available in this VS Code version');
        }
    } catch (err) {
        console.error('[HackingTool] Failed to register LM tools:', err);
    }

    // Run preflight check on activation
    setTimeout(() => {
        vscode.window.showInformationMessage('HackingTool loaded! Run "HackingTool: Preflight Check" to verify setup.', 'Run Check')
            .then(selection => {
                if (selection === 'Run Check') {
                    runPreflight();
                }
            });
    }, 1000);
}

function loadToolsData() {
    const toolsPath = path.join(extensionPath, 'plugins', 'hackingtool', 'data', 'tools.json');
    try {
        if (fs.existsSync(toolsPath)) {
            const data = fs.readFileSync(toolsPath, 'utf8');
            toolsData = JSON.parse(data);
        } else {
            vscode.window.showWarningMessage('Tools database not found. Run "Refresh Tool Index" to build it.');
        }
    } catch (error) {
        vscode.window.showErrorMessage(`Failed to load tools: ${error.message}`);
    }
}

function getPythonPath() {
    const config = vscode.workspace.getConfiguration('hackingtool');
    return config.get('pythonPath', 'python3');
}

function getScriptPath(scriptName) {
    return path.join(extensionPath, 'plugins', 'hackingtool', 'scripts', scriptName);
}

async function runPythonScript(scriptName, args = [], options = {}) {
    const pythonPath = getPythonPath();
    const scriptPath = getScriptPath(scriptName);
    
    return new Promise((resolve, reject) => {
        const proc = spawn(pythonPath, [scriptPath, ...args], {
            cwd: path.join(extensionPath, 'plugins', 'hackingtool'),
            env: {
                ...process.env,
                CLAUDE_PLUGIN_ROOT: path.join(extensionPath, 'plugins', 'hackingtool')
            }
        });

        let stdout = '';
        let stderr = '';

        proc.stdout.on('data', (data) => {
            stdout += data.toString();
        });

        proc.stderr.on('data', (data) => {
            stderr += data.toString();
        });

        proc.on('close', (code) => {
            if (code === 0) {
                try {
                    const result = JSON.parse(stdout);
                    resolve(result);
                } catch (e) {
                    resolve({ stdout, stderr, raw: true });
                }
            } else {
                reject({ code, stdout, stderr });
            }
        });

        proc.on('error', (error) => {
            reject(error);
        });
    });
}

// Like runPythonScript but always resolves (never rejects) and supports cancellation.
// Used by the Copilot LM tools so errors are returned as structured data.
async function runPythonScriptForLM(scriptName, args = [], token = null) {
    const pythonPath = getPythonPath();
    const scriptPath = getScriptPath(scriptName);

    return new Promise((resolve) => {
        const proc = spawn(pythonPath, [scriptPath, ...args], {
            cwd: path.join(extensionPath, 'plugins', 'hackingtool'),
            env: {
                ...process.env,
                CLAUDE_PLUGIN_ROOT: path.join(extensionPath, 'plugins', 'hackingtool')
            }
        });

        let stdout = '';
        let stderr = '';

        if (token) {
            token.onCancellationRequested(() => {
                proc.kill();
                resolve({ error: 'Cancelled by user', stdout, stderr });
            });
        }

        proc.stdout.on('data', (data) => { stdout += data.toString(); });
        proc.stderr.on('data', (data) => { stderr += data.toString(); });

        proc.on('close', (code) => {
            try {
                resolve(JSON.parse(stdout));
            } catch (_) {
                resolve({ stdout, stderr, returncode: code });
            }
        });

        proc.on('error', (err) => {
            resolve({ error: err.message, stdout, stderr });
        });
    });
}

async function runPreflight() {
    outputChannel.clear();
    outputChannel.show();
    outputChannel.appendLine('🔍 Running preflight check...\n');

    try {
        const result = await runPythonScript('ht_preflight.py');
        
        outputChannel.appendLine('=== PREFLIGHT RESULTS ===\n');
        outputChannel.appendLine(`Verdict: ${result.verdict.toUpperCase()}`);
        outputChannel.appendLine(`Backend: ${result.env.preferred_backend}`);
        outputChannel.appendLine(`Host: ${result.env.host} (${result.env.arch})`);
        
        if (result.env.in_wsl) {
            outputChannel.appendLine('Running inside WSL');
        }
        
        if (result.env.docker) {
            outputChannel.appendLine('✓ Docker available');
        }
        
        if (result.env.wsl_distros && result.env.wsl_distros.length > 0) {
            outputChannel.appendLine(`WSL distros: ${result.env.wsl_distros.join(', ')}`);
        }

        if (result.recommendations && result.recommendations.length > 0) {
            outputChannel.appendLine('\n=== RECOMMENDATIONS ===\n');
            result.recommendations.forEach(rec => {
                outputChannel.appendLine(`• [${rec.priority}] ${rec.action} — ${rec.why}`);
            });
        }

        outputChannel.appendLine('\n' + JSON.stringify(result, null, 2));

        let message = `Preflight ${result.verdict}: Backend=${result.env.preferred_backend}`;
        if (result.verdict === 'ready') {
            vscode.window.showInformationMessage(message);
        } else if (result.verdict === 'partial') {
            vscode.window.showWarningMessage(message);
        } else {
            vscode.window.showErrorMessage(message);
        }
    } catch (error) {
        outputChannel.appendLine(`\n❌ Error: ${error.message || error}`);
        vscode.window.showErrorMessage(`Preflight failed: ${error.message || error}`);
    }
}

async function showEnvironment() {
    outputChannel.clear();
    outputChannel.show();
    outputChannel.appendLine('🌍 Environment Information\n');

    try {
        const result = await runPythonScript('ht_env.py');
        outputChannel.appendLine(JSON.stringify(result, null, 2));
        
        vscode.window.showInformationMessage(
            `Host: ${result.host}, Backend: ${result.preferred_backend}, Docker: ${result.docker}`
        );
    } catch (error) {
        outputChannel.appendLine(`\n❌ Error: ${error.message || error}`);
        vscode.window.showErrorMessage(`Failed to get environment: ${error.message || error}`);
    }
}

async function searchTools() {
    const query = await vscode.window.showInputBox({
        prompt: 'Search tools (name, category, tag, or description)',
        placeHolder: 'e.g., nmap, subdomain, osint'
    });

    if (!query) return;

    outputChannel.clear();
    outputChannel.show();
    outputChannel.appendLine(`🔍 Searching for: "${query}"\n`);

    try {
        const result = await runPythonScript('ht_search.py', ['--q', query]);
        
        if (result.matches && result.matches.length > 0) {
            outputChannel.appendLine(`Found ${result.matches.length} tool(s):\n`);
            
            result.matches.forEach((tool, idx) => {
                outputChannel.appendLine(`${idx + 1}. ${tool.title} (${tool.id})`);
                outputChannel.appendLine(`   ${tool.description}`);
                outputChannel.appendLine(`   URL: ${tool.project_url}`);
                outputChannel.appendLine('');
            });

            // Offer to run a tool
            const items = result.matches.map(t => ({
                label: t.title,
                description: t.id,
                detail: t.description,
                tool: t
            }));

            const selected = await vscode.window.showQuickPick(items, {
                placeHolder: 'Select a tool to run'
            });

            if (selected) {
                runToolInteractive(selected.tool);
            }
        } else {
            outputChannel.appendLine('No tools found.');
            vscode.window.showInformationMessage('No tools found matching your query.');
        }
    } catch (error) {
        outputChannel.appendLine(`\n❌ Error: ${error.message || error}`);
        vscode.window.showErrorMessage(`Search failed: ${error.message || error}`);
    }
}

async function runToolCommand() {
    if (!toolsData || !toolsData.tools) {
        vscode.window.showErrorMessage('Tools not loaded. Run "Refresh Tool Index" first.');
        return;
    }

    const items = toolsData.tools.map(t => ({
        label: t.title,
        description: t.id,
        detail: t.description,
        tool: t
    }));

    const selected = await vscode.window.showQuickPick(items, {
        placeHolder: 'Select a tool to run',
        matchOnDescription: true,
        matchOnDetail: true
    });

    if (selected) {
        runToolInteractive(selected.tool);
    }
}

async function runToolInteractive(tool) {
    // Check if tool is interactive
    if (tool.capabilities && tool.capabilities.interactive) {
        const proceed = await vscode.window.showWarningMessage(
            `${tool.title} is interactive. You may need to use --force --command for non-interactive mode.`,
            'Proceed', 'Cancel'
        );
        if (proceed !== 'Proceed') return;
    }

    const args = await vscode.window.showInputBox({
        prompt: `Arguments for ${tool.title}`,
        placeHolder: 'e.g., -h or --help',
        value: '--help'
    });

    if (args === undefined) return;

    runTool(tool.id, args);
}

async function runTool(toolId, args = '') {
    const config = vscode.workspace.getConfiguration('hackingtool');
    const timeout = config.get('defaultTimeout', 180);
    const showOutput = config.get('showOutputChannel', true);

    if (showOutput) {
        outputChannel.clear();
        outputChannel.show();
    }

    outputChannel.appendLine(`▶️  Running: ${toolId}`);
    outputChannel.appendLine(`Arguments: ${args || '(none)'}`);
    outputChannel.appendLine(`Timeout: ${timeout}s\n`);
    outputChannel.appendLine('=' .repeat(60) + '\n');

    const startTime = Date.now();

    try {
        const pythonPath = getPythonPath();
        const scriptPath = getScriptPath('ht_run.py');
        const cmdArgs = [toolId];
        
        if (args) {
            cmdArgs.push('--args', args);
        }
        
        cmdArgs.push('--timeout', timeout.toString());

        // Run in terminal for better interactivity
        const terminal = vscode.window.createTerminal({
            name: `HackingTool: ${toolId}`,
            cwd: path.join(extensionPath, 'plugins', 'hackingtool'),
            env: {
                CLAUDE_PLUGIN_ROOT: path.join(extensionPath, 'plugins', 'hackingtool')
            }
        });

        terminal.show();
        terminal.sendText(`${pythonPath} "${scriptPath}" ${cmdArgs.join(' ')}`);

        outputChannel.appendLine(`✓ Launched in terminal: ${toolId}`);
        outputChannel.appendLine(`Duration: ${Date.now() - startTime}ms`);

    } catch (error) {
        outputChannel.appendLine(`\n❌ Error: ${error.message || error}`);
        vscode.window.showErrorMessage(`Tool execution failed: ${error.message || error}`);
    }
}

async function refreshTools() {
    outputChannel.clear();
    outputChannel.show();
    outputChannel.appendLine('🔄 Refreshing tool index...\n');

    try {
        const result = await runPythonScript('ht_index.py');
        
        if (result.raw) {
            outputChannel.appendLine(result.stdout);
        } else {
            outputChannel.appendLine(`Indexed ${result.tool_count || 0} tools`);
        }

        loadToolsData();
        vscode.window.showInformationMessage('Tool index refreshed successfully!');
    } catch (error) {
        outputChannel.appendLine(`\n❌ Error: ${error.message || error}`);
        vscode.window.showErrorMessage(`Failed to refresh tools: ${error.message || error}`);
    }
}

async function runToolFromExplorer(item) {
    if (item && item.tool) {
        runToolInteractive(item.tool);
    }
}

async function showToolInfo(item) {
    if (!item || !item.tool) return;

    const tool = item.tool;
    const panel = vscode.window.createWebviewPanel(
        'toolInfo',
        tool.title,
        vscode.ViewColumn.One,
        {}
    );

    panel.webview.html = getToolInfoHtml(tool);
}

function getToolInfoHtml(tool) {
    const caps = tool.capabilities || {};
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${tool.title}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; padding: 20px; }
        h1 { color: #007acc; }
        .section { margin: 20px 0; }
        .label { font-weight: bold; color: #666; }
        .badge { display: inline-block; padding: 4px 8px; margin: 2px; border-radius: 3px; font-size: 12px; }
        .badge-success { background: #28a745; color: white; }
        .badge-warning { background: #ffc107; color: black; }
        .badge-danger { background: #dc3545; color: white; }
        .badge-info { background: #17a2b8; color: white; }
        code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
        pre { background: #f4f4f4; padding: 12px; border-radius: 4px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>${tool.title}</h1>
    
    <div class="section">
        <div class="label">ID:</div>
        <code>${tool.id}</code>
    </div>

    <div class="section">
        <div class="label">Description:</div>
        <p>${tool.description}</p>
    </div>

    <div class="section">
        <div class="label">Category:</div>
        <span class="badge badge-info">${tool.category}</span>
    </div>

    <div class="section">
        <div class="label">Project URL:</div>
        <a href="${tool.project_url}" target="_blank">${tool.project_url}</a>
    </div>

    <div class="section">
        <div class="label">Supported OS:</div>
        ${(tool.supported_os || []).map(os => `<span class="badge badge-info">${os}</span>`).join(' ')}
    </div>

    <div class="section">
        <div class="label">Capabilities:</div><br>
        ${caps.interactive ? '<span class="badge badge-warning">Interactive</span>' : '<span class="badge badge-success">Non-interactive</span>'}
        ${caps.requires_sudo ? '<span class="badge badge-warning">Requires Sudo</span>' : ''}
        ${caps.requires_gui ? '<span class="badge badge-warning">Requires GUI</span>' : ''}
        ${caps.requires_wifi ? '<span class="badge badge-warning">Requires WiFi</span>' : ''}
        ${caps.requires_hardware ? '<span class="badge badge-warning">Requires Hardware</span>' : ''}
        ${caps.long_running ? '<span class="badge badge-info">Long Running</span>' : ''}
        ${caps.installable ? '<span class="badge badge-success">Installable</span>' : ''}
        ${caps.runnable ? '<span class="badge badge-success">Runnable</span>' : '<span class="badge badge-danger">Not Runnable</span>'}
    </div>

    ${tool.install_commands && tool.install_commands.length > 0 ? `
    <div class="section">
        <div class="label">Install Commands:</div>
        <pre>${tool.install_commands.join('\n')}</pre>
    </div>
    ` : ''}

    ${tool.run_commands && tool.run_commands.length > 0 ? `
    <div class="section">
        <div class="label">Run Commands:</div>
        <pre>${tool.run_commands.join('\n')}</pre>
    </div>
    ` : ''}

    ${tool.tags && tool.tags.length > 0 ? `
    <div class="section">
        <div class="label">Tags:</div>
        ${tool.tags.map(tag => `<span class="badge badge-info">${tag}</span>`).join(' ')}
    </div>
    ` : ''}
</body>
</html>`;
}

class ToolExplorerProvider {
    constructor() {
        this._onDidChangeTreeData = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._onDidChangeTreeData.event;
    }

    refresh() {
        loadToolsData();
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element) {
        return element;
    }

    async getChildren(element) {
        if (!toolsData || !toolsData.tools) {
            return [];
        }

        if (!element) {
            // Root level: show categories
            const categories = {};
            toolsData.tools.forEach(tool => {
                const cat = tool.category || 'uncategorized';
                if (!categories[cat]) {
                    categories[cat] = [];
                }
                categories[cat].push(tool);
            });

            return Object.keys(categories).sort().map(cat => {
                const count = categories[cat].length;
                const item = new vscode.TreeItem(
                    `${cat.replace(/_/g, ' ').toUpperCase()} (${count})`,
                    vscode.TreeItemCollapsibleState.Collapsed
                );
                item.iconPath = new vscode.ThemeIcon('folder');
                item.contextValue = 'category';
                item.category = cat;
                item.tools = categories[cat];
                return item;
            });
        } else if (element.contextValue === 'category') {
            // Category level: show tools
            return element.tools.map(tool => {
                const item = new vscode.TreeItem(
                    tool.title,
                    vscode.TreeItemCollapsibleState.None
                );
                item.description = tool.id;
                item.tooltip = tool.description;
                item.iconPath = new vscode.ThemeIcon('tools');
                item.contextValue = 'tool';
                item.tool = tool;
                return item;
            });
        }

        return [];
    }
}

// ---------------------------------------------------------------------------
// Copilot Language Model Tools
// ---------------------------------------------------------------------------

class PreflightTool {
    async invoke(options, token) {
        const result = await runPythonScriptForLM('ht_preflight.py', [], token);
        return new vscode.LanguageModelToolResult([
            new vscode.LanguageModelTextPart(JSON.stringify(result, null, 2))
        ]);
    }
}

class SearchTool {
    async invoke(options, token) {
        const input = options.input || {};
        const args = [];
        if (input.query)      args.push('--q',          input.query);
        if (input.category)   args.push('--category',   input.category);
        if (input.tag)        args.push('--tag',         input.tag);
        if (input.capability) args.push('--capability', input.capability);
        const result = await runPythonScriptForLM('ht_search.py', args, token);
        return new vscode.LanguageModelToolResult([
            new vscode.LanguageModelTextPart(JSON.stringify(result, null, 2))
        ]);
    }
}

class RunTool {
    async invoke(options, token) {
        const { tool_id, args, timeout } = options.input || {};
        if (!tool_id) {
            return new vscode.LanguageModelToolResult([
                new vscode.LanguageModelTextPart(JSON.stringify({ error: 'tool_id is required' }))
            ]);
        }
        const cmdArgs = [tool_id];
        if (args)    cmdArgs.push('--args',    args);
        if (timeout) cmdArgs.push('--timeout', String(timeout));
        const result = await runPythonScriptForLM('ht_run.py', cmdArgs, token);
        return new vscode.LanguageModelToolResult([
            new vscode.LanguageModelTextPart(JSON.stringify(result, null, 2))
        ]);
    }
}

function deactivate() {
    if (outputChannel) {
        outputChannel.dispose();
    }
}

module.exports = {
    activate,
    deactivate
};
