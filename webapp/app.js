/**
 * SecuredAI Lab - Interactive Agent Security Playground
 * =====================================================
 * Client-side only application for demonstrating AI agent security vulnerabilities
 * All API calls are made directly from browser using user's own API key
 * 
 * Supports multiple OWASP ASI modules dynamically loaded from modules.js
 */

// ============================================
// Configuration & State
// ============================================

const CONFIG = {
    // Backend API URL - update this when deploying
    backendUrl: localStorage.getItem('securedai-backend-url') || 'http://localhost:8080',
    
    providers: {
        openai: {
            name: 'OpenAI',
            baseUrl: 'https://api.openai.com/v1/chat/completions',
            models: ['gpt-4o-mini', 'gpt-4o', 'gpt-4-turbo'],
            keyPrefix: 'sk-'
        },
        gemini: {
            name: 'Google Gemini',
            baseUrl: 'https://generativelanguage.googleapis.com/v1beta/models',
            models: ['gemini-2.0-flash', 'gemini-1.5-pro'],
            keyPrefix: 'AIza'
        },
        anthropic: {
            name: 'Anthropic',
            baseUrl: 'https://api.anthropic.com/v1/messages',
            models: ['claude-3-haiku-20240307', 'claude-3-sonnet-20240229'],
            keyPrefix: 'sk-ant-'
        }
    }
};

// State management
const state = {
    apiKey: null,
    provider: 'gemini',
    model: 'gemini-2.0-flash',
    mitigationsEnabled: true,
    backendMode: localStorage.getItem('securedai-backend-mode') === 'true',
    agentType: 'both', // 'vulnerable', 'secure', or 'both'
    currentModule: null,
    logs: [],
    stats: {
        total: 0,
        safe: 0,
        blocked: 0,
        dangerous: 0
    }
};

// Simulated customer database (shared across modules)
const CUSTOMER_DATABASE = {
    "C001": { name: "Alice Johnson", email: "alice@example.com", phone: "555-0101", credit_card_last4: "4242", ssn: "***-**-1234" },
    "C002": { name: "Bob Smith", email: "bob@example.com", phone: "555-0102", credit_card_last4: "1234", ssn: "***-**-5678" },
    "C003": { name: "Charlie Brown", email: "charlie@example.com", phone: "555-0103", credit_card_last4: "5678", ssn: "***-**-9012" }
};

// ============================================
// Module Management
// ============================================

function initializeModule(moduleId) {
    const module = window.getModule(moduleId);
    if (!module) {
        console.error(`Module ${moduleId} not found`);
        return;
    }
    
    state.currentModule = module;
    
    // Update UI with module content
    updateHeroSection(module);
    updateStatsSection(module);
    updatePresets(module);
    updateAttackCards(module);
    updateMitigations(module);
    updateModuleSelector(moduleId);
    
    // Clear logs when switching modules
    clearLogs();
    
    // Reset detection display
    updateRiskDisplay(0, [], []);
    
    console.log(`🔄 Switched to module: ${module.id} - ${module.title}`);
}

function updateHeroSection(module) {
    // Update badge
    document.getElementById('hero-badge').textContent = module.hero.badge;
    
    // Update title
    document.getElementById('hero-title-prefix').textContent = `Explore ${module.title}`;
    document.getElementById('hero-title-gradient').textContent = module.subtitle;
    
    // Update subtitle
    document.getElementById('hero-subtitle').textContent = module.description;
    
    // Update terminal
    document.getElementById('terminal-title').textContent = module.hero.terminalTitle;
    
    const terminalBody = document.getElementById('terminal-body');
    terminalBody.innerHTML = module.hero.terminalLogs.map((log, i) => `
        <div class="log-line ${log.status}" style="animation-delay: ${0.2 + i * 0.2}s">
            <span class="timestamp">[${String(9 + Math.floor(i/2)).padStart(2, '0')}:${42 + i}:${String(17 + i * 3).padStart(2, '0')}]</span>
            <span class="status">${log.status === 'safe' ? '✓' : log.status === 'warning' ? '⚠' : '🚨'}</span>
            <span class="message">${log.message}</span>
        </div>
    `).join('');
    
    // Update accent color
    document.documentElement.style.setProperty('--module-color', module.color);
}

function updateStatsSection(module) {
    const statsSection = document.getElementById('stats-section');
    statsSection.innerHTML = module.stats.map(stat => `
        <div class="stat-card">
            <div class="stat-icon">${stat.icon}</div>
            <div class="stat-value">${stat.value}</div>
            <div class="stat-label">${stat.label}</div>
        </div>
    `).join('');
}

function updatePresets(module) {
    const presetSelect = document.getElementById('preset-select');
    presetSelect.innerHTML = '<option value="">-- Select Preset --</option>';
    
    Object.entries(module.presets).forEach(([key, preset]) => {
        const option = document.createElement('option');
        option.value = key;
        option.textContent = `${preset.icon} ${preset.name}`;
        presetSelect.appendChild(option);
    });
}

function updateAttackCards(module) {
    const attackCards = document.getElementById('attack-cards');
    document.getElementById('attacks-subtitle').textContent = 
        `Explore different ${module.title.toLowerCase()} techniques and their detection`;
    
    attackCards.innerHTML = module.attacks.map(attack => `
        <div class="attack-card" data-attack="${attack.id}">
            <div class="attack-card-header">
                <div class="attack-icon">${attack.icon}</div>
                <div class="attack-severity ${attack.severity}">${attack.severity.toUpperCase()} RISK</div>
            </div>
            <h3 class="attack-title">${attack.title}</h3>
            <p class="attack-description">${attack.description}</p>
            <div class="attack-patterns">
                ${attack.patterns.map(p => `<span class="pattern-tag">${escapeHtml(p)}</span>`).join('')}
            </div>
            <button class="btn btn-outline btn-sm" onclick="loadAttack('${attack.id}')">
                Try This Attack →
            </button>
        </div>
    `).join('');
}

function updateMitigations(module) {
    const mitigationsGrid = document.getElementById('mitigations-grid');
    document.getElementById('mitigations-subtitle').textContent = 
        `Universal defense strategies - highlighted for ${module.id}: ${module.title}`;
    
    // Get all mitigations
    const allMitigations = window.getAllMitigations();
    
    // Get module-specific relevance
    const primaryIds = module.mitigationRefs?.primary || [];
    const applicableIds = module.mitigationRefs?.applicable || [];
    
    // Sort: primary first, then applicable, then others
    const sortedMitigations = [...allMitigations].sort((a, b) => {
        const aIsPrimary = primaryIds.includes(a.id);
        const bIsPrimary = primaryIds.includes(b.id);
        const aIsApplicable = applicableIds.includes(a.id);
        const bIsApplicable = applicableIds.includes(b.id);
        
        if (aIsPrimary && !bIsPrimary) return -1;
        if (!aIsPrimary && bIsPrimary) return 1;
        if (aIsApplicable && !bIsApplicable) return -1;
        if (!aIsApplicable && bIsApplicable) return 1;
        return parseInt(a.number) - parseInt(b.number);
    });
    
    mitigationsGrid.innerHTML = sortedMitigations.map(mit => {
        const isPrimary = primaryIds.includes(mit.id);
        const isApplicable = applicableIds.includes(mit.id);
        const relevance = isPrimary ? 'primary' : (isApplicable ? 'applicable' : 'other');
        const relevanceLabel = isPrimary ? '★ Primary' : (isApplicable ? '◆ Applicable' : '○ Universal');
        
        return `
            <div class="mitigation-card ${relevance}" data-mitigation="${mit.id}">
                <div class="mitigation-header">
                    <div class="mitigation-icon">${mit.icon}</div>
                    <div class="mitigation-relevance ${relevance}">${relevanceLabel}</div>
                </div>
                <h4>${mit.title}</h4>
                <p>${mit.description}</p>
                <div class="mitigation-footer">
                    <div class="mitigation-category">${mit.category}</div>
                    <div class="mitigation-status ${mit.status}">
                        <span class="status-dot"></span>
                        <span>${mit.status === 'active' ? 'Active' : 'Simulated'}</span>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function updateModuleSelector(currentModuleId) {
    const modules = window.getAvailableModules();
    const dropdown = document.getElementById('module-dropdown');
    const currentBtn = document.getElementById('module-dropdown-btn');
    const current = window.getModule(currentModuleId);
    
    // Update button text
    document.getElementById('current-module-icon').textContent = current.icon;
    document.getElementById('current-module-name').textContent = `${current.id}: ${current.title}`;
    
    // Populate dropdown
    dropdown.innerHTML = modules.map(m => `
        <button class="module-option ${m.id === currentModuleId ? 'active' : ''}" 
                onclick="switchModule('${m.id}')"
                style="--module-accent: ${m.color}">
            <span class="module-option-icon">${m.icon}</span>
            <span class="module-option-text">
                <span class="module-option-id">${m.id}</span>
                <span class="module-option-title">${m.title}</span>
            </span>
        </button>
    `).join('');
}

function switchModule(moduleId) {
    initializeModule(moduleId);
    closeModuleDropdown();
    
    // Save preference
    localStorage.setItem('securedai-module', moduleId);
}

function toggleModuleDropdown() {
    const dropdown = document.getElementById('module-dropdown');
    dropdown.classList.toggle('active');
}

function closeModuleDropdown() {
    document.getElementById('module-dropdown').classList.remove('active');
}

// ============================================
// Detection Engine
// ============================================

function detectInjection(text) {
    if (!state.currentModule) return { riskScore: 0, flags: [], patterns: [] };
    
    const flags = [];
    const patterns = [];
    let riskScore = 0;

    // Use module-specific detection patterns
    for (const { pattern, severity, label } of state.currentModule.detectionPatterns) {
        if (pattern.test(text)) {
            const severityScore = severity === 'high' ? 0.3 : severity === 'medium' ? 0.2 : 0.1;
            riskScore += severityScore;
            patterns.push({ pattern: label, severity });
            flags.push({ message: `Pattern detected: ${label}`, severity });
        }
    }

    // Cap at 1.0
    riskScore = Math.min(riskScore, 1.0);

    return { riskScore, flags, patterns };
}

function sanitizeInput(text) {
    let sanitized = text;
    const removals = [];

    // Remove HTML comments
    if (sanitized.includes('<!--')) {
        sanitized = sanitized.replace(/<!--[\s\S]*?-->/g, '[REMOVED: Hidden content]');
        removals.push('HTML comments removed');
    }

    // Remove system tags
    if (sanitized.toLowerCase().includes('<system>') || sanitized.toLowerCase().includes('</system>')) {
        sanitized = sanitized.replace(/<\/?system>/gi, '[REMOVED]');
        removals.push('System tags removed');
    }

    // Neutralize common injection patterns
    const neutralizePatterns = [
        { pattern: /ignore\s+(previous|above|all)\s+instructions?/gi, replacement: '[BLOCKED: Ignore command]' },
        { pattern: /you\s+are\s+now/gi, replacement: '[BLOCKED: Role override]' },
        { pattern: /new\s+instructions?:/gi, replacement: '[BLOCKED: New instructions]' }
    ];

    for (const { pattern, replacement } of neutralizePatterns) {
        if (pattern.test(sanitized)) {
            sanitized = sanitized.replace(pattern, replacement);
            removals.push(`Blocked pattern neutralized`);
        }
    }

    return { sanitized, removals };
}

// ============================================
// UI Updates
// ============================================

function updateRiskDisplay(riskScore, flags, patterns) {
    const riskBadge = document.getElementById('risk-badge');
    const riskFill = document.getElementById('risk-fill');
    const riskScoreEl = document.getElementById('risk-score');
    const patternsList = document.getElementById('patterns-list');
    const inlineThreat = document.getElementById('inline-threat');

    // Determine risk level
    let riskLevel = 'safe';
    if (riskScore > 0.6) riskLevel = 'danger';
    else if (riskScore > 0.3) riskLevel = 'warning';

    // Update inline threat indicator container
    if (inlineThreat) {
        inlineThreat.className = 'inline-threat-indicator';
        if (riskScore > 0.6) {
            inlineThreat.classList.add('high-risk');
        } else if (riskScore > 0.3) {
            inlineThreat.classList.add('has-threats');
        }
    }

    // Update badge
    riskBadge.className = `risk-badge ${riskLevel}`;
    riskBadge.innerHTML = `
        <span class="risk-icon">${riskLevel === 'safe' ? '✓' : riskLevel === 'warning' ? '⚠' : '🚨'}</span>
        <span class="risk-text">${riskLevel === 'safe' ? 'Safe' : riskLevel === 'warning' ? 'Suspicious' : 'Danger'}</span>
    `;

    // Update meter
    riskFill.style.width = `${riskScore * 100}%`;
    riskFill.className = `risk-meter-fill ${riskLevel}`;
    
    // Update score value with color
    riskScoreEl.textContent = riskScore.toFixed(2);
    riskScoreEl.className = `risk-score-value ${riskLevel}`;

    // Update patterns (compact view)
    patternsList.innerHTML = '';
    if (patterns.length > 0) {
        patterns.forEach(p => {
            const span = document.createElement('span');
            span.className = 'pattern-tag';
            span.textContent = p.pattern;
            patternsList.appendChild(span);
        });
    }
}

function updateResponseDisplay(response, blocked, time, model) {
    const responseContent = document.getElementById('response-content');
    const actionBadge = document.getElementById('action-badge');
    const responseTime = document.getElementById('response-time');
    const responseModel = document.getElementById('response-model');

    // Update action badge
    actionBadge.className = `action-badge ${blocked ? 'blocked' : 'executed'}`;
    actionBadge.innerHTML = `
        <span class="action-icon">${blocked ? '⛔' : '✓'}</span>
        <span class="action-text">${blocked ? 'Blocked' : 'Executed'}</span>
    `;

    // Render markdown response
    let renderedResponse;
    if (typeof marked !== 'undefined') {
        // Configure marked for security
        marked.setOptions({
            breaks: true,
            gfm: true
        });
        renderedResponse = marked.parse(response);
    } else {
        // Fallback to escaped text if marked isn't loaded
        renderedResponse = `<pre>${escapeHtml(response)}</pre>`;
    }
    
    responseContent.innerHTML = `<div class="response-text markdown-body">${renderedResponse}</div>`;

    // Update meta
    responseTime.textContent = `${time}ms`;
    responseModel.textContent = model;
}

// Enhanced logging with different entry types
function addLogEntry(type, message, details = null, status = 'info') {
    const icons = {
        'start': '▶️',
        'detection': '🔍',
        'sanitize': '🧹',
        'tool_call': '🔧',
        'data_access': '📂',
        'email': '📧',
        'refund': '💰',
        'payment': '💳',
        'command': '💻',
        'http': '🌐',
        'delete': '🗑️',
        'blocked': '⛔',
        'response': '💬',
        'warning': '⚠️',
        'danger': '🚨',
        'success': '✅',
        'info': 'ℹ️'
    };

    const entry = {
        time: new Date().toLocaleTimeString(),
        type,
        icon: icons[type] || icons['info'],
        message,
        details,
        status // 'safe', 'blocked', 'dangerous', 'info'
    };

    state.logs.unshift(entry);
    state.stats.total++;
    
    if (status === 'safe') state.stats.safe++;
    else if (status === 'blocked') state.stats.blocked++;
    else if (status === 'dangerous') state.stats.dangerous++;

    updateLogsDisplay();
    
    // Auto-scroll log to top
    const logContainer = document.getElementById('activity-log');
    logContainer.scrollTop = 0;
}

function updateLogsDisplay() {
    const log = document.getElementById('activity-log');

    if (state.logs.length === 0) {
        log.innerHTML = `
            <div class="log-empty">
                <span class="empty-icon">📋</span>
                <span>No activity yet. Run some tests to see logs here.</span>
            </div>
        `;
        return;
    }

    log.innerHTML = state.logs.map(entry => {
        const statusClass = entry.status === 'dangerous' ? 'danger' : entry.status;
        const statusText = {
            'safe': '✓ Safe',
            'blocked': '⛔ Blocked',
            'dangerous': '🚨 EXECUTED',
            'info': 'ℹ️ Info'
        }[entry.status] || '';
        
        let detailsHtml = '';
        if (entry.details) {
            detailsHtml = `<div class="log-details">${escapeHtml(entry.details)}</div>`;
        }
        
        return `
            <div class="log-entry ${statusClass}" data-type="${entry.type}">
                <div class="log-main">
                    <span class="log-time">${entry.time}</span>
                    <span class="log-icon">${entry.icon}</span>
                    <span class="log-message">${escapeHtml(entry.message)}</span>
                    <span class="log-status">${statusText}</span>
                </div>
                ${detailsHtml}
            </div>
        `;
    }).join('');
}

// ============================================
// API Integration
// ============================================

async function callOpenAI(messages) {
    const response = await fetch(CONFIG.providers.openai.baseUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${state.apiKey}`
        },
        body: JSON.stringify({
            model: state.model,
            messages: messages,
            max_tokens: 1000,
            temperature: 0.7
        })
    });

    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error?.message || 'API request failed');
    }

    const data = await response.json();
    return data.choices[0].message.content;
}

async function callGemini(messages) {
    const url = `${CONFIG.providers.gemini.baseUrl}/${state.model}:generateContent?key=${state.apiKey}`;
    
    // Convert OpenAI format to Gemini format
    const contents = messages.map(m => ({
        role: m.role === 'assistant' ? 'model' : 'user',
        parts: [{ text: m.content }]
    }));

    const response = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            contents: contents,
            generationConfig: {
                maxOutputTokens: 1000,
                temperature: 0.7
            }
        })
    });

    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error?.message || 'API request failed');
    }

    const data = await response.json();
    return data.candidates[0].content.parts[0].text;
}

async function callAnthropic(messages) {
    // Extract system message if present
    const systemMsg = messages.find(m => m.role === 'system');
    const otherMsgs = messages.filter(m => m.role !== 'system');

    const response = await fetch(CONFIG.providers.anthropic.baseUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'x-api-key': state.apiKey,
            'anthropic-version': '2023-06-01',
            'anthropic-dangerous-direct-browser-access': 'true'
        },
        body: JSON.stringify({
            model: state.model,
            max_tokens: 1000,
            system: systemMsg?.content || '',
            messages: otherMsgs.map(m => ({
                role: m.role,
                content: m.content
            }))
        })
    });

    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error?.message || 'API request failed');
    }

    const data = await response.json();
    return data.content[0].text;
}

async function callLLM(userInput) {
    if (!state.currentModule) throw new Error('No module loaded');
    
    const systemPrompt = state.currentModule.systemPrompt;

    const messages = [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userInput }
    ];

    switch (state.provider) {
        case 'openai':
            return await callOpenAI(messages);
        case 'gemini':
            return await callGemini(messages);
        case 'anthropic':
            return await callAnthropic(messages);
        default:
            throw new Error('Unknown provider');
    }
}

// ============================================
// Backend API Integration (CrewAI)
// ============================================

async function callBackendAPI(prompt) {
    const response = await fetch(`${CONFIG.backendUrl}/api/execute`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            prompt: prompt,
            agent_type: state.agentType,
            provider: state.provider,
            model: state.model,
            api_key: state.apiKey,
        }),
    });

    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Backend API request failed');
    }

    return await response.json();
}

async function callBackendStream(prompt) {
    const response = await fetch(`${CONFIG.backendUrl}/api/execute/stream`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            prompt: prompt,
            agent_type: state.agentType,
            provider: state.provider,
            model: state.model,
            api_key: state.apiKey,
        }),
    });

    if (!response.ok) {
        throw new Error('Backend streaming request failed');
    }

    return response;
}

function processBackendResult(data) {
    // Process thinking steps
    const processThinking = (result, agentType) => {
        if (result?.thinking) {
            result.thinking.forEach(step => {
                addLogEntry('info', `[${agentType}] Thought: ${step.thought?.substring(0, 80)}...`, 
                    step.action ? `Action: ${step.action}` : null, 'info');
            });
        }
    };

    // Process tool calls
    const processToolCalls = (result, agentType) => {
        if (result?.tool_calls) {
            result.tool_calls.forEach(tc => {
                const status = tc.blocked ? 'blocked' : (agentType === 'vulnerable' ? 'dangerous' : 'safe');
                addLogEntry('tool_call', `[${agentType}] ${tc.tool}(${tc.args?.substring(0, 50)}...)`, 
                    tc.result?.substring(0, 100), status);
            });
        }
    };

    // Process policy actions
    const processPolicyActions = (result) => {
        if (result?.policy_actions) {
            result.policy_actions.forEach(pa => {
                addLogEntry('blocked', `Policy: ${pa.tool} - ${pa.action}`, pa.reason, 'blocked');
            });
        }
    };

    // Process vulnerable agent result
    if (data.vulnerable_result) {
        addLogEntry('start', '🔴 Vulnerable Agent Execution', null, 'info');
        processThinking(data.vulnerable_result, 'Vulnerable');
        processToolCalls(data.vulnerable_result, 'vulnerable');
        
        if (data.vulnerable_result.error) {
            addLogEntry('warning', `Error: ${data.vulnerable_result.error}`, null, 'info');
        }
    }

    // Process secure agent result
    if (data.secure_result) {
        addLogEntry('start', '🟢 Secure Agent Execution', null, 'info');
        processThinking(data.secure_result, 'Secure');
        processToolCalls(data.secure_result, 'secure');
        processPolicyActions(data.secure_result);
        
        if (data.secure_result.error) {
            addLogEntry('warning', `Error: ${data.secure_result.error}`, null, 'info');
        }
    }

    // Log comparison
    if (data.comparison) {
        const comp = data.comparison;
        if (comp.attack_mitigated) {
            addLogEntry('success', '✅ Attack mitigated by secure agent!', 
                `Blocked: ${comp.secure_blocked} actions`, 'safe');
        } else {
            addLogEntry('danger', '⚠️ Attack executed on both agents', 
                `Tool calls: Vuln=${comp.vulnerable_tool_calls}, Secure=${comp.secure_tool_calls}`, 'dangerous');
        }
    }

    // Build response text
    let responseText = '';
    
    if (data.vulnerable_result?.response) {
        responseText += `## 🔴 Vulnerable Agent\n\n${data.vulnerable_result.response}\n\n`;
        responseText += `*Execution time: ${data.vulnerable_result.execution_time_ms}ms*\n\n`;
    }
    
    if (data.secure_result?.response) {
        responseText += `## 🟢 Secure Agent\n\n${data.secure_result.response}\n\n`;
        responseText += `*Execution time: ${data.secure_result.execution_time_ms}ms*\n\n`;
        
        if (data.secure_result.policy_actions?.length > 0) {
            responseText += `### Policy Actions\n`;
            data.secure_result.policy_actions.forEach(pa => {
                responseText += `- **${pa.tool}**: ${pa.action} - ${pa.reason}\n`;
            });
        }
    }

    if (data.comparison) {
        responseText += `\n---\n### Comparison\n`;
        responseText += `- Attack mitigated: ${data.comparison.attack_mitigated ? '✅ Yes' : '❌ No'}\n`;
        responseText += `- Vulnerable tool calls: ${data.comparison.vulnerable_tool_calls}\n`;
        responseText += `- Secure tool calls: ${data.comparison.secure_tool_calls}\n`;
        responseText += `- Secure blocked: ${data.comparison.secure_blocked}\n`;
    }

    return responseText || 'No response from agents.';
}

async function handleSSEStream(prompt) {
    const response = await callBackendStream(prompt);
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    
    let fullResult = { vulnerable_result: null, secure_result: null };

    while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const chunk = decoder.decode(value);
        const lines = chunk.split('\n');

        for (const line of lines) {
            if (line.startsWith('data: ')) {
                try {
                    const eventData = JSON.parse(line.slice(6));
                    
                    switch (eventData.event) {
                        case 'start':
                            addLogEntry('start', eventData.data.message, null, 'info');
                            break;
                        case 'status':
                            addLogEntry('info', `${eventData.data.agent} agent: ${eventData.data.status}`, null, 'info');
                            break;
                        case 'thinking':
                            const step = eventData.data.step;
                            addLogEntry('info', `[${eventData.data.agent}] ${step.thought?.substring(0, 60)}...`, 
                                step.action || null, 'info');
                            break;
                        case 'tool_call':
                            const tc = eventData.data.tool_call;
                            const status = eventData.data.agent === 'vulnerable' ? 'dangerous' : 'safe';
                            addLogEntry('tool_call', `[${eventData.data.agent}] ${tc.tool}`, tc.args, status);
                            break;
                        case 'policy':
                            const pa = eventData.data.policy_action;
                            addLogEntry('blocked', `Policy: ${pa.tool}`, pa.reason, 'blocked');
                            break;
                        case 'result':
                            if (eventData.data.agent === 'vulnerable') {
                                fullResult.vulnerable_result = eventData.data.result;
                            } else {
                                fullResult.secure_result = eventData.data.result;
                            }
                            break;
                        case 'done':
                            addLogEntry('success', eventData.data.message, null, 'safe');
                            break;
                        case 'error':
                            addLogEntry('warning', `Error: ${eventData.data.message}`, null, 'info');
                            break;
                    }
                } catch (e) {
                    console.error('SSE parse error:', e);
                }
            }
        }
    }

    return fullResult;
}

async function checkBackendHealth() {
    try {
        const response = await fetch(`${CONFIG.backendUrl}/api/health`, {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' },
        });
        
        if (response.ok) {
            const data = await response.json();
            return { online: true, crewai: data.crewai_available };
        }
    } catch (e) {
        console.log('Backend not available:', e.message);
    }
    return { online: false, crewai: false };
}

function updateBackendStatus(online, crewai) {
    const statusEl = document.getElementById('backend-status');
    if (statusEl) {
        if (online && crewai) {
            statusEl.className = 'backend-status online';
            statusEl.innerHTML = 'Backend Online';
        } else if (online) {
            statusEl.className = 'backend-status partial';
            statusEl.innerHTML = 'Backend (No CrewAI)';
        } else {
            statusEl.className = 'backend-status offline';
            statusEl.innerHTML = 'Backend Offline';
        }
    }
}

// ============================================
// Main Analysis Function
// ============================================

async function analyzeAndExecute() {
    const userInput = document.getElementById('user-input').value.trim();
    const mitigationsEnabled = document.getElementById('enable-mitigations').checked;
    const sendBtn = document.getElementById('send-btn');

    if (!userInput) {
        showToast('Please enter a message to analyze', 'warning');
        return;
    }

    if (!state.currentModule) {
        showToast('No module loaded', 'error');
        return;
    }

    // Check if API key is required
    if (!state.apiKey) {
        showToast('Please set your API key first', 'warning');
        openModal();
        return;
    }

    // Use backend mode if enabled
    if (state.backendMode) {
        await analyzeWithBackend(userInput);
        return;
    }

    // Pre-check: detect threats to see if we need an API key
    const preCheck = detectInjection(userInput);
    const willBeBlocked = mitigationsEnabled && preCheck.riskScore > 0.5;

    // Disable button and show loading
    sendBtn.disabled = true;
    sendBtn.innerHTML = '<span class="spinner"></span><span>Analyzing...</span>';

    const startTime = performance.now();

    // Log the start
    addLogEntry('start', `New ${state.currentModule.id} request received`, 
        userInput.substring(0, 80) + '...', 'info');

    try {
        // Step 1: Detect threats
        const { riskScore, flags, patterns } = detectInjection(userInput);
        updateRiskDisplay(riskScore, flags, patterns);
        
        // Log detection results
        if (patterns.length > 0) {
            addLogEntry('detection', `Threat detection: ${patterns.length} pattern(s) found`, 
                patterns.map(p => p.pattern).join(', '), 
                riskScore > 0.5 ? 'blocked' : 'info');
        }

        // Step 2: Check if blocked
        const blocked = mitigationsEnabled && riskScore > 0.5;

        // Always simulate tool calls to show what WOULD happen
        const toolCalls = state.currentModule.simulateToolCalls('', userInput, mitigationsEnabled);
        
        // Log detected tool calls (shows what attack is trying to do)
        if (toolCalls.length > 0) {
            if (blocked) {
                // Show what would have been blocked
                toolCalls.forEach(tc => {
                    if (tc.dangerous || tc.type === 'blocked') {
                        addLogEntry('blocked', `BLOCKED: ${tc.tool}(${tc.args})`, tc.result, 'blocked');
                    } else {
                        addLogEntry(tc.type, `${tc.tool}(${tc.args})`, tc.result, 'safe');
                    }
                });
            } else {
                // Show what is being executed
                toolCalls.forEach(tc => {
                    const status = tc.dangerous ? 'dangerous' : (tc.type === 'blocked' ? 'blocked' : 'safe');
                    addLogEntry(tc.type, `${tc.tool}(${tc.args})`, tc.result, status);
                });
                
                // Summary of dangerous actions
                const dangerousCount = toolCalls.filter(tc => tc.dangerous).length;
                if (dangerousCount > 0) {
                    addLogEntry('danger', `🚨 ${dangerousCount} DANGEROUS ACTION(S) EXECUTED!`, 
                        `${state.currentModule.title} attack successful - agent performed unauthorized actions`, 'dangerous');
                }
            }
        }

        let response;
        if (blocked) {
            // Log the detection patterns
            flags.forEach(flag => {
                addLogEntry('warning', `Mitigation triggered`, flag.message, 'blocked');
            });
            
            // Generate blocked response
            response = `🛡️ SECURITY ALERT: This request has been blocked.

**Detected threats:**
${flags.map(f => `• ${f.message}`).join('\n')}

**Blocked tool calls:**
${toolCalls.filter(tc => tc.dangerous).map(tc => `• ${tc.tool}(${tc.args}) - ${tc.result}`).join('\n') || '• No dangerous tool calls detected'}

**Risk Score:** ${(riskScore * 100).toFixed(0)}%

This appears to be a ${state.currentModule.title.toLowerCase()} attempt. The security policies have prevented this action.

If you believe this is a false positive, please contact the security team.`;

            addLogEntry('success', 'Attack successfully blocked by mitigations', null, 'safe');
        } else {
            // Sanitize input if mitigations enabled
            let processedInput = userInput;
            if (mitigationsEnabled) {
                const { sanitized, removals } = sanitizeInput(userInput);
                processedInput = sanitized;
                if (removals.length > 0) {
                    addLogEntry('sanitize', `Input sanitized: ${removals.length} modification(s)`, 
                        removals.join(', '), 'info');
                }
            } else if (riskScore > 0.3) {
                // Warn that mitigations are off
                addLogEntry('warning', '⚠️ MITIGATIONS DISABLED - Attack payload will be processed!', 
                    'The following tool calls may expose sensitive data', 'info');
            }

            // Call LLM
            addLogEntry('info', `Calling ${state.provider.toUpperCase()} API...`, state.model, 'info');
            response = await callLLM(processedInput);
            
            // Log response
            addLogEntry('response', 'Agent response generated', 
                response.substring(0, 100) + '...', 
                toolCalls.some(tc => tc.dangerous) ? 'dangerous' : 'safe');
        }

        const endTime = performance.now();
        const elapsed = Math.round(endTime - startTime);

        updateResponseDisplay(response, blocked, elapsed, state.model);

    } catch (error) {
        console.error('Error:', error);
        addLogEntry('warning', `Error: ${error.message}`, null, 'info');
        showToast(`Error: ${error.message}`, 'error');
        
        // Reset displays
        updateResponseDisplay(`Error: ${error.message}`, true, 0, state.model);
    } finally {
        // Re-enable button
        sendBtn.disabled = false;
        sendBtn.innerHTML = '<span class="btn-icon">▶</span><span>Analyze & Execute</span>';
    }
}

async function analyzeWithBackend(userInput) {
    const sendBtn = document.getElementById('send-btn');
    
    // Disable button and show loading
    sendBtn.disabled = true;
    sendBtn.innerHTML = '<span class="spinner"></span><span>Running CrewAI...</span>';

    const startTime = performance.now();

    // Log the start
    addLogEntry('start', `🤖 CrewAI Backend: Processing request...`, 
        userInput.substring(0, 80) + '...', 'info');

    try {
        // Run threat detection (frontend)
        const { riskScore, flags, patterns } = detectInjection(userInput);
        updateRiskDisplay(riskScore, flags, patterns);
        
        if (patterns.length > 0) {
            addLogEntry('detection', `Frontend threat detection: ${patterns.length} pattern(s) found`, 
                patterns.map(p => p.pattern).join(', '), 'info');
        }

        // Call backend API
        addLogEntry('info', `Calling CrewAI backend (${state.agentType} agent)...`, 
            `Provider: ${state.provider}`, 'info');
        
        const data = await callBackendAPI(userInput);
        
        if (!data.success) {
            throw new Error('Backend execution failed');
        }

        // Process and display results
        const response = processBackendResult(data);

        const endTime = performance.now();
        const elapsed = Math.round(endTime - startTime);

        // Determine if attack was mitigated
        const blocked = data.comparison?.attack_mitigated || 
            (data.secure_result?.policy_actions?.length > 0);

        updateResponseDisplay(response, blocked, elapsed, `CrewAI (${state.provider})`);

    } catch (error) {
        console.error('Backend Error:', error);
        addLogEntry('warning', `Backend Error: ${error.message}`, null, 'info');
        showToast(`Backend Error: ${error.message}`, 'error');
        
        // Reset displays
        updateResponseDisplay(`Error: ${error.message}\n\nMake sure the backend server is running.`, true, 0, 'Backend');
    } finally {
        // Re-enable button
        sendBtn.disabled = false;
        sendBtn.innerHTML = '<span class="btn-icon">▶</span><span>Analyze & Execute</span>';
    }
}

// ============================================
// Modal & API Key Management
// ============================================

function openModal() {
    document.getElementById('api-modal').classList.add('active');
    
    // Restore saved values
    if (state.apiKey) {
        document.getElementById('api-key-input').value = state.apiKey;
    }
    document.getElementById('api-provider').value = state.provider;
    updateModelOptions();
    
    // Restore saved model if it exists
    if (state.model) {
        document.getElementById('model-select').value = state.model;
    }
}

function closeModal() {
    document.getElementById('api-modal').classList.remove('active');
}

function updateModelOptions() {
    const provider = document.getElementById('api-provider').value;
    const modelSelect = document.getElementById('model-select');
    const models = CONFIG.providers[provider].models;
    
    modelSelect.innerHTML = models.map((m, i) => 
        `<option value="${m}" ${i === 0 ? 'selected' : ''}>${m}</option>`
    ).join('');
}

function saveApiKey() {
    const apiKey = document.getElementById('api-key-input').value.trim();
    const provider = document.getElementById('api-provider').value;
    const model = document.getElementById('model-select').value;

    if (!apiKey) {
        showToast('Please enter an API key', 'warning');
        return;
    }

    // Basic validation
    const expectedPrefix = CONFIG.providers[provider].keyPrefix;
    if (!apiKey.startsWith(expectedPrefix)) {
        showToast(`API key should start with "${expectedPrefix}" for ${CONFIG.providers[provider].name}`, 'warning');
        return;
    }

    // Save to state (session only - not persisted)
    state.apiKey = apiKey;
    state.provider = provider;
    state.model = model;

    // Update UI
    document.getElementById('key-status').textContent = `${provider.toUpperCase()} ✓`;
    document.getElementById('api-key-btn').classList.add('connected');

    closeModal();
    showToast('API key saved (session only)', 'success');
}

function toggleKeyVisibility() {
    const input = document.getElementById('api-key-input');
    input.type = input.type === 'password' ? 'text' : 'password';
}

// ============================================
// Utility Functions
// ============================================

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icons = {
        success: '✓',
        error: '✕',
        warning: '⚠',
        info: 'ℹ'
    };

    toast.innerHTML = `
        <span class="toast-icon">${icons[type]}</span>
        <span class="toast-message">${escapeHtml(message)}</span>
    `;

    container.appendChild(toast);

    // Auto remove after 4 seconds
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100px)';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

function scrollToSection(id) {
    document.getElementById(id).scrollIntoView({ behavior: 'smooth' });
}

function loadAttack(type) {
    if (!state.currentModule) return;
    
    const preset = state.currentModule.presets[type];
    if (preset) {
        document.getElementById('user-input').value = preset.payload;
        document.getElementById('preset-select').value = type;
        scrollToSection('playground');
        
        // Immediately run detection (but not execution)
        const { riskScore, flags, patterns } = detectInjection(preset.payload);
        updateRiskDisplay(riskScore, flags, patterns);
    }
}

function clearLogs() {
    state.logs = [];
    state.stats = { total: 0, safe: 0, blocked: 0, dangerous: 0 };
    updateLogsDisplay();
}

// ============================================
// Event Listeners
// ============================================

document.addEventListener('DOMContentLoaded', () => {
    // Initialize with saved or default module
    const savedModule = localStorage.getItem('securedai-module') || 'ASI01';
    initializeModule(savedModule);
    
    // Module dropdown
    document.getElementById('module-dropdown-btn').addEventListener('click', toggleModuleDropdown);
    
    // Close dropdown when clicking outside
    document.addEventListener('click', (e) => {
        if (!e.target.closest('.module-selector')) {
            closeModuleDropdown();
        }
    });
    
    // API Key button
    document.getElementById('api-key-btn').addEventListener('click', openModal);
    
    // Modal backdrop click to close
    document.querySelector('.modal-backdrop').addEventListener('click', closeModal);
    
    // Provider change updates models
    document.getElementById('api-provider').addEventListener('change', updateModelOptions);
    
    // Send button
    document.getElementById('send-btn').addEventListener('click', analyzeAndExecute);
    
    // Preset selector
    document.getElementById('preset-select').addEventListener('change', (e) => {
        if (!state.currentModule) return;
        
        const preset = state.currentModule.presets[e.target.value];
        if (preset) {
            document.getElementById('user-input').value = preset.payload;
            
            // Run detection preview
            const { riskScore, flags, patterns } = detectInjection(preset.payload);
            updateRiskDisplay(riskScore, flags, patterns);
        }
    });
    
    // Clear logs button
    document.getElementById('clear-logs').addEventListener('click', () => {
        clearLogs();
        showToast('Logs cleared', 'info');
    });
    
    // Keyboard shortcut for send (Ctrl+Enter)
    document.getElementById('user-input').addEventListener('keydown', (e) => {
        if (e.ctrlKey && e.key === 'Enter') {
            analyzeAndExecute();
        }
    });
    
    // Real-time threat detection as user types
    document.getElementById('user-input').addEventListener('input', (e) => {
        const text = e.target.value;
        if (text.trim()) {
            const { riskScore, flags, patterns } = detectInjection(text);
            updateRiskDisplay(riskScore, flags, patterns);
        } else {
            // Reset to safe when empty
            updateRiskDisplay(0, [], []);
        }
    });
    
    // Nav link active state
    const navLinks = document.querySelectorAll('.nav-link');
    const sections = document.querySelectorAll('section[id]');
    
    window.addEventListener('scroll', () => {
        let current = '';
        sections.forEach(section => {
            const sectionTop = section.offsetTop;
            if (scrollY >= sectionTop - 200) {
                current = section.getAttribute('id');
            }
        });
        
        navLinks.forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('href') === `#${current}`) {
                link.classList.add('active');
            }
        });
    });

    // Initialize logs display
    updateLogsDisplay();
    
    // Backend mode toggle
    const backendToggle = document.getElementById('enable-backend');
    if (backendToggle) {
        backendToggle.checked = state.backendMode;
        backendToggle.addEventListener('change', (e) => {
            state.backendMode = e.target.checked;
            localStorage.setItem('securedai-backend-mode', state.backendMode);
            
            // Update UI
            updateBackendModeUI();
            
            if (state.backendMode) {
                showToast('Backend mode enabled - using CrewAI agents', 'success');
                checkBackendHealth().then(({ online, crewai }) => {
                    updateBackendStatus(online, crewai);
                    if (!online) {
                        showToast('Backend server not available. Start it with: cd backend && uvicorn main:app', 'warning');
                    }
                });
            } else {
                showToast('Direct mode enabled - using browser LLM calls', 'info');
            }
        });
    }
    
    // Agent type selector
    const agentTypeSelect = document.getElementById('agent-type-select');
    if (agentTypeSelect) {
        agentTypeSelect.addEventListener('change', (e) => {
            state.agentType = e.target.value;
        });
    }
    
    // Backend URL configuration
    const backendUrlInput = document.getElementById('backend-url-input');
    if (backendUrlInput) {
        backendUrlInput.value = CONFIG.backendUrl;
        backendUrlInput.addEventListener('change', (e) => {
            CONFIG.backendUrl = e.target.value;
            localStorage.setItem('securedai-backend-url', e.target.value);
            showToast('Backend URL updated', 'info');
            
            // Check new backend
            checkBackendHealth().then(({ online, crewai }) => {
                updateBackendStatus(online, crewai);
            });
        });
    }
    
    // Check backend health on startup if backend mode is enabled
    if (state.backendMode) {
        checkBackendHealth().then(({ online, crewai }) => {
            updateBackendStatus(online, crewai);
        });
    }
    
    // Initialize backend mode UI
    updateBackendModeUI();
    
    console.log('🛡️ SecuredAI Lab initialized');
    console.log('👋 Welcome! Set your API key to start experimenting.');
    if (state.backendMode) {
        console.log('🤖 Backend mode enabled - using CrewAI agents');
    }
});

function updateBackendModeUI() {
    const backendOptions = document.getElementById('backend-options');
    const directModeOptions = document.querySelector('.security-toggle');
    
    if (backendOptions) {
        backendOptions.style.display = state.backendMode ? 'flex' : 'none';
    }
    
    // Update button text based on mode
    const sendBtn = document.getElementById('send-btn');
    if (sendBtn) {
        const btnText = sendBtn.querySelector('span:last-child');
        if (btnText) {
            btnText.textContent = state.backendMode ? 'Run CrewAI Agent' : 'Analyze & Execute';
        }
    }
}

// Expose functions globally for onclick handlers
window.loadAttack = loadAttack;
window.closeModal = closeModal;
window.saveApiKey = saveApiKey;
window.toggleKeyVisibility = toggleKeyVisibility;
window.scrollToSection = scrollToSection;
window.switchModule = switchModule;
