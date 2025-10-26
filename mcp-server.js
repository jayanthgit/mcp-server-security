require('dotenv').config();
const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const jwt = require('jsonwebtoken'); // Using jsonwebtoken to decode

// --- LangChain & Gemini Imports ---
const { ChatGoogleGenerativeAI } = require('@langchain/google-genai');
const { initializeAgentExecutorWithOptions } = require('langchain/agents');
const { AIMessage, HumanMessage } = require("@langchain/core/messages");
const { MessagesPlaceholder } = require("@langchain/core/prompts");
const { DynamicTool } = require("langchain/tools");

if (!process.env.GEMINI_API_KEY) {
  console.error('[MCP-SERVER] GEMINI_API_KEY not found in .env file.');
  process.exit(1);
}

const PORT = process.env.PORT || 4000;
const AUTH_PORT = parseInt(PORT) + 1;
// Secret for signing M2M tokens. In production, this would be a secure, rotated key.
const MOCK_JWT_SECRET = 'a-very-secure-mock-secret-key-for-m2m';

// =============================================================================
// MOCK KNOWLEDGE SERVICE CLASS
// =============================================================================
class KnowledgeService {
  constructor() {
    this.MOCK_KB_DATA = [
      {
        id: "policy_001",
        title: "Phishing Incident Response",
        type: "playbook",
        keywords: "phishing, email, suspicious, report",
        content: "1. Do not click any links or open attachments. 2. Report the email using the 'Report Phishing' button in Outlook. 3. If you clicked a link, immediately disconnect from the network and call IT Support. 4. IT Support will analyze the email headers and quarantine the threat."
      },
      {
        id: "policy_002",
        title: "Data Classification Policy",
        type: "policy",
        keywords: "data, classification, confidential, public",
        content: "Data is classified into four categories: Public, Internal, Confidential, and Restricted. 'Confidential' data includes PII and financial information. 'Restricted' data is top-secret strategic information."
      },
      {
        id: "policy_003",
        title: "Production Outage Escalation Path",
        type: "playbook",
        keywords: "outage, production, escalation, breach",
        content: "1. P0 (Production Down): On-call engineer pages the SRE team lead and the Head of Engineering. 2. If a security breach is suspected, the CISO must be paged immediately. 3. The engineering team lead is the incident commander. 4. A war room is established. 5. Comms team handles external status updates."
      },
      {
        id: "policy_004",
        title: "System Compromise Playbook",
        type: "playbook",
        keywords: "compromise, hack, malware, breach, report",
        content: "1. Isolate the affected system from the network immediately. 2. Do not power off the system (to preserve volatile memory). 3. Escalate to the Security Incident Response Team (SIRT). 4. SIRT will begin forensics and identify the attack vector. 5. All credentials associated with the system must be rotated."
      },
      {
        id: "policy_005",
        title: "Cloud Misconfiguration Response",
        type: "policy",
        keywords: "cloud, aws, gcp, azure, misconfiguration, s3, public",
        content: "1. Any detection of a critical misconfiguration (e.g., public S3 bucket, open RDP port) must be treated as a P1 incident. 2. The Cloud Engineering team must remediate the finding within 15 minutes. 3. The Security team will scan for exposed data. 4. Post-incident, a root cause analysis (RCA) must be completed."
      }
    ];
    console.log('[KnowledgeService] Initialized.');
  }

  search(query) {
    const lowerQuery = query.toLowerCase();
    const results = this.MOCK_KB_DATA.filter(doc =>
      doc.keywords.toLowerCase().includes(lowerQuery) ||
      doc.title.toLowerCase().includes(lowerQuery)
    );
    console.log(`[KnowledgeService] Query: "${query}", Found: ${results.length} docs`);
    return results;
  }
}

// =============================================================================
// MOCK LOG SERVICE CLASS
// =============================================================================
class LogService {
  constructor() {
    this.MOCK_LOG_CSV_CONTENT = `timestamp,username,source_ip,reason
2025-10-26T10:00:00Z,admin,192.168.1.10,Bad password
2025-10-26T10:01:15Z,j.doe,10.5.2.120,Successful login
2025-10-26T10:02:30Z,s.sales,203.0.113.15,Successful login
2025-10-26T10:05:00Z,admin,192.168.1.10,Bad password
2025-10-26T10:05:10Z,admin,192.168.1.10,Bad password
2025-10-26T10:05:20Z,admin,192.168.1.10,Bad password
2025-10-26T10:05:30Z,admin,192.168.1.10,Account locked
2025-10-26T10:15:00Z,svc_backup,10.0.0.5,Successful login
2025-10-26T11:00:00Z,a.engineer,10.5.3.10,Successful login
2025-10-26T11:05:00Z,a.engineer,10.5.3.10,config_change(prod-db-1):set_firewall_rule(0.0.0.0/0)
2025-10-26T11:06:00Z,security_scanner,10.0.0.20,alert(prod-db-1):public_firewall_rule_detected
2025-10-26T11:10:00Z,a.engineer,10.5.3.10,config_change(prod-db-1):remove_firewall_rule(0.0.0.0/0)
2025-10-26T12:00:00Z,m.marketing,10.5.4.20,Successful login
2025-10-26T12:05:00Z,unknown_user,185.12.33.1,User not found
2025-10-26T12:05:15Z,unknown_user,185.12.33.1,User not found
2025-10-26T12:30:00Z,j.doe,10.5.2.120,malware_alert:trojan.downloader.xyz
2025-10-26T12:30:05Z,network_firewall,10.5.2.120,connection_blocked(url:evil-c2-server.com)
2025-10-26T12:31:00Z,it_admin,10.0.0.50,action:isolate_host(10.5.2.120)
2025-10-26T13:00:00Z,s.sales,203.0.113.15,Successful login
2025-10-26T13:15:00Z,prod-db-1,10.1.1.5,unusual_network_activity(outbound:45.12.3.100,port:4444)
2025-10-26T13:16:00Z,network_firewall,10.1.1.5,connection_blocked(ip:45.12.3.100)
2025-10-26T14:00:00Z,b.finance,10.5.5.10,Successful login
2025-10-26T14:30:00Z,dev-user-1,10.6.1.5,Successful login
2025-1to-26T15:00:00Z,admin,192.168.1.10,Bad password
2025-10-26T15:01:15Z,j.doe,10.5.2.120,Successful login
2025-10-26T15:02:30Z,s.sales,203.0.113.15,Successful login
2025-10-26T15:05:00Z,admin,192.168.1.10,Bad password
2025-10-26T15:05:10Z,admin,192.168.1.10,Bad password
2025-10-26T15:05:20Z,admin,192.168.1.10,Bad password
2025-10-26T15:05:30Z,admin,192.168.1.10,Account locked
2025-10-26T15:15:00Z,svc_backup,10.0.0.5,Successful login
2025-10-26T15:00:00Z,a.engineer,10.5.3.10,Successful login
2025-10-26T15:05:00Z,a.engineer,10.5.3.10,config_change(prod-db-1):set_firewall_rule(0.0.0.0/0)
2025-10-26T15:06:00Z,security_scanner,10.0.0.20,alert(prod-db-1):public_firewall_rule_detected
2025-10-26T15:10:00Z,a.engineer,10.5.3.10,config_change(prod-db-1):remove_firewall_rule(0.0.0.0/0)
2025-10-26T15:00:00Z,m.marketing,10.5.4.20,Successful login
2025-10-26T15:05:00Z,unknown_user,185.12.33.1,User not found
2025-10-26T15:05:15Z,unknown_user,185.12.33.1,User not found
2025-10-26T15:30:00Z,j.doe,10.5.2.120,malware_alert:trojan.downloader.xyz
2025-10-26T15:30:05Z,network_firewall,10.5.2.120,connection_blocked(url:evil-c2-server.com)
2025-10-26T15:31:00Z,it_admin,10.0.0.50,action:isolate_host(10.5.2.120)
2025-10-26T15:00:00Z,s.sales,203.0.113.15,Successful login
2m-10-26T16:15:00Z,prod-db-1,10.1.1.5,unusual_network_activity(outbound:45.12.3.100,port:4444)
2Such-10-26T16:16:00Z,network_firewall,10.1.1.5,connection_blocked(ip:45.12.3.100)
2025-10-26T16:00:00Z,b.finance,10.5.5.10,Successful login
2025-10-26T16:30:00Z,dev-user-1,10.6.1.5,Successful login
2025-10-26T16:20:00Z,prod-db-2,10.1.1.10,data_exfil_alert(policy:financial_data,bytes:10MB)
`;
    this.logEntries = this.MOCK_LOG_CSV_CONTENT.split('\n')
      .slice(1) // remove header
      .filter(line => line.trim() !== '')
      .map(line => {
        const [timestamp, username, source_ip, reason] = line.split(',');
        return { timestamp, username, source_ip, reason };
      });
    console.log(`[LogService] Initialized with ${this.logEntries.length} in-memory log entries.`);
  }

  queryLogs(input) {
    if (!input || typeof input !== 'string' || input.trim() === '') {
      return JSON.stringify({ error: "Invalid query input. Must be a non-empty string." });
    }

    const lowerInput = input.toLowerCase();
    let results = [];

    // The agent is responsible for sending a good keyword (e.g., "failed", "admin").
    results = this.logEntries.filter(entry => {
      const lineString = JSON.stringify(entry).toLowerCase();
      return lineString.includes(lowerInput);
    });

    console.log(`[LogService] Query: "${input}", Found: ${results.length} log entries`);

    if (results.length === 0) {
      return JSON.stringify({ message: "No matching log entries found." });
    }

    // Return a summary or all results
    return JSON.stringify({
      count: results.length,
      preview: results.slice(0, 10) // Return first 10 matches
    });
  }
}

// =============================================================================
// MOCK M2M AUTH SERVER CLASS
// =============================================================================
class MockAuthServer {
  constructor(port) {
    this.port = port;
    this.authApp = express();
    this.MOCK_M2M_CLIENTS = {
      'mcp-server-client-id': {
        secret: 'mcp-server-client-secret',
        grant: 'client_credentials',
        // Define the fine-grained scopes this client is allowed to request
        allowedScopes: ['logs:read', 'kb:read', 'logs:write', 'kb:write']
      }
    };

    this.authApp.use(bodyParser.urlencoded({ extended: true }));
    this.authApp.use(bodyParser.json());

    this.authApp.post('/oauth/token', (req, res) => {
      const { client_id, client_secret, grant_type } = req.body;
      const authHeader = req.headers.authorization;
      let clientIdFromHeader, clientSecretFromHeader;

      if (authHeader && authHeader.startsWith('Basic ')) {
        const basicAuth = Buffer.from(authHeader.split(' ')[1], 'base64').toString();
        [clientIdFromHeader, clientSecretFromHeader] = basicAuth.split(':');
      }

      const effectiveClientId = client_id || clientIdFromHeader;
      const effectiveClientSecret = client_secret || clientSecretFromHeader;

      const client = this.MOCK_M2M_CLIENTS[effectiveClientId];

      if (!client || client.secret !== effectiveClientSecret) {
        this.logAuthAuditEvent(`Failed auth: Invalid client_id or secret for ${effectiveClientId}`);
        return res.status(401).json({ error: 'invalid_client' });
      }

      if (grant_type !== 'client_credentials') {
        this.logAuthAuditEvent(`Failed auth: Invalid grant_type for ${effectiveClientId}`);
        return res.status(400).json({ error: 'unsupported_grant_type' });
      }

      // --- Scope Logic ---
      // For this mock, we'll just grant the client's pre-configured scopes.
      // A real server might let the client *request* a subset of its allowed scopes.
      const scopesToGrant = "logs:read kb:read"; // Hardcoding read-only scopes for this client

      const tokenPayload = {
        sub: effectiveClientId,
        scope: scopesToGrant, // Space-separated string of granted scopes
        aud: 'eos-services', // Audience
        iss: 'eos-mock-auth-server', // Issuer
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600, // Expires in 1 hour
      };

      // Sign the token
      const token = jwt.sign(tokenPayload, MOCK_JWT_SECRET);

      const responsePayload = {
        access_token: token,
        token_type: 'Bearer',
        expires_in: 3600,
        scope: scopesToGrant
      };

      this.logAuthAuditEvent(`Success auth: Token issued for ${effectiveClientId} with scopes: [${scopesToGrant}]`);
      res.json(responsePayload);
    });
  }

  logAuthAuditEvent(message) {
    console.log(`[AuthServer] LOG: ${message}`);
  }

  start() {
    this.authApp.listen(this.port, () => {
      console.log(`[AuthServer] Mock M2M OAuth server running on http://localhost:${this.port}`);
    });
  }
}

// =============================================================================
// MAIN MCP SERVER CLASS
// =============================================================================
class McpServer {
  constructor(port, knowledgeService, logService) {
    this.port = port;
    this.knowledgeService = knowledgeService;
    this.logService = logService;
    this.app = express();
    this.llm = null;
    this.chatHistory = [];
    this.indexTemplate = ''; // Will be set in setupTemplates
    this.m2mTokenPayload = null; // Will store the decoded JWT payload
    this.m2mTokenFetchInterval = null;

    this.setupMiddleware();
    this.setupTemplates();
    this.setupRoutes();
    this.setupAgent();
  }

  setupMiddleware() {
    this.app.use(bodyParser.json());
    this.app.use(bodyParser.urlencoded({ extended: true }));

    this.app.use((req, res, next) => {
      console.log(`[MCP-SERVER] ${new Date().toISOString()} - ${req.method} ${req.url}`);
      next();
    });
  }

  setupTemplates() {
    this.indexTemplate = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Eos Security Assistant</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <style>
            body { font-family: 'Inter', sans-serif; }
            .chat-bubble-user { background-color: #3b82f6; color: white; }
            .chat-bubble-ai { background-color: #4b5563; color: white; }
            ::-webkit-scrollbar { width: 6px; }
            ::-webkit-scrollbar-thumb { background: #4b5563; border-radius: 3px; }
        </style>
    </head>
    <body class="bg-gray-900 text-gray-100 flex flex-col h-screen">
        <header class="bg-gray-800 p-4 shadow-md">
            <h1 class="text-xl font-semibold">Eos Security Assistant</h1>
        </header>

        <main id="chat-container" class="flex-1 overflow-y-auto p-4 space-y-4">
            <!-- Chat messages will be injected here -->
            <div class="chat-bubble-ai p-3 rounded-lg max-w-xl">
                Hello! I am the Eos Security Assistant. How can I help you with policies or logs today?
            </div>
        </main>

        <footer class="bg-gray-800 p-4">
            <form id="chat-form" class="flex space-x-2">
                <input type="text" id="chat-input" class="flex-1 p-3 bg-gray-700 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" placeholder="Ask about security policies or logs..." autocomplete="off">
                <button type="submit" id="send-button" class="bg-blue-600 hover:bg-blue-700 text-white font-semibold p-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                    Send
                </button>
            </form>
        </footer>

        <script>
            const chatForm = document.getElementById('chat-form');
            const chatInput = document.getElementById('chat-input');
            const chatContainer = document.getElementById('chat-container');
            const sendButton = document.getElementById('send-button');

            chatForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                const query = chatInput.value.trim();
                if (!query) return;

                appendMessage(query, 'user');
                chatInput.value = '';
                sendButton.disabled = true;
                sendButton.textContent = '...';

                try {
                    const response = await fetch('/chat', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ query })
                    });

                    if (!response.ok) {
                        const err = await response.json();
                        throw new Error(err.error || 'Server error');
                    }

                    const data = await response.json();
                    appendMessage(data.response, 'ai');

                } catch (error) {
                    appendMessage('Error: ' + error.message, 'ai');
                } finally {
                    sendButton.disabled = false;
                    sendButton.textContent = 'Send';
                }
            });

            function appendMessage(text, sender) {
                const bubble = document.createElement('div');
                bubble.classList.add('p-3', 'rounded-lg', 'max-w-xl', 'break-words');
                bubble.classList.add(sender === 'user' ? 'chat-bubble-user' : 'chat-bubble-ai');
                bubble.classList.add(sender === 'user' ? 'self-end' : 'self-start');
                
                // Simple text formatting
                text = text.replace(/\\n/g, '<br>');
                bubble.innerHTML = text;
                
                chatContainer.appendChild(bubble);
                chatContainer.scrollTop = chatContainer.scrollHeight;
            }
        </script>
    </body>
    </html>
    `;
  }

  setupRoutes() {
    this.app.get('/', (req, res) => {
      // For simplicity, render template directly
      res.send(this.indexTemplate);
    });

    this.app.post('/chat', (req, res) => {
      this.handleChat(req, res);
    });
  }

  setupAgent() {
    this.llm = new ChatGoogleGenerativeAI({
      apiKey: process.env.GEMINI_API_KEY,
      modelName: "gemini-2.0-flash",
      temperature: 0,
    });

    // --- Agent Tools (bound to service instances) ---
    const knowledgeBaseTool = new DynamicTool({
      name: "search_knowledge_base",
      description: `Searches the company knowledge base for security policies, playbooks, and other documents. Input MUST be a single, relevant keyword (e.g., 'phishing', 'outage', 'data'). Do NOT send a full sentence.`,
      func: async (input) => {
        const user = this.getMockUser();
        const requiredScope = 'kb:read';

        // M2M Scope Check
        if (!this.hasScope(requiredScope)) {
          this.logAuditEvent({
            type: 'TOKEN_SCOPE_DENIED',
            tool: 'search_knowledge_base',
            requiredScope,
            tokenScopes: this.m2mTokenPayload?.scope || 'none',
            userId: user.id
          });
          return `Access Denied: Server does not have permission to read knowledge base.`;
        }

        // RBAC Check: All roles can access the knowledge base
        try {
          const result = this.knowledgeService.search(input);
          this.logAuditEvent({ type: 'TOOL_USE', tool: 'search_knowledge_base', input, userRole: user.role, userId: user.id });
          return JSON.stringify(result);
        } catch (error) {
          return `Error searching knowledge base: ${error.message}`;
        }
      }
    });

    const logQueryTool = new DynamicTool({
      name: "query_logs",
      description: `Queries the company log files. Input MUST be a single, relevant keyword (e.g., 'Bad password', 'admin', '192.168.1.10', 'malware'). Do NOT send a full sentence.`,
      func: async (input) => {
        const user = this.getMockUser();
        const requiredScope = 'logs:read';

        // 1. User RBAC Check
        if (user.role !== 'security_analyst') {
          this.logAuditEvent({ type: 'USER_RBAC_DENIED', tool: 'query_logs', userRole: user.role, userId: user.id });
          return "Access Denied: You do not have permission to query logs.";
        }

        // 2. M2M Scope Check
        if (!this.hasScope(requiredScope)) {
          this.logAuditEvent({
            type: 'TOKEN_SCOPE_DENIED',
            tool: 'query_logs',
            requiredScope,
            tokenScopes: this.m2mTokenPayload?.scope || 'none',
            userId: user.id
          });
          return `Access Denied: Server does not have permission to read logs.`;
        }

        // All checks passed
        try {
          const result = this.logService.queryLogs(input);
          this.logAuditEvent({ type: 'TOOL_USE', tool: 'query_logs', input, userRole: user.role, userId: user.id });
          return JSON.stringify(result);
        } catch (error) {
          return `Error querying logs: ${error.message}`;
        }
      }
    });

    this.tools = [knowledgeBaseTool, logQueryTool];
  }

  getMockUser() {
    // Hardcoded user for simplified RBAC check
    return {
      id: 'sec_analyst_01',
      name: 'Security Analyst',
      role: 'security_analyst'
    };
  }

  logAuditEvent(event) {
    // In a real app, this would write to a secure, append-only log file or stream
    console.log(`[MCP-SERVER] AUDIT: ${JSON.stringify(event)}`);
  }

  isPromptInjection(query) {
    const injectionKeywords = [
      'ignore previous instructions',
      'disregard all prior directives',
      'system prompt:',
      'your new instructions are'
    ];
    const lowerCaseQuery = query.toLowerCase().replace(/[\W_]+/g, ' ').trim();
    return injectionKeywords.some(keyword => lowerCaseQuery.includes(keyword));
  }

  hasScope(requiredScope) {
    if (!this.m2mTokenPayload || !this.m2mTokenPayload.scope) {
      console.warn('[MCP-SERVER] M2M token not found or has no scopes.');
      return false;
    }
    const grantedScopes = this.m2mTokenPayload.scope.split(' ');
    return grantedScopes.includes(requiredScope);
  }

  async handleChat(req, res) {
    const query = req.body.query;
    const user = this.getMockUser(); // Get hardcoded user

    this.logAuditEvent({ type: 'QUERY', query, userId: user.id, userRole: user.role });

    // Check if M2M token is valid before proceeding
    if (!this.m2mTokenPayload) {
      this.logAuditEvent({ type: 'ERROR', error: 'Server M2M token is not available.', userId: user.id });
      return res.status(500).json({ error: 'Server is not ready, please try again soon.' });
    }

    if (this.isPromptInjection(query)) {
      this.logAuditEvent({ type: 'PROMPT_INJECTION_DETECTED', query, userId: user.id });
      return res.status(400).json({ response: "I'm sorry, I can't process that request." });
    }

    try {
      const executor = await initializeAgentExecutorWithOptions(this.tools, this.llm, {
        agentType: "chat-conversational-react-description",
        verbose: true,
        agentArgs: {
          systemMessage: `You are a helpful Eos Security Assistant.
          Your user is '${user.name}' and their role is '${user.role}'.
          Be concise and helpful.
          
          VERY IMPORTANT: You MUST NOT pass a full sentence to any tool.
          You MUST extract the single most relevant keyword.
          
          Examples for 'query_logs':
          - User: 'show me all failed logins' -> call query_logs('Bad password')
          - User: 'any failed passwords?' -> call query_logs('Bad password')
          - User: 'what happened with admin' -> call query_logs('admin')
          - User: 'any malware alerts?' -> call query_logs('malware')
          - User: 'activity for ip 185.12.33.1' -> call query_logs('185.12.33.1')

          Examples for 'search_knowledge_base':
          - User: 'how do I report a phishing email?' -> call search_knowledge_base('phishing')
          - User: 'what to do for system compromise?' -> call search_knowledge_base('compromise')
          - User: 'what is the data classification policy?' -> call search_knowledge_base('data')
          - User: 'how to report a security incident?' -> call search_knowledge_base('phishing') or search_knowledge_base('compromise')

          If you don't have a tool to answer, state that you do not have the capability.`
        }
      });

      const result = await executor.invoke({
        input: query,
        chat_history: this.chatHistory
      });

      const output = result.output;

      this.chatHistory.push(new HumanMessage(query));
      this.chatHistory.push(new AIMessage(output));

      this.logAuditEvent({ type: 'RESPONSE', userId: user.id, userRole: user.role, response: output });
      res.json({ response: output });

    } catch (error) {
      console.error('[MCP-SERVER] Error during agent execution:', error);
      this.logAuditEvent({ type: 'ERROR', error: error.message, userId: user.id });
      res.status(500).json({ error: 'An error occurred during agent execution.' });
    }
  }

  async fetchM2MToken() {
    try {
      const response = await fetch(`http://localhost:${AUTH_PORT}/oauth/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          'client_id': 'mcp-server-client-id',
          'client_secret': 'mcp-server-client-secret',
          'grant_type': 'client_credentials'
        })
      });

      if (!response.ok) {
        throw new Error(`Auth server responded with ${response.status}`);
      }

      const data = await response.json();
      const accessToken = data.access_token;

      // Decode the JWT to store its payload (which includes scopes)
      // Note: In a real app, you'd verify the signature first
      this.m2mTokenPayload = jwt.decode(accessToken);

      if (!this.m2mTokenPayload) {
        throw new Error('Failed to decode M2M token.');
      }

      console.log('[MCP-SERVER] Successfully fetched and decoded M2M token. Scopes:', this.m2mTokenPayload.scope);

      // Schedule a refresh well before it expires
      const expiresIn = this.m2mTokenPayload.exp - this.m2mTokenPayload.iat;
      const refreshDelay = (expiresIn * 0.9) * 1000; // 90% of expiry

      // Clear old interval if it exists
      if (this.m2mTokenFetchInterval) {
        clearInterval(this.m2mTokenFetchInterval);
      }

      this.m2mTokenFetchInterval = setTimeout(() => this.fetchM2MToken(), refreshDelay);

    } catch (error) {
      console.error('[MCP-SERVER] Failed to get M2M token:', error.message);
      this.m2mTokenPayload = null; // Invalidate token on failure
      // Retry after a delay
      if (this.m2mTokenFetchInterval) {
        clearInterval(this.m2mTokenFetchInterval);
      }
      this.m2mTokenFetchInterval = setTimeout(() => this.fetchM2MToken(), 30000); // Retry in 30 seconds
    }
  }

  start() {
    this.app.listen(this.port, () => {
      console.log(`[MCP-SERVER] Main server running on http://localhost:${this.port}`);
    });
    // Get the first M2M token
    this.fetchM2MToken();
  }
}

// =============================================================================
// SERVER STARTUP
// =============================================================================
async function run() {
  // 1. Initialize Services
  const knowledgeService = new KnowledgeService();
  const logService = new LogService();

  // 2. Start the Mock M2M Auth Server
  const authServer = new MockAuthServer(AUTH_PORT);
  authServer.start();

  // 3. Start the Main MCP Server
  const mcpServer = new McpServer(PORT, knowledgeService, logService);
  mcpServer.start();
}

run().catch(console.error);
