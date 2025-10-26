/*
================================================================================
MCP-SERVER (ALL-IN-ONE)
Founding Engineer Evaluation Prototype
================================================================================

This single file contains the entire Node.js application, including:
1.  Main Express Server (Chatbot UI & API)
    -   Serves a server-rendered EJS chatbot UI.
    -   Handles user login with session-based authentication.
    -   Implements Role-Based Access Control (RBAC) for tools.
    -   Provides a `/chat` endpoint for the agentic AI.
    -   Includes detailed audit logging for all user actions.
2.  Mock M2M Auth Server
    -   Runs on a separate port (PORT + 1).
    -   Simulates an OAuth 2.0 client credentials flow.
    -   Issues mock JWTs and maintains its own audit log.
3.  Mock Services (In-File)
    -   KnowledgeService: In-memory JSON database for security policies.
    -   LogService: Reads from a mock CSV file (`failed_logins.csv`).
4.  Mock Data Generation
    -   Creates a `logs` directory on startup.
    -   Generates `failed_logins.csv`, `audit.log`, and `auth_audit.log`.

--------------------------------------------------------------------------------
SYSTEM DESIGN OVERVIEW
--------------------------------------------------------------------------------

+----------------------+   (Browser)
|      User (UI)       |
| (Sales / Security)   |
+----------------------+
       |
       | (HTTPS: 4000)
       | 1. /login (POST)
       | 2. / (GET)
       | 3. /chat (POST)
       v
+--------------------------------------------------------------------------+
| MAIN MCP SERVER (Node.js / Express @ Port 4000)                          |
|                                                                          |
|  +------------------+  +------------------+  +-------------------------+ |
|  |  Login/Session   |  |  Chat Endpoint   |  |   EJS Render Engine     | |
|  |  (cookie-parser, |  |  (/chat)         |  |   (In-memory templates) | |
|  | express-session) |  |                  |  +-------------------------+ |
|  +------------------+  +------------------+                              |
|          |                     |                                         |
|          |                     | 4. RBAC Check                           |
|          |                     | (User Role in Session)                  |
|          v                     v                                         |
|  +------------------+  +-----------------------------------------------+ |
|  |   Audit Logger   |  |  LangChain Agent Executor (Gemini)            | |
|  | (writes to       |  |                                               | |
|  |  audit.log)      |  |  +------------------+  +--------------------+ | |
|  +------------------+  |  | knowledgeBaseTool|  | logQueryTool       | | |
|                        |  | (All Roles)      |  | (Security Role ONLY)| | |
|                        |  +------------------+  +--------------------+ | |
|                        |         |                     |                 | |
|                        |         | 5a.                 | 5b.             | |
|                        |         v                     v                 | |
|                        |  +------------------+  +--------------------+ | |
|                        |  | Mock Knowledge   |  | Mock Log Service   | | |
|                        |  | Service (In-mem  |  | (Reads             | | |
|                        |  | JSON)            |  | failed_logins.csv) | | |
|                        |  +------------------+  +--------------------+ | |
|                        +-----------------------------------------------+ |
|                                                                          |
| 7. Startup: "M2M Auth" |                                                  |
| (Fetches token from     |                                                  |
|  Mock Auth Server)      |                                                  |
+--------------------------------------------------------------------------+
       |
       | (HTTP: 4001)
       | 7. POST /oauth/token
       v
+--------------------------------------------------------------------------+
| MOCK M2M AUTH SERVER (Node.js / Express @ Port 4001)                     |
|                                                                          |
|  +------------------+  +------------------+  +-------------------------+ |
|  | /oauth/token     |  |  Mock Client DB  |  |   Auth Audit Logger     | |
|  | Endpoint (POST)  |  |  (client_id,     |  |   (writes to            | |
|  |                  |  |   client_secret) |  |    auth_audit.log)      | |
|  +------------------+  +------------------+  +-------------------------+ |
+--------------------------------------------------------------------------+

--------------------------------------------------------------------------------
*/

require('dotenv').config();
const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const fs = require('fs');
const ejs = require('ejs');
const cookieParser = require('cookie-parser');
const session = require('express-session');

// --- LangChain & Gemini Imports ---
const { ChatGoogleGenerativeAI } = require('@langchain/google-genai');
const { initializeAgentExecutorWithOptions } = require('langchain/agents');
const { AIMessage, HumanMessage } = require("@langchain/core/messages");
const { DynamicTool } = require("langchain/tools");

// --- Environment Check ---
if (!process.env.GEMINI_API_KEY) {
  console.error('[MCP-SERVER] GEMINI_API_KEY not found in environment variables. Please set it in the .env file.');
  process.exit(1);
}

// --- Constants ---
const PORT = process.env.PORT || 4000;
const AUTH_PORT = parseInt(PORT) + 1;
const LOG_DIR = path.join(__dirname, 'logs');
const AUDIT_LOG_FILE = path.join(LOG_DIR, 'audit.log');
const AUTH_AUDIT_LOG_FILE = path.join(LOG_DIR, 'auth_audit.log');
const MOCK_LOGS_FILE = path.join(LOG_DIR, 'failed_logins.csv');

// =============================================================================
// MOCK DATA & FILE GENERATION
// =============================================================================

// --- Mock User Database (for UI Login) ---
const MOCK_USERS = {
  'j.analyst': {
    id: 'j.analyst',
    name: 'Jane Analyst',
    role: 'security_analyst',
    password: 'password123' // Plain text for demo purposes ONLY.
  },
  's.sales': {
    id: 's.sales',
    name: 'Sam Sales',
    role: 'sales_employee',
    password: 'password123'
  }
};

// --- Mock Knowledge Base (for RAG) ---
const KNOWLEDGE_BASE = [
  {
    id: 'policy-001',
    type: 'policy',
    keywords: ['phishing', 'email', 'report', 'handle'],
    title: 'Phishing Response Policy',
    content: "If you suspect an email is a phishing attempt: 1. Do not click any links or open attachments. 2. Report the email using the 'Report Phishing' button in Outlook. 3. If you accidentally clicked a link, disconnect from the network immediately and call the IT Help Desk at x500."
  },
  {
    id: 'playbook-001',
    type: 'playbook',
    keywords: ['production outage', 'security breach', 'escalation'],
    title: 'Production Breach Escalation Path',
    content: "For a production outage caused by a suspected security breach: 1. The on-call engineer pages the Head of SRE and the CISO immediately. 2. A war room is established (Zoom link: zoom.us/j/warroom). 3. The SRE team focuses on containment (e.g., network isolation). 4. The Security team begins investigation. 5. Do not communicate externally without CISO approval."
  },
  {
    id: 'policy-002',
    type: 'policy',
    keywords: ['password', 'policy', 'reset', 'mfa'],
    title: 'Password & Authentication Policy',
    content: 'All user passwords must be reset every 90 days. Passwords must be at least 14 characters long and include an uppercase letter, a lowercase letter, a number, and a special character. Multi-Factor Authentication (MFA) is required for all external-facing systems.'
  }
];

// --- Mock Log File Data (for LogService) ---
const MOCK_LOG_CSV_CONTENT = `timestamp,username,source_ip,reason
2025-10-26T10:00:00Z,admin,192.168.1.10,Bad password
2025-10-26T10:01:00Z,j.analyst,203.0.113.25,Bad password
2025-10-26T10:02:00Z,root,198.51.100.1,User not found
2025-10-26T10:05:00Z,admin,192.168.1.10,Bad password
2025-10-26T10:06:00Z,s.sales,203.0.113.50,Bad password
2025-10-26T10:15:00Z,guest,172.16.0.5,User disabled
2025-10-26T10:20:00Z,j.analyst,10.0.0.2,Successful login
2025-10-26T10:21:00Z,s.sales,10.0.0.3,Successful login
2025-10-26T11:00:00Z,admin,198.51.100.1,Bad password
`;

// --- Mock M2M Client Credentials ---
const MOCK_M2M_CLIENTS = {
  'mcp_service_client_id': {
    secret: 'mcp_service_client_secret_xyz789',
    grant_type: 'client_credentials',
    audience: 'urn:mcp-internal-api'
  }
};

/**
 * Initializes mock data files and directories on startup.
 */
function initializeMockData() {
  try {
    // 1. Create 'logs' directory if it doesn't exist
    if (!fs.existsSync(LOG_DIR)) {
      fs.mkdirSync(LOG_DIR);
      console.log(`[MCP-SERVER] Created directory: ${LOG_DIR}`);
    }

    // 2. Create mock 'failed_logins.csv' if it doesn't exist
    if (!fs.existsSync(MOCK_LOGS_FILE)) {
      fs.writeFileSync(MOCK_LOGS_FILE, MOCK_LOG_CSV_CONTENT);
      console.log(`[MCP-SERVER] Created mock log file: ${MOCK_LOGS_FILE}`);
    }

    // 3. Ensure log files are present (even if empty)
    if (!fs.existsSync(AUDIT_LOG_FILE)) {
      fs.writeFileSync(AUDIT_LOG_FILE, '');
    }
    if (!fs.existsSync(AUTH_AUDIT_LOG_FILE)) {
      fs.writeFileSync(AUTH_AUDIT_LOG_FILE, '');
    }

  } catch (error) {
    console.error(`[MCP-SERVER] Failed to initialize mock data: ${error.message}`);
    process.exit(1);
  }
}

// =============================================================================
// MOCK SERVICES (IN-FILE)
// =============================================================================

// --- Mock Knowledge Service ---

/**
 * Searches the in-memory knowledge base.
 * @param {string} input - The user's search query.
 * @returns {Promise<string>} A JSON string of matching documents.
 */
async function searchKnowledgeBase(input) {
  console.log(`[KnowledgeService] Searching for: ${input}`);
  const searchTerms = input.toLowerCase().split(/\s+/);
  const results = KNOWLEDGE_BASE.filter(doc => {
    const combinedText = `${doc.title} ${doc.keywords.join(' ')} ${doc.content}`.toLowerCase();
    return searchTerms.some(term => combinedText.includes(term));
  });

  if (results.length === 0) {
    return JSON.stringify({
      found: 0,
      message: "No relevant documents found in the knowledge base."
    });
  }

  // Return summaries to save on tokens
  const summaries = results.map(doc => ({
    title: doc.title,
    type: doc.type,
    contentSummary: doc.content.substring(0, 150) + '...'
  }));

  return JSON.stringify({
    found: summaries.length,
    results: summaries
  });
}

// --- Mock Log Query Service ---

/**
 * Queries the mock CSV log file.
 * @param {string} input - The user's query (e.g., "failed logins", "admin").
 * @returns {Promise<string>} A JSON string of log query results.
 */
async function queryLogs(input) {
  console.log(`[LogService] Querying logs for: ${input}`);
  try {
    const data = await fs.promises.readFile(MOCK_LOGS_FILE, 'utf8');
    const lines = data.split('\n');
    const headers = lines[0].split(',');

    const searchTerm = input.toLowerCase();

    let results = [];
    // Start from 1 to skip header
    for (let i = 1; i < lines.length; i++) {
      if (lines[i].toLowerCase().includes(searchTerm)) {
        const values = lines[i].split(',');
        let entry = {};
        headers.forEach((header, index) => {
          entry[header.trim()] = values[index] ? values[index].trim() : '';
        });
        results.push(entry);
      }
    }

    if (results.length === 0) {
      return JSON.stringify({
        found: 0,
        message: "No matching log entries found."
      });
    }

    // Simulate aggregation for "failed logins"
    if (searchTerm.includes('failed') || searchTerm.includes('bad password')) {
      const failed = results.filter(r => r.reason && r.reason.toLowerCase() !== 'successful login');
      return JSON.stringify({
        found: failed.length,
        message: `Found ${failed.length} log entries matching '${input}'.`,
        results: failed.slice(0, 10) // Return max 10 to save tokens
      });
    }

    return JSON.stringify({
      found: results.length,
      message: `Found ${results.length} log entries matching '${input}'.`,
      results: results.slice(0, 10) // Return max 10
    });

  } catch (error) {
    console.error(`[LogService] Error reading log file: ${error.message}`);
    return JSON.stringify({ error: "Failed to read log file." });
  }
}

// =============================================================================
// MAIN MCP SERVER (PORT 4000)
// =============================================================================

const app = express();

// --- Main Audit Logging ---
const auditLogStream = fs.createWriteStream(AUDIT_LOG_FILE, { flags: 'a' });

/**
 * Logs an audit event to the main audit.log file.
 * @param {object} event - The event object to log.
 */
function logAuditEvent(event) {
  try {
    const logEntry = `[${new Date().toISOString()}] ${JSON.stringify(event)}
`;
    auditLogStream.write(logEntry);
  } catch (error) {
    console.error(`[MCP-SERVER] Failed to write to audit log: ${error.message}`);
  }
}

// --- EJS Templates (In-memory) ---

const loginTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP Assistant - Login</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { font-family: 'Inter', sans-serif; }
    </style>
</head>
<body class="bg-gray-900 text-gray-100 flex items-center justify-center min-h-screen">
    <div class="w-full max-w-md bg-gray-800 p-8 rounded-lg shadow-2xl">
        <h1 class="text-3xl font-bold text-center text-blue-400 mb-2">Eos Security Assistant</h1>
        <p class="text-center text-gray-400 mb-6">Please sign in to continue</p>
        
        <% if (error) { %>
            <div class="bg-red-800 border border-red-600 text-red-100 px-4 py-3 rounded-md relative mb-4" role="alert">
                <span class="block sm:inline"><%= error %></span>
            </div>
        <% } %>

        <form action="/login" method="POST">
            <div class="mb-4">
                <label for="username" class="block text-sm font-medium text-gray-300 mb-2">Username</label>
                <input type="text" id="username" name="username" required
                       class="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500">
            </div>
            <div class="mb-6">
                <label for="password" class="block text-sm font-medium text-gray-300 mb-2">Password</label>
                <input type="password" id="password" name="password" required
                       class="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500">
            </div>
            <button type="submit"
                    class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded-md transition duration-300 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-opacity-50">
                Sign In
            </button>
        </form>
        <div class="mt-6 text-xs text-gray-500 text-center">
            <p class="font-bold">Demo Logins (password: password123)</p>
            <p>Security Analyst: <span class="font-mono">j.analyst</span></p>
            <p>Sales Employee: <span class="font-mono">s.sales</span></p>
        </div>
    </div>
</body>
</html>
`;

const indexTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP Security Assistant</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { font-family: 'Inter', sans-serif; }
        #chatbox { height: calc(100vh - 200px); }
        .user-msg { background-color: #2563EB; color: white; }
        .ai-msg { background-color: #374151; color: white; }
        .tool-call { 
          font-family: monospace; 
          font-size: 0.8rem;
          background-color: #1F2937;
          border: 1px solid #4B5563;
          padding: 8px;
          border-radius: 4px;
          margin-top: 8px;
          white-space: pre-wrap;
          word-break: break-all;
        }
    </style>
</head>
<body class="bg-gray-900 text-gray-100 flex flex-col h-screen">

    <header class="bg-gray-800 shadow-md p-4 flex justify-between items-center">
        <h1 class="text-xl font-bold text-blue-400">Eos Security Assistant</h1>
        <div class="text-right">
            <p class="text-sm">Welcome, <span class="font-medium"><%= user.name %></span></p>
            <p class="text-xs text-gray-400">Role: <span class="font-medium capitalize"><%= user.role.replace('_', ' ') %></span></p>
            <a href="/logout" class="text-xs text-blue-400 hover:underline">Logout</a>
        </div>
    </header>

    <main id="chatbox" class="flex-1 overflow-y-auto p-4 space-y-4">
        <!-- Chat messages will be appended here -->
        <div class="ai-msg p-4 rounded-lg max-w-xl shadow-md">
            Hello <%= user.name %>. I am the Eos Security Assistant. 
            <% if (user.role === 'security_analyst') { %>
                You have full access, including policies and log queries.
            <% } else { %>
                You have access to our security knowledge base.
            <% } %>
            How can I help you?
        </div>
    </main>

    <footer class="bg-gray-800 p-4">
        <form id="chat-form" class="flex items-center space-x-2">
            <input type="text" id="query-input" placeholder="Ask about security policies or logs..."
                   class="flex-1 px-4 py-2 bg-gray-700 border border-gray-600 rounded-full text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
                   autocomplete="off">
            <button type="submit" id="send-button"
                    class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded-full transition duration-300 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-opacity-50">
                Send
            </button>
        </form>
    </footer>

    <script>
        const chatForm = document.getElementById('chat-form');
        const queryInput = document.getElementById('query-input');
        const sendButton = document.getElementById('send-button');
        const chatbox = document.getElementById('chatbox');

        chatForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const query = queryInput.value.trim();
            if (!query) return;

            // Disable form and add user message
            queryInput.value = '';
            queryInput.disabled = true;
            sendButton.disabled = true;
            sendButton.textContent = '...';
            addMessage(query, 'user');

            try {
                const response = await fetch('/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ query: query })
                });

                if (!response.ok) {
                    const errorData = await response.json();
                    throw new Error(errorData.response || 'An unknown error occurred.');
                }

                const data = await response.json();
                addMessage(data.response, 'ai');

            } catch (error) {
                addMessage('Error: ' + error.message, 'ai', 'bg-red-800');
            } finally {
                // Re-enable form
                queryInput.disabled = false;
                sendButton.disabled = false;
                sendButton.textContent = 'Send';
                queryInput.focus();
            }
        });

        function addMessage(text, sender, extraClasses = '') {
            const msgDiv = document.createElement('div');
            const alignment = sender === 'user' ? 'ml-auto bg-blue-600' : 'mr-auto bg-gray-700';
            msgDiv.className = \`p-4 rounded-lg max-w-xl shadow-md \${alignment} \${extraClasses}\`;
            
            // Sanitize text before setting innerHTML (simple version)
            let safeText = text.replace(/</g, "&lt;").replace(/>/g, "&gt;");
            
            // Format agent tool calls for readability
            safeText = safeText.replace(/\\n/g, '<br>');
            safeText = safeText.replace(
              /Invoking tool: (.*?) with input: (.*?)(?=<br>|<|$)/g,
              '<div class="tool-call"><strong>Tool:</strong> $1<br><strong>Input:</strong> $2</div>'
            );
            safeText = safeText.replace(
              /Tool (.*?) returned: (.*?)(?=<br>|<|$)/g,
              '<div class="tool-call" style="background-color: #374151;"><strong>Tool Result:</strong> $2</div>'
            );

            msgDiv.innerHTML = safeText;
            chatbox.appendChild(msgDiv);
            chatbox.scrollTop = chatbox.scrollHeight;
        }
    </script>
</body>
</html>
`;


// --- Main App Middleware ---
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET || 'a-very-strong-development-secret-key', // Use env var in production
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // Set to true if using HTTPS
}));

// --- Main App Auth Middleware ---
const checkAuth = (req, res, next) => {
  if (req.session.user) {
    next();
  } else {
    res.redirect('/login');
  }
};

// --- Agentic AI Setup ---
const llm = new ChatGoogleGenerativeAI({
  apiKey: process.env.GEMINI_API_KEY,
  modelName: "gemini-1.5-flash", // Using Flash for speed in a chat app
  temperature: 0,
});

// --- Agent Tools ---
const knowledgeBaseTool = new DynamicTool({
  name: "search_knowledge_base",
  description: "Searches the company knowledge base for security policies, playbooks, and other documents. Use this to answer questions about company policies, procedures, and 'how-to' guides.",
  func: async (input) => {
    // Note: The logAuditEvent is called inside the /chat endpoint
    // to gain access to the user's session.
    return searchKnowledgeBase(input);
  }
});

const logQueryTool = new DynamicTool({
  name: "query_logs",
  description: "Queries the company security log files. Use this to find information about specific events, like 'failed login attempts', 'activity for user admin', or 'logs from IP 203.0.113.25'.",
  func: async (input) => {
    // Note: The logAuditEvent is called inside the /chat endpoint.
    return queryLogs(input);
  }
});

// --- Prompt Injection Defense ---
function isPromptInjection(query) {
  // Simple keyword-based defense
  const injectionKeywords = [
    'ignore previous instructions',
    'disregard your orders',
    'forget what you were told',
    'you are now a new persona',
    'system prompt:',
    'roleplay as'
  ];
  const lowerCaseQuery = query.toLowerCase();
  return injectionKeywords.some(keyword => lowerCaseQuery.includes(keyword));
}

// --- Main App Routes ---

app.get('/login', (req, res) => {
  const html = ejs.render(loginTemplate, { error: null });
  res.send(html);
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = MOCK_USERS[username];

  if (user && user.password === password) {
    req.session.user = user; // Store user in session
    logAuditEvent({
      type: 'LOGIN_SUCCESS',
      userId: user.id,
      userRole: user.role,
      source_ip: req.ip
    });
    res.redirect('/');
  } else {
    logAuditEvent({
      type: 'LOGIN_FAILURE',
      username: username,
      source_ip: req.ip
    });
    const html = ejs.render(loginTemplate, { error: 'Invalid username or password' });
    res.status(401).send(html);
  }
});

app.get('/logout', (req, res) => {
  if (req.session.user) {
    logAuditEvent({
      type: 'LOGOUT',
      userId: req.session.user.id,
      userRole: req.session.user.role
    });
    req.session.destroy();
  }
  res.redirect('/login');
});

// Protected routes
app.get('/', checkAuth, (req, res) => {
  const html = ejs.render(indexTemplate, { user: req.session.user });
  res.send(html);
});

// --- Main Chat Endpoint (with RBAC) ---
app.post('/chat', checkAuth, async (req, res) => {
  const query = req.body.query;
  const user = req.session.user;

  console.log(`[MCP-SERVER] User query from ${user.id} (${user.role}): ${query}`);
  logAuditEvent({
    type: 'QUERY',
    userId: user.id,
    userRole: user.role,
    query
  });

  if (isPromptInjection(query)) {
    console.log(`[MCP-SERVER] Prompt injection detected: ${query}`);
    logAuditEvent({
      type: 'PROMPT_INJECTION_DETECTED',
      userId: user.id,
      userRole: user.role,
      query
    });
    return res.status(400).json({ response: "I'm sorry, that request appears to be malicious and has been blocked." });
  }

  //
  // --- RBAC IMPLEMENTATION ---
  // Dynamically assemble tools based on user's role
  //
  const tools = [knowledgeBaseTool]; // All users get the knowledge base
  if (user.role === 'security_analyst') {
    tools.push(logQueryTool); // Only 'security_analyst' gets the log tool
  }

  // We need to wrap the tool functions to include our audit logging
  // This is a more robust way to capture tool calls.
  const toolsForAgent = tools.map(tool => {
    return new DynamicTool({
      ...tool,
      func: async (input) => {
        logAuditEvent({
          type: 'AGENT_TOOL_CALL',
          userId: user.id,
          userRole: user.role,
          tool: tool.name,
          input: input
        });

        const result = await tool.func(input);

        logAuditEvent({
          type: 'AGENT_TOOL_RESULT',
          userId: user.id,
          userRole: user.role,
          tool: tool.name,
          result: result.substring(0, 200) + '...' // Log truncated result
        });
        return result;
      }
    });
  });

  try {
    const executor = await initializeAgentExecutorWithOptions(toolsForAgent, llm, {
      agentType: "chat-conversational-react-description",
      verbose: true, // This will log agent thoughts to the console
      agentArgs: {
        systemMessage: `You are a helpful Eos Security Assistant.
        Your user is '${user.name}' and their role is '${user.role}'.
        Be concise and helpful.
        If you don't have a tool to answer a question (e.g., a 'sales_employee' asks for logs),
        you MUST state that you do not have the permission or capability to perform that action.`
      }
    });

    // Note: 'chat_history' is not explicitly passed here as this agent type
    // doesn't support it in the same way. We rely on the LLM's context.
    // For a real app, we'd manage history in req.session.chatHistory
    const result = await executor.invoke({ input: query });

    const output = result.output;
    console.log(`[MCP-SERVER] Agent output: ${output}`);

    logAuditEvent({
      type: 'RESPONSE',
      userId: user.id,
      userRole: user.role,
      response: output
    });

    res.json({ response: output });

  } catch (error) {
    console.error('[MCP-SERVER] Error during agent execution:', error);
    logAuditEvent({
      type: 'ERROR_AGENT',
      userId: user.id,
      userRole: user.role,
      error: error.message
    });
    res.status(500).json({ response: 'An error occurred while processing your request.' });
  }
});

// =============================================================================
// MOCK M2M AUTH SERVER (PORT 4001)
// =============================================================================

const authApp = express();
authApp.use(bodyParser.urlencoded({ extended: true })); // OAuth uses urlencoded forms
authApp.use(bodyParser.json());

// --- Auth Audit Logging ---
const authAuditLogStream = fs.createWriteStream(AUTH_AUDIT_LOG_FILE, { flags: 'a' });

/**
 * Logs an audit event to the auth_audit.log file.
 * @param {string} message - The log message.
 */
function logAuthAuditEvent(message) {
  try {
    const logEntry = `[${new Date().toISOString()}] ${message}
`;
    authAuditLogStream.write(logEntry);
  } catch (error) {
    console.error(`[AuthServer] Failed to write to auth audit log: ${error.message}`);
  }
}

/**
 * Creates a mock JWT (Base64 encoded JSON).
 * This is NOT a real, signed JWT, just a simulation for the demo.
 */
function createMockJwt(clientId, audience) {
  const header = { alg: 'NONE', typ: 'JWT' };
  const payload = {
    iss: `http://localhost:${AUTH_PORT}`,
    sub: clientId,
    aud: audience,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600, // Expires in 1 hour
    scope: 'read:logs write:reports'
  };

  const b64Header = Buffer.from(JSON.stringify(header)).toString('base64url');
  const b64Payload = Buffer.from(JSON.stringify(payload)).toString('base64url');

  return `${b64Header}.${b64Payload}.`; // No signature
}

// --- Auth Server Endpoint ---

authApp.post('/oauth/token', (req, res) => {
  const { client_id, client_secret, grant_type, audience } = req.body;

  const client = MOCK_M2M_CLIENTS[client_id];

  if (!client || client.secret !== client_secret) {
    logAuthAuditEvent(`AUTH_FAILURE: Invalid credentials for client_id '${client_id}' from IP ${req.ip}`);
    return res.status(401).json({ error: 'invalid_client' });
  }

  if (client.grant_type !== grant_type) {
    logAuthAuditEvent(`AUTH_FAILURE: Invalid grant_type '${grant_type}' for client_id '${client_id}'`);
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }

  if (client.audience !== audience) {
    logAuthAuditEvent(`AUTH_FAILURE: Invalid audience '${audience}' for client_id '${client_id}'`);
    return res.status(400).json({ error: 'invalid_request' });
  }

  // All checks passed, issue mock token
  logAuthAuditEvent(`AUTH_SUCCESS: Issued token to client_id '${client_id}' for audience '${audience}'`);

  const mockToken = createMockJwt(client_id, audience);

  res.json({
    access_token: mockToken,
    expires_in: 3600,
    token_type: 'Bearer'
  });
});

// =============================================================================
// SERVER STARTUP
// =============================================================================

async function simulateM2MAuthOnStartup() {
  console.log('[MCP-SERVER] Simulating M2M Auth on startup...');
  try {
    const authUrl = `http://localhost:${AUTH_PORT}/oauth/token`;
    const m2mClient = MOCK_M2M_CLIENTS['mcp_service_client_id'];

    const response = await fetch(authUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        'client_id': 'mcp_service_client_id',
        'client_secret': m2mClient.secret,
        'grant_type': m2mClient.grant_type,
        'audience': m2mClient.audience
      })
    });

    if (!response.ok) {
      throw new Error(`Auth server responded with ${response.status}`);
    }

    const data = await response.json();
    console.log(`[MCP-SERVER] Successfully fetched M2M service token (expires in ${data.expires_in}s).`);
    // In a real app, this token would be stored and used for backend API calls.
    // e.g., global.m2mToken = data.access_token;

  } catch (error) {
    console.error(`[MCP-SERVER] Failed to simulate M2M auth on startup: ${error.message}. Is the auth server running?`);
  }
}


// 1. Initialize Mock Data
initializeMockData();

// 2. Start the Mock M2M Auth Server
authApp.listen(AUTH_PORT, () => {
  console.log(`[AuthServer] Mock M2M OAuth Server listening on http://localhost:${AUTH_PORT}`);
});

// 3. Start the Main MCP Server
app.listen(PORT, async () => {
  console.log(`[MCP-SERVER] Main Chat Server listening on http://localhost:${PORT}`);
  console.log(`[MCP-SERVER] Login at http://localhost:${PORT}/login`);

  // 4. Simulate the main server getting its M2M token
  // We wait a second to ensure the auth server is fully up
  setTimeout(simulateM2MAuthOnStartup, 1000);
});
