document.addEventListener('DOMContentLoaded', () => {
    const naturalQueryInput = document.getElementById('natural-query');
    const targetSiemSelect = document.getElementById('target-siem');
    const generateButton = document.getElementById('generate-button');
    const generatedQueryCode = document.getElementById('generated-query-code');
    const queryExplanation = document.getElementById('query-explanation');
    const historyList = document.getElementById('history-list');
    const exampleList = document.getElementById('example-list');
    const logSuggestionsList = document.getElementById('log-suggestions-list');

    // --- Core Query Generation Logic (Simulated) ---
    // In a real application, this would call a Python backend/LLM API
    function generateQuery(prompt, siem) {
        // Simple mapping/parsing logic for demonstration
        const lowerPrompt = prompt.toLowerCase();
        let query = "";
        let explanation = "";
        let logSources = ["General security logs"];

        // Basic keyword detection (simplified)
        const isPowerShell = lowerPrompt.includes("powershell");
        const isAdmin = lowerPrompt.includes("admin");
        const is24h = lowerPrompt.includes("24h") || lowerPrompt.includes("24 hours");

        // Set default explanation and log sources
        explanation = "Looks for security events matching the user's intent.";
        logSources = ["Sysmon (Event ID 1 - Process Create)", "Windows Event Logs (4688)"];

        if (isPowerShell) {
            explanation = "Looks for PowerShell process creation events";
        }
        if (isAdmin) {
            explanation += " by administrator accounts";
        }
        if (is24h) {
            explanation += " in the past 24 hours.";
        } else {
            explanation += " in the default time range.";
        }

        // Simulated SIEM Query Generation
        switch (siem) {
            case 'kql':
                query = `SecurityEvent | where EventID == 4688`;
                if (isPowerShell) query += ` | where Process endswith "powershell.exe"`;
                if (isAdmin) query += ` | where AccountType == "Admin"`;
                if (is24h) query += ` | where TimeGenerated > ago(24h)`;
                break;
            case 'spl':
                query = `index=wineventlog EventCode=4688`;
                if (isPowerShell) query += ` CommandLine="*powershell.exe*"`;
                if (isAdmin) query += ` | search user_type="admin"`;
                if (is24h) query += ` earliest=-24h`;
                break;
            case 'eql':
                query = `process where event.action == "process_started"`;
                if (isPowerShell) query += ` and process.name == "powershell.exe"`;
                if (isAdmin) query += ` and user.group == "Administrators"`;
                // EQL doesn't typically handle time range in the query itself, but in the API/UI filter
                break;
            case 'aql':
                query = `SELECT QIDNAME(qid) AS 'Event Name', * FROM events WHERE LOGSOURCEID IN (4, 10) AND username IS NOT NULL`;
                if (isPowerShell) query += ` AND "powershell.exe" IN ("Process Name", "Command Line")`;
                if (isAdmin) query += ` AND user_role='admin'`;
                if (is24h) query += ` START '24 hours ago'`;
                break;
            case 'dql':
                query = `event.module:winlog and winlog.event_id:4688`;
                if (isPowerShell) query += ` and winlog.event_data.process_name:"powershell.exe"`;
                if (isAdmin) query += ` and user.group:"Administrators"`;
                // Time handled by API/UI
                break;
            default:
                query = "Error: Unknown SIEM type.";
                explanation = "Could not generate query for the selected SIEM.";
        }

        return { query, explanation, logSources };
    }

    // --- Event Handlers ---
    generateButton.addEventListener('click', () => {
        const prompt = naturalQueryInput.value.trim();
        const siem = targetSiemSelect.value;

        if (prompt === "") {
            alert("Please enter a natural language request.");
            return;
        }

        // 1. Generate Query
        const { query, explanation, logSources } = generateQuery(prompt, siem);

        // 2. Update Output Area
        generatedQueryCode.textContent = query;
        queryExplanation.textContent = explanation;
        
        // 3. Update Log Sources
        logSuggestionsList.innerHTML = '';
        logSources.forEach(source => {
            const li = document.createElement('li');
            li.textContent = source;
            logSuggestionsList.appendChild(li);
        });

        // 4. Update History (simplistic in-memory storage)
        updateHistory(prompt, siem, query);
    });

    // Handle Example Clicks
    exampleList.addEventListener('click', (event) => {
        if (event.target.tagName === 'LI') {
            const query = event.target.getAttribute('data-query');
            if (query) {
                naturalQueryInput.value = query;
                // Optional: Automatically trigger generation
                generateButton.click(); 
            }
        }
    });

    // Handle Copy Button
    document.querySelector('.query-block').addEventListener('click', (event) => {
        if (event.target.classList.contains('copy-button')) {
            const codeToCopy = document.getElementById(event.target.getAttribute('data-target')).textContent;
            navigator.clipboard.writeText(codeToCopy).then(() => {
                const originalText = event.target.textContent;
                event.target.textContent = 'Copied!';
                setTimeout(() => {
                    event.target.textContent = originalText;
                }, 1500);
            }).catch(err => {
                console.error('Could not copy text: ', err);
            });
        }
    });

    // --- History Management ---
    function updateHistory(prompt, siem, query) {
        // Remove 'No recent queries.' if present
        if (historyList.firstElementChild && historyList.firstElementChild.textContent === 'No recent queries.') {
             historyList.innerHTML = '';
        }
        
        const newHistoryItem = document.createElement('li');
        newHistoryItem.textContent = `[${siem.toUpperCase()}] ${prompt}`;
        newHistoryItem.setAttribute('data-full-query', query);
        newHistoryItem.setAttribute('data-prompt', prompt);

        // Prepend to the list (most recent first)
        historyList.prepend(newHistoryItem);

        // Limit history size (e.g., to 5)
        if (historyList.children.length > 5) {
            historyList.removeChild(historyList.lastChild);
        }
    }

    // Handle History Clicks (to reuse a query)
    historyList.addEventListener('click', (event) => {
        if (event.target.tagName === 'LI') {
            const prompt = event.target.getAttribute('data-prompt');
            if (prompt) {
                naturalQueryInput.value = prompt;
            }
        }
    });
});