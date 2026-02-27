// Lynx - YARA-compatible pattern matching engine
// Scans actual file content (text + binary) against rule pattern sets

const YARA_RULES = {
    malicious_executable: {
        name: 'Malicious Executable',
        patterns: ['CreateRemoteThread','VirtualAllocEx','WriteProcessMemory','NtWriteVirtualMemory','RtlCreateUserThread'],
        description: 'Process injection API calls detected'
    },
    evasion: {
        name: 'Anti-Analysis / Evasion',
        patterns: ['IsDebuggerPresent','CheckRemoteDebuggerPresent','NtQueryInformationProcess','SetUnhandledExceptionFilter','OutputDebugString'],
        description: 'Anti-debug or anti-analysis techniques'
    },
    persistence: {
        name: 'Persistence Mechanism',
        patterns: ['RegCreateKey','RegSetValueEx','HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run','schtasks /create','sc create','HKLM','RunOnce'],
        description: 'Registry or scheduled task persistence'
    },
    malicious_script: {
        name: 'Malicious Script',
        patterns: ['eval(base64_decode','FromBase64String','IEX(','Invoke-Expression','WScript.Shell','ActiveXObject','Shell.Application'],
        description: 'Script execution or obfuscation patterns'
    },
    malicious_document: {
        name: 'Malicious Document Macro',
        patterns: ['AutoOpen','Document_Open','AutoExec','VBA','CreateObject','WScript.Shell','Shell(','Chr('],
        description: 'Office macro or embedded command execution'
    },
    ransomware: {
        name: 'Ransomware Pattern',
        patterns: ['your files have been encrypted','send bitcoin','pay the ransom','ransom note','WNcry@2ol7','WannaCry','NotPetya','your personal files are encrypted'],
        description: 'Ransom demand or known ransomware strings'
    },
    keylogger: {
        name: 'Keylogger Pattern',
        patterns: ['GetAsyncKeyState','SetWindowsHookEx','WH_KEYBOARD_LL','WH_KEYBOARD','keybd_event','MapVirtualKey'],
        description: 'Keyboard hook or keylogging API calls'
    },
    backdoor: {
        name: 'Backdoor / RAT Pattern',
        patterns: ['meterpreter','reverse shell','bind shell','cmd.exe /c','nc -e','ncat','netcat','/bin/sh -i'],
        description: 'Remote shell or RAT command channel'
    },
    network_c2: {
        name: 'Network C2 Activity',
        patterns: ['URLDownloadToFile','WinHttpOpen','InternetOpen','HttpSendRequest','socket(AF_INET','connect(sock','send(sock'],
        description: 'Suspicious network communication patterns'
    },
    credential_theft: {
        name: 'Credential Theft',
        patterns: ['lsass','mimikatz','sekurlsa','logonpasswords','pass-the-hash','kerberos','dcsync'],
        description: 'Credential dumping or lateral movement patterns'
    }
};

/**
 * Asynchronously scan file content against all YARA rule pattern sets.
 * Returns an array of match objects with rule name, severity, and matched patterns.
 */
async function analyzeWithYARA(file) {
    return new Promise((resolve) => {
        const reader = new FileReader();
        reader.onload = (e) => {
            const bytes   = new Uint8Array(e.target.result);
            const content = new TextDecoder('utf-8', { fatal: false }).decode(bytes).toLowerCase();
            const results = [];

            for (const [ruleId, rule] of Object.entries(YARA_RULES)) {
                const matches = rule.patterns.filter(p => content.includes(p.toLowerCase()));
                if (matches.length > 0) {
                    results.push({
                        rule:        rule.name,
                        description: rule.description,
                        matches,
                        severity:    calculateSeverity(matches.length, rule.patterns.length)
                    });
                }
            }

            resolve(results);
        };
        reader.onerror = () => resolve([]);
        reader.readAsArrayBuffer(file);
    });
}

// Fonction pour calculer la sévérité basée sur le nombre de patterns trouvés
function calculateSeverity(matches, totalPatterns) {
    const ratio = matches / totalPatterns;
    if (ratio >= 0.8) return 'HIGH';
    if (ratio >= 0.5) return 'MEDIUM';
    return 'LOW';
}

// Fonction pour obtenir une description détaillée des menaces
function getThreatDescription(yaraResults) {
    if (yaraResults.length === 0) return null;
    
    const descriptions = yaraResults.map(result => 
        `${result.rule} (${result.severity}): ${result.description}`
    );
    
    return descriptions.join('; ');
}

// Export des fonctions pour utilisation dans le fichier principal
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        YARA_RULES,
        analyzeWithYARA,
        calculateSeverity,
        getThreatDescription
    };
} 