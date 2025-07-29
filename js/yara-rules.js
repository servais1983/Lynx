// Règles YARA simulées pour Lynx
// Ces règles simulent la détection de patterns malveillants

const YARA_RULES = {
    // Règles pour les exécutables malveillants
    malicious_executable: {
        name: "Malicious Executable",
        patterns: [
            "MZ",
            "PE",
            "CreateRemoteThread",
            "VirtualAllocEx",
            "WriteProcessMemory"
        ],
        description: "Détecte les exécutables avec des patterns suspects"
    },

    // Règles pour les scripts malveillants
    malicious_script: {
        name: "Malicious Script",
        patterns: [
            "eval(",
            "document.write",
            "window.location",
            "setTimeout",
            "setInterval"
        ],
        description: "Détecte les scripts avec des fonctions dangereuses"
    },

    // Règles pour les documents malveillants
    malicious_document: {
        name: "Malicious Document",
        patterns: [
            "VBA",
            "macro",
            "AutoOpen",
            "Document_Open",
            "Shell"
        ],
        description: "Détecte les documents avec des macros suspectes"
    },

    // Règles pour les ransomwares
    ransomware: {
        name: "Ransomware Pattern",
        patterns: [
            "encrypt",
            "decrypt",
            "ransom",
            "bitcoin",
            "wallet"
        ],
        description: "Détecte les patterns typiques des ransomwares"
    },

    // Règles pour les keyloggers
    keylogger: {
        name: "Keylogger Pattern",
        patterns: [
            "GetAsyncKeyState",
            "SetWindowsHookEx",
            "WH_KEYBOARD",
            "keyboard",
            "keystroke"
        ],
        description: "Détecte les patterns de keyloggers"
    },

    // Règles pour les backdoors
    backdoor: {
        name: "Backdoor Pattern",
        patterns: [
            "bind(",
            "listen(",
            "accept(",
            "connect(",
            "socket"
        ],
        description: "Détecte les patterns de backdoors réseau"
    }
};

// Fonction pour analyser un fichier avec les règles YARA
function analyzeWithYARA(file) {
    const results = [];
    const fileContent = file.name.toLowerCase() + file.type.toLowerCase();
    
    Object.entries(YARA_RULES).forEach(([ruleId, rule]) => {
        const matches = rule.patterns.filter(pattern => 
            fileContent.includes(pattern.toLowerCase())
        );
        
        if (matches.length > 0) {
            results.push({
                rule: rule.name,
                description: rule.description,
                matches: matches,
                severity: calculateSeverity(matches.length, rule.patterns.length)
            });
        }
    });
    
    return results;
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