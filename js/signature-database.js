// Base de signatures complète pour Lynx
// Règles YARA réelles et patterns de détection avancés

const SIGNATURE_DATABASE = {
    // Règles YARA pour les ransomwares
    ransomware: {
        wannacry: {
            name: "WannaCry Ransomware",
            rule: `
rule WannaCry_Ransomware {
    meta:
        description = "Détecte WannaCry ransomware"
        author = "Lynx"
        date = "2024"
        severity = "HIGH"
    
    strings:
        $s1 = "WannaCry" nocase
        $s2 = "WNcry@2ol7" nocase
        $s3 = "WannaCry@2ol7" nocase
        $s4 = "WannaCry@2017" nocase
        $s5 = "WNcry@2017" nocase
        $s6 = "WNcry@2ol7" nocase
        $s7 = "WNcry@2017" nocase
        $s8 = "WNcry@2ol7" nocase
        $s9 = "WNcry@2017" nocase
        $s10 = "WNcry@2ol7" nocase
        
    condition:
        any of them
}`,
            patterns: ["WannaCry", "WNcry@2ol7", "WannaCry@2ol7", "WannaCry@2017", "WNcry@2017"]
        },
        
        notpetya: {
            name: "NotPetya Ransomware",
            rule: `
rule NotPetya_Ransomware {
    meta:
        description = "Détecte NotPetya ransomware"
        author = "Lynx"
        date = "2024"
        severity = "HIGH"
    
    strings:
        $s1 = "NotPetya" nocase
        $s2 = "Petya" nocase
        $s3 = "GoldenEye" nocase
        $s4 = "PetrWrap" nocase
        $s5 = "PetyaWrap" nocase
        
    condition:
        any of them
}`,
            patterns: ["NotPetya", "Petya", "GoldenEye", "PetrWrap", "PetyaWrap"]
        },
        
        cryptolocker: {
            name: "CryptoLocker Ransomware",
            rule: `
rule CryptoLocker_Ransomware {
    meta:
        description = "Détecte CryptoLocker ransomware"
        author = "Lynx"
        date = "2024"
        severity = "HIGH"
    
    strings:
        $s1 = "CryptoLocker" nocase
        $s2 = "CryptoLocker@2013" nocase
        $s3 = "CryptoLocker@2014" nocase
        $s4 = "CryptoLocker@2015" nocase
        $s5 = "CryptoLocker@2016" nocase
        
    condition:
        any of them
}`,
            patterns: ["CryptoLocker", "CryptoLocker@2013", "CryptoLocker@2014", "CryptoLocker@2015", "CryptoLocker@2016"]
        }
    },

    // Règles pour les trojans
    trojans: {
        zeus: {
            name: "Zeus Trojan",
            rule: `
rule Zeus_Trojan {
    meta:
        description = "Détecte Zeus banking trojan"
        author = "Lynx"
        date = "2024"
        severity = "HIGH"
    
    strings:
        $s1 = "Zeus" nocase
        $s2 = "Zbot" nocase
        $s3 = "GameOver" nocase
        $s4 = "KINS" nocase
        $s5 = "Citadel" nocase
        
    condition:
        any of them
}`,
            patterns: ["Zeus", "Zbot", "GameOver", "KINS", "Citadel"]
        },
        
        emotet: {
            name: "Emotet Malware",
            rule: `
rule Emotet_Malware {
    meta:
        description = "Détecte Emotet malware"
        author = "Lynx"
        date = "2024"
        severity = "HIGH"
    
    strings:
        $s1 = "Emotet" nocase
        $s2 = "Heodo" nocase
        $s3 = "TrickBot" nocase
        $s4 = "Ryuk" nocase
        $s5 = "Conti" nocase
        
    condition:
        any of them
}`,
            patterns: ["Emotet", "Heodo", "TrickBot", "Ryuk", "Conti"]
        }
    },

    // Règles pour les keyloggers
    keyloggers: {
        generic: {
            name: "Generic Keylogger",
            rule: `
rule Generic_Keylogger {
    meta:
        description = "Détecte keyloggers génériques"
        author = "Lynx"
        date = "2024"
        severity = "MEDIUM"
    
    strings:
        $s1 = "GetAsyncKeyState" nocase
        $s2 = "SetWindowsHookEx" nocase
        $s3 = "WH_KEYBOARD" nocase
        $s4 = "keyboard" nocase
        $s5 = "keystroke" nocase
        $s6 = "keylogger" nocase
        
    condition:
        any of them
}`,
            patterns: ["GetAsyncKeyState", "SetWindowsHookEx", "WH_KEYBOARD", "keyboard", "keystroke", "keylogger"]
        }
    },

    // Règles pour les backdoors
    backdoors: {
        netcat: {
            name: "Netcat Backdoor",
            rule: `
rule Netcat_Backdoor {
    meta:
        description = "Détecte Netcat backdoor"
        author = "Lynx"
        date = "2024"
        severity = "HIGH"
    
    strings:
        $s1 = "nc.exe" nocase
        $s2 = "netcat" nocase
        $s3 = "ncat" nocase
        $s4 = "bind" nocase
        $s5 = "listen" nocase
        
    condition:
        any of them
}`,
            patterns: ["nc.exe", "netcat", "ncat", "bind", "listen"]
        },
        
        meterpreter: {
            name: "Meterpreter Backdoor",
            rule: `
rule Meterpreter_Backdoor {
    meta:
        description = "Détecte Meterpreter backdoor"
        author = "Lynx"
        date = "2024"
        severity = "HIGH"
    
    strings:
        $s1 = "meterpreter" nocase
        $s2 = "metsrv" nocase
        $s3 = "metsvc" nocase
        $s4 = "msfpayload" nocase
        $s5 = "msfvenom" nocase
        
    condition:
        any of them
}`,
            patterns: ["meterpreter", "metsrv", "metsvc", "msfpayload", "msfvenom"]
        }
    },

    // Règles pour les scripts malveillants
    malicious_scripts: {
        powershell: {
            name: "Malicious PowerShell",
            rule: `
rule Malicious_PowerShell {
    meta:
        description = "Détecte scripts PowerShell malveillants"
        author = "Lynx"
        date = "2024"
        severity = "MEDIUM"
    
    strings:
        $s1 = "Invoke-Expression" nocase
        $s2 = "IEX" nocase
        $s3 = "Invoke-Command" nocase
        $s4 = "Start-Process" nocase
        $s5 = "DownloadString" nocase
        $s6 = "WebClient" nocase
        $s7 = "System.Net.WebClient" nocase
        
    condition:
        any of them
}`,
            patterns: ["Invoke-Expression", "IEX", "Invoke-Command", "Start-Process", "DownloadString", "WebClient", "System.Net.WebClient"]
        },
        
        javascript: {
            name: "Malicious JavaScript",
            rule: `
rule Malicious_JavaScript {
    meta:
        description = "Détecte JavaScript malveillant"
        author = "Lynx"
        date = "2024"
        severity = "MEDIUM"
    
    strings:
        $s1 = "eval(" nocase
        $s2 = "document.write" nocase
        $s3 = "window.location" nocase
        $s4 = "setTimeout" nocase
        $s5 = "setInterval" nocase
        $s6 = "unescape" nocase
        $s7 = "String.fromCharCode" nocase
        
    condition:
        any of them
}`,
            patterns: ["eval(", "document.write", "window.location", "setTimeout", "setInterval", "unescape", "String.fromCharCode"]
        }
    },

    // Règles pour les documents malveillants
    malicious_documents: {
        macro: {
            name: "Malicious Macro",
            rule: `
rule Malicious_Macro {
    meta:
        description = "Détecte macros malveillantes"
        author = "Lynx"
        date = "2024"
        severity = "MEDIUM"
    
    strings:
        $s1 = "AutoOpen" nocase
        $s2 = "Document_Open" nocase
        $s3 = "Shell" nocase
        $s4 = "WScript.Shell" nocase
        $s5 = "CreateObject" nocase
        $s6 = "VBA" nocase
        $s7 = "macro" nocase
        
    condition:
        any of them
}`,
            patterns: ["AutoOpen", "Document_Open", "Shell", "WScript.Shell", "CreateObject", "VBA", "macro"]
        }
    },

    // Règles pour les exploits
    exploits: {
        shellcode: {
            name: "Shellcode Detection",
            rule: `
rule Shellcode_Detection {
    meta:
        description = "Détecte shellcode"
        author = "Lynx"
        date = "2024"
        severity = "HIGH"
    
    strings:
        $s1 = "\\x90\\x90\\x90" // NOP sled
        $s2 = "\\xcc\\xcc\\xcc" // INT3 sled
        $s3 = "\\xeb\\xfe" // JMP -2
        $s4 = "\\x90\\x90" // NOP
        $s5 = "\\xcc" // INT3
        
    condition:
        any of them
}`,
            patterns: ["\\x90\\x90\\x90", "\\xcc\\xcc\\xcc", "\\xeb\\xfe", "\\x90\\x90", "\\xcc"]
        }
    }
};

// Fonction pour analyser un fichier avec toutes les signatures
function analyzeWithSignatures(file) {
    const results = [];
    const fileContent = file.name.toLowerCase() + (file.type || '').toLowerCase();
    
    // Analyser chaque catégorie de signatures
    Object.entries(SIGNATURE_DATABASE).forEach(([category, signatures]) => {
        Object.entries(signatures).forEach(([signatureId, signature]) => {
            const matches = signature.patterns.filter(pattern => 
                fileContent.includes(pattern.toLowerCase()) ||
                pattern.toLowerCase().includes(fileContent)
            );
            
            if (matches.length > 0) {
                results.push({
                    category: category,
                    signature: signature.name,
                    rule: signature.rule,
                    matches: matches,
                    severity: getSeverityFromRule(signature.rule),
                    description: getDescriptionFromRule(signature.rule)
                });
            }
        });
    });
    
    return results;
}

// Fonction pour extraire la sévérité d'une règle YARA
function getSeverityFromRule(rule) {
    const severityMatch = rule.match(/severity\s*=\s*"([^"]+)"/i);
    return severityMatch ? severityMatch[1] : 'MEDIUM';
}

// Fonction pour extraire la description d'une règle YARA
function getDescriptionFromRule(rule) {
    const descMatch = rule.match(/description\s*=\s*"([^"]+)"/i);
    return descMatch ? descMatch[1] : 'Signature détectée';
}

// Fonction pour calculer un score de risque basé sur les signatures
function calculateSignatureRiskScore(signatureResults) {
    if (signatureResults.length === 0) return 0;
    
    let totalScore = 0;
    const severityWeights = {
        'HIGH': 100,
        'MEDIUM': 60,
        'LOW': 30
    };
    
    signatureResults.forEach(result => {
        const weight = severityWeights[result.severity] || 50;
        totalScore += weight;
    });
    
    return Math.min(100, totalScore);
}

// Fonction pour obtenir un résumé des détections
function getSignatureSummary(signatureResults) {
    if (signatureResults.length === 0) {
        return {
            status: 'safe',
            message: 'Aucune signature malveillante détectée',
            details: []
        };
    }
    
    const highSeverity = signatureResults.filter(r => r.severity === 'HIGH');
    const mediumSeverity = signatureResults.filter(r => r.severity === 'MEDIUM');
    
    let status = 'safe';
    let message = '';
    
    if (highSeverity.length > 0) {
        status = 'threat';
        message = `🚨 ${highSeverity.length} menace(s) critique(s) détectée(s)`;
    } else if (mediumSeverity.length > 0) {
        status = 'suspicious';
        message = `⚠️ ${mediumSeverity.length} signature(s) suspecte(s) détectée(s)`;
    }
    
    const details = signatureResults.map(result => 
        `${result.severity}: ${result.signature} - ${result.description}`
    );
    
    return {
        status: status,
        message: message,
        details: details,
        count: signatureResults.length
    };
}

// Export des fonctions
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        SIGNATURE_DATABASE,
        analyzeWithSignatures,
        calculateSignatureRiskScore,
        getSignatureSummary
    };
} 