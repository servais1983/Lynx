// Rechercheur de patterns spécifiques pour Lynx
// Recherche des patterns malveillants spécifiques dans les fichiers

const PATTERN_DATABASE = {
    // Patterns de ransomwares
    ransomware_patterns: {
        wannacry: {
            name: "WannaCry Patterns",
            patterns: [
                "WannaCry",
                "WNcry@2ol7",
                "WannaCry@2ol7",
                "WannaCry@2017",
                "WNcry@2017",
                "WNcry@2ol7",
                "WannaCry@2ol7",
                "WannaCry@2017",
                "WNcry@2017",
                "WNcry@2ol7"
            ],
            severity: "HIGH",
            description: "Patterns spécifiques au ransomware WannaCry"
        },
        notpetya: {
            name: "NotPetya Patterns",
            patterns: [
                "NotPetya",
                "Petya",
                "GoldenEye",
                "PetrWrap",
                "PetyaWrap",
                "EternalPetya",
                "Petr"
            ],
            severity: "HIGH",
            description: "Patterns spécifiques au ransomware NotPetya"
        },
        cryptolocker: {
            name: "CryptoLocker Patterns",
            patterns: [
                "CryptoLocker",
                "CryptoLocker@2013",
                "CryptoLocker@2014",
                "CryptoLocker@2015",
                "CryptoLocker@2016",
                "CryptoLocker@2017",
                "CryptoLocker@2018",
                "CryptoLocker@2019",
                "CryptoLocker@2020",
                "CryptoLocker@2021"
            ],
            severity: "HIGH",
            description: "Patterns spécifiques au ransomware CryptoLocker"
        }
    },

    // Patterns de trojans
    trojan_patterns: {
        zeus: {
            name: "Zeus Trojan Patterns",
            patterns: [
                "Zeus",
                "Zbot",
                "GameOver",
                "KINS",
                "Citadel",
                "Zeus@2011",
                "Zeus@2012",
                "Zeus@2013",
                "Zeus@2014",
                "Zeus@2015"
            ],
            severity: "HIGH",
            description: "Patterns spécifiques au trojan Zeus"
        },
        emotet: {
            name: "Emotet Patterns",
            patterns: [
                "Emotet",
                "Heodo",
                "TrickBot",
                "Ryuk",
                "Conti",
                "Emotet@2014",
                "Emotet@2015",
                "Emotet@2016",
                "Emotet@2017",
                "Emotet@2018"
            ],
            severity: "HIGH",
            description: "Patterns spécifiques au malware Emotet"
        }
    },

    // Patterns de keyloggers
    keylogger_patterns: {
        generic: {
            name: "Generic Keylogger Patterns",
            patterns: [
                "GetAsyncKeyState",
                "SetWindowsHookEx",
                "WH_KEYBOARD",
                "keyboard",
                "keystroke",
                "keylogger",
                "GetKeyboardState",
                "GetKeyState",
                "GetKeyboardLayout",
                "GetKeyboardLayoutList"
            ],
            severity: "MEDIUM",
            description: "Patterns génériques de keyloggers"
        }
    },

    // Patterns de backdoors
    backdoor_patterns: {
        netcat: {
            name: "Netcat Backdoor Patterns",
            patterns: [
                "nc.exe",
                "netcat",
                "ncat",
                "bind",
                "listen",
                "connect",
                "reverse",
                "shell",
                "cmd",
                "powershell"
            ],
            severity: "HIGH",
            description: "Patterns spécifiques aux backdoors Netcat"
        },
        meterpreter: {
            name: "Meterpreter Patterns",
            patterns: [
                "meterpreter",
                "metsrv",
                "metsvc",
                "msfpayload",
                "msfvenom",
                "metasploit",
                "msfconsole",
                "msfvenom",
                "msfpayload",
                "msfvenom"
            ],
            severity: "HIGH",
            description: "Patterns spécifiques à Meterpreter"
        }
    },

    // Patterns de scripts malveillants
    script_patterns: {
        powershell: {
            name: "Malicious PowerShell Patterns",
            patterns: [
                "Invoke-Expression",
                "IEX",
                "Invoke-Command",
                "Start-Process",
                "DownloadString",
                "WebClient",
                "System.Net.WebClient",
                "New-Object",
                "Get-Content",
                "Set-Content"
            ],
            severity: "MEDIUM",
            description: "Patterns de scripts PowerShell malveillants"
        },
        javascript: {
            name: "Malicious JavaScript Patterns",
            patterns: [
                "eval(",
                "document.write",
                "window.location",
                "setTimeout",
                "setInterval",
                "unescape",
                "String.fromCharCode",
                "document.cookie",
                "localStorage",
                "sessionStorage"
            ],
            severity: "MEDIUM",
            description: "Patterns de JavaScript malveillant"
        }
    },

    // Patterns de documents malveillants
    document_patterns: {
        macro: {
            name: "Malicious Macro Patterns",
            patterns: [
                "AutoOpen",
                "Document_Open",
                "Shell",
                "WScript.Shell",
                "CreateObject",
                "VBA",
                "macro",
                "Sub",
                "Function",
                "End Sub"
            ],
            severity: "MEDIUM",
            description: "Patterns de macros malveillantes"
        }
    },

    // Patterns d'exploits
    exploit_patterns: {
        shellcode: {
            name: "Shellcode Patterns",
            patterns: [
                "\\x90\\x90\\x90",
                "\\xcc\\xcc\\xcc",
                "\\xeb\\xfe",
                "\\x90\\x90",
                "\\xcc",
                "\\x31\\xc0",
                "\\x31\\xdb",
                "\\x31\\xc9",
                "\\x31\\xd2",
                "\\xcd\\x80"
            ],
            severity: "HIGH",
            description: "Patterns de shellcode"
        }
    },

    // Patterns personnalisés (string1, string2, etc.)
    custom_patterns: {
        string1: {
            name: "Custom Pattern String1",
            patterns: [
                "string1",
                "String1",
                "STRING1",
                "string_1",
                "string-1"
            ],
            severity: "MEDIUM",
            description: "Pattern personnalisé string1"
        },
        string2: {
            name: "Custom Pattern String2",
            patterns: [
                "string2",
                "String2",
                "STRING2",
                "string_2",
                "string-2"
            ],
            severity: "MEDIUM",
            description: "Pattern personnalisé string2"
        },
        string3: {
            name: "Custom Pattern String3",
            patterns: [
                "string3",
                "String3",
                "STRING3",
                "string_3",
                "string-3"
            ],
            severity: "MEDIUM",
            description: "Pattern personnalisé string3"
        },
        malicious: {
            name: "Malicious Patterns",
            patterns: [
                "malicious",
                "Malicious",
                "MALICIOUS",
                "malware",
                "Malware",
                "MALWARE",
                "virus",
                "Virus",
                "VIRUS",
                "trojan",
                "Trojan",
                "TROJAN"
            ],
            severity: "HIGH",
            description: "Patterns génériques malveillants"
        }
    }
};

class PatternSearcher {
    constructor() {
        this.patterns = PATTERN_DATABASE;
        this.searchResults = [];
    }

    // Rechercher des patterns dans un fichier
    async searchPatterns(file) {
        const results = [];
        
        return new Promise((resolve) => {
            const reader = new FileReader();
            
            reader.onload = function(e) {
                const content = e.target.result;
                const textContent = typeof content === 'string' ? content : new TextDecoder().decode(content);
                
                // Rechercher dans chaque catégorie de patterns
                Object.entries(PATTERN_DATABASE).forEach(([category, patternGroups]) => {
                    Object.entries(patternGroups).forEach(([patternName, patternData]) => {
                        const matches = this.findPatternMatches(textContent, patternData.patterns);
                        
                        if (matches.length > 0) {
                            results.push({
                                category: category,
                                patternName: patternData.name,
                                severity: patternData.severity,
                                description: patternData.description,
                                matches: matches,
                                totalMatches: matches.length,
                                file: file.name
                            });
                        }
                    });
                });
                
                resolve(results);
            }.bind(this);
            
            reader.readAsText(file);
        });
    }

    // Trouver les correspondances de patterns
    findPatternMatches(content, patterns) {
        const matches = [];
        const lowerContent = content.toLowerCase();
        
        patterns.forEach(pattern => {
            const lowerPattern = pattern.toLowerCase();
            let index = 0;
            
            while ((index = lowerContent.indexOf(lowerPattern, index)) !== -1) {
                matches.push({
                    pattern: pattern,
                    position: index,
                    context: this.getContext(content, index, pattern.length)
                });
                index += pattern.length;
            }
        });
        
        return matches;
    }

    // Obtenir le contexte autour d'une correspondance
    getContext(content, position, patternLength, contextSize = 50) {
        const start = Math.max(0, position - contextSize);
        const end = Math.min(content.length, position + patternLength + contextSize);
        return content.substring(start, end);
    }

    // Analyser un fichier avec recherche de patterns
    async analyzeFileWithPatterns(file) {
        try {
            const patternResults = await this.searchPatterns(file);
            
            if (patternResults.length === 0) {
                return {
                    status: 'safe',
                    riskScore: 0,
                    details: ['Aucun pattern suspect détecté'],
                    patterns: []
                };
            }

            // Calculer le score de risque basé sur les patterns trouvés
            let riskScore = 0;
            let status = 'safe';
            
            patternResults.forEach(result => {
                if (result.severity === 'HIGH') {
                    riskScore += 30;
                    status = 'threat';
                } else if (result.severity === 'MEDIUM') {
                    riskScore += 15;
                    if (status !== 'threat') {
                        status = 'suspicious';
                    }
                }
            });

            riskScore = Math.min(100, riskScore);

            const details = patternResults.map(result => 
                `🔍 ${result.patternName} (${result.severity}): ${result.totalMatches} correspondance(s) trouvée(s)`
            );

            return {
                status: status,
                riskScore: riskScore,
                details: details,
                patterns: patternResults,
                totalPatterns: patternResults.length
            };

        } catch (error) {
            console.error('Erreur lors de l\'analyse des patterns:', error);
            return {
                status: 'error',
                riskScore: 0,
                details: [`Erreur d'analyse: ${error.message}`],
                patterns: []
            };
        }
    }

    // Ajouter un pattern personnalisé
    addCustomPattern(category, name, patterns, severity = 'MEDIUM', description = '') {
        if (!this.patterns[category]) {
            this.patterns[category] = {};
        }
        
        this.patterns[category][name] = {
            name: name,
            patterns: patterns,
            severity: severity,
            description: description
        };
        
        console.log(`✅ Pattern personnalisé ajouté: ${category}/${name}`);
    }

    // Supprimer un pattern
    removePattern(category, name) {
        if (this.patterns[category] && this.patterns[category][name]) {
            delete this.patterns[category][name];
            console.log(`🗑️ Pattern supprimé: ${category}/${name}`);
            return true;
        }
        return false;
    }

    // Lister tous les patterns disponibles
    listAllPatterns() {
        const allPatterns = [];
        
        Object.entries(this.patterns).forEach(([category, patternGroups]) => {
            Object.entries(patternGroups).forEach(([name, patternData]) => {
                allPatterns.push({
                    category: category,
                    name: name,
                    displayName: patternData.name,
                    severity: patternData.severity,
                    description: patternData.description,
                    patternCount: patternData.patterns.length
                });
            });
        });
        
        return allPatterns;
    }

    // Générer un rapport de recherche
    generatePatternReport(searchResults) {
        const report = {
            timestamp: new Date().toISOString(),
            totalPatterns: searchResults.length,
            categories: {},
            severity: {
                HIGH: 0,
                MEDIUM: 0,
                LOW: 0
            },
            totalMatches: 0
        };

        searchResults.forEach(result => {
            // Compter par catégorie
            if (!report.categories[result.category]) {
                report.categories[result.category] = 0;
            }
            report.categories[result.category]++;

            // Compter par sévérité
            report.severity[result.severity]++;

            // Compter les correspondances totales
            report.totalMatches += result.totalMatches;
        });

        return report;
    }
}

// Instance globale du chercheur de patterns
const patternSearcher = new PatternSearcher();

// Fonction pour analyser un fichier avec recherche de patterns
async function analyzeFileWithPatterns(file) {
    return await patternSearcher.analyzeFileWithPatterns(file);
}

// Export des fonctions
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        PATTERN_DATABASE,
        PatternSearcher,
        patternSearcher,
        analyzeFileWithPatterns
    };
} 