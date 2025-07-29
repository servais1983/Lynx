// Configuration unifiée pour Lynx
// Centralise toutes les configurations et règles de détection

class UnifiedConfig {
    constructor() {
        this.environment = this.detectEnvironment();
        this.config = this.loadConfiguration();
        this.rules = this.loadRules();
        this.security = this.loadSecuritySettings();
    }

    // Détection de l'environnement
    detectEnvironment() {
        const hostname = window.location.hostname;
        if (hostname === 'localhost' || hostname === '127.0.0.1') {
            return 'development';
        }
        return 'production';
    }

    // Configuration principale
    loadConfiguration() {
        const baseConfig = {
            // Configuration de l'interface
            UI: {
                ANIMATION_DURATION: 300,
                PROGRESS_UPDATE_INTERVAL: 200,
                STATUS_CHECK_INTERVAL: 5000,
                MAX_FILE_SIZE: 100 * 1024 * 1024, // 100MB
                MAX_FILES_PER_BATCH: 50,
                THEME: 'dark',
                LANGUAGE: 'fr',
                AUTO_REFRESH: true,
                REFRESH_INTERVAL: 5000,
                SHOW_PROGRESS: true,
                SHOW_DETAILS: true
            },

            // Configuration d'analyse
            ANALYSIS: {
                SUSPICIOUS_EXTENSIONS: [
                    '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', 
                    '.vbs', '.js', '.ps1', '.msi', '.jar', '.hta'
                ],
                DOCUMENT_EXTENSIONS: [
                    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
                    '.pdf', '.rtf', '.txt'
                ],
                ARCHIVE_EXTENSIONS: [
                    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2'
                ],
                RISK_THRESHOLDS: {
                    LOW: 30,
                    MEDIUM: 60,
                    HIGH: 80,
                    CRITICAL: 90
                },
                SIZE_THRESHOLDS: {
                    SMALL: 1024 * 1024, // 1MB
                    MEDIUM: 10 * 1024 * 1024, // 10MB
                    LARGE: 50 * 1024 * 1024 // 50MB
                }
            },

            // Configuration des moteurs
            ENGINES: {
                YARA: {
                    ENABLED: true,
                    CONFIDENCE_THRESHOLD: 0.7,
                    MAX_RULES_PER_FILE: 10
                },
                ML: {
                    ENABLED: true,
                    CONFIDENCE_THRESHOLD: 0.75,
                    FEATURE_EXTRACTION_ENABLED: true,
                    MODEL_UPDATE_INTERVAL: 7 * 24 * 60 * 60 * 1000 // 7 jours
                },
                HASH: {
                    ENABLED: true,
                    ALGORITHMS: ['MD5', 'SHA1', 'SHA256'],
                    DATABASE_SIZE: 1000000 // 1M signatures
                },
                BEHAVIORAL: {
                    ENABLED: false,
                    MONITORING_DURATION: 30000, // 30 secondes
                    API_ENDPOINTS: []
                }
            },

            // Configuration de performance
            PERFORMANCE: {
                WORKER_THREADS: 4,
                MEMORY_LIMIT: 512 * 1024 * 1024, // 512MB
                TIMEOUT: 30000, // 30 secondes
                CACHE_ENABLED: true,
                CACHE_SIZE: 100, // 100 entrées
                MAX_CONCURRENT_ANALYSES: 2,
                ANALYSIS_TIMEOUT: 60000 // 60 secondes
            },

            // Configuration de reporting
            REPORTING: {
                AUTO_GENERATE: true,
                FORMATS: ['JSON', 'CSV', 'PDF'],
                INCLUDE_DETAILS: true,
                INCLUDE_STATS: true,
                INCLUDE_VISUALIZATIONS: true,
                SAVE_LOCALLY: true
            },

            // Configuration de visualisation
            VISUALIZATION: {
                CHART_COLORS: {
                    SAFE: '#4CAF50',
                    SUSPICIOUS: '#ff9800',
                    THREAT: '#f44336'
                },
                ANIMATION_SPEED: 0.3,
                UPDATE_FREQUENCY: 1000 // 1 seconde
            },

            // Configuration des logs
            LOGGING: {
                ENABLED: true,
                LEVEL: 'INFO',
                MAX_FILES: 10,
                MAX_SIZE: 10 * 1024 * 1024, // 10MB
                CONSOLE_OUTPUT: true
            },

            // Configuration des notifications
            NOTIFICATIONS: {
                ENABLED: true,
                SOUND: true,
                DESKTOP: true,
                BROWSER: true
            }
        };

        // Configuration spécifique à l'environnement
        if (this.environment === 'production') {
            baseConfig.VIRUSTOTAL = {
                API_KEY: this.getSecureAPIKey(),
                RATE_LIMIT: 4, // Requêtes par minute (gratuit)
                TIMEOUT: 30000, // 30 secondes
                RETRY_ATTEMPTS: 3,
                ENABLED: true
            };
            baseConfig.SIGNATURES = {
                AUTO_UPDATE: true,
                UPDATE_INTERVAL: 24 * 60 * 60 * 1000, // 24 heures
                CACHE_ENABLED: true,
                CACHE_SIZE: 1000,
                ENABLED: true
            };
        } else {
            baseConfig.VIRUSTOTAL = {
                API_KEY: 'test-key',
                RATE_LIMIT: 10,
                TIMEOUT: 10000,
                RETRY_ATTEMPTS: 1,
                ENABLED: false
            };
            baseConfig.SIGNATURES = {
                AUTO_UPDATE: false,
                UPDATE_INTERVAL: 60 * 60 * 1000, // 1 heure
                CACHE_ENABLED: true,
                CACHE_SIZE: 100,
                ENABLED: true
            };
        }

        return baseConfig;
    }

    // Récupération sécurisée de la clé API
    getSecureAPIKey() {
        // En production, la clé devrait être stockée de manière sécurisée
        // Ici, on utilise localStorage comme solution temporaire
        const storedKey = localStorage.getItem('virustotal_api_key');
        if (storedKey) {
            return storedKey;
        }
        
        // Clé par défaut (à remplacer par une vraie clé)
        const defaultKey = '3136c308ce9db10a8dadb4f42c4032009b031598fe5706d2c0337ddf8c8acb8d';
        localStorage.setItem('virustotal_api_key', defaultKey);
        return defaultKey;
    }

    // Chargement des règles de détection
    loadRules() {
        return {
            // Règles YARA unifiées
            YARA_RULES: this.loadYaraRules(),
            
            // Signatures de fichiers
            SIGNATURES: this.loadSignatures(),
            
            // Patterns de recherche
            PATTERNS: this.loadPatterns(),
            
            // Règles de triage
            TRIAGE_RULES: this.loadTriageRules()
        };
    }

    // Chargement des règles YARA
    loadYaraRules() {
        return {
            MALWARE_GENERAL: {
                name: "Malware General",
                rule: `
rule Malware_General {
    strings:
        $s1 = "CreateRemoteThread" nocase
        $s2 = "VirtualAlloc" nocase
        $s3 = "WriteProcessMemory" nocase
        $s4 = "cmd.exe" nocase
        $s5 = "powershell.exe" nocase
    condition:
        any of them
}`,
                severity: "HIGH",
                confidence: 0.8
            },
            
            RANSOMWARE: {
                name: "Ransomware Detection",
                rule: `
rule Ransomware_Detection {
    strings:
        $s1 = "encrypt" nocase
        $s2 = "decrypt" nocase
        $s3 = "ransom" nocase
        $s4 = "bitcoin" nocase
        $s5 = "wallet" nocase
    condition:
        3 of them
}`,
                severity: "CRITICAL",
                confidence: 0.9
            },
            
            SHELLCODE: {
                name: "Shellcode Detection",
                rule: `
rule Shellcode_Detection {
    strings:
        $s1 = { 90 90 90 90 90 90 90 90 }
        $s2 = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? }
        $s3 = { 89 E5 83 EC ?? 83 E4 F0 }
    condition:
        any of them
}`,
                severity: "HIGH",
                confidence: 0.85
            }
        };
    }

    // Chargement des signatures
    loadSignatures() {
        return {
            KNOWN_MALWARE: {
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
                    name: "Empty File",
                    type: "BENIGN",
                    confidence: 1.0
                },
                "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3": {
                    name: "Test File",
                    type: "BENIGN",
                    confidence: 1.0
                }
            },
            
            FILE_HEADERS: {
                "4D5A": "PE Executable",
                "504B0304": "ZIP Archive",
                "25504446": "PDF Document",
                "D0CF11E0": "Office Document",
                "7F454C46": "ELF Executable"
            }
        };
    }

    // Chargement des patterns
    loadPatterns() {
        return {
            SUSPICIOUS_STRINGS: [
                "CreateRemoteThread",
                "VirtualAlloc",
                "WriteProcessMemory",
                "cmd.exe",
                "powershell.exe",
                "encrypt",
                "decrypt",
                "ransom",
                "bitcoin",
                "wallet"
            ],
            
            REGEX_PATTERNS: [
                {
                    pattern: /https?:\/\/[^\s]+/g,
                    name: "URL Detection",
                    severity: "MEDIUM"
                },
                {
                    pattern: /[A-Za-z0-9+/]{20,}={0,2}/g,
                    name: "Base64 Detection",
                    severity: "LOW"
                },
                {
                    pattern: /[0-9A-Fa-f]{32}/g,
                    name: "MD5 Hash",
                    severity: "LOW"
                }
            ]
        };
    }

    // Chargement des règles de triage
    loadTriageRules() {
        return {
            PRIORITY_LEVELS: {
                CRITICAL: {
                    score: 90,
                    action: "IMMEDIATE_QUARANTINE",
                    color: "#f44336"
                },
                HIGH: {
                    score: 80,
                    action: "QUARANTINE",
                    color: "#ff5722"
                },
                MEDIUM: {
                    score: 60,
                    action: "FLAG_FOR_REVIEW",
                    color: "#ff9800"
                },
                LOW: {
                    score: 30,
                    action: "MONITOR",
                    color: "#4caf50"
                }
            },
            
            AUTOMATION_RULES: [
                {
                    condition: "vt_positives > 10",
                    action: "AUTO_QUARANTINE",
                    priority: "CRITICAL"
                },
                {
                    condition: "yara_matches > 0",
                    action: "FLAG_FOR_REVIEW",
                    priority: "HIGH"
                },
                {
                    condition: "file_size > 50MB",
                    action: "DEEP_SCAN",
                    priority: "MEDIUM"
                }
            ]
        };
    }

    // Chargement des paramètres de sécurité
    loadSecuritySettings() {
        return {
            ENCRYPTION: {
                algorithm: 'AES-256-GCM',
                keyLength: 256,
                ivLength: 12,
                saltLength: 16
            },
            
            AUTHENTICATION: {
                enabled: true,
                sessionTimeout: 3600000, // 1 heure
                maxLoginAttempts: 5,
                lockoutDuration: 900000 // 15 minutes
            },
            
            RATE_LIMITING: {
                enabled: true,
                maxRequestsPerMinute: 100,
                maxRequestsPerHour: 1000,
                maxFileSize: 100 * 1024 * 1024 // 100MB
            },
            
            FILE_VALIDATION: {
                allowedExtensions: ['exe', 'dll', 'js', 'ps1', 'bat', 'txt', 'pdf', 'doc', 'zip', 'rar'],
                maxFileSize: 100 * 1024 * 1024, // 100MB
                scanForMalware: true,
                validateIntegrity: true
            },
            
            SECURITY_LOGGING: {
                enabled: true,
                logLevel: 'INFO',
                logRetention: 30, // jours
                sensitiveDataMasking: true
            },
            
            API_SECURITY: {
                enabled: true,
                corsEnabled: false,
                apiKeyRequired: true,
                requestValidation: true
            },
            
            NETWORK_SECURITY: {
                httpsOnly: true,
                contentSecurityPolicy: true,
                xssProtection: true,
                csrfProtection: true
            },
            
            SANDBOX: {
                enabled: false,
                quarantineEnabled: false,
                autoDelete: false,
                encryptionEnabled: false
            }
        };
    }

    // Méthodes utilitaires
    get(path) {
        return path.split('.').reduce((obj, key) => obj && obj[key], this.config);
    }

    set(path, value) {
        const keys = path.split('.');
        const lastKey = keys.pop();
        const obj = keys.reduce((o, key) => o[key] = o[key] || {}, this.config);
        obj[lastKey] = value;
    }

    getRule(type, name) {
        return this.rules[type]?.[name];
    }

    getAllRules(type) {
        return this.rules[type] || {};
    }

    getSecuritySetting(path) {
        return path.split('.').reduce((obj, key) => obj && obj[key], this.security);
    }

    validateConfig() {
        const errors = [];
        
        // Validation des seuils de risque
        const thresholds = this.config.ANALYSIS.RISK_THRESHOLDS;
        if (thresholds.LOW >= thresholds.MEDIUM || 
            thresholds.MEDIUM >= thresholds.HIGH || 
            thresholds.HIGH >= thresholds.CRITICAL) {
            errors.push("Seuils de risque mal configurés");
        }
        
        // Validation des tailles de fichiers
        const sizes = this.config.ANALYSIS.SIZE_THRESHOLDS;
        if (sizes.SMALL >= sizes.MEDIUM || sizes.MEDIUM >= sizes.LARGE) {
            errors.push("Seuils de taille mal configurés");
        }
        
        return errors;
    }

    // Export pour compatibilité
    export() {
        return {
            config: this.config,
            rules: this.rules,
            security: this.security,
            environment: this.environment
        };
    }
}

// Instance globale
const UNIFIED_CONFIG = new UnifiedConfig();

// Export pour utilisation dans d'autres modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = UnifiedConfig;
} else {
    window.UNIFIED_CONFIG = UNIFIED_CONFIG;
} 