// Configuration de Lynx
// Centralise tous les paramètres de l'application

const CONFIG = {
    // Paramètres de l'interface
    UI: {
        ANIMATION_DURATION: 300,
        PROGRESS_UPDATE_INTERVAL: 200,
        STATUS_CHECK_INTERVAL: 5000,
        MAX_FILE_SIZE: 100 * 1024 * 1024, // 100MB
        MAX_FILES_PER_BATCH: 50
    },

    // Paramètres d'analyse
    ANALYSIS: {
        // Extensions suspectes
        SUSPICIOUS_EXTENSIONS: [
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', 
            '.vbs', '.js', '.ps1', '.msi', '.jar', '.hta'
        ],
        
        // Extensions de documents
        DOCUMENT_EXTENSIONS: [
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.pdf', '.rtf', '.txt'
        ],
        
        // Extensions d'archives
        ARCHIVE_EXTENSIONS: [
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2'
        ],
        
        // Seuils de risque
        RISK_THRESHOLDS: {
            LOW: 30,
            MEDIUM: 60,
            HIGH: 80,
            CRITICAL: 90
        },
        
        // Tailles de fichiers
        SIZE_THRESHOLDS: {
            SMALL: 1024 * 1024, // 1MB
            MEDIUM: 10 * 1024 * 1024, // 10MB
            LARGE: 50 * 1024 * 1024 // 50MB
        }
    },

    // Paramètres des moteurs de détection
    ENGINES: {
        YARA: {
            ENABLED: true,
            CONFIDENCE_THRESHOLD: 0.7,
            MAX_RULES_PER_FILE: 10
        },
        
        ML: {
            ENABLED: true,
            CONFIDENCE_THRESHOLD: 0.75,
            FEATURE_EXTRACTION_ENABLED: true
        },
        
        HASH: {
            ENABLED: true,
            ALGORITHMS: ['MD5', 'SHA1', 'SHA256'],
            DATABASE_SIZE: 1000000 // 1M signatures
        },
        
        BEHAVIORAL: {
            ENABLED: false, // Désactivé par défaut
            MONITORING_DURATION: 30000, // 30 secondes
            API_ENDPOINTS: []
        }
    },

    // Paramètres de visualisation
    VISUALIZATION: {
        CHART_COLORS: {
            SAFE: '#4CAF50',
            SUSPICIOUS: '#ff9800',
            THREAT: '#f44336'
        },
        
        ANIMATION_SPEED: 0.3,
        UPDATE_FREQUENCY: 1000 // 1 seconde
    },

    // Paramètres de sécurité
    SECURITY: {
        SANDBOX_ENABLED: false,
        QUARANTINE_ENABLED: false,
        AUTO_DELETE: false,
        ENCRYPTION_ENABLED: false
    },

    // Messages et textes
    MESSAGES: {
        UPLOAD: {
            DRAG_DROP: "Glissez vos fichiers ici ou cliquez pour sélectionner",
            SUPPORTED_FORMATS: "Supports: ZIP, EXE, DOC, PDF, JS, et plus...",
            MAX_SIZE: "Taille maximale: 100MB par fichier",
            MAX_FILES: "Maximum 50 fichiers par lot"
        },
        
        ANALYSIS: {
            IN_PROGRESS: "Analyse en cours...",
            COMPLETED: "Analyse terminée",
            ERROR: "Erreur lors de l'analyse",
            NO_FILES: "Aucun fichier analysé pour le moment"
        },
        
        THREATS: {
            SAFE: "Fichier sécurisé",
            SUSPICIOUS: "Fichier suspect",
            THREAT: "Menace détectée",
            CRITICAL: "Menace critique"
        }
    },

    // Paramètres de performance
    PERFORMANCE: {
        WORKER_THREADS: 4,
        MEMORY_LIMIT: 512 * 1024 * 1024, // 512MB
        TIMEOUT: 30000, // 30 secondes
        CACHE_ENABLED: true,
        CACHE_SIZE: 100 // 100 entrées
    },

    // Paramètres de reporting
    REPORTING: {
        AUTO_GENERATE: false,
        FORMATS: ['JSON', 'CSV', 'PDF'],
        INCLUDE_DETAILS: true,
        INCLUDE_STATS: true,
        INCLUDE_VISUALIZATIONS: true
    }
};

// Fonction pour obtenir un paramètre de configuration
function getConfig(path) {
    return path.split('.').reduce((obj, key) => obj && obj[key], CONFIG);
}

// Fonction pour définir un paramètre de configuration
function setConfig(path, value) {
    const keys = path.split('.');
    const lastKey = keys.pop();
    const obj = keys.reduce((o, key) => o[key] = o[key] || {}, CONFIG);
    obj[lastKey] = value;
}

// Fonction pour valider la configuration
function validateConfig() {
    const errors = [];
    
    // Vérifier les seuils de risque
    const thresholds = CONFIG.ANALYSIS.RISK_THRESHOLDS;
    if (thresholds.LOW >= thresholds.MEDIUM || 
        thresholds.MEDIUM >= thresholds.HIGH || 
        thresholds.HIGH >= thresholds.CRITICAL) {
        errors.push("Seuils de risque mal configurés");
    }
    
    // Vérifier les tailles de fichiers
    const sizes = CONFIG.ANALYSIS.SIZE_THRESHOLDS;
    if (sizes.SMALL >= sizes.MEDIUM || sizes.MEDIUM >= sizes.LARGE) {
        errors.push("Seuils de taille mal configurés");
    }
    
    return errors;
}

// Fonction pour obtenir la configuration par défaut
function getDefaultConfig() {
    return JSON.parse(JSON.stringify(CONFIG));
}

// Export des fonctions pour utilisation dans d'autres fichiers
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        CONFIG,
        getConfig,
        setConfig,
        validateConfig,
        getDefaultConfig
    };
} 