// Configuration de production pour Lynx
// Paramètres optimisés pour l'utilisation en production

const PRODUCTION_CONFIG = {
    // Configuration VirusTotal
    VIRUSTOTAL: {
        API_KEY: '', // L'utilisateur doit fournir sa propre clé API via l'interface
        RATE_LIMIT: 4, // Requêtes par minute (gratuit)
        TIMEOUT: 30000, // 30 secondes
        RETRY_ATTEMPTS: 3,
        ENABLED: true
    },

    // Configuration des signatures
    SIGNATURES: {
        AUTO_UPDATE: true,
        UPDATE_INTERVAL: 24 * 60 * 60 * 1000, // 24 heures
        CACHE_ENABLED: true,
        CACHE_SIZE: 1000,
        ENABLED: true
    },

    // Configuration ML
    MACHINE_LEARNING: {
        ENABLED: true,
        CONFIDENCE_THRESHOLD: 0.75,
        FEATURE_EXTRACTION: true,
        MODEL_UPDATE_INTERVAL: 7 * 24 * 60 * 60 * 1000 // 7 jours
    },

    // Configuration de performance
    PERFORMANCE: {
        MAX_CONCURRENT_ANALYSES: 2,
        ANALYSIS_TIMEOUT: 60000, // 60 secondes
        MEMORY_LIMIT: 512 * 1024 * 1024, // 512MB
        WORKER_THREADS: 4,
        CACHE_ENABLED: true
    },

    // Configuration de sécurité
    SECURITY: {
        SANDBOX_ENABLED: false,
        QUARANTINE_ENABLED: false,
        AUTO_DELETE: false,
        ENCRYPTION_ENABLED: false,
        LOG_LEVEL: 'INFO'
    },

    // Configuration de reporting
    REPORTING: {
        AUTO_GENERATE: true,
        FORMATS: ['JSON', 'CSV'],
        INCLUDE_DETAILS: true,
        INCLUDE_STATS: true,
        INCLUDE_VISUALIZATIONS: true,
        SAVE_LOCALLY: true
    },

    // Configuration de l'interface
    UI: {
        AUTO_REFRESH: true,
        REFRESH_INTERVAL: 5000, // 5 secondes
        SHOW_PROGRESS: true,
        SHOW_DETAILS: true,
        THEME: 'dark',
        LANGUAGE: 'fr'
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

// Fonction pour initialiser la configuration de production
function initializeProductionConfig() {
    // Vérifier la disponibilité des APIs
    checkAPIAvailability();
    
    // Initialiser le cache
    initializeCache();
    
    // Configurer les logs
    setupLogging();
    
    // Configurer les notifications
    setupNotifications();
    
    console.log('Configuration de production initialisée');
}

// Fonction pour vérifier la disponibilité des APIs
async function checkAPIAvailability() {
    try {
        // Test VirusTotal
        if (PRODUCTION_CONFIG.VIRUSTOTAL.ENABLED) {
            const testResponse = await fetch('https://www.virustotal.com/vtapi/v2/file/report', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    apikey: PRODUCTION_CONFIG.VIRUSTOTAL.API_KEY,
                    resource: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' // Hash SHA256 vide
                })
            });
            
            if (testResponse.ok) {
                console.log('✅ API VirusTotal disponible');
            } else {
                console.warn('⚠️ API VirusTotal non disponible');
                PRODUCTION_CONFIG.VIRUSTOTAL.ENABLED = false;
            }
        }
    } catch (error) {
        console.warn('⚠️ Erreur lors du test des APIs:', error);
        PRODUCTION_CONFIG.VIRUSTOTAL.ENABLED = false;
    }
}

// Fonction pour initialiser le cache
function initializeCache() {
    if (PRODUCTION_CONFIG.SIGNATURES.CACHE_ENABLED) {
        // Utiliser localStorage pour le cache
        if (!localStorage.getItem('threathunter_cache')) {
            localStorage.setItem('threathunter_cache', JSON.stringify({}));
        }
        console.log('✅ Cache initialisé');
    }
}

// Fonction pour configurer les logs
function setupLogging() {
    if (PRODUCTION_CONFIG.LOGGING.ENABLED) {
        // Rediriger console.log vers un système de logs
        const originalLog = console.log;
        console.log = function(...args) {
            originalLog.apply(console, args);
            // Ici on pourrait ajouter la logique pour sauvegarder les logs
        };
        console.log('✅ Système de logs configuré');
    }
}

// Fonction pour configurer les notifications
function setupNotifications() {
    if (PRODUCTION_CONFIG.NOTIFICATIONS.ENABLED) {
        // Demander la permission pour les notifications
        if ('Notification' in window) {
            Notification.requestPermission().then(permission => {
                if (permission === 'granted') {
                    console.log('✅ Notifications activées');
                } else {
                    console.log('⚠️ Notifications non autorisées');
                }
            });
        }
    }
}

// Fonction pour obtenir un paramètre de configuration
function getProductionConfig(path) {
    return path.split('.').reduce((obj, key) => obj && obj[key], PRODUCTION_CONFIG);
}

// Fonction pour définir un paramètre de configuration
function setProductionConfig(path, value) {
    const keys = path.split('.');
    const lastKey = keys.pop();
    const obj = keys.reduce((o, key) => o[key] = o[key] || {}, PRODUCTION_CONFIG);
    obj[lastKey] = value;
}

// Fonction pour envoyer une notification
function sendNotification(title, message, type = 'info') {
    if (PRODUCTION_CONFIG.NOTIFICATIONS.ENABLED) {
        if ('Notification' in window && Notification.permission === 'granted') {
            new Notification(title, {
                body: message,
                icon: '/favicon.ico'
            });
        }
        
        // Notification sonore
        if (PRODUCTION_CONFIG.NOTIFICATIONS.SOUND) {
            // Ici on pourrait ajouter un son de notification
        }
    }
}

// Fonction pour sauvegarder un rapport
function saveReport(data, format = 'JSON') {
    if (PRODUCTION_CONFIG.REPORTING.AUTO_GENERATE) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const filename = `threathunter_report_${timestamp}.${format.toLowerCase()}`;
        
        let content = '';
        if (format === 'JSON') {
            content = JSON.stringify(data, null, 2);
        } else if (format === 'CSV') {
            content = generateCSV(data);
        }
        
        const blob = new Blob([content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        
        URL.revokeObjectURL(url);
        
        console.log(`📄 Rapport sauvegardé: ${filename}`);
    }
}

// Fonction pour générer un CSV
function generateCSV(data) {
    const headers = ['Nom', 'Taille', 'Type', 'Status', 'Score de Risque', 'Hash', 'Timestamp'];
    const rows = data.map(file => [
        file.name,
        file.size,
        file.type,
        file.status,
        file.riskScore,
        file.hash,
        file.timestamp
    ]);
    
    return [headers, ...rows].map(row => row.join(',')).join('\n');
}

// Export des fonctions
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        PRODUCTION_CONFIG,
        initializeProductionConfig,
        getProductionConfig,
        setProductionConfig,
        sendNotification,
        saveReport
    };
} 