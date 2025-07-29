// Configuration avancée pour Lynx
// Interface de personnalisation et paramètres avancés

class AdvancedConfig {
    constructor() {
        this.settings = {
            // Configuration IA
            ai: {
                enableTensorFlow: true,
                enablePhi3: true,
                confidenceThreshold: 0.7,
                maxFileSize: 100 * 1024 * 1024, // 100MB
                enableLearning: true,
                modelUpdateInterval: 24 * 60 * 60 * 1000 // 24h
            },
            
            // Configuration sécurité
            security: {
                enableEncryption: true,
                enableRateLimiting: true,
                maxRequestsPerMinute: 100,
                enableFileValidation: true,
                enableAnomalyDetection: true,
                logRetentionDays: 30
            },
            
            // Configuration analyse
            analysis: {
                enableVirusTotal: true,
                enableYARA: true,
                enableSignatures: true,
                enablePatterns: true,
                enableZIPProcessing: true,
                enableBehavioralAnalysis: true,
                parallelProcessing: true,
                maxConcurrentAnalyses: 5
            },
            
            // Configuration interface
            ui: {
                enableAnimations: true,
                enableRealTimeUpdates: true,
                enableDarkMode: false,
                enableNotifications: true,
                language: 'fr',
                theme: 'glassmorphic'
            },
            
            // Configuration rapports
            reporting: {
                enableAutoReports: false,
                reportFormat: 'pdf',
                enableIOCExtraction: true,
                enableTimeline: true,
                enableStatistics: true
            }
        };
        
        this.loadSettings();
    }

    // Charger les paramètres depuis localStorage
    loadSettings() {
        try {
            const savedSettings = localStorage.getItem('lynxAdvancedConfig');
            if (savedSettings) {
                const parsed = JSON.parse(savedSettings);
                this.settings = { ...this.settings, ...parsed };
                console.log('✅ Configuration avancée chargée');
            }
        } catch (error) {
            console.warn('⚠️ Erreur chargement configuration, utilisation des valeurs par défaut');
        }
    }

    // Sauvegarder les paramètres
    saveSettings() {
        try {
            localStorage.setItem('lynxAdvancedConfig', JSON.stringify(this.settings));
            console.log('💾 Configuration avancée sauvegardée');
        } catch (error) {
            console.error('❌ Erreur sauvegarde configuration:', error);
        }
    }

    // Mettre à jour un paramètre
    updateSetting(category, key, value) {
        if (this.settings[category] && this.settings[category].hasOwnProperty(key)) {
            this.settings[category][key] = value;
            this.saveSettings();
            console.log(`⚙️ Paramètre mis à jour: ${category}.${key} = ${value}`);
            return true;
        }
        return false;
    }

    // Obtenir un paramètre
    getSetting(category, key) {
        return this.settings[category]?.[key];
    }

    // Réinitialiser aux valeurs par défaut
    resetToDefaults() {
        this.settings = {
            ai: {
                enableTensorFlow: true,
                enablePhi3: true,
                confidenceThreshold: 0.7,
                maxFileSize: 100 * 1024 * 1024,
                enableLearning: true,
                modelUpdateInterval: 24 * 60 * 60 * 1000
            },
            security: {
                enableEncryption: true,
                enableRateLimiting: true,
                maxRequestsPerMinute: 100,
                enableFileValidation: true,
                enableAnomalyDetection: true,
                logRetentionDays: 30
            },
            analysis: {
                enableVirusTotal: true,
                enableYARA: true,
                enableSignatures: true,
                enablePatterns: true,
                enableZIPProcessing: true,
                enableBehavioralAnalysis: true,
                parallelProcessing: true,
                maxConcurrentAnalyses: 5
            },
            ui: {
                enableAnimations: true,
                enableRealTimeUpdates: true,
                enableDarkMode: false,
                enableNotifications: true,
                language: 'fr',
                theme: 'glassmorphic'
            },
            reporting: {
                enableAutoReports: false,
                reportFormat: 'pdf',
                enableIOCExtraction: true,
                enableTimeline: true,
                enableStatistics: true
            }
        };
        
        this.saveSettings();
        console.log('🔄 Configuration réinitialisée aux valeurs par défaut');
    }

    // Exporter la configuration
    exportConfig() {
        const config = {
            version: '1.0.0',
            timestamp: new Date().toISOString(),
            settings: this.settings
        };
        
        const blob = new Blob([JSON.stringify(config, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        
        const link = document.createElement('a');
        link.href = url;
        link.download = `lynx-config-${new Date().toISOString().split('T')[0]}.json`;
        link.click();
        
        URL.revokeObjectURL(url);
    }

    // Importer la configuration
    importConfig(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => {
                try {
                    const config = JSON.parse(e.target.result);
                    if (config.settings) {
                        this.settings = { ...this.settings, ...config.settings };
                        this.saveSettings();
                        console.log('✅ Configuration importée avec succès');
                        resolve(true);
                    } else {
                        reject(new Error('Format de configuration invalide'));
                    }
                } catch (error) {
                    reject(new Error('Erreur de parsing du fichier de configuration'));
                }
            };
            reader.onerror = () => reject(new Error('Erreur de lecture du fichier'));
            reader.readAsText(file);
        });
    }

    // Validation de la configuration
    validateConfig() {
        const errors = [];
        
        // Vérifier les seuils de confiance
        if (this.settings.ai.confidenceThreshold < 0 || this.settings.ai.confidenceThreshold > 1) {
            errors.push('Seuil de confiance IA invalide (doit être entre 0 et 1)');
        }
        
        // Vérifier la taille maximale des fichiers
        if (this.settings.ai.maxFileSize <= 0) {
            errors.push('Taille maximale des fichiers invalide');
        }
        
        // Vérifier le rate limiting
        if (this.settings.security.maxRequestsPerMinute <= 0) {
            errors.push('Limite de requêtes invalide');
        }
        
        // Vérifier la rétention des logs
        if (this.settings.security.logRetentionDays < 1) {
            errors.push('Rétention des logs invalide');
        }
        
        return {
            isValid: errors.length === 0,
            errors: errors
        };
    }

    // Obtenir des statistiques de configuration
    getConfigStats() {
        const stats = {
            totalSettings: 0,
            enabledFeatures: 0,
            disabledFeatures: 0,
            categories: Object.keys(this.settings).length
        };
        
        Object.values(this.settings).forEach(category => {
            Object.values(category).forEach(value => {
                stats.totalSettings++;
                if (typeof value === 'boolean') {
                    if (value) stats.enabledFeatures++;
                    else stats.disabledFeatures++;
                }
            });
        });
        
        return stats;
    }

    // Appliquer la configuration au système
    applyConfiguration() {
        console.log('🔧 Application de la configuration avancée...');
        
        // Appliquer les paramètres IA
        if (aiEngine) {
            aiEngine.confidenceThreshold = this.settings.ai.confidenceThreshold;
            aiEngine.maxFileSize = this.settings.ai.maxFileSize;
        }
        
        // Appliquer les paramètres de sécurité
        if (devSecOpsConfig) {
            devSecOpsConfig.securitySettings.rateLimiting.maxRequestsPerMinute = 
                this.settings.security.maxRequestsPerMinute;
            devSecOpsConfig.securitySettings.securityLogging.logRetention = 
                this.settings.security.logRetentionDays;
        }
        
        // Appliquer les paramètres d'interface
        this.applyUISettings();
        
        console.log('✅ Configuration appliquée avec succès');
    }

    // Appliquer les paramètres d'interface
    applyUISettings() {
        const body = document.body;
        
        // Mode sombre
        if (this.settings.ui.enableDarkMode) {
            body.classList.add('dark-mode');
        } else {
            body.classList.remove('dark-mode');
        }
        
        // Animations
        if (!this.settings.ui.enableAnimations) {
            body.classList.add('no-animations');
        } else {
            body.classList.remove('no-animations');
        }
        
        // Notifications
        if (this.settings.ui.enableNotifications) {
            this.enableNotifications();
        } else {
            this.disableNotifications();
        }
    }

    // Activer les notifications
    enableNotifications() {
        if ('Notification' in window) {
            Notification.requestPermission().then(permission => {
                if (permission === 'granted') {
                    console.log('🔔 Notifications activées');
                }
            });
        }
    }

    // Désactiver les notifications
    disableNotifications() {
        console.log('🔕 Notifications désactivées');
    }

    // Envoyer une notification
    sendNotification(title, message) {
        if (this.settings.ui.enableNotifications && 'Notification' in window) {
            if (Notification.permission === 'granted') {
                new Notification(title, {
                    body: message,
                    icon: '/favicon.ico'
                });
            }
        }
    }

    // Obtenir la configuration pour l'export
    getConfigForExport() {
        return {
            version: '1.0.0',
            timestamp: new Date().toISOString(),
            settings: this.settings,
            stats: this.getConfigStats(),
            validation: this.validateConfig()
        };
    }
}

// Export pour utilisation
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { AdvancedConfig };
} 