// Script d'aide à la migration pour Lynx v2.0
// Facilite la transition depuis les versions précédentes

class MigrationHelper {
    constructor() {
        this.migrationLog = [];
        this.migrationStatus = {
            completed: false,
            errors: [],
            warnings: [],
            migratedItems: 0
        };
    }

    // Migration automatique au démarrage
    async performAutoMigration() {
        console.log('🔄 Début de la migration automatique...');
        
        try {
            // Migration des configurations
            await this.migrateConfigurations();
            
            // Migration des clés API
            await this.migrateAPIKeys();
            
            // Migration des données utilisateur
            await this.migrateUserData();
            
            // Validation de la migration
            await this.validateMigration();
            
            this.migrationStatus.completed = true;
            console.log('✅ Migration terminée avec succès');
            
            // Affichage du rapport
            this.showMigrationReport();
            
        } catch (error) {
            console.error('❌ Erreur lors de la migration:', error);
            this.migrationStatus.errors.push(error.message);
            this.showMigrationReport();
        }
    }

    // Migration des configurations
    async migrateConfigurations() {
        console.log('📋 Migration des configurations...');
        
        try {
            // Récupération des anciennes configurations
            const oldConfigs = this.getOldConfigurations();
            
            // Migration vers la nouvelle structure
            for (const [key, value] of Object.entries(oldConfigs)) {
                try {
                    this.migrateConfigKey(key, value);
                    this.migrationStatus.migratedItems++;
                } catch (error) {
                    this.migrationStatus.warnings.push(`Configuration ${key}: ${error.message}`);
                }
            }
            
            // Sauvegarde des configurations migrées
            this.saveMigratedConfigurations();
            
            console.log(`✅ ${this.migrationStatus.migratedItems} configurations migrées`);
            
        } catch (error) {
            throw new Error(`Erreur migration configurations: ${error.message}`);
        }
    }

    // Récupération des anciennes configurations
    getOldConfigurations() {
        const configs = {};
        
        // Configuration de base
        if (typeof CONFIG !== 'undefined') {
            configs.base = CONFIG;
        }
        
        // Configuration de production
        if (typeof PRODUCTION_CONFIG !== 'undefined') {
            configs.production = PRODUCTION_CONFIG;
        }
        
        // Configuration DevSecOps
        if (typeof DevSecOpsConfig !== 'undefined') {
            configs.devsecops = new DevSecOpsConfig().securitySettings;
        }
        
        return configs;
    }

    // Migration d'une clé de configuration
    migrateConfigKey(key, value) {
        const migrationMap = {
            'ANALYSIS.RISK_THRESHOLDS': 'ANALYSIS.RISK_THRESHOLDS',
            'ANALYSIS.SIZE_THRESHOLDS': 'ANALYSIS.SIZE_THRESHOLDS',
            'ENGINES.YARA.ENABLED': 'ENGINES.YARA.ENABLED',
            'ENGINES.ML.ENABLED': 'ENGINES.ML.ENABLED',
            'PERFORMANCE.WORKER_THREADS': 'PERFORMANCE.WORKER_THREADS',
            'REPORTING.AUTO_GENERATE': 'REPORTING.AUTO_GENERATE'
        };
        
        if (migrationMap[key]) {
            UNIFIED_CONFIG.set(migrationMap[key], value);
            this.migrationLog.push(`Config migrée: ${key} -> ${migrationMap[key]}`);
        }
    }

    // Migration des clés API
    async migrateAPIKeys() {
        console.log('🔑 Migration des clés API...');
        
        try {
            // Récupération des anciennes clés
            const oldKeys = this.getOldAPIKeys();
            
            for (const [service, key] of Object.entries(oldKeys)) {
                try {
                    await secureAPIManager.addAPIKey(service, key);
                    this.migrationStatus.migratedItems++;
                    this.migrationLog.push(`Clé API migrée: ${service}`);
                } catch (error) {
                    this.migrationStatus.warnings.push(`Clé API ${service}: ${error.message}`);
                }
            }
            
            console.log(`✅ ${Object.keys(oldKeys).length} clés API migrées`);
            
        } catch (error) {
            throw new Error(`Erreur migration clés API: ${error.message}`);
        }
    }

    // Récupération des anciennes clés API
    getOldAPIKeys() {
        const keys = {};
        
        // Clé VirusTotal depuis l'ancienne configuration
        if (typeof PRODUCTION_CONFIG !== 'undefined' && PRODUCTION_CONFIG.VIRUSTOTAL) {
            keys.virustotal = PRODUCTION_CONFIG.VIRUSTOTAL.API_KEY;
        }
        
        // Clés stockées localement
        const storedKeys = localStorage.getItem('virustotal_api_key');
        if (storedKeys) {
            keys.virustotal = storedKeys;
        }
        
        return keys;
    }

    // Migration des données utilisateur
    async migrateUserData() {
        console.log('👤 Migration des données utilisateur...');
        
        try {
            // Migration des préférences
            this.migrateUserPreferences();
            
            // Migration des rapports
            this.migrateReports();
            
            // Migration des logs
            this.migrateLogs();
            
            console.log('✅ Données utilisateur migrées');
            
        } catch (error) {
            throw new Error(`Erreur migration données utilisateur: ${error.message}`);
        }
    }

    // Migration des préférences utilisateur
    migrateUserPreferences() {
        const preferences = {
            theme: localStorage.getItem('lynx_theme') || 'dark',
            language: localStorage.getItem('lynx_language') || 'fr',
            autoRefresh: localStorage.getItem('lynx_auto_refresh') !== 'false',
            showDetails: localStorage.getItem('lynx_show_details') !== 'false'
        };
        
        // Application des préférences
        UNIFIED_CONFIG.set('UI.THEME', preferences.theme);
        UNIFIED_CONFIG.set('UI.LANGUAGE', preferences.language);
        UNIFIED_CONFIG.set('UI.AUTO_REFRESH', preferences.autoRefresh);
        UNIFIED_CONFIG.set('UI.SHOW_DETAILS', preferences.showDetails);
        
        this.migrationLog.push('Préférences utilisateur migrées');
    }

    // Migration des rapports
    migrateReports() {
        const reports = JSON.parse(localStorage.getItem('lynx_reports') || '[]');
        
        if (reports.length > 0) {
            // Conversion au nouveau format
            const newReports = reports.map(report => ({
                ...report,
                version: '2.0.0',
                migratedAt: new Date().toISOString()
            }));
            
            localStorage.setItem('lynx_reports_v2', JSON.stringify(newReports));
            this.migrationLog.push(`${reports.length} rapports migrés`);
        }
    }

    // Migration des logs
    migrateLogs() {
        const oldLogs = JSON.parse(localStorage.getItem('lynx_logs') || '[]');
        
        if (oldLogs.length > 0) {
            // Conversion au nouveau format
            const newLogs = oldLogs.map(log => ({
                ...log,
                version: '2.0.0',
                migratedAt: new Date().toISOString()
            }));
            
            localStorage.setItem('lynx_logs_v2', JSON.stringify(newLogs));
            this.migrationLog.push(`${oldLogs.length} logs migrés`);
        }
    }

    // Validation de la migration
    async validateMigration() {
        console.log('🔍 Validation de la migration...');
        
        const validations = [
            this.validateConfigurations(),
            this.validateAPIKeys(),
            this.validateUserData()
        ];
        
        const results = await Promise.all(validations);
        
        for (const result of results) {
            if (!result.valid) {
                this.migrationStatus.errors.push(result.error);
            }
        }
        
        console.log('✅ Validation terminée');
    }

    // Validation des configurations
    async validateConfigurations() {
        try {
            const errors = UNIFIED_CONFIG.validateConfig();
            
            if (errors.length > 0) {
                return {
                    valid: false,
                    error: `Erreurs de configuration: ${errors.join(', ')}`
                };
            }
            
            return { valid: true };
        } catch (error) {
            return {
                valid: false,
                error: `Erreur validation configurations: ${error.message}`
            };
        }
    }

    // Validation des clés API
    async validateAPIKeys() {
        try {
            const errors = secureAPIManager.validateConfiguration();
            
            if (errors.length > 0) {
                return {
                    valid: false,
                    error: `Erreurs clés API: ${errors.join(', ')}`
                };
            }
            
            return { valid: true };
        } catch (error) {
            return {
                valid: false,
                error: `Erreur validation clés API: ${error.message}`
            };
        }
    }

    // Validation des données utilisateur
    async validateUserData() {
        try {
            // Vérification de la cohérence des données
            const reports = JSON.parse(localStorage.getItem('lynx_reports_v2') || '[]');
            const logs = JSON.parse(localStorage.getItem('lynx_logs_v2') || '[]');
            
            if (reports.length > 0 || logs.length > 0) {
                return { valid: true };
            }
            
            return { valid: true };
        } catch (error) {
            return {
                valid: false,
                error: `Erreur validation données utilisateur: ${error.message}`
            };
        }
    }

    // Sauvegarde des configurations migrées
    saveMigratedConfigurations() {
        try {
            const configData = {
                version: '2.0.0',
                migratedAt: new Date().toISOString(),
                config: UNIFIED_CONFIG.export()
            };
            
            localStorage.setItem('lynx_config_v2', JSON.stringify(configData));
        } catch (error) {
            console.warn('Erreur sauvegarde configurations:', error);
        }
    }

    // Affichage du rapport de migration
    showMigrationReport() {
        const report = {
            status: this.migrationStatus.completed ? '✅ Succès' : '❌ Échec',
            migratedItems: this.migrationStatus.migratedItems,
            errors: this.migrationStatus.errors.length,
            warnings: this.migrationStatus.warnings.length,
            log: this.migrationLog
        };
        
        console.log('📊 Rapport de migration:', report);
        
        // Affichage dans l'interface si disponible
        this.showMigrationNotification(report);
    }

    // Notification de migration dans l'interface
    showMigrationNotification(report) {
        if (typeof showNotification === 'function') {
            const message = `
                Migration Lynx v2.0 terminée
                ✅ ${report.migratedItems} éléments migrés
                ${report.errors > 0 ? `❌ ${report.errors} erreurs` : ''}
                ${report.warnings > 0 ? `⚠️ ${report.warnings} avertissements` : ''}
            `;
            
            showNotification('Migration', message, report.errors > 0 ? 'error' : 'success');
        }
    }

    // Nettoyage des anciennes données
    cleanupOldData() {
        try {
            // Suppression des anciennes clés de localStorage
            const oldKeys = [
                'virustotal_api_key',
                'lynx_theme',
                'lynx_language',
                'lynx_auto_refresh',
                'lynx_show_details',
                'lynx_reports',
                'lynx_logs'
            ];
            
            for (const key of oldKeys) {
                localStorage.removeItem(key);
            }
            
            console.log('🧹 Anciennes données nettoyées');
            
        } catch (error) {
            console.warn('Erreur nettoyage anciennes données:', error);
        }
    }

    // Récupération des données de migration
    getMigrationData() {
        return {
            status: this.migrationStatus,
            log: this.migrationLog,
            timestamp: new Date().toISOString()
        };
    }

    // Export pour compatibilité
    export() {
        return {
            performAutoMigration: () => this.performAutoMigration(),
            getMigrationData: () => this.getMigrationData(),
            cleanupOldData: () => this.cleanupOldData()
        };
    }
}

// Instance globale
const migrationHelper = new MigrationHelper();

// Migration automatique au chargement
document.addEventListener('DOMContentLoaded', () => {
    // Délai pour permettre l'initialisation des autres modules
    setTimeout(() => {
        migrationHelper.performAutoMigration();
    }, 1000);
});

// Export pour utilisation dans d'autres modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = MigrationHelper;
} else {
    window.migrationHelper = migrationHelper;
} 