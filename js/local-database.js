// Base de données locale pour Lynx
// Stockage des signatures personnalisées et données persistantes

class LocalDatabase {
    constructor() {
        this.dbName = 'LynxDatabase';
        this.version = 1;
        this.db = null;
        this.isInitialized = false;
    }

    // Initialiser la base de données
    async initialize() {
        try {
            console.log('🗄️ Initialisation de la base de données locale...');
            
            // Vérifier si IndexedDB est disponible
            if (!window.indexedDB) {
                console.warn('⚠️ IndexedDB non disponible, utilisation du localStorage');
                this.useLocalStorage = true;
                this.isInitialized = true;
                return;
            }
            
            // Ouvrir la base de données
            const request = indexedDB.open(this.dbName, this.version);
            
            request.onerror = (event) => {
                console.error('❌ Erreur ouverture base de données:', event.target.error);
                this.useLocalStorage = true;
                this.isInitialized = true;
            };
            
            request.onsuccess = (event) => {
                this.db = event.target.result;
                this.isInitialized = true;
                console.log('✅ Base de données locale initialisée');
            };
            
            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                
                // Créer les stores
                this.createStores(db);
            };
            
        } catch (error) {
            console.error('❌ Erreur initialisation base de données:', error);
            this.useLocalStorage = true;
            this.isInitialized = true;
        }
    }

    // Créer les stores de la base de données
    createStores(db) {
        // Store des signatures
        if (!db.objectStoreNames.contains('signatures')) {
            const signatureStore = db.createObjectStore('signatures', { keyPath: 'id', autoIncrement: true });
            signatureStore.createIndex('name', 'name', { unique: false });
            signatureStore.createIndex('category', 'category', { unique: false });
            signatureStore.createIndex('enabled', 'enabled', { unique: false });
        }
        
        // Store des analyses
        if (!db.objectStoreNames.contains('analyses')) {
            const analysisStore = db.createObjectStore('analyses', { keyPath: 'id', autoIncrement: true });
            analysisStore.createIndex('fileName', 'fileName', { unique: false });
            analysisStore.createIndex('timestamp', 'timestamp', { unique: false });
            analysisStore.createIndex('status', 'status', { unique: false });
        }
        
        // Store des plugins
        if (!db.objectStoreNames.contains('plugins')) {
            const pluginStore = db.createObjectStore('plugins', { keyPath: 'id' });
            pluginStore.createIndex('enabled', 'enabled', { unique: false });
            pluginStore.createIndex('category', 'category', { unique: false });
        }
        
        // Store des configurations
        if (!db.objectStoreNames.contains('configurations')) {
            const configStore = db.createObjectStore('configurations', { keyPath: 'key' });
        }
        
        // Store des rapports
        if (!db.objectStoreNames.contains('reports')) {
            const reportStore = db.createObjectStore('reports', { keyPath: 'id', autoIncrement: true });
            reportStore.createIndex('type', 'type', { unique: false });
            reportStore.createIndex('timestamp', 'timestamp', { unique: false });
        }
        
        console.log('📦 Stores de base de données créés');
    }

    // Gestion des signatures
    async addSignature(signature) {
        const signatureData = {
            name: signature.name,
            pattern: signature.pattern,
            category: signature.category || 'custom',
            description: signature.description || '',
            enabled: signature.enabled !== false,
            confidence: signature.confidence || 0.7,
            severity: signature.severity || 'MEDIUM',
            tags: signature.tags || [],
            createdBy: signature.createdBy || 'user',
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };

        if (this.useLocalStorage) {
            return this.addSignatureToLocalStorage(signatureData);
        } else {
            return this.addSignatureToIndexedDB(signatureData);
        }
    }

    async getSignatures(filters = {}) {
        if (this.useLocalStorage) {
            return this.getSignaturesFromLocalStorage(filters);
        } else {
            return this.getSignaturesFromIndexedDB(filters);
        }
    }

    async updateSignature(id, updates) {
        if (this.useLocalStorage) {
            return this.updateSignatureInLocalStorage(id, updates);
        } else {
            return this.updateSignatureInIndexedDB(id, updates);
        }
    }

    async deleteSignature(id) {
        if (this.useLocalStorage) {
            return this.deleteSignatureFromLocalStorage(id);
        } else {
            return this.deleteSignatureFromIndexedDB(id);
        }
    }

    // Gestion des analyses
    async saveAnalysis(analysis) {
        const analysisData = {
            fileName: analysis.fileName,
            fileSize: analysis.fileSize,
            fileType: analysis.fileType,
            status: analysis.status,
            riskScore: analysis.riskScore,
            details: analysis.details,
            timestamp: analysis.timestamp || new Date().toISOString(),
            hash: analysis.hash || '',
            analysisTime: analysis.analysisTime || 0
        };

        if (this.useLocalStorage) {
            return this.saveAnalysisToLocalStorage(analysisData);
        } else {
            return this.saveAnalysisToIndexedDB(analysisData);
        }
    }

    async getAnalyses(filters = {}) {
        if (this.useLocalStorage) {
            return this.getAnalysesFromLocalStorage(filters);
        } else {
            return this.getAnalysesFromIndexedDB(filters);
        }
    }

    // Gestion des plugins
    async savePlugin(plugin) {
        const pluginData = {
            id: plugin.id,
            name: plugin.name,
            version: plugin.version,
            description: plugin.description,
            author: plugin.author,
            enabled: plugin.enabled,
            config: plugin.config || {},
            category: plugin.category || 'general',
            installTime: plugin.installTime || new Date().toISOString(),
            lastUpdate: new Date().toISOString()
        };

        if (this.useLocalStorage) {
            return this.savePluginToLocalStorage(pluginData);
        } else {
            return this.savePluginToIndexedDB(pluginData);
        }
    }

    async getPlugins(filters = {}) {
        if (this.useLocalStorage) {
            return this.getPluginsFromLocalStorage(filters);
        } else {
            return this.getPluginsFromIndexedDB(filters);
        }
    }

    // Gestion des configurations
    async saveConfiguration(key, value) {
        const configData = {
            key: key,
            value: value,
            timestamp: new Date().toISOString()
        };

        if (this.useLocalStorage) {
            return this.saveConfigurationToLocalStorage(configData);
        } else {
            return this.saveConfigurationToIndexedDB(configData);
        }
    }

    async getConfiguration(key) {
        if (this.useLocalStorage) {
            return this.getConfigurationFromLocalStorage(key);
        } else {
            return this.getConfigurationFromIndexedDB(key);
        }
    }

    // Gestion des rapports
    async saveReport(report) {
        const reportData = {
            type: report.type,
            title: report.title,
            content: report.content,
            format: report.format || 'json',
            timestamp: report.timestamp || new Date().toISOString(),
            analysisIds: report.analysisIds || [],
            metadata: report.metadata || {}
        };

        if (this.useLocalStorage) {
            return this.saveReportToLocalStorage(reportData);
        } else {
            return this.saveReportToIndexedDB(reportData);
        }
    }

    async getReports(filters = {}) {
        if (this.useLocalStorage) {
            return this.getReportsFromLocalStorage(filters);
        } else {
            return this.getReportsFromIndexedDB(filters);
        }
    }

    // Méthodes localStorage (fallback)
    addSignatureToLocalStorage(signatureData) {
        try {
            const signatures = JSON.parse(localStorage.getItem('lynxSignatures') || '[]');
            signatureData.id = Date.now();
            signatures.push(signatureData);
            localStorage.setItem('lynxSignatures', JSON.stringify(signatures));
            return signatureData.id;
        } catch (error) {
            console.error('❌ Erreur ajout signature localStorage:', error);
            throw error;
        }
    }

    getSignaturesFromLocalStorage(filters) {
        try {
            let signatures = JSON.parse(localStorage.getItem('lynxSignatures') || '[]');
            
            // Appliquer les filtres
            if (filters.category) {
                signatures = signatures.filter(s => s.category === filters.category);
            }
            if (filters.enabled !== undefined) {
                signatures = signatures.filter(s => s.enabled === filters.enabled);
            }
            if (filters.search) {
                const search = filters.search.toLowerCase();
                signatures = signatures.filter(s => 
                    s.name.toLowerCase().includes(search) ||
                    s.description.toLowerCase().includes(search)
                );
            }
            
            return signatures;
        } catch (error) {
            console.error('❌ Erreur récupération signatures localStorage:', error);
            return [];
        }
    }

    updateSignatureInLocalStorage(id, updates) {
        try {
            const signatures = JSON.parse(localStorage.getItem('lynxSignatures') || '[]');
            const index = signatures.findIndex(s => s.id === id);
            
            if (index !== -1) {
                signatures[index] = { ...signatures[index], ...updates, updatedAt: new Date().toISOString() };
                localStorage.setItem('lynxSignatures', JSON.stringify(signatures));
                return true;
            }
            
            return false;
        } catch (error) {
            console.error('❌ Erreur mise à jour signature localStorage:', error);
            return false;
        }
    }

    deleteSignatureFromLocalStorage(id) {
        try {
            const signatures = JSON.parse(localStorage.getItem('lynxSignatures') || '[]');
            const filteredSignatures = signatures.filter(s => s.id !== id);
            localStorage.setItem('lynxSignatures', JSON.stringify(filteredSignatures));
            return true;
        } catch (error) {
            console.error('❌ Erreur suppression signature localStorage:', error);
            return false;
        }
    }

    saveAnalysisToLocalStorage(analysisData) {
        try {
            const analyses = JSON.parse(localStorage.getItem('lynxAnalyses') || '[]');
            analysisData.id = Date.now();
            analyses.push(analysisData);
            
            // Limiter à 1000 analyses
            if (analyses.length > 1000) {
                analyses.splice(0, analyses.length - 1000);
            }
            
            localStorage.setItem('lynxAnalyses', JSON.stringify(analyses));
            return analysisData.id;
        } catch (error) {
            console.error('❌ Erreur sauvegarde analyse localStorage:', error);
            throw error;
        }
    }

    getAnalysesFromLocalStorage(filters) {
        try {
            let analyses = JSON.parse(localStorage.getItem('lynxAnalyses') || '[]');
            
            // Appliquer les filtres
            if (filters.status) {
                analyses = analyses.filter(a => a.status === filters.status);
            }
            if (filters.dateFrom) {
                analyses = analyses.filter(a => new Date(a.timestamp) >= new Date(filters.dateFrom));
            }
            if (filters.dateTo) {
                analyses = analyses.filter(a => new Date(a.timestamp) <= new Date(filters.dateTo));
            }
            
            // Trier par date (plus récent en premier)
            analyses.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
            
            return analyses;
        } catch (error) {
            console.error('❌ Erreur récupération analyses localStorage:', error);
            return [];
        }
    }

    savePluginToLocalStorage(pluginData) {
        try {
            const plugins = JSON.parse(localStorage.getItem('lynxPlugins') || '[]');
            const index = plugins.findIndex(p => p.id === pluginData.id);
            
            if (index !== -1) {
                plugins[index] = pluginData;
            } else {
                plugins.push(pluginData);
            }
            
            localStorage.setItem('lynxPlugins', JSON.stringify(plugins));
            return pluginData.id;
        } catch (error) {
            console.error('❌ Erreur sauvegarde plugin localStorage:', error);
            throw error;
        }
    }

    getPluginsFromLocalStorage(filters) {
        try {
            let plugins = JSON.parse(localStorage.getItem('lynxPlugins') || '[]');
            
            // Appliquer les filtres
            if (filters.enabled !== undefined) {
                plugins = plugins.filter(p => p.enabled === filters.enabled);
            }
            if (filters.category) {
                plugins = plugins.filter(p => p.category === filters.category);
            }
            
            return plugins;
        } catch (error) {
            console.error('❌ Erreur récupération plugins localStorage:', error);
            return [];
        }
    }

    saveConfigurationToLocalStorage(configData) {
        try {
            const configs = JSON.parse(localStorage.getItem('lynxConfigurations') || '{}');
            configs[configData.key] = configData;
            localStorage.setItem('lynxConfigurations', JSON.stringify(configs));
            return configData.key;
        } catch (error) {
            console.error('❌ Erreur sauvegarde configuration localStorage:', error);
            throw error;
        }
    }

    getConfigurationFromLocalStorage(key) {
        try {
            const configs = JSON.parse(localStorage.getItem('lynxConfigurations') || '{}');
            return configs[key] ? configs[key].value : null;
        } catch (error) {
            console.error('❌ Erreur récupération configuration localStorage:', error);
            return null;
        }
    }

    saveReportToLocalStorage(reportData) {
        try {
            const reports = JSON.parse(localStorage.getItem('lynxReports') || '[]');
            reportData.id = Date.now();
            reports.push(reportData);
            
            // Limiter à 100 rapports
            if (reports.length > 100) {
                reports.splice(0, reports.length - 100);
            }
            
            localStorage.setItem('lynxReports', JSON.stringify(reports));
            return reportData.id;
        } catch (error) {
            console.error('❌ Erreur sauvegarde rapport localStorage:', error);
            throw error;
        }
    }

    getReportsFromLocalStorage(filters) {
        try {
            let reports = JSON.parse(localStorage.getItem('lynxReports') || '[]');
            
            // Appliquer les filtres
            if (filters.type) {
                reports = reports.filter(r => r.type === filters.type);
            }
            if (filters.dateFrom) {
                reports = reports.filter(r => new Date(r.timestamp) >= new Date(filters.dateFrom));
            }
            if (filters.dateTo) {
                reports = reports.filter(r => new Date(r.timestamp) <= new Date(filters.dateTo));
            }
            
            // Trier par date (plus récent en premier)
            reports.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
            
            return reports;
        } catch (error) {
            console.error('❌ Erreur récupération rapports localStorage:', error);
            return [];
        }
    }

    // Méthodes IndexedDB
    addSignatureToIndexedDB(signatureData) {
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction(['signatures'], 'readwrite');
            const store = transaction.objectStore('signatures');
            const request = store.add(signatureData);
            
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    getSignaturesFromIndexedDB(filters) {
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction(['signatures'], 'readonly');
            const store = transaction.objectStore('signatures');
            const request = store.getAll();
            
            request.onsuccess = () => {
                let signatures = request.result;
                
                // Appliquer les filtres
                if (filters.category) {
                    signatures = signatures.filter(s => s.category === filters.category);
                }
                if (filters.enabled !== undefined) {
                    signatures = signatures.filter(s => s.enabled === filters.enabled);
                }
                
                resolve(signatures);
            };
            
            request.onerror = () => reject(request.error);
        });
    }

    updateSignatureInIndexedDB(id, updates) {
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction(['signatures'], 'readwrite');
            const store = transaction.objectStore('signatures');
            const getRequest = store.get(id);
            
            getRequest.onsuccess = () => {
                const signature = getRequest.result;
                if (signature) {
                    const updatedSignature = { ...signature, ...updates, updatedAt: new Date().toISOString() };
                    const putRequest = store.put(updatedSignature);
                    
                    putRequest.onsuccess = () => resolve(true);
                    putRequest.onerror = () => reject(putRequest.error);
                } else {
                    resolve(false);
                }
            };
            
            getRequest.onerror = () => reject(getRequest.error);
        });
    }

    deleteSignatureFromIndexedDB(id) {
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction(['signatures'], 'readwrite');
            const store = transaction.objectStore('signatures');
            const request = store.delete(id);
            
            request.onsuccess = () => resolve(true);
            request.onerror = () => reject(request.error);
        });
    }

    // Statistiques de la base de données
    async getDatabaseStats() {
        const stats = {
            signatures: 0,
            analyses: 0,
            plugins: 0,
            reports: 0,
            configurations: 0,
            totalSize: 0
        };

        try {
            if (this.useLocalStorage) {
                stats.signatures = JSON.parse(localStorage.getItem('lynxSignatures') || '[]').length;
                stats.analyses = JSON.parse(localStorage.getItem('lynxAnalyses') || '[]').length;
                stats.plugins = JSON.parse(localStorage.getItem('lynxPlugins') || '[]').length;
                stats.reports = JSON.parse(localStorage.getItem('lynxReports') || '[]').length;
                stats.configurations = Object.keys(JSON.parse(localStorage.getItem('lynxConfigurations') || '{}')).length;
            } else {
                // Statistiques IndexedDB
                const stores = ['signatures', 'analyses', 'plugins', 'reports', 'configurations'];
                for (const storeName of stores) {
                    const count = await this.getStoreCount(storeName);
                    stats[storeName] = count;
                }
            }

            // Calculer la taille approximative
            stats.totalSize = this.calculateDatabaseSize();

        } catch (error) {
            console.error('❌ Erreur calcul statistiques base de données:', error);
        }

        return stats;
    }

    // Obtenir le nombre d'éléments dans un store
    async getStoreCount(storeName) {
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction([storeName], 'readonly');
            const store = transaction.objectStore(storeName);
            const request = store.count();
            
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    // Calculer la taille de la base de données
    calculateDatabaseSize() {
        let size = 0;
        
        try {
            if (this.useLocalStorage) {
                const keys = ['lynxSignatures', 'lynxAnalyses', 'lynxPlugins', 'lynxReports', 'lynxConfigurations'];
                keys.forEach(key => {
                    const data = localStorage.getItem(key);
                    if (data) {
                        size += new Blob([data]).size;
                    }
                });
            }
        } catch (error) {
            console.error('❌ Erreur calcul taille base de données:', error);
        }
        
        return size;
    }

    // Nettoyer la base de données
    async cleanupDatabase(options = {}) {
        const { keepDays = 30, maxAnalyses = 1000, maxReports = 100 } = options;
        
        try {
            console.log('🧹 Nettoyage de la base de données...');
            
            const cutoffDate = new Date();
            cutoffDate.setDate(cutoffDate.getDate() - keepDays);
            
            if (this.useLocalStorage) {
                // Nettoyer les analyses anciennes
                const analyses = JSON.parse(localStorage.getItem('lynxAnalyses') || '[]');
                const recentAnalyses = analyses.filter(a => new Date(a.timestamp) > cutoffDate);
                if (recentAnalyses.length > maxAnalyses) {
                    recentAnalyses.splice(0, recentAnalyses.length - maxAnalyses);
                }
                localStorage.setItem('lynxAnalyses', JSON.stringify(recentAnalyses));
                
                // Nettoyer les rapports anciens
                const reports = JSON.parse(localStorage.getItem('lynxReports') || '[]');
                const recentReports = reports.filter(r => new Date(r.timestamp) > cutoffDate);
                if (recentReports.length > maxReports) {
                    recentReports.splice(0, recentReports.length - maxReports);
                }
                localStorage.setItem('lynxReports', JSON.stringify(recentReports));
                
            } else {
                // Nettoyage IndexedDB
                await this.cleanupIndexedDB(cutoffDate, maxAnalyses, maxReports);
            }
            
            console.log('✅ Nettoyage de la base de données terminé');
            
        } catch (error) {
            console.error('❌ Erreur nettoyage base de données:', error);
        }
    }

    // Nettoyer IndexedDB
    async cleanupIndexedDB(cutoffDate, maxAnalyses, maxReports) {
        // Nettoyer les analyses
        const analyses = await this.getAnalysesFromIndexedDB({});
        const recentAnalyses = analyses.filter(a => new Date(a.timestamp) > cutoffDate);
        
        if (recentAnalyses.length > maxAnalyses) {
            const toDelete = recentAnalyses.slice(0, recentAnalyses.length - maxAnalyses);
            for (const analysis of toDelete) {
                await this.deleteAnalysisFromIndexedDB(analysis.id);
            }
        }
        
        // Nettoyer les rapports
        const reports = await this.getReportsFromIndexedDB({});
        const recentReports = reports.filter(r => new Date(r.timestamp) > cutoffDate);
        
        if (recentReports.length > maxReports) {
            const toDelete = recentReports.slice(0, recentReports.length - maxReports);
            for (const report of toDelete) {
                await this.deleteReportFromIndexedDB(report.id);
            }
        }
    }

    // Méthodes IndexedDB manquantes (simulation)
    async getAnalysesFromIndexedDB(filters) {
        return [];
    }

    async deleteAnalysisFromIndexedDB(id) {
        return true;
    }

    async getReportsFromIndexedDB(filters) {
        return [];
    }

    async deleteReportFromIndexedDB(id) {
        return true;
    }
}

// Export pour utilisation
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { LocalDatabase };
} 