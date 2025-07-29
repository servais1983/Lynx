// Système de Plugins pour Lynx
// Architecture extensible pour ajouter de nouvelles fonctionnalités

class PluginSystem {
    constructor() {
        this.plugins = new Map();
        this.hooks = new Map();
        this.api = this.createPluginAPI();
        this.isInitialized = false;
    }

    // Initialiser le système de plugins
    async initialize() {
        try {
            console.log('🔌 Initialisation du système de plugins...');
            
            // Charger les plugins installés
            await this.loadInstalledPlugins();
            
            // Initialiser les hooks
            this.initializeHooks();
            
            // Démarrer tous les plugins
            await this.startAllPlugins();
            
            this.isInitialized = true;
            console.log('✅ Système de plugins initialisé');
            
        } catch (error) {
            console.error('❌ Erreur initialisation plugins:', error);
            throw error;
        }
    }

    // Créer l'API pour les plugins
    createPluginAPI() {
        return {
            // Analyse de fichiers
            analyzeFile: async (file, options) => {
                return await this.executeHook('analyzeFile', { file, options });
            },
            
            // Ajouter des signatures
            addSignature: (signature) => {
                return this.executeHook('addSignature', { signature });
            },
            
            // Notifications
            showNotification: (title, message, options) => {
                if (window.uiManager) {
                    window.uiManager.showNotification(title, message, options);
                }
            },
            
            // Interface utilisateur
            addUIElement: (element, container) => {
                return this.executeHook('addUIElement', { element, container });
            },
            
            // Base de données
            getDatabase: () => {
                return this.getPluginDatabase();
            },
            
            // Configuration
            getConfig: (key) => {
                return this.getPluginConfig(key);
            },
            
            setConfig: (key, value) => {
                return this.setPluginConfig(key, value);
            },
            
            // Logs
            log: (level, message, data) => {
                console.log(`[PLUGIN-${level}] ${message}`, data);
            },
            
            // Utilitaires
            utils: {
                hashFile: async (file) => {
                    return await this.hashFile(file);
                },
                extractStrings: async (file) => {
                    return await this.extractStrings(file);
                },
                validateFile: (file) => {
                    return this.validateFile(file);
                }
            }
        };
    }

    // Initialiser les hooks
    initializeHooks() {
        const defaultHooks = [
            'analyzeFile',
            'addSignature', 
            'addUIElement',
            'onFileUpload',
            'onAnalysisComplete',
            'onThreatDetected',
            'onPluginLoad',
            'onPluginUnload'
        ];
        
        defaultHooks.forEach(hook => {
            this.hooks.set(hook, []);
        });
        
        console.log('🎣 Hooks initialisés');
    }

    // Charger les plugins installés
    async loadInstalledPlugins() {
        try {
            const installedPlugins = localStorage.getItem('lynxInstalledPlugins');
            if (installedPlugins) {
                const plugins = JSON.parse(installedPlugins);
                
                for (const pluginData of plugins) {
                    await this.loadPlugin(pluginData);
                }
            }
        } catch (error) {
            console.warn('⚠️ Erreur chargement plugins:', error);
        }
    }

    // Charger un plugin
    async loadPlugin(pluginData) {
        try {
            const plugin = {
                id: pluginData.id,
                name: pluginData.name,
                version: pluginData.version,
                description: pluginData.description,
                author: pluginData.author,
                enabled: pluginData.enabled || true,
                config: pluginData.config || {},
                hooks: pluginData.hooks || [],
                dependencies: pluginData.dependencies || []
            };
            
            // Vérifier les dépendances
            if (await this.checkDependencies(plugin)) {
                this.plugins.set(plugin.id, plugin);
                console.log(`✅ Plugin chargé: ${plugin.name} v${plugin.version}`);
            } else {
                console.warn(`⚠️ Dépendances manquantes pour ${plugin.name}`);
            }
            
        } catch (error) {
            console.error(`❌ Erreur chargement plugin ${pluginData.name}:`, error);
        }
    }

    // Vérifier les dépendances d'un plugin
    async checkDependencies(plugin) {
        for (const dependency of plugin.dependencies) {
            // Vérifier si la dépendance est disponible
            if (!this.isDependencyAvailable(dependency)) {
                return false;
            }
        }
        return true;
    }

    // Vérifier si une dépendance est disponible
    isDependencyAvailable(dependency) {
        // Vérifier les APIs du navigateur
        if (dependency.startsWith('api:')) {
            const apiName = dependency.substring(4);
            return window[apiName] !== undefined;
        }
        
        // Vérifier les modules Lynx
        if (dependency.startsWith('lynx:')) {
            const moduleName = dependency.substring(5);
            return window[moduleName] !== undefined;
        }
        
        return true;
    }

    // Démarrer tous les plugins
    async startAllPlugins() {
        for (const [id, plugin] of this.plugins) {
            if (plugin.enabled) {
                await this.startPlugin(id);
            }
        }
    }

    // Démarrer un plugin
    async startPlugin(pluginId) {
        const plugin = this.plugins.get(pluginId);
        if (!plugin) {
            throw new Error(`Plugin ${pluginId} non trouvé`);
        }

        try {
            // Exécuter le hook onPluginLoad
            await this.executeHook('onPluginLoad', { plugin });
            
            // Marquer le plugin comme démarré
            plugin.started = true;
            plugin.startTime = new Date().toISOString();
            
            console.log(`🚀 Plugin démarré: ${plugin.name}`);
            
        } catch (error) {
            console.error(`❌ Erreur démarrage plugin ${plugin.name}:`, error);
        }
    }

    // Arrêter un plugin
    async stopPlugin(pluginId) {
        const plugin = this.plugins.get(pluginId);
        if (!plugin) {
            throw new Error(`Plugin ${pluginId} non trouvé`);
        }

        try {
            // Exécuter le hook onPluginUnload
            await this.executeHook('onPluginUnload', { plugin });
            
            // Marquer le plugin comme arrêté
            plugin.started = false;
            plugin.stopTime = new Date().toISOString();
            
            console.log(`🛑 Plugin arrêté: ${plugin.name}`);
            
        } catch (error) {
            console.error(`❌ Erreur arrêt plugin ${plugin.name}:`, error);
        }
    }

    // Installer un plugin
    async installPlugin(pluginUrl, config = {}) {
        try {
            console.log(`📦 Installation du plugin depuis: ${pluginUrl}`);
            
            // Télécharger le plugin
            const pluginData = await this.downloadPlugin(pluginUrl);
            
            // Valider le plugin
            this.validatePlugin(pluginData);
            
            // Installer le plugin
            const plugin = {
                id: pluginData.id,
                name: pluginData.name,
                version: pluginData.version,
                description: pluginData.description,
                author: pluginData.author,
                enabled: true,
                config: { ...pluginData.defaultConfig, ...config },
                hooks: pluginData.hooks || [],
                dependencies: pluginData.dependencies || [],
                url: pluginUrl,
                installTime: new Date().toISOString()
            };
            
            // Ajouter le plugin
            this.plugins.set(plugin.id, plugin);
            
            // Sauvegarder la liste des plugins
            this.saveInstalledPlugins();
            
            // Démarrer le plugin
            await this.startPlugin(plugin.id);
            
            console.log(`✅ Plugin installé: ${plugin.name}`);
            return plugin;
            
        } catch (error) {
            console.error('❌ Erreur installation plugin:', error);
            throw error;
        }
    }

    // Désinstaller un plugin
    async uninstallPlugin(pluginId) {
        const plugin = this.plugins.get(pluginId);
        if (!plugin) {
            throw new Error(`Plugin ${pluginId} non trouvé`);
        }

        try {
            // Arrêter le plugin
            await this.stopPlugin(pluginId);
            
            // Supprimer le plugin
            this.plugins.delete(pluginId);
            
            // Sauvegarder la liste des plugins
            this.saveInstalledPlugins();
            
            console.log(`🗑️ Plugin désinstallé: ${plugin.name}`);
            
        } catch (error) {
            console.error(`❌ Erreur désinstallation plugin ${plugin.name}:`, error);
            throw error;
        }
    }

    // Télécharger un plugin
    async downloadPlugin(pluginUrl) {
        try {
            const response = await fetch(pluginUrl);
            if (!response.ok) {
                throw new Error(`Erreur HTTP: ${response.status}`);
            }
            
            const pluginData = await response.json();
            return pluginData;
            
        } catch (error) {
            throw new Error(`Erreur téléchargement plugin: ${error.message}`);
        }
    }

    // Valider un plugin
    validatePlugin(pluginData) {
        const requiredFields = ['id', 'name', 'version', 'description', 'author'];
        
        for (const field of requiredFields) {
            if (!pluginData[field]) {
                throw new Error(`Champ requis manquant: ${field}`);
            }
        }
        
        // Valider l'ID du plugin
        if (!/^[a-z0-9-]+$/.test(pluginData.id)) {
            throw new Error('ID de plugin invalide (doit contenir uniquement des lettres minuscules, chiffres et tirets)');
        }
        
        // Vérifier la version
        if (!/^\d+\.\d+\.\d+$/.test(pluginData.version)) {
            throw new Error('Version invalide (format: x.y.z)');
        }
    }

    // Exécuter un hook
    async executeHook(hookName, data) {
        const hooks = this.hooks.get(hookName) || [];
        const results = [];
        
        for (const hook of hooks) {
            try {
                const result = await hook(data, this.api);
                if (result !== undefined) {
                    results.push(result);
                }
            } catch (error) {
                console.error(`❌ Erreur hook ${hookName}:`, error);
            }
        }
        
        return results;
    }

    // Ajouter un hook
    addHook(hookName, callback) {
        if (!this.hooks.has(hookName)) {
            this.hooks.set(hookName, []);
        }
        
        this.hooks.get(hookName).push(callback);
        console.log(`🎣 Hook ajouté: ${hookName}`);
    }

    // Supprimer un hook
    removeHook(hookName, callback) {
        const hooks = this.hooks.get(hookName);
        if (hooks) {
            const index = hooks.indexOf(callback);
            if (index > -1) {
                hooks.splice(index, 1);
                console.log(`🎣 Hook supprimé: ${hookName}`);
            }
        }
    }

    // Sauvegarder la liste des plugins installés
    saveInstalledPlugins() {
        try {
            const pluginsList = Array.from(this.plugins.values()).map(plugin => ({
                id: plugin.id,
                name: plugin.name,
                version: plugin.version,
                description: plugin.description,
                author: plugin.author,
                enabled: plugin.enabled,
                config: plugin.config,
                hooks: plugin.hooks,
                dependencies: plugin.dependencies,
                url: plugin.url,
                installTime: plugin.installTime
            }));
            
            localStorage.setItem('lynxInstalledPlugins', JSON.stringify(pluginsList));
            console.log('💾 Liste des plugins sauvegardée');
            
        } catch (error) {
            console.error('❌ Erreur sauvegarde plugins:', error);
        }
    }

    // Obtenir la base de données des plugins
    getPluginDatabase() {
        return {
            // Signatures personnalisées
            signatures: this.getCustomSignatures(),
            
            // Configuration
            config: this.getPluginConfig(),
            
            // Statistiques
            stats: this.getPluginStats()
        };
    }

    // Obtenir les signatures personnalisées
    getCustomSignatures() {
        try {
            return JSON.parse(localStorage.getItem('lynxCustomSignatures') || '[]');
        } catch (error) {
            return [];
        }
    }

    // Ajouter une signature personnalisée
    addCustomSignature(signature) {
        try {
            const signatures = this.getCustomSignatures();
            signatures.push({
                ...signature,
                id: Date.now(),
                addedBy: 'plugin',
                timestamp: new Date().toISOString()
            });
            
            localStorage.setItem('lynxCustomSignatures', JSON.stringify(signatures));
            console.log('✅ Signature personnalisée ajoutée');
            
        } catch (error) {
            console.error('❌ Erreur ajout signature:', error);
        }
    }

    // Obtenir la configuration des plugins
    getPluginConfig() {
        try {
            return JSON.parse(localStorage.getItem('lynxPluginConfig') || '{}');
        } catch (error) {
            return {};
        }
    }

    // Définir la configuration d'un plugin
    setPluginConfig(key, value) {
        try {
            const config = this.getPluginConfig();
            config[key] = value;
            localStorage.setItem('lynxPluginConfig', JSON.stringify(config));
            
        } catch (error) {
            console.error('❌ Erreur configuration plugin:', error);
        }
    }

    // Obtenir les statistiques des plugins
    getPluginStats() {
        const stats = {
            total: this.plugins.size,
            enabled: 0,
            disabled: 0,
            started: 0,
            hooks: 0
        };
        
        for (const plugin of this.plugins.values()) {
            if (plugin.enabled) stats.enabled++;
            else stats.disabled++;
            
            if (plugin.started) stats.started++;
        }
        
        for (const hooks of this.hooks.values()) {
            stats.hooks += hooks.length;
        }
        
        return stats;
    }

    // Utilitaires pour les plugins
    async hashFile(file) {
        return new Promise((resolve) => {
            const reader = new FileReader();
            reader.onload = (e) => {
                const arrayBuffer = e.target.result;
                window.crypto.subtle.digest('SHA-256', arrayBuffer).then(hash => {
                    const hashArray = Array.from(new Uint8Array(hash));
                    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                    resolve(hashHex);
                });
            };
            reader.readAsArrayBuffer(file);
        });
    }

    async extractStrings(file) {
        return new Promise((resolve) => {
            const reader = new FileReader();
            reader.onload = (e) => {
                const content = e.target.result;
                const strings = content.match(/[A-Za-z0-9]{4,}/g) || [];
                resolve(strings);
            };
            reader.readAsText(file);
        });
    }

    validateFile(file) {
        // Validation de base
        if (file.size > 100 * 1024 * 1024) { // 100MB
            return false;
        }
        
        const allowedTypes = ['exe', 'dll', 'js', 'ps1', 'bat', 'txt', 'pdf', 'doc'];
        const ext = file.name.split('.').pop().toLowerCase();
        
        return allowedTypes.includes(ext);
    }

    // Obtenir la liste des plugins
    getPluginsList() {
        return Array.from(this.plugins.values()).map(plugin => ({
            id: plugin.id,
            name: plugin.name,
            version: plugin.version,
            description: plugin.description,
            author: plugin.author,
            enabled: plugin.enabled,
            started: plugin.started,
            installTime: plugin.installTime
        }));
    }

    // Obtenir les informations d'un plugin
    getPluginInfo(pluginId) {
        const plugin = this.plugins.get(pluginId);
        if (!plugin) {
            return null;
        }
        
        return {
            ...plugin,
            stats: this.getPluginStats(),
            hooks: Array.from(this.hooks.entries()).filter(([hookName, hooks]) => 
                hooks.length > 0
            ).map(([hookName, hooks]) => ({
                name: hookName,
                count: hooks.length
            }))
        };
    }
}

// Export pour utilisation
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { PluginSystem };
} 