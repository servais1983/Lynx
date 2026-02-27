// API REST pour Lynx
// Interface d'intégration avec d'autres outils de sécurité

class LynxRESTAPI {
    constructor() {
        this.endpoints = {
            base: '/api/v1',
            version: '1.0.0',
            cors: {
                // Restrict to localhost origins only — never expose with wildcard
                origin: ['http://localhost:3786', 'http://127.0.0.1:3786', 'http://localhost:5173'],
                methods: ['GET', 'POST'],
                allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key']
            }
        };
        
        this.routes = this.initializeRoutes();
        this.middleware = this.initializeMiddleware();
        this.isRunning = false;
    }

    // Initialiser les routes API
    initializeRoutes() {
        return {
            // Endpoints d'analyse
            'POST /analyze': this.analyzeFile.bind(this),
            'POST /analyze/batch': this.analyzeBatch.bind(this),
            'GET /analyze/:id': this.getAnalysisResult.bind(this),
            'GET /analyze': this.getAnalysisHistory.bind(this),
            
            // Endpoints de configuration
            'GET /config': this.getConfig.bind(this),
            'PUT /config': this.updateConfig.bind(this),
            'POST /config/reset': this.resetConfig.bind(this),
            
            // Endpoints de signatures
            'GET /signatures': this.getSignatures.bind(this),
            'POST /signatures': this.addSignature.bind(this),
            'PUT /signatures/:id': this.updateSignature.bind(this),
            'DELETE /signatures/:id': this.deleteSignature.bind(this),
            
            // Endpoints de plugins
            'GET /plugins': this.getPlugins.bind(this),
            'POST /plugins': this.installPlugin.bind(this),
            'DELETE /plugins/:id': this.uninstallPlugin.bind(this),
            
            // Endpoints de rapports
            'GET /reports': this.getReports.bind(this),
            'POST /reports/generate': this.generateReport.bind(this),
            'GET /reports/:id': this.getReport.bind(this),
            
            // Endpoints de statistiques
            'GET /stats': this.getStats.bind(this),
            'GET /stats/realtime': this.getRealTimeStats.bind(this),
            
            // Endpoints de santé
            'GET /health': this.getHealth.bind(this),
            'GET /status': this.getStatus.bind(this)
        };
    }

    // Initialiser le middleware
    initializeMiddleware() {
        return {
            // Authentification
            authenticate: (req) => {
                const apiKey = req.headers['X-API-Key'] || req.headers['authorization'];
                if (!apiKey) {
                    throw new Error('API Key manquante');
                }
                return this.validateAPIKey(apiKey);
            },
            
            // Validation des données
            validateRequest: (req, schema) => {
                return this.validateSchema(req.body, schema);
            },
            
            // Rate limiting
            rateLimit: (req) => {
                return this.checkRateLimit(req);
            },
            
            // Logging
            logRequest: (req, res) => {
                this.logAPIRequest(req, res);
            }
        };
    }

    // Démarrer l'API
    async start() {
        try {
            console.log('🚀 Démarrage de l\'API REST Lynx...');
            
            // Vérifier les prérequis
            await this.checkPrerequisites();
            
            // Initialiser la base de données
            await this.initializeDatabase();
            
            // Démarrer le serveur Express (simulation)
            this.isRunning = true;
            
            console.log(`✅ API REST démarrée sur ${this.endpoints.base}`);
            console.log('📚 Documentation: /api/v1/docs');
            
        } catch (error) {
            console.error('❌ Erreur démarrage API:', error);
            throw error;
        }
    }

    // Analyser un fichier via API
    async analyzeFile(req, res) {
        try {
            // Validation
            this.middleware.authenticate(req);
            this.middleware.validateRequest(req, this.getAnalyzeSchema());
            this.middleware.rateLimit(req);
            
            const { file, options = {} } = req.body;
            
            // Créer un ID unique pour l'analyse
            const analysisId = this.generateAnalysisId();
            
            // Lancer l'analyse asynchrone
            this.runAnalysis(analysisId, file, options);
            
            // Réponse immédiate avec ID
            res.json({
                success: true,
                analysisId: analysisId,
                status: 'processing',
                message: 'Analyse en cours...',
                estimatedTime: '30-60 secondes'
            });
            
        } catch (error) {
            res.status(400).json({
                success: false,
                error: error.message
            });
        }
    }

    // Analyser un lot de fichiers
    async analyzeBatch(req, res) {
        try {
            this.middleware.authenticate(req);
            
            const { files, options = {} } = req.body;
            
            if (!Array.isArray(files) || files.length === 0) {
                throw new Error('Liste de fichiers invalide');
            }
            
            const batchId = this.generateBatchId();
            const analysisPromises = files.map(file => 
                this.runAnalysis(this.generateAnalysisId(), file, options)
            );
            
            // Lancer toutes les analyses en parallèle
            const results = await Promise.allSettled(analysisPromises);
            
            res.json({
                success: true,
                batchId: batchId,
                totalFiles: files.length,
                completed: results.filter(r => r.status === 'fulfilled').length,
                failed: results.filter(r => r.status === 'rejected').length,
                results: results.map((result, index) => ({
                    fileIndex: index,
                    success: result.status === 'fulfilled',
                    data: result.status === 'fulfilled' ? result.value : null,
                    error: result.status === 'rejected' ? result.reason : null
                }))
            });
            
        } catch (error) {
            res.status(400).json({
                success: false,
                error: error.message
            });
        }
    }

    // Obtenir le résultat d'une analyse
    async getAnalysisResult(req, res) {
        try {
            this.middleware.authenticate(req);
            
            const { id } = req.params;
            const result = await this.getAnalysisFromDatabase(id);
            
            if (!result) {
                return res.status(404).json({
                    success: false,
                    error: 'Analyse non trouvée'
                });
            }
            
            res.json({
                success: true,
                analysis: result
            });
            
        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    // Obtenir l'historique des analyses
    async getAnalysisHistory(req, res) {
        try {
            this.middleware.authenticate(req);
            
            const { limit = 50, offset = 0, status } = req.query;
            
            const history = await this.getAnalysisHistoryFromDatabase({
                limit: parseInt(limit),
                offset: parseInt(offset),
                status
            });
            
            res.json({
                success: true,
                history: history.analyses,
                total: history.total,
                limit: parseInt(limit),
                offset: parseInt(offset)
            });
            
        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    // Gestion des signatures
    async getSignatures(req, res) {
        try {
            this.middleware.authenticate(req);
            
            const signatures = await this.getSignaturesFromDatabase();
            
            res.json({
                success: true,
                signatures: signatures,
                total: signatures.length
            });
            
        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    async addSignature(req, res) {
        try {
            this.middleware.authenticate(req);
            this.middleware.validateRequest(req, this.getSignatureSchema());
            
            const signature = req.body;
            const newSignature = await this.addSignatureToDatabase(signature);
            
            res.status(201).json({
                success: true,
                signature: newSignature,
                message: 'Signature ajoutée avec succès'
            });
            
        } catch (error) {
            res.status(400).json({
                success: false,
                error: error.message
            });
        }
    }

    // Gestion des plugins
    async getPlugins(req, res) {
        try {
            this.middleware.authenticate(req);
            
            const plugins = await this.getPluginsFromDatabase();
            
            res.json({
                success: true,
                plugins: plugins,
                total: plugins.length
            });
            
        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    async installPlugin(req, res) {
        try {
            this.middleware.authenticate(req);
            
            const { pluginUrl, pluginConfig } = req.body;
            
            const plugin = await this.installPluginFromUrl(pluginUrl, pluginConfig);
            
            res.status(201).json({
                success: true,
                plugin: plugin,
                message: 'Plugin installé avec succès'
            });
            
        } catch (error) {
            res.status(400).json({
                success: false,
                error: error.message
            });
        }
    }

    // Génération de rapports
    async generateReport(req, res) {
        try {
            this.middleware.authenticate(req);
            
            const { analysisIds, reportType, format } = req.body;
            
            const report = await this.generateReportFromAnalyses(analysisIds, reportType, format);
            
            res.json({
                success: true,
                report: report,
                downloadUrl: `/api/v1/reports/${report.id}/download`
            });
            
        } catch (error) {
            res.status(400).json({
                success: false,
                error: error.message
            });
        }
    }

    // Statistiques
    async getStats(req, res) {
        try {
            this.middleware.authenticate(req);
            
            const stats = await this.getStatisticsFromDatabase();
            
            res.json({
                success: true,
                stats: stats
            });
            
        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    // Statistiques en temps réel
    async getRealTimeStats(req, res) {
        try {
            this.middleware.authenticate(req);
            
            const realTimeStats = this.getRealTimeStatistics();
            
            res.json({
                success: true,
                stats: realTimeStats,
                timestamp: new Date().toISOString()
            });
            
        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }

    // Santé de l'API
    async getHealth(req, res) {
        const health = {
            status: 'healthy',
            timestamp: new Date().toISOString(),
            version: this.endpoints.version,
            uptime: process.uptime(),
            memory: process.memoryUsage(),
            components: {
                database: await this.checkDatabaseHealth(),
                ai: await this.checkAIHealth(),
                security: await this.checkSecurityHealth()
            }
        };
        
        res.json(health);
    }

    // Statut de l'API
    async getStatus(req, res) {
        const status = {
            running: this.isRunning,
            endpoints: Object.keys(this.routes).length,
            activeConnections: this.getActiveConnections(),
            lastRequest: this.getLastRequestTime(),
            performance: this.getPerformanceMetrics()
        };
        
        res.json(status);
    }

    // Méthodes utilitaires
    generateAnalysisId() {
        return `analysis_${Date.now()}_${crypto.randomUUID().replace(/-/g,'').slice(0,9)}`;
    }

    generateBatchId() {
        return `batch_${Date.now()}_${crypto.randomUUID().replace(/-/g,'').slice(0,9)}`;
    }

    validateAPIKey(apiKey) {
        // Simulation de validation d'API key
        const validKeys = ['lynx_api_key_123', 'lynx_api_key_456'];
        return validKeys.includes(apiKey);
    }

    validateSchema(data, schema) {
        // Validation simple des schémas
        for (const [field, rules] of Object.entries(schema)) {
            if (rules.required && !data[field]) {
                throw new Error(`Champ requis manquant: ${field}`);
            }
        }
        return true;
    }

    getAnalyzeSchema() {
        return {
            file: { required: true },
            options: { required: false }
        };
    }

    getSignatureSchema() {
        return {
            name: { required: true },
            pattern: { required: true },
            category: { required: true }
        };
    }

    checkRateLimit(req) {
        // Simulation de rate limiting
        return true;
    }

    logAPIRequest(req, res) {
        console.log(`[API] ${req.method} ${req.url} - ${res.statusCode}`);
    }

    // Méthodes de base de données (simulation)
    async initializeDatabase() {
        console.log('🗄️ Initialisation de la base de données API...');
        // Simulation
        return true;
    }

    async runAnalysis(analysisId, file, options) {
        // Risk score is computed by the real analysis engines (ai-engine, ml-models, yara-rules).
        // The REST endpoint exposes the result — no simulated random data.
        return {
            id: analysisId,
            fileName: file.name,
            status: 'completed',
            riskScore: null, // Populated by the caller after real engine analysis
            timestamp: new Date().toISOString()
        };
    }

    async getAnalysisFromDatabase(id) {
        // Simulation
        return {
            id: id,
            status: 'completed',
            results: {}
        };
    }

    async getAnalysisHistoryFromDatabase(options) {
        // Simulation
        return {
            analyses: [],
            total: 0
        };
    }

    async getSignaturesFromDatabase() {
        // Simulation
        return [];
    }

    async addSignatureToDatabase(signature) {
        // Simulation
        return { ...signature, id: Date.now() };
    }

    async getPluginsFromDatabase() {
        // Simulation
        return [];
    }

    async installPluginFromUrl(url, config) {
        // Simulation
        return { id: Date.now(), url, config };
    }

    async generateReportFromAnalyses(analysisIds, reportType, format) {
        // Simulation
        return {
            id: Date.now(),
            type: reportType,
            format: format
        };
    }

    async getStatisticsFromDatabase() {
        // Simulation
        return {
            totalAnalyses: 0,
            threatsDetected: 0,
            averageRiskScore: 0
        };
    }

    getRealTimeStatistics() {
        // Simulation
        return {
            activeAnalyses: 0,
            threatsPerMinute: 0,
            systemLoad: 0
        };
    }

    async checkDatabaseHealth() {
        return { status: 'healthy' };
    }

    async checkAIHealth() {
        return { status: 'healthy' };
    }

    async checkSecurityHealth() {
        return { status: 'healthy' };
    }

    getActiveConnections() {
        return 0;
    }

    getLastRequestTime() {
        return new Date().toISOString();
    }

    getPerformanceMetrics() {
        return {
            responseTime: 0,
            throughput: 0
        };
    }

    async checkPrerequisites() {
        // Vérifier les prérequis
        return true;
    }
}

// Export pour utilisation
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { LynxRESTAPI };
} 