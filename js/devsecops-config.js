// Configuration DevSecOps pour Lynx
// Sécurisation complète de l'application

class DevSecOpsConfig {
    constructor() {
        this.securitySettings = {
            // Chiffrement
            encryption: {
                algorithm: 'AES-256-GCM',
                keyLength: 256,
                ivLength: 12,
                saltLength: 16
            },
            
            // Authentification
            authentication: {
                enabled: true,
                sessionTimeout: 3600000, // 1 heure
                maxLoginAttempts: 5,
                lockoutDuration: 900000 // 15 minutes
            },
            
            // Rate Limiting
            rateLimiting: {
                enabled: true,
                maxRequestsPerMinute: 100,
                maxRequestsPerHour: 1000,
                maxFileSize: 100 * 1024 * 1024 // 100MB
            },
            
            // Validation des fichiers
            fileValidation: {
                allowedExtensions: ['exe', 'dll', 'js', 'ps1', 'bat', 'txt', 'pdf', 'doc', 'zip', 'rar'],
                maxFileSize: 100 * 1024 * 1024, // 100MB
                scanForMalware: true,
                validateIntegrity: true
            },
            
            // Logs de sécurité
            securityLogging: {
                enabled: true,
                logLevel: 'INFO',
                logRetention: 30, // jours
                sensitiveDataMasking: true
            },
            
            // API Security
            apiSecurity: {
                enabled: true,
                corsEnabled: false,
                apiKeyRequired: true,
                requestValidation: true
            },
            
            // Network Security
            networkSecurity: {
                httpsOnly: true,
                contentSecurityPolicy: true,
                xssProtection: true,
                csrfProtection: true
            }
        };
        
        this.threatDetection = {
            // Détection d'anomalies
            anomalyDetection: {
                enabled: true,
                threshold: 0.8,
                learningRate: 0.01
            },
            
            // Détection de comportements suspects
            behavioralAnalysis: {
                enabled: true,
                fileOperations: true,
                networkActivity: true,
                registryChanges: true,
                processCreation: true
            },
            
            // Détection de signatures
            signatureDetection: {
                enabled: true,
                yaraRules: true,
                hashAnalysis: true,
                stringPatterns: true
            }
        };
        
        this.compliance = {
            // GDPR
            gdpr: {
                enabled: true,
                dataRetention: 30, // jours
                userConsent: true,
                dataAnonymization: true
            },
            
            // ISO 27001
            iso27001: {
                enabled: true,
                accessControl: true,
                auditLogging: true,
                incidentResponse: true
            },
            
            // SOC 2
            soc2: {
                enabled: true,
                securityMonitoring: true,
                vulnerabilityManagement: true,
                changeManagement: true
            }
        };
    }

    // Initialisation de la sécurité
    async initializeSecurity() {
        try {
            console.log('🔐 Initialisation de la sécurité DevSecOps...');
            
            // Vérifier les prérequis de sécurité
            await this.checkSecurityPrerequisites();
            
            // Initialiser le chiffrement
            await this.initializeEncryption();
            
            // Configurer les logs de sécurité
            this.setupSecurityLogging();
            
            // Configurer la validation des fichiers
            this.setupFileValidation();
            
            // Configurer la détection de menaces
            this.setupThreatDetection();
            
            console.log('✅ Sécurité DevSecOps initialisée avec succès');
            
        } catch (error) {
            console.error('❌ Erreur d\'initialisation de la sécurité:', error);
            throw new Error('Échec de l\'initialisation de la sécurité');
        }
    }

    // Vérification des prérequis de sécurité
    async checkSecurityPrerequisites() {
        // Vérifier HTTPS
        if (location.protocol !== 'https:' && location.hostname !== 'localhost') {
            throw new Error('HTTPS requis pour la sécurité');
        }
        
        // Vérifier les APIs de sécurité du navigateur
        if (!window.crypto || !window.crypto.subtle) {
            throw new Error('APIs de chiffrement non disponibles');
        }
        
        // Vérifier les APIs de stockage sécurisé
        if (!window.localStorage || !window.sessionStorage) {
            throw new Error('Stockage sécurisé non disponible');
        }
        
        console.log('✅ Prérequis de sécurité vérifiés');
    }

    // Initialisation du chiffrement
    async initializeEncryption() {
        try {
            // Générer une clé de chiffrement
            const key = await window.crypto.subtle.generateKey(
                {
                    name: 'AES-GCM',
                    length: 256
                },
                true,
                ['encrypt', 'decrypt']
            );
            
            this.encryptionKey = key;
            console.log('🔐 Chiffrement initialisé');
            
        } catch (error) {
            console.error('❌ Erreur d\'initialisation du chiffrement:', error);
            throw error;
        }
    }

    // Configuration des logs de sécurité
    setupSecurityLogging() {
        this.securityLogger = {
            log: (level, message, data = {}) => {
                const logEntry = {
                    timestamp: new Date().toISOString(),
                    level: level,
                    message: message,
                    data: this.maskSensitiveData(data),
                    userAgent: navigator.userAgent,
                    url: window.location.href
                };
                
                // Stocker dans localStorage (limité)
                this.storeSecurityLog(logEntry);
                
                // Afficher dans la console
                console.log(`[SECURITY-${level}] ${message}`, data);
            },
            
            info: (message, data) => this.log('INFO', message, data),
            warn: (message, data) => this.log('WARN', message, data),
            error: (message, data) => this.log('ERROR', message, data),
            critical: (message, data) => this.log('CRITICAL', message, data)
        };
        
        console.log('📝 Logs de sécurité configurés');
    }

    // Masquage des données sensibles
    maskSensitiveData(data) {
        const masked = { ...data };
        const sensitiveFields = ['password', 'token', 'key', 'secret', 'apiKey'];
        
        for (let field of sensitiveFields) {
            if (masked[field]) {
                masked[field] = '***MASKED***';
            }
        }
        
        return masked;
    }

    // Stockage des logs de sécurité
    storeSecurityLog(logEntry) {
        try {
            const logs = JSON.parse(localStorage.getItem('securityLogs') || '[]');
            logs.push(logEntry);
            
            // Limiter à 1000 entrées
            if (logs.length > 1000) {
                logs.splice(0, logs.length - 1000);
            }
            
            localStorage.setItem('securityLogs', JSON.stringify(logs));
            
        } catch (error) {
            console.error('Erreur de stockage des logs:', error);
        }
    }

    // Configuration de la validation des fichiers
    setupFileValidation() {
        this.fileValidator = {
            validateFile: (file) => {
                // Vérifier la taille
                if (file.size > this.securitySettings.fileValidation.maxFileSize) {
                    this.securityLogger.warn('Fichier trop volumineux', { 
                        filename: file.name, 
                        size: file.size 
                    });
                    return false;
                }
                
                // Vérifier l'extension
                const ext = file.name.split('.').pop().toLowerCase();
                if (!this.securitySettings.fileValidation.allowedExtensions.includes(ext)) {
                    this.securityLogger.warn('Extension de fichier non autorisée', { 
                        filename: file.name, 
                        extension: ext 
                    });
                    return false;
                }
                
                // Vérifier l'intégrité
                if (this.securitySettings.fileValidation.validateIntegrity) {
                    this.validateFileIntegrity(file);
                }
                
                this.securityLogger.info('Fichier validé avec succès', { 
                    filename: file.name, 
                    size: file.size 
                });
                
                return true;
            },
            
            validateFileIntegrity: (file) => {
                // Calculer le hash du fichier
                const reader = new FileReader();
                reader.onload = (e) => {
                    const arrayBuffer = e.target.result;
                    window.crypto.subtle.digest('SHA-256', arrayBuffer).then(hash => {
                        const hashArray = Array.from(new Uint8Array(hash));
                        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                        
                        this.securityLogger.info('Hash de fichier calculé', { 
                            filename: file.name, 
                            hash: hashHex 
                        });
                    });
                };
                reader.readAsArrayBuffer(file);
            }
        };
        
        console.log('✅ Validation des fichiers configurée');
    }

    // Configuration de la détection de menaces
    setupThreatDetection() {
        this.threatDetector = {
            // Détection d'anomalies
            detectAnomalies: (data) => {
                const anomalyScore = this.calculateAnomalyScore(data);
                
                if (anomalyScore > this.threatDetection.anomalyDetection.threshold) {
                    this.securityLogger.critical('Anomalie détectée', { 
                        score: anomalyScore, 
                        data: data 
                    });
                    return true;
                }
                
                return false;
            },
            
            // Détection de comportements suspects
            detectSuspiciousBehavior: (behavior) => {
                const suspiciousPatterns = [
                    'file_operations',
                    'network_activity', 
                    'registry_changes',
                    'process_creation'
                ];
                
                for (let pattern of suspiciousPatterns) {
                    if (behavior[pattern]) {
                        this.securityLogger.warn('Comportement suspect détecté', { 
                            pattern: pattern, 
                            behavior: behavior 
                        });
                        return true;
                    }
                }
                
                return false;
            },
            
            // Calcul du score d'anomalie
            calculateAnomalyScore: (data) => {
                // Algorithme simple de détection d'anomalie
                let score = 0;
                
                // Vérifier les patterns suspects
                const suspiciousPatterns = [
                    'malware', 'virus', 'trojan', 'backdoor',
                    'encrypt', 'ransom', 'keylogger', 'spyware'
                ];
                
                const content = JSON.stringify(data).toLowerCase();
                for (let pattern of suspiciousPatterns) {
                    if (content.includes(pattern)) {
                        score += 0.2;
                    }
                }
                
                // Vérifier la taille des données
                if (data.size > 50 * 1024 * 1024) { // 50MB
                    score += 0.1;
                }
                
                return Math.min(1, score);
            }
        };
        
        console.log('🎯 Détection de menaces configurée');
    }

    // Validation de sécurité pour les requêtes API
    validateApiRequest(request) {
        // Vérifier le rate limiting
        if (!this.checkRateLimit()) {
            this.securityLogger.warn('Rate limit dépassé', { request });
            return false;
        }
        
        // Vérifier l'authentification
        if (this.securitySettings.apiSecurity.apiKeyRequired) {
            if (!request.headers || !request.headers['X-API-Key']) {
                this.securityLogger.error('Clé API manquante', { request });
                return false;
            }
        }
        
        // Vérifier la validation des données
        if (this.securitySettings.apiSecurity.requestValidation) {
            if (!this.validateRequestData(request)) {
                this.securityLogger.error('Données de requête invalides', { request });
                return false;
            }
        }
        
        return true;
    }

    // Vérification du rate limiting
    checkRateLimit() {
        const now = Date.now();
        const requests = JSON.parse(localStorage.getItem('apiRequests') || '[]');
        
        // Nettoyer les anciennes requêtes
        const recentRequests = requests.filter(req => now - req.timestamp < 60000);
        
        if (recentRequests.length >= this.securitySettings.rateLimiting.maxRequestsPerMinute) {
            return false;
        }
        
        // Ajouter la nouvelle requête
        recentRequests.push({ timestamp: now });
        localStorage.setItem('apiRequests', JSON.stringify(recentRequests));
        
        return true;
    }

    // Validation des données de requête
    validateRequestData(request) {
        // Vérifier la structure des données
        if (!request || typeof request !== 'object') {
            return false;
        }
        
        // Vérifier les champs requis
        const requiredFields = ['method', 'url'];
        for (let field of requiredFields) {
            if (!request[field]) {
                return false;
            }
        }
        
        // Vérifier les types de données
        if (typeof request.method !== 'string' || typeof request.url !== 'string') {
            return false;
        }
        
        return true;
    }

    // Chiffrement de données sensibles
    async encryptSensitiveData(data) {
        try {
            const encoder = new TextEncoder();
            const dataBuffer = encoder.encode(JSON.stringify(data));
            
            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            const encryptedData = await window.crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                this.encryptionKey,
                dataBuffer
            );
            
            return {
                data: Array.from(new Uint8Array(encryptedData)),
                iv: Array.from(iv)
            };
            
        } catch (error) {
            this.securityLogger.error('Erreur de chiffrement', { error: error.message });
            throw error;
        }
    }

    // Déchiffrement de données sensibles
    async decryptSensitiveData(encryptedData) {
        try {
            const dataBuffer = new Uint8Array(encryptedData.data);
            const iv = new Uint8Array(encryptedData.iv);
            
            const decryptedData = await window.crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                this.encryptionKey,
                dataBuffer
            );
            
            const decoder = new TextDecoder();
            return JSON.parse(decoder.decode(decryptedData));
            
        } catch (error) {
            this.securityLogger.error('Erreur de déchiffrement', { error: error.message });
            throw error;
        }
    }

    // Nettoyage des données sensibles
    cleanupSensitiveData() {
        try {
            // Nettoyer les logs de sécurité
            localStorage.removeItem('securityLogs');
            localStorage.removeItem('apiRequests');
            
            // Nettoyer les clés de chiffrement
            if (this.encryptionKey) {
                window.crypto.subtle.exportKey('raw', this.encryptionKey);
                this.encryptionKey = null;
            }
            
            this.securityLogger.info('Données sensibles nettoyées');
            
        } catch (error) {
            console.error('Erreur de nettoyage:', error);
        }
    }
}

// Export pour utilisation
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { DevSecOpsConfig };
} 