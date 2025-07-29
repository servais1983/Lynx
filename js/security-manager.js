// Gestionnaire de Sécurité Avancé pour Lynx
// Authentification multi-facteurs, chiffrement, audit trail

class SecurityManager {
    constructor() {
        this.isInitialized = false;
        this.currentUser = null;
        this.sessionToken = null;
        this.mfaEnabled = false;
        this.auditTrail = [];
        this.securityConfig = this.initializeSecurityConfig();
    }

    // Initialiser la configuration de sécurité
    initializeSecurityConfig() {
        return {
            // Authentification
            auth: {
                sessionTimeout: 3600000, // 1 heure
                maxLoginAttempts: 5,
                lockoutDuration: 900000, // 15 minutes
                passwordMinLength: 12,
                requireMFA: true,
                mfaMethods: ['totp', 'sms', 'email'],
                totpIssuer: 'Lynx Security',
                totpAlgorithm: 'SHA1',
                totpDigits: 6,
                totpPeriod: 30
            },
            
            // Chiffrement
            encryption: {
                algorithm: 'AES-256-GCM',
                keyLength: 256,
                ivLength: 12,
                saltLength: 16,
                pbkdf2Iterations: 100000
            },
            
            // Audit Trail
            audit: {
                enabled: true,
                logLevel: 'INFO',
                retentionDays: 365,
                sensitiveDataMasking: true,
                realTimeAlerts: true
            },
            
            // Zero Trust
            zeroTrust: {
                enabled: true,
                deviceFingerprinting: true,
                behaviorAnalysis: true,
                continuousAuth: true,
                riskScoring: true
            },
            
            // Isolation
            isolation: {
                sandboxedAnalysis: true,
                processIsolation: true,
                memoryProtection: true,
                networkIsolation: true
            }
        };
    }

    // Initialiser le gestionnaire de sécurité
    async initialize() {
        try {
            console.log('🔐 Initialisation du gestionnaire de sécurité...');
            
            // Vérifier les prérequis de sécurité
            await this.checkSecurityPrerequisites();
            
            // Initialiser le chiffrement
            await this.initializeEncryption();
            
            // Configurer l'audit trail
            this.setupAuditTrail();
            
            // Configurer l'authentification
            await this.setupAuthentication();
            
            // Configurer Zero Trust
            this.setupZeroTrust();
            
            this.isInitialized = true;
            console.log('✅ Gestionnaire de sécurité initialisé');
            
        } catch (error) {
            console.error('❌ Erreur initialisation sécurité:', error);
            throw error;
        }
    }

    // Vérifier les prérequis de sécurité
    async checkSecurityPrerequisites() {
        // Vérifier HTTPS
        if (location.protocol !== 'https:' && location.hostname !== 'localhost') {
            throw new Error('HTTPS requis pour la sécurité');
        }
        
        // Vérifier les APIs de sécurité
        if (!window.crypto || !window.crypto.subtle) {
            throw new Error('APIs de chiffrement non disponibles');
        }
        
        // Vérifier les APIs de stockage sécurisé
        if (!window.localStorage || !window.sessionStorage) {
            throw new Error('Stockage sécurisé non disponible');
        }
        
        // Vérifier les APIs de géolocalisation pour Zero Trust
        if (!navigator.geolocation) {
            console.warn('⚠️ Géolocalisation non disponible pour Zero Trust');
        }
        
        console.log('✅ Prérequis de sécurité vérifiés');
    }

    // Initialiser le chiffrement
    async initializeEncryption() {
        try {
            // Générer une clé de chiffrement principale
            this.masterKey = await window.crypto.subtle.generateKey(
                {
                    name: 'AES-GCM',
                    length: 256
                },
                true,
                ['encrypt', 'decrypt']
            );
            
            // Générer une clé pour les tokens
            this.tokenKey = await window.crypto.subtle.generateKey(
                {
                    name: 'HMAC',
                    hash: 'SHA-256'
                },
                true,
                ['sign', 'verify']
            );
            
            console.log('🔐 Chiffrement initialisé');
            
        } catch (error) {
            console.error('❌ Erreur initialisation chiffrement:', error);
            throw error;
        }
    }

    // Configurer l'audit trail
    setupAuditTrail() {
        this.auditLogger = {
            log: (level, event, data = {}) => {
                const auditEntry = {
                    timestamp: new Date().toISOString(),
                    level: level,
                    event: event,
                    data: this.maskSensitiveData(data),
                    user: this.currentUser?.id || 'anonymous',
                    sessionId: this.sessionToken,
                    userAgent: navigator.userAgent,
                    ip: this.getClientIP(),
                    deviceFingerprint: this.getDeviceFingerprint()
                };
                
                this.auditTrail.push(auditEntry);
                
                // Limiter la taille de l'audit trail
                if (this.auditTrail.length > 10000) {
                    this.auditTrail = this.auditTrail.slice(-5000);
                }
                
                // Stocker dans localStorage
                this.storeAuditEntry(auditEntry);
                
                // Alerte en temps réel si critique
                if (level === 'CRITICAL' && this.securityConfig.audit.realTimeAlerts) {
                    this.sendSecurityAlert(auditEntry);
                }
                
                console.log(`[AUDIT-${level}] ${event}`, data);
            },
            
            info: (event, data) => this.log('INFO', event, data),
            warn: (event, data) => this.log('WARN', event, data),
            error: (event, data) => this.log('ERROR', event, data),
            critical: (event, data) => this.log('CRITICAL', event, data)
        };
        
        console.log('📝 Audit trail configuré');
    }

    // Configurer l'authentification
    async setupAuthentication() {
        // Vérifier si un utilisateur est déjà connecté
        const savedSession = localStorage.getItem('lynxSession');
        if (savedSession) {
            try {
                const session = JSON.parse(savedSession);
                if (this.validateSession(session)) {
                    this.currentUser = session.user;
                    this.sessionToken = session.token;
                    this.auditLogger.info('SESSION_RESTORED', { userId: this.currentUser.id });
                }
            } catch (error) {
                console.warn('⚠️ Session invalide, déconnexion requise');
                this.logout();
            }
        }
        
        console.log('🔑 Authentification configurée');
    }

    // Configurer Zero Trust
    setupZeroTrust() {
        if (!this.securityConfig.zeroTrust.enabled) return;
        
        this.zeroTrustEngine = {
            // Analyse comportementale
            analyzeBehavior: (action) => {
                const behavior = {
                    action: action,
                    timestamp: Date.now(),
                    context: this.getBehaviorContext(),
                    riskScore: this.calculateBehaviorRisk(action)
                };
                
                this.auditLogger.info('BEHAVIOR_ANALYSIS', behavior);
                return behavior;
            },
            
            // Fingerprinting des appareils
            getDeviceFingerprint: () => {
                return this.getDeviceFingerprint();
            },
            
            // Score de risque continu
            calculateRiskScore: () => {
                return this.calculateContinuousRiskScore();
            },
            
            // Authentification continue
            continuousAuth: () => {
                return this.performContinuousAuth();
            }
        };
        
        console.log('🛡️ Zero Trust configuré');
    }

    // Authentification multi-facteurs
    async authenticate(username, password, mfaCode = null) {
        try {
            this.auditLogger.info('LOGIN_ATTEMPT', { username });
            
            // Vérifier les tentatives de connexion
            if (this.isAccountLocked(username)) {
                throw new Error('Compte temporairement verrouillé');
            }
            
            // Authentification par mot de passe
            const user = await this.authenticatePassword(username, password);
            if (!user) {
                this.recordFailedLogin(username);
                throw new Error('Identifiants invalides');
            }
            
            // Vérification MFA si activée
            if (this.securityConfig.auth.requireMFA && user.mfaEnabled) {
                if (!mfaCode) {
                    throw new Error('Code MFA requis');
                }
                
                if (!await this.verifyMFA(user, mfaCode)) {
                    this.recordFailedLogin(username);
                    throw new Error('Code MFA invalide');
                }
            }
            
            // Créer la session
            const session = await this.createSession(user);
            
            // Analyser le comportement
            this.zeroTrustEngine.analyzeBehavior('LOGIN_SUCCESS');
            
            this.auditLogger.info('LOGIN_SUCCESS', { userId: user.id });
            
            return session;
            
        } catch (error) {
            this.auditLogger.error('LOGIN_FAILED', { 
                username, 
                error: error.message 
            });
            throw error;
        }
    }

    // Authentification par mot de passe
    async authenticatePassword(username, password) {
        // Simulation - remplacer par une vraie base de données
        const users = JSON.parse(localStorage.getItem('lynxUsers') || '[]');
        const user = users.find(u => u.username === username);
        
        if (!user) return null;
        
        // Vérifier le hash du mot de passe
        const passwordHash = await this.hashPassword(password, user.salt);
        if (passwordHash !== user.passwordHash) {
            return null;
        }
        
        return user;
    }

    // Vérifier le code MFA
    async verifyMFA(user, code) {
        // Simulation TOTP - remplacer par une vraie implémentation
        const expectedCode = this.generateTOTP(user.mfaSecret);
        return code === expectedCode;
    }

    // Générer un code TOTP
    generateTOTP(secret) {
        const now = Math.floor(Date.now() / 1000);
        const timeStep = this.securityConfig.auth.totpPeriod;
        const counter = Math.floor(now / timeStep);
        
        // Simulation simple - remplacer par une vraie implémentation TOTP
        const hash = this.simpleHash(secret + counter);
        return (hash % 1000000).toString().padStart(6, '0');
    }

    // Hash simple pour simulation
    simpleHash(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32bit integer
        }
        return Math.abs(hash);
    }

    // Créer une session
    async createSession(user) {
        const sessionToken = await this.generateSessionToken(user);
        const session = {
            user: user,
            token: sessionToken,
            createdAt: Date.now(),
            expiresAt: Date.now() + this.securityConfig.auth.sessionTimeout
        };
        
        // Stocker la session
        localStorage.setItem('lynxSession', JSON.stringify(session));
        
        this.currentUser = user;
        this.sessionToken = sessionToken;
        
        return session;
    }

    // Générer un token de session
    async generateSessionToken(user) {
        const payload = {
            userId: user.id,
            username: user.username,
            iat: Date.now(),
            exp: Date.now() + this.securityConfig.auth.sessionTimeout
        };
        
        const encoder = new TextEncoder();
        const data = encoder.encode(JSON.stringify(payload));
        
        const signature = await window.crypto.subtle.sign(
            'HMAC',
            this.tokenKey,
            data
        );
        
        const signatureArray = Array.from(new Uint8Array(signature));
        const signatureHex = signatureArray.map(b => b.toString(16).padStart(2, '0')).join('');
        
        return btoa(JSON.stringify(payload)) + '.' + signatureHex;
    }

    // Valider une session
    validateSession(session) {
        if (!session || !session.token || !session.expiresAt) {
            return false;
        }
        
        if (Date.now() > session.expiresAt) {
            return false;
        }
        
        // Vérifier la signature du token
        return this.verifySessionToken(session.token);
    }

    // Vérifier un token de session
    async verifySessionToken(token) {
        try {
            const [payloadB64, signature] = token.split('.');
            const payload = JSON.parse(atob(payloadB64));
            
            const encoder = new TextEncoder();
            const data = encoder.encode(JSON.stringify(payload));
            
            const signatureArray = new Uint8Array(signature.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
            
            return await window.crypto.subtle.verify(
                'HMAC',
                this.tokenKey,
                signatureArray,
                data
            );
        } catch (error) {
            return false;
        }
    }

    // Déconnexion
    logout() {
        this.auditLogger.info('LOGOUT', { userId: this.currentUser?.id });
        
        this.currentUser = null;
        this.sessionToken = null;
        localStorage.removeItem('lynxSession');
        
        // Rediriger vers la page de connexion
        window.location.href = '/login.html';
    }

    // Vérifier si un compte est verrouillé
    isAccountLocked(username) {
        const lockouts = JSON.parse(localStorage.getItem('lynxLockouts') || '{}');
        const lockout = lockouts[username];
        
        if (!lockout) return false;
        
        if (Date.now() < lockout.until) {
            return true;
        } else {
            // Nettoyer le verrouillage expiré
            delete lockouts[username];
            localStorage.setItem('lynxLockouts', JSON.stringify(lockouts));
            return false;
        }
    }

    // Enregistrer une tentative de connexion échouée
    recordFailedLogin(username) {
        const lockouts = JSON.parse(localStorage.getItem('lynxLockouts') || '{}');
        const attempts = JSON.parse(localStorage.getItem('lynxLoginAttempts') || '{}');
        
        // Incrémenter les tentatives
        attempts[username] = (attempts[username] || 0) + 1;
        localStorage.setItem('lynxLoginAttempts', JSON.stringify(attempts));
        
        // Vérifier si le compte doit être verrouillé
        if (attempts[username] >= this.securityConfig.auth.maxLoginAttempts) {
            lockouts[username] = {
                until: Date.now() + this.securityConfig.auth.lockoutDuration
            };
            localStorage.setItem('lynxLockouts', JSON.stringify(lockouts));
            
            this.auditLogger.critical('ACCOUNT_LOCKED', { username });
        }
    }

    // Hasher un mot de passe
    async hashPassword(password, salt) {
        const encoder = new TextEncoder();
        const passwordData = encoder.encode(password + salt);
        
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', passwordData);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // Masquer les données sensibles
    maskSensitiveData(data) {
        const masked = { ...data };
        const sensitiveFields = ['password', 'token', 'secret', 'key', 'mfaCode'];
        
        for (let field of sensitiveFields) {
            if (masked[field]) {
                masked[field] = '***MASKED***';
            }
        }
        
        return masked;
    }

    // Stocker une entrée d'audit
    storeAuditEntry(entry) {
        try {
            const auditLog = JSON.parse(localStorage.getItem('lynxAuditLog') || '[]');
            auditLog.push(entry);
            
            // Limiter la taille du log
            if (auditLog.length > 1000) {
                auditLog.splice(0, auditLog.length - 1000);
            }
            
            localStorage.setItem('lynxAuditLog', JSON.stringify(auditLog));
            
        } catch (error) {
            console.error('❌ Erreur stockage audit log:', error);
        }
    }

    // Envoyer une alerte de sécurité
    sendSecurityAlert(auditEntry) {
        if (window.uiManager) {
            window.uiManager.showNotification(
                '🚨 Alerte de Sécurité',
                `Événement critique détecté: ${auditEntry.event}`,
                { type: 'error', duration: 0 }
            );
        }
    }

    // Obtenir l'IP du client (simulation)
    getClientIP() {
        return '127.0.0.1'; // Simulation
    }

    // Obtenir l'empreinte de l'appareil
    getDeviceFingerprint() {
        const fingerprint = {
            userAgent: navigator.userAgent,
            language: navigator.language,
            platform: navigator.platform,
            screenResolution: `${screen.width}x${screen.height}`,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            canvas: this.getCanvasFingerprint(),
            webgl: this.getWebGLFingerprint()
        };
        
        return this.hashFingerprint(JSON.stringify(fingerprint));
    }

    // Empreinte Canvas
    getCanvasFingerprint() {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillText('Lynx Security Fingerprint', 2, 2);
        return canvas.toDataURL();
    }

    // Empreinte WebGL
    getWebGLFingerprint() {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (!gl) return 'no-webgl';
        
        return gl.getParameter(gl.VENDOR) + gl.getParameter(gl.RENDERER);
    }

    // Hasher l'empreinte
    hashFingerprint(fingerprint) {
        let hash = 0;
        for (let i = 0; i < fingerprint.length; i++) {
            const char = fingerprint.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return Math.abs(hash).toString(16);
    }

    // Obtenir le contexte comportemental
    getBehaviorContext() {
        return {
            timestamp: Date.now(),
            url: window.location.href,
            referrer: document.referrer,
            userAgent: navigator.userAgent,
            screenSize: `${screen.width}x${screen.height}`,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
        };
    }

    // Calculer le score de risque comportemental
    calculateBehaviorRisk(action) {
        let riskScore = 0;
        
        // Actions à risque élevé
        const highRiskActions = ['FILE_UPLOAD', 'ANALYSIS_START', 'CONFIG_CHANGE'];
        if (highRiskActions.includes(action)) {
            riskScore += 30;
        }
        
        // Actions à risque moyen
        const mediumRiskActions = ['LOGIN', 'LOGOUT', 'REPORT_GENERATE'];
        if (mediumRiskActions.includes(action)) {
            riskScore += 15;
        }
        
        // Vérifier l'heure (activité suspecte la nuit)
        const hour = new Date().getHours();
        if (hour < 6 || hour > 23) {
            riskScore += 10;
        }
        
        return Math.min(100, riskScore);
    }

    // Calculer le score de risque continu
    calculateContinuousRiskScore() {
        let riskScore = 0;
        
        // Vérifier la session
        if (!this.currentUser) {
            riskScore += 50;
        }
        
        // Vérifier l'activité récente
        const recentActivity = this.auditTrail.slice(-10);
        const suspiciousActions = recentActivity.filter(entry => 
            entry.level === 'CRITICAL' || entry.level === 'ERROR'
        ).length;
        
        riskScore += suspiciousActions * 10;
        
        return Math.min(100, riskScore);
    }

    // Authentification continue
    performContinuousAuth() {
        const riskScore = this.calculateContinuousRiskScore();
        
        if (riskScore > 80) {
            this.auditLogger.critical('CONTINUOUS_AUTH_FAILED', { riskScore });
            this.logout();
            return false;
        }
        
        return true;
    }

    // Vérifier l'autorisation
    checkAuthorization(action, resource) {
        if (!this.currentUser) {
            return false;
        }
        
        // Vérifier les permissions de l'utilisateur
        const permissions = this.currentUser.permissions || [];
        
        if (!permissions.includes(action)) {
            this.auditLogger.warn('UNAUTHORIZED_ACCESS', { 
                action, 
                resource, 
                userId: this.currentUser.id 
            });
            return false;
        }
        
        return true;
    }

    // Obtenir l'audit trail
    getAuditTrail(filters = {}) {
        let filteredTrail = [...this.auditTrail];
        
        if (filters.level) {
            filteredTrail = filteredTrail.filter(entry => entry.level === filters.level);
        }
        
        if (filters.userId) {
            filteredTrail = filteredTrail.filter(entry => entry.user === filters.userId);
        }
        
        if (filters.dateFrom) {
            filteredTrail = filteredTrail.filter(entry => 
                new Date(entry.timestamp) >= new Date(filters.dateFrom)
            );
        }
        
        if (filters.dateTo) {
            filteredTrail = filteredTrail.filter(entry => 
                new Date(entry.timestamp) <= new Date(filters.dateTo)
            );
        }
        
        return filteredTrail;
    }

    // Obtenir les statistiques de sécurité
    getSecurityStats() {
        const stats = {
            totalAuditEntries: this.auditTrail.length,
            criticalEvents: this.auditTrail.filter(entry => entry.level === 'CRITICAL').length,
            errorEvents: this.auditTrail.filter(entry => entry.level === 'ERROR').length,
            warningEvents: this.auditTrail.filter(entry => entry.level === 'WARN').length,
            currentRiskScore: this.calculateContinuousRiskScore(),
            sessionActive: !!this.currentUser,
            mfaEnabled: this.mfaEnabled
        };
        
        return stats;
    }
}

// Export pour utilisation
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { SecurityManager };
} 