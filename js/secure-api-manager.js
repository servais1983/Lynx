// Gestionnaire d'API sécurisé pour Lynx
// Gère les clés d'API de manière sécurisée

// Local escape helper — prevents XSS when inserting user-supplied values into HTML
function _escHtml(str) {
    if (str == null) return '';
    return String(str)
        .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
        .replace(/"/g,'&quot;').replace(/'/g,'&#x27;');
}
    constructor() {
        this.apiKeys = new Map();
        this.rateLimiters = new Map();
        this.encryptionKey = this.generateEncryptionKey();
        this.init();
    }

    // Initialisation
    async init() {
        await this.loadStoredKeys();
        this.setupRateLimiters();
        this.setupSecurityHeaders();
    }

    // Generates a stable master key: reuses the one stored in localStorage,
    // or creates a new random key on first run and persists it.
    generateEncryptionKey() {
        const STORAGE_KEY = 'lynx_master_key';
        const stored = localStorage.getItem(STORAGE_KEY);
        if (stored && stored.length === 64) {
            return stored; // Reuse existing key
        }
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        const key = Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
        localStorage.setItem(STORAGE_KEY, key);
        return key;
    }

    // Chargement des clés stockées de manière sécurisée
    async loadStoredKeys() {
        try {
            const storedKeys = localStorage.getItem('lynx_api_keys');
            if (storedKeys) {
                const decryptedKeys = await this.decryptData(storedKeys);
                const keys = JSON.parse(decryptedKeys);
                
                for (const [service, key] of Object.entries(keys)) {
                    this.apiKeys.set(service, key);
                }
            }
        } catch (error) {
            console.warn('Erreur lors du chargement des clés API:', error);
        }
    }

    // Sauvegarde sécurisée des clés
    async saveKeys() {
        try {
            const keysObject = {};
            for (const [service, key] of this.apiKeys.entries()) {
                keysObject[service] = key;
            }
            
            const encryptedKeys = await this.encryptData(JSON.stringify(keysObject));
            localStorage.setItem('lynx_api_keys', encryptedKeys);
        } catch (error) {
            console.error('Erreur lors de la sauvegarde des clés:', error);
        }
    }

    // Chiffrement des données
    async encryptData(data) {
        try {
            const encoder = new TextEncoder();
            const dataBuffer = encoder.encode(data);
            
            // Génération d'un IV aléatoire
            const iv = crypto.getRandomValues(new Uint8Array(12));
            
            // Import de la clé
            const keyMaterial = await crypto.subtle.importKey(
                'raw',
                encoder.encode(this.encryptionKey),
                { name: 'PBKDF2' },
                false,
                ['deriveBits', 'deriveKey']
            );
            
            // Derivation of the wrapping key
            const key = await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: encoder.encode('lynx-' + this.encryptionKey.slice(0, 16)),
                    iterations: 210000,
                    hash: 'SHA-256'
                },
                keyMaterial,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt']
            );
            
            // Chiffrement
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                dataBuffer
            );
            
            // Combinaison IV + données chiffrées
            const result = new Uint8Array(iv.length + encrypted.length);
            result.set(iv);
            result.set(new Uint8Array(encrypted), iv.length);
            
            return btoa(String.fromCharCode(...result));
        } catch (error) {
            console.error('Erreur de chiffrement:', error);
            throw error;
        }
    }

    // Déchiffrement des données
    async decryptData(encryptedData) {
        try {
            const decoder = new TextDecoder();
            const data = Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0));
            
            // Séparation IV et données
            const iv = data.slice(0, 12);
            const encrypted = data.slice(12);
            
            // Import de la clé
            const encoder = new TextEncoder();
            const keyMaterial = await crypto.subtle.importKey(
                'raw',
                encoder.encode(this.encryptionKey),
                { name: 'PBKDF2' },
                false,
                ['deriveBits', 'deriveKey']
            );
            
            // Derivation of the unwrapping key
            const key = await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: encoder.encode('lynx-' + this.encryptionKey.slice(0, 16)),
                    iterations: 210000,
                    hash: 'SHA-256'
                },
                keyMaterial,
                { name: 'AES-GCM', length: 256 },
                false,
                ['decrypt']
            );
            
            // Déchiffrement
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                encrypted
            );
            
            return decoder.decode(decrypted);
        } catch (error) {
            console.error('Erreur de déchiffrement:', error);
            throw error;
        }
    }

    // Configuration des rate limiters
    setupRateLimiters() {
        // VirusTotal: 4 requêtes par minute
        this.rateLimiters.set('virustotal', {
            maxRequests: 4,
            windowMs: 60000, // 1 minute
            requests: []
        });
        
        // API personnalisée: 100 requêtes par minute
        this.rateLimiters.set('custom', {
            maxRequests: 100,
            windowMs: 60000,
            requests: []
        });
    }

    // Configuration des en-têtes de sécurité
    setupSecurityHeaders() {
        // Ajout d'en-têtes de sécurité pour les requêtes
        this.securityHeaders = {
            'X-Requested-With': 'XMLHttpRequest',
            'X-Lynx-Version': '1.0.0',
            'X-Lynx-Client': 'browser'
        };
    }

    // Ajout d'une clé API
    async addAPIKey(service, key) {
        this.apiKeys.set(service, key);
        await this.saveKeys();
        
        // Log de sécurité
        this.logSecurityEvent('API_KEY_ADDED', {
            service: service,
            timestamp: new Date().toISOString()
        });
    }

    // Récupération d'une clé API
    getAPIKey(service) {
        return this.apiKeys.get(service);
    }

    // Suppression d'une clé API
    async removeAPIKey(service) {
        this.apiKeys.delete(service);
        await this.saveKeys();
        
        // Log de sécurité
        this.logSecurityEvent('API_KEY_REMOVED', {
            service: service,
            timestamp: new Date().toISOString()
        });
    }

    // Vérification du rate limiting
    async checkRateLimit(service) {
        const limiter = this.rateLimiters.get(service);
        if (!limiter) {
            return true; // Pas de limite pour ce service
        }

        const now = Date.now();
        const windowStart = now - limiter.windowMs;

        // Nettoyage des anciennes requêtes
        limiter.requests = limiter.requests.filter(time => time > windowStart);

        // Vérification de la limite
        if (limiter.requests.length >= limiter.maxRequests) {
            const oldestRequest = limiter.requests[0];
            const waitTime = windowStart + limiter.windowMs - oldestRequest;
            
            throw new Error(`Rate limit dépassé pour ${service}. Attendez ${Math.ceil(waitTime / 1000)} secondes.`);
        }

        // Ajout de la requête actuelle
        limiter.requests.push(now);
        return true;
    }

    // Requête API sécurisée
    async secureRequest(service, url, options = {}) {
        try {
            // Vérification du rate limiting
            await this.checkRateLimit(service);

            // Récupération de la clé API
            const apiKey = this.getAPIKey(service);
            if (!apiKey) {
                throw new Error(`Clé API manquante pour ${service}`);
            }

            // Configuration de la requête
            const requestOptions = {
                method: options.method || 'GET',
                headers: {
                    ...this.securityHeaders,
                    ...options.headers
                },
                body: options.body
            };

            // Ajout de la clé API selon le service
            if (service === 'virustotal') {
                if (requestOptions.method === 'POST') {
                    const formData = new FormData();
                    formData.append('apikey', apiKey);
                    if (options.body) {
                        for (const [key, value] of Object.entries(options.body)) {
                            formData.append(key, value);
                        }
                    }
                    requestOptions.body = formData;
                } else {
                    const urlObj = new URL(url);
                    urlObj.searchParams.append('apikey', apiKey);
                    url = urlObj.toString();
                }
            }

            // Exécution de la requête
            const response = await fetch(url, requestOptions);

            // Vérification de la réponse
            if (!response.ok) {
                throw new Error(`Erreur HTTP ${response.status}: ${response.statusText}`);
            }

            // Log de sécurité
            this.logSecurityEvent('API_REQUEST_SUCCESS', {
                service: service,
                url: url,
                status: response.status,
                timestamp: new Date().toISOString()
            });

            return response;
        } catch (error) {
            // Log de sécurité
            this.logSecurityEvent('API_REQUEST_ERROR', {
                service: service,
                url: url,
                error: error.message,
                timestamp: new Date().toISOString()
            });

            throw error;
        }
    }

    // Log de sécurité
    logSecurityEvent(event, data) {
        const logEntry = {
            event: event,
            data: data,
            timestamp: new Date().toISOString(),
            userAgent: navigator.userAgent,
            url: window.location.href
        };

        // Stockage local des logs de sécurité
        const securityLogs = JSON.parse(localStorage.getItem('lynx_security_logs') || '[]');
        securityLogs.push(logEntry);
        
        // Limitation à 1000 entrées
        if (securityLogs.length > 1000) {
            securityLogs.splice(0, securityLogs.length - 1000);
        }
        
        localStorage.setItem('lynx_security_logs', JSON.stringify(securityLogs));
        
        // Log console en développement
        if (window.location.hostname === 'localhost') {
            console.log('Security Event:', logEntry);
        }
    }

    // Interface utilisateur pour la gestion des clés
    showAPIKeyManager() {
        const existing = document.getElementById('api-key-modal');
        if (existing) existing.remove();

        const modal = document.createElement('div');
        modal.id = 'api-key-modal';
        modal.className = 'api-key-modal';
        modal.innerHTML = `
            <div class="modal-content">
                <h3>API Key Management</h3>
                <div class="api-keys-list" id="api-keys-list">
                    ${this.generateAPIKeysList()}
                </div>
                <div class="add-key-form">
                    <h4>Add a new key</h4>
                    <select id="serviceSelect">
                        <option value="virustotal">VirusTotal</option>
                        <option value="custom">Custom API</option>
                    </select>
                    <input type="password" id="apiKeyInput" placeholder="API Key" autocomplete="off">
                    <button id="addApiKeyBtn">Add</button>
                </div>
                <button id="closeApiKeyModal">Close</button>
            </div>
        `;
        document.body.appendChild(modal);

        // Use event delegation — never use inline onclick with data from the key map
        modal.querySelector('#addApiKeyBtn').addEventListener('click', () => this.addKeyFromUI());
        modal.querySelector('#closeApiKeyModal').addEventListener('click', () => modal.remove());
        modal.querySelector('#api-keys-list').addEventListener('click', (e) => {
            if (e.target.classList.contains('remove-api-key-btn')) {
                const service = e.target.closest('[data-service]').getAttribute('data-service');
                if (service) this.removeAPIKey(service).then(() => this.showAPIKeyManager());
            }
        });
    }

    // Génération de la liste des clés
    generateAPIKeysList() {
        if (this.apiKeys.size === 0) {
            return '<p style="color:#666;">No API keys configured.</p>';
        }
        let html = '';
        for (const [service, key] of this.apiKeys.entries()) {
            html += `
                <div class="api-key-item" data-service="${_escHtml(service)}">
                    <span class="service-name">${_escHtml(service)}</span>
                    <span class="key-preview">${_escHtml(key.substring(0, 8))}&hellip;</span>
                    <button class="remove-api-key-btn">Remove</button>
                </div>
            `;
        }
        return html;
    }

    // Ajout de clé depuis l'interface
    async addKeyFromUI() {
        const service = document.getElementById('serviceSelect').value;
        const key = document.getElementById('apiKeyInput').value;
        
        if (!key.trim()) {
            alert('Veuillez entrer une clé API');
            return;
        }
        
        try {
            await this.addAPIKey(service, key);
            alert('Clé API ajoutée avec succès');
            document.getElementById('apiKeyInput').value = '';
            this.showAPIKeyManager(); // Rafraîchir l'interface
        } catch (error) {
            alert('Erreur lors de l\'ajout de la clé: ' + error.message);
        }
    }

    // Validation de la configuration
    validateConfiguration() {
        const errors = [];
        
        // Vérification des clés requises
        if (!this.apiKeys.has('virustotal')) {
            errors.push('Clé VirusTotal manquante');
        }
        
        // Vérification des rate limiters
        if (!this.rateLimiters.has('virustotal')) {
            errors.push('Rate limiter VirusTotal non configuré');
        }
        
        return errors;
    }

    // Export pour compatibilité
    export() {
        return {
            hasKey: (service) => this.apiKeys.has(service),
            getKey: (service) => this.getAPIKey(service),
            validate: () => this.validateConfiguration()
        };
    }
}

// Instance globale
const secureAPIManager = new SecureAPIManager();

// Export pour utilisation dans d'autres modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SecureAPIManager;
} else {
    window.secureAPIManager = secureAPIManager;
} 