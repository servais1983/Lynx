// Intégration API VirusTotal pour Lynx
// Utilise l'API officielle pour l'analyse en temps réel

class VirusTotalAPI {
    constructor(apiKey) {
        this.apiKey = apiKey;
        this.baseURL = 'https://www.virustotal.com/vtapi/v2';
        this.rateLimit = 4; // Requêtes par minute (gratuit)
        this.lastRequest = 0;
    }

    // Vérifier le rate limiting
    async checkRateLimit() {
        const now = Date.now();
        const timeSinceLastRequest = now - this.lastRequest;
        const minInterval = 60000 / this.rateLimit; // 60 secondes / rate limit

        if (timeSinceLastRequest < minInterval) {
            const waitTime = minInterval - timeSinceLastRequest;
            await new Promise(resolve => setTimeout(resolve, waitTime));
        }
        this.lastRequest = Date.now();
    }

    // Calculer le hash SHA256 d'un fichier
    async calculateFileHash(file) {
        return new Promise((resolve) => {
            const reader = new FileReader();
            reader.onload = function(e) {
                const arrayBuffer = e.target.result;
                crypto.subtle.digest('SHA-256', arrayBuffer).then(hashBuffer => {
                    const hashArray = Array.from(new Uint8Array(hashBuffer));
                    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                    resolve(hashHex);
                });
            };
            reader.readAsArrayBuffer(file);
        });
    }

    // Vérifier un hash dans VirusTotal
    async checkHash(hash) {
        try {
            await this.checkRateLimit();
            
            const response = await fetch(`${this.baseURL}/file/report`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    apikey: this.apiKey,
                    resource: hash
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            return this.parseVirusTotalResponse(data);
        } catch (error) {
            console.error('Erreur VirusTotal:', error);
            return {
                success: false,
                error: error.message,
                positives: 0,
                total: 0,
                scan_date: null,
                permalink: null
            };
        }
    }

    // Analyser un fichier complet
    async analyzeFile(file) {
        try {
            const hash = await this.calculateFileHash(file);
            const result = await this.checkHash(hash);
            
            return {
                file: file,
                hash: hash,
                vtResult: result,
                analysis: this.generateAnalysis(result, file)
            };
        } catch (error) {
            console.error('Erreur analyse fichier:', error);
            return {
                file: file,
                hash: null,
                vtResult: null,
                analysis: {
                    status: 'error',
                    riskScore: 0,
                    details: [`Erreur: ${error.message}`]
                }
            };
        }
    }

    // Parser la réponse VirusTotal
    parseVirusTotalResponse(data) {
        if (data.response_code === 0) {
            return {
                success: false,
                positives: 0,
                total: 0,
                scan_date: null,
                permalink: null,
                message: 'Fichier non trouvé dans la base de données'
            };
        }

        return {
            success: true,
            positives: data.positives || 0,
            total: data.total || 0,
            scan_date: data.scan_date,
            permalink: data.permalink,
            scans: data.scans || {},
            message: 'Analyse complète'
        };
    }

    // Générer l'analyse basée sur les résultats
    generateAnalysis(vtResult, file) {
        const details = [];
        let status = 'safe';
        let riskScore = 0;

        if (!vtResult.success) {
            details.push('Fichier non trouvé dans VirusTotal');
            status = 'unknown';
            riskScore = 10;
        } else {
            const detectionRate = vtResult.positives / vtResult.total;
            
            if (detectionRate > 0.1) { // Plus de 10% de détections
                status = 'threat';
                riskScore = Math.min(100, detectionRate * 100 + 50);
                details.push(`🚨 DÉTECTÉ PAR ${vtResult.positives}/${vtResult.total} ANTIVIRUS`);
            } else if (detectionRate > 0.05) { // Plus de 5% de détections
                status = 'suspicious';
                riskScore = Math.min(80, detectionRate * 100 + 30);
                details.push(`⚠️ SUSPECT: ${vtResult.positives}/${vtResult.total} détections`);
            } else {
                status = 'safe';
                riskScore = Math.max(0, 100 - (detectionRate * 100));
                details.push(`✅ Sécurisé: ${vtResult.positives}/${vtResult.total} détections`);
            }

            if (vtResult.scan_date) {
                details.push(`📅 Dernière analyse: ${new Date(vtResult.scan_date * 1000).toLocaleDateString()}`);
            }

            if (vtResult.permalink) {
                details.push(`🔗 <a href="${vtResult.permalink}" target="_blank">Voir sur VirusTotal</a>`);
            }
        }

        // Analyse supplémentaire basée sur le type de fichier
        const ext = file.name.split('.').pop().toLowerCase();
        if (['exe', 'scr', 'bat', 'cmd', 'com', 'pif'].includes(ext)) {
            details.push(`⚠️ Extension potentiellement dangereuse: .${ext}`);
            riskScore = Math.min(100, riskScore + 20);
        }

        return {
            status: status,
            riskScore: Math.round(riskScore),
            details: details,
            vtData: vtResult
        };
    }

    // Analyser plusieurs fichiers
    async analyzeFiles(files) {
        const results = [];
        
        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            console.log(`Analyse VirusTotal: ${file.name} (${i + 1}/${files.length})`);
            
            const result = await this.analyzeFile(file);
            results.push(result);
            
            // Pause entre les requêtes pour respecter le rate limit
            if (i < files.length - 1) {
                await new Promise(resolve => setTimeout(resolve, 15000)); // 15 secondes
            }
        }
        
        return results;
    }
}

// Instance globale de l'API VirusTotal
const vtAPI = new VirusTotalAPI(''); // L'utilisateur doit fournir sa propre clé API via l'interface

// Export pour utilisation dans d'autres modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        VirusTotalAPI,
        vtAPI
    };
} 