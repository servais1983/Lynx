// Lynx - VirusTotal API v3 integration
// Uses the official v3 REST API with header-based authentication

class VirusTotalAPI {
    constructor(apiKey) {
        this.apiKey = apiKey;
        this.baseURL = 'https://www.virustotal.com/api/v3';
        this.rateLimit = 4; // requests per minute on free tier
        this.lastRequest = 0;
    }

    async checkRateLimit() {
        const now = Date.now();
        const minInterval = 60000 / this.rateLimit;
        const elapsed = now - this.lastRequest;
        if (elapsed < minInterval) {
            await new Promise(resolve => setTimeout(resolve, minInterval - elapsed));
        }
        this.lastRequest = Date.now();
    }

    async calculateFileHash(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => {
                crypto.subtle.digest('SHA-256', e.target.result).then(hashBuffer => {
                    const hashArray = Array.from(new Uint8Array(hashBuffer));
                    resolve(hashArray.map(b => b.toString(16).padStart(2, '0')).join(''));
                }).catch(reject);
            };
            reader.onerror = reject;
            reader.readAsArrayBuffer(file);
        });
    }

    async checkHash(hash) {
        if (!this.apiKey) {
            return { success: false, error: 'No API key configured', positives: 0, total: 0 };
        }
        try {
            await this.checkRateLimit();

            const response = await fetch(`${this.baseURL}/files/${hash}`, {
                method: 'GET',
                headers: {
                    'x-apikey': this.apiKey,
                    'Accept': 'application/json'
                }
            });

            if (response.status === 404) {
                return { success: false, positives: 0, total: 0, message: 'File not found in VirusTotal database' };
            }
            if (response.status === 401) {
                return { success: false, error: 'Invalid API key', positives: 0, total: 0 };
            }
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const json = await response.json();
            return this.parseV3Response(json);
        } catch (error) {
            console.error('VirusTotal error:', error);
            return { success: false, error: error.message, positives: 0, total: 0 };
        }
    }

    parseV3Response(json) {
        const attrs   = json.data && json.data.attributes;
        const stats   = attrs  && attrs.last_analysis_stats;
        if (!attrs || !stats) {
            return { success: false, positives: 0, total: 0, message: 'Unexpected response format' };
        }
        const positives  = (stats.malicious || 0) + (stats.suspicious || 0);
        const total      = Object.values(stats).reduce((a, b) => a + b, 0);
        const engines    = attrs.last_analysis_results || {};
        const detections = Object.entries(engines)
            .filter(([, v]) => v.category === 'malicious' || v.category === 'suspicious')
            .map(([engine, v]) => `${engine}: ${v.result || v.category}`);

        return {
            success:    true,
            positives,
            total,
            scan_date:  attrs.last_analysis_date,
            permalink:  `https://www.virustotal.com/gui/file/${json.data.id}`,
            detections,
            stats,
            message:    'Analysis complete'
        };
    }

    async analyzeFile(file) {
        try {
            const hash   = await this.calculateFileHash(file);
            const result = await this.checkHash(hash);
            return { file, hash, vtResult: result, analysis: this.generateAnalysis(result, file) };
        } catch (error) {
            console.error('File analysis error:', error);
            return {
                file, hash: null, vtResult: null,
                analysis: { status: 'error', riskScore: 0, details: [`Error: ${error.message}`] }
            };
        }
    }

    generateAnalysis(vtResult, file) {
        const details = [];
        let status    = 'safe';
        let riskScore = 0;

        if (!vtResult || !vtResult.success) {
            details.push(vtResult && vtResult.error ? `VirusTotal error: ${vtResult.error}` : 'File not in VirusTotal database');
            status    = 'unknown';
            riskScore = 5;
        } else {
            const rate = vtResult.total > 0 ? vtResult.positives / vtResult.total : 0;
            if (rate > 0.10) {
                status    = 'threat';
                riskScore = Math.min(100, Math.round(rate * 100) + 40);
                details.push(`DETECTED by ${vtResult.positives}/${vtResult.total} engines`);
            } else if (rate > 0.05) {
                status    = 'suspicious';
                riskScore = Math.min(80, Math.round(rate * 100) + 25);
                details.push(`Suspicious: ${vtResult.positives}/${vtResult.total} detections`);
            } else {
                status    = 'safe';
                riskScore = Math.max(0, Math.round(rate * 100));
                details.push(`Clean: ${vtResult.positives}/${vtResult.total} detections`);
            }

            if (vtResult.detections && vtResult.detections.length > 0)
                details.push(...vtResult.detections.slice(0, 5).map(d => `  - ${d}`));

            if (vtResult.scan_date)
                details.push(`Last scan: ${new Date(vtResult.scan_date * 1000).toLocaleDateString()}`);

            if (vtResult.permalink)
                details.push(`<a href="${vtResult.permalink}" target="_blank" rel="noopener">View on VirusTotal</a>`);
        }

        const ext = file.name.split('.').pop().toLowerCase();
        const dangerousExts = ['exe','scr','bat','cmd','com','pif','vbs','ps1','hta','wsf','jar','msi'];
        if (dangerousExts.includes(ext)) {
            details.push(`High-risk extension: .${ext}`);
            riskScore = Math.min(100, riskScore + 15);
        }

        return { status, riskScore: Math.round(riskScore), details, vtData: vtResult };
    }

    async analyzeFiles(files) {
        const results = [];
        for (let i = 0; i < files.length; i++) {
            console.log(`VirusTotal: ${files[i].name} (${i + 1}/${files.length})`);
            results.push(await this.analyzeFile(files[i]));
            if (i < files.length - 1)
                await new Promise(resolve => setTimeout(resolve, 16000));
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