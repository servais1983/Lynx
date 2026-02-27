// Lynx - AI Engine powered by Transformers.js (Hugging Face)
// Uses real in-browser inference via ONNX Runtime Web
// Model: Xenova/nli-deberta-v3-small  (zero-shot classification)
// CDN:   https://cdn.jsdelivr.net/npm/@xenova/transformers@2

/**
 * Lazy-load the Transformers.js pipeline.
 * Uses a module-level singleton so the model is only downloaded once.
 */

let _pipelinePromise = null;

async function getClassifier() {
    if (_pipelinePromise) return _pipelinePromise;

    const { pipeline } = await import(
        'https://cdn.jsdelivr.net/npm/@xenova/transformers@2/dist/transformers.min.js'
    );

    _pipelinePromise = pipeline(
        'zero-shot-classification',
        'Xenova/nli-deberta-v3-small',
        { quantized: true }
    );

    return _pipelinePromise;
}

const THREAT_LABELS = ['malware','ransomware','trojan','backdoor','keylogger','benign'];

// ── Heuristic helpers (deterministic, no Math.random) ────────────────────────

function shannonEntropy(bytes) {
    if (!bytes || bytes.length === 0) return 0;
    const freq = new Uint32Array(256);
    for (const b of bytes) freq[b]++;
    let h = 0;
    const n = bytes.length;
    for (const c of freq) {
        if (c > 0) { const p = c / n; h -= p * Math.log2(p); }
    }
    return h;
}

const INJECTION_APIS   = ['CreateRemoteThread','VirtualAllocEx','WriteProcessMemory','NtWriteVirtualMemory'];
const EVASION_APIS     = ['IsDebuggerPresent','CheckRemoteDebuggerPresent','NtQueryInformationProcess'];
const PERSISTENCE_APIS = ['RegCreateKey','RegSetValueEx','schtasks','sc create','HKLM','HKCU'];
const NETWORK_APIS     = ['WSAStartup','socket','connect','WinHttpOpen','URLDownloadToFile','InternetOpen'];
const CRYPTO_APIS      = ['CryptEncrypt','BCryptEncrypt','EVP_EncryptInit','AES_encrypt'];
const SHELL_APIS       = ['ShellExecute','WScript.Shell','cmd.exe','powershell','base64_decode','FromBase64String'];
const RANSOM_TERMS     = ['ransom','bitcoin','payment','your files have been encrypted','decrypt your files','pay'];
const KEYLOG_APIS      = ['SetWindowsHookEx','GetAsyncKeyState','WH_KEYBOARD','keybd_event'];

function countHits(text, terms) {
    const lower = text.toLowerCase();
    return terms.filter(t => lower.includes(t.toLowerCase())).length;
}

function extractTextFeatures(content, bytes, ext) {
    return {
        entropy:         shannonEntropy(bytes),
        injectionHits:   countHits(content, INJECTION_APIS),
        evasionHits:     countHits(content, EVASION_APIS),
        persistenceHits: countHits(content, PERSISTENCE_APIS),
        networkHits:     countHits(content, NETWORK_APIS),
        cryptoHits:      countHits(content, CRYPTO_APIS),
        shellHits:       countHits(content, SHELL_APIS),
        ransomHits:      countHits(content, RANSOM_TERMS),
        keylogHits:      countHits(content, KEYLOG_APIS),
        obfuscation:     (content.match(/[A-Za-z0-9+/]{80,}={0,2}/g)||[]).length +
                         (content.match(/\\x[0-9a-fA-F]{2}/g)||[]).length +
                         (content.match(/eval\s*\(/gi)||[]).length,
        ext
    };
}

// ── SecureAIEngine ────────────────────────────────────────────────────────────

class SecureAIEngine {
    constructor() {
        this.classifier    = null;
        this.isInitialized = false;
        this.rateLimit     = { count: 0, windowStart: 0, max: 100 };
    }

    async initialize() {
        console.log('AI Engine: loading Transformers.js (Xenova/nli-deberta-v3-small)...');
        try {
            this.classifier    = await getClassifier();
            this.isInitialized = true;
            console.log('AI Engine: ready.');
        } catch (err) {
            console.warn('AI Engine: Transformers.js unavailable, heuristic-only mode.', err.message);
            this.classifier    = null;
            this.isInitialized = true;
        }
    }

    checkRateLimit() {
        const now = Date.now();
        if (now - this.rateLimit.windowStart > 60000) {
            this.rateLimit.count       = 0;
            this.rateLimit.windowStart = now;
        }
        return ++this.rateLimit.count <= this.rateLimit.max;
    }

    validateFile(file) {
        return file && file.size > 0 && file.size <= 100 * 1024 * 1024;
    }

    async analyzeFile(file, options = {}) {
        if (!this.isInitialized) throw new Error('AI Engine not initialized');
        if (!this.checkRateLimit())  throw new Error('Rate limit exceeded');
        if (!this.validateFile(file)) throw new Error('Invalid file');

        const { bytes, text } = await this._readFile(file);
        const ext     = file.name.split('.').pop().toLowerCase();
        const features = extractTextFeatures(text, bytes, ext);

        const heuristicResult = this._heuristicScore(features);
        let llmResult = null;
        if (this.classifier && text.trim().length > 20) {
            llmResult = await this._classifyWithLLM(text, file.name);
        }

        return this._combine(heuristicResult, llmResult, features);
    }

    // ── Private ──────────────────────────────────────────────────────────────

    _readFile(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => {
                const bytes = new Uint8Array(e.target.result);
                const text  = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
                resolve({ bytes, text });
            };
            reader.onerror = reject;
            reader.readAsArrayBuffer(file);
        });
    }

    _heuristicScore(f) {
        let score    = 0;
        const issues = [];

        if (f.entropy > 7.2)      { score += 28; issues.push(`Entropy ${f.entropy.toFixed(2)} — likely packed/encrypted`); }
        else if (f.entropy > 6.5) { score += 12; issues.push(`Entropy ${f.entropy.toFixed(2)} — elevated`); }

        if (f.injectionHits > 0)   { score += f.injectionHits   * 9;  issues.push(`Process injection APIs (${f.injectionHits})`); }
        if (f.evasionHits > 0)     { score += f.evasionHits     * 7;  issues.push(`Anti-debug/evasion APIs (${f.evasionHits})`); }
        if (f.persistenceHits > 0) { score += f.persistenceHits * 6;  issues.push(`Persistence mechanisms (${f.persistenceHits})`); }
        if (f.cryptoHits > 0)      { score += f.cryptoHits      * 5;  issues.push(`Crypto APIs (${f.cryptoHits})`); }
        if (f.shellHits > 0)       { score += f.shellHits       * 7;  issues.push(`Shell/exec APIs (${f.shellHits})`); }
        if (f.keylogHits > 0)      { score += f.keylogHits      * 10; issues.push(`Keylogger APIs (${f.keylogHits})`); }
        if (f.ransomHits > 0)      { score += f.ransomHits      * 10; issues.push(`Ransom-related strings (${f.ransomHits})`); }
        if (f.obfuscation > 5)     { score += 18; issues.push(`Obfuscation indicators (${f.obfuscation})`); }
        else if (f.obfuscation > 0){ score += 6;  issues.push(`Possible obfuscation (${f.obfuscation})`); }

        return { score: Math.min(100, score), issues, entropy: f.entropy };
    }

    async _classifyWithLLM(text, filename) {
        try {
            const sample = text.replace(/[^\x20-\x7E\n]/g, '').slice(0, 1500) || filename;
            const result = await this.classifier(sample, THREAT_LABELS, { multi_label: false });
            const map = {};
            result.labels.forEach((l, i) => { map[l] = result.scores[i]; });
            return map;
        } catch (err) {
            console.warn('LLM classification failed:', err.message);
            return null;
        }
    }

    _combine(heuristic, llm, features) {
        let finalScore = heuristic.score;
        const insights = [...(heuristic.issues || [])];
        let llmThreat  = null;
        let llmBenign  = null;

        if (llm) {
            const nonBenign = THREAT_LABELS.filter(l => l !== 'benign');
            llmThreat  = nonBenign.reduce((best, l) => llm[l] > llm[best] ? l : best, nonBenign[0]);
            llmBenign  = llm['benign'] || 0;
            const llmScore = (1 - llmBenign) * 100;
            finalScore = Math.round(finalScore * 0.55 + llmScore * 0.45);
            insights.push(`LLM: ${llmThreat} (${(llm[llmThreat] * 100).toFixed(1)}% confidence)`);
            insights.push(`LLM benign probability: ${(llmBenign * 100).toFixed(1)}%`);
        }

        return {
            score:           finalScore,
            confidence:      llm ? Math.min(0.97, 0.60 + (heuristic.issues.length * 0.05)) : 0.75,
            threatLevel:     this._toThreatLevel(finalScore),
            entropy:         features.entropy,
            insights,
            recommendations: this._recommendations(finalScore, llmThreat),
            details:         { heuristic, llm }
        };
    }

    _toThreatLevel(score) {
        if (score >= 80) return 'CRITICAL';
        if (score >= 60) return 'HIGH';
        if (score >= 35) return 'MEDIUM';
        if (score >= 15) return 'LOW';
        return 'SAFE';
    }

    _recommendations(score, llmLabel) {
        const recs = [];
        if (score >= 80)      recs.push('CRITICAL: Quarantine immediately and isolate the system.');
        else if (score >= 60) recs.push('HIGH: Do not execute. Submit for further analysis.');
        else if (score >= 35) recs.push('MEDIUM: Treat with caution. Manual review recommended.');
        else if (score >= 15) recs.push('LOW: Minor indicators present. Monitor if deployed.');
        else                  recs.push('SAFE: No significant threat indicators detected.');
        if (llmLabel && llmLabel !== 'benign')
            recs.push(`LLM identified behaviour consistent with: ${llmLabel.toUpperCase()}`);
        return recs;
    }

    // Legacy-compatible helpers used by lynx.js
    getFileType(filename) {
        return filename.split('.').pop().toLowerCase();
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { SecureAIEngine };
}
