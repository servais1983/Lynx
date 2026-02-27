// Lynx - Static Analysis ML Models
// Heuristic scoring based on real file content analysis

// Dangerous API patterns per category
const DANGEROUS_APIS = {
    injection:    ['CreateRemoteThread','VirtualAllocEx','WriteProcessMemory','NtWriteVirtualMemory','RtlCreateUserThread'],
    persistence:  ['RegCreateKey','RegSetValueEx','HKEY_LOCAL_MACHINE','HKEY_CURRENT_USER','schtasks','sc create'],
    evasion:      ['IsDebuggerPresent','CheckRemoteDebuggerPresent','NtQueryInformationProcess','OutputDebugString','VirtualProtect'],
    network:      ['WSAStartup','socket','connect','send','recv','InternetOpen','URLDownloadToFile','WinHttpOpen'],
    crypto:       ['CryptEncrypt','CryptDecryptMessage','BCryptEncrypt','EVP_EncryptInit','AES_encrypt'],
    keylogger:    ['SetWindowsHookEx','GetAsyncKeyState','WH_KEYBOARD','GetKeyState','keybd_event'],
    shellcode:    ['ShellExecute','WScript.Shell','cmd.exe','powershell','base64_decode','FromBase64String'],
    ransomware:   ['ransom','bitcoin','wallet','decrypt files','your files are encrypted','pay','BTC']
};

const OBFUSCATION_PATTERNS = [
    /eval\s*\(/gi,
    /unescape\s*\(/gi,
    /String\.fromCharCode/gi,
    /\\x[0-9a-fA-F]{2}/g,         // hex escapes
    /[A-Za-z0-9+/]{100,}={0,2}/g, // long base64 blocks
    /chr\(\d+\)/gi,                // VBA chr() calls
    /document\.write\s*\(/gi
];

/**
 * Compute Shannon entropy of a Uint8Array (0–8 bits).
 */
function computeEntropy(bytes) {
    if (!bytes || bytes.length === 0) return 0;
    const freq = new Uint32Array(256);
    for (const b of bytes) freq[b]++;
    let h = 0;
    const n = bytes.length;
    for (const c of freq) {
        if (c > 0) {
            const p = c / n;
            h -= p * Math.log2(p);
        }
    }
    return h;
}

/**
 * Score a text sample against a list of dangerous string patterns.
 * Returns { matchCount, matchedTerms }.
 */
function scorePatterns(text, patternList) {
    let matchCount = 0;
    const matchedTerms = [];
    const lower = text.toLowerCase();
    for (const p of patternList) {
        const term = p.toLowerCase();
        if (lower.includes(term)) {
            matchCount++;
            matchedTerms.push(p);
        }
    }
    return { matchCount, matchedTerms };
}

class MLModel {
    constructor(name, type) {
        this.name = name;
        this.type = type; // 'script' | 'executable' | 'document' | 'behavioral' | 'ransomware'
        this.features = [];
    }

    addFeature(feature) {
        this.features.push(feature);
    }

    /**
     * Analyse file content synchronously.
     * fileContent: string (text), fileBytes: Uint8Array, ext: string
     */
    score(fileContent, fileBytes, ext) {
        let risk = 0;
        const evidence = [];
        const allApiStrings = Object.values(DANGEROUS_APIS).flat();

        // --- Shannon entropy (high entropy = possible packing/encryption)
        const entropy = computeEntropy(fileBytes);
        if (entropy > 7.2) {
            risk += 30;
            evidence.push(`High entropy: ${entropy.toFixed(2)} (possible packing/encryption)`);
        } else if (entropy > 6.5) {
            risk += 15;
            evidence.push(`Elevated entropy: ${entropy.toFixed(2)}`);
        }

        // --- Dangerous API usage
        const apiScore = scorePatterns(fileContent, allApiStrings);
        if (apiScore.matchCount > 0) {
            const apiRisk = Math.min(40, apiScore.matchCount * 8);
            risk += apiRisk;
            evidence.push(`Dangerous APIs (${apiScore.matchCount}): ${apiScore.matchedTerms.slice(0,5).join(', ')}`);
        }

        // --- Obfuscation detection
        let obfCount = 0;
        for (const re of OBFUSCATION_PATTERNS) {
            const m = fileContent.match(re);
            if (m) obfCount += m.length;
        }
        if (obfCount > 5) {
            risk += 20;
            evidence.push(`Obfuscation indicators: ${obfCount} occurrences`);
        } else if (obfCount > 0) {
            risk += 8;
            evidence.push(`Possible obfuscation: ${obfCount} indicator(s)`);
        }

        // --- Ransomware-specific
        if (this.type === 'ransomware') {
            const rsScore = scorePatterns(fileContent, DANGEROUS_APIS.ransomware);
            if (rsScore.matchCount >= 2) {
                risk += 35;
                evidence.push(`Ransomware patterns: ${rsScore.matchedTerms.join(', ')}`);
            }
            const cryptoScore = scorePatterns(fileContent, DANGEROUS_APIS.crypto);
            if (cryptoScore.matchCount > 0) {
                risk += 15;
                evidence.push(`Crypto API usage: ${cryptoScore.matchedTerms.join(', ')}`);
            }
        }

        // --- Script-specific
        if (this.type === 'script') {
            const shellScore = scorePatterns(fileContent, DANGEROUS_APIS.shellcode);
            if (shellScore.matchCount > 0) {
                risk += Math.min(25, shellScore.matchCount * 6);
                evidence.push(`Shell/exec patterns: ${shellScore.matchedTerms.join(', ')}`);
            }
        }

        // --- Executable-specific: check for suspicious section names
        if (this.type === 'executable') {
            const suspSections = ['.upx', 'UPX!', 'packed', '.aspack', 'PEspin'];
            const secScore = scorePatterns(fileContent, suspSections);
            if (secScore.matchCount > 0) {
                risk += 20;
                evidence.push(`Packed/suspicious sections: ${secScore.matchedTerms.join(', ')}`);
            }
        }

        // --- Document-specific: macro patterns
        if (this.type === 'document') {
            const macroPatterns = ['AutoOpen','Document_Open','AutoExec','Shell','CreateObject','WScript'];
            const macroScore = scorePatterns(fileContent, macroPatterns);
            if (macroScore.matchCount > 0) {
                risk += Math.min(30, macroScore.matchCount * 8);
                evidence.push(`Macro indicators: ${macroScore.matchedTerms.join(', ')}`);
            }
        }

        const finalScore = Math.min(100, risk);
        const confidence = Math.min(0.97, 0.55 + (evidence.length * 0.07));

        return {
            prediction: finalScore >= 50 ? 'malicious' : finalScore >= 25 ? 'suspicious' : 'benign',
            confidence: parseFloat(confidence.toFixed(2)),
            score: finalScore,
            evidence
        };
    }
}

// Static analysis models
const ML_MODELS = {
    executable_classifier: new MLModel('Executable Classifier', 'executable'),
    document_classifier:   new MLModel('Document Classifier',   'document'),
    script_classifier:     new MLModel('Script Classifier',     'script'),
    behavioral_classifier: new MLModel('Behavioral Classifier', 'behavioral'),
    ransomware_detector:   new MLModel('Ransomware Detector',   'ransomware')
};

ML_MODELS.executable_classifier.addFeature('entropy_analysis');
ML_MODELS.executable_classifier.addFeature('import_analysis');
ML_MODELS.executable_classifier.addFeature('section_analysis');
ML_MODELS.document_classifier.addFeature('macro_analysis');
ML_MODELS.document_classifier.addFeature('embedded_objects');
ML_MODELS.script_classifier.addFeature('function_analysis');
ML_MODELS.script_classifier.addFeature('obfuscation_detection');
ML_MODELS.ransomware_detector.addFeature('encryption_patterns');
ML_MODELS.ransomware_detector.addFeature('ransom_note_detection');

/**
 * Read a file and run all applicable models.
 * Returns a Promise resolving to the results object.
 */
function analyzeWithML(file) {
    return new Promise((resolve) => {
        const ext = file.name.split('.').pop().toLowerCase();
        const reader = new FileReader();

        reader.onload = (e) => {
            const bytes = new Uint8Array(e.target.result);
            // Text decoding — ignore errors for binary files
            let text = '';
            try { text = new TextDecoder('utf-8', { fatal: false }).decode(bytes); } catch (_) {}

            let primaryModel = ML_MODELS.behavioral_classifier;
            if (['exe','dll','sys','scr'].includes(ext))             primaryModel = ML_MODELS.executable_classifier;
            else if (['doc','docx','xls','xlsx','ppt','pptx'].includes(ext)) primaryModel = ML_MODELS.document_classifier;
            else if (['js','vbs','ps1','bat','cmd','hta','wsf'].includes(ext)) primaryModel = ML_MODELS.script_classifier;

            const primary    = primaryModel.score(text, bytes, ext);
            const ransomware = ML_MODELS.ransomware_detector.score(text, bytes, ext);

            resolve({
                primary: {
                    model:      primaryModel.name,
                    prediction: primary.prediction,
                    confidence: primary.confidence,
                    score:      primary.score,
                    evidence:   primary.evidence
                },
                ransomware: {
                    model:      ML_MODELS.ransomware_detector.name,
                    prediction: ransomware.prediction,
                    confidence: ransomware.confidence,
                    score:      ransomware.score,
                    evidence:   ransomware.evidence
                }
            });
        };

        reader.onerror = () => resolve({
            primary:    { model: 'N/A', prediction: 'error', confidence: 0, score: 0, evidence: [] },
            ransomware: { model: 'N/A', prediction: 'error', confidence: 0, score: 0, evidence: [] }
        });

        reader.readAsArrayBuffer(file);
    });
}

function getMLRecommendation(mlResults) {
    const recommendations = [];
    if (mlResults.primary.prediction === 'malicious') {
        recommendations.push(`[THREAT] ${mlResults.primary.model}: score ${mlResults.primary.score}/100`);
        if (mlResults.primary.evidence && mlResults.primary.evidence.length)
            recommendations.push(...mlResults.primary.evidence.map(e => `  - ${e}`));
    } else if (mlResults.primary.prediction === 'suspicious') {
        recommendations.push(`[SUSPICIOUS] ${mlResults.primary.model}: score ${mlResults.primary.score}/100`);
    }
    if (mlResults.ransomware.prediction === 'malicious') {
        recommendations.push(`[RANSOMWARE] ${mlResults.ransomware.model}: score ${mlResults.ransomware.score}/100`);
        if (mlResults.ransomware.evidence && mlResults.ransomware.evidence.length)
            recommendations.push(...mlResults.ransomware.evidence.map(e => `  - ${e}`));
    }
    if (mlResults.primary.confidence < 0.60)
        recommendations.push('Low confidence result — manual review recommended.');
    if (recommendations.length === 0)
        recommendations.push('No threats detected by static analysis.');
    return recommendations;
}

function calculateGlobalRiskScore(mlResults) {
    // Ransomware detection weighted at 65%, primary model at 35%
    return Math.round((mlResults.primary.score * 0.35) + (mlResults.ransomware.score * 0.65));
}

function getMLInsights(mlResults) {
    return [
        `Primary model   : ${mlResults.primary.model}`,
        `Confidence      : ${Math.round(mlResults.primary.confidence * 100)}%`,
        `Static score    : ${mlResults.primary.score}/100`,
        `Ransomware score: ${mlResults.ransomware.score}/100`,
        ...(mlResults.primary.evidence  || []).map(e => `  evidence: ${e}`),
        ...(mlResults.ransomware.evidence || []).map(e => `  ransomware: ${e}`)
    ];
}

// Export des fonctions pour utilisation dans le fichier principal
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        ML_MODELS,
        analyzeWithML,
        getMLRecommendation,
        calculateGlobalRiskScore,
        getMLInsights
    };
} 