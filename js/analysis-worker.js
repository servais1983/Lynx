// Web Worker pour l'analyse parallèle des fichiers
// Exécution en arrière-plan sans bloquer l'interface

// Configuration du worker
const WORKER_CONFIG = {
    maxConcurrentAnalyses: 4,
    timeout: 30000, // 30 secondes
    chunkSize: 1024 * 1024, // 1MB par chunk
    enableCompression: true
};

// État du worker
let workerState = {
    isBusy: false,
    currentAnalyses: 0,
    completedAnalyses: 0,
    failedAnalyses: 0,
    startTime: null
};

// Cache des modèles IA
let aiModels = null;
let yaraRules = null;
let signatures = null;

// Initialisation du worker
self.onmessage = function(e) {
    const { type, data } = e.data;
    
    switch (type) {
        case 'INIT':
            initializeWorker(data);
            break;
        case 'ANALYZE_FILE':
            analyzeFile(data);
            break;
        case 'ANALYZE_BATCH':
            analyzeBatch(data);
            break;
        case 'GET_STATUS':
            sendStatus();
            break;
        case 'CLEANUP':
            cleanup();
            break;
        default:
            console.warn('Type de message inconnu:', type);
    }
};

// Initialiser le worker
async function initializeWorker(config) {
    try {
        console.log('🔧 Initialisation du Web Worker...');
        
        // Charger les ressources
        await loadResources(config);
        
        // Initialiser l'état
        workerState.startTime = Date.now();
        
        self.postMessage({
            type: 'WORKER_READY',
            data: {
                maxConcurrentAnalyses: WORKER_CONFIG.maxConcurrentAnalyses,
                capabilities: ['file_analysis', 'batch_processing', 'ai_inference', 'yara_matching']
            }
        });
        
        console.log('✅ Web Worker initialisé');
        
    } catch (error) {
        self.postMessage({
            type: 'WORKER_ERROR',
            error: error.message
        });
    }
}

// Charger les ressources nécessaires
async function loadResources(config) {
    // Charger les modèles IA
    aiModels = await loadAIModels();
    
    // Charger les règles YARA
    yaraRules = await loadYARARules();
    
    // Charger les signatures
    signatures = await loadSignatures();
    
    console.log('📦 Ressources chargées:', {
        aiModels: Object.keys(aiModels).length,
        yaraRules: Object.keys(yaraRules).length,
        signatures: signatures.length
    });
}

// Analyser un fichier
async function analyzeFile(fileData) {
    if (workerState.currentAnalyses >= WORKER_CONFIG.maxConcurrentAnalyses) {
        self.postMessage({
            type: 'ANALYSIS_QUEUED',
            fileId: fileData.id
        });
        return;
    }
    
    workerState.isBusy = true;
    workerState.currentAnalyses++;
    
    const analysisId = generateAnalysisId();
    const startTime = Date.now();
    
    try {
        console.log(`🔍 Début analyse: ${fileData.name}`);
        
        // Analyser le fichier par chunks
        const chunks = await splitFileIntoChunks(fileData.content);
        const analysisResults = [];
        
        for (let i = 0; i < chunks.length; i++) {
            const chunk = chunks[i];
            
            // Analyse IA
            const aiResults = await analyzeChunkWithAI(chunk, fileData);
            analysisResults.push(aiResults);
            
            // Analyse YARA
            const yaraResults = await analyzeChunkWithYARA(chunk, fileData);
            analysisResults.push(yaraResults);
            
            // Analyse des signatures
            const signatureResults = await analyzeChunkWithSignatures(chunk, fileData);
            analysisResults.push(signatureResults);
            
            // Progression
            const progress = ((i + 1) / chunks.length) * 100;
            self.postMessage({
                type: 'ANALYSIS_PROGRESS',
                analysisId: analysisId,
                progress: progress,
                chunk: i + 1,
                totalChunks: chunks.length
            });
        }
        
        // Combiner les résultats
        const finalResults = combineAnalysisResults(analysisResults, fileData);
        
        const analysisTime = Date.now() - startTime;
        workerState.completedAnalyses++;
        
        self.postMessage({
            type: 'ANALYSIS_COMPLETE',
            analysisId: analysisId,
            results: finalResults,
            analysisTime: analysisTime,
            fileId: fileData.id
        });
        
        console.log(`✅ Analyse terminée: ${fileData.name} (${analysisTime}ms)`);
        
    } catch (error) {
        workerState.failedAnalyses++;
        
        self.postMessage({
            type: 'ANALYSIS_ERROR',
            analysisId: analysisId,
            error: error.message,
            fileId: fileData.id
        });
        
        console.error(`❌ Erreur analyse: ${fileData.name}`, error);
    } finally {
        workerState.currentAnalyses--;
        if (workerState.currentAnalyses === 0) {
            workerState.isBusy = false;
        }
    }
}

// Analyser un lot de fichiers
async function analyzeBatch(batchData) {
    const { files, options } = batchData;
    const batchId = generateBatchId();
    const results = [];
    
    console.log(`📦 Début analyse batch: ${files.length} fichiers`);
    
    // Traiter les fichiers en parallèle avec limitation
    const chunks = chunkArray(files, WORKER_CONFIG.maxConcurrentAnalyses);
    
    for (let i = 0; i < chunks.length; i++) {
        const chunk = chunks[i];
        const chunkPromises = chunk.map(file => analyzeFileInBatch(file, options));
        
        const chunkResults = await Promise.allSettled(chunkPromises);
        
        // Ajouter les résultats
        chunkResults.forEach((result, index) => {
            if (result.status === 'fulfilled') {
                results.push(result.value);
            } else {
                results.push({
                    fileId: chunk[index].id,
                    error: result.reason.message,
                    status: 'failed'
                });
            }
        });
        
        // Progression du batch
        const progress = ((i + 1) / chunks.length) * 100;
        self.postMessage({
            type: 'BATCH_PROGRESS',
            batchId: batchId,
            progress: progress,
            completed: results.length,
            total: files.length
        });
    }
    
    self.postMessage({
        type: 'BATCH_COMPLETE',
        batchId: batchId,
        results: results,
        summary: generateBatchSummary(results)
    });
    
    console.log(`✅ Batch terminé: ${results.length} fichiers analysés`);
}

// Analyser un fichier dans un batch
async function analyzeFileInBatch(fileData, options) {
    return new Promise(async (resolve, reject) => {
        const timeout = setTimeout(() => {
            reject(new Error('Timeout d\'analyse'));
        }, WORKER_CONFIG.timeout);
        
        try {
            const results = await analyzeFile(fileData);
            clearTimeout(timeout);
            resolve(results);
        } catch (error) {
            clearTimeout(timeout);
            reject(error);
        }
    });
}

// Diviser un fichier en chunks
async function splitFileIntoChunks(fileContent) {
    const chunks = [];
    const chunkSize = WORKER_CONFIG.chunkSize;
    
    for (let i = 0; i < fileContent.length; i += chunkSize) {
        const chunk = fileContent.slice(i, i + chunkSize);
        chunks.push(chunk);
    }
    
    return chunks;
}

// Analyser un chunk avec l'IA
async function analyzeChunkWithAI(chunk, fileData) {
    if (!aiModels) return null;
    
    const features = extractFeatures(chunk, fileData);
    const results = {};
    
    for (const [modelName, model] of Object.entries(aiModels)) {
        try {
            const prediction = await model.predict(features);
            results[modelName] = prediction;
        } catch (error) {
            console.warn(`Erreur modèle ${modelName}:`, error);
        }
    }
    
    return {
        type: 'ai_analysis',
        results: results,
        features: features
    };
}

// Analyser un chunk avec YARA
async function analyzeChunkWithYARA(chunk, fileData) {
    if (!yaraRules) return null;
    
    const matches = [];
    const chunkString = chunk.toString();
    
    for (const [ruleName, rule] of Object.entries(yaraRules)) {
        try {
            const ruleMatches = rule.patterns.filter(pattern => 
                chunkString.toLowerCase().includes(pattern.toLowerCase())
            );
            
            if (ruleMatches.length > 0) {
                matches.push({
                    rule: ruleName,
                    patterns: ruleMatches,
                    severity: rule.severity,
                    description: rule.description
                });
            }
        } catch (error) {
            console.warn(`Erreur règle YARA ${ruleName}:`, error);
        }
    }
    
    return {
        type: 'yara_analysis',
        matches: matches
    };
}

// Analyser un chunk avec les signatures
async function analyzeChunkWithSignatures(chunk, fileData) {
    if (!signatures) return null;
    
    const matches = [];
    const chunkString = chunk.toString();
    
    for (const signature of signatures) {
        try {
            if (signature.enabled && chunkString.toLowerCase().includes(signature.pattern.toLowerCase())) {
                matches.push({
                    signature: signature.name,
                    pattern: signature.pattern,
                    category: signature.category,
                    confidence: signature.confidence
                });
            }
        } catch (error) {
            console.warn(`Erreur signature ${signature.name}:`, error);
        }
    }
    
    return {
        type: 'signature_analysis',
        matches: matches
    };
}

// Extraire les features d'un chunk
function extractFeatures(chunk, fileData) {
    const features = {
        // Features de base
        chunkSize: chunk.length,
        fileSize: fileData.size,
        fileType: fileData.type,
        
        // Features de contenu
        entropy: calculateEntropy(chunk),
        stringCount: extractStrings(chunk).length,
        
        // Features statistiques
        byteDistribution: calculateByteDistribution(chunk),
        patternDensity: calculatePatternDensity(chunk)
    };
    
    return features;
}

// Calculer l'entropie Shannon
function calculateEntropy(data) {
    const byteCounts = new Array(256).fill(0);
    
    for (let i = 0; i < data.length; i++) {
        byteCounts[data[i]]++;
    }
    
    let entropy = 0;
    const totalBytes = data.length;
    
    for (let count of byteCounts) {
        if (count > 0) {
            const probability = count / totalBytes;
            entropy -= probability * Math.log2(probability);
        }
    }
    
    return entropy;
}

// Extraire les chaînes de caractères
function extractStrings(data) {
    const strings = [];
    let currentString = '';
    
    for (let i = 0; i < data.length; i++) {
        const byte = data[i];
        
        if (byte >= 32 && byte <= 126) { // Caractères imprimables
            currentString += String.fromCharCode(byte);
        } else {
            if (currentString.length >= 4) {
                strings.push(currentString);
            }
            currentString = '';
        }
    }
    
    if (currentString.length >= 4) {
        strings.push(currentString);
    }
    
    return strings;
}

// Calculer la distribution des bytes
function calculateByteDistribution(data) {
    const distribution = new Array(256).fill(0);
    
    for (let i = 0; i < data.length; i++) {
        distribution[data[i]]++;
    }
    
    return distribution;
}

// Calculer la densité de patterns
function calculatePatternDensity(data) {
    const suspiciousPatterns = [
        'malware', 'virus', 'trojan', 'backdoor', 'keylogger',
        'encrypt', 'ransom', 'shellcode', 'exploit', 'payload'
    ];
    
    const dataString = data.toString().toLowerCase();
    let matchCount = 0;
    
    for (const pattern of suspiciousPatterns) {
        if (dataString.includes(pattern)) {
            matchCount++;
        }
    }
    
    return matchCount / suspiciousPatterns.length;
}

// Combiner les résultats d'analyse
function combineAnalysisResults(results, fileData) {
    const combined = {
        fileName: fileData.name,
        fileSize: fileData.size,
        fileType: fileData.type,
        timestamp: new Date().toISOString(),
        analysisResults: results,
        summary: generateAnalysisSummary(results),
        riskScore: calculateRiskScore(results),
        status: determineStatus(results)
    };
    
    return combined;
}

// Générer un résumé d'analyse
function generateAnalysisSummary(results) {
    const summary = {
        aiDetections: 0,
        yaraMatches: 0,
        signatureMatches: 0,
        totalThreats: 0,
        totalSuspicious: 0
    };
    
    results.forEach(result => {
        if (result.type === 'ai_analysis' && result.results) {
            Object.values(result.results).forEach(prediction => {
                if (prediction.prediction === 'malicious') {
                    summary.aiDetections++;
                    summary.totalThreats++;
                }
            });
        }
        
        if (result.type === 'yara_analysis' && result.matches) {
            summary.yaraMatches += result.matches.length;
            summary.totalThreats += result.matches.length;
        }
        
        if (result.type === 'signature_analysis' && result.matches) {
            summary.signatureMatches += result.matches.length;
            summary.totalSuspicious += result.matches.length;
        }
    });
    
    return summary;
}

// Calculer le score de risque
function calculateRiskScore(results) {
    let score = 0;
    
    results.forEach(result => {
        if (result.type === 'ai_analysis' && result.results) {
            Object.values(result.results).forEach(prediction => {
                if (prediction.prediction === 'malicious') {
                    score += prediction.confidence * 100;
                }
            });
        }
        
        if (result.type === 'yara_analysis' && result.matches) {
            result.matches.forEach(match => {
                if (match.severity === 'HIGH') {
                    score += 80;
                } else if (match.severity === 'MEDIUM') {
                    score += 50;
                } else {
                    score += 20;
                }
            });
        }
        
        if (result.type === 'signature_analysis' && result.matches) {
            result.matches.forEach(match => {
                score += match.confidence * 100;
            });
        }
    });
    
    return Math.min(100, score);
}

// Déterminer le statut
function determineStatus(results) {
    const riskScore = calculateRiskScore(results);
    
    if (riskScore > 80) return 'CRITICAL';
    if (riskScore > 60) return 'HIGH';
    if (riskScore > 30) return 'MEDIUM';
    if (riskScore > 10) return 'LOW';
    return 'SAFE';
}

// Générer un résumé de batch
function generateBatchSummary(results) {
    const summary = {
        total: results.length,
        successful: results.filter(r => r.status !== 'failed').length,
        failed: results.filter(r => r.status === 'failed').length,
        threats: results.filter(r => r.status === 'CRITICAL' || r.status === 'HIGH').length,
        suspicious: results.filter(r => r.status === 'MEDIUM' || r.status === 'LOW').length,
        safe: results.filter(r => r.status === 'SAFE').length
    };
    
    return summary;
}

// Diviser un tableau en chunks
function chunkArray(array, chunkSize) {
    const chunks = [];
    for (let i = 0; i < array.length; i += chunkSize) {
        chunks.push(array.slice(i, i + chunkSize));
    }
    return chunks;
}

// Générer des IDs uniques
function generateAnalysisId() {
    return `analysis_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

function generateBatchId() {
    return `batch_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

// Envoyer le statut du worker
function sendStatus() {
    self.postMessage({
        type: 'WORKER_STATUS',
        data: {
            ...workerState,
            uptime: Date.now() - (workerState.startTime || Date.now())
        }
    });
}

// Nettoyer le worker
function cleanup() {
    console.log('🧹 Nettoyage du Web Worker...');
    
    // Nettoyer les ressources
    aiModels = null;
    yaraRules = null;
    signatures = null;
    
    // Réinitialiser l'état
    workerState = {
        isBusy: false,
        currentAnalyses: 0,
        completedAnalyses: 0,
        failedAnalyses: 0,
        startTime: null
    };
    
    self.postMessage({
        type: 'WORKER_CLEANED'
    });
}

// Charger les modèles IA (simulation)
async function loadAIModels() {
    return {
        malware: {
            predict: (features) => ({
                prediction: Math.random() > 0.7 ? 'malicious' : 'benign',
                confidence: Math.random() * 0.3 + 0.7
            })
        },
        ransomware: {
            predict: (features) => ({
                prediction: Math.random() > 0.8 ? 'ransomware' : 'benign',
                confidence: Math.random() * 0.2 + 0.8
            })
        }
    };
}

// Charger les règles YARA (simulation)
async function loadYARARules() {
    return {
        wannacry: {
            patterns: ['WNcry@2ol7', 'WannaCry', 'WanaCrypt0r'],
            severity: 'HIGH',
            description: 'Ransomware WannaCry'
        },
        zeus: {
            patterns: ['Zeus', 'Zbot', 'Gameover'],
            severity: 'HIGH',
            description: 'Trojan Zeus'
        }
    };
}

// Charger les signatures (simulation)
async function loadSignatures() {
    return [
        {
            name: 'Suspicious String 1',
            pattern: 'string1',
            category: 'custom',
            confidence: 0.8,
            enabled: true
        },
        {
            name: 'Suspicious String 2',
            pattern: 'string2',
            category: 'custom',
            confidence: 0.8,
            enabled: true
        }
    ];
} 