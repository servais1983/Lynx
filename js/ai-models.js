// Modèles IA pré-entraînés pour Lynx
// Modèles spécialisés pour la détection de malware

class AIModels {
    constructor() {
        this.models = {};
        this.modelUrls = {
            malware: 'https://storage.googleapis.com/lynx-models/malware-detector.json',
            ransomware: 'https://storage.googleapis.com/lynx-models/ransomware-detector.json',
            behavioral: 'https://storage.googleapis.com/lynx-models/behavioral-analyzer.json'
        };
        this.isInitialized = false;
    }

    async initialize() {
        console.log('🤖 Chargement des modèles IA pré-entraînés...');
        
        try {
            // Charger les modèles en parallèle
            const modelPromises = Object.entries(this.modelUrls).map(async ([name, url]) => {
                try {
                    const model = await tf.loadLayersModel(url);
                    this.models[name] = model;
                    console.log(`✅ Modèle ${name} chargé`);
                    return { name, success: true };
                } catch (error) {
                    console.warn(`⚠️ Modèle ${name} non disponible, utilisation du mode dégradé`);
                    return { name, success: false, error };
                }
            });

            await Promise.all(modelPromises);
            this.isInitialized = true;
            console.log('🎯 Modèles IA initialisés');
            
        } catch (error) {
            console.error('❌ Erreur de chargement des modèles:', error);
            // Mode dégradé avec modèles simulés
            this.initializeFallbackModels();
        }
    }

    // Modèles de fallback — scoring déterministe basé sur les features
    initializeFallbackModels() {
        // Derive a deterministic score from the feature vector so the same
        // file always produces the same result without Math.random().
        const featureScore = (features) => {
            if (!Array.isArray(features) || features.length === 0) return 0;
            const sum = features.reduce((a, b) => a + Math.abs(b || 0), 0);
            return Math.min(100, (sum / features.length) * 100);
        };
        this.models = {
            malware: {
                predict: (features) => {
                    const score = featureScore(features);
                    return { prediction: score > 60 ? 'malicious' : 'benign', confidence: Math.min(0.97, 0.50 + score / 200), score };
                }
            },
            ransomware: {
                predict: (features) => {
                    const score = featureScore(features);
                    return { prediction: score > 70 ? 'ransomware' : 'benign', confidence: Math.min(0.97, 0.55 + score / 200), score };
                }
            },
            behavioral: {
                predict: (features) => {
                    const score = featureScore(features);
                    return { prediction: score > 50 ? 'suspicious' : 'normal', confidence: Math.min(0.95, 0.45 + score / 200), score };
                }
            }
        };
        this.isInitialized = true;
        console.log('Fallback mode active — deterministic heuristic scoring');
    }

    // Analyse avec tous les modèles
    async analyzeWithAllModels(features) {
        if (!this.isInitialized) {
            throw new Error('Modèles IA non initialisés');
        }

        const results = {};

        for (const [modelName, model] of Object.entries(this.models)) {
            try {
                if (model.predict) {
                    // Modèle TensorFlow.js
                    const tensor = tf.tensor2d([features]);
                    const prediction = await model.predict(tensor);
                    const data = await prediction.data();
                    
                    results[modelName] = {
                        prediction: data[0] > 0.5 ? 'malicious' : 'benign',
                        confidence: data[0],
                        score: data[0] * 100
                    };
                } else {
                    // Modèle simulé
                    results[modelName] = model.predict(features);
                }
            } catch (error) {
                console.error(`Erreur avec le modèle ${modelName}:`, error);
                results[modelName] = {
                    prediction: 'unknown',
                    confidence: 0,
                    score: 0,
                    error: error.message
                };
            }
        }

        return results;
    }

    // Obtenir une recommandation basée sur tous les modèles
    getRecommendation(results) {
        const recommendations = [];
        let maxScore = 0;
        let threatLevel = 'SAFE';

        for (const [modelName, result] of Object.entries(results)) {
            if (result.score > maxScore) {
                maxScore = result.score;
            }

            if (result.prediction === 'malicious' || result.prediction === 'ransomware') {
                if (result.score > 80) {
                    threatLevel = 'CRITICAL';
                    recommendations.push(`🚨 ${modelName.toUpperCase()}: Menace critique détectée (${result.score}%)`);
                } else if (result.score > 60) {
                    threatLevel = 'HIGH';
                    recommendations.push(`⚠️ ${modelName.toUpperCase()}: Menace élevée détectée (${result.score}%)`);
                }
            }
        }

        if (maxScore < 30) {
            recommendations.push('✅ Aucune menace détectée par l\'IA');
        }

        return {
            threatLevel,
            maxScore,
            recommendations
        };
    }
}

// Export pour utilisation
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { AIModels };
} 