// Modèles de Machine Learning simulés pour Lynx
// Ces modèles simulent l'analyse IA des fichiers

class MLModel {
    constructor(name, confidence) {
        this.name = name;
        this.confidence = confidence;
        this.features = [];
    }

    addFeature(feature) {
        this.features.push(feature);
    }

    predict(file) {
        // Simulation d'une prédiction ML
        const baseScore = Math.random() * 100;
        const featureBonus = this.features.length * 10;
        const finalScore = Math.min(100, baseScore + featureBonus);
        
        return {
            prediction: finalScore > 70 ? 'malicious' : 'benign',
            confidence: this.confidence,
            score: finalScore,
            features: this.features
        };
    }
}

// Modèles ML spécialisés
const ML_MODELS = {
    // Modèle pour les exécutables
    executable_classifier: new MLModel("Executable Classifier", 0.85),
    
    // Modèle pour les documents
    document_classifier: new MLModel("Document Classifier", 0.78),
    
    // Modèle pour les scripts
    script_classifier: new MLModel("Script Classifier", 0.92),
    
    // Modèle comportemental
    behavioral_classifier: new MLModel("Behavioral Classifier", 0.88),
    
    // Modèle de détection de ransomwares
    ransomware_detector: new MLModel("Ransomware Detector", 0.95)
};

// Configuration des features pour chaque modèle
ML_MODELS.executable_classifier.addFeature("entropy_analysis");
ML_MODELS.executable_classifier.addFeature("import_analysis");
ML_MODELS.executable_classifier.addFeature("section_analysis");

ML_MODELS.document_classifier.addFeature("macro_analysis");
ML_MODELS.document_classifier.addFeature("embedded_objects");
ML_MODELS.document_classifier.addFeature("metadata_analysis");

ML_MODELS.script_classifier.addFeature("function_analysis");
ML_MODELS.script_classifier.addFeature("obfuscation_detection");
ML_MODELS.script_classifier.addFeature("network_activity");

ML_MODELS.behavioral_classifier.addFeature("file_operations");
ML_MODELS.behavioral_classifier.addFeature("registry_changes");
ML_MODELS.behavioral_classifier.addFeature("network_connections");

ML_MODELS.ransomware_detector.addFeature("encryption_patterns");
ML_MODELS.ransomware_detector.addFeature("file_extension_changes");
ML_MODELS.ransomware_detector.addFeature("ransom_note_detection");

// Fonction pour analyser un fichier avec tous les modèles ML
function analyzeWithML(file) {
    const results = {};
    
    // Sélectionner le modèle approprié basé sur le type de fichier
    let selectedModel = ML_MODELS.behavioral_classifier; // Modèle par défaut
    
    const ext = file.name.split('.').pop().toLowerCase();
    
    if (['exe', 'dll', 'sys', 'scr'].includes(ext)) {
        selectedModel = ML_MODELS.executable_classifier;
    } else if (['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'].includes(ext)) {
        selectedModel = ML_MODELS.document_classifier;
    } else if (['js', 'vbs', 'ps1', 'bat', 'cmd'].includes(ext)) {
        selectedModel = ML_MODELS.script_classifier;
    }
    
    // Analyse avec le modèle sélectionné
    const prediction = selectedModel.predict(file);
    
    // Analyse supplémentaire avec le détecteur de ransomware
    const ransomwarePrediction = ML_MODELS.ransomware_detector.predict(file);
    
    results.primary = {
        model: selectedModel.name,
        prediction: prediction.prediction,
        confidence: prediction.confidence,
        score: prediction.score,
        features: prediction.features
    };
    
    results.ransomware = {
        model: ML_MODELS.ransomware_detector.name,
        prediction: ransomwarePrediction.prediction,
        confidence: ransomwarePrediction.confidence,
        score: ransomwarePrediction.score,
        features: ransomwarePrediction.features
    };
    
    return results;
}

// Fonction pour obtenir une recommandation basée sur l'analyse ML
function getMLRecommendation(mlResults) {
    const primary = mlResults.primary;
    const ransomware = mlResults.ransomware;
    
    let recommendations = [];
    
    if (primary.prediction === 'malicious') {
        recommendations.push(`Modèle ${primary.model}: Fichier suspect détecté (${primary.score}%)`);
    }
    
    if (ransomware.prediction === 'malicious') {
        recommendations.push(`⚠️ RANSOMWARE DÉTECTÉ! Score: ${ransomware.score}%`);
    }
    
    if (primary.confidence < 0.7) {
        recommendations.push("Confiance faible - analyse manuelle recommandée");
    }
    
    if (recommendations.length === 0) {
        recommendations.push("Aucune menace détectée par l'IA");
    }
    
    return recommendations;
}

// Fonction pour calculer un score de risque global
function calculateGlobalRiskScore(mlResults) {
    const primaryScore = mlResults.primary.score;
    const ransomwareScore = mlResults.ransomware.score;
    
    // Pondération : ransomware a plus de poids
    const globalScore = (primaryScore * 0.4) + (ransomwareScore * 0.6);
    
    return Math.round(globalScore);
}

// Fonction pour obtenir des insights détaillés
function getMLInsights(mlResults) {
    const insights = [];
    
    insights.push(`🎯 Modèle principal: ${mlResults.primary.model}`);
    insights.push(`📊 Score de confiance: ${Math.round(mlResults.primary.confidence * 100)}%`);
    insights.push(`🔍 Features analysées: ${mlResults.primary.features.length}`);
    
    if (mlResults.ransomware.prediction === 'malicious') {
        insights.push(`🚨 DÉTECTION RANSOMWARE: ${mlResults.ransomware.score}%`);
    }
    
    return insights;
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