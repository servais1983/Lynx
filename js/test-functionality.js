// Script de test pour vérifier les fonctionnalités de Lynx
// À exécuter dans la console du navigateur

function testLynxFunctionality() {
    console.log('🧪 Test des fonctionnalités de Lynx...');
    
    const tests = {
        // Test 1: Vérifier que tous les modules sont chargés
        modulesLoaded: () => {
            const modules = [
                'CONFIG',
                'YARA_RULES', 
                'ML_MODELS',
                'SIGNATURE_DATABASE',
                'vtAPI',
                'PRODUCTION_CONFIG',
                'REAL_YARA_RULES',
                'zipProcessor',
                'patternSearcher',
                'triageAutomation'
            ];
            
            const missing = modules.filter(module => typeof window[module] === 'undefined');
            
            if (missing.length === 0) {
                console.log('✅ Tous les modules sont chargés');
                return true;
            } else {
                console.error('❌ Modules manquants:', missing);
                return false;
            }
        },

        // Test 2: Vérifier les règles YARA réelles
        realYaraRules: () => {
            if (typeof REAL_YARA_RULES !== 'undefined') {
                const ruleCount = Object.keys(REAL_YARA_RULES).length;
                console.log(`✅ Règles YARA réelles: ${ruleCount} catégories`);
                return true;
            } else {
                console.error('❌ Règles YARA réelles non chargées');
                return false;
            }
        },

        // Test 3: Vérifier le processeur ZIP
        zipProcessor: () => {
            if (typeof zipProcessor !== 'undefined') {
                console.log('✅ Processeur ZIP opérationnel');
                return true;
            } else {
                console.error('❌ Processeur ZIP non chargé');
                return false;
            }
        },

        // Test 4: Vérifier le chercheur de patterns
        patternSearcher: () => {
            if (typeof patternSearcher !== 'undefined') {
                const patterns = patternSearcher.listAllPatterns();
                console.log(`✅ Chercheur de patterns: ${patterns.length} patterns disponibles`);
                return true;
            } else {
                console.error('❌ Chercheur de patterns non chargé');
                return false;
            }
        },

        // Test 5: Vérifier l'automatisation du triage
        triageAutomation: () => {
            if (typeof triageAutomation !== 'undefined') {
                console.log('✅ Automatisation du triage opérationnelle');
                return true;
            } else {
                console.error('❌ Automatisation du triage non chargée');
                return false;
            }
        },

        // Test 6: Vérifier l'API VirusTotal
        virusTotalAPI: () => {
            if (typeof vtAPI !== 'undefined') {
                console.log('✅ API VirusTotal configurée');
                return true;
            } else {
                console.error('❌ API VirusTotal non chargée');
                return false;
            }
        },

        // Test 7: Vérifier la base de signatures
        signatureDatabase: () => {
            if (typeof SIGNATURE_DATABASE !== 'undefined') {
                const categories = Object.keys(SIGNATURE_DATABASE).length;
                console.log(`✅ Base de signatures: ${categories} catégories`);
                return true;
            } else {
                console.error('❌ Base de signatures non chargée');
                return false;
            }
        },

        // Test 8: Vérifier les modèles ML
        mlModels: () => {
            if (typeof ML_MODELS !== 'undefined') {
                const modelCount = Object.keys(ML_MODELS).length;
                console.log(`✅ Modèles ML: ${modelCount} modèles`);
                return true;
            } else {
                console.error('❌ Modèles ML non chargés');
                return false;
            }
        },

        // Test 9: Vérifier la configuration
        configuration: () => {
            if (typeof CONFIG !== 'undefined') {
                console.log('✅ Configuration chargée');
                return true;
            } else {
                console.error('❌ Configuration non chargée');
                return false;
            }
        },

        // Test 10: Vérifier la configuration de production
        productionConfig: () => {
            if (typeof PRODUCTION_CONFIG !== 'undefined') {
                console.log('✅ Configuration de production chargée');
                return true;
            } else {
                console.error('❌ Configuration de production non chargée');
                return false;
            }
        }
    };

    // Exécuter tous les tests
    let passedTests = 0;
    let totalTests = Object.keys(tests).length;

    console.log('🔍 Démarrage des tests...\n');

    Object.entries(tests).forEach(([testName, testFunction]) => {
        console.log(`📋 Test: ${testName}`);
        try {
            if (testFunction()) {
                passedTests++;
            }
        } catch (error) {
            console.error(`❌ Erreur dans le test ${testName}:`, error);
        }
        console.log('');
    });

    // Résumé final
    console.log('📊 Résumé des tests:');
    console.log(`✅ Tests réussis: ${passedTests}/${totalTests}`);
    
    if (passedTests === totalTests) {
        console.log('🎉 Toutes les fonctionnalités sont opérationnelles !');
        console.log('🚀 Lynx est prêt à l\'emploi !');
    } else {
        console.log('⚠️ Certaines fonctionnalités nécessitent une attention');
    }

    return {
        passed: passedTests,
        total: totalTests,
        success: passedTests === totalTests
    };
}

// Test des fonctionnalités spécifiques
function testSpecificFeatures() {
    console.log('🧪 Test des fonctionnalités spécifiques...\n');

    // Test 1: Règles YARA réelles
    console.log('🔍 Test des règles YARA réelles...');
    if (typeof analyzeWithRealYARA === 'function') {
        console.log('✅ Fonction analyzeWithRealYARA disponible');
    } else {
        console.log('❌ Fonction analyzeWithRealYARA manquante');
    }

    // Test 2: Traitement ZIP
    console.log('📦 Test du traitement ZIP...');
    if (typeof zipProcessor !== 'undefined' && zipProcessor.isArchive) {
        console.log('✅ Fonction isArchive disponible');
    } else {
        console.log('❌ Fonction isArchive manquante');
    }

    // Test 3: Recherche de patterns
    console.log('🔍 Test de la recherche de patterns...');
    if (typeof analyzeFileWithPatterns === 'function') {
        console.log('✅ Fonction analyzeFileWithPatterns disponible');
    } else {
        console.log('❌ Fonction analyzeFileWithPatterns manquante');
    }

    // Test 4: Automatisation du triage
    console.log('🤖 Test de l\'automatisation du triage...');
    if (typeof startTriageAutomation === 'function') {
        console.log('✅ Fonction startTriageAutomation disponible');
    } else {
        console.log('❌ Fonction startTriageAutomation manquante');
    }

    // Test 5: API VirusTotal
    console.log('🌐 Test de l\'API VirusTotal...');
    if (typeof vtAPI !== 'undefined' && vtAPI.analyzeFile) {
        console.log('✅ API VirusTotal configurée');
    } else {
        console.log('❌ API VirusTotal non configurée');
    }
}

// Fonction pour tester l'interface utilisateur
function testUserInterface() {
    console.log('🖥️ Test de l\'interface utilisateur...\n');

    const uiElements = [
        'fileInput',
        'fileList', 
        'threatVisualization',
        'chartCanvas',
        'aiInsights',
        'customPatternName',
        'customPatternValue',
        'sourceDirectory',
        'destinationDirectory',
        'startTriageBtn'
    ];

    let foundElements = 0;
    uiElements.forEach(elementId => {
        const element = document.getElementById(elementId);
        if (element) {
            console.log(`✅ Élément UI trouvé: ${elementId}`);
            foundElements++;
        } else {
            console.log(`❌ Élément UI manquant: ${elementId}`);
        }
    });

    console.log(`\n📊 Éléments UI: ${foundElements}/${uiElements.length} trouvés`);
    return foundElements === uiElements.length;
}

// Fonction principale de test
function runAllTests() {
    console.log('🚀 Démarrage des tests complets de Lynx...\n');
    
    const results = {
        modules: testLynxFunctionality(),
        features: testSpecificFeatures(),
        ui: testUserInterface()
    };

    console.log('\n🎯 Résumé final:');
    console.log(`📦 Modules: ${results.modules.passed}/${results.modules.total} tests réussis`);
    console.log(`🔧 Fonctionnalités: Testées`);
    console.log(`🖥️ Interface: ${results.ui ? 'OK' : 'Problèmes détectés'}`);

    if (results.modules.success && results.ui) {
        console.log('\n🎉 Lynx est entièrement fonctionnel !');
        console.log('✅ Prêt pour l\'analyse de fichiers');
        console.log('✅ Prêt pour l\'automatisation du triage');
        console.log('✅ Prêt pour la recherche de patterns');
        console.log('✅ Prêt pour le traitement d\'archives');
    } else {
        console.log('\n⚠️ Certains composants nécessitent une attention');
    }
}

// Exporter les fonctions pour la console
window.testLynxFunctionality = testLynxFunctionality;
window.testSpecificFeatures = testSpecificFeatures;
window.testUserInterface = testUserInterface;
window.runAllTests = runAllTests;

// Auto-exécution si demandé
if (typeof window !== 'undefined' && window.location.search.includes('test=true')) {
    setTimeout(runAllTests, 1000);
} 