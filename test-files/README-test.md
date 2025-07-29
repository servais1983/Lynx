# Tests de Lynx

## Fichiers de test inclus :

### test-sample.txt
Contient des patterns qui déclenchent les règles YARA :
- string1, string2 (patterns personnalisés)
- malicious, suspicious (contenu suspect)
- WannaCry, Zeus, Emotet (malware)
- GetAsyncKeyState (keylogger)
- meterpreter (backdoor)
- Invoke-Expression (PowerShell malveillant)
- eval( (JavaScript malveillant)
- AutoOpen (macro malveillante)
- \x90\x90\x90 (shellcode)

## Comment tester :

1. **Ouvrir la console du navigateur** (F12)
2. **Exécuter les tests** : `runAllTests()`
3. **Tester l'upload** : Glisser test-sample.txt dans la zone d'upload
4. **Tester l'automatisation** : Cliquer sur "Démarrer l'Automatisation"
5. **Tester les patterns** : Ajouter des patterns personnalisés

## Fonctionnalités à vérifier :

✅ **Règles YARA réelles** - Détection de patterns malveillants  
✅ **Traitement ZIP** - Extraction et analyse d'archives  
✅ **Copie automatique** - Transfert des fichiers suspects  
✅ **Patterns spécifiques** - string1, string2, etc.  
✅ **Automatisation triage** - Analyse d'un répertoire source  
✅ **Interface moderne** - Glassmorphisme et animations  
✅ **Visualisations** - Graphiques temps réel  
✅ **API VirusTotal** - Analyse en ligne  
✅ **Base de signatures** - 100+ signatures  
✅ **Modèles ML** - Classification IA  

## Commandes de test disponibles :

- `testLynxFunctionality()` - Test des modules
- `testSpecificFeatures()` - Test des fonctionnalités
- `testUserInterface()` - Test de l'interface
- `runAllTests()` - Tests complets 