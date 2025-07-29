# 🎯 Démonstration Lynx

Ce dossier contient des fichiers de démonstration pour tester les capacités de Lynx.

## 📁 Fichiers de Démonstration

### 🔍 **Fichiers avec Patterns Spécifiques**
- `string1_demo.txt` - Contient le pattern "string1"
- `string2_demo.js` - Contient le pattern "string2" 
- `string3_demo.py` - Contient le pattern "string3"

### 🚨 **Fichiers Malveillants Simulés**
- `wannacry_sample.txt` - Patterns WannaCry ransomware
- `zeus_trojan.txt` - Patterns Zeus trojan
- `keylogger_demo.txt` - Patterns de keylogger
- `backdoor_demo.txt` - Patterns de backdoor

### ⚠️ **Fichiers Suspects**
- `malicious_script.js` - Script JavaScript avec fonctions suspectes
- `suspicious_powershell.ps1` - Script PowerShell suspect
- `malicious_macro.txt` - Patterns de macros malveillantes

### ✅ **Fichiers Propres (Contrôle)**
- `clean_document.txt` - Document propre sans patterns
- `normal_image.jpg` - Fichier image (normalement ignoré)
- `safe_script.py` - Script Python propre

## 🧪 Comment Tester

1. **Ouvrir Lynx** dans votre navigateur
2. **Sélectionner le dossier "demo"** comme répertoire source
3. **Démarrer l'automatisation** et observer les résultats
4. **Vérifier le rapport** pour voir les détections

## 📊 Résultats Attendus

### 🎯 **Fichiers Détectés (Devraient être copiés)**
- `string1_demo.txt` - Pattern personnalisé
- `string2_demo.js` - Pattern personnalisé
- `string3_demo.py` - Pattern personnalisé
- `wannacry_sample.txt` - Ransomware (HIGH)
- `zeus_trojan.txt` - Trojan (HIGH)
- `keylogger_demo.txt` - Keylogger (HIGH)
- `backdoor_demo.txt` - Backdoor (HIGH)
- `malicious_script.js` - Script malveillant (MEDIUM)
- `suspicious_powershell.ps1` - PowerShell suspect (MEDIUM)
- `malicious_macro.txt` - Macro suspecte (MEDIUM)

### ✅ **Fichiers Ignorés (Devraient rester dans le répertoire source)**
- `clean_document.txt` - Aucun pattern détecté
- `normal_image.jpg` - Fichier image (non analysé)
- `safe_script.py` - Script propre

## 🔍 **Analyse Contextuelle**

Lynx utilise une analyse contextuelle pour réduire les faux positifs :
- **Type de fichier** : Les .exe, .dll, .bat, .ps1 ont plus de poids
- **Taille** : Les gros fichiers sont plus suspects
- **Densité** : Beaucoup de patterns = plus suspect
- **Contexte** : Mots-clés autour des patterns
- **Confiance** : Score de confiance pour chaque détection

## 📋 **Rapport de Démonstration**

Après l'analyse, vous devriez voir :
- **10 fichiers détectés** comme suspects
- **3 fichiers ignorés** comme sûrs
- **Scores de confiance** pour chaque détection
- **Contexte détaillé** pour chaque pattern

## 🎯 **Objectif de la Démo**

Cette démonstration montre :
- ✅ Détection précise des patterns malveillants
- ✅ Réduction des faux positifs par analyse contextuelle
- ✅ Copie automatique des fichiers suspects
- ✅ Rapports détaillés avec scores de confiance
- ✅ Interface moderne et intuitive

**Lynx est maintenant un outil professionnel de triage de fichiers !** 🚀 