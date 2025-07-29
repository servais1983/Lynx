# 🛠️ Guide d'Installation - Lynx

## 📋 Prérequis

### Système d'exploitation
- ✅ **Windows** 10/11
- ✅ **macOS** 10.14+
- ✅ **Linux** (Ubuntu 18.04+, CentOS 7+)

### Logiciels requis
- **Python** 3.7 ou supérieur
- **Node.js** 14+ (optionnel, pour npm)
- **Navigateur web moderne** :
  - Chrome 80+
  - Firefox 75+
  - Safari 13+
  - Edge 80+

### Connexion Internet
- Requise pour les ressources CDN (Three.js, TensorFlow.js)
- Optionnelle pour l'API VirusTotal (si configurée)

## 🚀 Installation Rapide

### Méthode 1 : Avec npm (Recommandée)

```bash
# 1. Cloner le repository
git clone https://github.com/servais1983/Lynx.git

# 2. Aller dans le dossier
cd Lynx

# 3. Installer les dépendances (optionnel)
npm install

# 4. Lancer Lynx
npm start

# 5. Ouvrir dans le navigateur
# http://localhost:3786
```

### Méthode 2 : Avec Python uniquement

```bash
# 1. Cloner le repository
git clone https://github.com/servais1983/Lynx.git

# 2. Aller dans le dossier
cd Lynx

# 3. Lancer le serveur Python
python -m http.server 3786

# 4. Ouvrir dans le navigateur
# http://localhost:3786
```

### Méthode 3 : Téléchargement direct

1. **Téléchargez** le ZIP depuis GitHub
2. **Extrayez** le contenu
3. **Ouvrez** un terminal dans le dossier
4. **Lancez** : `python -m http.server 3786`
5. **Ouvrez** : `http://localhost:3786`

## 🔧 Configuration Avancée

### Configuration VirusTotal (Optionnelle)

Pour utiliser l'API VirusTotal :

1. **Créez un compte** sur [VirusTotal](https://www.virustotal.com/)
2. **Obtenez votre clé API** dans les paramètres
3. **Modifiez** `js/config.js` :

```javascript
VIRUSTOTAL_API_KEY: 'votre_clé_api_ici'
```

### Configuration des ports

Si le port 3786 est occupé, vous pouvez changer :

```bash
# Avec Python
python -m http.server 8080

# Avec npm, modifiez package.json
{
  "scripts": {
    "start": "python -m http.server 8080"
  }
}
```

### Configuration du proxy

Si vous êtes derrière un proxy d'entreprise :

```bash
# Avec Python
python -m http.server 3786 --proxy http://proxy.company.com:8080

# Variables d'environnement
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
```

## 🧪 Test de l'Installation

### Test rapide

1. **Ouvrez** Lynx dans votre navigateur
2. **Glissez-déposez** un fichier texte
3. **Vérifiez** que l'analyse fonctionne
4. **Consultez** les résultats

### Test complet

1. **Créez** un fichier de test :
```bash
echo "Ceci est un fichier de test pour Lynx" > test.txt
```

2. **Analysez** le fichier dans Lynx
3. **Vérifiez** que :
   - L'interface se charge correctement
   - L'upload fonctionne
   - L'analyse s'exécute
   - Les résultats s'affichent

## 🔍 Dépannage

### Problème : "Port déjà utilisé"

```bash
# Vérifiez les ports utilisés
netstat -an | grep 3786

# Utilisez un autre port
python -m http.server 8080
```

### Problème : "Module not found"

```bash
# Vérifiez Python
python --version

# Installez Python si nécessaire
# Windows : https://www.python.org/downloads/
# macOS : brew install python
# Linux : sudo apt-get install python3
```

### Problème : "CORS error"

```bash
# Utilisez un serveur local
python -m http.server 3786

# Ou ajoutez les headers CORS
python -m http.server 3786 --cors
```

### Problème : "Navigateur non supporté"

- **Mettez à jour** votre navigateur
- **Activez JavaScript**
- **Désactivez** les bloqueurs de contenu
- **Autorisez** les cookies

## 🚀 Première Utilisation

### 1. Interface principale
- **Zone d'upload** : Glissez vos fichiers ici
- **Panneau de contrôle** : Boutons d'analyse
- **Résultats** : Liste des fichiers analysés
- **Visualisations** : Graphiques interactifs

### 2. Analyse de fichiers
1. **Glissez-déposez** vos fichiers
2. **Attendez** l'analyse automatique
3. **Consultez** les résultats
4. **Cliquez** sur un fichier pour les détails

### 3. Automatisation du triage
1. **Sélectionnez** un répertoire source
2. **Configurez** le répertoire destination
3. **Lancez** l'automatisation
4. **Suivez** la progression

## 📊 Vérification des Fonctionnalités

### ✅ Tests à effectuer

- [ ] **Interface** : Chargement de la page
- [ ] **Upload** : Glisser-déposer de fichiers
- [ ] **Analyse** : Traitement des fichiers
- [ ] **Résultats** : Affichage des détails
- [ ] **Visualisations** : Graphiques interactifs
- [ ] **Automatisation** : Triage de répertoires
- [ ] **Patterns** : Ajout de patterns personnalisés
- [ ] **Sécurité** : Fonctionnement en mode isolé

### 🔧 Tests avancés

```bash
# Test de performance
time python -m http.server 3786

# Test de mémoire
python -c "import psutil; print(psutil.virtual_memory())"

# Test de réseau
curl -I http://localhost:3786
```

## 🆘 Support

### Ressources d'aide

- **Documentation** : [README.md](README.md)
- **Issues** : [GitHub Issues](https://github.com/servais1983/Lynx/issues)
- **Wiki** : [GitHub Wiki](https://github.com/servais1983/Lynx/wiki)

### Contact

- **Email** : support@lynx-security.com
- **Discord** : [Serveur Lynx](https://discord.gg/lynx)
- **Twitter** : [@LynxSecurity](https://twitter.com/LynxSecurity)

## 🎉 Félicitations !

Lynx est maintenant installé et prêt à analyser vos fichiers ! 

**Prochaines étapes :**
1. **Testez** avec quelques fichiers
2. **Explorez** les fonctionnalités avancées
3. **Configurez** vos patterns personnalisés
4. **Partagez** vos retours d'expérience

**Bonne analyse ! 🦁✨** 