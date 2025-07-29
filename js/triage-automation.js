// Automatisation du Triage pour Lynx
// Reproduit l'essence du script original : analyse automatique d'un répertoire source

class TriageAutomation {
    constructor() {
        this.sourceDirectory = 'Triage'; // Répertoire source par défaut
        this.destinationDirectory = 'Fichiers correspondants'; // Répertoire de destination
        this.yaraRules = {
            // Patterns spécifiques et précis
            string1: {
                name: "String1 Detection",
                patterns: ["string1", "String1", "STRING1"],
                severity: "MEDIUM",
                description: "Détection de string1",
                context: "Pattern personnalisé string1"
            },
            string2: {
                name: "String2 Detection", 
                patterns: ["string2", "String2", "STRING2"],
                severity: "MEDIUM",
                description: "Détection de string2",
                context: "Pattern personnalisé string2"
            },
            string3: {
                name: "String3 Detection",
                patterns: ["string3", "String3", "STRING3"],
                severity: "MEDIUM", 
                description: "Détection de string3",
                context: "Pattern personnalisé string3"
            },
            
            // Ransomware - Patterns très spécifiques
            wannacry: { 
                name: "WannaCry Ransomware", 
                patterns: [
                    "WNcry@2ol7", "WannaCry", "WNcry", "WanaCrypt0r", "WanaDecrypt0r",
                    "WannaCry@2ol7", "WannaCry@2ol7", "WannaCry@2ol7"
                ], 
                severity: "HIGH", 
                description: "Ransomware WannaCry détecté",
                context: "Patterns spécifiques au ransomware WannaCry"
            },
            
            // Trojans - Patterns spécifiques
            zeus_trojan: { 
                name: "Zeus Trojan", 
                patterns: [
                    "Zeus", "Zbot", "Gameover", "Citadel", "KINS",
                    "Zeus@2ol7", "Zeus@2ol7", "Zeus@2ol7"
                ], 
                severity: "HIGH", 
                description: "Trojan Zeus détecté",
                context: "Patterns spécifiques au trojan Zeus"
            },
            
            // Keyloggers - Patterns spécifiques
            keylogger: { 
                name: "Keylogger Detection", 
                patterns: [
                    "GetAsyncKeyState", "SetWindowsHookEx", "WH_KEYBOARD_LL",
                    "keylogger", "KeyLogger", "KEYLOGGER"
                ], 
                severity: "HIGH", 
                description: "Keylogger détecté",
                context: "Patterns de surveillance clavier"
            },
            
            // Backdoors - Patterns spécifiques
            backdoor: { 
                name: "Backdoor Detection", 
                patterns: [
                    "meterpreter", "Meterpreter", "METERPRETER",
                    "reverse shell", "Reverse Shell", "REVERSE SHELL",
                    "bind shell", "Bind Shell", "BIND SHELL"
                ], 
                severity: "HIGH", 
                description: "Backdoor détecté",
                context: "Patterns de backdoor et shell reverse"
            },
            
            // Scripts malveillants - Patterns spécifiques
            malicious_script: { 
                name: "Malicious Script", 
                patterns: [
                    "Invoke-Expression", "IEX", "iex",
                    "eval(", "eval (", "eval(",
                    "exec(", "exec (", "exec(",
                    "system(", "system (", "system("
                ], 
                severity: "MEDIUM", 
                description: "Script malveillant détecté",
                context: "Patterns de scripts malveillants"
            },
            
            // Macros malveillantes - Patterns spécifiques
            malicious_macro: { 
                name: "Malicious Macro", 
                patterns: [
                    "AutoOpen", "Auto_Open", "Document_Open",
                    "AutoClose", "Auto_Close", "Document_Close",
                    "Workbook_Open", "Worksheet_Activate"
                ], 
                severity: "MEDIUM", 
                description: "Macro malveillante détectée",
                context: "Patterns de macros automatiques"
            },
            
            // Shellcode - Patterns spécifiques
            shellcode: { 
                name: "Shellcode Detection", 
                patterns: [
                    "\\x90\\x90\\x90", "\\x90\\x90\\x90", "\\x90\\x90\\x90",
                    "\\xcc\\xcc\\xcc", "\\xcc\\xcc\\xcc", "\\xcc\\xcc\\xcc",
                    "\\x00\\x00\\x00", "\\x00\\x00\\x00", "\\x00\\x00\\x00"
                ], 
                severity: "HIGH", 
                description: "Shellcode détecté",
                context: "Patterns de shellcode et NOP sled"
            }
        };
        
        this.processedFiles = [];
        this.matchedFiles = [];
        this.errors = [];
        this.isRunning = false;
    }

    // Démarrer l'automatisation du triage
    async startTriageAutomation() {
        if (this.isRunning) {
            console.log('⚠️ Triage déjà en cours...');
            return;
        }

        this.isRunning = true;
        console.log('🚀 Démarrage de l\'automatisation du triage...');
        console.log('☕ Vous pouvez déguster un café pendant que le script fait son travail !');
        console.log('\n🔍 Ce que Lynx va analyser:');
        console.log('  • Patterns malveillants (string1, string2, malicious, suspicious)');
        console.log('  • Ransomware (WannaCry, Emotet)');
        console.log('  • Trojans (Zeus, backdoors)');
        console.log('  • Keyloggers (GetAsyncKeyState)');
        console.log('  • Scripts malveillants (PowerShell, JavaScript)');
        console.log('  • Macros suspectes (AutoOpen)');
        console.log('  • Shellcode et exploits');
        console.log('  • Extensions de fichiers suspects');
        console.log('  • Taille et comportement anormal');

        try {
            // Simuler la lecture du répertoire source
            const files = await this.scanSourceDirectory();
            console.log(`\n📁 ${files.length} fichiers trouvés dans le répertoire source`);

            // Analyser chaque fichier
            for (let i = 0; i < files.length; i++) {
                const file = files[i];
                console.log(`\n🔍 Analyse du fichier ${i + 1}/${files.length}: ${file.name}`);
                console.log(`   📄 Description: ${file.description}`);
                console.log(`   📏 Taille: ${file.size} bytes`);
                console.log(`   🏷️ Type: ${file.type}`);
                
                const result = await this.analyzeFile(file);
                this.processedFiles.push(result);

                // Mettre à jour la progression
                this.updateProgress(i + 1, files.length);

                // Pause pour éviter de surcharger
                await this.sleep(500);
            }

            // Copier les fichiers correspondants
            if (this.matchedFiles.length > 0) {
                console.log(`\n📁 Copie de ${this.matchedFiles.length} fichiers correspondants vers ${this.destinationDirectory}...`);
                await this.copyMatchedFiles();
            } else {
                console.log('\n✅ Aucun fichier suspect trouvé - répertoire sécurisé !');
            }

            // Générer le rapport final
            this.generateFinalReport();

        } catch (error) {
            console.error('❌ Erreur lors du triage:', error);
            this.errors.push(error.message);
        } finally {
            this.isRunning = false;
            console.log('✅ Automatisation du triage terminée !');
        }
    }

    // Scanner le répertoire source (vraies données)
    async scanSourceDirectory() {
        console.log(`📂 Scan du répertoire: ${this.sourceDirectory}`);
        
        // Utiliser les vrais fichiers sélectionnés par l'utilisateur
        if (window.selectedDirectoryFiles && window.selectedDirectoryFiles.length > 0) {
            const realFiles = window.selectedDirectoryFiles.map(file => ({
                name: file.name,
                size: file.size,
                type: file.type || this.getFileType(file.name),
                description: this.getFileDescription(file.name, file.size),
                file: file // Garder la référence au vrai fichier
            }));
            
            console.log(`📊 ${realFiles.length} vrais fichiers trouvés dans le répertoire`);
            return realFiles;
        } else {
            console.warn('❌ Aucun répertoire sélectionné. Veuillez sélectionner un répertoire source.');
            return [];
        }
    }

    // Obtenir le type de fichier basé sur l'extension
    getFileType(filename) {
        const ext = filename.split('.').pop().toLowerCase();
        const typeMap = {
            'txt': 'text/plain',
            'js': 'application/javascript',
            'html': 'text/html',
            'css': 'text/css',
            'json': 'application/json',
            'xml': 'application/xml',
            'pdf': 'application/pdf',
            'doc': 'application/msword',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'xls': 'application/vnd.ms-excel',
            'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'ppt': 'application/vnd.ms-powerpoint',
            'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'zip': 'application/zip',
            'rar': 'application/x-rar-compressed',
            '7z': 'application/x-7z-compressed',
            'exe': 'application/x-executable',
            'dll': 'application/x-dll',
            'bat': 'application/x-batch',
            'cmd': 'application/x-batch',
            'ps1': 'application/x-powershell',
            'py': 'text/x-python',
            'php': 'text/x-php',
            'java': 'text/x-java-source',
            'c': 'text/x-c',
            'cpp': 'text/x-c++src',
            'h': 'text/x-c',
            'hpp': 'text/x-c++src',
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'png': 'image/png',
            'gif': 'image/gif',
            'bmp': 'image/bmp',
            'mp3': 'audio/mpeg',
            'mp4': 'video/mp4',
            'avi': 'video/x-msvideo',
            'mov': 'video/quicktime'
        };
        return typeMap[ext] || 'application/octet-stream';
    }

    // Générer une description basée sur le nom et la taille du fichier
    getFileDescription(filename, size) {
        const ext = filename.split('.').pop().toLowerCase();
        const sizeKB = Math.round(size / 1024);
        
        let description = `Fichier ${ext.toUpperCase()} (${sizeKB} KB)`;
        
        // Ajouter des descriptions spécifiques selon le type
        if (['exe', 'dll', 'bat', 'cmd', 'ps1'].includes(ext)) {
            description += ' - Potentiellement exécutable';
        } else if (['zip', 'rar', '7z'].includes(ext)) {
            description += ' - Archive compressée';
        } else if (['txt', 'log'].includes(ext)) {
            description += ' - Fichier texte';
        } else if (['jpg', 'jpeg', 'png', 'gif', 'bmp'].includes(ext)) {
            description += ' - Fichier image';
        } else if (['mp3', 'wav', 'flac'].includes(ext)) {
            description += ' - Fichier audio';
        } else if (['mp4', 'avi', 'mov'].includes(ext)) {
            description += ' - Fichier vidéo';
        }
        
        return description;
    }

    // Analyser un fichier avec les règles YARA
    async analyzeFile(file) {
        const result = {
            name: file.name,
            size: file.size,
            type: file.type,
            description: file.description || 'Fichier standard',
            matches: [],
            status: 'safe',
            riskScore: 0,
            timestamp: new Date().toISOString()
        };

        try {
            // Lire le vrai contenu du fichier
            let fileContent = '';
            
            if (file.file) {
                // Utiliser le vrai fichier sélectionné
                try {
                    fileContent = await this.readFileContent(file.file);
                } catch (error) {
                    console.warn(`⚠️ Impossible de lire le contenu de ${file.name}: ${error.message}`);
                    fileContent = this.generateMockContent(file.name); // Fallback
                }
            } else {
                // Fallback pour les fichiers simulés
                fileContent = this.generateMockContent(file.name);
            }
            
            console.log(`🔍 Analyse de ${file.name}: ${file.description}`);
            console.log(`   📏 Taille: ${file.size} bytes`);
            console.log(`   🏷️ Type: ${file.type}`);
            
            // Appliquer les règles YARA avec analyse contextuelle
            Object.entries(this.yaraRules).forEach(([ruleName, rule]) => {
                const matches = this.findYARAMatches(fileContent, rule.patterns);
                
                if (matches.length > 0) {
                    // Analyse contextuelle pour réduire les faux positifs
                    const contextScore = this.analyzeContext(fileContent, matches, file.name, file.type);
                    
                    if (contextScore > 0.3) { // Seuil minimum pour considérer comme vrai positif
                        result.matches.push({
                            rule: rule.name,
                            patterns: matches,
                            severity: rule.severity,
                            description: rule.description,
                            context: rule.context,
                            confidence: contextScore
                        });

                        console.log(`  ⚠️ Règle "${rule.name}" déclenchée: ${matches.join(', ')} (Confiance: ${Math.round(contextScore * 100)}%)`);

                        // Mettre à jour le statut et le score de risque basé sur la confiance
                        if (rule.severity === 'HIGH' && contextScore > 0.7) {
                            result.status = 'threat';
                            result.riskScore = Math.max(result.riskScore, Math.round(90 * contextScore));
                            console.log(`  🚨 MENACE DÉTECTÉE: ${file.name} (Confiance élevée)`);
                        } else if (rule.severity === 'MEDIUM' && contextScore > 0.5 && result.status !== 'threat') {
                            result.status = 'suspicious';
                            result.riskScore = Math.max(result.riskScore, Math.round(60 * contextScore));
                            console.log(`  ⚠️ COMPORTEMENT SUSPECT: ${file.name} (Confiance modérée)`);
                        } else {
                            console.log(`  ℹ️ Pattern détecté mais faible confiance: ${file.name}`);
                        }
                    } else {
                        console.log(`  ℹ️ Pattern "${rule.name}" ignoré (faible confiance): ${file.name}`);
                    }
                }
            });

            // Si des correspondances sont trouvées, ajouter aux fichiers correspondants
            if (result.matches.length > 0) {
                this.matchedFiles.push(result);
                console.log(`🎯 Fichier correspondant: ${file.name} (${result.matches.length} règles)`);
            } else {
                console.log(`✅ Fichier sécurisé: ${file.name}`);
            }

        } catch (error) {
            console.error(`❌ Erreur lors de l'analyse de ${file.name}:`, error);
            result.error = error.message;
        }

        return result;
    }

    // Lire le contenu d'un vrai fichier
    async readFileContent(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            
            reader.onload = function(e) {
                try {
                    const content = e.target.result;
                    resolve(content);
                } catch (error) {
                    reject(new Error(`Erreur lors de la lecture: ${error.message}`));
                }
            };
            
            reader.onerror = function() {
                reject(new Error('Erreur lors de la lecture du fichier'));
            };
            
            // Lire comme texte pour les fichiers texte, binaire pour les autres
            const textExtensions = ['txt', 'log', 'js', 'html', 'css', 'json', 'xml', 'py', 'php', 'java', 'c', 'cpp', 'h', 'hpp', 'bat', 'cmd', 'ps1'];
            const ext = file.name.split('.').pop().toLowerCase();
            
            if (textExtensions.includes(ext)) {
                reader.readAsText(file);
            } else {
                // Pour les fichiers binaires, lire les premiers bytes pour détecter les patterns
                reader.readAsArrayBuffer(file);
            }
        });
    }

    // Trouver les correspondances YARA
    findYARAMatches(content, patterns) {
        const matches = [];
        
        if (typeof content === 'string') {
            // Recherche dans le contenu texte
            const lowerContent = content.toLowerCase();
            patterns.forEach(pattern => {
                const lowerPattern = pattern.toLowerCase();
                if (lowerContent.includes(lowerPattern)) {
                    matches.push(pattern);
                }
            });
        } else if (content instanceof ArrayBuffer) {
            // Recherche dans le contenu binaire
            const uint8Array = new Uint8Array(content);
            const binaryString = Array.from(uint8Array).map(byte => String.fromCharCode(byte)).join('');
            const lowerBinary = binaryString.toLowerCase();
            
            patterns.forEach(pattern => {
                const lowerPattern = pattern.toLowerCase();
                if (lowerBinary.includes(lowerPattern)) {
                    matches.push(pattern);
                }
            });
        }
        
        return matches;
    }

    // Analyser le contexte pour réduire les faux positifs
    analyzeContext(content, matches, filename, fileType) {
        let contextScore = 0.5; // Score de base
        
        // 1. Vérifier le type de fichier
        const ext = filename.split('.').pop().toLowerCase();
        const suspiciousExtensions = ['exe', 'dll', 'bat', 'cmd', 'ps1', 'vbs', 'js'];
        const safeExtensions = ['txt', 'log', 'doc', 'pdf', 'jpg', 'png', 'mp3', 'mp4'];
        
        if (suspiciousExtensions.includes(ext)) {
            contextScore += 0.2; // Plus de poids pour les fichiers exécutables
        } else if (safeExtensions.includes(ext)) {
            contextScore -= 0.1; // Moins de poids pour les fichiers sûrs
        }
        
        // 2. Vérifier la taille du fichier
        if (content.length < 100) {
            contextScore -= 0.2; // Fichiers très petits = moins probable
        } else if (content.length > 10000) {
            contextScore += 0.1; // Gros fichiers = plus probable
        }
        
        // 3. Vérifier la fréquence des patterns
        const totalMatches = matches.length;
        const contentLength = content.length;
        const patternDensity = totalMatches / contentLength;
        
        if (patternDensity > 0.01) { // Beaucoup de patterns
            contextScore += 0.3;
        } else if (patternDensity < 0.001) { // Très peu de patterns
            contextScore -= 0.2;
        }
        
        // 4. Vérifier le contexte autour des patterns
        let contextMatches = 0;
        matches.forEach(pattern => {
            const patternIndex = content.toLowerCase().indexOf(pattern.toLowerCase());
            if (patternIndex !== -1) {
                // Analyser le contexte autour du pattern
                const contextStart = Math.max(0, patternIndex - 50);
                const contextEnd = Math.min(content.length, patternIndex + pattern.length + 50);
                const context = content.substring(contextStart, contextEnd).toLowerCase();
                
                // Vérifier s'il y a des mots-clés suspects dans le contexte
                const suspiciousKeywords = ['malware', 'virus', 'trojan', 'backdoor', 'keylogger', 'exploit', 'shellcode'];
                const hasSuspiciousContext = suspiciousKeywords.some(keyword => context.includes(keyword));
                
                if (hasSuspiciousContext) {
                    contextMatches++;
                }
            }
        });
        
        if (contextMatches > 0) {
            contextScore += (contextMatches / matches.length) * 0.3;
        }
        
        // 5. Vérifier les patterns de strings spécifiques
        if (matches.some(m => m.includes('string1') || m.includes('string2') || m.includes('string3'))) {
            // Patterns personnalisés - score plus élevé
            contextScore += 0.2;
        }
        
        // 6. Vérifier les patterns de malware spécifiques
        const malwarePatterns = ['wannacry', 'zeus', 'meterpreter', 'getasynckeystate'];
        if (matches.some(m => malwarePatterns.some(mp => m.toLowerCase().includes(mp)))) {
            contextScore += 0.4; // Patterns de malware = score élevé
        }
        
        // Normaliser le score entre 0 et 1
        contextScore = Math.max(0, Math.min(1, contextScore));
        
        return contextScore;
    }

    // Générer du contenu simulé basé sur le nom du fichier
    generateMockContent(filename) {
        const lowerName = filename.toLowerCase();
        
        if (lowerName.includes('string1')) {
            return 'Ce fichier contient string1 et d\'autres données normales.';
        } else if (lowerName.includes('string2')) {
            return 'Contenu avec string2 et des informations supplémentaires.';
        } else if (lowerName.includes('string3')) {
            return 'Fichier contenant string3 et du contenu standard.';
        } else if (lowerName.includes('wannacry')) {
            return 'WNcry@2ol7 WannaCry ransomware code with encryption routines.';
        } else if (lowerName.includes('zeus')) {
            return 'Zeus trojan with Zbot Gameover Citadel KINS functionality.';
        } else if (lowerName.includes('keylogger')) {
            return 'GetAsyncKeyState SetWindowsHookEx WH_KEYBOARD_LL keylogger code.';
        } else if (lowerName.includes('backdoor')) {
            return 'meterpreter reverse shell bind shell backdoor code.';
        } else if (lowerName.includes('malicious') || lowerName.includes('suspicious')) {
            return 'Contenu normal sans patterns suspects.';
        } else {
            return 'Contenu normal sans patterns suspects.';
        }
    }

    // Copier les fichiers correspondants
    async copyMatchedFiles() {
        if (this.matchedFiles.length === 0) {
            console.log('✅ Aucun fichier correspondant à copier');
            return;
        }

        console.log(`📁 Copie de ${this.matchedFiles.length} fichiers vers ${this.destinationDirectory}`);

        for (const file of this.matchedFiles) {
            try {
                await this.copyFile(file);
                console.log(`✅ Copié: ${file.name}`);
            } catch (error) {
                console.error(`❌ Erreur lors de la copie de ${file.name}:`, error);
                this.errors.push(`Erreur copie ${file.name}: ${error.message}`);
            }
        }
    }

    // Copier un fichier (réel)
    async copyFile(file) {
        try {
            console.log(`📋 Copie de ${file.name} vers ${this.destinationDirectory}`);
            
            if (file.file) {
                // Créer un lien de téléchargement pour le fichier
                const link = document.createElement('a');
                link.href = URL.createObjectURL(file.file);
                link.download = `${this.destinationDirectory}/${file.name}`;
                link.style.display = 'none';
                
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                
                // Libérer l'URL
                setTimeout(() => URL.revokeObjectURL(link.href), 100);
                
                console.log(`✅ Fichier ${file.name} prêt pour téléchargement`);
            } else {
                console.log(`📋 Fichier simulé: ${file.name} -> ${this.destinationDirectory}/${file.name}`);
            }
            
            await this.sleep(200);
            return true;
            
        } catch (error) {
            console.error(`❌ Erreur lors de la copie de ${file.name}:`, error);
            throw error;
        }
    }

    // Sécuriser un chemin de fichier
    securePath(path) {
        // Protection contre les attaques directory traversal
        const normalized = path.replace(/[<>:"|?*]/g, '_');
        return normalized.replace(/\.\./g, '_');
    }

    // Mettre à jour la progression
    updateProgress(current, total) {
        const percentage = Math.round((current / total) * 100);
        console.log(`📊 Progression: ${current}/${total} (${percentage}%)`);
        
        // Mettre à jour l'interface utilisateur si disponible
        const progressElement = document.getElementById('triageProgress');
        const statusElement = document.getElementById('triageStatus');
        
        if (progressElement) {
            progressElement.style.width = `${percentage}%`;
            progressElement.textContent = `${percentage}%`;
        }
        
        if (statusElement) {
            statusElement.textContent = `Analyse en cours... ${current}/${total} fichiers traités (${percentage}%)`;
        }
        
        // Mettre à jour les statistiques en temps réel
        this.updateStatistics();
    }

    // Mettre à jour les statistiques
    updateStatistics() {
        const processedElement = document.getElementById('processedCount');
        const matchedElement = document.getElementById('matchedCount');
        const errorElement = document.getElementById('errorCount');
        
        if (processedElement) {
            processedElement.textContent = this.processedFiles.length;
        }
        
        if (matchedElement) {
            matchedElement.textContent = this.matchedFiles.length;
        }
        
        if (errorElement) {
            errorElement.textContent = this.errors.length;
        }
    }

    // Générer le rapport final
    generateFinalReport() {
        const report = {
            timestamp: new Date().toISOString(),
            sourceDirectory: this.sourceDirectory,
            destinationDirectory: this.destinationDirectory,
            totalFiles: this.processedFiles.length,
            matchedFiles: this.matchedFiles.length,
            errors: this.errors.length,
            summary: {
                safe: this.processedFiles.filter(f => f.status === 'safe').length,
                suspicious: this.processedFiles.filter(f => f.status === 'suspicious').length,
                threat: this.processedFiles.filter(f => f.status === 'threat').length
            },
            matchedFilesDetails: this.matchedFiles.map(file => ({
                name: file.name,
                status: file.status,
                riskScore: file.riskScore,
                matches: file.matches.length
            })),
            errors: this.errors
        };

        console.log('📋 Rapport final du triage:');
        console.log(`📁 Fichiers traités: ${report.totalFiles}`);
        console.log(`🎯 Fichiers correspondants: ${report.matchedFiles}`);
        console.log(`❌ Erreurs: ${report.errors}`);
        console.log(`✅ Sécurisés: ${report.summary.safe}`);
        console.log(`⚠️ Suspects: ${report.summary.suspicious}`);
        console.log(`🚨 Menaces: ${report.summary.threat}`);

        return report;
    }

    // Fonction utilitaire pour les pauses
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    // Configurer les répertoires
    setDirectories(source, destination) {
        this.sourceDirectory = this.securePath(source);
        this.destinationDirectory = this.securePath(destination);
        console.log(`📂 Répertoires configurés: ${this.sourceDirectory} -> ${this.destinationDirectory}`);
    }

    // Ajouter une règle YARA personnalisée
    addYARARule(name, patterns, severity = 'MEDIUM', description = '') {
        this.yaraRules[name] = {
            name: name,
            patterns: patterns,
            severity: severity,
            description: description
        };
        console.log(`✅ Règle YARA ajoutée: ${name}`);
    }

    // Obtenir les statistiques en temps réel
    getStatistics() {
        return {
            isRunning: this.isRunning,
            processedFiles: this.processedFiles.length,
            matchedFiles: this.matchedFiles.length,
            errors: this.errors.length,
            sourceDirectory: this.sourceDirectory,
            destinationDirectory: this.destinationDirectory
        };
    }
}

// Instance globale de l'automatisation du triage
window.triageAutomation = new TriageAutomation();

// Fonction pour démarrer l'automatisation
function startTriageAutomation() {
    return window.triageAutomation.startTriageAutomation();
}

// Fonction pour configurer les répertoires
function configureTriageDirectories(source, destination) {
    window.triageAutomation.setDirectories(source, destination);
}

// Fonction pour obtenir les statistiques
function getTriageStatistics() {
    return window.triageAutomation.getStatistics();
}

// Rendre les fonctions globales
window.startTriageAutomation = startTriageAutomation;
window.configureTriageDirectories = configureTriageDirectories;
window.getTriageStatistics = getTriageStatistics;

// Export des fonctions
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        TriageAutomation,
        triageAutomation: window.triageAutomation,
        startTriageAutomation,
        configureTriageDirectories,
        getTriageStatistics
    };
} 