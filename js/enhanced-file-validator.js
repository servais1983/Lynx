// Validateur de fichiers amélioré pour Lynx
// Utilise les magic numbers et d'autres techniques de validation avancées

class EnhancedFileValidator {
    constructor() {
        this.magicNumbers = this.loadMagicNumbers();
        this.fileSignatures = this.loadFileSignatures();
        this.suspiciousPatterns = this.loadSuspiciousPatterns();
        this.maxFileSize = 100 * 1024 * 1024; // 100MB
    }

    // Chargement des magic numbers
    loadMagicNumbers() {
        return {
            // Exécutables
            '4D5A': { type: 'PE_EXECUTABLE', description: 'Portable Executable (Windows)' },
            '7F454C46': { type: 'ELF_EXECUTABLE', description: 'Executable and Linkable Format (Linux)' },
            'FEEDFACE': { type: 'MACHO_EXECUTABLE', description: 'Mach-O Executable (macOS)' },
            'FEEDFACF': { type: 'MACHO_EXECUTABLE', description: 'Mach-O Executable (macOS)' },
            
            // Documents
            '25504446': { type: 'PDF_DOCUMENT', description: 'PDF Document' },
            'D0CF11E0': { type: 'OFFICE_DOCUMENT', description: 'Microsoft Office Document' },
            '504B0304': { type: 'ZIP_ARCHIVE', description: 'ZIP Archive' },
            '504B0506': { type: 'ZIP_ARCHIVE', description: 'ZIP Archive (Empty)' },
            '504B0708': { type: 'ZIP_ARCHIVE', description: 'ZIP Archive (Spanned)' },
            
            // Images
            'FFD8FF': { type: 'JPEG_IMAGE', description: 'JPEG Image' },
            '89504E47': { type: 'PNG_IMAGE', description: 'PNG Image' },
            '47494638': { type: 'GIF_IMAGE', description: 'GIF Image' },
            '52494646': { type: 'RIFF_CONTAINER', description: 'RIFF Container (WAV, AVI, etc.)' },
            
            // Archives
            '1F8B08': { type: 'GZIP_ARCHIVE', description: 'GZIP Archive' },
            '425A68': { type: 'BZIP2_ARCHIVE', description: 'BZIP2 Archive' },
            '377ABC': { type: '7ZIP_ARCHIVE', description: '7-Zip Archive' },
            '52617221': { type: 'RAR_ARCHIVE', description: 'RAR Archive' },
            
            // Scripts
            '2321': { type: 'SHELL_SCRIPT', description: 'Shell Script (Shebang)' },
            '3C3F706870': { type: 'PHP_SCRIPT', description: 'PHP Script' },
            '3C21444F4354': { type: 'HTML_DOCUMENT', description: 'HTML Document' },
            
            // Autres
            'EFBBBF': { type: 'UTF8_BOM', description: 'UTF-8 BOM' },
            'FFFE': { type: 'UTF16_LE_BOM', description: 'UTF-16 Little Endian BOM' },
            'FEFF': { type: 'UTF16_BE_BOM', description: 'UTF-16 Big Endian BOM' }
        };
    }

    // Chargement des signatures de fichiers
    loadFileSignatures() {
        return {
            // Signatures de malware connus (exemples)
            'MALWARE_SIGNATURES': {
                // Signatures hexadécimales de malware connus
                '4D5A90000300000004000000FFFF': {
                    name: 'Suspicious PE Header',
                    risk: 'HIGH',
                    description: 'PE header avec caractéristiques suspectes'
                },
                'E8': {
                    name: 'Call Instruction',
                    risk: 'MEDIUM',
                    description: 'Instruction d\'appel de fonction'
                }
            },
            
            // Signatures de fichiers légitimes
            'LEGITIMATE_SIGNATURES': {
                '4D5A500001000000': {
                    name: 'Standard PE Header',
                    risk: 'LOW',
                    description: 'En-tête PE standard'
                }
            }
        };
    }

    // Chargement des patterns suspects
    loadSuspiciousPatterns() {
        return {
            // Patterns de shellcode
            'SHELLCODE_PATTERNS': [
                { pattern: /90{8,}/, name: 'NOP Sled', risk: 'HIGH' },
                { pattern: /68.{4}68.{4}68.{4}/, name: 'Push Instructions', risk: 'HIGH' },
                { pattern: /89E583EC.{2}83E4F0/, name: 'Function Prologue', risk: 'MEDIUM' }
            ],
            
            // Patterns de scripts malveillants
            'SCRIPT_PATTERNS': [
                { pattern: /powershell\.exe/i, name: 'PowerShell Execution', risk: 'MEDIUM' },
                { pattern: /cmd\.exe/i, name: 'Command Prompt', risk: 'MEDIUM' },
                { pattern: /wscript\.exe/i, name: 'Windows Script Host', risk: 'MEDIUM' },
                { pattern: /cscript\.exe/i, name: 'Command Line Script Host', risk: 'MEDIUM' }
            ],
            
            // Patterns de chiffrement
            'ENCRYPTION_PATTERNS': [
                { pattern: /encrypt/i, name: 'Encryption Keyword', risk: 'MEDIUM' },
                { pattern: /decrypt/i, name: 'Decryption Keyword', risk: 'MEDIUM' },
                { pattern: /ransom/i, name: 'Ransomware Keyword', risk: 'HIGH' },
                { pattern: /bitcoin/i, name: 'Bitcoin Reference', risk: 'MEDIUM' }
            ],
            
            // Patterns de réseau
            'NETWORK_PATTERNS': [
                { pattern: /https?:\/\/[^\s]+/g, name: 'URL Detection', risk: 'LOW' },
                { pattern: /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/, name: 'IP Address', risk: 'LOW' }
            ]
        };
    }

    // Validation principale d'un fichier
    async validateFile(file) {
        const validation = {
            file: file,
            isValid: true,
            warnings: [],
            errors: [],
            riskScore: 0,
            fileType: null,
            magicNumber: null,
            suspiciousPatterns: [],
            recommendations: []
        };

        try {
            // Validation de base
            await this.validateBasicProperties(file, validation);
            
            // Analyse du magic number
            await this.analyzeMagicNumber(file, validation);
            
            // Analyse du contenu
            await this.analyzeContent(file, validation);
            
            // Calcul du score de risque
            this.calculateRiskScore(validation);
            
            // Génération des recommandations
            this.generateRecommendations(validation);
            
        } catch (error) {
            validation.errors.push(`Erreur lors de la validation: ${error.message}`);
            validation.isValid = false;
        }

        return validation;
    }

    // Validation des propriétés de base
    async validateBasicProperties(file, validation) {
        // Vérification de la taille
        if (file.size > this.maxFileSize) {
            validation.errors.push(`Fichier trop volumineux: ${(file.size / 1024 / 1024).toFixed(2)}MB`);
            validation.isValid = false;
        }

        // Vérification du nom
        const fileName = file.name.toLowerCase();
        const extension = fileName.substring(fileName.lastIndexOf('.'));
        
        // Extensions suspectes
        const suspiciousExtensions = ['.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js', '.ps1'];
        if (suspiciousExtensions.includes(extension)) {
            validation.warnings.push(`Extension suspecte détectée: ${extension}`);
            validation.riskScore += 20;
        }

        // Vérification des caractères suspects dans le nom
        const suspiciousChars = /[^\w\-\.]/;
        if (suspiciousChars.test(fileName)) {
            validation.warnings.push('Caractères suspects dans le nom du fichier');
            validation.riskScore += 10;
        }
    }

    // Analyse du magic number
    async analyzeMagicNumber(file, validation) {
        try {
            const buffer = await this.readFileHeader(file, 16);
            const hexHeader = Array.from(new Uint8Array(buffer))
                .map(byte => byte.toString(16).padStart(2, '0'))
                .join('').toUpperCase();

            // Recherche du magic number
            for (const [magic, info] of Object.entries(this.magicNumbers)) {
                if (hexHeader.startsWith(magic)) {
                    validation.magicNumber = magic;
                    validation.fileType = info.type;
                    
                    // Évaluation du risque selon le type
                    this.evaluateFileTypeRisk(info.type, validation);
                    break;
                }
            }

            // Si aucun magic number reconnu
            if (!validation.magicNumber) {
                validation.warnings.push('Type de fichier non reconnu');
                validation.riskScore += 15;
            }

        } catch (error) {
            validation.errors.push(`Erreur lors de l'analyse du magic number: ${error.message}`);
        }
    }

    // Analyse du contenu du fichier
    async analyzeContent(file, validation) {
        try {
            const content = await this.readFileContent(file);
            const textContent = await this.extractTextContent(content);
            
            // Recherche de patterns suspects
            for (const [category, patterns] of Object.entries(this.suspiciousPatterns)) {
                for (const pattern of patterns) {
                    const matches = textContent.match(pattern.pattern);
                    if (matches) {
                        validation.suspiciousPatterns.push({
                            category: category,
                            pattern: pattern.name,
                            risk: pattern.risk,
                            matches: matches.length
                        });
                        
                        // Augmentation du score de risque selon la catégorie
                        switch (pattern.risk) {
                            case 'HIGH':
                                validation.riskScore += 30;
                                break;
                            case 'MEDIUM':
                                validation.riskScore += 15;
                                break;
                            case 'LOW':
                                validation.riskScore += 5;
                                break;
                        }
                    }
                }
            }

            // Analyse des signatures de fichiers
            await this.analyzeFileSignatures(content, validation);

        } catch (error) {
            validation.errors.push(`Erreur lors de l'analyse du contenu: ${error.message}`);
        }
    }

    // Analyse des signatures de fichiers
    async analyzeFileSignatures(content, validation) {
        const hexContent = Array.from(new Uint8Array(content))
            .map(byte => byte.toString(16).padStart(2, '0'))
            .join('').toUpperCase();

        // Vérification des signatures de malware
        for (const [signature, info] of Object.entries(this.fileSignatures.MALWARE_SIGNATURES)) {
            if (hexContent.includes(signature)) {
                validation.suspiciousPatterns.push({
                    category: 'MALWARE_SIGNATURE',
                    pattern: info.name,
                    risk: info.risk,
                    description: info.description
                });
                
                if (info.risk === 'HIGH') {
                    validation.riskScore += 40;
                } else if (info.risk === 'MEDIUM') {
                    validation.riskScore += 20;
                }
            }
        }
    }

    // Évaluation du risque selon le type de fichier
    evaluateFileTypeRisk(fileType, validation) {
        const riskLevels = {
            'PE_EXECUTABLE': 25,
            'ELF_EXECUTABLE': 25,
            'MACHO_EXECUTABLE': 25,
            'SHELL_SCRIPT': 20,
            'PHP_SCRIPT': 15,
            'ZIP_ARCHIVE': 10,
            'RAR_ARCHIVE': 10,
            'PDF_DOCUMENT': 5,
            'JPEG_IMAGE': 0,
            'PNG_IMAGE': 0,
            'GIF_IMAGE': 0
        };

        if (riskLevels[fileType] !== undefined) {
            validation.riskScore += riskLevels[fileType];
        }
    }

    // Calcul du score de risque final
    calculateRiskScore(validation) {
        // Limitation du score à 100
        validation.riskScore = Math.min(validation.riskScore, 100);
        
        // Détermination du niveau de risque
        if (validation.riskScore >= 80) {
            validation.riskLevel = 'CRITICAL';
        } else if (validation.riskScore >= 60) {
            validation.riskLevel = 'HIGH';
        } else if (validation.riskScore >= 40) {
            validation.riskLevel = 'MEDIUM';
        } else if (validation.riskScore >= 20) {
            validation.riskLevel = 'LOW';
        } else {
            validation.riskLevel = 'SAFE';
        }
    }

    // Génération des recommandations
    generateRecommendations(validation) {
        if (validation.riskLevel === 'CRITICAL') {
            validation.recommendations.push('⚠️ Fichier hautement suspect - Analyse approfondie recommandée');
            validation.recommendations.push('🔒 Quarantaine immédiate recommandée');
        } else if (validation.riskLevel === 'HIGH') {
            validation.recommendations.push('⚠️ Fichier suspect - Analyse approfondie recommandée');
        } else if (validation.riskLevel === 'MEDIUM') {
            validation.recommendations.push('🔍 Analyse supplémentaire recommandée');
        } else if (validation.riskLevel === 'LOW') {
            validation.recommendations.push('✅ Fichier probablement sûr');
        } else {
            validation.recommendations.push('✅ Fichier sûr');
        }

        // Recommandations spécifiques selon les patterns détectés
        for (const pattern of validation.suspiciousPatterns) {
            if (pattern.category === 'SHELLCODE_PATTERNS') {
                validation.recommendations.push('🚨 Shellcode détecté - Analyse dynamique recommandée');
            } else if (pattern.category === 'SCRIPT_PATTERNS') {
                validation.recommendations.push('📜 Script potentiellement malveillant détecté');
            } else if (pattern.category === 'ENCRYPTION_PATTERNS') {
                validation.recommendations.push('🔐 Activité de chiffrement détectée');
            }
        }
    }

    // Lecture de l'en-tête du fichier
    async readFileHeader(file, bytes) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => resolve(e.target.result);
            reader.onerror = reject;
            reader.readAsArrayBuffer(file.slice(0, bytes));
        });
    }

    // Lecture du contenu du fichier
    async readFileContent(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => resolve(e.target.result);
            reader.onerror = reject;
            reader.readAsArrayBuffer(file);
        });
    }

    // Extraction du contenu texte
    async extractTextContent(arrayBuffer) {
        try {
            const decoder = new TextDecoder('utf-8');
            return decoder.decode(arrayBuffer);
        } catch (error) {
            // Si UTF-8 échoue, essayer avec d'autres encodages
            try {
                const decoder = new TextDecoder('latin1');
                return decoder.decode(arrayBuffer);
            } catch (error2) {
                return '';
            }
        }
    }

    // Validation en lot
    async validateFiles(files) {
        const results = [];
        const maxConcurrent = 2; // Limitation pour éviter la surcharge

        for (let i = 0; i < files.length; i += maxConcurrent) {
            const batch = files.slice(i, i + maxConcurrent);
            const batchPromises = batch.map(file => this.validateFile(file));
            const batchResults = await Promise.all(batchPromises);
            results.push(...batchResults);
        }

        return results;
    }

    // Export pour compatibilité
    export() {
        return {
            validateFile: (file) => this.validateFile(file),
            validateFiles: (files) => this.validateFiles(files),
            getMagicNumbers: () => this.magicNumbers,
            getSuspiciousPatterns: () => this.suspiciousPatterns
        };
    }
}

// Instance globale
const enhancedFileValidator = new EnhancedFileValidator();

// Export pour utilisation dans d'autres modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = EnhancedFileValidator;
} else {
    window.enhancedFileValidator = enhancedFileValidator;
} 