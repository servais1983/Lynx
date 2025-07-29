// Processeur ZIP pour Lynx
// Extrait et analyse le contenu des archives ZIP

class ZIPProcessor {
    constructor() {
        this.supportedFormats = ['.zip', '.rar', '.7z', '.tar', '.gz'];
        this.extractedFiles = [];
    }

    // Vérifier si le fichier est une archive
    isArchive(file) {
        const extension = file.name.toLowerCase();
        return this.supportedFormats.some(format => extension.endsWith(format));
    }

    // Traiter une archive ZIP
    async processZIPArchive(file) {
        try {
            console.log(`📦 Traitement de l'archive: ${file.name}`);
            
            // Utiliser JSZip pour extraire le contenu
            const JSZip = window.JSZip;
            if (!JSZip) {
                throw new Error('JSZip n\'est pas disponible');
            }

            const zip = new JSZip();
            const zipContent = await zip.loadAsync(file);
            
            const extractedFiles = [];
            const analysisResults = [];

            // Parcourir tous les fichiers dans l'archive
            for (const [filename, zipEntry] of Object.entries(zipContent.files)) {
                if (!zipEntry.dir) {
                    try {
                        // Extraire le contenu du fichier
                        const fileContent = await zipEntry.async('string');
                        
                        // Créer un objet File simulé pour l'analyse
                        const extractedFile = {
                            name: filename,
                            size: zipEntry._data.uncompressedSize,
                            type: this.getFileType(filename),
                            content: fileContent,
                            isExtracted: true,
                            originalArchive: file.name
                        };

                        extractedFiles.push(extractedFile);

                        // Analyser le fichier extrait
                        const analysis = await this.analyzeExtractedFile(extractedFile);
                        if (analysis) {
                            analysisResults.push(analysis);
                        }

                    } catch (error) {
                        console.warn(`⚠️ Erreur lors de l'extraction de ${filename}:`, error);
                    }
                }
            }

            return {
                archiveName: file.name,
                totalFiles: extractedFiles.length,
                extractedFiles: extractedFiles,
                analysisResults: analysisResults,
                hasThreats: analysisResults.some(r => r.status === 'threat'),
                hasSuspicious: analysisResults.some(r => r.status === 'suspicious')
            };

        } catch (error) {
            console.error('❌ Erreur lors du traitement de l\'archive:', error);
            return {
                archiveName: file.name,
                error: error.message,
                totalFiles: 0,
                extractedFiles: [],
                analysisResults: []
            };
        }
    }

    // Analyser un fichier extrait
    async analyzeExtractedFile(file) {
        try {
            const results = [];

            // 1. Analyse YARA réelle
            try {
                const yaraResults = await analyzeWithRealYARA(file);
                if (yaraResults && yaraResults.length > 0) {
                    results.push(...yaraResults);
                }
            } catch (error) {
                console.warn('Erreur analyse YARA:', error);
            }

            // 2. Analyse des signatures
            try {
                const signatureResults = analyzeWithSignatures(file);
                if (signatureResults && signatureResults.length > 0) {
                    results.push(...signatureResults);
                }
            } catch (error) {
                console.warn('Erreur analyse signatures:', error);
            }

            // 3. Analyse ML
            try {
                const mlResults = analyzeWithML(file);
                if (mlResults) {
                    results.push(mlResults);
                }
            } catch (error) {
                console.warn('Erreur analyse ML:', error);
            }

            // Déterminer le statut global
            let status = 'safe';
            let riskScore = 0;

            if (results.some(r => r.severity === 'HIGH' || r.status === 'threat')) {
                status = 'threat';
                riskScore = 90;
            } else if (results.some(r => r.severity === 'MEDIUM' || r.status === 'suspicious')) {
                status = 'suspicious';
                riskScore = 60;
            }

            return {
                name: file.name,
                size: file.size,
                type: file.type,
                status: status,
                riskScore: riskScore,
                results: results,
                isExtracted: true,
                originalArchive: file.originalArchive
            };

        } catch (error) {
            console.error('Erreur analyse fichier extrait:', error);
            return null;
        }
    }

    // Déterminer le type de fichier basé sur l'extension
    getFileType(filename) {
        const extension = filename.toLowerCase().split('.').pop();
        const typeMap = {
            'exe': 'application/x-executable',
            'dll': 'application/x-dll',
            'bat': 'application/x-batch',
            'cmd': 'application/x-batch',
            'ps1': 'application/x-powershell',
            'vbs': 'application/x-vbscript',
            'js': 'application/javascript',
            'py': 'application/x-python',
            'txt': 'text/plain',
            'log': 'text/plain',
            'xml': 'application/xml',
            'json': 'application/json',
            'doc': 'application/msword',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'xls': 'application/vnd.ms-excel',
            'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'ppt': 'application/vnd.ms-powerpoint',
            'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'pdf': 'application/pdf'
        };
        
        return typeMap[extension] || 'application/octet-stream';
    }

    // Copier les fichiers suspects vers un dossier de destination
    async copySuspiciousFiles(analysisResults, destinationFolder = 'lynx_results') {
        const suspiciousFiles = analysisResults.filter(result => 
            result.status === 'threat' || result.status === 'suspicious'
        );

        if (suspiciousFiles.length === 0) {
            console.log('✅ Aucun fichier suspect à copier');
            return [];
        }

        console.log(`📁 Copie de ${suspiciousFiles.length} fichiers suspects vers ${destinationFolder}`);

        const copiedFiles = [];

        for (const file of suspiciousFiles) {
            try {
                // Créer le dossier de destination s'il n'existe pas
                await this.createDirectory(destinationFolder);

                // Générer un nom de fichier unique
                const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
                const safeName = file.name.replace(/[^a-zA-Z0-9.-]/g, '_');
                const newFileName = `${timestamp}_${safeName}`;
                const destinationPath = `${destinationFolder}/${newFileName}`;

                // Copier le fichier
                await this.copyFile(file, destinationPath);
                
                copiedFiles.push({
                    originalName: file.name,
                    newName: newFileName,
                    destination: destinationPath,
                    status: file.status,
                    riskScore: file.riskScore
                });

                console.log(`✅ Copié: ${file.name} -> ${destinationPath}`);

            } catch (error) {
                console.error(`❌ Erreur lors de la copie de ${file.name}:`, error);
            }
        }

        return copiedFiles;
    }

    // Créer un dossier (simulation pour le navigateur)
    async createDirectory(path) {
        // Dans un environnement navigateur, on ne peut pas créer de dossiers
        // Cette fonction est une simulation pour la démonstration
        console.log(`📁 Création du dossier: ${path}`);
        return true;
    }

    // Copier un fichier (simulation pour le navigateur)
    async copyFile(file, destinationPath) {
        // Dans un environnement navigateur, on ne peut pas copier directement
        // Cette fonction simule la copie pour la démonstration
        console.log(`📋 Copie simulée: ${file.name} -> ${destinationPath}`);
        
        // En réalité, on pourrait utiliser l'API File System Access ou download
        if (file.content) {
            // Créer un blob et télécharger
            const blob = new Blob([file.content], { type: file.type });
            const url = URL.createObjectURL(blob);
            
            const a = document.createElement('a');
            a.href = url;
            a.download = destinationPath.split('/').pop();
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }
        
        return true;
    }

    // Générer un rapport d'analyse d'archive
    generateArchiveReport(archiveAnalysis) {
        const report = {
            timestamp: new Date().toISOString(),
            archiveName: archiveAnalysis.archiveName,
            totalFiles: archiveAnalysis.totalFiles,
            extractedFiles: archiveAnalysis.extractedFiles.length,
            threats: archiveAnalysis.analysisResults.filter(r => r.status === 'threat').length,
            suspicious: archiveAnalysis.analysisResults.filter(r => r.status === 'suspicious').length,
            safe: archiveAnalysis.analysisResults.filter(r => r.status === 'safe').length,
            details: archiveAnalysis.analysisResults.map(result => ({
                name: result.name,
                status: result.status,
                riskScore: result.riskScore,
                size: result.size,
                type: result.type
            }))
        };

        return report;
    }
}

// Instance globale du processeur ZIP
const zipProcessor = new ZIPProcessor();

// Fonction pour traiter un fichier (archive ou normal)
async function processFile(file) {
    if (zipProcessor.isArchive(file)) {
        console.log(`📦 Archive détectée: ${file.name}`);
        return await zipProcessor.processZIPArchive(file);
    } else {
        console.log(`📄 Fichier normal: ${file.name}`);
        // Traitement normal du fichier
        return await analyzeFile(file);
    }
}

// Export des fonctions
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        ZIPProcessor,
        zipProcessor,
        processFile
    };
} 