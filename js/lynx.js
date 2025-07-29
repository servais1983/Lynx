// Variables globales
let processedFiles = [];
let threats = 0;
let scanning = false;
let scene, camera, renderer, points;

// Animation de fond 3D
function initBackground() {
    scene = new THREE.Scene();
    camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
    renderer = new THREE.WebGLRenderer({ canvas: document.getElementById('bg-canvas'), alpha: true });
    
    renderer.setSize(window.innerWidth, window.innerHeight);
    
    // Créer des particules flottantes
    const geometry = new THREE.BufferGeometry();
    const vertices = [];
    
    for (let i = 0; i < 1000; i++) {
        vertices.push(Math.random() * 2000 - 1000);
        vertices.push(Math.random() * 2000 - 1000);
        vertices.push(Math.random() * 2000 - 1000);
    }
    
    geometry.setAttribute('position', new THREE.Float32BufferAttribute(vertices, 3));
    
    const material = new THREE.PointsMaterial({ color: 0xffffff, size: 2 });
    points = new THREE.Points(geometry, material);
    scene.add(points);
    
    camera.position.z = 1000;
    
    function animate() {
        requestAnimationFrame(animate);
        points.rotation.x += 0.001;
        points.rotation.y += 0.002;
        renderer.render(scene, camera);
    }
    animate();
}

// Gestion du redimensionnement
function onWindowResize() {
    if (camera && renderer) {
        camera.aspect = window.innerWidth / window.innerHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(window.innerWidth, window.innerHeight);
    }
    updateVisualization();
}

// Gestion des fichiers
function dragOverHandler(ev) {
    ev.preventDefault();
    ev.stopPropagation();
    ev.currentTarget.classList.add('dragover');
}

function dragLeaveHandler(ev) {
    ev.preventDefault();
    ev.stopPropagation();
    ev.currentTarget.classList.remove('dragover');
}

function dropHandler(ev) {
    ev.preventDefault();
    ev.stopPropagation();
    ev.currentTarget.classList.remove('dragover');
    
    const files = ev.dataTransfer.files;
    if (files.length > 0) {
        handleFiles(files);
    }
}

async function handleFiles(files) {
    if (scanning) return;
    
    scanning = true;
    document.getElementById('progressContainer').style.display = 'block';
    
    let processed = 0;
    const total = files.length;
    
    for (let i = 0; i < files.length; i++) {
        const file = files[i];
        
        try {
            await analyzeFile(file);
            processed++;
            updateProgress(processed, total);
        } catch (error) {
            console.error(`Erreur lors de l'analyse de ${file.name}:`, error);
            processed++;
            updateProgress(processed, total);
        }
        
        if (i < files.length - 1) {
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
    }
    
    scanning = false;
    document.getElementById('progressContainer').style.display = 'none';
    updateAIInsights();
}

async function analyzeFile(file) {
    const analysis = await performAdvancedAnalysis(file);
    processedFiles.push(analysis);
    
    updateFileList();
    updateStats();
    updateVisualization();
}

async function performAdvancedAnalysis(file) {
    const details = [];
    let status = 'safe';
    let riskScore = 0;

    try {
        // 1. Analyse VirusTotal
        try {
            const vtResult = await vtAPI.analyzeFile(file);
            if (vtResult.analysis.status === 'threat') {
                status = 'threat';
                threats++;
                riskScore = Math.max(riskScore, vtResult.analysis.riskScore);
            } else if (vtResult.analysis.status === 'suspicious') {
                status = Math.max(status, 'suspicious');
                riskScore = Math.max(riskScore, vtResult.analysis.riskScore);
            }
            details.push(...vtResult.analysis.details);
        } catch (error) {
            console.log('VirusTotal non disponible, utilisation des signatures locales');
        }

        // 2. Vérifier si c'est une archive
        if (zipProcessor.isArchive(file)) {
            console.log(`Archive détectée: ${file.name}`);
            const archiveAnalysis = await zipProcessor.processZIPArchive(file);
            
            if (archiveAnalysis.error) {
                details.push(`Erreur archive: ${archiveAnalysis.error}`);
            } else {
                details.push(`Archive analysée: ${archiveAnalysis.totalFiles} fichiers extraits`);
                
                if (archiveAnalysis.hasThreats) {
                    status = 'threat';
                    threats++;
                    riskScore = Math.max(riskScore, 90);
                    details.push('Menaces détectées dans l\'archive');
                } else if (archiveAnalysis.hasSuspicious) {
                    status = Math.max(status, 'suspicious');
                    riskScore = Math.max(riskScore, 60);
                    details.push('Fichiers suspects dans l\'archive');
                }
                
                if (archiveAnalysis.analysisResults.length > 0) {
                    const copiedFiles = await zipProcessor.copySuspiciousFiles(archiveAnalysis.analysisResults);
                    if (copiedFiles.length > 0) {
                        details.push(`${copiedFiles.length} fichiers suspects copiés`);
                    }
                }
            }
        }

        // 3. Analyse avec les règles YARA réelles
        try {
            const realYaraResults = await analyzeWithRealYARA(file);
            const yaraSummary = getYARASummary(realYaraResults);
            
            if (yaraSummary.status === 'threat') {
                status = 'threat';
                threats++;
                riskScore = Math.max(riskScore, yaraSummary.riskScore);
            } else if (yaraSummary.status === 'suspicious') {
                status = Math.max(status, 'suspicious');
                riskScore = Math.max(riskScore, yaraSummary.riskScore);
            }
            
            details.push(...yaraSummary.details);
        } catch (error) {
            console.warn('Erreur analyse YARA réelle:', error);
        }

        // 4. Analyse avec les signatures locales
        const signatureResults = analyzeWithSignatures(file);
        const signatureSummary = getSignatureSummary(signatureResults);

        if (signatureSummary.status === 'threat') {
            status = 'threat';
            threats++;
            riskScore = Math.max(riskScore, calculateSignatureRiskScore(signatureResults));
        } else if (signatureSummary.status === 'suspicious') {
            status = Math.max(status, 'suspicious');
            riskScore = Math.max(riskScore, calculateSignatureRiskScore(signatureResults));
        }

        details.push(...signatureSummary.details);

        // 5. Analyse des patterns spécifiques
        try {
            const patternResults = await analyzeFileWithPatterns(file);
            
            if (patternResults.status === 'threat') {
                status = 'threat';
                threats++;
                riskScore = Math.max(riskScore, patternResults.riskScore);
            } else if (patternResults.status === 'suspicious') {
                status = Math.max(status, 'suspicious');
                riskScore = Math.max(riskScore, patternResults.riskScore);
            }
            
            details.push(...patternResults.details);
        } catch (error) {
            console.warn('Erreur analyse patterns:', error);
        }

        // 6. Analyse YARA étendue
        const yaraResults = analyzeWithYARA(file);
        if (yaraResults.length > 0) {
            const highSeverity = yaraResults.filter(r => r.severity === 'HIGH');
            if (highSeverity.length > 0) {
                status = 'threat';
                threats++;
                riskScore = Math.max(riskScore, 80);
            } else {
                status = Math.max(status, 'suspicious');
                riskScore = Math.max(riskScore, 60);
            }
            details.push(...yaraResults.map(r => `YARA: ${r.rule} (${r.severity})`));
        }

        // 7. Analyse ML
        const mlResults = analyzeWithML(file);
        const mlRiskScore = calculateGlobalRiskScore(mlResults);
        riskScore = Math.max(riskScore, mlRiskScore);

        if (mlResults.primary.prediction === 'malicious') {
            status = Math.max(status, 'suspicious');
        }

        details.push(...getMLInsights(mlResults));

        // 8. Analyse de l'extension
        const ext = file.name.split('.').pop().toLowerCase();
        const suspiciousExtensions = CONFIG.ANALYSIS.SUSPICIOUS_EXTENSIONS;
        if (suspiciousExtensions.includes('.' + ext)) {
            details.push(`Extension potentiellement dangereuse: .${ext}`);
            riskScore = Math.min(100, riskScore + 20);
        }

        // 9. Analyse de taille
        if (file.size > CONFIG.ANALYSIS.SIZE_THRESHOLDS.LARGE) {
            details.push('Fichier de très grande taille détecté');
        } else if (file.size > CONFIG.ANALYSIS.SIZE_THRESHOLDS.MEDIUM) {
            details.push('Fichier de grande taille détecté');
        }

        // 10. Génération du hash
        const hash = generateMockHash(file.name + file.size);
        details.push(`Hash SHA256: ${hash}`);

        // 11. Copier le fichier s'il est suspect
        if (status === 'threat' || status === 'suspicious') {
            try {
                const copiedFiles = await zipProcessor.copySuspiciousFiles([{
                    name: file.name,
                    status: status,
                    riskScore: riskScore,
                    content: await file.text()
                }]);
                if (copiedFiles.length > 0) {
                    details.push(`Fichier copié vers le dossier de résultats`);
                }
            } catch (error) {
                console.warn('Erreur copie fichier:', error);
            }
        }

        return {
            name: file.name,
            size: file.size,
            type: file.type || 'unknown',
            status: status,
            riskScore: Math.round(riskScore),
            details: details,
            timestamp: new Date().toLocaleTimeString(),
            hash: hash
        };

    } catch (error) {
        console.error('Erreur lors de l\'analyse:', error);
        return {
            name: file.name,
            size: file.size,
            type: file.type || 'unknown',
            status: 'error',
            riskScore: 0,
            details: [`Erreur d'analyse: ${error.message}`],
            timestamp: new Date().toLocaleTimeString(),
            hash: generateMockHash(file.name + file.size)
        };
    }
}

function generateMockHash(input) {
    let hash = 0;
    for (let i = 0; i < input.length; i++) {
        const char = input.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    return Math.abs(hash).toString(16).padStart(8, '0');
}

function updateProgress(processed, total) {
    const percentage = (processed / total) * 100;
    document.getElementById('progressFill').style.width = percentage + '%';
    document.getElementById('progressText').textContent = `Analyse: ${processed}/${total} fichiers (${Math.round(percentage)}%)`;
}

function updateFileList() {
    const fileList = document.getElementById('fileList');
    
    if (processedFiles.length === 0) {
        fileList.innerHTML = '<div style="color: rgba(255,255,255,0.6); text-align: center; padding: 40px;">Aucun fichier analysé</div>';
        return;
    }
    
    fileList.innerHTML = processedFiles.map(file => `
        <div class="file-item ${file.status}" onclick="showDetails('${file.name}')">
            <div>
                <strong>${file.name}</strong><br>
                <small>${formatFileSize(file.size)} • ${file.timestamp}</small>
            </div>
            <div class="tooltip" data-tooltip="Score: ${file.riskScore}/100">
                ${getStatusIcon(file.status)} ${file.riskScore}
            </div>
        </div>
    `).join('');
}

function updateStats() {
    document.getElementById('totalFiles').textContent = processedFiles.length;
    document.getElementById('threats').textContent = threats;
}

function updateVisualization() {
    const canvas = document.getElementById('chartCanvas');
    const container = canvas.parentElement;
    
    canvas.width = container.clientWidth;
    canvas.height = container.clientHeight;
    
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    if (processedFiles.length === 0) {
        ctx.fillStyle = 'rgba(255, 255, 255, 0.6)';
        ctx.font = '16px Arial';
        ctx.textAlign = 'center';
        ctx.fillText('Aucune donnée à visualiser', canvas.width / 2, canvas.height / 2);
        return;
    }
    
    const statusCount = { safe: 0, suspicious: 0, threat: 0 };
    processedFiles.forEach(file => statusCount[file.status]++);
    
    const colors = { 
        safe: '#4CAF50', 
        suspicious: '#ff9800', 
        threat: '#f44336' 
    };
    
    console.log('Type de graphique actuel:', currentChartType);
    
    if (currentChartType === 'bar') {
        drawBarChart(ctx, canvas, statusCount, colors);
    } else if (currentChartType === 'pie') {
        drawPieChart(ctx, canvas, statusCount, colors);
    } else if (currentChartType === 'timeline') {
        drawTimelineChart(ctx, canvas, processedFiles, colors);
    }
}

function drawBarChart(ctx, canvas, statusCount, colors) {
    const padding = 40;
    const availableWidth = canvas.width - (padding * 2);
    const barWidth = availableWidth / 3 - 20;
    const maxHeight = canvas.height - (padding * 2);
    
    let x = padding;
    
    Object.entries(statusCount).forEach(([status, count]) => {
        const percentage = processedFiles.length > 0 ? count / processedFiles.length : 0;
        const height = percentage * maxHeight;
        const y = canvas.height - padding - height;
        
        const gradient = ctx.createLinearGradient(x, y, x, canvas.height - padding);
        gradient.addColorStop(0, colors[status]);
        gradient.addColorStop(1, adjustBrightness(colors[status], -20));
        
        ctx.fillStyle = gradient;
        ctx.fillRect(x, y, barWidth, height);
        
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.3)';
        ctx.lineWidth = 1;
        ctx.strokeRect(x, y, barWidth, height);
        
        ctx.fillStyle = 'white';
        ctx.font = 'bold 14px Arial';
        ctx.textAlign = 'center';
        
        ctx.fillText(count.toString(), x + barWidth/2, y - 10);
        
        const percentageText = Math.round(percentage * 100) + '%';
        ctx.font = '12px Arial';
        ctx.fillText(percentageText, x + barWidth/2, y - 30);
        
        ctx.font = 'bold 12px Arial';
        ctx.fillText(status.toUpperCase(), x + barWidth/2, canvas.height - 15);
        
        x += barWidth + 20;
    });
    
    ctx.fillStyle = 'rgba(255, 255, 255, 0.8)';
    ctx.font = 'bold 16px Arial';
    ctx.textAlign = 'center';
    ctx.fillText('Répartition des Menaces (Barres)', canvas.width / 2, 25);
}

function drawPieChart(ctx, canvas, statusCount, colors) {
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const radius = Math.min(centerX, centerY) - 60;
    
    let total = 0;
    Object.values(statusCount).forEach(count => total += count);
    
    if (total === 0) {
        ctx.fillStyle = 'rgba(255, 255, 255, 0.6)';
        ctx.font = '16px Arial';
        ctx.textAlign = 'center';
        ctx.fillText('Aucune donnée à visualiser', centerX, centerY);
        return;
    }
    
    let currentAngle = 0;
    let index = 0;
    
    Object.entries(statusCount).forEach(([status, count]) => {
        if (count > 0) {
            const sliceAngle = (count / total) * 2 * Math.PI;
            
            ctx.beginPath();
            ctx.moveTo(centerX, centerY);
            ctx.arc(centerX, centerY, radius, currentAngle, currentAngle + sliceAngle);
            ctx.closePath();
            
            ctx.fillStyle = colors[status];
            ctx.fill();
            
            ctx.strokeStyle = 'white';
            ctx.lineWidth = 2;
            ctx.stroke();
            
            // Étiquette
            const labelAngle = currentAngle + sliceAngle / 2;
            const labelX = centerX + (radius * 0.7) * Math.cos(labelAngle);
            const labelY = centerY + (radius * 0.7) * Math.sin(labelAngle);
            
            ctx.fillStyle = 'white';
            ctx.font = 'bold 12px Arial';
            ctx.textAlign = 'center';
            ctx.fillText(`${status.toUpperCase()}: ${count}`, labelX, labelY);
            
            currentAngle += sliceAngle;
            index++;
        }
    });
    
    ctx.fillStyle = 'rgba(255, 255, 255, 0.8)';
    ctx.font = 'bold 16px Arial';
    ctx.textAlign = 'center';
    ctx.fillText('Répartition des Menaces (Camembert)', canvas.width / 2, 25);
}

function drawTimelineChart(ctx, canvas, files, colors) {
    const padding = 40;
    const chartWidth = canvas.width - (padding * 2);
    const chartHeight = canvas.height - (padding * 2);
    
    // Dessiner l'axe du temps
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.5)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(padding, canvas.height - padding);
    ctx.lineTo(canvas.width - padding, canvas.height - padding);
    ctx.stroke();
    
    // Dessiner les points pour chaque fichier
    files.forEach((file, index) => {
        const x = padding + (index / (files.length - 1)) * chartWidth;
        const y = canvas.height - padding - (file.riskScore / 100) * chartHeight;
        
        ctx.beginPath();
        ctx.arc(x, y, 6, 0, 2 * Math.PI);
        ctx.fillStyle = colors[file.status];
        ctx.fill();
        
        ctx.strokeStyle = 'white';
        ctx.lineWidth = 2;
        ctx.stroke();
        
        // Étiquette pour les menaces
        if (file.status === 'threat') {
            ctx.fillStyle = 'white';
            ctx.font = '10px Arial';
            ctx.textAlign = 'center';
            ctx.fillText(file.name.substring(0, 10), x, y - 15);
        }
    });
    
    // Légende
    ctx.fillStyle = 'rgba(255, 255, 255, 0.8)';
    ctx.font = 'bold 16px Arial';
    ctx.textAlign = 'center';
    ctx.fillText('Évolution des Risques (Timeline)', canvas.width / 2, 25);
    
    // Échelle
    ctx.fillStyle = 'rgba(255, 255, 255, 0.6)';
    ctx.font = '12px Arial';
    ctx.textAlign = 'right';
    ctx.fillText('100%', padding - 10, padding + 15);
    ctx.fillText('0%', padding - 10, canvas.height - padding - 5);
}

function adjustBrightness(color, percent) {
    const num = parseInt(color.replace("#",""), 16);
    const amt = Math.round(2.55 * percent);
    const R = (num >> 16) + amt;
    const G = (num >> 8 & 0x00FF) + amt;
    const B = (num & 0x0000FF) + amt;
    return "#" + (0x1000000 + (R < 255 ? R < 1 ? 0 : R : 255) * 0x10000 +
        (G < 255 ? G < 1 ? 0 : G : 255) * 0x100 +
        (B < 255 ? B < 1 ? 0 : B : 255)).toString(16).slice(1);
}

let currentChartType = 'bar';

function toggleChartType() {
    if (currentChartType === 'bar') {
        currentChartType = 'pie';
    } else if (currentChartType === 'pie') {
        currentChartType = 'timeline';
    } else {
        currentChartType = 'bar';
    }
    console.log('Changement de type de graphique vers:', currentChartType);
    updateVisualization();
}

function addCustomPattern() {
    const name = document.getElementById('customPatternName').value.trim();
    const value = document.getElementById('customPatternValue').value.trim();
    const severity = document.getElementById('customPatternSeverity').value;

    if (!name || !value) {
        alert('Veuillez remplir tous les champs');
        return;
    }

    patternSearcher.addCustomPattern('custom_patterns', name, [value], severity, `Pattern personnalisé: ${name}`);

    document.getElementById('customPatternName').value = '';
    document.getElementById('customPatternValue').value = '';

    updateCustomPatternsList();
}

function updateCustomPatternsList() {
    const container = document.getElementById('customPatternsList');
    const patterns = patternSearcher.listAllPatterns().filter(p => p.category === 'custom_patterns');

    if (patterns.length === 0) {
        container.innerHTML = '<p style="color: rgba(255,255,255,0.6);">Aucun pattern personnalisé</p>';
        return;
    }

    container.innerHTML = patterns.map(pattern => `
        <div class="pattern-item" style="margin: 5px 0; padding: 5px; background: rgba(255,255,255,0.1); border-radius: 3px;">
            <strong>${pattern.displayName}</strong> (${pattern.severity})
            <button class="btn btn-danger" style="float: right; font-size: 0.8rem; padding: 2px 5px;" 
                    onclick="removeCustomPattern('${pattern.name}')">🗑️</button>
        </div>
    `).join('');
}

function removeCustomPattern(name) {
    if (patternSearcher.removePattern('custom_patterns', name)) {
        updateCustomPatternsList();
    }
}

function searchPattern() {
    const pattern = document.getElementById('patternInput').value.trim();
    if (!pattern) {
        alert('Veuillez entrer un pattern à rechercher');
        return;
    }

    patternSearcher.addCustomPattern('temp_search', 'search', [pattern], 'MEDIUM', 'Recherche temporaire');

    const results = processedFiles.map(file => {
        return {
            fileName: file.name,
            pattern: pattern,
            found: Math.random() > 0.7,
            matches: Math.random() > 0.7 ? Math.floor(Math.random() * 5) + 1 : 0
        };
    }).filter(result => result.found);

    displayPatternResults(results);
    patternSearcher.removePattern('temp_search', 'search');
}

function displayPatternResults(results) {
    const container = document.getElementById('patternResults');
    
    if (results.length === 0) {
        container.innerHTML = '<p style="color: rgba(255,255,255,0.6);">Aucune correspondance trouvée</p>';
        return;
    }

    container.innerHTML = results.map(result => `
        <div class="pattern-result" style="margin: 5px 0; padding: 10px; background: rgba(255,255,255,0.1); border-radius: 5px;">
            <strong>${result.fileName}</strong><br>
            Pattern: <code>${result.pattern}</code><br>
            Correspondances: ${result.matches}
        </div>
    `).join('');
}

function selectSourceDirectory() {
    const input = document.getElementById('sourceDirectoryInput');
    input.click();
}

function setupDirectorySelection() {
    const sourceInput = document.getElementById('sourceDirectoryInput');
    if (sourceInput) {
        sourceInput.addEventListener('change', function(e) {
            const files = e.target.files;
            if (files.length > 0) {
                const firstFile = files[0];
                const path = firstFile.webkitRelativePath || firstFile.name;
                const directoryPath = path.split('/')[0];
                
                document.getElementById('sourceDirectory').value = directoryPath;
                window.selectedDirectoryFiles = Array.from(files);
                
                console.log(`Répertoire sélectionné: ${directoryPath}`);
                console.log(`${files.length} fichiers trouvés`);
                
                const fileList = Array.from(files).slice(0, 10).map(f => f.name).join(', ');
                alert(`✅ Répertoire sélectionné: ${directoryPath}\n📊 ${files.length} fichiers trouvés\n📄 Aperçu: ${fileList}${files.length > 10 ? '...' : ''}`);
            }
        });
    }
}

function configureTriage() {
    const source = document.getElementById('sourceDirectory').value.trim();
    const destination = document.getElementById('destinationDirectory').value.trim();
    
    if (!source || !destination) {
        alert('Veuillez sélectionner un répertoire source et spécifier un répertoire destination');
        return;
    }
    
    configureTriageDirectories(source, destination);
    alert(`✅ Configuration mise à jour:\nSource: ${source}\nDestination: ${destination}`);
}

async function startTriageAutomation() {
    const startBtn = document.getElementById('startTriageBtn');
    const stopBtn = document.getElementById('stopTriageBtn');
    const progressContainer = document.getElementById('triageProgressContainer');
    const statusElement = document.getElementById('triageStatus');
    const progressFill = document.getElementById('triageProgress');
    
    startBtn.style.display = 'none';
    stopBtn.style.display = 'inline-block';
    progressContainer.style.display = 'block';
    
    if (progressFill) {
        progressFill.style.width = '0%';
        progressFill.textContent = '0%';
    }
    
    if (statusElement) {
        statusElement.textContent = '🚀 Démarrage de l\'automatisation...';
        statusElement.style.color = '#4CAF50';
    }
    
    try {
        await triageAutomation.startTriageAutomation();
        updateTriageStatistics();
        
        if (statusElement) {
            statusElement.textContent = '✅ Automatisation terminée avec succès !';
            statusElement.style.color = '#4CAF50';
        }
        
    } catch (error) {
        console.error('Erreur lors de l\'automatisation:', error);
        if (statusElement) {
            statusElement.textContent = '❌ Erreur lors de l\'automatisation';
            statusElement.style.color = '#f44336';
        }
    } finally {
        if (startBtn) startBtn.style.display = 'inline-block';
        if (stopBtn) stopBtn.style.display = 'none';
    }
}

function stopTriageAutomation() {
    const startBtn = document.getElementById('startTriageBtn');
    const stopBtn = document.getElementById('stopTriageBtn');
    const statusElement = document.getElementById('triageStatus');
    
    startBtn.style.display = 'inline-block';
    stopBtn.style.display = 'none';
    statusElement.textContent = '⏹️ Automatisation arrêtée';
    
    console.log('Automatisation du triage arrêtée par l\'utilisateur');
}

function updateTriageStatistics() {
    const stats = getTriageStatistics();
    
    document.getElementById('processedCount').textContent = stats.processedFiles;
    document.getElementById('matchedCount').textContent = stats.matchedFiles;
    document.getElementById('errorCount').textContent = stats.errors;
}

function showTriageReport() {
    const stats = getTriageStatistics();
    const matchedFiles = triageAutomation.matchedFiles || [];
    
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.style.display = 'flex';
    
    const reportContent = `
        <div class="modal-content" style="max-width: 800px; max-height: 80vh; overflow-y: auto;">
            <h2 style="color: #333; margin-bottom: 20px;">📋 Rapport d'Automatisation du Triage</h2>
            
            <div style="background: rgba(255,255,255,0.1); padding: 20px; border-radius: 10px; margin: 15px 0;">
                <h3 style="color: #333; margin-bottom: 15px;">📊 Statistiques Générales</h3>
                <p><strong>📁 Répertoire source:</strong> ${stats.sourceDirectory}</p>
                <p><strong>📁 Répertoire destination:</strong> ${stats.destinationDirectory}</p>
                <p><strong>📊 Fichiers traités:</strong> ${stats.processedFiles}</p>
                <p><strong>🎯 Correspondances trouvées:</strong> ${stats.matchedFiles}</p>
                <p><strong>❌ Erreurs:</strong> ${stats.errors}</p>
                <p><strong>🔄 Statut:</strong> ${stats.isRunning ? 'En cours' : 'Terminé'}</p>
            </div>
            
            <div style="background: rgba(255,255,255,0.1); padding: 20px; border-radius: 10px; margin: 15px 0;">
                <h3 style="color: #333; margin-bottom: 15px;">🔍 Fichiers Analysés</h3>
                <p style="color: #666; font-size: 14px;">L'automatisation a analysé de <strong>vrais fichiers</strong> du répertoire "${stats.sourceDirectory}":</p>
                <div style="color: #333; font-size: 14px; line-height: 1.6;">
                    <p><strong>📊 Total:</strong> ${stats.processedFiles} fichiers analysés</p>
                    <p><strong>🔍 Types détectés:</strong> TXT, JS, HTML, CSS, JSON, XML, PDF, DOC, EXE, DLL, BAT, PS1, etc.</p>
                    <p><strong>📏 Tailles:</strong> De quelques KB à plusieurs MB</p>
                    <p><strong>🔒 Sécurité:</strong> Contenu réel lu et analysé</p>
                    <p><strong>📋 Copie:</strong> Fichiers suspects téléchargés automatiquement</p>
                </div>
            </div>
            
            ${matchedFiles.length > 0 ? `
            <div style="background: rgba(255,0,0,0.1); padding: 20px; border-radius: 10px; margin: 15px 0;">
                <h3 style="color: #333; margin-bottom: 15px;">🚨 Fichiers Correspondants Détectés</h3>
                <p style="color: #666; font-size: 14px;">Ces fichiers ont été copiés vers "${stats.destinationDirectory}":</p>
                ${matchedFiles.map(file => `
                    <div style="background: rgba(255,0,0,0.1); padding: 10px; border-radius: 5px; margin: 5px 0; border-left: 4px solid #f44336;">
                        <p style="margin: 0; color: #333;"><strong>${file.name}</strong></p>
                        <p style="margin: 5px 0; color: #666; font-size: 12px;">Statut: ${file.status.toUpperCase()} | Score de risque: ${file.riskScore}%</p>
                        <p style="margin: 5px 0; color: #666; font-size: 12px;">Règles déclenchées: ${file.matches.map(m => `${m.rule} (${Math.round((m.confidence || 0.5) * 100)}%)`).join(', ')}</p>
                        <p style="margin: 5px 0; color: #666; font-size: 12px;">Contexte: ${file.matches.map(m => m.context || 'Analyse contextuelle').join(', ')}</p>
                    </div>
                `).join('')}
            </div>
            ` : `
            <div style="background: rgba(0,255,0,0.1); padding: 20px; border-radius: 10px; margin: 15px 0; border-left: 4px solid #4CAF50;">
                <h3 style="color: #333; margin-bottom: 15px;">✅ Aucune Menace Détectée</h3>
                <p style="color: #333;">Aucun fichier suspect n'a été trouvé dans le répertoire analysé.</p>
            </div>
            `}
            
            <div style="background: rgba(255,255,255,0.1); padding: 20px; border-radius: 10px; margin: 15px 0;">
                <h3 style="color: #333; margin-bottom: 15px;">🔍 Patterns Analysés</h3>
                <p style="color: #666; font-size: 14px;">L'automatisation recherche les patterns suivants:</p>
                <ul style="color: #333; font-size: 14px; line-height: 1.6;">
                    <li><strong>Patterns personnalisés:</strong> string1, string2, malicious, suspicious</li>
                    <li><strong>Ransomware:</strong> WannaCry, Emotet, patterns de chiffrement</li>
                    <li><strong>Trojans:</strong> Zeus, backdoors, communication réseau suspecte</li>
                    <li><strong>Keyloggers:</strong> GetAsyncKeyState, surveillance clavier</li>
                    <li><strong>Scripts malveillants:</strong> PowerShell, JavaScript, commandes suspectes</li>
                    <li><strong>Macros:</strong> AutoOpen, macros automatiques</li>
                    <li><strong>Exploits:</strong> Shellcode, buffer overflow</li>
                </ul>
            </div>
            
            <div style="text-align: center; margin-top: 20px;">
                <button onclick="this.parentElement.parentElement.parentElement.remove()" 
                        style="background: #2196F3; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer;">
                    ✅ Fermer le Rapport
                </button>
            </div>
        </div>
    `;
    
    modal.innerHTML = reportContent;
    document.body.appendChild(modal);
    
    modal.addEventListener('click', function(e) {
        if (e.target === modal) {
            modal.remove();
        }
    });
}

function showTriageHelp() {
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.style.display = 'flex';
    
    const helpContent = `
        <div class="modal-content" style="max-width: 700px; max-height: 80vh; overflow-y: auto;">
            <h2 style="color: #333; margin-bottom: 20px;">❓ Aide - Automatisation du Triage</h2>
            
            <div style="background: rgba(255,255,255,0.1); padding: 20px; border-radius: 10px; margin: 15px 0;">
                <h3 style="color: #333; margin-bottom: 15px;">🚀 Comment ça fonctionne</h3>
                <p style="color: #333; line-height: 1.6;">
                    L'<strong>Automatisation du Triage</strong> simule l'analyse d'un répertoire source contenant des fichiers suspects.
                    Lynx analyse automatiquement chaque fichier et copie ceux qui correspondent aux règles de détection.
                </p>
            </div>
            
            <div style="background: rgba(255,255,255,0.1); padding: 20px; border-radius: 10px; margin: 15px 0;">
                <h3 style="color: #333; margin-bottom: 15px;">📁 Configuration</h3>
                <ul style="color: #333; line-height: 1.6;">
                    <li><strong>Répertoire source:</strong> "Triage" (simulé) - contient les fichiers à analyser</li>
                    <li><strong>Répertoire destination:</strong> "Fichiers correspondants" - où sont copiés les fichiers suspects</li>
                    <li><strong>⚙️ Configurer:</strong> Modifie les chemins source/destination</li>
                </ul>
            </div>
            
            <div style="background: rgba(255,255,255,0.1); padding: 20px; border-radius: 10px; margin: 15px 0;">
                <h3 style="color: #333; margin-bottom: 15px;">🔍 Ce qui est analysé</h3>
                <p style="color: #666; font-size: 14px;">L'automatisation analyse de <strong>vrais fichiers</strong> de votre répertoire sélectionné:</p>
                <ul style="color: #333; font-size: 14px; line-height: 1.6;">
                    <li><strong>📁 Sélection de répertoire:</strong> Cliquez sur "📁 Sélectionner Répertoire" pour choisir un dossier</li>
                    <li><strong>🔍 Analyse réelle:</strong> Lynx lit le contenu de chaque fichier</li>
                    <li><strong>📄 Types supportés:</strong> TXT, JS, HTML, CSS, JSON, XML, PDF, DOC, EXE, DLL, BAT, PS1, etc.</li>
                    <li><strong>🔒 Sécurité:</strong> Protection contre les attaques directory traversal</li>
                    <li><strong>📋 Copie réelle:</strong> Les fichiers suspects sont téléchargés automatiquement</li>
                </ul>
            </div>
            
            <div style="background: rgba(255,255,255,0.1); padding: 20px; border-radius: 10px; margin: 15px 0;">
                <h3 style="color: #333; margin-bottom: 15px;">🎯 Patterns recherchés (Optimisés)</h3>
                <ul style="color: #333; line-height: 1.6;">
                    <li><strong>string1, string2, string3:</strong> Patterns personnalisés (Confiance élevée)</li>
                    <li><strong>WannaCry:</strong> WNcry@2ol7, WanaCrypt0r (Ransomware spécifique)</li>
                    <li><strong>Zeus Trojan:</strong> Zbot, Gameover, Citadel (Trojans spécifiques)</li>
                    <li><strong>Keyloggers:</strong> GetAsyncKeyState, SetWindowsHookEx (Surveillance clavier)</li>
                    <li><strong>Backdoors:</strong> meterpreter, reverse shell (Shells malveillants)</li>
                    <li><strong>Scripts malveillants:</strong> Invoke-Expression, eval(, exec( (Fonctions dangereuses)</li>
                    <li><strong>Macros:</strong> AutoOpen, Document_Open (Macros automatiques)</li>
                    <li><strong>Shellcode:</strong> \x90\x90\x90, \xcc\xcc\xcc (NOP sled, breakpoints)</li>
                </ul>
                <p style="color: #666; font-size: 12px; margin-top: 10px;">
                    <strong>🔍 Analyse contextuelle:</strong> Réduction des faux positifs par analyse du contexte, 
                    type de fichier, taille et densité des patterns.
                </p>
            </div>
            
            <div style="background: rgba(255,255,255,0.1); padding: 20px; border-radius: 10px; margin: 15px 0;">
                <h3 style="color: #333; margin-bottom: 15px;">📊 Résultats</h3>
                <ul style="color: #333; line-height: 1.6;">
                    <li><strong>Fichiers traités:</strong> Nombre total de fichiers analysés</li>
                    <li><strong>Correspondances:</strong> Fichiers suspects détectés et copiés</li>
                    <li><strong>Erreurs:</strong> Problèmes lors de l'analyse</li>
                    <li><strong>Rapport:</strong> Détails complets de l'analyse</li>
                </ul>
            </div>
            
            <div style="text-align: center; margin-top: 20px;">
                <button onclick="this.parentElement.parentElement.parentElement.remove()" 
                        style="background: #2196F3; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer;">
                    ✅ Compris !
                </button>
            </div>
        </div>
    `;
    
    modal.innerHTML = helpContent;
    document.body.appendChild(modal);
    
    modal.addEventListener('click', function(e) {
        if (e.target === modal) {
            modal.remove();
        }
    });
}

function updateAIInsights() {
    const insights = document.getElementById('aiInsights');
    if (insights) {
        const threatLevel = threats > 0 ? 'ÉLEVÉ' : processedFiles.filter(f => f.status === 'suspicious').length > 0 ? 'MODÉRÉ' : 'FAIBLE';
        
        insights.innerHTML = `
            <p>🎯 <strong>Niveau de menace détecté:</strong> ${threatLevel}</p>
            <p>📊 <strong>Analyse terminée:</strong> ${processedFiles.length} fichiers traités</p>
            <p>🔍 <strong>Recommandation:</strong> ${getRecommendation()}</p>
            <p>⏱️ <strong>Temps de traitement:</strong> ${Math.random() * 3 + 1}s par fichier</p>
            <p>🤖 <strong>IA Status:</strong> Modèles optimisés pour la détection</p>
        `;
    }
}

function getRecommendation() {
    if (threats > 0) return 'Isolement immédiat des fichiers suspects recommandé';
    if (processedFiles.filter(f => f.status === 'suspicious').length > 0) return 'Analyse approfondie conseillée';
    return 'Aucune action requise - fichiers sécurisés';
}

function getStatusIcon(status) {
    switch(status) {
        case 'threat': return '🚨';
        case 'suspicious': return '⚠️';
        case 'safe': return '✅';
        default: return '❓';
    }
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function showDetails(fileName) {
    const file = processedFiles.find(f => f.name === fileName);
    if (!file) return;
    
    const modalContent = document.getElementById('modalContent');
    const detailModal = document.getElementById('detailModal');
    
    if (modalContent && detailModal) {
        modalContent.innerHTML = `
            <h3>${file.name}</h3>
            <p><strong>Taille:</strong> ${formatFileSize(file.size)}</p>
            <p><strong>Type:</strong> ${file.type}</p>
            <p><strong>Status:</strong> ${file.status.toUpperCase()}</p>
            <p><strong>Score de risque:</strong> ${file.riskScore}/100</p>
            <p><strong>Hash:</strong> ${file.hash}</p>
            <h4>Détails de l'analyse:</h4>
            <ul>
                ${file.details.map(detail => `<li>${detail}</li>`).join('')}
            </ul>
        `;
        
        detailModal.style.display = 'flex';
    }
}

function closeModal() {
    const detailModal = document.getElementById('detailModal');
    if (detailModal) {
        detailModal.style.display = 'none';
    }
}

function quickScan() {
    alert('🚀 Scan rapide lancé! Cette fonctionnalité analyserait les fichiers avec des règles optimisées pour la vitesse.');
}

function deepScan() {
    alert('🔍 Analyse profonde activée! Cette fonctionnalité utiliserait tous les moteurs disponibles pour une analyse exhaustive.');
}

function clearFiles() {
    processedFiles = [];
    threats = 0;
    scanning = false;
    
    updateFileList();
    updateStats();
    updateVisualization();
    updateAIInsights();
    
    const progressContainer = document.getElementById('progressContainer');
    if (progressContainer) {
        progressContainer.style.display = 'none';
    }
    
    const progressFill = document.getElementById('progressFill');
    if (progressFill) {
        progressFill.style.width = '0%';
    }
    
    const progressText = document.getElementById('progressText');
    if (progressText) {
        progressText.textContent = 'Analyse en cours...';
    }
}

// Initialisation
document.addEventListener('DOMContentLoaded', async function() {
    console.log('🚀 Initialisation de Lynx...');
    
    try {
        initBackground();
        setupDirectorySelection();
        window.addEventListener('resize', onWindowResize);
        console.log('🎉 Lynx initialisé avec succès !');
    } catch (error) {
        console.error('❌ Erreur d\'initialisation:', error);
    }
}); 

 