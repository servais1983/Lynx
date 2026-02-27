// Gestionnaire d'Interface Utilisateur pour Lynx
// Thèmes, mode sombre, notifications et personnalisation

class UIManager {
    constructor() {
        this.currentTheme = 'glassmorphic';
        this.isDarkMode = false;
        this.notificationsEnabled = false;
        this.themes = this.initializeThemes();
        this.notifications = [];
        this.isInitialized = false;
    }

    // Initialiser les thèmes disponibles
    initializeThemes() {
        return {
            glassmorphic: {
                name: 'Glassmorphic',
                description: 'Design moderne avec effets de verre',
                variables: {
                    '--bg-primary': 'rgba(255, 255, 255, 0.1)',
                    '--bg-secondary': 'rgba(255, 255, 255, 0.05)',
                    '--text-primary': '#ffffff',
                    '--text-secondary': '#cccccc',
                    '--accent-color': '#2196F3',
                    '--border-color': 'rgba(255, 255, 255, 0.2)',
                    '--shadow': '0 8px 32px rgba(0, 0, 0, 0.3)',
                    '--backdrop': 'blur(10px)'
                }
            },
            material: {
                name: 'Material Design',
                description: 'Design Material de Google',
                variables: {
                    '--bg-primary': '#ffffff',
                    '--bg-secondary': '#f5f5f5',
                    '--text-primary': '#212121',
                    '--text-secondary': '#757575',
                    '--accent-color': '#6200ee',
                    '--border-color': '#e0e0e0',
                    '--shadow': '0 2px 4px rgba(0,0,0,0.1)',
                    '--backdrop': 'none'
                }
            },
            neumorphic: {
                name: 'Neumorphic',
                description: 'Design avec effets 3D doux',
                variables: {
                    '--bg-primary': '#e0e5ec',
                    '--bg-secondary': '#f0f3f6',
                    '--text-primary': '#2d3748',
                    '--text-secondary': '#4a5568',
                    '--accent-color': '#3182ce',
                    '--border-color': '#cbd5e0',
                    '--shadow': '8px 8px 16px #a3b1c6, -8px -8px 16px #ffffff',
                    '--backdrop': 'none'
                }
            },
            cyberpunk: {
                name: 'Cyberpunk',
                description: 'Thème futuriste avec néons',
                variables: {
                    '--bg-primary': '#0a0a0a',
                    '--bg-secondary': '#1a1a1a',
                    '--text-primary': '#00ff41',
                    '--text-secondary': '#00cc33',
                    '--accent-color': '#ff0080',
                    '--border-color': '#00ff41',
                    '--shadow': '0 0 20px rgba(0, 255, 65, 0.3)',
                    '--backdrop': 'blur(5px)'
                }
            }
        };
    }

    // Initialiser l'interface
    async initialize() {
        try {
            console.log('🎨 Initialisation de l\'interface utilisateur...');
            
            // Charger les préférences utilisateur
            this.loadUserPreferences();
            
            // Appliquer le thème actuel
            this.applyTheme(this.currentTheme);
            
            // Configurer le mode sombre automatique
            this.setupAutoDarkMode();
            
            // Initialiser les notifications
            this.initializeNotifications();
            
            // Configurer les événements
            this.setupEventListeners();
            
            this.isInitialized = true;
            console.log('✅ Interface utilisateur initialisée');
            
        } catch (error) {
            console.error('❌ Erreur initialisation UI:', error);
            throw error;
        }
    }

    // Charger les préférences utilisateur
    loadUserPreferences() {
        try {
            const preferences = localStorage.getItem('lynxUIPreferences');
            if (preferences) {
                const prefs = JSON.parse(preferences);
                this.currentTheme = prefs.theme || 'glassmorphic';
                this.isDarkMode = prefs.darkMode || false;
                this.notificationsEnabled = prefs.notifications || false;
            }
        } catch (error) {
            console.warn('⚠️ Erreur chargement préférences UI, utilisation des valeurs par défaut');
        }
    }

    // Sauvegarder les préférences utilisateur
    saveUserPreferences() {
        try {
            const preferences = {
                theme: this.currentTheme,
                darkMode: this.isDarkMode,
                notifications: this.notificationsEnabled,
                timestamp: new Date().toISOString()
            };
            
            localStorage.setItem('lynxUIPreferences', JSON.stringify(preferences));
            console.log('💾 Préférences UI sauvegardées');
            
        } catch (error) {
            console.error('❌ Erreur sauvegarde préférences UI:', error);
        }
    }

    // Appliquer un thème
    applyTheme(themeName) {
        const theme = this.themes[themeName];
        if (!theme) {
            console.warn(`⚠️ Thème ${themeName} non trouvé, utilisation du thème par défaut`);
            themeName = 'glassmorphic';
        }

        const root = document.documentElement;
        
        // Appliquer les variables CSS
        Object.entries(theme.variables).forEach(([property, value]) => {
            root.style.setProperty(property, value);
        });

        // Ajouter la classe du thème
        document.body.className = document.body.className.replace(/theme-\w+/g, '');
        document.body.classList.add(`theme-${themeName}`);

        this.currentTheme = themeName;
        this.saveUserPreferences();

        // Déclencher un événement personnalisé
        document.dispatchEvent(new CustomEvent('themeChanged', {
            detail: { theme: themeName, themeData: theme }
        }));

        console.log(`🎨 Thème appliqué: ${theme.name}`);
    }

    // Changer de thème
    changeTheme(themeName) {
        if (this.themes[themeName]) {
            this.applyTheme(themeName);
            this.showNotification('Thème changé', `Thème ${this.themes[themeName].name} appliqué`);
        } else {
            console.error(`❌ Thème ${themeName} non disponible`);
        }
    }

    // Configurer le mode sombre automatique
    setupAutoDarkMode() {
        // Détecter la préférence système
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)');
        
        // Écouter les changements de préférence système
        prefersDark.addListener((e) => {
            if (this.isAutoDarkMode()) {
                this.setDarkMode(e.matches);
            }
        });

        // Appliquer le mode sombre initial
        if (this.isAutoDarkMode()) {
            this.setDarkMode(prefersDark.matches);
        }
    }

    // Activer/désactiver le mode sombre
    setDarkMode(enabled) {
        this.isDarkMode = enabled;
        
        if (enabled) {
            document.body.classList.add('dark-mode');
            document.body.classList.remove('light-mode');
        } else {
            document.body.classList.remove('dark-mode');
            document.body.classList.add('light-mode');
        }

        this.saveUserPreferences();
        
        // Déclencher un événement
        document.dispatchEvent(new CustomEvent('darkModeChanged', {
            detail: { enabled: this.isDarkMode }
        }));

        console.log(`🌙 Mode sombre ${enabled ? 'activé' : 'désactivé'}`);
    }

    // Vérifier si le mode sombre automatique est activé
    isAutoDarkMode() {
        return localStorage.getItem('lynxAutoDarkMode') === 'true';
    }

    // Activer le mode sombre automatique
    setAutoDarkMode(enabled) {
        localStorage.setItem('lynxAutoDarkMode', enabled.toString());
        
        if (enabled) {
            const prefersDark = window.matchMedia('(prefers-color-scheme: dark)');
            this.setDarkMode(prefersDark.matches);
        }
    }

    // Initialiser les notifications
    initializeNotifications() {
        if ('Notification' in window) {
            Notification.requestPermission().then(permission => {
                this.notificationsEnabled = permission === 'granted';
                console.log(`🔔 Notifications ${this.notificationsEnabled ? 'activées' : 'désactivées'}`);
            });
        }
    }

    // Afficher une notification
    showNotification(title, message, options = {}) {
        // Notification native du navigateur
        if (this.notificationsEnabled && 'Notification' in window) {
            if (Notification.permission === 'granted') {
                new Notification(title, {
                    body: message,
                    icon: '/favicon.ico',
                    badge: '/favicon.ico',
                    ...options
                });
            }
        }

        // Notification personnalisée dans l'interface
        this.showCustomNotification(title, message, options);
    }

    // Afficher une notification personnalisée
    showCustomNotification(title, message, options = {}) {
        const notification = document.createElement('div');
        notification.className = `custom-notification ${options.type || 'info'}`;

        // Use DOM methods — NOT innerHTML — to prevent XSS from title/message
        const header = document.createElement('div');
        header.className = 'notification-header';

        const titleSpan = document.createElement('span');
        titleSpan.className = 'notification-title';
        titleSpan.textContent = title;

        const closeBtn = document.createElement('button');
        closeBtn.className = 'notification-close';
        closeBtn.textContent = '×';
        closeBtn.addEventListener('click', () => notification.remove());

        header.appendChild(titleSpan);
        header.appendChild(closeBtn);

        const body = document.createElement('div');
        body.className = 'notification-body';
        body.textContent = message;

        notification.appendChild(header);
        notification.appendChild(body);

        // Ajouter au conteneur de notifications
        let container = document.getElementById('notification-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'notification-container';
            document.body.appendChild(container);
        }

        container.appendChild(notification);

        // Animation d'entrée
        setTimeout(() => {
            notification.classList.add('show');
        }, 100);

        // Auto-suppression après délai
        if (options.duration !== 0) {
            setTimeout(() => {
                notification.classList.remove('show');
                setTimeout(() => notification.remove(), 300);
            }, options.duration || 5000);
        }

        // Ajouter à l'historique
        this.notifications.push({
            title,
            message,
            timestamp: new Date().toISOString(),
            type: options.type || 'info'
        });

        // Limiter l'historique
        if (this.notifications.length > 100) {
            this.notifications.shift();
        }
    }

    // Configurer les événements
    setupEventListeners() {
        // Écouter les changements de thème
        document.addEventListener('themeChanged', (e) => {
            this.updateThemeIndicator(e.detail.theme);
        });

        // Écouter les changements de mode sombre
        document.addEventListener('darkModeChanged', (e) => {
            this.updateDarkModeIndicator(e.detail.enabled);
        });

        // Écouter les raccourcis clavier
        document.addEventListener('keydown', (e) => {
            this.handleKeyboardShortcuts(e);
        });
    }

    // Gérer les raccourcis clavier
    handleKeyboardShortcuts(e) {
        // Ctrl/Cmd + T : Changer de thème
        if ((e.ctrlKey || e.metaKey) && e.key === 't') {
            e.preventDefault();
            this.cycleTheme();
        }

        // Ctrl/Cmd + D : Basculer le mode sombre
        if ((e.ctrlKey || e.metaKey) && e.key === 'd') {
            e.preventDefault();
            this.toggleDarkMode();
        }

        // Échap : Fermer les modales
        if (e.key === 'Escape') {
            this.closeAllModals();
        }
    }

    // Changer de thème cycliquement
    cycleTheme() {
        const themes = Object.keys(this.themes);
        const currentIndex = themes.indexOf(this.currentTheme);
        const nextIndex = (currentIndex + 1) % themes.length;
        this.changeTheme(themes[nextIndex]);
    }

    // Basculer le mode sombre
    toggleDarkMode() {
        this.setDarkMode(!this.isDarkMode);
    }

    // Fermer toutes les modales
    closeAllModals() {
        const modals = document.querySelectorAll('.modal');
        modals.forEach(modal => {
            modal.style.display = 'none';
        });
    }

    // Mettre à jour l'indicateur de thème
    updateThemeIndicator(themeName) {
        const indicator = document.getElementById('theme-indicator');
        if (indicator) {
            indicator.textContent = this.themes[themeName].name;
        }
    }

    // Mettre à jour l'indicateur de mode sombre
    updateDarkModeIndicator(enabled) {
        const indicator = document.getElementById('dark-mode-indicator');
        if (indicator) {
            indicator.textContent = enabled ? '🌙' : '☀️';
        }
    }

    // Obtenir les statistiques de l'interface
    getUIStats() {
        return {
            currentTheme: this.currentTheme,
            isDarkMode: this.isDarkMode,
            notificationsEnabled: this.notificationsEnabled,
            notificationsCount: this.notifications.length,
            themesAvailable: Object.keys(this.themes).length,
            autoDarkMode: this.isAutoDarkMode()
        };
    }

    // Obtenir la liste des thèmes
    getThemesList() {
        return Object.entries(this.themes).map(([key, theme]) => ({
            id: key,
            name: theme.name,
            description: theme.description,
            isActive: key === this.currentTheme
        }));
    }

    // Obtenir l'historique des notifications
    getNotificationsHistory() {
        return this.notifications.slice(-20); // 20 dernières notifications
    }

    // Effacer l'historique des notifications
    clearNotificationsHistory() {
        this.notifications = [];
        console.log('🗑️ Historique des notifications effacé');
    }

    // Créer un sélecteur de thème
    createThemeSelector() {
        const selector = document.createElement('div');
        selector.className = 'theme-selector';
        selector.innerHTML = `
            <label for="theme-select">Thème:</label>
            <select id="theme-select">
                ${Object.entries(this.themes).map(([key, theme]) => 
                    `<option value="${key}" ${key === this.currentTheme ? 'selected' : ''}>
                        ${theme.name}
                    </option>`
                ).join('')}
            </select>
        `;

        // Écouter les changements
        const select = selector.querySelector('#theme-select');
        select.addEventListener('change', (e) => {
            this.changeTheme(e.target.value);
        });

        return selector;
    }

    // Créer un panneau de contrôle
    createControlPanel() {
        const panel = document.createElement('div');
        panel.className = 'ui-control-panel';
        panel.innerHTML = `
            <h3>🎨 Contrôles d'Interface</h3>
            <div class="control-group">
                <label>
                    <input type="checkbox" id="dark-mode-toggle" ${this.isDarkMode ? 'checked' : ''}>
                    Mode sombre
                </label>
            </div>
            <div class="control-group">
                <label>
                    <input type="checkbox" id="auto-dark-mode" ${this.isAutoDarkMode() ? 'checked' : ''}>
                    Mode sombre automatique
                </label>
            </div>
            <div class="control-group">
                <label>
                    <input type="checkbox" id="notifications-toggle" ${this.notificationsEnabled ? 'checked' : ''}>
                    Notifications
                </label>
            </div>
            <div class="control-group">
                <button onclick="uiManager.cycleTheme()">🔄 Changer de thème</button>
            </div>
        `;

        // Configurer les événements
        const darkModeToggle = panel.querySelector('#dark-mode-toggle');
        darkModeToggle.addEventListener('change', (e) => {
            this.setDarkMode(e.target.checked);
        });

        const autoDarkModeToggle = panel.querySelector('#auto-dark-mode');
        autoDarkModeToggle.addEventListener('change', (e) => {
            this.setAutoDarkMode(e.target.checked);
        });

        const notificationsToggle = panel.querySelector('#notifications-toggle');
        notificationsToggle.addEventListener('change', (e) => {
            this.notificationsEnabled = e.target.checked;
            this.saveUserPreferences();
        });

        return panel;
    }
}

// Export pour utilisation
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { UIManager };
} 