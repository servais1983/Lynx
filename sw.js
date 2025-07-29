// Service Worker pour Lynx
// Cache, offline et performance

const CACHE_NAME = 'lynx-v1.0.0';
const STATIC_CACHE = 'lynx-static-v1.0.0';
const DYNAMIC_CACHE = 'lynx-dynamic-v1.0.0';
const API_CACHE = 'lynx-api-v1.0.0';

// Ressources à mettre en cache
const STATIC_RESOURCES = [
    '/',
    '/index.html',
    '/css/styles.css',
    '/css/themes.css',
    '/js/lynx.js',
    '/js/config.js',
    '/js/yara-rules.js',
    '/js/ml-models.js',
    '/js/signature-database.js',
    '/js/virustotal-api.js',
    '/js/ai-engine.js',
    '/js/ai-models.js',
    '/js/report-generator.js',
    '/js/advanced-config.js',
    '/js/rest-api.js',
    '/js/ui-manager.js',
    '/js/plugin-system.js',
    '/js/local-database.js',
    '/js/devsecops-config.js',
    '/js/production-config.js',
    '/js/real-yara-rules.js',
    '/js/zip-processor.js',
    '/js/pattern-searcher.js',
    '/js/triage-automation.js',
    '/js/test-functionality.js',
    '/js/analysis-worker.js',
    '/demo/README-demo.md',
    '/demo/string1_demo.txt',
    '/demo/string2_demo.js',
    '/demo/string3_demo.py',
    '/demo/wannacry_sample.txt',
    '/demo/zeus_trojan.txt',
    '/demo/keylogger_demo.txt',
    '/demo/backdoor_demo.txt',
    '/demo/shellcode_demo.txt',
    '/demo/malicious_script.js',
    '/demo/suspicious_powershell.ps1',
    '/demo/malicious_macro.txt',
    '/demo/clean_document.txt',
    '/demo/safe_script.py',
    '/demo/normal_image.jpg'
];

// Installation du Service Worker
self.addEventListener('install', event => {
    console.log('🔧 Installation du Service Worker Lynx...');
    
    event.waitUntil(
        caches.open(STATIC_CACHE)
            .then(cache => {
                console.log('📦 Mise en cache des ressources statiques...');
                return cache.addAll(STATIC_RESOURCES);
            })
            .then(() => {
                console.log('✅ Service Worker installé');
                return self.skipWaiting();
            })
            .catch(error => {
                console.error('❌ Erreur installation Service Worker:', error);
            })
    );
});

// Activation du Service Worker
self.addEventListener('activate', event => {
    console.log('🚀 Activation du Service Worker Lynx...');
    
    event.waitUntil(
        Promise.all([
            // Nettoyer les anciens caches
            cleanOldCaches(),
            // Prendre le contrôle immédiatement
            self.clients.claim()
        ])
    );
});

// Interception des requêtes
self.addEventListener('fetch', event => {
    const { request } = event;
    const url = new URL(request.url);
    
    // Stratégie de cache selon le type de ressource
    if (isStaticResource(request)) {
        event.respondWith(cacheFirst(request));
    } else if (isAPIRequest(request)) {
        event.respondWith(networkFirst(request));
    } else if (isAnalysisRequest(request)) {
        event.respondWith(analysisStrategy(request));
    } else {
        event.respondWith(networkFirst(request));
    }
});

// Vérifier si c'est une ressource statique
function isStaticResource(request) {
    const url = new URL(request.url);
    return STATIC_RESOURCES.some(resource => 
        url.pathname === resource || 
        url.pathname.endsWith('.css') ||
        url.pathname.endsWith('.js') ||
        url.pathname.endsWith('.html')
    );
}

// Vérifier si c'est une requête API
function isAPIRequest(request) {
    const url = new URL(request.url);
    return url.pathname.startsWith('/api/') || 
           url.hostname.includes('virustotal.com') ||
           url.hostname.includes('api.');
}

// Vérifier si c'est une requête d'analyse
function isAnalysisRequest(request) {
    const url = new URL(request.url);
    return url.pathname.includes('analyze') || 
           url.pathname.includes('analysis');
}

// Stratégie Cache First
async function cacheFirst(request) {
    try {
        // Essayer le cache d'abord
        const cachedResponse = await caches.match(request);
        if (cachedResponse) {
            return cachedResponse;
        }
        
        // Sinon, aller sur le réseau
        const networkResponse = await fetch(request);
        
        // Mettre en cache pour la prochaine fois
        if (networkResponse.ok) {
            const cache = await caches.open(DYNAMIC_CACHE);
            cache.put(request, networkResponse.clone());
        }
        
        return networkResponse;
        
    } catch (error) {
        console.error('❌ Erreur cache first:', error);
        throw error;
    }
}

// Stratégie Network First
async function networkFirst(request) {
    try {
        // Essayer le réseau d'abord
        const networkResponse = await fetch(request);
        
        // Mettre en cache si succès
        if (networkResponse.ok) {
            const cache = await caches.open(DYNAMIC_CACHE);
            cache.put(request, networkResponse.clone());
        }
        
        return networkResponse;
        
    } catch (error) {
        // En cas d'échec réseau, essayer le cache
        const cachedResponse = await caches.match(request);
        if (cachedResponse) {
            return cachedResponse;
        }
        
        // Sinon, retourner une page d'erreur offline
        return createOfflineResponse(request);
    }
}

// Stratégie pour les analyses
async function analysisStrategy(request) {
    try {
        // Pour les analyses, toujours essayer le réseau d'abord
        const networkResponse = await fetch(request);
        
        // Mettre en cache les résultats d'analyse
        if (networkResponse.ok) {
            const cache = await caches.open(API_CACHE);
            cache.put(request, networkResponse.clone());
        }
        
        return networkResponse;
        
    } catch (error) {
        // Pour les analyses, pas de fallback cache
        return createAnalysisErrorResponse(request, error);
    }
}

// Créer une réponse offline
function createOfflineResponse(request) {
    const offlineHTML = `
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Lynx - Mode Hors Ligne</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }
                .offline-container {
                    text-align: center;
                    padding: 2rem;
                    background: rgba(255, 255, 255, 0.1);
                    border-radius: 1rem;
                    backdrop-filter: blur(10px);
                }
                .offline-icon {
                    font-size: 4rem;
                    margin-bottom: 1rem;
                }
                h1 {
                    margin-bottom: 1rem;
                }
                p {
                    margin-bottom: 1rem;
                    opacity: 0.8;
                }
                .retry-btn {
                    background: #2196F3;
                    color: white;
                    border: none;
                    padding: 0.5rem 1rem;
                    border-radius: 0.5rem;
                    cursor: pointer;
                    font-size: 1rem;
                }
                .retry-btn:hover {
                    background: #1976D2;
                }
            </style>
        </head>
        <body>
            <div class="offline-container">
                <div class="offline-icon">📡</div>
                <h1>Mode Hors Ligne</h1>
                <p>Vous êtes actuellement hors ligne.</p>
                <p>Certaines fonctionnalités de Lynx peuvent ne pas être disponibles.</p>
                <button class="retry-btn" onclick="window.location.reload()">
                    Réessayer
                </button>
            </div>
        </body>
        </html>
    `;
    
    return new Response(offlineHTML, {
        status: 200,
        statusText: 'OK',
        headers: {
            'Content-Type': 'text/html',
            'Cache-Control': 'no-cache'
        }
    });
}

// Créer une réponse d'erreur d'analyse
function createAnalysisErrorResponse(request, error) {
    const errorResponse = {
        error: 'ANALYSIS_FAILED',
        message: 'L\'analyse a échoué en raison d\'une erreur réseau',
        details: error.message,
        timestamp: new Date().toISOString(),
        request: {
            url: request.url,
            method: request.method
        }
    };
    
    return new Response(JSON.stringify(errorResponse), {
        status: 503,
        statusText: 'Service Unavailable',
        headers: {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-cache'
        }
    });
}

// Nettoyer les anciens caches
async function cleanOldCaches() {
    const cacheNames = await caches.keys();
    const cachesToDelete = cacheNames.filter(name => 
        name.startsWith('lynx-') && name !== STATIC_CACHE && name !== DYNAMIC_CACHE && name !== API_CACHE
    );
    
    return Promise.all(
        cachesToDelete.map(name => {
            console.log(`🗑️ Suppression du cache: ${name}`);
            return caches.delete(name);
        })
    );
}

// Gestion des messages du Service Worker
self.addEventListener('message', event => {
    const { type, data } = event.data;
    
    switch (type) {
        case 'SKIP_WAITING':
            self.skipWaiting();
            break;
        case 'GET_CACHE_INFO':
            getCacheInfo().then(info => {
                event.ports[0].postMessage(info);
            });
            break;
        case 'CLEAR_CACHE':
            clearCache(data.cacheName).then(() => {
                event.ports[0].postMessage({ success: true });
            });
            break;
        case 'UPDATE_CACHE':
            updateCache(data.resources).then(() => {
                event.ports[0].postMessage({ success: true });
            });
            break;
        default:
            console.warn('Type de message inconnu:', type);
    }
});

// Obtenir les informations du cache
async function getCacheInfo() {
    const cacheNames = await caches.keys();
    const cacheInfo = {};
    
    for (const name of cacheNames) {
        const cache = await caches.open(name);
        const keys = await cache.keys();
        cacheInfo[name] = {
            size: keys.length,
            urls: keys.map(request => request.url)
        };
    }
    
    return cacheInfo;
}

// Vider un cache spécifique
async function clearCache(cacheName) {
    if (cacheName) {
        await caches.delete(cacheName);
        console.log(`🗑️ Cache supprimé: ${cacheName}`);
    } else {
        const cacheNames = await caches.keys();
        await Promise.all(cacheNames.map(name => caches.delete(name)));
        console.log('🗑️ Tous les caches supprimés');
    }
}

// Mettre à jour le cache
async function updateCache(resources) {
    const cache = await caches.open(DYNAMIC_CACHE);
    
    for (const resource of resources) {
        try {
            const response = await fetch(resource);
            if (response.ok) {
                await cache.put(resource, response);
                console.log(`✅ Ressource mise en cache: ${resource}`);
            }
        } catch (error) {
            console.warn(`⚠️ Erreur mise en cache: ${resource}`, error);
        }
    }
}

// Gestion des erreurs
self.addEventListener('error', event => {
    console.error('❌ Erreur Service Worker:', event.error);
});

self.addEventListener('unhandledrejection', event => {
    console.error('❌ Promesse rejetée non gérée:', event.reason);
});

// Fonctionnalités avancées

// Compression des données
async function compressData(data) {
    try {
        const stream = new ReadableStream({
            start(controller) {
                const encoder = new TextEncoder();
                const encoded = encoder.encode(JSON.stringify(data));
                controller.enqueue(encoded);
                controller.close();
            }
        });
        
        const compressedStream = stream.pipeThrough(new CompressionStream('gzip'));
        const chunks = [];
        
        for await (const chunk of compressedStream) {
            chunks.push(chunk);
        }
        
        return new Blob(chunks);
    } catch (error) {
        console.error('❌ Erreur compression:', error);
        return new Blob([JSON.stringify(data)]);
    }
}

// Décompression des données
async function decompressData(blob) {
    try {
        const stream = blob.stream();
        const decompressedStream = stream.pipeThrough(new DecompressionStream('gzip'));
        const chunks = [];
        
        for await (const chunk of decompressedStream) {
            chunks.push(chunk);
        }
        
        const decoder = new TextDecoder();
        const text = decoder.decode(new Uint8Array(chunks.flatMap(chunk => [...chunk])));
        return JSON.parse(text);
    } catch (error) {
        console.error('❌ Erreur décompression:', error);
        return null;
    }
}

// Synchronisation en arrière-plan
async function backgroundSync() {
    try {
        const registration = await navigator.serviceWorker.ready;
        
        if ('sync' in registration) {
            await registration.sync.register('background-sync');
            console.log('🔄 Synchronisation en arrière-plan enregistrée');
        }
    } catch (error) {
        console.error('❌ Erreur synchronisation:', error);
    }
}

// Gestion des notifications push
self.addEventListener('push', event => {
    if (event.data) {
        const data = event.data.json();
        
        const options = {
            body: data.body || 'Nouvelle notification Lynx',
            icon: '/favicon.ico',
            badge: '/favicon.ico',
            tag: 'lynx-notification',
            data: data.data || {},
            actions: data.actions || []
        };
        
        event.waitUntil(
            self.registration.showNotification(data.title || 'Lynx', options)
        );
    }
});

// Gestion des clics sur les notifications
self.addEventListener('notificationclick', event => {
    event.notification.close();
    
    if (event.action === 'open') {
        event.waitUntil(
            clients.openWindow('/')
        );
    } else {
        event.waitUntil(
            clients.matchAll().then(clients => {
                if (clients.length > 0) {
                    clients[0].focus();
                } else {
                    clients.openWindow('/');
                }
            })
        );
    }
});

console.log('🔧 Service Worker Lynx chargé'); 