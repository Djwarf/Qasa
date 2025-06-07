// QaSa Service Worker - Offline Support and Caching

const CACHE_NAME = 'qasa-v1';
const DYNAMIC_CACHE = 'qasa-dynamic-v1';

// Files to cache for offline use
const urlsToCache = [
  '/',
  '/index.html',
  '/styles.css',
  '/enhanced-styles.css',
  '/enhanced-app.js',
  '/enhanced-crypto.js',
  '/enhanced-network.js',
  '/enhanced-ui.js',
  '/discovery.js',
  '/favicon.svg',
  '/manifest.json',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css',
  'https://cdn.jsdelivr.net/npm/qrcode@1.5.1/build/qrcode.min.js'
];

// Install event - cache static assets
self.addEventListener('install', event => {
  console.log('[ServiceWorker] Install');
  
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('[ServiceWorker] Caching static assets');
        return cache.addAll(urlsToCache);
      })
      .then(() => self.skipWaiting())
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', event => {
  console.log('[ServiceWorker] Activate');
  
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheName !== CACHE_NAME && cacheName !== DYNAMIC_CACHE) {
            console.log('[ServiceWorker] Removing old cache:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

// Fetch event - serve from cache, fallback to network
self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);
  
  // Skip WebSocket requests
  if (url.protocol === 'ws:' || url.protocol === 'wss:') {
    return;
  }
  
  // Skip non-GET requests
  if (request.method !== 'GET') {
    return;
  }
  
  // Handle API requests differently
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(networkFirst(request));
    return;
  }
  
  // For everything else, try cache first
  event.respondWith(cacheFirst(request));
});

// Cache-first strategy
async function cacheFirst(request) {
  const cache = await caches.open(CACHE_NAME);
  const cached = await cache.match(request);
  
  if (cached) {
    console.log('[ServiceWorker] Serving from cache:', request.url);
    return cached;
  }
  
  try {
    const response = await fetch(request);
    
    // Cache successful responses
    if (response.ok) {
      const cache = await caches.open(DYNAMIC_CACHE);
      cache.put(request, response.clone());
    }
    
    return response;
  } catch (error) {
    console.error('[ServiceWorker] Fetch failed:', error);
    
    // Return offline page if available
    const offlinePage = await cache.match('/offline.html');
    if (offlinePage) {
      return offlinePage;
    }
    
    // Return a basic offline response
    return new Response('Offline - Please check your connection', {
      status: 503,
      statusText: 'Service Unavailable',
      headers: new Headers({
        'Content-Type': 'text/plain'
      })
    });
  }
}

// Network-first strategy for API calls
async function networkFirst(request) {
  try {
    const response = await fetch(request);
    
    // Cache successful API responses
    if (response.ok) {
      const cache = await caches.open(DYNAMIC_CACHE);
      cache.put(request, response.clone());
    }
    
    return response;
  } catch (error) {
    console.log('[ServiceWorker] Network request failed, trying cache:', request.url);
    
    const cache = await caches.open(DYNAMIC_CACHE);
    const cached = await cache.match(request);
    
    if (cached) {
      return cached;
    }
    
    // Return error response
    return new Response(JSON.stringify({
      error: 'Network error',
      offline: true
    }), {
      status: 503,
      statusText: 'Service Unavailable',
      headers: new Headers({
        'Content-Type': 'application/json'
      })
    });
  }
}

// Background sync for offline messages
self.addEventListener('sync', event => {
  console.log('[ServiceWorker] Sync event:', event.tag);
  
  if (event.tag === 'sync-messages') {
    event.waitUntil(syncOfflineMessages());
  }
});

async function syncOfflineMessages() {
  try {
    // Get offline messages from IndexedDB
    const db = await openDB();
    const messages = await getOfflineMessages(db);
    
    // Send each message
    for (const message of messages) {
      try {
        const response = await fetch('/api/messages', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(message)
        });
        
        if (response.ok) {
          // Remove from offline queue
          await removeOfflineMessage(db, message.id);
          
          // Notify clients
          self.clients.matchAll().then(clients => {
            clients.forEach(client => {
              client.postMessage({
                type: 'message-synced',
                messageId: message.id
              });
            });
          });
        }
      } catch (error) {
        console.error('[ServiceWorker] Failed to sync message:', error);
      }
    }
  } catch (error) {
    console.error('[ServiceWorker] Sync failed:', error);
  }
}

// Push notifications
self.addEventListener('push', event => {
  console.log('[ServiceWorker] Push received');
  
  const options = {
    body: 'New message received',
    icon: '/icon-192.png',
    badge: '/icon-96.png',
    vibrate: [200, 100, 200],
    tag: 'qasa-notification',
    requireInteraction: true,
    actions: [
      {
        action: 'view',
        title: 'View',
        icon: '/icon-view.png'
      },
      {
        action: 'dismiss',
        title: 'Dismiss',
        icon: '/icon-dismiss.png'
      }
    ]
  };
  
  if (event.data) {
    try {
      const data = event.data.json();
      options.body = data.body || options.body;
      options.tag = data.tag || options.tag;
      
      if (data.sender) {
        options.body = `${data.sender}: ${options.body}`;
      }
    } catch (error) {
      console.error('[ServiceWorker] Error parsing push data:', error);
    }
  }
  
  event.waitUntil(
    self.registration.showNotification('QaSa', options)
  );
});

// Notification click handler
self.addEventListener('notificationclick', event => {
  console.log('[ServiceWorker] Notification click:', event.action);
  
  event.notification.close();
  
  if (event.action === 'dismiss') {
    return;
  }
  
  // Open or focus the app
  event.waitUntil(
    clients.matchAll({
      type: 'window',
      includeUncontrolled: true
    }).then(clientList => {
      // Check if app is already open
      for (const client of clientList) {
        if (client.url.includes(self.location.origin) && 'focus' in client) {
          return client.focus();
        }
      }
      
      // Open new window if not open
      if (clients.openWindow) {
        return clients.openWindow('/');
      }
    })
  );
});

// Message handler for client communication
self.addEventListener('message', event => {
  console.log('[ServiceWorker] Message received:', event.data);
  
  if (event.data.type === 'skip-waiting') {
    self.skipWaiting();
  }
  
  if (event.data.type === 'queue-message') {
    // Store message for offline sync
    queueOfflineMessage(event.data.message).then(() => {
      event.ports[0].postMessage({ success: true });
    }).catch(error => {
      event.ports[0].postMessage({ success: false, error: error.message });
    });
  }
});

// IndexedDB helpers for offline message queue
function openDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('qasa-offline', 1);
    
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
    
    request.onupgradeneeded = event => {
      const db = event.target.result;
      
      if (!db.objectStoreNames.contains('messages')) {
        db.createObjectStore('messages', { keyPath: 'id' });
      }
    };
  });
}

async function queueOfflineMessage(message) {
  const db = await openDB();
  const tx = db.transaction(['messages'], 'readwrite');
  const store = tx.objectStore('messages');
  
  return store.add({
    ...message,
    id: `${Date.now()}-${Math.random()}`,
    queued_at: new Date().toISOString()
  });
}

async function getOfflineMessages(db) {
  const tx = db.transaction(['messages'], 'readonly');
  const store = tx.objectStore('messages');
  
  return new Promise((resolve, reject) => {
    const request = store.getAll();
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function removeOfflineMessage(db, messageId) {
  const tx = db.transaction(['messages'], 'readwrite');
  const store = tx.objectStore('messages');
  
  return store.delete(messageId);
}

// Periodic background sync for checking new messages
self.addEventListener('periodicsync', event => {
  if (event.tag === 'check-messages') {
    event.waitUntil(checkForNewMessages());
  }
});

async function checkForNewMessages() {
  try {
    const response = await fetch('/api/messages/check');
    
    if (response.ok) {
      const data = await response.json();
      
      if (data.hasNewMessages) {
        // Show notification
        self.registration.showNotification('QaSa', {
          body: `You have ${data.count} new message${data.count > 1 ? 's' : ''}`,
          icon: '/icon-192.png',
          badge: '/icon-96.png',
          tag: 'new-messages'
        });
      }
    }
  } catch (error) {
    console.error('[ServiceWorker] Failed to check messages:', error);
  }
}

// Cache cleanup - remove old dynamic cache entries
async function cleanupCache() {
  const cache = await caches.open(DYNAMIC_CACHE);
  const requests = await cache.keys();
  const now = Date.now();
  const maxAge = 7 * 24 * 60 * 60 * 1000; // 7 days
  
  for (const request of requests) {
    const response = await cache.match(request);
    const dateHeader = response.headers.get('date');
    
    if (dateHeader) {
      const date = new Date(dateHeader).getTime();
      
      if (now - date > maxAge) {
        console.log('[ServiceWorker] Removing old cache entry:', request.url);
        await cache.delete(request);
      }
    }
  }
}

// Run cleanup periodically
setInterval(cleanupCache, 24 * 60 * 60 * 1000); // Daily

console.log('[ServiceWorker] Service Worker loaded');