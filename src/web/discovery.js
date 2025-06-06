// Enhanced Discovery Mode Functionality
class DiscoveryMode {
    constructor(webSocketHandler) {
        this.ws = webSocketHandler;
        this.searchResults = [];
        this.searchType = 'all'; // all, name, key, capability, proximity
        this.activeFilters = {
            online: false,
            authenticated: false,
            encrypted: false,
            proximity: false,
            postQuantum: false,
            trusted: false,
            verified: false
        };
        this.sortBy = 'reputation'; // reputation, latency, proximity, trust
        this.sortOrder = 'desc'; // asc, desc
        this.searchHistory = [];
        this.savedSearches = [];
        this.peerMetrics = new Map();
        this.discoveryStats = {};
        this.autoRefresh = true;
        this.refreshInterval = 30000; // 30 seconds
        this.refreshTimer = null;
        
        this.initElements();
        this.initEventListeners();
        this.loadSavedSearches();
        this.startAutoRefresh();
    }

    initElements() {
        // Create DOM elements
        this.discoveryContainer = document.getElementById('discovery-container');
        this.searchInput = document.getElementById('discovery-search');
        this.searchTypeSelect = document.getElementById('search-type');
        this.searchButton = document.getElementById('discovery-search-btn');
        this.resultsContainer = document.getElementById('discovery-results');
        this.filtersContainer = document.getElementById('discovery-filters');
        this.loadingIndicator = document.getElementById('discovery-loading');
        
        // Enhanced UI elements
        this.sortSelect = document.getElementById('discovery-sort');
        this.sortOrderButton = document.getElementById('sort-order-btn');
        this.statsContainer = document.getElementById('discovery-stats');
        this.advancedFiltersPanel = document.getElementById('advanced-filters');
        this.searchHistoryButton = document.getElementById('search-history-btn');
        this.saveSearchButton = document.getElementById('save-search-btn');
        this.autoRefreshToggle = document.getElementById('auto-refresh-toggle');
        this.refreshIntervalSelect = document.getElementById('refresh-interval');
        this.exportButton = document.getElementById('export-results-btn');
        this.mapViewButton = document.getElementById('map-view-btn');
        this.listViewButton = document.getElementById('list-view-btn');
        this.viewMode = 'list'; // list, map
        
        // Create enhanced filter elements if they don't exist
        this.createEnhancedFilters();
        this.createStatsPanel();
    }

    initEventListeners() {
        // Add event listeners
        this.searchButton.addEventListener('click', () => this.performSearch());
        this.searchInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.performSearch();
            }
        });

        // Filter change listeners
        document.querySelectorAll('.discovery-filter-checkbox').forEach(checkbox => {
            checkbox.addEventListener('change', () => {
                this.activeFilters[checkbox.dataset.filter] = checkbox.checked;
                this.filterResults();
            });
        });

        // Search type change
        this.searchTypeSelect.addEventListener('change', () => {
            this.searchType = this.searchTypeSelect.value;
        });
    }

    performSearch() {
        const query = this.searchInput.value.trim();
        if (query === '') return;

        // Show loading indicator
        this.setLoading(true);
        
        // Clear previous results
        this.searchResults = [];
        this.updateResultsView();

        // Send search request through websocket
        this.ws.send(JSON.stringify({
            type: 'search',
            data: {
                query: query,
                type: this.searchType
            }
        }));
    }

    handleSearchResults(data) {
        this.searchResults = data.results;
        this.setLoading(false);
        this.filterResults();
    }

    filterResults() {
        let filteredResults = [...this.searchResults];
        
        // Apply filters
        if (this.activeFilters.online) {
            filteredResults = filteredResults.filter(peer => peer.online);
        }
        
        if (this.activeFilters.authenticated) {
            filteredResults = filteredResults.filter(peer => peer.authenticated);
        }
        
        if (this.activeFilters.encrypted) {
            filteredResults = filteredResults.filter(peer => peer.encryption_status === 'enabled');
        }
        
        if (this.activeFilters.proximity) {
            // Sort by proximity (if available)
            filteredResults.sort((a, b) => {
                if (a.proximity && b.proximity) {
                    return a.proximity - b.proximity;
                }
                return 0;
            });
        }

        this.updateResultsView(filteredResults);
    }

    updateResultsView(results = this.searchResults) {
        this.resultsContainer.innerHTML = '';
        
        if (results.length === 0) {
            this.resultsContainer.innerHTML = '<div class="no-results">No peers found</div>';
            return;
        }

        results.forEach(peer => {
            const peerElement = document.createElement('div');
            peerElement.className = 'peer-result';
            
            // Determine status indicators
            const onlineStatus = peer.online ? 
                '<span class="status-indicator online" title="Online"></span>' : 
                '<span class="status-indicator offline" title="Offline"></span>';
                
            const authStatus = peer.authenticated ? 
                '<span class="auth-badge" title="Authenticated">✓</span>' : '';
                
            const encryptStatus = peer.encryption_status === 'enabled' ? 
                '<span class="encrypt-badge" title="Encrypted">🔒</span>' : '';
            
            // Format name/ID display
            let displayName = peer.identifier || shortPeerId(peer.peer_id);
            
            peerElement.innerHTML = `
                <div class="peer-header">
                    ${onlineStatus}
                    <h3 class="peer-name">${displayName}</h3>
                    ${authStatus}
                    ${encryptStatus}
                </div>
                <div class="peer-details">
                    <div class="peer-id">${shortPeerId(peer.peer_id)}</div>
                    ${peer.key_id ? `<div class="peer-key-id">Key: ${shortPeerId(peer.key_id)}</div>` : ''}
                </div>
                <div class="peer-actions">
                    <button class="connect-btn" data-peer-id="${peer.peer_id}">Connect</button>
                    <button class="chat-btn" data-peer-id="${peer.peer_id}">Chat</button>
                </div>
            `;
            
            // Add event listeners to buttons
            peerElement.querySelector('.connect-btn').addEventListener('click', () => {
                this.connectToPeer(peer.peer_id);
            });
            
            peerElement.querySelector('.chat-btn').addEventListener('click', () => {
                this.startChat(peer.peer_id);
            });
            
            this.resultsContainer.appendChild(peerElement);
        });
    }

    connectToPeer(peerId) {
        // Connect to the peer
        this.ws.send(JSON.stringify({
            type: 'connect',
            data: {
                peer_addr: peerId
            }
        }));
        
        // If needed, also initiate key exchange
        this.ws.send(JSON.stringify({
            type: 'key_exchange',
            data: {
                peer_id: peerId,
                algorithm: 'kyber' // Default to Kyber 
            }
        }));
    }

    startChat(peerId) {
        // Connect first
        this.connectToPeer(peerId);
        
        // Then select for chat
        selectContact(peerId);
        
        // Switch to chat view
        document.querySelector('.discovery-toggle').click();
    }

    setLoading(isLoading) {
        if (isLoading) {
            this.loadingIndicator.style.display = 'block';
        } else {
            this.loadingIndicator.style.display = 'none';
        }
    }
}

// Initialize discovery mode when the main app is ready
document.addEventListener('DOMContentLoaded', () => {
    // This will be initialized after WebSocket is connected in app.js
    window.initDiscovery = (ws) => {
        window.discoveryMode = new DiscoveryMode(ws);
    };
}); 