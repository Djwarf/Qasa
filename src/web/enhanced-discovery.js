// Enhanced Discovery Mode with Advanced Features
class EnhancedDiscovery extends DiscoveryMode {
    constructor(webSocketHandler) {
        super(webSocketHandler);
        this.peerAnalytics = new PeerAnalytics();
        this.geoLocation = null;
        this.initEnhancedFeatures();
    }

    initEnhancedFeatures() {
        this.initGeolocation();
        this.initAdvancedSearch();
    }

    createEnhancedFilters() {
        const filtersHTML = `
            <div class="filters-section">
                <div class="basic-filters">
                    <label class="filter-label">
                        <input type="checkbox" class="discovery-filter-checkbox" data-filter="online"> Online
                    </label>
                    <label class="filter-label">
                        <input type="checkbox" class="discovery-filter-checkbox" data-filter="authenticated"> Authenticated
                    </label>
                    <label class="filter-label">
                        <input type="checkbox" class="discovery-filter-checkbox" data-filter="encrypted"> Encrypted
                    </label>
                    <label class="filter-label">
                        <input type="checkbox" class="discovery-filter-checkbox" data-filter="postQuantum"> Post-Quantum
                    </label>
                </div>
                
                <div class="filter-actions">
                    <button id="clear-filters-btn" class="secondary-button">Clear Filters</button>
                    <button id="save-filter-preset-btn" class="primary-button">Save Preset</button>
                </div>
            </div>
        `;
        
        if (this.filtersContainer) {
            this.filtersContainer.innerHTML = filtersHTML;
        }
    }

    initAdvancedSearch() {
        // Add advanced search functionality placeholder
        console.log('Advanced search features initialized');
    }

    initGeolocation() {
        if (navigator.geolocation) {
            navigator.geolocation.getCurrentPosition(
                (position) => {
                    this.geoLocation = {
                        latitude: position.coords.latitude,
                        longitude: position.coords.longitude
                    };
                },
                (error) => console.warn('Geolocation not available:', error)
            );
        }
    }

    exportResults() {
        const data = {
            timestamp: new Date().toISOString(),
            total_results: this.searchResults.length,
            filters: this.activeFilters,
            results: this.searchResults
        };
        
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `qasa-discovery-results-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
    }
}

// Peer Analytics Class
class PeerAnalytics {
    constructor() {
        this.metrics = new Map();
        this.trends = new Map();
    }

    updateMetrics(peerId, metrics) {
        const existing = this.metrics.get(peerId) || { history: [] };
        existing.current = metrics;
        existing.history.push({
            timestamp: Date.now(),
            reputation: metrics.reputation,
            latency: metrics.latency,
            online: metrics.online
        });
        
        if (existing.history.length > 100) {
            existing.history.shift();
        }
        
        this.metrics.set(peerId, existing);
    }

    getPeerTrend(peerId) {
        return this.trends.get(peerId) || null;
    }
}

// Global function for map popup
function connectToPeerFromMap(peerId) {
    if (window.discoveryMode) {
        window.discoveryMode.connectToPeer(peerId);
    }
} 