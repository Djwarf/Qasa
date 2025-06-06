// Enhanced QaSa Network Module - P2P Networking and Discovery

class QaSaNetwork {
    constructor() {
        this.ws = null;
        this.peers = new Map();
        this.peerMetrics = new Map();
        this.discoveryResults = new Map();
        this.connectionQuality = new Map();
        this.reputationScores = new Map();
        this.networkStats = {
            totalPeers: 0,
            onlinePeers: 0,
            avgLatency: 0,
            bandwidth: 0,
            packetLoss: 0
        };
        
        this.discoveryCallbacks = new Map();
        this.metricsInterval = null;
    }

    init(ws) {
        this.ws = ws;
        this.startMetricsCollection();
        this.initializeNetworkMonitoring();
    }

    // Peer Discovery
    async discoverPeers(options = {}) {
        const {
            type = 'all',
            filters = {},
            limit = 50,
            location = null
        } = options;
        
        const requestId = this.generateRequestId();
        
        return new Promise((resolve, reject) => {
            this.discoveryCallbacks.set(requestId, { resolve, reject });
            
            this.sendMessage('discover_peers', {
                request_id: requestId,
                type,
                filters: this.buildDiscoveryFilters(filters),
                limit,
                location
            });
            
            // Timeout after 30 seconds
            setTimeout(() => {
                if (this.discoveryCallbacks.has(requestId)) {
                    this.discoveryCallbacks.delete(requestId);
                    reject(new Error('Discovery timeout'));
                }
            }, 30000);
        });
    }

    buildDiscoveryFilters(filters) {
        const builtFilters = {};
        
        if (filters.online) {
            builtFilters.online_only = true;
        }
        
        if (filters.authenticated) {
            builtFilters.authenticated_only = true;
        }
        
        if (filters.quantumSafe) {
            builtFilters.quantum_safe = true;
        }
        
        if (filters.highReputation) {
            builtFilters.min_reputation = 4.0;
        }
        
        if (filters.maxLatency) {
            builtFilters.max_latency = filters.maxLatency;
        }
        
        if (filters.capabilities) {
            builtFilters.required_capabilities = filters.capabilities;
        }
        
        return builtFilters;
    }

    handleSearchResults(data) {
        const { request_id, results, total_found, search_metadata } = data;
        
        // Process results
        const processedResults = results.map(result => this.processSearchResult(result));
        
        // Store in discovery results
        processedResults.forEach(peer => {
            this.discoveryResults.set(peer.peer_id, peer);
        });
        
        // Handle callback
        const callback = this.discoveryCallbacks.get(request_id);
        if (callback) {
            callback.resolve({
                results: processedResults,
                total: total_found,
                metadata: search_metadata
            });
            this.discoveryCallbacks.delete(request_id);
        }
        
        // Update UI
        this.updateDiscoveryUI(processedResults);
    }

    processSearchResult(result) {
        const processed = {
            peer_id: result.peer_id,
            username: result.username || null,
            display_name: result.username || this.shortenPeerId(result.peer_id),
            online: result.online || false,
            last_seen: result.last_seen,
            authenticated: result.authenticated || false,
            quantum_safe: result.quantum_safe || false,
            reputation: result.reputation || 0,
            latency: result.latency || null,
            location: result.location || null,
            capabilities: result.capabilities || [],
            metadata: result.metadata || {}
        };
        
        // Calculate trust score
        processed.trust_score = this.calculateTrustScore(processed);
        
        return processed;
    }

    calculateTrustScore(peer) {
        let score = 0;
        
        // Base score from reputation
        score += peer.reputation * 20;
        
        // Bonus for authentication
        if (peer.authenticated) score += 10;
        
        // Bonus for quantum-safe
        if (peer.quantum_safe) score += 15;
        
        // Penalty for being offline
        if (!peer.online) score -= 5;
        
        // Penalty for high latency
        if (peer.latency) {
            if (peer.latency > 500) score -= 10;
            else if (peer.latency > 200) score -= 5;
        }
        
        // Ensure score is between 0 and 100
        return Math.max(0, Math.min(100, score));
    }

    // Peer Metrics
    handlePeerMetrics(data) {
        const { peer_id, metrics } = data;
        
        const processedMetrics = {
            peer_id,
            latency: metrics.latency,
            bandwidth: metrics.bandwidth,
            packet_loss: metrics.packet_loss,
            uptime: metrics.uptime,
            messages_sent: metrics.messages_sent,
            messages_received: metrics.messages_received,
            bytes_sent: metrics.bytes_sent,
            bytes_received: metrics.bytes_received,
            connection_quality: this.calculateConnectionQuality(metrics),
            last_updated: new Date().toISOString()
        };
        
        this.peerMetrics.set(peer_id, processedMetrics);
        this.updateConnectionQuality(peer_id, processedMetrics.connection_quality);
        
        // Update network stats
        this.updateNetworkStats();
        
        // Notify UI
        this.updatePeerMetricsUI(peer_id, processedMetrics);
    }

    calculateConnectionQuality(metrics) {
        let quality = 100;
        
        // Deduct for latency
        if (metrics.latency > 1000) quality -= 30;
        else if (metrics.latency > 500) quality -= 20;
        else if (metrics.latency > 200) quality -= 10;
        else if (metrics.latency > 100) quality -= 5;
        
        // Deduct for packet loss
        quality -= metrics.packet_loss * 2;
        
        // Deduct for low bandwidth
        if (metrics.bandwidth < 1000000) quality -= 20; // Less than 1 Mbps
        else if (metrics.bandwidth < 5000000) quality -= 10; // Less than 5 Mbps
        
        return Math.max(0, Math.min(100, quality));
    }

    updateConnectionQuality(peerId, quality) {
        this.connectionQuality.set(peerId, {
            quality,
            level: this.getQualityLevel(quality),
            timestamp: new Date().toISOString()
        });
    }

    getQualityLevel(quality) {
        if (quality >= 90) return 'excellent';
        if (quality >= 70) return 'good';
        if (quality >= 50) return 'fair';
        if (quality >= 30) return 'poor';
        return 'very poor';
    }

    // Reputation System
    async updatePeerReputation(peerId, rating, reason = '') {
        this.sendMessage('update_reputation', {
            peer_id: peerId,
            rating,
            reason
        });
        
        // Update local cache
        const currentRep = this.reputationScores.get(peerId) || { score: 0, count: 0 };
        currentRep.score = ((currentRep.score * currentRep.count) + rating) / (currentRep.count + 1);
        currentRep.count++;
        this.reputationScores.set(peerId, currentRep);
    }

    getReputationScore(peerId) {
        const rep = this.reputationScores.get(peerId);
        return rep ? rep.score : 0;
    }

    // Network Monitoring
    initializeNetworkMonitoring() {
        // Monitor WebRTC connections if available
        if (window.RTCPeerConnection) {
            this.monitorWebRTC();
        }
        
        // Monitor network changes
        if ('connection' in navigator) {
            navigator.connection.addEventListener('change', () => {
                this.handleNetworkChange();
            });
        }
        
        // Monitor online/offline status
        window.addEventListener('online', () => this.handleOnlineStatus(true));
        window.addEventListener('offline', () => this.handleOnlineStatus(false));
    }

    monitorWebRTC() {
        // Override RTCPeerConnection to monitor connections
        const OriginalRTCPeerConnection = window.RTCPeerConnection;
        
        window.RTCPeerConnection = function(...args) {
            const pc = new OriginalRTCPeerConnection(...args);
            
            // Monitor connection state
            pc.addEventListener('connectionstatechange', () => {
                if (window.qasaApp?.networkModule) {
                    window.qasaApp.networkModule.handleRTCStateChange(pc);
                }
            });
            
            // Monitor ICE connection state
            pc.addEventListener('iceconnectionstatechange', () => {
                if (window.qasaApp?.networkModule) {
                    window.qasaApp.networkModule.handleICEStateChange(pc);
                }
            });
            
            return pc;
        };
        
        window.RTCPeerConnection.prototype = OriginalRTCPeerConnection.prototype;
    }

    handleRTCStateChange(pc) {
        console.log('RTC connection state:', pc.connectionState);
        
        if (pc.connectionState === 'connected') {
            this.collectRTCStats(pc);
        }
    }

    handleICEStateChange(pc) {
        console.log('ICE connection state:', pc.iceConnectionState);
    }

    async collectRTCStats(pc) {
        try {
            const stats = await pc.getStats();
            const metrics = this.processRTCStats(stats);
            
            // Update peer metrics with RTC stats
            if (metrics.remoteAddress) {
                const peerId = this.findPeerByAddress(metrics.remoteAddress);
                if (peerId) {
                    this.updatePeerMetricsFromRTC(peerId, metrics);
                }
            }
        } catch (error) {
            console.error('Failed to collect RTC stats:', error);
        }
    }

    processRTCStats(stats) {
        const metrics = {
            packetsLost: 0,
            packetsReceived: 0,
            bytesReceived: 0,
            bytesSent: 0,
            currentRoundTripTime: 0,
            availableOutgoingBandwidth: 0,
            remoteAddress: null
        };
        
        stats.forEach(report => {
            if (report.type === 'inbound-rtp') {
                metrics.packetsLost += report.packetsLost || 0;
                metrics.packetsReceived += report.packetsReceived || 0;
                metrics.bytesReceived += report.bytesReceived || 0;
            } else if (report.type === 'outbound-rtp') {
                metrics.bytesSent += report.bytesSent || 0;
            } else if (report.type === 'candidate-pair' && report.state === 'succeeded') {
                metrics.currentRoundTripTime = report.currentRoundTripTime || 0;
                metrics.availableOutgoingBandwidth = report.availableOutgoingBandwidth || 0;
                metrics.remoteAddress = report.remote?.address || null;
            }
        });
        
        return metrics;
    }

    updatePeerMetricsFromRTC(peerId, rtcMetrics) {
        const currentMetrics = this.peerMetrics.get(peerId) || {};
        
        // Update with RTC metrics
        currentMetrics.latency = rtcMetrics.currentRoundTripTime * 1000; // Convert to ms
        currentMetrics.bandwidth = rtcMetrics.availableOutgoingBandwidth;
        currentMetrics.packet_loss = rtcMetrics.packetsLost / 
            (rtcMetrics.packetsReceived + rtcMetrics.packetsLost) * 100;
        
        this.peerMetrics.set(peerId, currentMetrics);
        this.updateConnectionQuality(peerId, this.calculateConnectionQuality(currentMetrics));
    }

    handleNetworkChange() {
        const connection = navigator.connection;
        
        const networkInfo = {
            type: connection.effectiveType,
            downlink: connection.downlink,
            rtt: connection.rtt,
            saveData: connection.saveData
        };
        
        console.log('Network changed:', networkInfo);
        
        // Adjust behavior based on network quality
        if (networkInfo.effectiveType === 'slow-2g' || networkInfo.effectiveType === '2g') {
            this.enableLowBandwidthMode();
        } else {
            this.disableLowBandwidthMode();
        }
        
        // Notify app
        if (window.qasaApp) {
            window.qasaApp.handleNetworkChange(networkInfo);
        }
    }

    handleOnlineStatus(online) {
        console.log('Network status:', online ? 'online' : 'offline');
        
        if (online) {
            // Reconnect WebSocket
            if (window.qasaApp && (!this.ws || this.ws.readyState !== WebSocket.OPEN)) {
                window.qasaApp.initWebSocket();
            }
        }
        
        // Update UI
        if (window.qasaApp?.uiModule) {
            window.qasaApp.uiModule.updateConnectionStatus(online ? 'online' : 'offline');
        }
    }

    // Bandwidth Management
    enableLowBandwidthMode() {
        console.log('Enabling low bandwidth mode');
        
        // Disable auto-loading of images
        this.disableAutoLoadImages = true;
        
        // Reduce quality settings
        if (window.qasaApp) {
            window.qasaApp.settings.autoLoadImages = false;
            window.qasaApp.settings.videoQuality = 'low';
            window.qasaApp.settings.audioQuality = 'low';
        }
        
        // Notify UI
        if (window.qasaApp?.uiModule) {
            window.qasaApp.uiModule.showNotification('Low bandwidth mode enabled', 'info');
        }
    }

    disableLowBandwidthMode() {
        console.log('Disabling low bandwidth mode');
        
        this.disableAutoLoadImages = false;
        
        if (window.qasaApp) {
            window.qasaApp.settings.autoLoadImages = true;
            window.qasaApp.settings.videoQuality = 'high';
            window.qasaApp.settings.audioQuality = 'high';
        }
    }

    // Metrics Collection
    startMetricsCollection() {
        // Collect metrics every 30 seconds
        this.metricsInterval = setInterval(() => {
            this.collectNetworkMetrics();
        }, 30000);
        
        // Initial collection
        this.collectNetworkMetrics();
    }

    async collectNetworkMetrics() {
        // Request metrics from backend
        this.sendMessage('get_network_metrics');
        
        // Collect local metrics
        const localMetrics = {
            timestamp: new Date().toISOString(),
            memory_usage: this.getMemoryUsage(),
            active_connections: this.peers.size,
            websocket_state: this.ws ? this.ws.readyState : null
        };
        
        // Check connection quality for all peers
        for (const [peerId, peer] of this.peers) {
            if (peer.online) {
                this.pingPeer(peerId);
            }
        }
        
        return localMetrics;
    }

    getMemoryUsage() {
        if (performance.memory) {
            return {
                used: performance.memory.usedJSHeapSize,
                total: performance.memory.totalJSHeapSize,
                limit: performance.memory.jsHeapSizeLimit
            };
        }
        return null;
    }

    async pingPeer(peerId) {
        const startTime = Date.now();
        
        this.sendMessage('ping', {
            peer_id: peerId,
            timestamp: startTime
        });
        
        // Store ping start time
        this.pendingPings = this.pendingPings || new Map();
        this.pendingPings.set(peerId, startTime);
    }

    handlePingResponse(data) {
        const { peer_id, timestamp } = data;
        
        if (this.pendingPings && this.pendingPings.has(peer_id)) {
            const startTime = this.pendingPings.get(peer_id);
            const latency = Date.now() - startTime;
            
            this.pendingPings.delete(peer_id);
            
            // Update peer metrics
            const metrics = this.peerMetrics.get(peer_id) || {};
            metrics.latency = latency;
            this.peerMetrics.set(peer_id, metrics);
            
            // Update connection quality
            this.updateConnectionQuality(peer_id, this.calculateConnectionQuality(metrics));
        }
    }

    // Network Statistics
    updateNetworkStats() {
        const allMetrics = Array.from(this.peerMetrics.values());
        
        this.networkStats = {
            totalPeers: this.peers.size,
            onlinePeers: Array.from(this.peers.values()).filter(p => p.online).length,
            avgLatency: this.calculateAverage(allMetrics.map(m => m.latency).filter(l => l > 0)),
            bandwidth: this.calculateTotal(allMetrics.map(m => m.bandwidth || 0)),
            packetLoss: this.calculateAverage(allMetrics.map(m => m.packet_loss || 0))
        };
        
        // Update UI
        this.updateNetworkStatsUI();
    }

    calculateAverage(values) {
        if (values.length === 0) return 0;
        return values.reduce((a, b) => a + b, 0) / values.length;
    }

    calculateTotal(values) {
        return values.reduce((a, b) => a + b, 0);
    }

    getNetworkStats() {
        return this.networkStats;
    }

    // Peer Management
    addPeer(peerId, peerInfo) {
        this.peers.set(peerId, {
            peer_id: peerId,
            ...peerInfo,
            added_at: new Date().toISOString()
        });
        
        // Initialize metrics
        if (!this.peerMetrics.has(peerId)) {
            this.peerMetrics.set(peerId, {
                peer_id: peerId,
                latency: 0,
                bandwidth: 0,
                packet_loss: 0
            });
        }
    }

    removePeer(peerId) {
        this.peers.delete(peerId);
        this.peerMetrics.delete(peerId);
        this.connectionQuality.delete(peerId);
    }

    getPeer(peerId) {
        return this.peers.get(peerId);
    }

    getAllPeers() {
        return Array.from(this.peers.values());
    }

    // Advanced Search
    async searchByProximity(location, radius = 50) {
        return this.discoverPeers({
            type: 'proximity',
            location,
            filters: {
                max_distance: radius
            }
        });
    }

    async searchByCapabilities(requiredCapabilities) {
        return this.discoverPeers({
            type: 'capabilities',
            filters: {
                capabilities: requiredCapabilities
            }
        });
    }

    async searchByReputation(minReputation = 4.0) {
        return this.discoverPeers({
            type: 'reputation',
            filters: {
                min_reputation: minReputation
            }
        });
    }

    // UI Updates
    updateDiscoveryUI(results) {
        if (window.qasaApp?.uiModule) {
            window.qasaApp.uiModule.renderDiscoveryResults(results);
        }
    }

    updatePeerMetricsUI(peerId, metrics) {
        if (window.qasaApp?.uiModule) {
            window.qasaApp.uiModule.updatePeerMetrics(peerId, metrics);
        }
    }

    updateNetworkStatsUI() {
        if (window.qasaApp?.uiModule) {
            window.qasaApp.uiModule.updateNetworkStats(this.networkStats);
        }
    }

    // Utility Functions
    sendMessage(type, data) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({
                type: `network_${type}`,
                data
            }));
        }
    }

    generateRequestId() {
        return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    }

    shortenPeerId(peerId) {
        if (!peerId || peerId.length < 16) return peerId;
        return `${peerId.substr(0, 8)}...${peerId.substr(-8)}`;
    }

    findPeerByAddress(address) {
        // This would need to be implemented based on how peers are mapped to addresses
        // For now, return null
        return null;
    }

    // Cleanup
    destroy() {
        if (this.metricsInterval) {
            clearInterval(this.metricsInterval);
        }
        
        this.peers.clear();
        this.peerMetrics.clear();
        this.discoveryResults.clear();
        this.connectionQuality.clear();
        this.reputationScores.clear();
    }
}