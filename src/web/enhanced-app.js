// Enhanced QaSa App - Main Application Logic

class QaSaApp {
    constructor() {
        this.ws = null;
        this.peerId = null;
        this.currentChat = null;
        this.contacts = new Map();
        this.chats = new Map();
        this.messages = new Map();
        this.typingTimers = new Map();
        this.unreadCounts = new Map();
        this.attachments = [];
        this.voiceRecording = false;
        this.theme = 'dark';
        this.settings = this.loadSettings();
        this.cryptoModule = new QaSaCrypto();
        this.networkModule = new QaSaNetwork();
        this.uiModule = new QaSaUI(this);
        this.notificationSound = new Audio('data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2/LDciUFLIHO8tiJNwgZaLvt559NEAxQp+PwtmMcBjiR1/LMeSwFJHfH8N2QQAoUXrTp66hVFApGn+DyvmwhBSl+zPLZhjEGHW/A7+OZURE');
        
        this.init();
    }

    init() {
        this.initWebSocket();
        this.bindEvents();
        this.loadLocalData();
        this.setupServiceWorker();
        this.requestNotificationPermission();
        this.applyTheme();
    }

    // WebSocket Connection Management
    initWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws`;
        
        this.ws = new WebSocket(wsUrl);
        
        this.ws.onopen = () => this.handleWebSocketOpen();
        this.ws.onclose = () => this.handleWebSocketClose();
        this.ws.onerror = (error) => this.handleWebSocketError(error);
        this.ws.onmessage = (event) => this.handleWebSocketMessage(event);
    }

    handleWebSocketOpen() {
        console.log('WebSocket connection established');
        this.uiModule.updateConnectionStatus('online');
        
        // Request initial data
        this.sendMessage('get_profile');
        this.sendMessage('get_contacts');
        this.sendMessage('get_keys');
        this.sendMessage('get_chats');
        
        // Initialize modules
        this.networkModule.init(this.ws);
        this.cryptoModule.init(this.ws);
    }

    handleWebSocketClose() {
        console.log('WebSocket connection closed');
        this.uiModule.updateConnectionStatus('offline');
        
        // Attempt to reconnect after 3 seconds
        setTimeout(() => this.initWebSocket(), 3000);
    }

    handleWebSocketError(error) {
        console.error('WebSocket error:', error);
        this.uiModule.showNotification('Connection error', 'error');
    }

    handleWebSocketMessage(event) {
        try {
            const message = JSON.parse(event.data);
            this.routeMessage(message);
        } catch (error) {
            console.error('Failed to parse message:', error);
        }
    }

    // Message Routing
    routeMessage(message) {
        switch (message.type) {
            case 'peer_id':
                this.handlePeerIdAssignment(message.data);
                break;
            case 'profile':
                this.handleProfileUpdate(message.data);
                break;
            case 'contacts':
                this.handleContactsUpdate(message.data);
                break;
            case 'chats':
                this.handleChatsUpdate(message.data);
                break;
            case 'message':
                this.handleIncomingMessage(message.data);
                break;
            case 'message_sent':
                this.handleMessageSent(message.data);
                break;
            case 'message_delivered':
                this.handleMessageDelivered(message.data);
                break;
            case 'message_read':
                this.handleMessageRead(message.data);
                break;
            case 'typing':
                this.handleTypingIndicator(message.data);
                break;
            case 'reaction':
                this.handleMessageReaction(message.data);
                break;
            case 'contact_status':
                this.handleContactStatus(message.data);
                break;
            case 'file_shared':
                this.handleFileShared(message.data);
                break;
            case 'file_progress':
                this.handleFileProgress(message.data);
                break;
            case 'keys_update':
                this.cryptoModule.handleKeysUpdate(message.data);
                break;
            case 'encryption_status':
                this.cryptoModule.handleEncryptionStatus(message.data);
                break;
            case 'search_results':
                this.networkModule.handleSearchResults(message.data);
                break;
            case 'peer_metrics':
                this.networkModule.handlePeerMetrics(message.data);
                break;
            case 'error':
                this.handleError(message.data);
                break;
        }
    }

    // Core Handlers
    handlePeerIdAssignment(data) {
        this.peerId = data.peer_id;
        this.uiModule.updatePeerId(this.peerId);
        
        // Generate QR code for easy sharing
        this.generateQRCode();
    }

    handleProfileUpdate(data) {
        this.profile = data;
        this.uiModule.updateProfile(data);
        
        // Store profile locally
        localStorage.setItem('qasa_profile', JSON.stringify(data));
    }

    handleContactsUpdate(data) {
        this.contacts.clear();
        data.contacts.forEach(contact => {
            this.contacts.set(contact.peer_id, contact);
        });
        this.uiModule.renderContacts(this.contacts);
    }

    handleChatsUpdate(data) {
        this.chats.clear();
        data.chats.forEach(chat => {
            this.chats.set(chat.peer_id, chat);
            if (chat.unread_count > 0) {
                this.unreadCounts.set(chat.peer_id, chat.unread_count);
            }
        });
        this.uiModule.renderChats(this.chats);
        this.updateUnreadBadge();
    }

    handleIncomingMessage(data) {
        const { from, content, timestamp, encrypted, signature, attachments, reply_to } = data;
        
        // Decrypt message if encrypted
        let decryptedContent = content;
        if (encrypted) {
            decryptedContent = this.cryptoModule.decryptMessage(content, from);
        }
        
        // Verify signature if present
        if (signature && !this.cryptoModule.verifySignature(content, signature, from)) {
            console.warn('Message signature verification failed');
        }
        
        // Store message
        if (!this.messages.has(from)) {
            this.messages.set(from, []);
        }
        
        const message = {
            id: this.generateMessageId(),
            from,
            content: decryptedContent,
            timestamp,
            encrypted,
            attachments,
            reply_to,
            reactions: [],
            status: 'received'
        };
        
        this.messages.get(from).push(message);
        
        // Update UI
        if (this.currentChat === from) {
            this.uiModule.displayMessage(message, false);
            // Mark as read
            this.sendMessage('mark_read', { peer_id: from, message_id: message.id });
        } else {
            // Update unread count
            const currentUnread = this.unreadCounts.get(from) || 0;
            this.unreadCounts.set(from, currentUnread + 1);
            this.updateUnreadBadge();
            
            // Show notification
            this.showMessageNotification(from, decryptedContent);
        }
        
        // Play notification sound if enabled
        if (this.settings.soundNotifications && this.currentChat !== from) {
            this.notificationSound.play().catch(e => console.log('Could not play sound:', e));
        }
        
        // Update chat list
        this.updateChatInList(from, message);
    }

    handleMessageSent(data) {
        const { message_id, to, timestamp } = data;
        
        // Update message status
        const messages = this.messages.get(to);
        if (messages) {
            const message = messages.find(m => m.id === message_id);
            if (message) {
                message.status = 'sent';
                message.timestamp = timestamp;
                this.uiModule.updateMessageStatus(message_id, 'sent');
            }
        }
    }

    handleMessageDelivered(data) {
        const { message_id, to } = data;
        
        // Update message status
        const messages = this.messages.get(to);
        if (messages) {
            const message = messages.find(m => m.id === message_id);
            if (message) {
                message.status = 'delivered';
                this.uiModule.updateMessageStatus(message_id, 'delivered');
            }
        }
    }

    handleMessageRead(data) {
        const { message_id, to } = data;
        
        // Update message status
        const messages = this.messages.get(to);
        if (messages) {
            const message = messages.find(m => m.id === message_id);
            if (message) {
                message.status = 'read';
                this.uiModule.updateMessageStatus(message_id, 'read');
            }
        }
    }

    handleTypingIndicator(data) {
        const { peer_id, typing } = data;
        
        if (typing) {
            this.uiModule.showTypingIndicator(peer_id);
            
            // Clear existing timer
            if (this.typingTimers.has(peer_id)) {
                clearTimeout(this.typingTimers.get(peer_id));
            }
            
            // Hide after 3 seconds
            const timer = setTimeout(() => {
                this.uiModule.hideTypingIndicator(peer_id);
                this.typingTimers.delete(peer_id);
            }, 3000);
            
            this.typingTimers.set(peer_id, timer);
        } else {
            this.uiModule.hideTypingIndicator(peer_id);
            if (this.typingTimers.has(peer_id)) {
                clearTimeout(this.typingTimers.get(peer_id));
                this.typingTimers.delete(peer_id);
            }
        }
    }

    handleMessageReaction(data) {
        const { message_id, peer_id, reaction, added } = data;
        
        const messages = this.messages.get(peer_id);
        if (messages) {
            const message = messages.find(m => m.id === message_id);
            if (message) {
                if (added) {
                    if (!message.reactions.find(r => r.peer_id === peer_id && r.emoji === reaction)) {
                        message.reactions.push({ peer_id, emoji: reaction });
                    }
                } else {
                    message.reactions = message.reactions.filter(
                        r => !(r.peer_id === peer_id && r.emoji === reaction)
                    );
                }
                
                if (this.currentChat === peer_id) {
                    this.uiModule.updateMessageReactions(message_id, message.reactions);
                }
            }
        }
    }

    handleContactStatus(data) {
        const { peer_id, online, last_seen } = data;
        
        const contact = this.contacts.get(peer_id);
        if (contact) {
            contact.online = online;
            contact.last_seen = last_seen;
            this.uiModule.updateContactStatus(peer_id, online, last_seen);
        }
        
        // Update chat if it's the current one
        if (this.currentChat === peer_id) {
            this.uiModule.updateChatStatus(online, last_seen);
        }
    }

    handleFileShared(data) {
        const { file_id, from, filename, size, encrypted } = data;
        
        // Add to files tab
        this.uiModule.addSharedFile({
            id: file_id,
            from,
            filename,
            size,
            encrypted,
            timestamp: new Date().toISOString()
        });
        
        // Show notification
        const contact = this.contacts.get(from);
        const displayName = contact?.username || this.shortenPeerId(from);
        this.showNotification(`${displayName} shared a file: ${filename}`, 'info');
    }

    handleFileProgress(data) {
        const { file_id, progress, status } = data;
        this.uiModule.updateFileProgress(file_id, progress, status);
    }

    handleError(data) {
        console.error('Server error:', data);
        this.uiModule.showNotification(data.message || 'An error occurred', 'error');
    }

    // Message Sending
    sendChatMessage(content, attachments = []) {
        if (!this.currentChat || (!content.trim() && attachments.length === 0)) return;
        
        const messageId = this.generateMessageId();
        const timestamp = new Date().toISOString();
        
        // Encrypt message if enabled
        let finalContent = content;
        let encrypted = false;
        let signature = null;
        
        if (this.settings.autoEncrypt && this.cryptoModule.hasKeysFor(this.currentChat)) {
            finalContent = this.cryptoModule.encryptMessage(content, this.currentChat);
            encrypted = true;
            signature = this.cryptoModule.signMessage(content);
        }
        
        const message = {
            id: messageId,
            to: this.currentChat,
            content: finalContent,
            original_content: content,
            timestamp,
            encrypted,
            signature,
            attachments: attachments.map(a => ({
                id: a.id,
                filename: a.name,
                size: a.size,
                type: a.type
            })),
            status: 'sending'
        };
        
        // Add to local messages
        if (!this.messages.has(this.currentChat)) {
            this.messages.set(this.currentChat, []);
        }
        this.messages.get(this.currentChat).push(message);
        
        // Display in UI
        this.uiModule.displayMessage(message, true);
        
        // Send via WebSocket
        this.sendMessage('message', {
            id: messageId,
            to: this.currentChat,
            content: finalContent,
            encrypted,
            signature,
            attachments: message.attachments
        });
        
        // Upload attachments if any
        attachments.forEach(attachment => {
            this.uploadFile(attachment, messageId);
        });
        
        // Update chat list
        this.updateChatInList(this.currentChat, message);
    }

    // File Handling
    async uploadFile(file, messageId) {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('message_id', messageId);
        formData.append('peer_id', this.currentChat);
        
        // Encrypt file if enabled
        if (this.settings.autoEncrypt) {
            const encryptedFile = await this.cryptoModule.encryptFile(file);
            formData.append('encrypted', 'true');
            formData.append('file', encryptedFile, file.name);
        }
        
        try {
            const response = await fetch('/api/upload', {
                method: 'POST',
                body: formData
            });
            
            if (!response.ok) throw new Error('Upload failed');
            
            const result = await response.json();
            this.sendMessage('file_uploaded', {
                message_id: messageId,
                file_id: result.file_id
            });
        } catch (error) {
            console.error('File upload failed:', error);
            this.uiModule.showNotification('File upload failed', 'error');
        }
    }

    async downloadFile(fileId, filename, encrypted = false) {
        try {
            const response = await fetch(`/api/download/${fileId}`);
            if (!response.ok) throw new Error('Download failed');
            
            let blob = await response.blob();
            
            // Decrypt if needed
            if (encrypted) {
                blob = await this.cryptoModule.decryptFile(blob);
            }
            
            // Create download link
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            a.click();
            URL.revokeObjectURL(url);
            
            this.uiModule.showNotification('File downloaded successfully', 'success');
        } catch (error) {
            console.error('File download failed:', error);
            this.uiModule.showNotification('File download failed', 'error');
        }
    }

    // Typing Indicators
    sendTypingIndicator(typing = true) {
        if (!this.currentChat) return;
        
        this.sendMessage('typing', {
            peer_id: this.currentChat,
            typing
        });
    }

    // Reactions
    toggleReaction(messageId, emoji) {
        const messages = this.messages.get(this.currentChat);
        if (!messages) return;
        
        const message = messages.find(m => m.id === messageId);
        if (!message) return;
        
        const existingReaction = message.reactions.find(
            r => r.peer_id === this.peerId && r.emoji === emoji
        );
        
        this.sendMessage('reaction', {
            message_id: messageId,
            peer_id: this.currentChat,
            reaction: emoji,
            added: !existingReaction
        });
    }

    // Chat Management
    selectChat(peerId) {
        this.currentChat = peerId;
        
        // Clear unread count
        if (this.unreadCounts.has(peerId)) {
            this.unreadCounts.delete(peerId);
            this.updateUnreadBadge();
        }
        
        // Load messages
        const messages = this.messages.get(peerId) || [];
        this.uiModule.displayChat(peerId, messages);
        
        // Mark messages as read
        const unreadMessages = messages.filter(m => m.status === 'received');
        unreadMessages.forEach(m => {
            this.sendMessage('mark_read', {
                peer_id: peerId,
                message_id: m.id
            });
        });
        
        // Update UI
        this.uiModule.setActiveChat(peerId);
        
        // Load encryption status
        this.cryptoModule.checkEncryptionStatus(peerId);
    }

    updateChatInList(peerId, lastMessage) {
        const chat = this.chats.get(peerId) || {
            peer_id: peerId,
            last_message: null,
            timestamp: new Date().toISOString(),
            unread_count: 0
        };
        
        chat.last_message = {
            content: lastMessage.content,
            timestamp: lastMessage.timestamp,
            from: lastMessage.from || this.peerId
        };
        
        this.chats.set(peerId, chat);
        this.uiModule.updateChatInList(peerId, chat);
    }

    // Contact Management
    async addContact(peerId) {
        this.sendMessage('add_contact', { peer_id: peerId });
    }

    async removeContact(peerId) {
        if (confirm('Are you sure you want to remove this contact?')) {
            this.sendMessage('remove_contact', { peer_id: peerId });
        }
    }

    async blockContact(peerId) {
        if (confirm('Are you sure you want to block this contact?')) {
            this.sendMessage('block_contact', { peer_id: peerId });
        }
    }

    // Search
    async searchPeers(query, filters = {}) {
        this.sendMessage('search', {
            query,
            filters,
            limit: 50
        });
    }

    // Settings
    saveSettings() {
        const settings = this.uiModule.getSettingsFromUI();
        this.settings = { ...this.settings, ...settings };
        
        // Save locally
        localStorage.setItem('qasa_settings', JSON.stringify(this.settings));
        
        // Send to server
        this.sendMessage('update_settings', settings);
        
        // Apply changes
        this.applySettings(settings);
        
        this.uiModule.showNotification('Settings saved successfully', 'success');
    }

    applySettings(settings) {
        // Apply theme
        if (settings.theme && settings.theme !== this.theme) {
            this.theme = settings.theme;
            this.applyTheme();
        }
        
        // Apply other settings
        if (settings.fontSize) {
            document.documentElement.style.setProperty('--font-size-base', 
                settings.fontSize === 'small' ? '13px' : 
                settings.fontSize === 'large' ? '16px' : '14px'
            );
        }
        
        // Update crypto settings
        if (settings.quantumOnly !== undefined) {
            this.cryptoModule.setQuantumOnly(settings.quantumOnly);
        }
    }

    loadSettings() {
        const saved = localStorage.getItem('qasa_settings');
        return saved ? JSON.parse(saved) : {
            theme: 'dark',
            fontSize: 'medium',
            desktopNotifications: true,
            soundNotifications: true,
            readReceipts: true,
            typingIndicators: true,
            lastSeen: true,
            autoEncrypt: true,
            quantumOnly: false,
            keyRotation: 'weekly',
            notificationPreview: 'full'
        };
    }

    // Theme Management
    applyTheme() {
        if (this.theme === 'light') {
            document.body.classList.add('light-theme');
        } else {
            document.body.classList.remove('light-theme');
        }
    }

    toggleTheme() {
        this.theme = this.theme === 'dark' ? 'light' : 'dark';
        this.applyTheme();
        this.settings.theme = this.theme;
        this.saveSettings();
    }

    // Notifications
    requestNotificationPermission() {
        if ('Notification' in window && Notification.permission === 'default') {
            Notification.requestPermission();
        }
    }

    showMessageNotification(from, content) {
        if (!this.settings.desktopNotifications) return;
        if (document.hasFocus() && this.currentChat === from) return;
        
        const contact = this.contacts.get(from);
        const displayName = contact?.username || this.shortenPeerId(from);
        
        let notificationBody = content;
        if (this.settings.notificationPreview === 'sender') {
            notificationBody = 'New message';
        } else if (this.settings.notificationPreview === 'none') {
            notificationBody = '';
        }
        
        if ('Notification' in window && Notification.permission === 'granted') {
            const notification = new Notification(`QaSa - ${displayName}`, {
                body: notificationBody,
                icon: '/favicon.svg',
                badge: '/favicon.svg',
                tag: from,
                renotify: true
            });
            
            notification.onclick = () => {
                window.focus();
                this.selectChat(from);
                notification.close();
            };
        }
    }

    showNotification(message, type = 'info') {
        this.uiModule.showNotification(message, type);
    }

    // Utility Functions
    sendMessage(type, data = {}) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({ type, data }));
        }
    }

    generateMessageId() {
        return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    }

    generateQRCode() {
        const data = {
            peer_id: this.peerId,
            addresses: this.profile?.addresses || []
        };
        
        QRCode.toCanvas(
            document.createElement('canvas'),
            JSON.stringify(data),
            {
                width: 256,
                margin: 2,
                color: {
                    dark: '#667eea',
                    light: '#ffffff'
                }
            },
            (error, canvas) => {
                if (error) {
                    console.error('QR code generation failed:', error);
                    return;
                }
                this.uiModule.displayQRCode(canvas);
            }
        );
    }

    shortenPeerId(peerId) {
        if (!peerId || peerId.length < 16) return peerId;
        return `${peerId.substr(0, 8)}...${peerId.substr(-8)}`;
    }

    updateUnreadBadge() {
        const totalUnread = Array.from(this.unreadCounts.values()).reduce((a, b) => a + b, 0);
        this.uiModule.updateUnreadBadge(totalUnread);
        
        // Update favicon badge
        this.updateFaviconBadge(totalUnread);
    }

    updateFaviconBadge(count) {
        const favicon = document.querySelector('link[rel="icon"]');
        if (!favicon) return;
        
        const canvas = document.createElement('canvas');
        canvas.width = 32;
        canvas.height = 32;
        const ctx = canvas.getContext('2d');
        
        // Draw original favicon
        const img = new Image();
        img.onload = () => {
            ctx.drawImage(img, 0, 0, 32, 32);
            
            if (count > 0) {
                // Draw badge
                ctx.fillStyle = '#f56565';
                ctx.beginPath();
                ctx.arc(24, 8, 8, 0, 2 * Math.PI);
                ctx.fill();
                
                // Draw count
                ctx.fillStyle = 'white';
                ctx.font = 'bold 10px Arial';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText(count > 99 ? '99+' : count.toString(), 24, 8);
            }
            
            favicon.href = canvas.toDataURL('image/png');
        };
        img.src = '/favicon.svg';
    }

    // Service Worker
    setupServiceWorker() {
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('/sw.js').then(registration => {
                console.log('Service Worker registered:', registration);
            }).catch(error => {
                console.error('Service Worker registration failed:', error);
            });
        }
    }

    // Local Data Management
    loadLocalData() {
        // Load cached data for offline support
        const cachedProfile = localStorage.getItem('qasa_profile');
        if (cachedProfile) {
            this.profile = JSON.parse(cachedProfile);
            this.uiModule.updateProfile(this.profile);
        }
        
        const cachedContacts = localStorage.getItem('qasa_contacts');
        if (cachedContacts) {
            const contacts = JSON.parse(cachedContacts);
            contacts.forEach(contact => {
                this.contacts.set(contact.peer_id, contact);
            });
            this.uiModule.renderContacts(this.contacts);
        }
    }

    // Event Binding
    bindEvents() {
        // Message input
        const messageInput = document.getElementById('message-text');
        let typingTimer;
        
        messageInput.addEventListener('input', () => {
            // Auto-resize textarea
            messageInput.style.height = 'auto';
            messageInput.style.height = messageInput.scrollHeight + 'px';
            
            // Send typing indicator
            if (this.settings.typingIndicators) {
                this.sendTypingIndicator(true);
                clearTimeout(typingTimer);
                typingTimer = setTimeout(() => {
                    this.sendTypingIndicator(false);
                }, 2000);
            }
        });
        
        messageInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendChatMessage(messageInput.value, this.attachments);
                messageInput.value = '';
                messageInput.style.height = 'auto';
                this.attachments = [];
                this.uiModule.clearAttachments();
            }
        });
        
        // Send button
        document.getElementById('send-btn').addEventListener('click', () => {
            const messageInput = document.getElementById('message-text');
            this.sendChatMessage(messageInput.value, this.attachments);
            messageInput.value = '';
            messageInput.style.height = 'auto';
            this.attachments = [];
            this.uiModule.clearAttachments();
        });
        
        // File attachment
        document.getElementById('attach-btn').addEventListener('click', () => {
            document.getElementById('file-input').click();
        });
        
        document.getElementById('file-input').addEventListener('change', (e) => {
            this.handleFileSelection(e.target.files);
        });
        
        // Voice messages
        document.getElementById('voice-message-btn').addEventListener('click', () => {
            this.toggleVoiceRecording();
        });
        
        // Settings
        document.getElementById('save-settings').addEventListener('click', () => {
            this.saveSettings();
        });
        
        // Theme toggle
        document.getElementById('theme-toggle').addEventListener('click', () => {
            this.toggleTheme();
        });
        
        // Search
        document.getElementById('discovery-search-btn').addEventListener('click', () => {
            const query = document.getElementById('discovery-search').value;
            const type = document.getElementById('search-type').value;
            const filters = this.uiModule.getSearchFilters();
            
            this.searchPeers(query, { type, ...filters });
        });
        
        // Start chat button
        document.getElementById('start-chat-btn').addEventListener('click', () => {
            document.querySelector('[data-tab="discovery"]').click();
        });
        
        // Mobile responsiveness
        if (window.innerWidth <= 768) {
            document.getElementById('back-to-chats').addEventListener('click', () => {
                this.uiModule.showSidebar();
            });
        }
        
        // Window focus/blur for read receipts
        window.addEventListener('focus', () => {
            if (this.currentChat) {
                const messages = this.messages.get(this.currentChat) || [];
                const unreadMessages = messages.filter(m => m.status === 'received');
                unreadMessages.forEach(m => {
                    this.sendMessage('mark_read', {
                        peer_id: this.currentChat,
                        message_id: m.id
                    });
                });
            }
        });
        
        // Context menu
        document.addEventListener('contextmenu', (e) => {
            if (e.target.closest('.message')) {
                e.preventDefault();
                this.uiModule.showContextMenu(e, e.target.closest('.message'));
            }
        });
        
        // Handle paste for image upload
        document.addEventListener('paste', (e) => {
            const items = e.clipboardData.items;
            for (let item of items) {
                if (item.type.indexOf('image') !== -1) {
                    const blob = item.getAsFile();
                    this.handleFileSelection([blob]);
                }
            }
        });
    }

    // File Handling
    handleFileSelection(files) {
        Array.from(files).forEach(file => {
            if (file.size > 100 * 1024 * 1024) { // 100MB limit
                this.uiModule.showNotification('File too large. Maximum size is 100MB', 'error');
                return;
            }
            
            const attachment = {
                id: this.generateMessageId(),
                file: file,
                name: file.name,
                size: file.size,
                type: file.type
            };
            
            this.attachments.push(attachment);
            this.uiModule.addAttachmentPreview(attachment);
        });
    }

    // Voice Recording
    async toggleVoiceRecording() {
        if (!this.voiceRecording) {
            try {
                const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
                this.mediaRecorder = new MediaRecorder(stream);
                const chunks = [];
                
                this.mediaRecorder.ondataavailable = (e) => chunks.push(e.data);
                this.mediaRecorder.onstop = () => {
                    const blob = new Blob(chunks, { type: 'audio/webm' });
                    const file = new File([blob], `voice_${Date.now()}.webm`, { type: 'audio/webm' });
                    this.handleFileSelection([file]);
                    
                    stream.getTracks().forEach(track => track.stop());
                };
                
                this.mediaRecorder.start();
                this.voiceRecording = true;
                this.uiModule.updateVoiceRecordingUI(true);
            } catch (error) {
                console.error('Failed to start recording:', error);
                this.uiModule.showNotification('Failed to access microphone', 'error');
            }
        } else {
            this.mediaRecorder.stop();
            this.voiceRecording = false;
            this.uiModule.updateVoiceRecordingUI(false);
        }
    }
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.qasaApp = new QaSaApp();
});