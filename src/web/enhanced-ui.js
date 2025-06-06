// Enhanced QaSa UI Module - User Interface Management

class QaSaUI {
    constructor(app) {
        this.app = app;
        this.activeModals = new Set();
        this.notifications = [];
        this.emojiPicker = null;
        this.contextMenu = null;
        this.activeTab = 'chats';
        this.isMobile = window.innerWidth <= 768;
        
        this.init();
    }

    init() {
        this.bindUIEvents();
        this.initializeModals();
        this.initializeEmojiPicker();
        this.initializeContextMenu();
        this.setupResponsiveness();
        this.initializeAnimations();
    }

    // Connection Status
    updateConnectionStatus(status) {
        const statusElement = document.getElementById('user-status');
        const statusText = document.getElementById('status-text');
        const connectionStatus = document.getElementById('connection-status');
        
        statusElement.className = `status-indicator ${status}`;
        statusText.textContent = status.charAt(0).toUpperCase() + status.slice(1);
        
        if (connectionStatus) {
            connectionStatus.textContent = status.charAt(0).toUpperCase() + status.slice(1);
            connectionStatus.style.color = status === 'online' ? 'var(--success-color)' : 'var(--danger-color)';
        }
    }

    // Profile Management
    updatePeerId(peerId) {
        document.getElementById('peer-id').textContent = this.app.shortenPeerId(peerId);
    }

    updateProfile(profile) {
        if (profile.username) {
            document.getElementById('user-name').textContent = profile.username;
        }
        
        // Update profile picture if available
        if (profile.avatar) {
            const profilePic = document.getElementById('profile-pic');
            profilePic.innerHTML = `<img src="${profile.avatar}" alt="Profile">`;
        }
    }

    displayQRCode(canvas) {
        const qrDisplay = document.getElementById('qr-code-display');
        qrDisplay.innerHTML = '';
        qrDisplay.appendChild(canvas);
    }

    // Chat Management
    renderChats(chats) {
        const chatList = document.getElementById('chat-list');
        chatList.innerHTML = '';
        
        // Sort chats by last message timestamp
        const sortedChats = Array.from(chats.values()).sort((a, b) => {
            const timeA = a.last_message?.timestamp || a.timestamp;
            const timeB = b.last_message?.timestamp || b.timestamp;
            return new Date(timeB) - new Date(timeA);
        });
        
        sortedChats.forEach(chat => {
            const contact = this.app.contacts.get(chat.peer_id);
            const displayName = contact?.username || this.app.shortenPeerId(chat.peer_id);
            const lastMessage = chat.last_message;
            const unreadCount = this.app.unreadCounts.get(chat.peer_id) || 0;
            
            const chatElement = document.createElement('div');
            chatElement.className = 'chat-item';
            chatElement.dataset.peerId = chat.peer_id;
            
            if (this.app.currentChat === chat.peer_id) {
                chatElement.classList.add('active');
            }
            
            chatElement.innerHTML = `
                <div class="chat-avatar">
                    ${this.getAvatarHTML(displayName, contact?.avatar)}
                </div>
                <div class="chat-info">
                    <div class="chat-name">
                        ${displayName}
                        ${contact?.authenticated ? '<i class="fas fa-check-circle verified"></i>' : ''}
                    </div>
                    <div class="chat-last-message">
                        ${lastMessage ? this.formatLastMessage(lastMessage) : 'No messages yet'}
                    </div>
                </div>
                <div class="chat-meta">
                    <div class="chat-time">${this.formatTime(lastMessage?.timestamp || chat.timestamp)}</div>
                    ${unreadCount > 0 ? `<div class="unread-count">${unreadCount}</div>` : ''}
                </div>
            `;
            
            chatElement.addEventListener('click', () => {
                this.app.selectChat(chat.peer_id);
            });
            
            chatList.appendChild(chatElement);
        });
    }

    formatLastMessage(message) {
        const maxLength = 50;
        let content = message.content;
        
        // Handle different message types
        if (message.attachments && message.attachments.length > 0) {
            const fileCount = message.attachments.length;
            content = `📎 ${fileCount} file${fileCount > 1 ? 's' : ''}`;
        } else if (message.type === 'voice') {
            content = '🎤 Voice message';
        }
        
        // Add sender prefix if it's not from the current user
        if (message.from !== this.app.peerId) {
            content = content;
        } else {
            content = `You: ${content}`;
        }
        
        // Truncate if too long
        if (content.length > maxLength) {
            content = content.substring(0, maxLength) + '...';
        }
        
        return content;
    }

    updateChatInList(peerId, chat) {
        // Remove existing chat item
        const existingItem = document.querySelector(`.chat-item[data-peer-id="${peerId}"]`);
        if (existingItem) {
            existingItem.remove();
        }
        
        // Re-render all chats to maintain sort order
        this.renderChats(this.app.chats);
    }

    // Contact Management
    renderContacts(contacts) {
        const contactList = document.getElementById('contact-list');
        contactList.innerHTML = '';
        
        // Sort contacts alphabetically
        const sortedContacts = Array.from(contacts.values()).sort((a, b) => {
            const nameA = a.username || a.peer_id;
            const nameB = b.username || b.peer_id;
            return nameA.localeCompare(nameB);
        });
        
        sortedContacts.forEach(contact => {
            const contactElement = document.createElement('div');
            contactElement.className = 'contact-item';
            contactElement.dataset.peerId = contact.peer_id;
            
            const statusClass = contact.online ? 'online' : 'offline';
            const displayName = contact.username || this.app.shortenPeerId(contact.peer_id);
            
            contactElement.innerHTML = `
                <div class="contact-avatar">
                    ${this.getAvatarHTML(displayName, contact.avatar)}
                </div>
                <div class="contact-info">
                    <div class="contact-name">
                        ${displayName}
                        ${contact.authenticated ? '<i class="fas fa-check-circle verified"></i>' : ''}
                        ${contact.quantum_safe ? '<i class="fas fa-atom quantum"></i>' : ''}
                    </div>
                    <span class="status-indicator ${statusClass}"></span>
                </div>
                <div class="contact-actions">
                    <button class="icon-button small" onclick="window.qasaApp.selectChat('${contact.peer_id}')" title="Message">
                        <i class="fas fa-comment"></i>
                    </button>
                    <button class="icon-button small" onclick="window.qasaApp.cryptoModule.initiateKeyExchange('${contact.peer_id}')" title="Key Exchange">
                        <i class="fas fa-key"></i>
                    </button>
                </div>
            `;
            
            contactList.appendChild(contactElement);
        });
    }

    updateContactStatus(peerId, online, lastSeen) {
        const contactElement = document.querySelector(`.contact-item[data-peer-id="${peerId}"]`);
        if (contactElement) {
            const statusIndicator = contactElement.querySelector('.status-indicator');
            statusIndicator.className = `status-indicator ${online ? 'online' : 'offline'}`;
        }
        
        // Update in chat list too
        const chatElement = document.querySelector(`.chat-item[data-peer-id="${peerId}"]`);
        if (chatElement) {
            // Could add online indicator to chat items
        }
    }

    // Discovery Results
    renderDiscoveryResults(results) {
        const resultsContainer = document.getElementById('discovery-results');
        const loadingIndicator = document.getElementById('discovery-loading');
        
        loadingIndicator.style.display = 'none';
        resultsContainer.innerHTML = '';
        
        if (results.length === 0) {
            resultsContainer.innerHTML = '<p class="no-results">No peers found matching your criteria</p>';
            return;
        }
        
        results.forEach(peer => {
            const peerElement = document.createElement('div');
            peerElement.className = 'discovery-peer';
            
            peerElement.innerHTML = `
                <div class="peer-info">
                    <div class="peer-avatar">
                        ${this.getAvatarHTML(peer.display_name, peer.avatar)}
                    </div>
                    <div class="peer-details">
                        <h4>${peer.display_name}</h4>
                        <div class="peer-meta">
                            ${peer.online ? '<span class="online-badge"><i class="fas fa-circle"></i> Online</span>' : '<span class="offline-badge"><i class="far fa-circle"></i> Offline</span>'}
                            ${peer.authenticated ? '<span class="verified-badge"><i class="fas fa-check"></i> Verified</span>' : ''}
                            ${peer.quantum_safe ? '<span class="quantum-badge"><i class="fas fa-atom"></i> Quantum-Safe</span>' : ''}
                            <span class="reputation-badge"><i class="fas fa-star"></i> ${peer.reputation.toFixed(1)}</span>
                            ${peer.latency ? `<span class="latency-badge"><i class="fas fa-signal"></i> ${peer.latency}ms</span>` : ''}
                        </div>
                        ${peer.location ? `<div class="peer-location"><i class="fas fa-map-marker-alt"></i> ${peer.location}</div>` : ''}
                    </div>
                </div>
                <div class="peer-actions">
                    <button class="action-button small" onclick="window.qasaApp.addContact('${peer.peer_id}')">
                        <i class="fas fa-user-plus"></i> Add
                    </button>
                    <button class="action-button small primary" onclick="window.qasaApp.selectChat('${peer.peer_id}')">
                        <i class="fas fa-comment"></i> Message
                    </button>
                </div>
            `;
            
            resultsContainer.appendChild(peerElement);
        });
    }

    // Chat Display
    displayChat(peerId, messages) {
        const chatMessages = document.getElementById('chat-messages');
        const messageInputContainer = document.getElementById('message-input-container');
        const welcomeScreen = document.getElementById('welcome-screen');
        const encryptionBar = document.getElementById('encryption-status-bar');
        
        // Hide welcome screen
        if (welcomeScreen) {
            welcomeScreen.style.display = 'none';
        }
        
        // Show message input
        messageInputContainer.style.display = 'flex';
        
        // Update chat header
        this.updateChatHeader(peerId);
        
        // Clear messages
        chatMessages.innerHTML = '';
        
        // Display encryption status
        const encryptionStatus = this.app.cryptoModule.encryptionStatus.get(peerId);
        if (encryptionStatus && encryptionStatus.quantum_safe) {
            encryptionBar.style.display = 'flex';
            encryptionBar.querySelector('span').textContent = 'Messages are end-to-end encrypted with quantum-safe algorithms';
        } else if (encryptionStatus && encryptionStatus.available) {
            encryptionBar.style.display = 'flex';
            encryptionBar.querySelector('span').textContent = 'Messages are end-to-end encrypted';
        } else {
            encryptionBar.style.display = 'none';
        }
        
        // Group messages by date
        const messagesByDate = this.groupMessagesByDate(messages);
        
        // Display messages
        messagesByDate.forEach(([date, dayMessages]) => {
            // Add date separator
            const dateSeparator = document.createElement('div');
            dateSeparator.className = 'date-separator';
            dateSeparator.textContent = this.formatDateSeparator(date);
            chatMessages.appendChild(dateSeparator);
            
            // Display messages for this date
            dayMessages.forEach(message => {
                this.displayMessage(message, message.from === this.app.peerId || message.to === peerId);
            });
        });
        
        // Scroll to bottom
        chatMessages.scrollTop = chatMessages.scrollHeight;
        
        // Focus message input
        document.getElementById('message-text').focus();
    }

    updateChatHeader(peerId) {
        const contact = this.app.contacts.get(peerId);
        const displayName = contact?.username || this.app.shortenPeerId(peerId);
        
        document.getElementById('current-chat').textContent = displayName;
        
        // Update status
        const peerStatus = document.getElementById('peer-status');
        if (contact?.online) {
            peerStatus.textContent = 'Online';
            peerStatus.style.color = 'var(--success-color)';
        } else if (contact?.last_seen) {
            peerStatus.textContent = `Last seen ${this.formatLastSeen(contact.last_seen)}`;
            peerStatus.style.color = 'var(--text-secondary)';
        } else {
            peerStatus.textContent = 'Offline';
            peerStatus.style.color = 'var(--text-tertiary)';
        }
    }

    updateChatStatus(online, lastSeen) {
        const peerStatus = document.getElementById('peer-status');
        if (online) {
            peerStatus.textContent = 'Online';
            peerStatus.style.color = 'var(--success-color)';
        } else if (lastSeen) {
            peerStatus.textContent = `Last seen ${this.formatLastSeen(lastSeen)}`;
            peerStatus.style.color = 'var(--text-secondary)';
        } else {
            peerStatus.textContent = 'Offline';
            peerStatus.style.color = 'var(--text-tertiary)';
        }
    }

    displayMessage(message, sent) {
        const chatMessages = document.getElementById('chat-messages');
        
        const messageElement = document.createElement('div');
        messageElement.className = `message ${sent ? 'sent' : 'received'}`;
        messageElement.dataset.messageId = message.id;
        
        const contact = sent ? null : this.app.contacts.get(message.from);
        const displayName = contact?.username || this.app.shortenPeerId(message.from);
        
        // Build message content
        let messageContent = `
            ${!sent ? `<div class="message-avatar">${this.getAvatarHTML(displayName, contact?.avatar, true)}</div>` : ''}
            <div class="message-content">
        `;
        
        // Add reply reference if replying to another message
        if (message.reply_to) {
            messageContent += `
                <div class="message-reply">
                    <i class="fas fa-reply"></i>
                    <span>Replying to message</span>
                </div>
            `;
        }
        
        // Add message text
        messageContent += `<div class="message-text">${this.escapeHtml(message.original_content || message.content)}</div>`;
        
        // Add attachments
        if (message.attachments && message.attachments.length > 0) {
            messageContent += '<div class="message-attachments">';
            message.attachments.forEach(attachment => {
                messageContent += this.renderAttachment(attachment);
            });
            messageContent += '</div>';
        }
        
        // Add message footer
        messageContent += `
                <div class="message-footer">
                    <span class="message-time">${this.formatTime(message.timestamp)}</span>
                    ${sent ? this.getMessageStatusIcon(message.status) : ''}
                    ${message.encrypted ? '<i class="fas fa-lock encrypted-icon" title="Encrypted"></i>' : ''}
                </div>
        `;
        
        // Add reactions
        if (message.reactions && message.reactions.length > 0) {
            messageContent += '<div class="message-reactions">';
            const reactionCounts = this.countReactions(message.reactions);
            Object.entries(reactionCounts).forEach(([emoji, count]) => {
                const hasReacted = message.reactions.some(r => r.peer_id === this.app.peerId && r.emoji === emoji);
                messageContent += `
                    <span class="reaction ${hasReacted ? 'reacted' : ''}" 
                          onclick="window.qasaApp.toggleReaction('${message.id}', '${emoji}')">
                        ${emoji} ${count}
                    </span>
                `;
            });
            messageContent += '</div>';
        }
        
        messageContent += '</div>';
        
        messageElement.innerHTML = messageContent;
        chatMessages.appendChild(messageElement);
        
        // Add animation
        messageElement.style.opacity = '0';
        requestAnimationFrame(() => {
            messageElement.style.opacity = '1';
        });
    }

    renderAttachment(attachment) {
        const fileIcon = this.getFileIcon(attachment.type);
        const fileSize = this.formatFileSize(attachment.size);
        
        return `
            <div class="attachment-item" onclick="window.qasaApp.downloadFile('${attachment.id}', '${attachment.filename}', ${attachment.encrypted || false})">
                <i class="${fileIcon}"></i>
                <div class="attachment-info">
                    <div class="attachment-name">${attachment.filename}</div>
                    <div class="attachment-size">${fileSize}</div>
                </div>
                <i class="fas fa-download"></i>
            </div>
        `;
    }

    updateMessageStatus(messageId, status) {
        const messageElement = document.querySelector(`[data-message-id="${messageId}"]`);
        if (messageElement) {
            const statusIcon = messageElement.querySelector('.message-status');
            if (statusIcon) {
                statusIcon.innerHTML = this.getMessageStatusIcon(status);
            }
        }
    }

    getMessageStatusIcon(status) {
        const icons = {
            sending: '<i class="far fa-clock"></i>',
            sent: '<i class="fas fa-check"></i>',
            delivered: '<i class="fas fa-check-double"></i>',
            read: '<i class="fas fa-check-double read"></i>'
        };
        return `<span class="message-status">${icons[status] || ''}</span>`;
    }

    updateMessageReactions(messageId, reactions) {
        const messageElement = document.querySelector(`[data-message-id="${messageId}"]`);
        if (!messageElement) return;
        
        let reactionsContainer = messageElement.querySelector('.message-reactions');
        if (!reactionsContainer && reactions.length > 0) {
            reactionsContainer = document.createElement('div');
            reactionsContainer.className = 'message-reactions';
            messageElement.querySelector('.message-content').appendChild(reactionsContainer);
        }
        
        if (reactions.length === 0 && reactionsContainer) {
            reactionsContainer.remove();
            return;
        }
        
        if (reactionsContainer) {
            const reactionCounts = this.countReactions(reactions);
            reactionsContainer.innerHTML = '';
            
            Object.entries(reactionCounts).forEach(([emoji, count]) => {
                const hasReacted = reactions.some(r => r.peer_id === this.app.peerId && r.emoji === emoji);
                reactionsContainer.innerHTML += `
                    <span class="reaction ${hasReacted ? 'reacted' : ''}" 
                          onclick="window.qasaApp.toggleReaction('${messageId}', '${emoji}')">
                        ${emoji} ${count}
                    </span>
                `;
            });
        }
    }

    countReactions(reactions) {
        const counts = {};
        reactions.forEach(reaction => {
            counts[reaction.emoji] = (counts[reaction.emoji] || 0) + 1;
        });
        return counts;
    }

    // Typing Indicators
    showTypingIndicator(peerId) {
        if (this.app.currentChat === peerId) {
            const typingIndicator = document.getElementById('typing-indicator');
            typingIndicator.style.display = 'inline-flex';
        }
        
        // Also show in chat list
        const chatElement = document.querySelector(`.chat-item[data-peer-id="${peerId}"]`);
        if (chatElement) {
            const lastMessage = chatElement.querySelector('.chat-last-message');
            if (lastMessage) {
                lastMessage.dataset.originalContent = lastMessage.textContent;
                lastMessage.innerHTML = '<i class="fas fa-ellipsis-h typing"></i> typing...';
            }
        }
    }

    hideTypingIndicator(peerId) {
        if (this.app.currentChat === peerId) {
            const typingIndicator = document.getElementById('typing-indicator');
            typingIndicator.style.display = 'none';
        }
        
        // Restore in chat list
        const chatElement = document.querySelector(`.chat-item[data-peer-id="${peerId}"]`);
        if (chatElement) {
            const lastMessage = chatElement.querySelector('.chat-last-message');
            if (lastMessage && lastMessage.dataset.originalContent) {
                lastMessage.textContent = lastMessage.dataset.originalContent;
                delete lastMessage.dataset.originalContent;
            }
        }
    }

    // File Handling
    addAttachmentPreview(attachment) {
        const attachmentsContainer = document.getElementById('message-attachments');
        attachmentsContainer.style.display = 'flex';
        
        const preview = document.createElement('div');
        preview.className = 'attachment-preview';
        preview.dataset.attachmentId = attachment.id;
        
        if (attachment.type.startsWith('image/')) {
            // Show image preview
            const reader = new FileReader();
            reader.onload = (e) => {
                preview.innerHTML = `
                    <img src="${e.target.result}" alt="${attachment.name}">
                    <button class="attachment-remove" onclick="window.qasaApp.removeAttachment('${attachment.id}')">
                        <i class="fas fa-times"></i>
                    </button>
                `;
            };
            reader.readAsDataURL(attachment.file);
        } else {
            // Show file icon
            const fileIcon = this.getFileIcon(attachment.type);
            preview.innerHTML = `
                <i class="${fileIcon}"></i>
                <div class="attachment-name">${attachment.name}</div>
                <button class="attachment-remove" onclick="window.qasaApp.removeAttachment('${attachment.id}')">
                    <i class="fas fa-times"></i>
                </button>
            `;
        }
        
        attachmentsContainer.appendChild(preview);
    }

    clearAttachments() {
        const attachmentsContainer = document.getElementById('message-attachments');
        attachmentsContainer.innerHTML = '';
        attachmentsContainer.style.display = 'none';
    }

    addSharedFile(file) {
        const fileList = document.getElementById('file-list');
        
        const fileCard = document.createElement('div');
        fileCard.className = 'file-card';
        fileCard.dataset.fileId = file.id;
        
        const fileIcon = this.getFileIcon(file.type || 'application/octet-stream');
        const fileSize = this.formatFileSize(file.size);
        
        fileCard.innerHTML = `
            <div class="file-card-icon">
                <i class="${fileIcon}"></i>
            </div>
            <div class="file-card-info">
                <div class="file-card-name">${file.filename}</div>
                <div class="file-card-meta">
                    ${fileSize} • ${this.formatTime(file.timestamp)}
                    ${file.encrypted ? ' • <i class="fas fa-lock"></i> Encrypted' : ''}
                </div>
            </div>
            <div class="file-card-actions">
                <button class="icon-button small" onclick="window.qasaApp.downloadFile('${file.id}', '${file.filename}', ${file.encrypted})">
                    <i class="fas fa-download"></i>
                </button>
            </div>
        `;
        
        fileList.insertBefore(fileCard, fileList.firstChild);
        
        // Update files badge
        const filesBadge = document.getElementById('files-badge');
        const currentCount = parseInt(filesBadge.textContent) || 0;
        filesBadge.textContent = currentCount + 1;
        filesBadge.style.display = 'inline-block';
    }

    updateFileProgress(fileId, progress, status) {
        const fileCard = document.querySelector(`[data-file-id="${fileId}"]`);
        if (!fileCard) return;
        
        // Add or update progress bar
        let progressBar = fileCard.querySelector('.file-progress');
        if (!progressBar) {
            progressBar = document.createElement('div');
            progressBar.className = 'file-progress';
            progressBar.innerHTML = '<div class="progress-bar"></div>';
            fileCard.appendChild(progressBar);
        }
        
        const bar = progressBar.querySelector('.progress-bar');
        bar.style.width = `${progress}%`;
        
        if (status === 'complete') {
            setTimeout(() => {
                progressBar.remove();
            }, 1000);
        }
    }

    // Voice Recording
    updateVoiceRecordingUI(recording) {
        const voiceButton = document.getElementById('voice-message-btn');
        if (recording) {
            voiceButton.classList.add('recording');
            voiceButton.innerHTML = '<i class="fas fa-stop"></i>';
            
            // Show recording indicator
            this.showNotification('Recording voice message...', 'info', 0);
        } else {
            voiceButton.classList.remove('recording');
            voiceButton.innerHTML = '<i class="fas fa-microphone"></i>';
            
            // Hide recording indicator
            this.hideNotification();
        }
    }

    // Notifications
    showNotification(message, type = 'info', duration = 3000) {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.innerHTML = `
            <i class="fas ${this.getNotificationIcon(type)}"></i>
            <span>${message}</span>
        `;
        
        document.body.appendChild(notification);
        
        // Animate in
        requestAnimationFrame(() => {
            notification.classList.add('show');
        });
        
        if (duration > 0) {
            setTimeout(() => {
                this.hideNotification(notification);
            }, duration);
        }
        
        this.notifications.push(notification);
        return notification;
    }

    hideNotification(notification = null) {
        if (!notification && this.notifications.length > 0) {
            notification = this.notifications[this.notifications.length - 1];
        }
        
        if (notification) {
            notification.classList.remove('show');
            setTimeout(() => {
                notification.remove();
                const index = this.notifications.indexOf(notification);
                if (index > -1) {
                    this.notifications.splice(index, 1);
                }
            }, 300);
        }
    }

    getNotificationIcon(type) {
        const icons = {
            success: 'fa-check-circle',
            error: 'fa-exclamation-circle',
            warning: 'fa-exclamation-triangle',
            info: 'fa-info-circle'
        };
        return icons[type] || icons.info;
    }

    // Badge Updates
    updateUnreadBadge(count) {
        const chatsBadge = document.getElementById('chats-badge');
        if (count > 0) {
            chatsBadge.textContent = count > 99 ? '99+' : count.toString();
            chatsBadge.style.display = 'inline-block';
        } else {
            chatsBadge.style.display = 'none';
        }
    }

    // Active Chat
    setActiveChat(peerId) {
        // Update chat list
        document.querySelectorAll('.chat-item').forEach(item => {
            item.classList.toggle('active', item.dataset.peerId === peerId);
        });
        
        // Hide sidebar on mobile
        if (this.isMobile) {
            this.hideSidebar();
        }
    }

    // Settings
    getSettingsFromUI() {
        return {
            port: parseInt(document.getElementById('port').value),
            mdns: document.getElementById('mdns').checked,
            dht: document.getElementById('dht').checked,
            relay: document.getElementById('relay').checked,
            requireAuth: document.getElementById('require-auth').checked,
            autoEncrypt: document.getElementById('auto-encrypt').checked,
            quantumOnly: document.getElementById('quantum-only').checked,
            keyRotation: document.getElementById('key-rotation').value,
            readReceipts: document.getElementById('read-receipts').checked,
            typingIndicators: document.getElementById('typing-indicators').checked,
            lastSeen: document.getElementById('last-seen').checked,
            desktopNotifications: document.getElementById('desktop-notifications').checked,
            soundNotifications: document.getElementById('sound-notifications').checked,
            notificationPreview: document.getElementById('notification-preview').value,
            theme: document.getElementById('theme-select').value,
            fontSize: document.getElementById('font-size').value,
            compactMode: document.getElementById('compact-mode').checked
        };
    }

    // Search Filters
    getSearchFilters() {
        const filters = {};
        
        document.querySelectorAll('.discovery-filter:checked').forEach(checkbox => {
            const filter = checkbox.dataset.filter;
            filters[filter] = true;
        });
        
        return filters;
    }

    // Encryption Status
    updateEncryptionStatus(peerId, status) {
        if (this.app.currentChat === peerId) {
            const encryptionBadge = document.getElementById('encryption-badge');
            const quantumBadge = document.getElementById('quantum-badge');
            
            if (status.available) {
                encryptionBadge.classList.add('active');
                if (status.quantum_safe) {
                    quantumBadge.classList.add('active');
                }
            } else {
                encryptionBadge.classList.remove('active');
                quantumBadge.classList.remove('active');
            }
        }
    }

    // Network Stats
    updateNetworkStats(stats) {
        // Could display network stats in a status bar or dashboard
        console.log('Network stats:', stats);
    }

    updatePeerMetrics(peerId, metrics) {
        // Update connection quality indicators
        const quality = this.app.networkModule.connectionQuality.get(peerId);
        if (quality) {
            // Could show connection quality in UI
            console.log(`Peer ${peerId} connection quality:`, quality);
        }
    }

    // Context Menu
    showContextMenu(event, messageElement) {
        event.preventDefault();
        
        const contextMenu = document.getElementById('context-menu');
        contextMenu.style.left = `${event.clientX}px`;
        contextMenu.style.top = `${event.clientY}px`;
        contextMenu.classList.add('active');
        
        this.contextMenu = {
            messageId: messageElement.dataset.messageId,
            element: messageElement
        };
        
        // Close on click outside
        document.addEventListener('click', () => {
            contextMenu.classList.remove('active');
        }, { once: true });
    }

    // Mobile Support
    showSidebar() {
        const sidebar = document.querySelector('.sidebar');
        sidebar.classList.add('mobile-open');
    }

    hideSidebar() {
        const sidebar = document.querySelector('.sidebar');
        sidebar.classList.remove('mobile-open');
    }

    // UI Events
    bindUIEvents() {
        // Tab switching
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                this.switchTab(tab.dataset.tab);
            });
        });
        
        // Modal handling
        document.querySelectorAll('.close-button').forEach(btn => {
            btn.addEventListener('click', () => {
                this.closeModal(btn.dataset.modal);
            });
        });
        
        // Settings tabs
        document.querySelectorAll('.settings-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                this.switchSettingsTab(tab.dataset.section);
            });
        });
        
        // File drop zone
        const dropZone = document.getElementById('file-drop-zone');
        if (dropZone) {
            dropZone.addEventListener('dragover', (e) => {
                e.preventDefault();
                dropZone.classList.add('drag-over');
            });
            
            dropZone.addEventListener('dragleave', () => {
                dropZone.classList.remove('drag-over');
            });
            
            dropZone.addEventListener('drop', (e) => {
                e.preventDefault();
                dropZone.classList.remove('drag-over');
                this.app.handleFileSelection(e.dataTransfer.files);
            });
            
            dropZone.addEventListener('click', () => {
                document.getElementById('file-input').click();
            });
        }
        
        // Security Center button
        document.getElementById('security-btn').addEventListener('click', () => {
            this.openModal('security-modal');
            this.loadSecurityInfo();
        });
        
        // QR Code button
        document.getElementById('qr-code-btn').addEventListener('click', () => {
            this.openModal('qr-modal');
        });
        
        // Context menu actions
        document.getElementById('ctx-reply').addEventListener('click', () => {
            this.replyToMessage(this.contextMenu.messageId);
        });
        
        document.getElementById('ctx-react').addEventListener('click', () => {
            this.showEmojiPicker(this.contextMenu.element);
        });
        
        document.getElementById('ctx-forward').addEventListener('click', () => {
            this.forwardMessage(this.contextMenu.messageId);
        });
        
        document.getElementById('ctx-copy').addEventListener('click', () => {
            this.copyMessageText(this.contextMenu.messageId);
        });
        
        document.getElementById('ctx-delete').addEventListener('click', () => {
            this.deleteMessage(this.contextMenu.messageId);
        });
        
        // Chat info button
        document.getElementById('chat-info-btn').addEventListener('click', () => {
            this.showChatInfo();
        });
        
        // Emoji button
        document.getElementById('emoji-btn').addEventListener('click', (e) => {
            this.toggleEmojiPicker(e.target);
        });
        
        // Search inputs
        document.getElementById('chat-search').addEventListener('input', (e) => {
            this.filterChats(e.target.value);
        });
        
        document.getElementById('contact-search').addEventListener('input', (e) => {
            this.filterContacts(e.target.value);
        });
    }

    // Tab Management
    switchTab(tabName) {
        // Update active tab
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.classList.toggle('active', tab.dataset.tab === tabName);
        });
        
        // Update active content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.toggle('active', content.id === `${tabName}-tab`);
        });
        
        this.activeTab = tabName;
    }

    switchSettingsTab(section) {
        document.querySelectorAll('.settings-tab').forEach(tab => {
            tab.classList.toggle('active', tab.dataset.section === section);
        });
        
        document.querySelectorAll('.settings-section').forEach(content => {
            content.classList.toggle('active', content.id === `${section}-settings`);
        });
    }

    // Modal Management
    openModal(modalId) {
        const modal = document.getElementById(modalId);
        modal.classList.add('active');
        this.activeModals.add(modalId);
        
        // Trap focus
        this.trapFocus(modal);
    }

    closeModal(modalId) {
        const modal = document.getElementById(modalId);
        modal.classList.remove('active');
        this.activeModals.delete(modalId);
    }

    trapFocus(element) {
        const focusableElements = element.querySelectorAll(
            'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        );
        const firstFocusable = focusableElements[0];
        const lastFocusable = focusableElements[focusableElements.length - 1];
        
        element.addEventListener('keydown', (e) => {
            if (e.key === 'Tab') {
                if (e.shiftKey) {
                    if (document.activeElement === firstFocusable) {
                        lastFocusable.focus();
                        e.preventDefault();
                    }
                } else {
                    if (document.activeElement === lastFocusable) {
                        firstFocusable.focus();
                        e.preventDefault();
                    }
                }
            } else if (e.key === 'Escape') {
                this.closeModal(element.id);
            }
        });
        
        firstFocusable?.focus();
    }

    // Security Center
    loadSecurityInfo() {
        // Load keys
        const keyList = document.getElementById('security-key-list');
        keyList.innerHTML = '';
        
        for (const [keyId, keyData] of this.app.cryptoModule.keys) {
            const keyElement = document.createElement('div');
            keyElement.className = 'key-item';
            keyElement.innerHTML = `
                <div class="key-icon">
                    <i class="fas fa-key"></i>
                </div>
                <div class="key-info">
                    <div class="key-algorithm">${keyData.algorithm.toUpperCase()}</div>
                    <div class="key-id">${this.app.shortenPeerId(keyId)}</div>
                    <div class="key-created">${this.formatDate(keyData.created_at)}</div>
                </div>
                <div class="key-status">
                    ${keyData.algorithm.includes('dilithium') || keyData.algorithm.includes('kyber') ? 
                        '<span class="badge quantum"><i class="fas fa-atom"></i> Quantum-Safe</span>' : 
                        '<span class="badge classical"><i class="fas fa-shield-alt"></i> Classical</span>'}
                </div>
            `;
            keyList.appendChild(keyElement);
        }
        
        // Load verified contacts
        const verifiedList = document.getElementById('verified-contacts');
        verifiedList.innerHTML = '';
        
        for (const [peerId, contact] of this.app.contacts) {
            if (contact.authenticated) {
                const contactElement = document.createElement('div');
                contactElement.className = 'verified-item';
                contactElement.innerHTML = `
                    <div class="verified-avatar">
                        ${this.getAvatarHTML(contact.username || peerId, contact.avatar, true)}
                    </div>
                    <div class="verified-info">
                        <div class="verified-name">${contact.username || this.app.shortenPeerId(peerId)}</div>
                        <div class="verified-id">${this.app.shortenPeerId(peerId)}</div>
                    </div>
                    <div class="verified-badge">
                        <i class="fas fa-check-circle"></i>
                    </div>
                `;
                verifiedList.appendChild(contactElement);
            }
        }
        
        // Update security score
        this.updateSecurityScore();
    }

    updateSecurityScore() {
        let score = 50; // Base score
        
        // Add points for quantum-safe keys
        const hasQuantumKeys = Array.from(this.app.cryptoModule.keys.values())
            .some(key => key.algorithm.includes('dilithium') || key.algorithm.includes('kyber'));
        if (hasQuantumKeys) score += 30;
        
        // Add points for verified contacts
        const verifiedCount = Array.from(this.app.contacts.values())
            .filter(c => c.authenticated).length;
        score += Math.min(20, verifiedCount * 5);
        
        // Display score
        const scoreElement = document.querySelector('.score-value');
        if (scoreElement) {
            scoreElement.textContent = score;
        }
    }

    // Chat Info
    showChatInfo() {
        if (!this.app.currentChat) return;
        
        const contact = this.app.contacts.get(this.app.currentChat);
        const displayName = contact?.username || this.app.shortenPeerId(this.app.currentChat);
        
        document.getElementById('chat-info-name').textContent = displayName;
        document.getElementById('chat-info-id').textContent = this.app.currentChat;
        
        // Show/hide badges
        document.getElementById('chat-verified-badge').style.display = 
            contact?.authenticated ? 'inline-flex' : 'none';
        document.getElementById('chat-quantum-badge').style.display = 
            contact?.quantum_safe ? 'inline-flex' : 'none';
        
        // Update encryption info
        const encStatus = this.app.cryptoModule.encryptionStatus.get(this.app.currentChat);
        if (encStatus) {
            const algorithms = encStatus.algorithms.join(', ');
            document.getElementById('chat-encryption-info').textContent = 
                `End-to-end encrypted with ${algorithms}`;
        }
        
        this.openModal('chat-info-modal');
    }

    // Emoji Picker
    initializeEmojiPicker() {
        const picker = document.getElementById('emoji-picker');
        const emojis = ['😀', '😃', '😄', '😁', '😅', '😂', '🤣', '😊', '😇', '🙂', 
                       '😍', '🥰', '😘', '😗', '😙', '😚', '😋', '😛', '😜', '🤪',
                       '👍', '👎', '👌', '✌️', '🤞', '🤟', '🤘', '🤙', '👏', '🙌',
                       '❤️', '🧡', '💛', '💚', '💙', '💜', '🖤', '🤍', '🤎', '💔'];
        
        picker.innerHTML = emojis.map(emoji => 
            `<span class="emoji-option" onclick="window.qasaApp.uiModule.insertEmoji('${emoji}')">${emoji}</span>`
        ).join('');
    }

    toggleEmojiPicker(target) {
        const picker = document.getElementById('emoji-picker');
        if (picker.style.display === 'none' || !picker.style.display) {
            const rect = target.getBoundingClientRect();
            picker.style.left = `${rect.left}px`;
            picker.style.bottom = `${window.innerHeight - rect.top + 5}px`;
            picker.style.display = 'grid';
            
            // Close on click outside
            setTimeout(() => {
                document.addEventListener('click', () => {
                    picker.style.display = 'none';
                }, { once: true });
            }, 100);
        } else {
            picker.style.display = 'none';
        }
    }

    insertEmoji(emoji) {
        const messageInput = document.getElementById('message-text');
        const start = messageInput.selectionStart;
        const end = messageInput.selectionEnd;
        const text = messageInput.value;
        
        messageInput.value = text.substring(0, start) + emoji + text.substring(end);
        messageInput.selectionStart = messageInput.selectionEnd = start + emoji.length;
        messageInput.focus();
        
        document.getElementById('emoji-picker').style.display = 'none';
    }

    showEmojiPicker(messageElement) {
        // Show emoji picker for reactions
        const picker = document.getElementById('emoji-picker');
        const rect = messageElement.getBoundingClientRect();
        
        picker.style.left = `${rect.left}px`;
        picker.style.top = `${rect.bottom + 5}px`;
        picker.style.display = 'grid';
        
        // Override click handler for reactions
        picker.querySelectorAll('.emoji-option').forEach(option => {
            option.onclick = () => {
                this.app.toggleReaction(this.contextMenu.messageId, option.textContent);
                picker.style.display = 'none';
            };
        });
    }

    // Message Actions
    replyToMessage(messageId) {
        // Implementation for reply feature
        console.log('Reply to message:', messageId);
    }

    forwardMessage(messageId) {
        // Implementation for forward feature
        console.log('Forward message:', messageId);
    }

    copyMessageText(messageId) {
        const messageElement = document.querySelector(`[data-message-id="${messageId}"]`);
        if (messageElement) {
            const text = messageElement.querySelector('.message-text').textContent;
            navigator.clipboard.writeText(text);
            this.showNotification('Message copied to clipboard', 'success');
        }
    }

    deleteMessage(messageId) {
        if (confirm('Delete this message?')) {
            // Implementation for delete feature
            console.log('Delete message:', messageId);
        }
    }

    // Search/Filter
    filterChats(query) {
        const lowerQuery = query.toLowerCase();
        document.querySelectorAll('.chat-item').forEach(item => {
            const name = item.querySelector('.chat-name').textContent.toLowerCase();
            const lastMessage = item.querySelector('.chat-last-message').textContent.toLowerCase();
            const matches = name.includes(lowerQuery) || lastMessage.includes(lowerQuery);
            item.style.display = matches ? 'flex' : 'none';
        });
    }

    filterContacts(query) {
        const lowerQuery = query.toLowerCase();
        document.querySelectorAll('.contact-item').forEach(item => {
            const name = item.querySelector('.contact-name').textContent.toLowerCase();
            const matches = name.includes(lowerQuery);
            item.style.display = matches ? 'flex' : 'none';
        });
    }

    // Utility Functions
    getAvatarHTML(name, avatarUrl = null, small = false) {
        if (avatarUrl) {
            return `<img src="${avatarUrl}" alt="${name}">`;
        }
        
        // Generate initials
        const initials = name.split(' ')
            .map(word => word[0])
            .join('')
            .substring(0, 2)
            .toUpperCase();
        
        return initials || '<i class="fas fa-user"></i>';
    }

    formatTime(timestamp) {
        if (!timestamp) return '';
        
        const date = new Date(timestamp);
        const now = new Date();
        const diff = now - date;
        
        // Today
        if (date.toDateString() === now.toDateString()) {
            return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        }
        
        // Yesterday
        const yesterday = new Date(now);
        yesterday.setDate(yesterday.getDate() - 1);
        if (date.toDateString() === yesterday.toDateString()) {
            return 'Yesterday';
        }
        
        // This week
        if (diff < 7 * 24 * 60 * 60 * 1000) {
            return date.toLocaleDateString([], { weekday: 'short' });
        }
        
        // Older
        return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
    }

    formatDate(timestamp) {
        if (!timestamp) return '';
        const date = new Date(timestamp);
        return date.toLocaleDateString([], { 
            year: 'numeric', 
            month: 'long', 
            day: 'numeric' 
        });
    }

    formatDateSeparator(date) {
        const today = new Date();
        const messageDate = new Date(date);
        
        if (messageDate.toDateString() === today.toDateString()) {
            return 'Today';
        }
        
        const yesterday = new Date(today);
        yesterday.setDate(yesterday.getDate() - 1);
        if (messageDate.toDateString() === yesterday.toDateString()) {
            return 'Yesterday';
        }
        
        return messageDate.toLocaleDateString([], { 
            weekday: 'long',
            year: 'numeric', 
            month: 'long', 
            day: 'numeric' 
        });
    }

    formatLastSeen(timestamp) {
        if (!timestamp) return 'unknown';
        
        const date = new Date(timestamp);
        const now = new Date();
        const diff = (now - date) / 1000; // seconds
        
        if (diff < 60) return 'just now';
        if (diff < 3600) return `${Math.floor(diff / 60)} minutes ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)} hours ago`;
        
        return this.formatTime(timestamp);
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    getFileIcon(mimeType) {
        if (!mimeType) return 'fas fa-file';
        
        if (mimeType.startsWith('image/')) return 'fas fa-image';
        if (mimeType.startsWith('video/')) return 'fas fa-video';
        if (mimeType.startsWith('audio/')) return 'fas fa-music';
        if (mimeType.includes('pdf')) return 'fas fa-file-pdf';
        if (mimeType.includes('word') || mimeType.includes('document')) return 'fas fa-file-word';
        if (mimeType.includes('sheet') || mimeType.includes('excel')) return 'fas fa-file-excel';
        if (mimeType.includes('presentation') || mimeType.includes('powerpoint')) return 'fas fa-file-powerpoint';
        if (mimeType.includes('zip') || mimeType.includes('compressed')) return 'fas fa-file-archive';
        if (mimeType.includes('text')) return 'fas fa-file-alt';
        
        return 'fas fa-file';
    }

    escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    }

    groupMessagesByDate(messages) {
        const groups = new Map();
        
        messages.forEach(message => {
            const date = new Date(message.timestamp).toDateString();
            if (!groups.has(date)) {
                groups.set(date, []);
            }
            groups.get(date).push(message);
        });
        
        return Array.from(groups.entries());
    }

    // Responsiveness
    setupResponsiveness() {
        // Handle window resize
        window.addEventListener('resize', () => {
            this.isMobile = window.innerWidth <= 768;
            
            // Adjust UI for mobile/desktop
            if (!this.isMobile) {
                // Show sidebar on desktop
                document.querySelector('.sidebar').classList.remove('mobile-open');
            }
        });
        
        // Handle back button on mobile
        if (this.isMobile) {
            document.getElementById('back-to-chats').style.display = 'block';
        }
    }

    // Animations
    initializeAnimations() {
        // Add intersection observer for fade-in animations
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('fade-in');
                }
            });
        });
        
        // Observe elements that should fade in
        document.querySelectorAll('.chat-item, .contact-item, .discovery-peer').forEach(el => {
            observer.observe(el);
        });
    }

    // Context Menu
    initializeContextMenu() {
        // Close context menu on escape
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                document.getElementById('context-menu').classList.remove('active');
            }
        });
    }

    // Modals
    initializeModals() {
        // Close modals on escape
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.activeModals.size > 0) {
                const lastModal = Array.from(this.activeModals).pop();
                this.closeModal(lastModal);
            }
        });
        
        // Close modals on background click
        document.querySelectorAll('.modal').forEach(modal => {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    this.closeModal(modal.id);
                }
            });
        });
    }
}