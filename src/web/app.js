// Enhanced QaSa Web Application
// WebSocket connection
let ws = null;
let peerId = null;
let currentChat = null;
let currentGroup = null;
let contacts = new Map();
let messages = new Map();
let groupChats = new Map();
let fileTransfers = new Map();
let encryptionSessions = new Map();
let activeStreams = new Map();
let userProfile = {};

// UI State
let currentView = 'chat';
let dragDropActive = false;
let isDarkMode = localStorage.getItem('darkMode') === 'true';
let notifications = [];
let isTyping = false;
let typingTimeout = null;

// DOM Elements
const peerIdElement = document.getElementById('peer-id');
const contactList = document.getElementById('contact-list');
const chatMessages = document.getElementById('chat-messages');
const messageInput = document.getElementById('message-text');
const sendButton = document.getElementById('send-btn');
const currentChatElement = document.getElementById('current-chat');
const connectionStatus = document.getElementById('connection-status');
const encryptionStatus = document.getElementById('encryption-status');
const themeToggleBtn = document.getElementById('theme-toggle-btn');
const notificationsBtn = document.getElementById('notifications-btn');

// Enhanced Navigation Elements
const navTabs = document.querySelectorAll('.nav-tab');
const tabContents = document.querySelectorAll('.tab-content');
const groupsTab = document.getElementById('groups-tab');
const filesTab = document.getElementById('files-tab');
const settingsTab = document.getElementById('settings-tab');

// New UI Elements
const groupList = document.getElementById('group-list');
const filesList = document.getElementById('files-list');
const encryptionSessionsList = document.getElementById('encryption-sessions');
const createGroupBtn = document.getElementById('create-group-btn');
const fileUploadArea = document.getElementById('file-upload-area');
const progressBar = document.getElementById('upload-progress');

// Modal Elements
const settingsModal = document.getElementById('settings-modal');
const keyManagementModal = document.getElementById('key-management-modal');
const profileModal = document.getElementById('profile-modal');
const settingsButton = document.getElementById('settings-btn');
const keyManagementButton = document.getElementById('key-management-btn');
const profileButton = document.getElementById('profile-btn');
const saveSettingsButton = document.getElementById('save-settings');
const cancelSettingsButton = document.getElementById('cancel-settings');
const closeKeyManagementButton = document.getElementById('close-key-management');
const saveProfileButton = document.getElementById('save-profile');
const cancelProfileButton = document.getElementById('cancel-profile');

// Initialize Enhanced WebSocket connection
function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    ws = new WebSocket(wsUrl);
    
    ws.onopen = () => {
        console.log('🔗 WebSocket connection established');
        updateConnectionStatus('Connected', 'success');
        
        // Initialize discovery mode after WebSocket is connected
        if (window.initDiscovery) {
            window.initDiscovery(ws);
        }
        
        // Start heartbeat
        startHeartbeat();
    };
    
    ws.onclose = () => {
        console.log('❌ WebSocket connection closed');
        updateConnectionStatus('Disconnected', 'error');
        // Attempt to reconnect after 5 seconds
        setTimeout(initWebSocket, 5000);
    };
    
    ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        updateConnectionStatus('Error', 'error');
    };
    
    ws.onmessage = (event) => {
        const message = JSON.parse(event.data);
        handleWebSocketMessage(message);
    };
}

// Enhanced message handling
function handleWebSocketMessageEnhanced(message) {
    console.log('📨 Received:', message.type, message.data);
    
    // Handle new message types
    switch (message.type) {
        case 'typing_indicator':
            handleTypingIndicator(message.data);
            break;
        case 'pong':
            // Handle ping response for connection quality
            break;
        case 'user_status_changed':
            handleUserStatusChange(message.data);
            break;
        case 'file_chunk':
            handleFileChunk(message.data);
            break;
        default:
            // Call original handler
            handleWebSocketMessage(message);
    }
}

// Handle peer ID assignment
function handlePeerId(data) {
    peerId = data.peer_id;
    peerIdElement.textContent = shortPeerId(peerId);
    document.title = `QaSa - ${shortPeerId(peerId)}`;
    
    // Load user profile if available
    ws.send(JSON.stringify({
        type: 'get_profile'
    }));
}

// Enhanced contact list handling
function handleContactList(data) {
    contacts.clear();
    contactList.innerHTML = '';
    
    data.contacts.forEach(contact => {
        contacts.set(contact.peer_id, contact);
        addContactToList(contact);
    });
    
    updateContactCount();
}

// Enhanced contact item with more features
function addContactToList(contact) {
    const contactElement = document.createElement('div');
    contactElement.className = 'contact-item';
    contactElement.dataset.peerId = contact.peer_id;
    
    const statusClass = contact.online ? 'online' : 'offline';
    const displayName = contact.display_name || contact.identifier || shortPeerId(contact.peer_id);
    const authIcon = contact.authenticated ? '🔒' : '🔓';
    const encryptionIcon = contact.encryption_status === 'enabled' ? '🛡️' : '';
    
    contactElement.innerHTML = `
        <div class="contact-info">
            <div class="contact-header">
                <span class="status-indicator ${statusClass}"></span>
                <span class="contact-name">${displayName}</span>
                <span class="contact-icons">${authIcon}${encryptionIcon}</span>
            </div>
            <div class="contact-details">
                <span class="peer-id-short">${shortPeerId(contact.peer_id)}</span>
                ${contact.queued_messages > 0 ? `<span class="message-count">${contact.queued_messages}</span>` : ''}
            </div>
        </div>
        <div class="contact-actions">
            <button class="btn-small" onclick="startEncryptedChat('${contact.peer_id}')">💬</button>
            <button class="btn-small" onclick="initiateKeyExchange('${contact.peer_id}')">🔑</button>
            <button class="btn-small" onclick="sendFile('${contact.peer_id}')">📎</button>
        </div>
    `;
    
    contactElement.addEventListener('click', (e) => {
        if (!e.target.classList.contains('btn-small')) {
            selectContact(contact.peer_id);
        }
    });
    
    contactList.appendChild(contactElement);
}

// Group chat handling
function handleGroupChats(data) {
    groupChats.clear();
    if (groupList) {
        groupList.innerHTML = '';
    }
    
    data.groups.forEach(group => {
        groupChats.set(group.id, group);
        addGroupToList(group);
    });
}

function addGroupToList(group) {
    if (!groupList) return;
    
    const groupElement = document.createElement('div');
    groupElement.className = 'group-item';
    groupElement.dataset.groupId = group.id;
    
    const memberCount = Object.keys(group.members).length;
    const encryptionIcon = group.is_encrypted ? '🔒' : '';
    const lastMessage = new Date(group.last_message).toLocaleString();
    
    groupElement.innerHTML = `
        <div class="group-info">
            <div class="group-header">
                <span class="group-name">${group.name}</span>
                <span class="group-icons">${encryptionIcon}</span>
            </div>
            <div class="group-details">
                <span class="member-count">${memberCount} members</span>
                <span class="last-activity">Last: ${lastMessage}</span>
            </div>
            <div class="group-description">${group.description || ''}</div>
        </div>
        <div class="group-actions">
            <button class="btn-small" onclick="openGroup('${group.id}')">Open</button>
            <button class="btn-small" onclick="leaveGroup('${group.id}')">Leave</button>
        </div>
    `;
    
    groupList.appendChild(groupElement);
}

// File transfer handling
function handleFileTransfers(data) {
    fileTransfers.clear();
    if (filesList) {
        filesList.innerHTML = '';
    }
    
    data.transfers.forEach(transfer => {
        fileTransfers.set(transfer.id, transfer);
        addFileTransferToList(transfer);
    });
}

function addFileTransferToList(transfer) {
    if (!filesList) return;
    
    const transferElement = document.createElement('div');
    transferElement.className = 'file-transfer-item';
    transferElement.dataset.transferId = transfer.id;
    
    const statusIcon = {
        'completed': '✅',
        'in_progress': '⏳',
        'failed': '❌',
        'pending': '⏳'
    }[transfer.status] || '❔';
    
    const encryptionIcon = transfer.is_encrypted ? '🔒' : '';
    const fileSize = formatFileSize(transfer.file_size);
    const progress = Math.round(transfer.progress);
    
    transferElement.innerHTML = `
        <div class="transfer-info">
            <div class="transfer-header">
                <span class="file-name">${transfer.file_name}</span>
                <span class="transfer-icons">${statusIcon}${encryptionIcon}</span>
            </div>
            <div class="transfer-details">
                <span class="file-size">${fileSize}</span>
                <span class="transfer-progress">${progress}%</span>
                <span class="transfer-peer">
                    ${transfer.from === peerId ? `To: ${shortPeerId(transfer.to)}` : `From: ${shortPeerId(transfer.from)}`}
                </span>
            </div>
            ${transfer.status === 'in_progress' ? `
                <div class="progress-bar">
                    <div class="progress-fill" style="width: ${progress}%"></div>
                </div>
            ` : ''}
        </div>
        <div class="transfer-actions">
            ${transfer.status === 'completed' && transfer.to === peerId ? 
                `<button class="btn-small" onclick="downloadFile('${transfer.id}')">Download</button>` : ''}
            <button class="btn-small" onclick="removeTransfer('${transfer.id}')">Remove</button>
        </div>
    `;
    
    filesList.appendChild(transferElement);
}

// Enhanced messaging with encryption support
function sendMessage() {
    const content = messageInput.value.trim();
    if (!content || !currentChat) return;
    
    const encrypt = document.getElementById('encrypt-checkbox')?.checked || false;
    
    const message = {
        type: 'message',
        data: {
            to: currentChat,
            content: content,
            encrypt: encrypt
        }
    };
    
    ws.send(JSON.stringify(message));
    
    // Add to local display
    displayMessage(currentChat, content, new Date().toISOString(), true, encrypt);
    
    messageInput.value = '';
    updateSendButton();
}

// Enhanced message display with encryption indicators
function displayMessage(peerId, content, timestamp, sent, encrypted = false) {
    const messageElement = document.createElement('div');
    messageElement.className = `message ${sent ? 'sent' : 'received'}`;
    
    const time = new Date(timestamp).toLocaleTimeString();
    const encryptionIcon = encrypted ? '<span class="encryption-icon">🔒</span>' : '';
    const displayName = sent ? 'You' : (contacts.get(peerId)?.display_name || shortPeerId(peerId));
    
    messageElement.innerHTML = `
        <div class="message-header">
            <span class="message-sender">${displayName}</span>
            <span class="message-time">${time}</span>
            ${encryptionIcon}
        </div>
        <div class="message-content">${escapeHtml(content)}</div>
    `;
    
    chatMessages.appendChild(messageElement);
    chatMessages.scrollTop = chatMessages.scrollHeight;
    
    // Store message
    if (!messages.has(peerId)) {
        messages.set(peerId, []);
    }
    messages.get(peerId).push({
        content,
        timestamp,
        sent,
        encrypted
    });
}

// Group messaging
function sendGroupMessage(groupId) {
    const input = document.getElementById('group-message-input');
    const content = input.value.trim();
    if (!content) return;
    
    const message = {
        type: 'group_message',
        data: {
            group_id: groupId,
            content: content
        }
    };
    
    ws.send(JSON.stringify(message));
    input.value = '';
}

function handleGroupMessage(data) {
    const group = groupChats.get(data.group_id);
    if (!group) return;
    
    // Display in group chat if it's currently open
    if (currentGroup === data.group_id) {
        displayGroupMessage(data);
    }
    
    // Show notification if group chat is not active
    if (currentView !== 'groups' || currentGroup !== data.group_id) {
        const senderName = group.members[data.from]?.display_name || shortPeerId(data.from);
        showNotification(`${group.name}`, `${senderName}: ${data.content.substring(0, 50)}...`, 'message');
    }
}

function displayGroupMessage(data) {
    const groupMessagesElement = document.getElementById('group-messages');
    if (!groupMessagesElement) return;
    
    const messageElement = document.createElement('div');
    messageElement.className = 'group-message';
    
    const time = new Date(data.timestamp).toLocaleTimeString();
    const group = groupChats.get(data.group_id);
    const senderName = group.members[data.from]?.display_name || shortPeerId(data.from);
    const isOwnMessage = data.from === peerId;
    
    messageElement.innerHTML = `
        <div class="message-header">
            <span class="message-sender ${isOwnMessage ? 'own-message' : ''}">${senderName}</span>
            <span class="message-time">${time}</span>
        </div>
        <div class="message-content">${escapeHtml(data.content)}</div>
    `;
    
    groupMessagesElement.appendChild(messageElement);
    groupMessagesElement.scrollTop = groupMessagesElement.scrollHeight;
}

// File upload functionality
function initFileUpload() {
    if (!fileUploadArea) return;
    
    fileUploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        fileUploadArea.classList.add('drag-over');
    });
    
    fileUploadArea.addEventListener('dragleave', () => {
        fileUploadArea.classList.remove('drag-over');
    });
    
    fileUploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        fileUploadArea.classList.remove('drag-over');
        
        const files = Array.from(e.dataTransfer.files);
        uploadFiles(files);
    });
    
    const fileInput = document.getElementById('file-input');
    if (fileInput) {
        fileInput.addEventListener('change', (e) => {
            const files = Array.from(e.target.files);
            uploadFiles(files);
        });
    }
}

function uploadFiles(files) {
    if (!currentChat) {
        showNotification('Error', 'Please select a contact first', 'error');
        return;
    }
    
    files.forEach(file => uploadFile(file));
}

function uploadFile(file) {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('recipient', currentChat);
    formData.append('encrypt', document.getElementById('encrypt-files-checkbox')?.checked || false);
    
    const xhr = new XMLHttpRequest();
    
    xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable) {
            const percentComplete = (e.loaded / e.total) * 100;
            updateUploadProgress(percentComplete);
        }
    });
    
    xhr.addEventListener('load', () => {
        if (xhr.status === 200) {
            const response = JSON.parse(xhr.responseText);
            showNotification('Success', `File uploaded: ${file.name}`, 'success');
            updateUploadProgress(0);
        } else {
            showNotification('Error', `Upload failed: ${xhr.statusText}`, 'error');
        }
    });
    
    xhr.addEventListener('error', () => {
        showNotification('Error', `Upload failed: ${file.name}`, 'error');
    });
    
    xhr.open('POST', '/api/files/upload');
    xhr.send(formData);
}

function updateUploadProgress(percent) {
    if (progressBar) {
        progressBar.style.width = `${percent}%`;
        progressBar.style.display = percent > 0 && percent < 100 ? 'block' : 'none';
    }
}

// Key exchange and encryption management
function initiateKeyExchange(peerID, algorithm = 'kyber') {
    const message = {
        type: 'key_exchange',
        data: {
            peer_id: peerID,
            algorithm: algorithm
        }
    };
    
    ws.send(JSON.stringify(message));
    showNotification('Key Exchange', `Initiating key exchange with ${shortPeerId(peerID)}`, 'info');
}

function handleKeyExchange(data) {
    showNotification('Key Exchange', `Key exchange completed with ${shortPeerId(data.peer_id)}`, 'success');
    
    // Update encryption session
    if (encryptionSessions.has(data.peer_id)) {
        const session = encryptionSessions.get(data.peer_id);
        session.key_exchanged = true;
        session.algorithm = data.algorithm;
    }
}

// Advanced search functionality
function performAdvancedSearch() {
    const query = document.getElementById('search-input').value;
    if (!query) return;
    
    const searchData = {
        type: 'search',
        data: {
            query: query,
            type: document.getElementById('search-type').value || 'name'
        }
    };
    
    ws.send(JSON.stringify(searchData));
}

// Navigation and UI management
function switchTab(tabName) {
    currentView = tabName;
    
    // Update tab buttons
    navTabs.forEach(tab => {
        tab.classList.remove('active');
        if (tab.dataset.tab === tabName) {
            tab.classList.add('active');
        }
    });
    
    // Update content areas
    tabContents.forEach(content => {
        content.classList.remove('active');
        if (content.id === `${tabName}-content`) {
            content.classList.add('active');
        }
    });
    
    // Load data for the active tab
    loadTabData(tabName);
}

function loadTabData(tabName) {
    switch (tabName) {
        case 'groups':
            // Request group chats update
            break;
        case 'files':
            // Request file transfers update
            break;
        case 'settings':
            loadSettings();
            break;
    }
}

// Create group functionality
function createGroup() {
    const name = prompt('Group name:');
    if (!name) return;
    
    const description = prompt('Group description (optional):') || '';
    const isEncrypted = confirm('Enable encryption for this group?');
    
    // Get selected contacts for the group
    const selectedContacts = Array.from(document.querySelectorAll('.contact-item.selected'))
        .map(item => item.dataset.peerId);
    
    const message = {
        type: 'create_group',
        data: {
            name: name,
            description: description,
            members: selectedContacts,
            is_encrypted: isEncrypted
        }
    };
    
    ws.send(JSON.stringify(message));
}

// Utility functions
function shortPeerId(peerId) {
    if (!peerId) return '';
    return peerId.length > 12 ? peerId.substring(0, 8) + '...' : peerId;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function updateConnectionStatus(status, type) {
    if (connectionStatus) {
        connectionStatus.textContent = status;
        connectionStatus.className = `status ${type}`;
    }
}

function updateContactCount() {
    const countElement = document.getElementById('contact-count');
    if (countElement) {
        countElement.textContent = contacts.size;
    }
}

function updateSendButton() {
    if (sendButton) {
        sendButton.disabled = !messageInput.value.trim() || !currentChat;
    }
}

// Enhanced notification system
function showNotification(title, message, type = 'info', duration = 5000) {
    // Browser notification if permission granted
    if (Notification.permission === "granted") {
        const notification = new Notification(title, {
            body: message,
            icon: "/favicon.svg"
        });
        
        setTimeout(() => notification.close(), duration);
    }
    
    // In-app notification
    const notificationElement = document.createElement('div');
    notificationElement.className = `notification ${type}`;
    notificationElement.innerHTML = `
        <div class="notification-content">
            <strong>${title}</strong>
            <p>${message}</p>
        </div>
        <button class="notification-close" onclick="this.parentElement.remove()">×</button>
    `;
    
    const container = document.getElementById('notifications') || document.body;
    container.appendChild(notificationElement);
    
    // Auto-remove after duration
    setTimeout(() => {
        if (notificationElement.parentElement) {
            notificationElement.remove();
        }
    }, duration);
}

// Heartbeat to keep connection alive
function startHeartbeat() {
    setInterval(() => {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'heartbeat' }));
        }
    }, 30000); // Every 30 seconds
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
    // Initialize WebSocket
    initWebSocket();
    
    // Initialize file upload
    initFileUpload();
    
    // Message input events
    if (messageInput) {
        messageInput.addEventListener('input', updateSendButton);
        messageInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
        });
    }
    
    // Send button
    if (sendButton) {
        sendButton.addEventListener('click', sendMessage);
    }
    
    // Create group button
    if (createGroupBtn) {
        createGroupBtn.addEventListener('click', createGroup);
    }
    
    // Tab navigation
    navTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            switchTab(tab.dataset.tab);
        });
    });
    
    // Request notification permission
    if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission();
    }
    
    // Initialize with chat tab
    switchTab('chat');
});

// Settings Modal
settingsButton.addEventListener('click', () => {
    settingsModal.classList.add('active');
});

cancelSettingsButton.addEventListener('click', () => {
    settingsModal.classList.remove('active');
});

saveSettingsButton.addEventListener('click', () => {
    const settings = {
        port: document.getElementById('port').value,
        mdns: document.getElementById('mdns').checked,
        dht: document.getElementById('dht').checked,
        require_auth: document.getElementById('require-auth').checked,
        offline_queue: document.getElementById('offline-queue').checked
    };
    
    ws.send(JSON.stringify({
        type: 'settings',
        data: settings
    }));
    
    settingsModal.classList.remove('active');
});

// Key Management Modal
keyManagementButton.addEventListener('click', () => {
    keyManagementModal.classList.add('active');
    // Request current keys
    ws.send(JSON.stringify({
        type: 'get_keys'
    }));
});

closeKeyManagementButton.addEventListener('click', () => {
    keyManagementModal.classList.remove('active');
});

// Profile Modal
profileButton.addEventListener('click', () => {
    profileModal.classList.add('active');
    // Request current profile and keys
    ws.send(JSON.stringify({
        type: 'get_profile'
    }));
    ws.send(JSON.stringify({
        type: 'get_keys'
    }));
});

saveProfileButton.addEventListener('click', () => {
    const username = document.getElementById('username').value;
    const keyId = document.getElementById('key-id').value;
    const metadata = document.getElementById('profile-metadata').value;
    
    ws.send(JSON.stringify({
        type: 'set_identifier',
        data: {
            username: username,
            key_id: keyId,
            metadata: metadata
        }
    }));
});

cancelProfileButton.addEventListener('click', () => {
    profileModal.classList.remove('active');
});

// Key Management Actions
document.getElementById('generate-keys').addEventListener('click', () => {
    ws.send(JSON.stringify({
        type: 'generate_keys'
    }));
});

document.getElementById('import-keys').addEventListener('click', () => {
    // Create file input
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    
    input.onchange = (e) => {
        const file = e.target.files[0];
        const reader = new FileReader();
        
        reader.onload = (event) => {
            ws.send(JSON.stringify({
                type: 'import_keys',
                data: event.target.result
            }));
        };
        
        reader.readAsText(file);
    };
    
    input.click();
});

document.getElementById('export-keys').addEventListener('click', () => {
    ws.send(JSON.stringify({
        type: 'export_keys'
    }));
});

document.getElementById('delete-keys').addEventListener('click', () => {
    if (confirm('Are you sure you want to delete all keys? This action cannot be undone.')) {
        ws.send(JSON.stringify({
            type: 'delete_keys'
        }));
    }
});

// Message input handling
messageInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
});

sendButton.addEventListener('click', sendMessage);

// Request notification permissions
function requestNotificationPermission() {
    if ("Notification" in window) {
        Notification.requestPermission();
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    initWebSocket();
    requestNotificationPermission();
    initAdvancedFeatures();
    initTheme();
});

// Enhanced Features Initialization
function initAdvancedFeatures() {
    // Dark mode toggle
    if (themeToggleBtn) {
        themeToggleBtn.addEventListener('click', toggleDarkMode);
    }
    
    // Notifications panel
    if (notificationsBtn) {
        notificationsBtn.addEventListener('click', toggleNotifications);
    }
    
    // Enhanced message input with typing indicators
    if (messageInput) {
        messageInput.addEventListener('input', handleTyping);
        messageInput.addEventListener('keydown', handleMessageInputKeydown);
    }
    
    // Auto-save drafts
    initDraftSaving();
    
    // Enhanced contact search
    initAdvancedSearch();
    
    // Keyboard shortcuts
    initKeyboardShortcuts();
    
    // Connection quality monitoring
    initConnectionMonitoring();
}

// Dark Mode Support
function initTheme() {
    // Apply saved theme
    if (isDarkMode) {
        document.documentElement.setAttribute('data-theme', 'dark');
        if (themeToggleBtn) {
            themeToggleBtn.textContent = '☀️';
            themeToggleBtn.title = 'Toggle Light Mode';
        }
    }
}

function toggleDarkMode() {
    isDarkMode = !isDarkMode;
    localStorage.setItem('darkMode', isDarkMode.toString());
    
    if (isDarkMode) {
        document.documentElement.setAttribute('data-theme', 'dark');
        themeToggleBtn.textContent = '☀️';
        themeToggleBtn.title = 'Toggle Light Mode';
    } else {
        document.documentElement.removeAttribute('data-theme');
        themeToggleBtn.textContent = '🌙';
        themeToggleBtn.title = 'Toggle Dark Mode';
    }
    
    // Animate the transition
    document.body.style.transition = 'all 0.3s ease';
    setTimeout(() => {
        document.body.style.transition = '';
    }, 300);
}

// Enhanced Typing Indicators
function handleTyping() {
    if (!isTyping && currentChat) {
        isTyping = true;
        sendTypingIndicator(true);
    }
    
    // Clear existing timeout
    if (typingTimeout) {
        clearTimeout(typingTimeout);
    }
    
    // Set new timeout
    typingTimeout = setTimeout(() => {
        isTyping = false;
        sendTypingIndicator(false);
    }, 2000);
}

function sendTypingIndicator(typing) {
    if (ws && ws.readyState === WebSocket.OPEN && currentChat) {
        ws.send(JSON.stringify({
            type: 'typing_indicator',
            data: {
                peer_id: currentChat,
                typing: typing
            }
        }));
    }
}

function handleTypingIndicator(data) {
    const typingElement = document.getElementById('typing-indicator');
    if (typingElement && data.peer_id === currentChat) {
        if (data.typing) {
            typingElement.style.display = 'block';
            typingElement.textContent = 'Typing...';
            typingElement.classList.add('animate-pulse');
        } else {
            typingElement.style.display = 'none';
            typingElement.classList.remove('animate-pulse');
        }
    }
}

// Enhanced Message Input
function handleMessageInputKeydown(e) {
    // Send on Enter (not Shift+Enter)
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
    
    // Auto-resize textarea
    autoResizeTextarea(e.target);
}

function autoResizeTextarea(textarea) {
    textarea.style.height = 'auto';
    textarea.style.height = Math.min(textarea.scrollHeight, 120) + 'px';
}

// Draft Saving
function initDraftSaving() {
    setInterval(() => {
        if (messageInput && messageInput.value.trim() && currentChat) {
            localStorage.setItem(`draft_${currentChat}`, messageInput.value);
        }
    }, 2000);
}

function loadDraft(peerId) {
    const draft = localStorage.getItem(`draft_${peerId}`);
    if (draft && messageInput) {
        messageInput.value = draft;
        autoResizeTextarea(messageInput);
    }
}

function clearDraft(peerId) {
    localStorage.removeItem(`draft_${peerId}`);
}

// Advanced Search
function initAdvancedSearch() {
    const searchInputs = document.querySelectorAll('.search-input');
    searchInputs.forEach(input => {
        let searchTimeout;
        input.addEventListener('input', (e) => {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                performAdvancedFilter(e.target.value);
            }, 300);
        });
    });
}

function performAdvancedFilter(query) {
    const items = document.querySelectorAll('.contact-item');
    query = query.toLowerCase();
    
    items.forEach(item => {
        const name = item.querySelector('.contact-name')?.textContent.toLowerCase() || '';
        const peerId = item.querySelector('.peer-id-short')?.textContent.toLowerCase() || '';
        
        if (name.includes(query) || peerId.includes(query) || query === '') {
            item.style.display = 'flex';
            item.style.animation = 'fadeIn 0.3s ease';
        } else {
            item.style.display = 'none';
        }
    });
}

// Keyboard Shortcuts
function initKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        // Ctrl/Cmd + D: Toggle dark mode
        if ((e.ctrlKey || e.metaKey) && e.key === 'd') {
            e.preventDefault();
            toggleDarkMode();
        }
        
        // Ctrl/Cmd + /: Focus search
        if ((e.ctrlKey || e.metaKey) && e.key === '/') {
            e.preventDefault();
            const searchInput = document.querySelector('.search-input:visible');
            if (searchInput) searchInput.focus();
        }
        
        // Escape: Close modals or panels
        if (e.key === 'Escape') {
            closeAllModals();
        }
        
        // Ctrl/Cmd + N: New group
        if ((e.ctrlKey || e.metaKey) && e.key === 'n') {
            e.preventDefault();
            if (currentView === 'groups') {
                createGroup();
            }
        }
    });
}

function closeAllModals() {
    const modals = document.querySelectorAll('.modal.active');
    modals.forEach(modal => modal.classList.remove('active'));
    
    const panels = document.querySelectorAll('.right-panel');
    panels.forEach(panel => panel.style.display = 'none');
}

// Notifications System
function toggleNotifications() {
    // Create notifications panel if it doesn't exist
    let notificationsPanel = document.getElementById('notifications-panel');
    if (!notificationsPanel) {
        notificationsPanel = createNotificationsPanel();
    }
    
    // Toggle visibility
    if (notificationsPanel.style.display === 'none') {
        notificationsPanel.style.display = 'block';
        notificationsPanel.style.animation = 'slideInRight 0.3s ease';
    } else {
        notificationsPanel.style.animation = 'slideOutRight 0.3s ease';
        setTimeout(() => {
            notificationsPanel.style.display = 'none';
        }, 300);
    }
}

function createNotificationsPanel() {
    const panel = document.createElement('div');
    panel.id = 'notifications-panel';
    panel.className = 'notifications-panel';
    panel.innerHTML = `
        <div class="panel-header">
            <h3>Notifications</h3>
            <button onclick="toggleNotifications()" class="btn-icon">✕</button>
        </div>
        <div class="notifications-list" id="notifications-list">
            <div class="no-notifications">No new notifications</div>
        </div>
        <div class="panel-footer">
            <button onclick="clearAllNotifications()" class="btn-small">Clear All</button>
        </div>
    `;
    
    document.body.appendChild(panel);
    return panel;
}

function addNotification(title, message, type = 'info') {
    const notification = {
        id: Date.now(),
        title,
        message,
        type,
        timestamp: new Date()
    };
    
    notifications.unshift(notification);
    updateNotificationsBadge();
    updateNotificationsList();
    
    // Auto-remove after 5 seconds for non-important notifications
    if (type === 'info') {
        setTimeout(() => {
            removeNotification(notification.id);
        }, 5000);
    }
}

function removeNotification(id) {
    notifications = notifications.filter(n => n.id !== id);
    updateNotificationsBadge();
    updateNotificationsList();
}

function clearAllNotifications() {
    notifications = [];
    updateNotificationsBadge();
    updateNotificationsList();
}

function updateNotificationsBadge() {
    const badge = notificationsBtn?.querySelector('.notification-badge');
    const count = notifications.length;
    
    if (count > 0) {
        if (!badge) {
            const newBadge = document.createElement('span');
            newBadge.className = 'notification-badge';
            newBadge.textContent = count;
            notificationsBtn.appendChild(newBadge);
        } else {
            badge.textContent = count;
        }
    } else if (badge) {
        badge.remove();
    }
}

function updateNotificationsList() {
    const list = document.getElementById('notifications-list');
    if (!list) return;
    
    if (notifications.length === 0) {
        list.innerHTML = '<div class="no-notifications">No new notifications</div>';
        return;
    }
    
    list.innerHTML = notifications.map(notification => `
        <div class="notification-item ${notification.type}">
            <div class="notification-header">
                <span class="notification-title">${notification.title}</span>
                <button onclick="removeNotification(${notification.id})" class="btn-close">✕</button>
            </div>
            <div class="notification-message">${notification.message}</div>
            <div class="notification-time">${formatTime(notification.timestamp)}</div>
        </div>
    `).join('');
}

// Connection Quality Monitoring
function initConnectionMonitoring() {
    let pingInterval;
    let connectionQuality = 'good';
    
    function startPinging() {
        pingInterval = setInterval(() => {
            if (ws && ws.readyState === WebSocket.OPEN) {
                const startTime = Date.now();
                const pingMessage = {
                    type: 'ping',
                    timestamp: startTime
                };
                
                ws.send(JSON.stringify(pingMessage));
                
                // Monitor for pong response
                setTimeout(() => {
                    const latency = Date.now() - startTime;
                    updateConnectionQuality(latency);
                }, 1000);
            }
        }, 5000);
    }
    
    function updateConnectionQuality(latency) {
        let newQuality;
        if (latency < 100) newQuality = 'excellent';
        else if (latency < 250) newQuality = 'good';
        else if (latency < 500) newQuality = 'fair';
        else newQuality = 'poor';
        
        if (newQuality !== connectionQuality) {
            connectionQuality = newQuality;
            updateConnectionQualityUI(newQuality, latency);
        }
    }
    
    function updateConnectionQualityUI(quality, latency) {
        const indicator = document.querySelector('.connection-quality');
        if (!indicator) {
            // Create connection quality indicator
            const statusElement = document.getElementById('connection-status');
            if (statusElement) {
                const qualityDiv = document.createElement('div');
                qualityDiv.className = 'connection-quality';
                statusElement.parentNode.appendChild(qualityDiv);
            }
        }
        
        const qualityElement = document.querySelector('.connection-quality');
        if (qualityElement) {
            qualityElement.className = `connection-quality ${quality}`;
            qualityElement.title = `Connection: ${quality} (${latency}ms)`;
            
            const icons = {
                excellent: '📶',
                good: '📶', 
                fair: '📶',
                poor: '📶'
            };
            
            qualityElement.textContent = icons[quality];
        }
    }
    
    startPinging();
}

function handleUserStatusChange(data) {
    const contact = contacts.get(data.peer_id);
    if (contact) {
        contact.online = data.online;
        contact.last_seen = data.last_seen;
        updateContactDisplay(data.peer_id);
        
        // Show notification for status changes
        if (data.online) {
            addNotification('User Online', `${contact.display_name || shortPeerId(data.peer_id)} is now online`, 'info');
        }
    }
}

function updateContactDisplay(peerId) {
    const contactElement = document.querySelector(`[data-peer-id="${peerId}"]`);
    const contact = contacts.get(peerId);
    
    if (contactElement && contact) {
        const statusIndicator = contactElement.querySelector('.status-indicator');
        if (statusIndicator) {
            statusIndicator.className = `status-indicator ${contact.online ? 'online' : 'offline'}`;
        }
    }
}

// File Transfer Enhancements
function handleFileChunk(data) {
    const transfer = fileTransfers.get(data.transfer_id);
    if (transfer) {
        transfer.progress = data.progress;
        updateFileTransferProgress(data.transfer_id, data.progress);
        
        if (data.progress >= 100) {
            transfer.status = 'completed';
            addNotification('File Transfer Complete', `${transfer.file_name} has been received`, 'success');
        }
    }
}

function updateFileTransferProgress(transferId, progress) {
    const progressElement = document.querySelector(`[data-transfer-id="${transferId}"] .progress-bar`);
    if (progressElement) {
        progressElement.style.width = `${progress}%`;
        progressElement.textContent = `${Math.round(progress)}%`;
    }
}

// Utility Functions
function formatTime(date) {
    return new Intl.DateTimeFormat('en-US', {
        hour: '2-digit',
        minute: '2-digit',
        hour12: false
    }).format(date);
} 