// WebSocket connection
let ws = null;
let peerId = null;
let currentChat = null;
let contacts = new Map();
let messages = new Map();

// DOM Elements
const peerIdElement = document.getElementById('peer-id');
const contactList = document.getElementById('contact-list');
const chatMessages = document.getElementById('chat-messages');
const messageInput = document.getElementById('message-text');
const sendButton = document.getElementById('send-btn');
const currentChatElement = document.getElementById('current-chat');
const connectionStatus = document.getElementById('connection-status');
const encryptionStatus = document.getElementById('encryption-status');

// Navigation Elements
const navTabs = document.querySelectorAll('.nav-tab');
const tabContents = document.querySelectorAll('.tab-content');

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

// Initialize WebSocket connection
function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    ws = new WebSocket(wsUrl);
    
    ws.onopen = () => {
        console.log('WebSocket connection established');
        connectionStatus.textContent = 'Connected';
        connectionStatus.style.color = 'var(--success-color)';
        
        // Initialize discovery mode after WebSocket is connected
        if (window.initDiscovery) {
            window.initDiscovery(ws);
        }
    };
    
    ws.onclose = () => {
        console.log('WebSocket connection closed');
        connectionStatus.textContent = 'Disconnected';
        connectionStatus.style.color = 'var(--error-color)';
        // Attempt to reconnect after 5 seconds
        setTimeout(initWebSocket, 5000);
    };
    
    ws.onerror = (error) => {
        console.error('WebSocket error:', error);
    };
    
    ws.onmessage = (event) => {
        const message = JSON.parse(event.data);
        handleWebSocketMessage(message);
    };
}

// Handle incoming WebSocket messages
function handleWebSocketMessage(message) {
    switch (message.type) {
        case 'peer_id':
            handlePeerId(message.data);
            break;
        case 'contact_list':
            handleContactList(message.data);
            break;
        case 'message':
            handleIncomingMessage(message.data);
            break;
        case 'contact_status':
            handleContactStatus(message.data);
            break;
        case 'key_exchange':
            handleKeyExchange(message.data);
            break;
        case 'search_results':
            handleSearchResults(message.data);
            break;
        case 'keys_list':
            handleKeysList(message.data);
            break;
        case 'profile_updated':
            handleProfileUpdated(message.data);
            break;
        case 'error':
            handleError(message.data);
            break;
    }
}

// Handle peer ID assignment
function handlePeerId(data) {
    peerId = data.peer_id;
    peerIdElement.textContent = shortPeerId(peerId);
    
    // Load user profile if available
    ws.send(JSON.stringify({
        type: 'get_profile'
    }));
}

// Handle contact list updates
function handleContactList(data) {
    contacts.clear();
    contactList.innerHTML = '';
    
    data.contacts.forEach(contact => {
        contacts.set(contact.peer_id, contact);
        addContactToList(contact);
    });
}

// Add a contact to the list
function addContactToList(contact) {
    const contactElement = document.createElement('div');
    contactElement.className = 'contact-item';
    contactElement.dataset.peerId = contact.peer_id;
    
    const statusClass = contact.online ? 'online' : 'offline';
    const displayName = contact.identifier || shortPeerId(contact.peer_id);
    
    contactElement.innerHTML = `
        <div class="contact-info">
            <span class="status-indicator ${statusClass}"></span>
            <span class="contact-name">${displayName}</span>
        </div>
    `;
    
    contactElement.addEventListener('click', () => selectContact(contact.peer_id));
    contactList.appendChild(contactElement);
}

// Handle incoming messages
function handleIncomingMessage(data) {
    const { from, content, timestamp } = data;
    
    if (!messages.has(from)) {
        messages.set(from, []);
    }
    
    const messageList = messages.get(from);
    messageList.push({
        content,
        timestamp,
        sent: false
    });
    
    if (currentChat === from) {
        displayMessage(from, content, timestamp, false);
    } else {
        // Notify user about new message
        showNotification(from, content);
    }
}

// Display a message in the chat
function displayMessage(peerId, content, timestamp, sent) {
    const messageElement = document.createElement('div');
    messageElement.className = `message ${sent ? 'sent' : 'received'}`;
    
    const time = new Date(timestamp).toLocaleTimeString();
    
    messageElement.innerHTML = `
        <div class="message-content">${content}</div>
        <div class="message-time">${time}</div>
    `;
    
    chatMessages.appendChild(messageElement);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

// Show a browser notification for new messages
function showNotification(peerId, content) {
    // Only show notifications if the user has granted permission
    if (Notification.permission === "granted") {
        const sender = contacts.get(peerId);
        const displayName = sender?.identifier || shortPeerId(peerId);
        
        const notification = new Notification("QaSa Message", {
            body: `${displayName}: ${content.substring(0, 50)}${content.length > 50 ? '...' : ''}`,
            icon: "/favicon.ico"
        });
        
        notification.onclick = () => {
            window.focus();
            selectContact(peerId);
        };
    } else if (Notification.permission !== "denied") {
        Notification.requestPermission();
    }
}

// Select a contact to chat with
function selectContact(peerId) {
    currentChat = peerId;
    const contact = contacts.get(peerId);
    const displayName = contact?.identifier || shortPeerId(peerId);
    
    currentChatElement.textContent = displayName;
    
    // Update active state in contact list
    document.querySelectorAll('.contact-item').forEach(item => {
        item.classList.toggle('active', item.dataset.peerId === peerId);
    });
    
    // Display messages for this contact
    chatMessages.innerHTML = '';
    const messageList = messages.get(peerId) || [];
    messageList.forEach(msg => {
        displayMessage(peerId, msg.content, msg.timestamp, msg.sent);
    });
    
    // Switch to contacts tab if we're in discovery mode
    if (!document.getElementById('contacts-tab').classList.contains('active')) {
        // Find and click the contacts tab
        document.querySelector('.nav-tab[data-tab="contacts"]').click();
    }
}

// Send a message
function sendMessage() {
    if (!currentChat || !messageInput.value.trim()) return;
    
    const content = messageInput.value.trim();
    const timestamp = new Date().toISOString();
    
    ws.send(JSON.stringify({
        type: 'message',
        data: {
            to: currentChat,
            content,
            timestamp
        }
    }));
    
    if (!messages.has(currentChat)) {
        messages.set(currentChat, []);
    }
    
    const messageList = messages.get(currentChat);
    messageList.push({
        content,
        timestamp,
        sent: true
    });
    
    displayMessage(currentChat, content, timestamp, true);
    messageInput.value = '';
}

// Handle contact status updates
function handleContactStatus(data) {
    const { peer_id, online } = data;
    const contact = contacts.get(peer_id);
    
    if (contact) {
        contact.online = online;
        const contactElement = document.querySelector(`.contact-item[data-peer-id="${peer_id}"]`);
        if (contactElement) {
            const statusIndicator = contactElement.querySelector('.status-indicator');
            statusIndicator.className = `status-indicator ${online ? 'online' : 'offline'}`;
        }
    }
}

// Handle key exchange
function handleKeyExchange(data) {
    const { peer_id, status } = data;
    if (status === 'success') {
        encryptionStatus.textContent = '🔒';
        encryptionStatus.title = 'End-to-end encryption enabled';
    } else {
        encryptionStatus.textContent = '⚠️';
        encryptionStatus.title = 'Encryption not available';
    }
}

// Handle search results
function handleSearchResults(data) {
    // Forward to the discovery mode handler
    if (window.discoveryMode) {
        window.discoveryMode.handleSearchResults(data);
    }
}

// Handle list of keys
function handleKeysList(data) {
    const keyList = document.getElementById('key-list');
    const keyIdSelect = document.getElementById('key-id');
    
    // Clear previous content
    keyList.innerHTML = '';
    keyIdSelect.innerHTML = '<option value="">Select a key</option>';
    
    // Add each key to the list
    data.keys.forEach(key => {
        const keyElement = document.createElement('div');
        keyElement.className = 'key-item';
        keyElement.innerHTML = `
            <div class="key-info">
                <strong>${key.type}</strong>
                <div>${shortPeerId(key.id)}</div>
                <div>${key.created_at}</div>
            </div>
        `;
        keyList.appendChild(keyElement);
        
        // Also add to select dropdown for profile
        const option = document.createElement('option');
        option.value = key.id;
        option.textContent = `${key.type} - ${shortPeerId(key.id)}`;
        keyIdSelect.appendChild(option);
    });
}

// Handle profile updated
function handleProfileUpdated(data) {
    // Update username if provided
    if (data.username) {
        document.getElementById('username').value = data.username;
    }
    
    // Update selected key if provided
    if (data.key_id) {
        document.getElementById('key-id').value = data.key_id;
    }
    
    // Update metadata if provided
    if (data.metadata) {
        document.getElementById('profile-metadata').value = data.metadata;
    }
    
    profileModal.classList.remove('active');
}

// Handle errors
function handleError(data) {
    console.error('Error:', data.message);
    // Display error in a more user-friendly way
    alert(`Error: ${data.message}`);
}

// Utility function to shorten peer IDs
function shortPeerId(peerId) {
    if (!peerId) return '';
    return peerId.substring(0, 8) + '...' + peerId.substring(peerId.length - 8);
}

// Tab navigation
navTabs.forEach(tab => {
    tab.addEventListener('click', () => {
        // Remove active class from all tabs and contents
        navTabs.forEach(t => t.classList.remove('active'));
        tabContents.forEach(c => c.classList.remove('active'));
        
        // Add active class to selected tab and content
        tab.classList.add('active');
        const tabName = tab.dataset.tab;
        document.getElementById(`${tabName}-tab`).classList.add('active');
    });
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
}); 