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

// Modal Elements
const settingsModal = document.getElementById('settings-modal');
const keyManagementModal = document.getElementById('key-management-modal');
const settingsButton = document.getElementById('settings-btn');
const keyManagementButton = document.getElementById('key-management-btn');
const saveSettingsButton = document.getElementById('save-settings');
const cancelSettingsButton = document.getElementById('cancel-settings');
const closeKeyManagementButton = document.getElementById('close-key-management');

// Initialize WebSocket connection
function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    ws = new WebSocket(wsUrl);
    
    ws.onopen = () => {
        console.log('WebSocket connection established');
        connectionStatus.textContent = 'Connected';
        connectionStatus.style.color = 'var(--success-color)';
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
        case 'error':
            handleError(message.data);
            break;
    }
}

// Handle peer ID assignment
function handlePeerId(data) {
    peerId = data.peer_id;
    peerIdElement.textContent = shortPeerId(peerId);
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
    
    contactElement.innerHTML = `
        <div class="contact-info">
            <span class="status-indicator ${statusClass}"></span>
            <span class="contact-name">${shortPeerId(contact.peer_id)}</span>
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

// Select a contact to chat with
function selectContact(peerId) {
    currentChat = peerId;
    currentChatElement.textContent = shortPeerId(peerId);
    
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

// Handle errors
function handleError(data) {
    console.error('Error:', data.message);
    // You might want to show this to the user in a more user-friendly way
}

// Utility function to shorten peer IDs
function shortPeerId(peerId) {
    return peerId.substring(0, 8) + '...' + peerId.substring(peerId.length - 8);
}

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

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    initWebSocket();
}); 