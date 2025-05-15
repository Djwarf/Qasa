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

// Search Elements
const searchInput = document.getElementById('search-input');
const searchButton = document.getElementById('search-btn');
const searchResults = document.getElementById('search-results');

// Modal Elements
const settingsModal = document.getElementById('settings-modal');
const keyManagementModal = document.getElementById('key-management-modal');
const connectModal = document.getElementById('connect-modal');
const settingsButton = document.getElementById('settings-btn');
const keyManagementButton = document.getElementById('key-management-btn');
const saveSettingsButton = document.getElementById('save-settings');
const cancelSettingsButton = document.getElementById('cancel-settings');
const closeKeyManagementButton = document.getElementById('close-key-management');
const connectBtn = document.getElementById('connect-btn');
const cancelConnectBtn = document.getElementById('cancel-connect');
const peerAddressInput = document.getElementById('peer-address');

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
        case 'message_sent':
            handleMessageSent(message.data);
            break;
        case 'contact_status':
            handleContactStatus(message.data);
            break;
        case 'search_results':
            handleSearchResults(message.data);
            break;
        case 'peer_connected':
            handlePeerConnected(message.data);
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

// Handle outgoing messages that were sent successfully
function handleMessageSent(data) {
    const { to, content, timestamp } = data;
    
    if (!messages.has(to)) {
        messages.set(to, []);
    }
    
    const messageList = messages.get(to);
    messageList.push({
        content,
        timestamp,
        sent: true
    });
    
    if (currentChat === to) {
        displayMessage(to, content, timestamp, true);
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

// Handle search results
function handleSearchResults(data) {
    const { query, results } = data;
    
    // Display search results
    searchResults.innerHTML = '';
    searchResults.classList.remove('hidden');
    
    if (results.length === 0) {
        searchResults.innerHTML = '<div class="search-result-item">No peers found matching your query</div>';
        return;
    }
    
    results.forEach(result => {
        const resultElement = document.createElement('div');
        resultElement.className = 'search-result-item';
        
        resultElement.innerHTML = `
            <div class="result-peer-id">${shortPeerId(result.peer_id)}</div>
            <div class="result-status">
                <span class="status-indicator ${result.connected ? 'online' : 'offline'}"></span>
                ${result.connected ? 'Connected' : 'Not Connected'}
                ${result.authenticated ? ' (Authenticated)' : ''}
            </div>
        `;
        
        // Add click handler to connect to the peer
        resultElement.addEventListener('click', () => {
            // If already connected, select the peer for chat
            if (result.connected) {
                selectContact(result.peer_id);
                searchResults.classList.add('hidden');
            } else {
                // Otherwise show connect modal
                showConnectModal(result.peer_id);
            }
        });
        
        searchResults.appendChild(resultElement);
    });
}

// Handle contact status updates
function handleContactStatus(data) {
    const { peer_id, online, authenticated } = data;
    
    if (contacts.has(peer_id)) {
        const contact = contacts.get(peer_id);
        contact.online = online;
        contact.authenticated = authenticated;
        
        // Update in the DOM
        const contactElement = document.querySelector(`.contact-item[data-peer-id="${peer_id}"]`);
        if (contactElement) {
            const statusIndicator = contactElement.querySelector('.status-indicator');
            statusIndicator.classList.toggle('online', online);
            statusIndicator.classList.toggle('offline', !online);
        }
    }
}

// Handle successful peer connection
function handlePeerConnected(data) {
    const { peer_id } = data;
    console.log(`Connected to peer: ${peer_id}`);
    
    // Close the connect modal
    connectModal.classList.remove('active');
    
    // Clear the input
    peerAddressInput.value = '';
    
    // Send a key exchange request
    requestKeyExchange(peer_id);
}

// Handle key exchange messages
function handleKeyExchange(data) {
    console.log('Key exchange completed', data);
    
    // Update encryption status
    encryptionStatus.textContent = '🔒';
    encryptionStatus.title = 'Encrypted with post-quantum cryptography';
    encryptionStatus.style.color = 'var(--success-color)';
}

// Handle error messages
function handleError(data) {
    console.error('Error from server:', data.message);
    alert(`Error: ${data.message}`);
}

// Shortens a peer ID for display
function shortPeerId(peerId) {
    if (!peerId || peerId.length <= 10) {
        return peerId;
    }
    return `${peerId.slice(0, 5)}...${peerId.slice(-5)}`;
}

// Send a message to the current contact
function sendMessage() {
    if (!currentChat || !messageInput.value.trim()) return;
    
    const content = messageInput.value.trim();
    
    ws.send(JSON.stringify({
        type: 'message',
        data: {
            to: currentChat,
            content
        }
    }));
    
    messageInput.value = '';
}

// Connect to a peer by address
function connectToPeer(address) {
    ws.send(JSON.stringify({
        type: 'connect',
        data: {
            peer_addr: address
        }
    }));
}

// Search for peers
function searchPeers() {
    const query = searchInput.value.trim();
    if (!query) return;
    
    ws.send(JSON.stringify({
        type: 'search',
        data: {
            query
        }
    }));
}

// Request key exchange with a peer
function requestKeyExchange(peerId) {
    ws.send(JSON.stringify({
        type: 'key_exchange',
        data: {
            peer_id: peerId,
            algorithm: 'kyber768' // Use Kyber-768 for post-quantum security
        }
    }));
}

// Show the connect modal
function showConnectModal(peerId = '') {
    connectModal.classList.add('active');
    if (peerId) {
        peerAddressInput.value = `/p2p/${peerId}`;
    }
}

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    initWebSocket();
    
    // Search functionality
    searchButton.addEventListener('click', searchPeers);
    searchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            searchPeers();
        }
    });
    
    // Hide search results when clicking elsewhere
    document.addEventListener('click', (e) => {
        if (!searchResults.contains(e.target) && e.target !== searchButton && e.target !== searchInput) {
            searchResults.classList.add('hidden');
        }
    });
    
    // Send message
    sendButton.addEventListener('click', sendMessage);
    messageInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });
    
    // Modal controls
    settingsButton.addEventListener('click', () => {
        settingsModal.classList.add('active');
    });
    
    keyManagementButton.addEventListener('click', () => {
        keyManagementModal.classList.add('active');
    });
    
    saveSettingsButton.addEventListener('click', () => {
        // Save settings
        settingsModal.classList.remove('active');
    });
    
    cancelSettingsButton.addEventListener('click', () => {
        settingsModal.classList.remove('active');
    });
    
    closeKeyManagementButton.addEventListener('click', () => {
        keyManagementModal.classList.remove('active');
    });
    
    // Connect modal
    connectBtn.addEventListener('click', () => {
        const address = peerAddressInput.value.trim();
        if (address) {
            connectToPeer(address);
        }
    });
    
    cancelConnectBtn.addEventListener('click', () => {
        connectModal.classList.remove('active');
        peerAddressInput.value = '';
    });
    
    // Close modals when clicking outside
    document.addEventListener('click', (e) => {
        if (e.target === settingsModal) {
            settingsModal.classList.remove('active');
        }
        if (e.target === keyManagementModal) {
            keyManagementModal.classList.remove('active');
        }
        if (e.target === connectModal) {
            connectModal.classList.remove('active');
        }
    });
}); 