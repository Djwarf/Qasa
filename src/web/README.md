# QaSa Web Module

This module provides the web-based user interface for the QaSa post-quantum secure chat application. It includes both the frontend (HTML/CSS/JavaScript) and backend (Go web server) components for the web interface.

## Features

- **Modern Web UI**: Clean, responsive web interface for secure messaging
- **Real-time Communication**: WebSocket-based real-time messaging
- **Peer Discovery**: Search and discover peers through the web interface
- **Key Management**: Visual interface for cryptographic key management
- **Status Dashboard**: Real-time status monitoring of the node and connections
- **Contact Management**: Organize and manage chat contacts
- **Settings Interface**: Configure node settings through the web UI

## Architecture

The web module consists of:

### Frontend Components
- `index.html` - Main application HTML structure
- `styles.css` - Modern CSS styling with responsive design
- `app.js` - Main application JavaScript logic
- `discovery.js` - Peer discovery functionality
- `favicon.svg` - Application icon

### Backend Components
- `web_server.go` - Go web server with WebSocket support
- `main.go` - Standalone web server application

## Usage

### As a Standalone Web Application

```bash
cd src/web
go run main.go --port 9000 --web-port 8080
```

This will start:
- The QaSa node on port 9000
- The web interface on http://localhost:8080

### As a Library

```go
import "github.com/qasa/web"

// Create web server instance
webServer := web.NewWebServer(node, chatProtocol, identifierDiscovery)

// Start the web server
go func() {
    if err := webServer.Start(8080); err != nil {
        log.Fatal("Web server error:", err)
    }
}()
```

## API Endpoints

The web server provides the following endpoints:

### Static Files
- `GET /` - Serves the web application files

### WebSocket API
- `WS /ws` - WebSocket connection for real-time communication

### REST API
- `GET /api/status` - Node status information
- `GET /api/peers` - Connected peers list
- `GET /api/search?q=<query>&type=<type>` - Peer search

## WebSocket Message Types

### Client to Server
- `message` - Send a chat message
- `connect` - Connect to a peer
- `search` - Search for peers
- `set_identifier` - Set user profile information
- `key_exchange` - Initiate key exchange

### Server to Client
- `peer_id` - Initial peer ID information
- `node_status` - Node status updates
- `contact_list` - Updated contact list
- `message_sent` - Confirmation of sent message
- `peer_connected` - Peer connection notification
- `search_results` - Search results
- `error` - Error notifications

## Dependencies

- **gorilla/websocket** - WebSocket support
- **qasa/network** - Core networking functionality

## Building

```bash
# Build the web module
cd src/web
go build -o qasa-web

# Or build as part of the main application
cd src
go build -o qasa main.go
```

## Security Considerations

1. **Origin Validation**: Currently allows all origins for development - should be restricted in production
2. **Authentication**: Web interface should implement proper authentication for production use
3. **HTTPS**: Should be served over HTTPS in production environments
4. **Input Validation**: All user inputs are validated before processing

## Future Enhancements

1. **Mobile Responsive Design**: Further optimize for mobile devices
2. **Push Notifications**: Add browser push notification support
3. **File Transfer UI**: Web interface for secure file transfers
4. **Theme Support**: Multiple UI themes and customization options
5. **Progressive Web App**: Add PWA capabilities for offline usage 