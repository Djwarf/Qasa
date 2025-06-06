// QaSa Web Interface Utilities
// Centralized utility functions to eliminate code duplication

// ============================================================================
// STRING UTILITIES
// ============================================================================

/**
 * Shortens a peer ID for display
 * @param {string} peerId - The peer ID to shorten
 * @returns {string} Shortened peer ID
 */
function shortPeerId(peerId) {
    if (!peerId) return '';
    return peerId.length > 12 ? peerId.substring(0, 8) + '...' : peerId;
}

/**
 * Escapes HTML characters to prevent XSS
 * @param {string} text - Text to escape
 * @returns {string} Escaped HTML
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Formats file size in human-readable format
 * @param {number} bytes - Size in bytes
 * @returns {string} Formatted size string
 */
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Formats a timestamp into a readable time string
 * @param {Date|string|number} date - Date to format
 * @returns {string} Formatted time string
 */
function formatTime(date) {
    if (!date) return '';
    const d = new Date(date);
    const now = new Date();
    const diff = now - d;
    
    // If less than a minute ago
    if (diff < 60000) {
        return 'just now';
    }
    
    // If today
    if (d.toDateString() === now.toDateString()) {
        return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
    
    // If this year
    if (d.getFullYear() === now.getFullYear()) {
        return d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + 
               ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
    
    // Full date
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

/**
 * Generates a unique ID
 * @returns {string} Unique identifier
 */
function generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2);
}

// ============================================================================
// NOTIFICATION SYSTEM
// ============================================================================

class NotificationManager {
    constructor() {
        this.notifications = [];
        this.maxNotifications = 100;
        this.container = null;
        this.badgeElement = null;
        this.init();
    }

    init() {
        // Create notifications container if it doesn't exist
        if (!document.getElementById('notifications-container')) {
            this.container = document.createElement('div');
            this.container.id = 'notifications-container';
            this.container.className = 'notifications-container';
            document.body.appendChild(this.container);
        } else {
            this.container = document.getElementById('notifications-container');
        }
    }

    /**
     * Shows a notification
     * @param {string} title - Notification title
     * @param {string} message - Notification message
     * @param {string} type - Notification type (info, success, warning, error)
     * @param {number} duration - Duration in milliseconds (0 for persistent)
     * @returns {string} Notification ID
     */
    show(title, message, type = 'info', duration = 5000) {
        const id = generateId();
        const notification = {
            id,
            title,
            message,
            type,
            timestamp: new Date(),
            persistent: duration === 0 || type === 'error'
        };

        // Add to notifications array
        this.notifications.unshift(notification);

        // Trim if too many
        if (this.notifications.length > this.maxNotifications) {
            this.notifications = this.notifications.slice(0, this.maxNotifications);
        }

        // Show browser notification if permission granted
        if (Notification.permission === "granted" && type !== 'info') {
            const browserNotification = new Notification(title, {
                body: message,
                icon: "/favicon.svg"
            });
            
            setTimeout(() => browserNotification.close(), Math.min(duration, 10000));
        }

        // Show in-app notification
        this.showInApp(notification, duration);
        this.updateBadge();

        return id;
    }

    showInApp(notification, duration) {
        const element = document.createElement('div');
        element.className = `notification notification-${notification.type}`;
        element.innerHTML = `
            <div class="notification-content">
                <strong class="notification-title">${escapeHtml(notification.title)}</strong>
                <p class="notification-message">${escapeHtml(notification.message)}</p>
                <span class="notification-time">${formatTime(notification.timestamp)}</span>
            </div>
            <button class="notification-close" data-id="${notification.id}">×</button>
        `;

        // Add close event listener
        element.querySelector('.notification-close').addEventListener('click', () => {
            this.remove(notification.id);
            element.remove();
        });

        this.container.appendChild(element);

        // Auto-remove if not persistent
        if (!notification.persistent && duration > 0) {
            setTimeout(() => {
                if (element.parentElement) {
                    element.remove();
                }
            }, duration);
        }
    }

    /**
     * Removes a notification by ID
     * @param {string} id - Notification ID
     */
    remove(id) {
        this.notifications = this.notifications.filter(n => n.id !== id);
        this.updateBadge();
    }

    /**
     * Clears all notifications
     */
    clear() {
        this.notifications = [];
        this.updateBadge();
        if (this.container) {
            this.container.innerHTML = '';
        }
    }

    /**
     * Gets unread notification count
     * @returns {number} Count of unread notifications
     */
    getUnreadCount() {
        return this.notifications.filter(n => !n.read).length;
    }

    /**
     * Updates the notification badge
     */
    updateBadge() {
        const count = this.getUnreadCount();
        const badge = document.querySelector('.notification-badge');
        if (badge) {
            badge.textContent = count;
            badge.style.display = count > 0 ? 'block' : 'none';
        }
    }

    /**
     * Marks a notification as read
     * @param {string} id - Notification ID
     */
    markAsRead(id) {
        const notification = this.notifications.find(n => n.id === id);
        if (notification) {
            notification.read = true;
            this.updateBadge();
        }
    }

    /**
     * Gets all notifications
     * @returns {Array} Array of notifications
     */
    getAll() {
        return [...this.notifications];
    }
}

// Global notification manager instance
const notificationManager = new NotificationManager();

// Convenience functions
function showNotification(title, message, type = 'info', duration = 5000) {
    return notificationManager.show(title, message, type, duration);
}

function showInfo(title, message) {
    return notificationManager.show(title, message, 'info', 5000);
}

function showSuccess(title, message) {
    return notificationManager.show(title, message, 'success', 3000);
}

function showWarning(title, message) {
    return notificationManager.show(title, message, 'warning', 8000);
}

function showError(title, message) {
    return notificationManager.show(title, message, 'error', 0); // Persistent
}

// ============================================================================
// THEME UTILITIES
// ============================================================================

class ThemeManager {
    constructor() {
        this.currentTheme = localStorage.getItem('theme') || 'light';
        this.init();
    }

    init() {
        this.applyTheme(this.currentTheme);
        this.setupToggleButton();
    }

    setupToggleButton() {
        const themeToggleBtn = document.getElementById('theme-toggle-btn');
        if (themeToggleBtn) {
            themeToggleBtn.addEventListener('click', () => this.toggle());
        }
    }

    toggle() {
        const newTheme = this.currentTheme === 'light' ? 'dark' : 'light';
        this.setTheme(newTheme);
    }

    setTheme(theme) {
        this.currentTheme = theme;
        this.applyTheme(theme);
        localStorage.setItem('theme', theme);
    }

    applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        const themeToggleBtn = document.getElementById('theme-toggle-btn');
        if (themeToggleBtn) {
            themeToggleBtn.textContent = theme === 'light' ? '🌙' : '☀️';
            themeToggleBtn.title = `Switch to ${theme === 'light' ? 'dark' : 'light'} mode`;
        }
    }
}

// Global theme manager
const themeManager = new ThemeManager();

// ============================================================================
// MODAL UTILITIES
// ============================================================================

/**
 * Shows a modal by ID
 * @param {string} modalId - Modal element ID
 */
function showModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add('active');
    }
}

/**
 * Hides a modal by ID
 * @param {string} modalId - Modal element ID
 */
function hideModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove('active');
    }
}

/**
 * Closes all open modals
 */
function closeAllModals() {
    const modals = document.querySelectorAll('.modal.active');
    modals.forEach(modal => modal.classList.remove('active'));
    
    const panels = document.querySelectorAll('.right-panel');
    panels.forEach(panel => panel.style.display = 'none');
}

// ============================================================================
// VALIDATION UTILITIES
// ============================================================================

/**
 * Validates a peer ID format
 * @param {string} peerId - Peer ID to validate
 * @returns {boolean} True if valid
 */
function isValidPeerId(peerId) {
    return typeof peerId === 'string' && peerId.length > 10 && /^[A-Za-z0-9]+$/.test(peerId);
}

/**
 * Validates an email address
 * @param {string} email - Email to validate
 * @returns {boolean} True if valid
 */
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

/**
 * Sanitizes input text
 * @param {string} text - Text to sanitize
 * @returns {string} Sanitized text
 */
function sanitizeInput(text) {
    return text.replace(/[<>]/g, '').trim();
}

// ============================================================================
// STORAGE UTILITIES
// ============================================================================

/**
 * Safely gets an item from localStorage
 * @param {string} key - Storage key
 * @param {*} defaultValue - Default value if key doesn't exist
 * @returns {*} Stored value or default
 */
function getStorageItem(key, defaultValue = null) {
    try {
        const item = localStorage.getItem(key);
        return item ? JSON.parse(item) : defaultValue;
    } catch (error) {
        console.warn('Error reading from localStorage:', error);
        return defaultValue;
    }
}

/**
 * Safely sets an item in localStorage
 * @param {string} key - Storage key
 * @param {*} value - Value to store
 */
function setStorageItem(key, value) {
    try {
        localStorage.setItem(key, JSON.stringify(value));
    } catch (error) {
        console.warn('Error writing to localStorage:', error);
    }
}

/**
 * Safely removes an item from localStorage
 * @param {string} key - Storage key
 */
function removeStorageItem(key) {
    try {
        localStorage.removeItem(key);
    } catch (error) {
        console.warn('Error removing from localStorage:', error);
    }
}

// ============================================================================
// DEBOUNCE/THROTTLE UTILITIES
// ============================================================================

/**
 * Debounce function - delays execution until after calls have stopped
 * @param {Function} func - Function to debounce
 * @param {number} wait - Wait time in milliseconds
 * @returns {Function} Debounced function
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * Throttle function - limits execution to once per time period
 * @param {Function} func - Function to throttle
 * @param {number} limit - Time limit in milliseconds
 * @returns {Function} Throttled function
 */
function throttle(func, limit) {
    let inThrottle;
    return function executedFunction(...args) {
        if (!inThrottle) {
            func.apply(this, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

// ============================================================================
// INITIALIZATION
// ============================================================================

// Initialize utilities when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    // Setup keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        // Ctrl+D or Cmd+D for dark mode toggle
        if ((e.ctrlKey || e.metaKey) && e.key === 'd') {
            e.preventDefault();
            themeManager.toggle();
        }
        
        // Escape to close modals
        if (e.key === 'Escape') {
            closeAllModals();
        }
    });
    
    // Request notification permission
    if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission();
    }
});

// Export utilities for global use
window.QaSaUtils = {
    // String utilities
    shortPeerId,
    escapeHtml,
    formatFileSize,
    formatTime,
    generateId,
    
    // Notification system
    notificationManager,
    showNotification,
    showInfo,
    showSuccess,
    showWarning,
    showError,
    
    // Theme management
    themeManager,
    
    // Modal utilities
    showModal,
    hideModal,
    closeAllModals,
    
    // Validation
    isValidPeerId,
    isValidEmail,
    sanitizeInput,
    
    // Storage
    getStorageItem,
    setStorageItem,
    removeStorageItem,
    
    // Performance
    debounce,
    throttle
}; 