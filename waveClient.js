// Wave API Client for interacting with the server
class WaveClient {
    constructor(baseUrl = "http://localhost:8080") {
        this.baseUrl = baseUrl;
        this.token = null;
    }

    // Set authentication token
    setToken(token) {
        this.token = token;
    }

    // Clear authentication token
    clearToken() {
        this.token = null;
    }

    // Get authentication headers
    getHeaders() {
        const headers = {
            "Content-Type": "application/json"
        };

        if (this.token) {
            headers["Authorization"] = `Bearer ${this.token}`;
        }

        return headers;
    }

    // Generic API request method
    async request(method, endpoint, data = null) {
        const url = `${this.baseUrl}${endpoint}`;
        const options = {
            method,
            headers: this.getHeaders(),
            credentials: "include", // Important for cookies if server uses them
        };

        if (data && (method === "POST" || method === "PUT" || method === "PATCH")) {
            options.body = JSON.stringify(data);
        }

        try {
            console.log(`API Request: ${method} ${url}`, options);
            const response = await fetch(url, options);
            let responseData;
            
            try {
                responseData = await response.json();
            } catch (e) {
                // Handle non-JSON responses
                responseData = {
                    success: false,
                    error: {
                        message: "Invalid response format",
                        code: "PARSE_ERROR"
                    }
                };
            }
            
            console.log(`API Response: ${method} ${url}`, responseData);

            // Return the response even if it's an error
            return responseData;
        } catch (error) {
            console.error(`API error (${method} ${endpoint}):`, error);
            // Return a structured error to match the API response format
            return {
                success: false,
                error: {
                    message: error.message,
                    code: "CLIENT_ERROR"
                }
            };
        }
    }

    // Authentication Endpoints
    async register(username, publicKey, encryptedPrivateKey, salt) {
        return this.request("POST", "/api/v1/auth/register", {
            username,
            public_key: publicKey,
            encrypted_private_key: encryptedPrivateKey,
            salt
        });
    }

    async login(username) {
        return this.request("POST", "/api/v1/auth/login", { username });
    }

    async logout() {
        const result = await this.request("POST", "/api/v1/auth/logout");
        this.clearToken(); // Always clear token locally
        return result;
    }

    async logoutAll() {
        const result = await this.request("POST", "/api/v1/auth/logout-all");
        this.clearToken(); // Always clear token locally
        return result;
    }

    // User & Key Endpoints
    async getPublicKey(username) {
        let endpoint = "/api/v1/keys/public";
        if (username) {
            endpoint += `?username=${encodeURIComponent(username)}`;
        }
        return this.request("GET", endpoint);
    }

    async getPrivateKey() {
        return this.request("GET", "/api/v1/keys/private");
    }

    // Contact Endpoints
    async getContacts() {
        return this.request("GET", "/api/v1/contacts");
    }

    async addContact(contactPublicKey, nickname) {
        return this.request("POST", "/api/v1/contacts", {
            contact_public_key: contactPublicKey,
            nickname
        });
    }

    async updateContact(contactPublicKey, nickname) {
        return this.request("PUT", `/api/v1/contacts/${encodeURIComponent(contactPublicKey)}`, {
            nickname
        });
    }

    async deleteContact(contactPublicKey) {
        return this.request("DELETE", `/api/v1/contacts/${encodeURIComponent(contactPublicKey)}`);
    }

    // Message Endpoints
    async sendMessage(recipientPubKey, ciphertextKEM, ciphertextMsg, nonce,
                      senderCiphertextKEM, senderCiphertextMsg, senderNonce) {
        return this.request("POST", "/api/v1/messages/send", {
            recipient_pubkey: recipientPubKey,
            ciphertext_kem: ciphertextKEM,
            ciphertext_msg: ciphertextMsg,
            nonce: nonce,
            sender_ciphertext_kem: senderCiphertextKEM,
            sender_ciphertext_msg: senderCiphertextMsg,
            sender_nonce: senderNonce
        });
    }

    async getMessages(limit = 100, offset = 0) {
        return this.request("GET", `/api/v1/messages?limit=${limit}&offset=${offset}`);
    }

    async getConversation(contactPubKey, limit = 100, offset = 0) {
        return this.request("GET", `/api/v1/messages/conversation/${encodeURIComponent(contactPubKey)}?limit=${limit}&offset=${offset}`);
    }

    async updateMessageStatus(messageId, status) {
        return this.request("PATCH", `/api/v1/messages/${messageId}/status`, {
            status
        });
    }

    // Account Management Endpoints
    async backupAccount() {
        return this.request("GET", "/api/v1/account/backup");
    }

    async recoverAccount(username, publicKey, encryptedPrivateKey, contacts = {}, messages = []) {
        return this.request("POST", "/api/v1/account/recover", {
            username,
            public_key: publicKey,
            encrypted_private_key: encryptedPrivateKey,
            contacts,
            messages
        });
    }

    async deleteAccount() {
        return this.request("DELETE", "/api/v1/account");
    }
    
    // Basic health check
    async ping() {
        return this.request("GET", "/");
    }
}

// Export the client
export default WaveClient;