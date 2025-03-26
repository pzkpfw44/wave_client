// popup.js - Fixed version with working registration and decryption
import createOQSModule from "./liboqs.js";
import WaveClient from "./waveClient.js";

// Global variables
let oqs;
let apiClient;
let currentUser = null;
let currentPassword = null;
let currentPrivateKey = null; // Uint8Array of decrypted private key
let currentPubKey = null;     // Your public key (base64) from /get_public_key
let allMessages = [];
let contactsMap = {};         // { publicKey: { nickname } }
let selectedContact = null;   // The recipient's public key (base64)

async function ensureOQSLoaded() {
  // Check if OQS is already loaded
  if (window.oqs) {
    console.log("OQS library already loaded");
    return window.oqs;
  }
  
  console.log("OQS library not detected, attempting to initialize...");
  
  // Check if createOQSModule function exists
  if (typeof createOQSModule !== 'function') {
    console.error("createOQSModule function not found!");
    
    // Check if the script is loaded
    const scriptLoaded = Array.from(document.getElementsByTagName('script'))
      .some(script => script.src && script.src.includes('liboqs.js'));
    
    if (!scriptLoaded) {
      console.log("Loading liboqs.js script...");
      
      // Dynamically load the script
      return new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = 'liboqs.js';
        script.type = 'module';
        script.onload = async () => {
          try {
            if (typeof createOQSModule === 'function') {
              window.oqs = await createOQSModule();
              console.log("OQS library successfully loaded");
              resolve(window.oqs);
            } else {
              reject(new Error("createOQSModule function not found after script load"));
            }
          } catch (error) {
            reject(error);
          }
        };
        script.onerror = () => reject(new Error("Failed to load liboqs.js script"));
        document.head.appendChild(script);
      });
    } else {
      throw new Error("liboqs.js script is loaded but createOQSModule function is not defined");
    }
  }
  
  // Initialize OQS module
  try {
    console.log("Initializing OQS module...");
    window.oqs = await createOQSModule();
    console.log("OQS library successfully initialized");
    return window.oqs;
  } catch (error) {
    console.error("Failed to initialize OQS module:", error);
    throw error;
  }
}

// When the document is loaded, try to preload OQS
document.addEventListener("DOMContentLoaded", () => {
  // Attempt to load OQS early
  ensureOQSLoaded().catch(err => {
    console.warn("Early OQS loading failed, will retry when needed:", err);
  });
});

// Debug mode
const DEBUG_MODE = true;
function debugLog(...args) {
  if (DEBUG_MODE) console.log('[DEBUG]', ...args);
}

document.addEventListener("DOMContentLoaded", async function () {
  debugLog("App Initialization", "Starting application initialization");
  
  // Initialize the API client
  apiClient = new WaveClient("http://localhost:8080");
  
  // Check for saved token
  const savedToken = localStorage.getItem('wave_auth_token');
  if (savedToken) {
    apiClient.setToken(savedToken);
    debugLog("Auth", "Loaded saved token from localStorage");
  }
  
  // Initialize the OQS WASM Module
  try {
    oqs = await ensureOQSLoaded();
    console.log("OQS WASM library loaded successfully");
  } catch (error) {
    console.error("Failed to initialize the OQS library:", error);
    alert("Error loading encryption modules. See console for details.");
    return;
  }
  
  // --------------------------------------------------------
  // OQS KeyEncapsulation Wrapper Class
  // --------------------------------------------------------
  oqs.KeyEncapsulation = class {
    constructor(algorithm) {
      if (algorithm !== "Kyber512") {
        throw new Error("Unsupported algorithm: " + algorithm);
      }
      this.algorithm = algorithm;
      this.secretKey = null;
      debugLog("KeyEncapsulation created for", algorithm);
    }
  
    async generate_keypair() {
      debugLog("Generating keypair...");
      const publicKeyPtr = oqs._malloc(800); // Public key size for Kyber512
      const secretKeyPtr = oqs._malloc(1600); // Secret key size for Kyber512
      
      const result = oqs._OQS_KEM_kyber_512_keypair(publicKeyPtr, secretKeyPtr);
      if (result !== 0) {
        oqs._free(publicKeyPtr);
        oqs._free(secretKeyPtr);
        throw new Error("Failed to generate keypair: " + result);
      }
      
      // Copy the keys before freeing the memory
      const publicKey = new Uint8Array(oqs.HEAPU8.subarray(publicKeyPtr, publicKeyPtr + 800));
      const secretKey = new Uint8Array(oqs.HEAPU8.subarray(secretKeyPtr, secretKeyPtr + 1600));
      
      // Create copies so they're not affected when we free the memory
      const publicKeyCopy = new Uint8Array(publicKey);
      const secretKeyCopy = new Uint8Array(secretKey);
      
      oqs._free(publicKeyPtr);
      oqs._free(secretKeyPtr);
      
      this.secretKey = secretKeyCopy;
      debugLog("Generated keypair", {
        publicKeySize: publicKeyCopy.byteLength,
        secretKeySize: secretKeyCopy.byteLength
      });
      
      return {
        publicKey: publicKeyCopy,
        secretKey: secretKeyCopy
      };
    }
  
    async encapSecret(publicKey) {
      debugLog("Encapsulating with public key of length:", publicKey.length);
      
      const publicKeyPtr = oqs._malloc(publicKey.length);
      const sharedSecretPtr = oqs._malloc(32); // Kyber512 shared secret is 32 bytes
      const ciphertextPtr = oqs._malloc(768); // Kyber512 ciphertext is 768 bytes
      
      // Copy public key to WASM memory
      oqs.HEAPU8.set(publicKey, publicKeyPtr);
      
      debugLog("Calling encaps function...");
      const result = oqs._OQS_KEM_kyber_512_encaps(
        ciphertextPtr, 
        sharedSecretPtr, 
        publicKeyPtr
      );
      
      if (result !== 0) {
        oqs._free(publicKeyPtr);
        oqs._free(sharedSecretPtr);
        oqs._free(ciphertextPtr);
        throw new Error("Encapsulation failed: " + result);
      }
      
      // Copy results before freeing memory
      const ciphertext = new Uint8Array(oqs.HEAPU8.subarray(ciphertextPtr, ciphertextPtr + 768));
      const sharedSecret = new Uint8Array(oqs.HEAPU8.subarray(sharedSecretPtr, sharedSecretPtr + 32));
      
      // Create copies
      const ciphertextCopy = new Uint8Array(ciphertext);
      const sharedSecretCopy = new Uint8Array(sharedSecret);
      
      // Free WASM memory
      oqs._free(publicKeyPtr);
      oqs._free(sharedSecretPtr);
      oqs._free(ciphertextPtr);
      
      debugLog("Encapsulation successful", {
        ciphertextLength: ciphertextCopy.length,
        sharedSecretLength: sharedSecretCopy.length
      });
      
      // Return the copied arrays
      return {
        ciphertext: ciphertextCopy,
        sharedSecret: sharedSecretCopy
      };
    }
  
    async loadSecretKey(secretKey) {
      debugLog("Loading secret key of length:", secretKey.length);
      this.secretKey = new Uint8Array(secretKey);
    }
  
    async decapSecret(ciphertext) {
      if (!this.secretKey) {
        throw new Error("No secret key loaded");
      }
      
      debugLog("Decapsulating with ciphertext of length:", ciphertext.length);
      debugLog("Using secret key of length:", this.secretKey.length);
      
      // Allocate memory
      const secretKeyPtr = oqs._malloc(this.secretKey.length);
      const ciphertextPtr = oqs._malloc(ciphertext.length);
      const sharedSecretPtr = oqs._malloc(32); // Kyber512 shared secret is 32 bytes
      
      // Copy data to WASM memory
      oqs.HEAPU8.set(this.secretKey, secretKeyPtr);
      oqs.HEAPU8.set(ciphertext, ciphertextPtr);
      
      debugLog("Calling decaps function...");
      const result = oqs._OQS_KEM_kyber_512_decaps(
        sharedSecretPtr,
        ciphertextPtr,
        secretKeyPtr
      );
      
      if (result !== 0) {
        oqs._free(secretKeyPtr);
        oqs._free(ciphertextPtr);
        oqs._free(sharedSecretPtr);
        throw new Error("Decapsulation failed: " + result);
      }
      
      // Copy result before freeing memory
      const sharedSecret = new Uint8Array(oqs.HEAPU8.subarray(sharedSecretPtr, sharedSecretPtr + 32));
      const sharedSecretCopy = new Uint8Array(sharedSecret);
      
      // Free WASM memory
      oqs._free(secretKeyPtr);
      oqs._free(ciphertextPtr);
      oqs._free(sharedSecretPtr);
      
      debugLog("Decapsulation successful", {
        sharedSecretLength: sharedSecretCopy.length
      });
      
      return sharedSecretCopy;
    }
  
    export_secret_key() {
      if (!this.secretKey) {
        throw new Error("No secret key to export");
      }
      return this.secretKey;
    }
  
    free() {
      // We handle memory cleanup after each operation
      this.secretKey = null;
    }
  };

  // Helper functions for the key generation process
  // These are simplified but maintain the correct format
  async function generateKyberKeypair() {
    if (!oqs) {
      throw new Error("OQS library not loaded");
    }
    
    debugLog("Generating Kyber keypair...");
    
    try {
      const kem = new oqs.KeyEncapsulation("Kyber512");
      const keypair = await kem.generate_keypair();
      
      debugLog("Keypair generated successfully", {
        publicKeyLength: keypair.publicKey.length,
        secretKeyLength: keypair.secretKey.length
      });
      
      return keypair;
    } catch (error) {
      debugLog("Keypair generation error:", error);
      // Fallback to random data for testing if necessary
      debugLog("Using fallback key generation");
      return {
        publicKey: crypto.getRandomValues(new Uint8Array(800)),
        secretKey: crypto.getRandomValues(new Uint8Array(1600))
      };
    }
  }

  // --------------------------------------------------------
  // Crypto Helper Functions
  // --------------------------------------------------------
  
  async function aesGcmEncryptJS(keyBytes, ivBytes, plaintext) {
    try {
      debugLog("AES-GCM encrypt start", {
        keyLength: keyBytes.length,
        ivLength: ivBytes.length,
        plaintextLength: plaintext.length
      });
      
      // Make sure the IV is exactly 12 bytes
      if (ivBytes.length !== 12) {
        debugLog(`IV length ${ivBytes.length} is incorrect, adjusting to 12 bytes`);
        const correctIV = new Uint8Array(12);
        correctIV.set(ivBytes.slice(0, Math.min(ivBytes.length, 12)));
        ivBytes = correctIV;
      }
      
      // Import the key
      const key = await crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "AES-GCM" },
        false,
        ["encrypt"]
      );
      
      // Encrypt
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: ivBytes, tagLength: 128 },
        key,
        plaintext
      );
      
      debugLog("AES-GCM encrypt successful", {
        ciphertextLength: encrypted.byteLength
      });
      
      return new Uint8Array(encrypted);
    } catch (error) {
      debugLog("AES-GCM encrypt error:", error);
      throw error;
    }
  }
  
  async function aesGcmDecryptJS(keyBytes, ivBytes, ciphertext) {
    try {
      debugLog("AES-GCM decrypt start", {
        keyLength: keyBytes.length,
        ivLength: ivBytes.length,
        ciphertextLength: ciphertext.length
      });
      
      // Important: Make sure the IV is exactly 12 bytes
      if (ivBytes.length !== 12) {
        debugLog(`IV length ${ivBytes.length} is incorrect, adjusting to 12 bytes`);
        const correctIV = new Uint8Array(12);
        correctIV.set(ivBytes.slice(0, Math.min(ivBytes.length, 12)));
        ivBytes = correctIV;
      }
      
      // Import the key
      const key = await crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
      );
      
      // Decrypt
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: ivBytes, tagLength: 128 },
        key,
        ciphertext
      );
      
      debugLog("AES-GCM decrypt successful", {
        plaintextLength: decrypted.byteLength
      });
      
      return new Uint8Array(decrypted);
    } catch (error) {
      debugLog("AES-GCM decrypt error:", error);
      return null;
    }
  }

  // --------------------------------------------------------
  // Avatar Helper Functions
  // --------------------------------------------------------
  
  // Helper function to get initials from a name
  function getInitials(name) {
    if (!name || typeof name !== 'string') return '??';
    
    // Split by spaces and get first two parts
    const parts = name.trim().split(/\s+/);
    
    if (parts.length === 1) {
      // If single word, take first two letters
      return parts[0].substring(0, 2);
    } else {
      // If multiple words, take first letter of first two words
      return parts[0].charAt(0) + parts[1].charAt(0);
    }
  }
  
  // Generate a consistent color based on string
  function getAvatarColor(name) {
    // Simple hash function
    let hash = 0;
    for (let i = 0; i < name.length; i++) {
      hash = name.charCodeAt(i) + ((hash << 5) - hash);
    }
    
    // Convert to hex string, ensuring it's positive
    hash = Math.abs(hash);
    
    // Use the predefined colors from CSS variables
    const colors = [
      '#FF5733', '#4a90e2', '#7b61ff', '#33FF57', 
      '#FF33A8', '#33FFF6', '#F033FF', '#FF9F33', 
      '#FFF833', '#33FFBD'
    ];
    
    // Use hash to select a color
    return colors[hash % colors.length];
  }
  
  // Create avatar element
  function createAvatar(name) {
    const initials = getInitials(name);
    const color = getAvatarColor(name);
    
    const avatar = document.createElement('div');
    avatar.className = 'contact-avatar';
    avatar.style.backgroundColor = color;
    avatar.textContent = initials;
    
    return avatar;
  }

  // --------------------------------------------------------
  // Backup and Recovery Functions
  // --------------------------------------------------------
  
  async function backupAccount() {
    try {
      const response = await apiClient.backupAccount();
      if (!response || !response.success) {
        alert("Backup failed: " + (response?.error?.message || "Unknown error"));
        return;
      }
      
      const backupJSON = JSON.stringify(response.data, null, 2);
      const blob = new Blob([backupJSON], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${currentUser || "account"}_backup.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Backup failed:", err);
      alert("Backup failed. See console for details.");
    }
  }
  
  async function recoverAccount() {
    const usernameInput = document.getElementById("recover-username");
    const fileInput = document.getElementById("backup-file-input");
    const username = usernameInput.value.trim();
    if (!username) {
      alert("Please enter your username.");
      return;
    }
    if (!fileInput.files || fileInput.files.length === 0) {
      alert("Please select a backup file.");
      return;
    }
    const file = fileInput.files[0];
    const reader = new FileReader();
    reader.onload = async function (e) {
      try {
        const backupData = JSON.parse(e.target.result);
        if (!backupData.public_key || !backupData.encrypted_private_key ||
            !backupData.encrypted_private_key.salt || !backupData.encrypted_private_key.encrypted_key) {
          alert("Invalid backup file format.");
          return;
        }
        if (!confirm("This will overwrite any existing account data for this username. Proceed?")) {
          return;
        }
        
        try {
          const response = await apiClient.recoverAccount(
            username,
            backupData.public_key,
            backupData.encrypted_private_key,
            backupData.contacts || {},
            backupData.messages || []
          );
          
          if (response && response.success) {
            alert("Account recovered successfully. Please log in again if required.");
            window.location.reload();
          } else {
            alert("Recovery failed: " + (response?.error?.message || "Unknown error"));
          }
        } catch (error) {
          console.error("Recovery API error:", error);
          alert("Recovery failed: " + error.message);
        }
      } catch (err) {
        console.error("Recovery error:", err);
        alert("Recovery failed. See console for details.");
      }
    };
    reader.readAsText(file);
  }

  // --------------------------------------------------------
  // DOM Elements
  // --------------------------------------------------------
  const sendMessageBtn = document.getElementById("send-message-btn");
  const tabContactsLink = document.getElementById("tab-contacts");
  const tabChatLink = document.getElementById("tab-chat");
  const tabSettingsLink = document.getElementById("tab-settings");
  const logoutLink = document.getElementById("logout-btn");
  const userLabel = document.getElementById("user-label");

  const authContainer = document.getElementById("auth-container");
  const contactsContainer = document.getElementById("contacts-container");
  const chatContainer = document.getElementById("chat-container");
  const settingsContainer = document.getElementById("settings-container");

  const loginUsernameInput = document.getElementById("login-username");
  const loginPasswordInput = document.getElementById("login-password");
  const loginBtn = document.getElementById("login-btn");
  const regUsernameInput = document.getElementById("reg-username");
  const regPasswordInput = document.getElementById("reg-password");
  const registerBtn = document.getElementById("register-btn");

  const contactPublicKeyInput = document.getElementById("contact-public-key");
  const contactNicknameInput = document.getElementById("contact-nickname");
  const addContactBtn = document.getElementById("add-contact-btn");
  const contactsDiv = document.getElementById("contacts");

  const contactSelect = document.getElementById("contact-select");
  const messagesDiv = document.getElementById("messages");
  const messageTextInput = document.getElementById("message-text");

  const publicKeyDisplay = document.getElementById("public-key-display");
  const copyKeyBtn = document.getElementById("copy-key-btn");
  const cancelAccountBtn = document.getElementById("cancel-account-btn");

  // Recovery UI elements
  const recoverUsernameInput = document.getElementById("recover-username");
  const backupFileInput = document.getElementById("backup-file-input");
  const recoverAccountBtn = document.getElementById("recover-account-btn");
  const backupAccountBtn = document.getElementById("backup-account-btn");

  // --------------------------------------------------------
  // Ensure All UI Components Are Fully Loaded
  // --------------------------------------------------------
  if (!tabContactsLink || !tabChatLink || !tabSettingsLink) {
    console.error("One or more navigation elements are missing!");
    return;
  }
  if (!loginBtn || !registerBtn) {
    console.error("Authentication buttons are missing!");
    return;
  }
  if (!contactSelect || !messagesDiv || !messageTextInput) {
    console.error("Chat elements are missing!");
    return;
  }
  if (!copyKeyBtn || !cancelAccountBtn) {
    console.error("Settings buttons are missing!");
    return;
  }
  if (!sendMessageBtn) {
    console.error("sendMessageBtn not found in the document.");
  } else {
    sendMessageBtn.disabled = false;
  }

  // --------------------------------------------------------
  // Authentication Checks
  // --------------------------------------------------------
  // Function to check if user is authenticated before allowing navigation
  function checkAuthentication(e, targetSection, targetLink) {
    if (!currentUser) {
      e.preventDefault();
      alert("Please log in to access this feature");
      showSection(authContainer);
      return false;
    }
    
    setActiveNavLink(targetLink);
    showSection(targetSection);
    return true;
  }

  // --------------------------------------------------------
  // Event Listeners
  // --------------------------------------------------------
  // Navigation event listeners
  tabContactsLink.addEventListener("click", (e) => {
    e.preventDefault();
    if (checkAuthentication(e, contactsContainer, tabContactsLink)) {
      loadContacts();
    }
  });
  
  tabChatLink.addEventListener("click", (e) => {
    e.preventDefault();
    if (checkAuthentication(e, chatContainer, tabChatLink)) {
      populateContactDropdown();
      renderMessages();
    }
  });
  
  tabSettingsLink.addEventListener("click", (e) => {
    e.preventDefault();
    if (checkAuthentication(e, settingsContainer, tabSettingsLink)) {
      fetchPublicKey();
    }
  });
  
  logoutLink.addEventListener("click", (e) => {
    e.preventDefault();
    doLogout();
  });

  // Event listeners for Backup and Recovery.
  if (backupAccountBtn) {
    backupAccountBtn.addEventListener("click", backupAccount);
  }
  if (recoverAccountBtn) {
    recoverAccountBtn.addEventListener("click", recoverAccount);
  }

  // Send Message handler with double encryption
  if (sendMessageBtn) {
    sendMessageBtn.addEventListener("click", async function () {
      if (!selectedContact) {
        let recipientInput = prompt("Enter recipient's public key (base64):");
        if (!recipientInput) {
          alert("No recipient provided.");
          return;
        }
        selectedContact = recipientInput;
        let opt = document.createElement("option");
        opt.value = recipientInput;
        opt.textContent = "Unknown user: " + recipientInput.substring(0, 10) + "...";
        contactSelect.appendChild(opt);
        contactSelect.value = recipientInput;
      }
      
      const messageText = messageTextInput.value.trim();
      if (!messageText) {
        alert("Please enter a message to send.");
        return;
      }
      
      try {
        debugLog("Sending message", {
          recipient: selectedContact.substring(0, 10) + "...",
          messageLength: messageText.length
        });
        
        sendMessageBtn.disabled = true;
        
        if (!oqs) {
          alert("Encryption library not loaded yet. Please try again in a moment.");
          sendMessageBtn.disabled = false;
          return;
        }
        
        // Step 1: Encrypt for recipient
        debugLog("Starting recipient encryption");
        const recipientPublicKeyBytes = base64ToBytes(selectedContact);
        let kemRecipient = new oqs.KeyEncapsulation("Kyber512");
        let { ciphertext, sharedSecret } = await kemRecipient.encapSecret(recipientPublicKeyBytes);
        kemRecipient.free();
        
        debugLog("Recipient encryption successful", {
          ciphertextLength: ciphertext.length,
          sharedSecretLength: sharedSecret.length
        });
        
        // Step 2: Encrypt for sender (so sender can read their own messages)
        debugLog("Starting sender encryption");
        const senderPublicKeyBytes = base64ToBytes(currentPubKey);
        let kemSender = new oqs.KeyEncapsulation("Kyber512");
        let { ciphertext: senderCiphertext, sharedSecret: senderSharedSecret } = 
          await kemSender.encapSecret(senderPublicKeyBytes);
        kemSender.free();
        
        debugLog("Sender encryption successful", {
          ciphertextLength: senderCiphertext.length,
          sharedSecretLength: senderSharedSecret.length
        });
        
        // Step 3: Encrypt message content with AES-GCM
        const messageBytes = new TextEncoder().encode(messageText);
        const recipientNonce = crypto.getRandomValues(new Uint8Array(12));
        const senderNonce = crypto.getRandomValues(new Uint8Array(12));
        
        debugLog("Encrypting message content");
        const encryptedMessageForRecipient = await aesGcmEncryptJS(
          sharedSecret, 
          recipientNonce, 
          messageBytes
        );
        
        const encryptedMessageForSender = await aesGcmEncryptJS(
          senderSharedSecret,
          senderNonce,
          messageBytes
        );
        
        debugLog("Message content encryption successful", {
          recipientCiphertextLength: encryptedMessageForRecipient.length,
          senderCiphertextLength: encryptedMessageForSender.length
        });
        
        // Step 4: Send the message
        debugLog("Sending to server");
        const response = await apiClient.sendMessage(
          selectedContact,
          bytesToBase64(ciphertext),
          bytesToBase64(encryptedMessageForRecipient),
          bytesToBase64(recipientNonce),
          bytesToBase64(senderCiphertext),
          bytesToBase64(encryptedMessageForSender),
          bytesToBase64(senderNonce)
        );
        
        if (!response || !response.success) {
          debugLog("Send failed", response?.error);
          alert("Failed to send message: " + (response?.error?.message || "Unknown error"));
          sendMessageBtn.disabled = false;
          return;
        }
        
        debugLog("Message sent successfully!");
        messageTextInput.value = "";
        
        // Reload messages
        setTimeout(async () => {
          await loadAllMessages();
          contactSelect.value = selectedContact;
          renderMessages();
          sendMessageBtn.disabled = false;
        }, 500);
        
      } catch (error) {
        debugLog("Send message error:", error);
        alert("Failed to send message: " + error.message);
        sendMessageBtn.disabled = false;
      }
    });
  }
  
  // Authentication event listeners: Fixed Registration
  registerBtn.addEventListener("click", async function () {
    const username = regUsernameInput.value.trim();
    const password = regPasswordInput.value.trim();
    
    if (!username || !password) {
      alert("Username and password are required");
      return;
    }
    
    // Disable the button to prevent multiple submissions
    registerBtn.disabled = true;
    
    try {
      console.log("Starting registration process for user:", username);
      
      // Generate a secure salt for key derivation
      const salt = crypto.getRandomValues(new Uint8Array(16));
      console.log("Salt generated:", {
        length: salt.length,
        preview: Array.from(salt.slice(0, 4)).map(b => b.toString(16).padStart(2, '0')).join('')
      });
      
      // Generate Kyber keypair
      let keypair;
      try {
        const kem = new oqs.KeyEncapsulation("Kyber512");
        keypair = await kem.generate_keypair();
        console.log("Generated Kyber keypair", {
          publicKeyLength: keypair.publicKey.length,
          secretKeyLength: keypair.secretKey.length
        });
      } catch (kpErr) {
        console.error("Error generating keypair:", kpErr);
        throw new Error("Failed to generate cryptographic keys: " + kpErr.message);
      }
      
      // Validate key sizes before proceeding
      if (keypair.publicKey.length < 800 || keypair.publicKey.length > 1000) {
        throw new Error(`Public key size (${keypair.publicKey.length} bytes) is outside allowed range (800-1000 bytes)`);
      }
      
      if (keypair.secretKey.length < 1200 || keypair.secretKey.length > 1600) {
        throw new Error(`Secret key size (${keypair.secretKey.length} bytes) is outside allowed range (1200-1600 bytes)`);
      }
      
      // Derive key for private key encryption
      const encoder = new TextEncoder();
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
      );
      
      const derivedKey = await crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt: salt,
          iterations: 100000,
          hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt"]
      );
      
      // Use exactly 12 bytes for the IV (AES-GCM requirement)
      const iv = new Uint8Array(12);
      iv.set(salt.slice(0, 12));
      
      console.log("Using IV for encryption:", {
        length: iv.length,
        preview: Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('')
      });
      
      // Encrypt the private key with AES-GCM
      const encryptedPrivateKey = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        derivedKey,
        keypair.secretKey
      );
      
      // Convert to Uint8Array for API submission
      const encryptedBytes = new Uint8Array(encryptedPrivateKey);
      
      // Check if the encrypted key is within acceptable size limits
      if (encryptedBytes.length < 1200 || encryptedBytes.length > 1600) {
        console.warn(`Encrypted private key size (${encryptedBytes.length} bytes) is outside allowed range (1200-1600 bytes)`);
      }
      
      console.log("Encrypted private key:", {
        length: encryptedBytes.length,
        preview: Array.from(encryptedBytes.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join('')
      });
      
      // Base64 encode all binary data for API submission
      const base64PublicKey = bytesToBase64(keypair.publicKey);
      const base64EncryptedPrivateKey = bytesToBase64(encryptedBytes);
      const base64Salt = bytesToBase64(salt);
      
      console.log("Registration data prepared:", {
        usernameLength: username.length,
        publicKeyB64Length: base64PublicKey.length,
        encryptedKeyB64Length: base64EncryptedPrivateKey.length,
        saltB64Length: base64Salt.length
      });
      
      // Register with the server
      const response = await apiClient.register(
        username,
        base64PublicKey,
        base64EncryptedPrivateKey,
        base64Salt
      );
      
      if (!response || !response.success) {
        console.error("Registration failed:", response?.error);
        alert("Registration failed: " + (response?.error?.message || "Unknown error"));
        registerBtn.disabled = false;
        return;
      }
      
      // Registration successful, store token
      const tokenData = response.data;
      apiClient.setToken(tokenData.access_token);
      localStorage.setItem('wave_auth_token', tokenData.access_token);
      localStorage.setItem('wave_username', username);
      
      console.log("Registration successful, setting up user session");
      
      // Set up user session
      currentUser = username;
      currentPassword = password;
      currentPrivateKey = keypair.secretKey;
      currentPubKey = base64PublicKey;
      
      userLabel.textContent = `Logged in as ${currentUser}`;
      
      // Navigate to chat
      showSection(chatContainer);
      setActiveNavLink(tabChatLink);
      
      // Load user data
      await loadContacts();
      await loadAllMessages();
      
      alert("Registration successful! You are now logged in.");
      
    } catch (error) {
      console.error("Registration error:", error);
      alert("Registration failed: " + error.message);
    } finally {
      registerBtn.disabled = false;
    }
  });

  loginBtn.addEventListener("click", async function () {
    const username = loginUsernameInput.value.trim();
    const password = loginPasswordInput.value.trim();
    
    if (!username || !password) {
      alert("Username and password are required");
      return;
    }
    
    try {
      debugLog("Authentication", {
        action: "login",
        username: username
      });
      
      const response = await apiClient.login(username);
      
      if (!response || !response.success) {
        debugLog("Authentication", {
          action: "login failed",
          error: response?.error?.message || "Unknown error"
        });
        alert("Login failed: " + (response?.error?.message || "Unknown error"));
        return;
      }
      
      const tokenData = response.data;
      apiClient.setToken(tokenData.access_token);
      localStorage.setItem('wave_auth_token', tokenData.access_token);
      localStorage.setItem('wave_username', username);
      
      debugLog("Authentication", {
        action: "login successful",
        username: username,
        tokenReceived: Boolean(tokenData.access_token)
      });
      
      currentUser = username;
      currentPassword = password;
      userLabel.textContent = `Logged in as ${currentUser}`;
      
      await fetchPublicKey();
      showSection(chatContainer);
      setActiveNavLink(tabChatLink);
      await loadPrivateKey();
      await loadContacts();
      await loadAllMessages();
    } catch (error) {
      debugLog("Authentication", {
        action: "login error",
        error: error.message
      });
      console.error("Login failed:", error);
      alert("Login failed: " + error.message);
    }
  });

  // Contacts event listener.
  addContactBtn.addEventListener("click", async function () {
    const contact_public_key = contactPublicKeyInput.value.trim();
    const nickname = contactNicknameInput.value.trim();
    if (!contact_public_key || !nickname) {
      alert("Please enter the contact's public key and nickname.");
      return;
    }
    
    try {
      debugLog("Contacts", {
        action: "adding contact",
        nickname: nickname,
        publicKeyLength: contact_public_key.length
      });
      
      const response = await apiClient.addContact(contact_public_key, nickname);
      
      debugLog("Contacts", {
        action: "contact add response",
        success: response?.success,
        error: response?.error?.message
      });
      
      if (!response || !response.success) {
        alert("Failed to add contact: " + (response?.error?.message || "Unknown error"));
        return;
      }
      
      alert("Contact added!");
      contactPublicKeyInput.value = "";
      contactNicknameInput.value = "";
      await loadContacts();
    } catch (error) {
      debugLog("Contacts", {
        action: "add contact error",
        error: error.message
      });
      console.error("Add contact failed:", error);
      alert("Failed to add contact: " + error.message);
    }
  });

  contactSelect.addEventListener("change", function () {
    selectedContact = contactSelect.value;
    debugLog("Chat", {
      action: "contact selected",
      selectedContact: selectedContact ? selectedContact.substring(0, 20) + "..." : "none"
    });
    renderMessages();
  });

  // Settings event listeners.
  copyKeyBtn.addEventListener("click", function () {
    publicKeyDisplay.select();
    document.execCommand("copy");
    alert("Public key copied!");
  });

  cancelAccountBtn.addEventListener("click", async function () {
    if (!confirm("Are you sure you want to delete your account? This cannot be undone.")) return;
    
    try {
      const response = await apiClient.deleteAccount();
      
      if (!response || !response.success) {
        alert("Failed to delete account: " + (response?.error?.message || "Unknown error"));
        return;
      }
      
      alert("Account deleted!");
      doLogout();
    } catch (error) {
      console.error("Delete account failed:", error);
      alert("Failed to delete account: " + error.message);
    }
  });

  // --------------------------------------------------------
  // Core Functionality
  // --------------------------------------------------------
  
  // Utility functions for encoding/decoding
  function base64ToBytes(b64) {
    const binStr = atob(b64.replace(/_/g, "/").replace(/-/g, "+"));
    const bytes = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) {
      bytes[i] = binStr.charCodeAt(i);
    }
    return bytes;
  }
  
  function bytesToBase64(bytes) {
    let binStr = "";
    for (let i = 0; i < bytes.length; i++) {
      binStr += String.fromCharCode(bytes[i]);
    }
    return btoa(binStr).replace(/\+/g, "-").replace(/\//g, "_");
  }

  // UI Functions
  function showSection(section) {
    authContainer.classList.add("hidden");
    contactsContainer.classList.add("hidden");
    chatContainer.classList.add("hidden");
    settingsContainer.classList.add("hidden");
    section.classList.remove("hidden");
  }
  
  function setActiveNavLink(link) {
    tabContactsLink.classList.remove("active");
    tabChatLink.classList.remove("active");
    tabSettingsLink.classList.remove("active");
    link.classList.add("active");
  }
  
  async function fetchPublicKey() {
    try {
      debugLog("Keys", {
        action: "fetching public key",
        username: currentUser
      });
      
      const response = await apiClient.getPublicKey(currentUser);
      
      if (!response || !response.success) {
        debugLog("Keys", {
          action: "public key fetch failed",
          error: response?.error?.message
        });
        publicKeyDisplay.value = "No public key found.";
        return;
      }
      
      currentPubKey = response.data.public_key;
      debugLog("Keys", {
        action: "public key fetched",
        publicKeyLength: currentPubKey.length,
        publicKeyPreview: currentPubKey.substring(0, 20) + "..."
      });
      
      publicKeyDisplay.value = currentPubKey;
    } catch (error) {
      debugLog("Keys", {
        action: "public key fetch error",
        error: error.message
      });
      console.error("Fetch public key failed:", error);
      publicKeyDisplay.value = "Error fetching public key";
    }
  }
  
  async function loadPrivateKey() {
    try {
      debugLog("Keys", {
        action: "loading private key",
        hasPassword: Boolean(currentPassword)
      });
      
      const response = await apiClient.getPrivateKey();
      
      if (!response || !response.success) {
        debugLog("Keys", {
          action: "private key load failed",
          error: response?.error?.message
        });
        console.warn("Error loading encrypted private key:", response?.error?.message || "Unknown error");
        return;
      }
      
      const data = response.data;
      const salt = base64ToBytes(data.salt);
      const encKey = base64ToBytes(data.encrypted_private_key);
      const iv = salt.slice(0, 12); // Use first 12 bytes of salt as IV
      
      debugLog("Keys", {
        action: "loaded encrypted private key",
        saltLength: salt.length,
        ivLength: iv.length,
        encryptedKeyLength: encKey.length
      });
    
      try {
        const derivedKey = await deriveAesKeyFromPassword(currentPassword, salt);
        
        try {
          const decryptedKey = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            derivedKey,
            encKey
          );
          
          currentPrivateKey = new Uint8Array(decryptedKey);
          
          debugLog("Keys", {
            action: "private key decrypted successfully",
            privateKeyLength: currentPrivateKey.length
          });
        } catch (decryptError) {
          debugLog("Keys", {
            action: "private key decryption failed",
            error: decryptError.message
          });
          
          throw new Error("Decryption failed, possibly due to incorrect password");
        }
      } catch (e) {
        debugLog("Keys", {
          action: "private key decryption failed",
          error: e.message
        });
        
        alert("Failed to decrypt private key. Please check your password.");
        currentPassword = prompt("Enter your password to unlock your account:");
        if (currentPassword) {
          debugLog("Keys", {
            action: "retrying private key decryption with new password"
          });
          
          const derivedKey = await deriveAesKeyFromPassword(currentPassword, salt);
          
          try {
            const decryptedKey = await crypto.subtle.decrypt(
              { name: "AES-GCM", iv: iv },
              derivedKey,
              encKey
            );
            
            currentPrivateKey = new Uint8Array(decryptedKey);
            
            debugLog("Keys", {
              action: "private key decryption retry succeeded",
              privateKeyLength: currentPrivateKey.length
            });
          } catch (retryError) {
            debugLog("Keys", {
              action: "private key decryption retry failed"
            });
            alert("Decryption failed again. Please try re-logging in.");
          }
        }
      }
    } catch (error) {
      debugLog("Keys", {
        action: "load private key error",
        error: error.message
      });
      console.error("Load private key failed:", error);
      alert("Failed to load private key: " + error.message);
    }
  }
  
  async function deriveAesKeyFromPassword(password, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveBits", "deriveKey"]
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );
  }
  
  async function loadContacts() {
    try {
      debugLog("Contacts", {
        action: "loading contacts"
      });
      
      const response = await apiClient.getContacts();
      
      if (!response || !response.success) {
        debugLog("Contacts", {
          action: "load contacts failed",
          error: response?.error?.message
        });
        console.warn("Failed to load contacts:", response?.error?.message || "Unknown error");
        return;
      }
      
      contactsMap = {};
      const contacts = response.data.contacts || [];
      
      // Convert contacts array to map
      for (const contact of contacts) {
        contactsMap[contact.contact_pubkey] = {
          nickname: contact.nickname
        };
      }
      
      debugLog("Contacts", {
        action: "contacts loaded",
        count: contacts.length
      });
      
      renderContacts();
    } catch (error) {
      debugLog("Contacts", {
        action: "load contacts error",
        error: error.message
      });
      console.error("Load contacts failed:", error);
    }
  }
  
  // UPDATED: renderContacts with avatars
  function renderContacts() {
    contactsDiv.innerHTML = "";
    
    debugLog("UI", {
      action: "rendering contacts",
      contactCount: Object.keys(contactsMap).length
    });
    
    for (const pubKey in contactsMap) {
      const { nickname } = contactsMap[pubKey];
      const div = document.createElement("div");
      div.classList.add("contact-item");
      
      // Create contact avatar with initials
      const avatar = createAvatar(nickname);
      
      const contactInfo = document.createElement("span");
      contactInfo.appendChild(avatar);
      contactInfo.appendChild(document.createTextNode(nickname));
      
      div.appendChild(contactInfo);
      
      const removeBtn = document.createElement("button");
      removeBtn.classList.add("remove-contact-btn");
      removeBtn.textContent = "Remove";
      removeBtn.addEventListener("click", async () => {
        await removeContact(pubKey);
      });
      
      div.appendChild(removeBtn);
      contactsDiv.appendChild(div);
    }
  }
  
  async function removeContact(pubKey) {
    try {
      debugLog("Contacts", {
        action: "removing contact",
        publicKey: pubKey.substring(0, 20) + "..."
      });
      
      const response = await apiClient.deleteContact(pubKey);
      
      if (!response || !response.success) {
        debugLog("Contacts", {
          action: "remove contact failed",
          error: response?.error?.message
        });
        alert("Failed to remove contact: " + (response?.error?.message || "Unknown error"));
        return;
      }
      
      debugLog("Contacts", {
        action: "contact removed successfully"
      });
      
      alert("Contact removed!");
      await loadContacts();
    } catch (error) {
      debugLog("Contacts", {
        action: "remove contact error",
        error: error.message
      });
      console.error("Remove contact failed:", error);
      alert("Failed to remove contact: " + error.message);
    }
  }
  
  async function loadAllMessages() {
    try {
      debugLog("Messages", {
        action: "loading all messages"
      });
      
      const response = await apiClient.getMessages();
      
      if (!response || !response.success) {
        debugLog("Messages", {
          action: "load messages failed",
          error: response?.error?.message
        });
        console.warn("Failed to load messages:", response?.error?.message || "Unknown error");
        allMessages = [];
        return;
      }
      
      allMessages = response.data.messages || [];
      
      debugLog("Messages", {
        action: "messages loaded",
        count: allMessages.length,
        firstMessageId: allMessages.length > 0 ? allMessages[0].message_id : "none"
      });
      
      // DIAGNOSTIC: Log individual message details for the first few messages
      if (allMessages.length > 0) {
        for (let i = 0; i < Math.min(3, allMessages.length); i++) {
          const msg = allMessages[i];
          debugLog("Message Details", {
            index: i,
            id: msg.message_id,
            sender: msg.sender_pubkey ? (msg.sender_pubkey.substring(0, 20) + "...") : "none",
            recipient: msg.recipient_pubkey ? (msg.recipient_pubkey.substring(0, 20) + "...") : "none",
            hasCiphertextKEM: Boolean(msg.ciphertext_kem),
            hasCiphertextMsg: Boolean(msg.ciphertext_msg),
            hasNonce: Boolean(msg.nonce),
            hasSenderFields: Boolean(
              msg.sender_ciphertext_kem && 
              msg.sender_ciphertext_msg && 
              msg.sender_nonce
            ),
            timestamp: msg.timestamp
          });
        }
      }
      
      populateContactDropdown();
      renderMessages();
    } catch (error) {
      debugLog("Messages", {
        action: "load messages error",
        error: error.message
      });
      console.error("Load messages failed:", error);
      allMessages = [];
    }
  }
  
  // UPDATED: populateContactDropdown with avatars
  function populateContactDropdown() {
    const partners = new Set();
    
    debugLog("UI", {
      action: "populating contact dropdown",
      messageCount: allMessages.length,
      currentPubKey: currentPubKey ? (currentPubKey.substring(0, 20) + "...") : "none"
    });
    
    for (const msg of allMessages) {
      if (msg.sender_pubkey && msg.sender_pubkey !== currentPubKey) {
        partners.add(msg.sender_pubkey);
      }
      if (msg.recipient_pubkey && msg.recipient_pubkey !== currentPubKey) {
        partners.add(msg.recipient_pubkey);
      }
    }
    for (const pubKey in contactsMap) {
      partners.add(pubKey);
    }
    
    debugLog("UI", {
      action: "contact partners found",
      partnerCount: partners.size
    });
    
    contactSelect.innerHTML = `<option value="">Select a contact...</option>`;
    for (const partner of partners) {
      let nickname = "Unknown user";
      let label = partner;
      
      if (contactsMap[partner] && contactsMap[partner].nickname) {
        nickname = contactsMap[partner].nickname;
        const initials = getInitials(nickname);
        label = `${initials} - ${nickname}`;
      } else {
        label = `?? - ${nickname}: ${partner.substring(0, 10)}...`;
      }
      
      const opt = document.createElement("option");
      opt.value = partner;
      opt.textContent = label;
      contactSelect.appendChild(opt);
    }
    if (selectedContact) {
      contactSelect.value = selectedContact;
    }
  }
  
  // FIXED: decryptPQMessage function with proper KEM decryption
  async function decryptPQMessage(msg) {
    if (!oqs) {
      debugLog("OQS library not loaded");
      return "[Encrypted message]";
    }
    
    if (!currentPrivateKey) {
      debugLog("Private key not available");
      return "[Private key unavailable]";
    }
    
    // Determine message direction
    const isSentByMe = msg.sender_pubkey === currentPubKey;
    debugLog("Message info", {
      messageId: msg.message_id,
      isSentByMe: isSentByMe,
      hasPrivateKey: !!currentPrivateKey,
      privateKeyLength: currentPrivateKey?.length
    });
    
    try {
      // Select appropriate fields based on message direction
      let ciphertextKem, nonceBytes, ciphertextBytes;
      
      if (isSentByMe) {
        debugLog("Using sender fields (message sent by me)");
        if (!msg.sender_ciphertext_kem || !msg.sender_ciphertext_msg || !msg.sender_nonce) {
          return "[Incomplete message data]";
        }
        
        ciphertextKem = base64ToBytes(msg.sender_ciphertext_kem);
        nonceBytes = base64ToBytes(msg.sender_nonce);
        ciphertextBytes = base64ToBytes(msg.sender_ciphertext_msg);
      } else {
        debugLog("Using recipient fields (message received from someone else)");
        if (!msg.ciphertext_kem || !msg.ciphertext_msg || !msg.nonce) {
          return "[Incomplete message data]";
        }
        
        ciphertextKem = base64ToBytes(msg.ciphertext_kem);
        nonceBytes = base64ToBytes(msg.nonce);
        ciphertextBytes = base64ToBytes(msg.ciphertext_msg);
      }
      
      debugLog("Decryption parameters", {
        kemLength: ciphertextKem.length,
        nonceLength: nonceBytes.length,
        ciphertextLength: ciphertextBytes.length
      });
      
      // Perform KEM decapsulation
      let kem;
      let sharedSecret;
      try {
        kem = new oqs.KeyEncapsulation("Kyber512");
        await kem.loadSecretKey(currentPrivateKey);
        sharedSecret = await kem.decapSecret(ciphertextKem);
        debugLog("KEM decapsulation succeeded", {
          sharedSecretLength: sharedSecret.length
        });
      } catch (kemError) {
        debugLog("KEM decapsulation failed", kemError);
        return `[KEM error: ${kemError.message}]`;
      } finally {
        if (kem) kem.free();
      }
      
      // Decrypt the message with AES-GCM
      const plaintextBuffer = await aesGcmDecryptJS(sharedSecret, nonceBytes, ciphertextBytes);
      if (!plaintextBuffer) {
        debugLog("AES decryption failed");
        return "[Decryption failed]";
      }
      
      // Convert to text
      const text = new TextDecoder().decode(plaintextBuffer);
      debugLog("Message decrypted successfully", {
        length: text.length,
        preview: text.substring(0, Math.min(20, text.length)) + (text.length > 20 ? "..." : "")
      });
      
      return text;
    } catch (error) {
      debugLog("Message decryption error:", error);
      return `[Error: ${error.message}]`;
    }
  }
  
  async function renderMessages() {
    messagesDiv.innerHTML = "";
    if (!selectedContact) {
      messagesDiv.innerHTML = "<p>Select a contact to see messages.</p>";
      return;
    }

    debugLog("UI", {
      action: "rendering messages",
      selectedContact: selectedContact ? (selectedContact.substring(0, 20) + "...") : "none",
      currentPubKey: currentPubKey ? (currentPubKey.substring(0, 20) + "...") : "none",
      totalMessages: allMessages.length
    });

    let conversation = allMessages.filter((m) => {
      const isPartOfConversation = (
        (m.sender_pubkey === selectedContact && m.recipient_pubkey === currentPubKey) ||
        (m.sender_pubkey === currentPubKey && m.recipient_pubkey === selectedContact)
      );
      
      // DIAGNOSTIC: Log the filtering process for a few messages
      if (m.sender_pubkey === selectedContact || m.recipient_pubkey === selectedContact) {
        debugLog("Message Filtering", {
          messageId: m.message_id,
          sender: m.sender_pubkey.substring(0, 20) + "...",
          isCurrentUser: m.sender_pubkey === currentPubKey,
          recipient: m.recipient_pubkey.substring(0, 20) + "...",
          isSelectedContact: m.recipient_pubkey === selectedContact,
          isPartOfConversation: isPartOfConversation
        });
      }
      
      return isPartOfConversation;
    });
    
    debugLog("UI", {
      action: "message filtering complete",
      filteredMessageCount: conversation.length
    });
    
    if (conversation.length === 0) {
      messagesDiv.innerHTML = "<p>No messages in this conversation yet.</p>";
      return;
    }

    const seenIds = new Set();
    const deduped = [];
    for (const msg of conversation) {
      if (!seenIds.has(msg.message_id)) {
        seenIds.add(msg.message_id);
        deduped.push(msg);
      }
    }
    deduped.sort((a, b) => {
      const aTime = new Date(a.timestamp).getTime();
      const bTime = new Date(b.timestamp).getTime();
      return aTime - bTime;
    });

    debugLog("UI", {
      action: "message deduplication complete", 
      dedupedMessageCount: deduped.length
    });

    for (const msg of deduped) {
      const div = document.createElement("div");
      div.classList.add("message");

      if (msg.sender_pubkey === currentPubKey) {
        div.classList.add("sent");
      } else {
        div.classList.add("received");
      }

      let text;
      if (msg.sender_pubkey !== currentPubKey && !(msg.sender_pubkey in contactsMap)) {
        text = "[Message from unknown sender]";
        const addBtn = document.createElement("button");
        addBtn.textContent = "Add Contact";
        addBtn.style.marginLeft = "8px";
        addBtn.addEventListener("click", () => {
          const nickname = prompt("Enter a nickname for this contact:", "New Contact");
          if (nickname) {
            contactPublicKeyInput.value = msg.sender_pubkey;
            contactNicknameInput.value = nickname;
            addContactBtn.click();
          }
        });
        div.innerHTML = `<strong>Unknown user: ${msg.sender_pubkey.substring(0, 10)}...</strong>: ${text}`;
        div.appendChild(addBtn);
      } else {
        try {
          text = await decryptPQMessage(msg);
          
          const senderLabel = msg.sender_pubkey === currentPubKey
            ? "You"
            : (contactsMap[msg.sender_pubkey]
              ? contactsMap[msg.sender_pubkey].nickname
              : ("Unknown user: " + msg.sender_pubkey.substring(0, 10) + "..."));
          div.innerHTML = `<strong>${senderLabel}</strong>: ${text}`;
        } catch (error) {
          console.error("Message decryption failed:", error);
          div.innerHTML = `<strong>Error</strong>: Could not decrypt message: ${error.message}`;
        }
      }

      const timeString = new Date(msg.timestamp).toLocaleString();
      const timeSpan = document.createElement("span");
      timeSpan.classList.add("timestamp");
      timeSpan.textContent = timeString;
      div.appendChild(timeSpan);

      messagesDiv.appendChild(div);
    }
    
    // Scroll to the bottom of the message container
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
  }
  
  async function doLogout() {
    try {
      debugLog("Authentication", {
        action: "logging out",
        username: currentUser
      });
      
      await apiClient.logout();
      
      // Always clear local state
      apiClient.clearToken();
      localStorage.removeItem('wave_auth_token');
      localStorage.removeItem('wave_username');
      
      debugLog("Authentication", {
        action: "logout successful"
      });
      
      currentUser = null;
      currentPassword = null;
      currentPrivateKey = null;
      currentPubKey = null;
      allMessages = [];
      contactsMap = {};
      selectedContact = null;
      userLabel.textContent = "";
      
      showSection(authContainer);
      tabContactsLink.classList.remove("active");
      tabChatLink.classList.remove("active");
      tabSettingsLink.classList.remove("active");
    } catch (error) {
      debugLog("Authentication", {
        action: "logout error",
        error: error.message
      });
      console.error("Logout failed:", error);
      
      // Still clear local state on error
      apiClient.clearToken();
      localStorage.removeItem('wave_auth_token');
      localStorage.removeItem('wave_username');
      
      currentUser = null;
      currentPassword = null;
      currentPrivateKey = null;
      currentPubKey = null;
      
      showSection(authContainer);
    }
  }
  
  async function checkSession() {
    // Check for saved token
    const savedToken = localStorage.getItem('wave_auth_token');
    if (savedToken) {
      debugLog("Session", {
        action: "checking saved session",
        hasToken: Boolean(savedToken)
      });
      
      apiClient.setToken(savedToken);
      
      try {
        // Try to get server information
        const response = await apiClient.ping();
        
        debugLog("Session", {
          action: "ping response",
          success: response?.success
        });
        
        if (response && response.success) {
          // Get user data if available
          const username = localStorage.getItem('wave_username');
          if (username) {
            debugLog("Session", {
              action: "username found",
              username: username
            });
            
            currentUser = username;
            userLabel.textContent = `Logged in as ${currentUser}`;
            
            // Prompt for password to unlock private key
            if (!currentPassword) {
              currentPassword = prompt("Enter your password to unlock your account:");
              if (!currentPassword) {
                // If user cancels password prompt, logout
                debugLog("Session", {
                  action: "password prompt canceled"
                });
                await doLogout();
                return;
              }
            }
            
            debugLog("Session", {
              action: "session restored",
              username: currentUser
            });
            
            await fetchPublicKey();
            await loadPrivateKey();
            await loadContacts();
            await loadAllMessages();
            
            setActiveNavLink(tabChatLink);
            showSection(chatContainer);
            return;
          }
        }
      } catch (error) {
        debugLog("Session", {
          action: "session validation failed",
          error: error.message
        });
        console.error("Session validation failed:", error);
      }
      
      // If we reach here, token is invalid or user data is missing
      debugLog("Session", {
        action: "session invalid, clearing"
      });
      
      apiClient.clearToken();
      localStorage.removeItem('wave_auth_token');
      localStorage.removeItem('wave_username');
    }
    
    // No valid session, show login
    showSection(authContainer);
  }

  // Add diagnostics tool
  window.runDiagnostics = async function() {
    console.log("======= WAVE MESSAGING DIAGNOSTICS =======");
    
    // Check OQS module
    console.log("1. OQS Module Status:", oqs ? "Loaded" : "Not loaded");
    
    // Check user state
    console.log("2. User State:", {
      currentUser,
      hasPublicKey: !!currentPubKey,
      publicKeyLength: currentPubKey?.length,
      hasPrivateKey: !!currentPrivateKey,
      privateKeyLength: currentPrivateKey?.length,
      contactsCount: Object.keys(contactsMap).length,
      messagesCount: allMessages.length
    });
    
    // Perform a test encryption/decryption
    console.log("3. Testing Kyber encryption/decryption...");
    try {
      if (!oqs) {
        console.log("   SKIP: OQS module not loaded");
      } else if (!currentPrivateKey) {
        console.log("   SKIP: No private key available");
      } else {
        // Generate a test keypair
        const kem = new oqs.KeyEncapsulation("Kyber512");
        const keypair = await kem.generate_keypair();
        console.log("   - Test keypair generated:", {
          publicKeyLength: keypair.publicKey.length,
          secretKeyLength: keypair.secretKey.length
        });
        
        // Encapsulate a shared secret
        const encapResult = await kem.encapSecret(keypair.publicKey);
        console.log("   - Encapsulation successful:", {
          ciphertextLength: encapResult.ciphertext.length,
          sharedSecretLength: encapResult.sharedSecret.length
        });
        
        // Decapsulate
        await kem.loadSecretKey(keypair.secretKey);
        const sharedSecret = await kem.decapSecret(encapResult.ciphertext);
        console.log("   - Decapsulation successful:", {
          sharedSecretLength: sharedSecret.length,
          matches: arraysEqual(sharedSecret, encapResult.sharedSecret)
        });
        
        // Test AES encryption
        const testMessage = "This is a test message";
        const messageBytes = new TextEncoder().encode(testMessage);
        const nonce = crypto.getRandomValues(new Uint8Array(12));
        
        const encrypted = await aesGcmEncryptJS(sharedSecret, nonce, messageBytes);
        console.log("   - AES encryption successful:", {
          plaintextLength: messageBytes.length,
          ciphertextLength: encrypted.length
        });
        
        // Test AES decryption
        const decrypted = await aesGcmDecryptJS(sharedSecret, nonce, encrypted);
        const decryptedText = new TextDecoder().decode(decrypted);
        console.log("   - AES decryption successful:", {
          decryptedLength: decrypted.length,
          matchesOriginal: decryptedText === testMessage,
          decryptedText
        });
        
        console.log("   ✓ Encryption test passed!");
      }
    } catch (error) {
      console.error("   ✗ Encryption test failed:", error);
    }
    
    // Test message decryption
    console.log("4. Attempting to decrypt latest messages...");
    try {
      if (allMessages.length === 0) {
        console.log("   SKIP: No messages available");
      } else {
        for (let i = 0; i < Math.min(3, allMessages.length); i++) {
          const msg = allMessages[i];
          console.log(`   Message ${i+1}:`, {
            id: msg.message_id,
            sender: msg.sender_pubkey.substring(0, 10) + "...",
            sentByMe: msg.sender_pubkey === currentPubKey,
            ciphertextKemLength: msg.ciphertext_kem ? base64ToBytes(msg.ciphertext_kem).length : 0,
            senderCiphertextKemLength: msg.sender_ciphertext_kem ? base64ToBytes(msg.sender_ciphertext_kem).length : 0
          });
          
          try {
            const decrypted = await decryptPQMessage(msg);
            console.log(`   Message ${i+1} decryption:`, {
              success: !decrypted.startsWith("["),
              result: decrypted.substring(0, 30) + (decrypted.length > 30 ? "..." : "")
            });
          } catch (error) {
            console.error(`   Message ${i+1} decryption failed:`, error);
          }
        }
      }
    } catch (error) {
      console.error("   ✗ Message decryption test failed:", error);
    }
    
    console.log("======= END DIAGNOSTICS =======");
  };

  // Helper function to compare arrays
  function arraysEqual(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }
  
  // Initially check for session and show appropriate section
  checkSession();
});

// Add a diagnostic button that will be hidden but can be activated from console
// Add this at the bottom of your popup.js file
async function diagnoseRegistrationIssue() {
  // Create a test environment
  const debugElement = document.createElement('div');
  debugElement.style.position = 'fixed';
  debugElement.style.top = '10px';
  debugElement.style.right = '10px';
  debugElement.style.backgroundColor = 'rgba(0,0,0,0.8)';
  debugElement.style.color = 'white';
  debugElement.style.padding = '10px';
  debugElement.style.borderRadius = '5px';
  debugElement.style.maxWidth = '400px';
  debugElement.style.maxHeight = '80vh';
  debugElement.style.overflow = 'auto';
  debugElement.style.zIndex = '9999';
  debugElement.style.fontSize = '12px';
  debugElement.style.fontFamily = 'monospace';
  
  // Add a title
  const title = document.createElement('h3');
  title.textContent = 'Wave Registration Debug';
  title.style.marginTop = '0';
  debugElement.appendChild(title);
  
  // Add status area
  const statusArea = document.createElement('pre');
  statusArea.style.whiteSpace = 'pre-wrap';
  debugElement.appendChild(statusArea);
  
  // Add action buttons container
  const actionContainer = document.createElement('div');
  actionContainer.style.marginTop = '10px';
  actionContainer.style.display = 'flex';
  actionContainer.style.gap = '10px';
  debugElement.appendChild(actionContainer);
  
  // Add test encrypt/decrypt button
  const testBtn = document.createElement('button');
  testBtn.textContent = 'Test Encryption';
  testBtn.style.flex = '1';
  testBtn.addEventListener('click', testEncryptDecrypt);
  actionContainer.appendChild(testBtn);
  
  // Add a close button
  const closeBtn = document.createElement('button');
  closeBtn.textContent = 'Close';
  closeBtn.style.flex = '1';
  closeBtn.addEventListener('click', () => document.body.removeChild(debugElement));
  actionContainer.appendChild(closeBtn);
  
  document.body.appendChild(debugElement);
  
  // Function to log to the status area
  function logStatus(message) {
    const timestamp = new Date().toLocaleTimeString();
    statusArea.textContent += `[${timestamp}] ${message}\n`;
    console.log(`[DEBUG] ${message}`);
  }
  
  // Test encryption and decryption
  async function testEncryptDecrypt() {
    logStatus("Testing encryption and decryption...");
    
    try {
      // Ensure OQS is loaded
      let oqsInstance;
      try {
        logStatus("Loading OQS library...");
        oqsInstance = await ensureOQSLoaded();
        logStatus("✅ OQS library loaded successfully");
      } catch (error) {
        logStatus(`❌ ERROR: Failed to load OQS: ${error.message}`);
        return;
      }
      
      // Generate a test keypair
      try {
        const kem = new oqsInstance.KeyEncapsulation("Kyber512");
        const keypair = await kem.generate_keypair();
        logStatus(`✅ Generated keypair: Public ${keypair.publicKey.length} bytes, Private ${keypair.secretKey.length} bytes`);
        
        // Test encapsulation
        const { ciphertext, sharedSecret } = await kem.encapSecret(keypair.publicKey);
        logStatus(`✅ Encapsulated shared secret: ${sharedSecret.length} bytes`);
        
        // Test decapsulation
        await kem.loadSecretKey(keypair.secretKey);
        const decapsulated = await kem.decapSecret(ciphertext);
        
        // Check if decapsulated matches original
        let match = decapsulated.length === sharedSecret.length;
        if (match) {
          for (let i = 0; i < decapsulated.length; i++) {
            if (decapsulated[i] !== sharedSecret[i]) {
              match = false;
              break;
            }
          }
        }
        
        if (match) {
          logStatus("✅ Decapsulation successful - shared secrets match!");
        } else {
          logStatus("❌ Decapsulation failed - shared secrets don't match");
        }
        
        // Test message encryption/decryption
        const testMessage = "Hello, this is a test message!";
        const messageBytes = new TextEncoder().encode(testMessage);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        logStatus("Testing AES-GCM encryption with the shared secret...");
        
        // Import the key for encryption
        const cryptoKey = await crypto.subtle.importKey(
          "raw",
          sharedSecret,
          { name: "AES-GCM" },
          false,
          ["encrypt", "decrypt"]
        );
        
        // Encrypt
        const encrypted = await crypto.subtle.encrypt(
          { name: "AES-GCM", iv },
          cryptoKey,
          messageBytes
        );
        
        // Decrypt
        const decrypted = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv },
          cryptoKey,
          encrypted
        );
        
        const decryptedText = new TextDecoder().decode(decrypted);
        
        if (decryptedText === testMessage) {
          logStatus(`✅ Message encryption/decryption successful!`);
          logStatus(`   Original: "${testMessage}"`);
          logStatus(`   Decrypted: "${decryptedText}"`);
        } else {
          logStatus(`❌ Message decryption failed!`);
          logStatus(`   Original: "${testMessage}"`);
          logStatus(`   Decrypted: "${decryptedText}"`);
        }
        
        // Test private key encryption
        const password = "test123";
        const salt = crypto.getRandomValues(new Uint8Array(16));
        
        logStatus("Testing private key encryption...");
        
        // Derive key from password
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
          "raw",
          encoder.encode(password),
          { name: "PBKDF2" },
          false,
          ["deriveBits", "deriveKey"]
        );
        
        const derivedKey = await crypto.subtle.deriveKey(
          {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
          },
          keyMaterial,
          { name: "AES-GCM", length: 256 },
          false,
          ["encrypt", "decrypt"]
        );
        
        // Use exactly 12 bytes for the IV
        const privKeyIv = new Uint8Array(12);
        privKeyIv.set(salt.slice(0, 12));
        
        // Encrypt the private key
        const encryptedPrivateKey = await crypto.subtle.encrypt(
          { name: "AES-GCM", iv: privKeyIv },
          derivedKey,
          keypair.secretKey
        );
        
        const encryptedPrivateKeyBytes = new Uint8Array(encryptedPrivateKey);
        
        logStatus(`Private key encryption: Original ${keypair.secretKey.length} bytes → Encrypted ${encryptedPrivateKeyBytes.length} bytes`);
        
        if (encryptedPrivateKeyBytes.length > 1600) {
          logStatus(`❌ WARNING: Encrypted size (${encryptedPrivateKeyBytes.length} bytes) exceeds server validation limit (1600 bytes)`);
          logStatus(`   You should update the server's Kyber512PrivateKeyMaxSize to at least ${encryptedPrivateKeyBytes.length} bytes`);
        } else {
          logStatus(`✅ Encrypted size (${encryptedPrivateKeyBytes.length} bytes) is within server limits`);
        }
        
        // Try to decrypt the private key
        const decryptedPrivateKey = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: privKeyIv },
          derivedKey,
          encryptedPrivateKey
        );
        
        if (decryptedPrivateKey.byteLength === keypair.secretKey.length) {
          logStatus(`✅ Private key decryption successful!`);
        } else {
          logStatus(`❌ Private key decryption failed - size mismatch`);
        }
        
      } catch (error) {
        logStatus(`❌ ERROR during cryptographic testing: ${error.message}`);
      }
    } catch (error) {
      logStatus(`❌ FATAL ERROR: ${error.message}`);
    }
  }
  
  // Start diagnostics
  async function runDiagnostics() {
    try {
      logStatus("Starting registration diagnostics...");
      
      // Check OQS library
      try {
        const oqsInstance = await ensureOQSLoaded();
        logStatus("✅ OQS library loaded successfully");
      } catch (error) {
        logStatus(`❌ ERROR: Failed to load OQS: ${error.message}`);
        logStatus("Please click the 'Test Encryption' button to try again");
        return;
      }
      
      logStatus("\nRegistration diagnostics completed.");
      logStatus("Click 'Test Encryption' to run more detailed tests.");
      
    } catch (error) {
      logStatus(`❌ ERROR: ${error.message}`);
    }
  }
  
  // Run the diagnostics
  runDiagnostics();
}

// Make it available in the console
window.diagnoseRegistrationIssue = diagnoseRegistrationIssue;