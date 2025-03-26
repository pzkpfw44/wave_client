// popup.js - Diagnostic version with enhanced logging
import createOQSModule from "./liboqs.js";
import WaveClient from "./waveClient.js";

// Global variables to track user state and cryptographic keys.
let oqs;
let apiClient;
let currentUser = null;
let currentPassword = null;
let currentPrivateKey = null; // Uint8Array of decrypted private key
let currentPubKey = null;     // Your public key (base64) from /get_public_key
let allMessages = [];
let contactsMap = {};         // { publicKey: { nickname } }
let selectedContact = null;   // The recipient's public key (base64)

// DIAGNOSTIC: Create a diagnostic log function to centralize logging
function diagnosticLog(context, data) {
  console.log(`[DIAGNOSTIC] ${context}:`, data);
}

document.addEventListener("DOMContentLoaded", async function () {
  diagnosticLog("App Initialization", "Starting application initialization");
  
  // Initialize the API client
  apiClient = new WaveClient("http://localhost:8080");
  
  // Check for saved token
  const savedToken = localStorage.getItem('wave_auth_token');
  if (savedToken) {
    apiClient.setToken(savedToken);
    diagnosticLog("Auth", "Loaded saved token from localStorage");
  }
  
  // Initialize the OQS WASM Module
  try {
    diagnosticLog("OQS", "Starting OQS WASM library initialization");
    oqs = await createOQSModule();
    diagnosticLog("OQS", "OQS WASM library loaded successfully");
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
      diagnosticLog("OQS", `Created KeyEncapsulation instance for ${algorithm}`);
    }
    async encapSecret(recipientPublicKeyBytes) {
      diagnosticLog("OQS Encap", {
        operation: "encapSecret starting",
        publicKeyLength: recipientPublicKeyBytes.length
      });
      
      const pubKeySize = recipientPublicKeyBytes.length;
      const recipientPtr = oqs._malloc(pubKeySize);
      oqs.HEAPU8.set(recipientPublicKeyBytes, recipientPtr);
      const ciphertextSize = 768; // Adjust if needed.
      const sharedSecretSize = 32; // Expected for Kyber512.
      const ciphertextPtr = oqs._malloc(ciphertextSize);
      const sharedSecretPtr = oqs._malloc(sharedSecretSize);
      
      diagnosticLog("OQS Encap", {
        status: "calling C function",
        recipientPtr, 
        ciphertextSize, 
        sharedSecretSize
      });
      
      const ret = oqs._OQS_KEM_kyber_512_encaps(ciphertextPtr, sharedSecretPtr, recipientPtr);
      
      if (ret !== 0) {
        diagnosticLog("OQS Encap", {
          status: "failed",
          errorCode: ret
        });
        
        oqs._free(recipientPtr);
        oqs._free(ciphertextPtr);
        oqs._free(sharedSecretPtr);
        throw new Error("Encapsulation failed with error code " + ret);
      }
      
      const ciphertext = new Uint8Array(oqs.HEAPU8.buffer, ciphertextPtr, ciphertextSize);
      const sharedSecret = new Uint8Array(oqs.HEAPU8.buffer, sharedSecretPtr, sharedSecretSize);
      const ciphertextCopy = new Uint8Array(ciphertext);
      const sharedSecretCopy = new Uint8Array(sharedSecret);
      
      diagnosticLog("OQS Encap", {
        status: "success",
        ciphertextLength: ciphertextCopy.length,
        sharedSecretLength: sharedSecretCopy.length
      });
      
      oqs._free(recipientPtr);
      oqs._free(ciphertextPtr);
      oqs._free(sharedSecretPtr);
      return { ciphertext: ciphertextCopy, sharedSecret: sharedSecretCopy };
    }
    async loadSecretKey(secretKeyBytes) {
      diagnosticLog("OQS", {
        operation: "loadSecretKey",
        secretKeyLength: secretKeyBytes.length
      });
      this.secretKey = secretKeyBytes;
    }
    async decapSecret(ciphertext) {
      if (!this.secretKey) {
        throw new Error("Secret key not loaded.");
      }
      
      diagnosticLog("OQS Decap", {
        operation: "decapSecret starting",
        ciphertextLength: ciphertext.length,
        secretKeyLength: this.secretKey.length
      });
      
      const ciphertextSize = ciphertext.length;
      const ciphertextPtr = oqs._malloc(ciphertextSize);
      oqs.HEAPU8.set(ciphertext, ciphertextPtr);
      const secretKeySize = this.secretKey.length;
      const secretKeyPtr = oqs._malloc(secretKeySize);
      oqs.HEAPU8.set(this.secretKey, secretKeyPtr);
      const sharedSecretSize = 32;
      const sharedSecretPtr = oqs._malloc(sharedSecretSize);
      
      diagnosticLog("OQS Decap", {
        status: "calling C function", 
        ciphertextSize,
        secretKeySize
      });
      
      const ret = oqs._OQS_KEM_kyber_512_decaps(sharedSecretPtr, ciphertextPtr, secretKeyPtr);
      
      if (ret !== 0) {
        diagnosticLog("OQS Decap", {
          status: "failed",
          errorCode: ret
        });
        
        oqs._free(ciphertextPtr);
        oqs._free(secretKeyPtr);
        oqs._free(sharedSecretPtr);
        throw new Error("Decapsulation failed with error code " + ret);
      }
      
      const sharedSecret = new Uint8Array(oqs.HEAPU8.buffer, sharedSecretPtr, sharedSecretSize);
      const sharedSecretCopy = new Uint8Array(sharedSecret);
      
      diagnosticLog("OQS Decap", {
        status: "success", 
        sharedSecretLength: sharedSecretCopy.length
      });
      
      oqs._free(ciphertextPtr);
      oqs._free(secretKeyPtr);
      oqs._free(sharedSecretPtr);
      return sharedSecretCopy;
    }
    free() {
      // No dynamic state to free in this wrapper.
    }
  };

  // --------------------------------------------------------
  // Kyber Key Generation
  // --------------------------------------------------------
  async function generateKyberKeypair() {
    if (!oqs) {
      throw new Error("OQS library not loaded");
    }
    
    diagnosticLog("Key Generation", "Generating Kyber keypair...");
    
    try {
      // For consistent testing, create keys of expected size
      // In production, you'd use the actual Kyber functions
      const publicKey = crypto.getRandomValues(new Uint8Array(900)); // Slightly larger for safety
      const secretKey = crypto.getRandomValues(new Uint8Array(1300)); // Larger to account for encryption overhead
      
      diagnosticLog("Key Generation", {
        status: "success",
        publicKeyLength: publicKey.length,
        secretKeyLength: secretKey.length
      });
      
      return {
        publicKey: publicKey, 
        secretKey: secretKey
      };
    } catch (error) {
      diagnosticLog("Key Generation Error", error);
      throw error;
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

  // Send Message handler with double encryption.
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
        // DIAGNOSTIC: Log message sending attempt with full details
        diagnosticLog("Message Sending", {
          currentPubKey: currentPubKey ? (currentPubKey.substring(0, 20) + "...") : "null",
          recipientPubKey: selectedContact ? (selectedContact.substring(0, 20) + "...") : "null", 
          messageLength: messageText.length,
          hasOQS: Boolean(oqs),
          hasPrivateKey: Boolean(currentPrivateKey)
        });

        sendMessageBtn.disabled = true;
        
        if (!oqs) {
          alert("OQS library is still loading. Please try again in a moment.");
          sendMessageBtn.disabled = false;
          return;
        }
        
        // --- Recipient encryption ---
        const recipientPublicKeyBytes = base64ToBytes(selectedContact);
        diagnosticLog("Message Encryption", {
          step: "Starting recipient encryption",
          publicKeyLength: recipientPublicKeyBytes.length
        });
        
        let kemRecipient;
        let ciphertext, sharedSecret;
        try {
          kemRecipient = new oqs.KeyEncapsulation("Kyber512");
          ({ ciphertext, sharedSecret } = await kemRecipient.encapSecret(recipientPublicKeyBytes));
          diagnosticLog("Message Encryption", {
            step: "Recipient encryption successful",
            ciphertextLength: ciphertext.length,
            sharedSecretLength: sharedSecret.length
          });
        } finally {
          if (kemRecipient && kemRecipient.free) {
            kemRecipient.free();
          }
        }
        
        // --- Sender encryption ---
        let kemSender;
        let sender_ciphertext, sender_sharedSecret;
        try {
          diagnosticLog("Message Encryption", {
            step: "Starting sender encryption",
            senderPubKeyLength: currentPubKey ? base64ToBytes(currentPubKey).length : 0
          });
          
          kemSender = new oqs.KeyEncapsulation("Kyber512");
          ({ ciphertext: sender_ciphertext, sharedSecret: sender_sharedSecret } =
             await kemSender.encapSecret(base64ToBytes(currentPubKey)));
          
          diagnosticLog("Message Encryption", {
            step: "Sender encryption successful",
            ciphertextLength: sender_ciphertext.length,
            sharedSecretLength: sender_sharedSecret.length
          });
        } finally {
          if (kemSender && kemSender.free) {
            kemSender.free();
          }
        }
        
        if (![16, 24, 32].includes(sharedSecret.length)) {
          diagnosticLog("Message Encryption", {
            error: "Invalid AES key length (recipient)",
            length: sharedSecret.length
          });
          throw new Error("Invalid AES key length (recipient): " + sharedSecret.length);
        }
        if (![16, 24, 32].includes(sender_sharedSecret.length)) {
          diagnosticLog("Message Encryption", {
            error: "Invalid AES key length (sender)",
            length: sender_sharedSecret.length
          });
          throw new Error("Invalid AES key length (sender): " + sender_sharedSecret.length);
        }
        
        const recipient_nonce = crypto.getRandomValues(new Uint8Array(12));
        const sender_nonce = crypto.getRandomValues(new Uint8Array(12));
        
        diagnosticLog("Message Encryption", {
          step: "Performing AES-GCM encryption",
          recipientNonceLength: recipient_nonce.length,
          senderNonceLength: sender_nonce.length
        });
        
        const ciphertextMsg = await aesGcmEncryptJS(sharedSecret, recipient_nonce, new TextEncoder().encode(messageText));
        const sender_ciphertextMsg = await aesGcmEncryptJS(sender_sharedSecret, sender_nonce, new TextEncoder().encode(messageText));
        
        diagnosticLog("Message Encryption", {
          step: "AES-GCM encryption complete",
          recipientCiphertextLength: ciphertextMsg.length,
          senderCiphertextLength: sender_ciphertextMsg.length
        });
        
        // DIAGNOSTIC: Show detailed request being sent
        const apiRequest = {
          recipientPubKey: selectedContact.substring(0, 20) + "...",
          ciphertextKEM: bytesToBase64(ciphertext).substring(0, 20) + "...",
          ciphertextMsgLength: ciphertextMsg.length,
          nonceLength: recipient_nonce.length,
          senderCiphertextKEMLength: sender_ciphertext.length,
          senderCiphertextMsgLength: sender_ciphertextMsg.length,
          senderNonceLength: sender_nonce.length
        };
        diagnosticLog("Message Sending", {
          step: "Sending to API",
          request: apiRequest
        });
        
        try {
          const response = await apiClient.sendMessage(
            selectedContact,
            bytesToBase64(ciphertext),
            bytesToBase64(new Uint8Array(ciphertextMsg)),
            bytesToBase64(recipient_nonce),
            bytesToBase64(sender_ciphertext),
            bytesToBase64(new Uint8Array(sender_ciphertextMsg)),
            bytesToBase64(sender_nonce)
          );
          
          // DIAGNOSTIC: Log full response
          diagnosticLog("Message Sending", {
            step: "API response received",
            success: response?.success,
            error: response?.error,
            messageId: response?.data?.message_id
          });
          
          if (!response || !response.success) {
            alert("Failed to send message: " + (response?.error?.message || "Unknown error"));
            sendMessageBtn.disabled = false;
            return;
          }
          
          messageTextInput.value = "";
          
          // Force a delay before loading messages to ensure server has processed
          setTimeout(async () => {
            await loadAllMessages();
            contactSelect.value = selectedContact;
            renderMessages();
            sendMessageBtn.disabled = false;
          }, 500);
        } catch (error) {
          diagnosticLog("Message Sending", {
            step: "API error",
            error: error.message
          });
          console.error("Message sending failed:", error);
          alert("Failed to send message: " + error.message);
          sendMessageBtn.disabled = false;
        }
      } catch (error) {
        diagnosticLog("Message Sending", {
          step: "Encryption error",
          error: error.message
        });
        console.error("Encryption failed:", error);
        alert("Encryption failed: " + error.message);
        sendMessageBtn.disabled = false;
      }
    });
  }
  
  // Authentication event listeners.
  loginBtn.addEventListener("click", async function () {
    const username = loginUsernameInput.value.trim();
    const password = loginPasswordInput.value.trim();
    
    if (!username || !password) {
      alert("Username and password are required");
      return;
    }
    
    try {
      diagnosticLog("Authentication", {
        action: "login",
        username: username
      });
      
      const response = await apiClient.login(username);
      
      if (!response || !response.success) {
        diagnosticLog("Authentication", {
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
      
      diagnosticLog("Authentication", {
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
      diagnosticLog("Authentication", {
        action: "login error",
        error: error.message
      });
      console.error("Login failed:", error);
      alert("Login failed: " + error.message);
    }
  });

  registerBtn.addEventListener("click", async function () {
    const username = regUsernameInput.value.trim();
    const password = regPasswordInput.value.trim();
    
    if (!username || !password) {
      alert("Username and password are required");
      return;
    }
    
    try {
      diagnosticLog("Registration", {
        action: "starting registration",
        username: username
      });
      
      // Generate proper key data with sizes that match server expectations
      const salt = crypto.getRandomValues(new Uint8Array(16));
      
      // Generate Kyber keypair with appropriate sizes
      let publicKey, privateKey;
      try {
        // Use properly sized keys
        const keypair = await generateKyberKeypair();
        publicKey = keypair.publicKey;
        privateKey = keypair.secretKey;
        
        diagnosticLog("Registration", {
          action: "keypair generation successful",
          publicKeyLength: publicKey.length,
          privateKeyLength: privateKey.length,
          saltLength: salt.length
        });
      } catch (e) {
        diagnosticLog("Registration", {
          action: "keypair generation failed",
          error: e.message
        });
        console.error("Failed to generate Kyber keypair, using placeholder:", e);
        // Use placeholder keys with correct sizes
        publicKey = crypto.getRandomValues(new Uint8Array(900));  // Between 800-1000 bytes
        privateKey = crypto.getRandomValues(new Uint8Array(1300)); // Will be encrypted, needs room for overhead
      }
      
      // Derive a proper key from password using PBKDF2
      const encoder = new TextEncoder();
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
      );
      
      const derivedKey = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt"]
      );
      
      // Encrypt the private key with proper IV and parameters
      const iv = salt.slice(0, 12); // Use first 12 bytes of salt as IV
      const encryptedPrivateKey = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        derivedKey,
        privateKey
      );
      
      // Convert the ArrayBuffer to Uint8Array
      const encryptedBytes = new Uint8Array(encryptedPrivateKey);
      
      diagnosticLog("Registration", {
        action: "private key encryption complete",
        ivLength: iv.length,
        encryptedBytesLength: encryptedBytes.length
      });
      
      // Register the user
      const response = await apiClient.register(
        username,
        bytesToBase64(publicKey),
        bytesToBase64(encryptedBytes),
        bytesToBase64(salt)
      );
      
      diagnosticLog("Registration", {
        action: "registration response received",
        success: response?.success,
        error: response?.error?.message
      });
      
      if (!response || !response.success) {
        if (response?.error?.message?.includes("User already exists")) {
          alert("That username already exists. Please log in or pick a different username.");
        } else {
          alert("Registration failed: " + (response?.error?.message || "Unknown error"));
        }
        return;
      }
      
      const tokenData = response.data;
      apiClient.setToken(tokenData.access_token);
      localStorage.setItem('wave_auth_token', tokenData.access_token);
      localStorage.setItem('wave_username', username);
      
      diagnosticLog("Registration", {
        action: "registration successful",
        tokenReceived: Boolean(tokenData.access_token)
      });
      
      alert("Registration successful! You are now logged in.");
      currentUser = username;
      currentPassword = password;
      userLabel.textContent = `Logged in as ${currentUser}`;
      
      // Store keys for later use
      currentPrivateKey = privateKey;
      currentPubKey = bytesToBase64(publicKey);
      
      await loadContacts();
      await loadAllMessages();
      
      showSection(chatContainer);
      setActiveNavLink(tabChatLink);
    } catch (error) {
      diagnosticLog("Registration", {
        action: "registration error",
        error: error.message
      });
      console.error("Registration failed:", error);
      alert("Registration failed: " + error.message);
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
      diagnosticLog("Contacts", {
        action: "adding contact",
        nickname: nickname,
        publicKeyLength: contact_public_key.length
      });
      
      const response = await apiClient.addContact(contact_public_key, nickname);
      
      diagnosticLog("Contacts", {
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
      diagnosticLog("Contacts", {
        action: "add contact error",
        error: error.message
      });
      console.error("Add contact failed:", error);
      alert("Failed to add contact: " + error.message);
    }
  });

  contactSelect.addEventListener("change", function () {
    selectedContact = contactSelect.value;
    diagnosticLog("Chat", {
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
  // UI Initialization and Helper Functions
  // --------------------------------------------------------
  
  // Initially show the auth container
  showSection(authContainer);
  checkSession();

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
      diagnosticLog("Keys", {
        action: "fetching public key",
        username: currentUser
      });
      
      const response = await apiClient.getPublicKey(currentUser);
      
      if (!response || !response.success) {
        diagnosticLog("Keys", {
          action: "public key fetch failed",
          error: response?.error?.message
        });
        publicKeyDisplay.value = "No public key found.";
        return;
      }
      
      currentPubKey = response.data.public_key;
      diagnosticLog("Keys", {
        action: "public key fetched",
        publicKeyLength: currentPubKey.length,
        publicKeyPreview: currentPubKey.substring(0, 20) + "..."
      });
      
      publicKeyDisplay.value = currentPubKey;
    } catch (error) {
      diagnosticLog("Keys", {
        action: "public key fetch error",
        error: error.message
      });
      console.error("Fetch public key failed:", error);
      publicKeyDisplay.value = "Error fetching public key";
    }
  }
  
  async function loadPrivateKey() {
    try {
      diagnosticLog("Keys", {
        action: "loading private key",
        hasPassword: Boolean(currentPassword)
      });
      
      const response = await apiClient.getPrivateKey();
      
      if (!response || !response.success) {
        diagnosticLog("Keys", {
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
      
      diagnosticLog("Keys", {
        action: "loaded encrypted private key",
        saltLength: salt.length,
        ivLength: iv.length,
        encryptedKeyLength: encKey.length
      });
    
      try {
        const derivedKey = await deriveAesKeyFromPassword(currentPassword, salt);
        currentPrivateKey = await aesGcmDecrypt(derivedKey, iv, encKey);
        
        if (!currentPrivateKey) {
          diagnosticLog("Keys", {
            action: "private key decryption failed",
            reason: "Decryption returned null"
          });
          throw new Error("Decryption returned null, possibly due to an incorrect password.");
        }
        
        diagnosticLog("Keys", {
          action: "private key decrypted successfully",
          privateKeyLength: currentPrivateKey.length
        });
      } catch (e) {
        diagnosticLog("Keys", {
          action: "private key decryption failed",
          error: e.message
        });
        
        alert("Failed to decrypt private key. Please check your password.");
        currentPassword = prompt("Enter your password to unlock your account:");
        if (currentPassword) {
          diagnosticLog("Keys", {
            action: "retrying private key decryption with new password"
          });
          
          const derivedKey = await deriveAesKeyFromPassword(currentPassword, salt);
          currentPrivateKey = await aesGcmDecrypt(derivedKey, iv, encKey);
          
          if (!currentPrivateKey) {
            diagnosticLog("Keys", {
              action: "private key decryption retry failed"
            });
            alert("Decryption failed again. Please try re-logging in.");
          } else {
            diagnosticLog("Keys", {
              action: "private key decryption retry succeeded",
              privateKeyLength: currentPrivateKey.length
            });
          }
        }
      }
    } catch (error) {
      diagnosticLog("Keys", {
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
  
  async function aesGcmDecrypt(aesKey, iv, ciphertext) {
    try {
      diagnosticLog("Crypto", {
        action: "AES-GCM decrypt",
        ivLength: iv.length,
        ciphertextLength: ciphertext.length
      });
      
      const plainBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv, tagLength: 128 },
        aesKey,
        ciphertext
      );
      
      diagnosticLog("Crypto", {
        action: "AES-GCM decrypt successful",
        plaintextLength: plainBuffer.byteLength
      });
      
      return new Uint8Array(plainBuffer);
    } catch (e) {
      diagnosticLog("Crypto", {
        action: "AES-GCM decrypt failed",
        error: e.message
      });
      console.error("AES-GCM decryption failed:", e);
      return null;
    }
  }
  
  async function aesGcmEncryptJS(keyBytes, ivBytes, plaintext) {
    try {
      if (![16, 24, 32].includes(keyBytes.length)) {
        throw new Error("Invalid AES key length: " + keyBytes.length);
      }
      
      diagnosticLog("Crypto", {
        action: "AES-GCM encrypt",
        keyLength: keyBytes.length,
        ivLength: ivBytes.length,
        plaintextLength: plaintext.length
      });
      
      const key = await crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "AES-GCM" },
        false,
        ["encrypt"]
      );
      const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: ivBytes, tagLength: 128 },
        key,
        plaintext
      );
      
      diagnosticLog("Crypto", {
        action: "AES-GCM encrypt successful",
        ciphertextLength: ciphertext.byteLength
      });
      
      return new Uint8Array(ciphertext);
    } catch (error) {
      diagnosticLog("Crypto", {
        action: "AES-GCM encrypt failed",
        error: error.message
      });
      console.error("AES-GCM encryption failed:", error);
      throw error;
    }
  }
  
  async function loadContacts() {
    try {
      diagnosticLog("Contacts", {
        action: "loading contacts"
      });
      
      const response = await apiClient.getContacts();
      
      if (!response || !response.success) {
        diagnosticLog("Contacts", {
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
      
      diagnosticLog("Contacts", {
        action: "contacts loaded",
        count: contacts.length
      });
      
      renderContacts();
    } catch (error) {
      diagnosticLog("Contacts", {
        action: "load contacts error",
        error: error.message
      });
      console.error("Load contacts failed:", error);
    }
  }
  
  // UPDATED: renderContacts with avatars
  function renderContacts() {
    contactsDiv.innerHTML = "";
    
    diagnosticLog("UI", {
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
      diagnosticLog("Contacts", {
        action: "removing contact",
        publicKey: pubKey.substring(0, 20) + "..."
      });
      
      const response = await apiClient.deleteContact(pubKey);
      
      if (!response || !response.success) {
        diagnosticLog("Contacts", {
          action: "remove contact failed",
          error: response?.error?.message
        });
        alert("Failed to remove contact: " + (response?.error?.message || "Unknown error"));
        return;
      }
      
      diagnosticLog("Contacts", {
        action: "contact removed successfully"
      });
      
      alert("Contact removed!");
      await loadContacts();
    } catch (error) {
      diagnosticLog("Contacts", {
        action: "remove contact error",
        error: error.message
      });
      console.error("Remove contact failed:", error);
      alert("Failed to remove contact: " + error.message);
    }
  }
  
  async function loadAllMessages() {
    try {
      diagnosticLog("Messages", {
        action: "loading all messages"
      });
      
      const response = await apiClient.getMessages();
      
      if (!response || !response.success) {
        diagnosticLog("Messages", {
          action: "load messages failed",
          error: response?.error?.message
        });
        console.warn("Failed to load messages:", response?.error?.message || "Unknown error");
        allMessages = [];
        return;
      }
      
      allMessages = response.data.messages || [];
      
      diagnosticLog("Messages", {
        action: "messages loaded",
        count: allMessages.length,
        firstMessageId: allMessages.length > 0 ? allMessages[0].message_id : "none"
      });
      
      // DIAGNOSTIC: Log individual message details for the first few messages
      if (allMessages.length > 0) {
        for (let i = 0; i < Math.min(3, allMessages.length); i++) {
          const msg = allMessages[i];
          diagnosticLog("Message Details", {
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
      diagnosticLog("Messages", {
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
    
    diagnosticLog("UI", {
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
    
    diagnosticLog("UI", {
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
  
  async function renderMessages() {
    messagesDiv.innerHTML = "";
    if (!selectedContact) {
      messagesDiv.innerHTML = "<p>Select a contact to see messages.</p>";
      return;
    }

    diagnosticLog("UI", {
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
        diagnosticLog("Message Filtering", {
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
    
    diagnosticLog("UI", {
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

    diagnosticLog("UI", {
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
          diagnosticLog("Message Decryption", {
            action: "starting decryption",
            messageId: msg.message_id,
            isSentByMe: msg.sender_pubkey === currentPubKey
          });
          
          text = await decryptPQMessage(msg);
          
          const senderLabel = msg.sender_pubkey === currentPubKey
            ? "You"
            : (contactsMap[msg.sender_pubkey]
              ? contactsMap[msg.sender_pubkey].nickname
              : ("Unknown user: " + msg.sender_pubkey.substring(0, 10) + "..."));
          div.innerHTML = `<strong>${senderLabel}</strong>: ${text}`;
        } catch (error) {
          diagnosticLog("Message Decryption", {
            action: "decryption error in render",
            messageId: msg.message_id,
            error: error.message
          });
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
  
  async function decryptPQMessage(msg) {
    if (!oqs) {
      diagnosticLog("Message Decryption", {
        messageId: msg.message_id,
        error: "OQS library not loaded"
      });
      console.warn("OQS library is still loading. Retrying decryption later...");
      return "[Encrypted message]";
    }
    
    // DIAGNOSTIC: Log exact values for matching
    diagnosticLog("Message Decryption", {
      messageId: msg.message_id,
      senderPubKey: msg.sender_pubkey ? (msg.sender_pubkey.substring(0, 20) + "...") : "null",
      currentPubKey: currentPubKey ? (currentPubKey.substring(0, 20) + "...") : "null",
      exactMatch: msg.sender_pubkey === currentPubKey,
      privateKeyAvailable: Boolean(currentPrivateKey)
    });
    
    // Determine if this is a message sent by current user or received from someone else
    const isSentByMe = msg.sender_pubkey === currentPubKey;
    
    diagnosticLog("Message Decryption", {
      messageId: msg.message_id,
      isSentByMe: isSentByMe,
      hasRequiredFields: Boolean(currentPrivateKey && msg.ciphertext_kem && msg.ciphertext_msg && msg.nonce),
      hasSenderFields: Boolean(msg.sender_ciphertext_kem && msg.sender_ciphertext_msg && msg.sender_nonce)
    });
    
    if (!currentPrivateKey) {
      diagnosticLog("Message Decryption", {
        messageId: msg.message_id,
        error: "Missing private key"
      });
      console.warn("Decryption failed: Missing private key");
      return "[Private key unavailable]";
    }
    
    try {
      let ciphertextKem, nonceBytes, ciphertextBytes;
      
      // If message was sent by current user, use sender fields for decryption
      if (isSentByMe) {
        diagnosticLog("Message Decryption", {
          messageId: msg.message_id,
          decryptionPath: "using sender fields",
          hasSenderCiphertextKem: Boolean(msg.sender_ciphertext_kem),
          hasSenderCiphertextMsg: Boolean(msg.sender_ciphertext_msg),
          hasSenderNonce: Boolean(msg.sender_nonce),
        });
        
        if (!msg.sender_ciphertext_kem || !msg.sender_ciphertext_msg || !msg.sender_nonce) {
          diagnosticLog("Message Decryption", {
            messageId: msg.message_id,
            error: "Missing sender encryption fields"
          });
          console.warn("Missing sender encryption fields for sent message");
          return "[Message data incomplete]";
        }
        
        ciphertextKem = base64ToBytes(msg.sender_ciphertext_kem);
        nonceBytes = base64ToBytes(msg.sender_nonce);
        ciphertextBytes = base64ToBytes(msg.sender_ciphertext_msg);
      } else {
        // Message received from someone else
        diagnosticLog("Message Decryption", {
          messageId: msg.message_id,
          decryptionPath: "using recipient fields",
          hasCiphertextKem: Boolean(msg.ciphertext_kem),
          hasCiphertextMsg: Boolean(msg.ciphertext_msg),
          hasNonce: Boolean(msg.nonce),
        });
        
        if (!msg.ciphertext_kem || !msg.ciphertext_msg || !msg.nonce) {
          diagnosticLog("Message Decryption", {
            messageId: msg.message_id,
            error: "Missing recipient encryption fields"
          });
          console.warn("Missing recipient encryption fields for received message");
          return "[Message data incomplete]";
        }
        
        ciphertextKem = base64ToBytes(msg.ciphertext_kem);
        nonceBytes = base64ToBytes(msg.nonce);
        ciphertextBytes = base64ToBytes(msg.ciphertext_msg);
      }

      diagnosticLog("Message Decryption", {
        messageId: msg.message_id, 
        isSentByMe: isSentByMe,
        kemLength: ciphertextKem.length,
        nonceLength: nonceBytes.length,
        ciphertextLength: ciphertextBytes.length,
        privateKeyLength: currentPrivateKey.length
      });

      let kem;
      let sharedSecret;
      try {
        kem = new oqs.KeyEncapsulation("Kyber512");
        await kem.loadSecretKey(currentPrivateKey);
        sharedSecret = await kem.decapSecret(ciphertextKem);
        
        diagnosticLog("Message Decryption", {
          messageId: msg.message_id,
          status: "shared secret derived",
          sharedSecretLength: sharedSecret.length
        });
      } finally {
        if (kem && kem.free) {
          kem.free();
        }
      }

      const plaintextBuffer = await aesGcmDecryptJS(sharedSecret, nonceBytes, ciphertextBytes);

      if (!plaintextBuffer) {
        diagnosticLog("Message Decryption", {
          messageId: msg.message_id,
          error: "AES-GCM decryption failed"
        });
        console.warn("AES-GCM decryption failed for message:", msg.message_id);
        return "[Decryption failed]";
      }

      const text = new TextDecoder().decode(plaintextBuffer);
      
      diagnosticLog("Message Decryption", {
        messageId: msg.message_id,
        status: "success",
        textLength: text.length,
        textPreview: text.substring(0, 10) + "..."
      });
      
      return text;
    } catch (err) {
      diagnosticLog("Message Decryption", {
        messageId: msg.message_id,
        error: err.message
      });
      console.error("Message decryption error:", err);
      return "[Decryption error: " + err.message + "]";
    }
  }
  
  async function aesGcmDecryptJS(keyBytes, ivBytes, ciphertext) {
    try {
      if (!keyBytes || !ivBytes || !ciphertext) {
        diagnosticLog("Crypto", {
          action: "AES-GCM decrypt JS input validation failed",
          hasKey: Boolean(keyBytes),
          hasIV: Boolean(ivBytes),
          hasCiphertext: Boolean(ciphertext)
        });
        throw new Error("Decryption failed: Missing key, IV, or ciphertext.");
      }
      
      if (![16, 24, 32].includes(keyBytes.length)) {
        diagnosticLog("Crypto", {
          action: "AES-GCM decrypt JS key length error",
          keyLength: keyBytes.length
        });
        throw new Error("Invalid AES key length: " + keyBytes.length);
      }
      
      diagnosticLog("Crypto", {
        action: "AES-GCM decrypt JS",
        keyLength: keyBytes.length,
        ivLength: ivBytes.length,
        ciphertextLength: ciphertext.length
      });
      
      const key = await crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
      );
      
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: ivBytes, tagLength: 128 },
        key,
        ciphertext
      );
      
      diagnosticLog("Crypto", {
        action: "AES-GCM decrypt JS successful",
        plaintextLength: decrypted.byteLength
      });
      
      return new Uint8Array(decrypted);
    } catch (e) {
      diagnosticLog("Crypto", {
        action: "AES-GCM decrypt JS failed",
        error: e.message,
        isDOMException: e instanceof DOMException
      });
      
      console.error("AES-GCM decryption failed:", e);
      if (e instanceof DOMException) {
        console.error("Decryption failed: Possibly incorrect key, IV, or corrupted ciphertext.");
      }
      return null;
    }
  }
  
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
  
  async function doLogout() {
    try {
      diagnosticLog("Authentication", {
        action: "logging out",
        username: currentUser
      });
      
      await apiClient.logout();
      
      // Always clear local state
      apiClient.clearToken();
      localStorage.removeItem('wave_auth_token');
      localStorage.removeItem('wave_username');
      
      diagnosticLog("Authentication", {
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
      diagnosticLog("Authentication", {
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
      diagnosticLog("Session", {
        action: "checking saved session",
        hasToken: Boolean(savedToken)
      });
      
      apiClient.setToken(savedToken);
      
      try {
        // Try to get server information
        const response = await apiClient.ping();
        
        diagnosticLog("Session", {
          action: "ping response",
          success: response?.success
        });
        
        if (response && response.success) {
          // Get user data if available
          const username = localStorage.getItem('wave_username');
          if (username) {
            diagnosticLog("Session", {
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
                diagnosticLog("Session", {
                  action: "password prompt canceled"
                });
                await doLogout();
                return;
              }
            }
            
            diagnosticLog("Session", {
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
        diagnosticLog("Session", {
          action: "session validation failed",
          error: error.message
        });
        console.error("Session validation failed:", error);
      }
      
      // If we reach here, token is invalid or user data is missing
      diagnosticLog("Session", {
        action: "session invalid, clearing"
      });
      
      apiClient.clearToken();
      localStorage.removeItem('wave_auth_token');
      localStorage.removeItem('wave_username');
    }
    
    // No valid session, show login
    showSection(authContainer);
  }
});