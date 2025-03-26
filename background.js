// Listen for messages from other parts of the extension
console.log("Background script loaded and active.");

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    console.log("Message received in background:", message);

    if (message.type === "test") {
        sendResponse({ reply: "Hello from background script!" });
    } else if (message.type === "fetch") {
        // Handle fetch requests from the popup
        fetch(message.url, message.options)
            .then(response => response.json())
            .then(data => {
                sendResponse({ success: true, data });
            })
            .catch(error => {
                console.error("Fetch error:", error);
                sendResponse({ success: false, error: error.message });
            });
    }

    return true; // Required for async responses
});