
async function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function collectCookies(url) {
    console.log("Collecting cookies for URL:", url);
    const cleanUrl = sanitizeUrl(url);
    if (!cleanUrl) {
        console.error("Invalid URL for cookies collection:", url);
        return [];
    }

    await delay(5000); 
    console.log(document.cookie);
    console.log("Collecting cookies for URL:", cleanUrl);
    try {
        const url = 'http://localhost:3000/';
        const cookies = await browser.cookies.getAll({ url });
        const formattedCookies = cookies.map(cookie => [
            cookie.name,
            cookie.value,
            0
        ]);
        console.log('Collected cookies:', formattedCookies);
        return formattedCookies;
    } catch (error) {
        console.error("Error collecting cookies:", error);
        return [];
    }
}

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "collectCookies") {
        console.log("Message received to collect cookies for URL:", message.url);
        collectCookies(message.url).then(cookies => {
            sendResponse({ cookies });
        });
    }
    return true;
});

function sanitizeUrl(url) {
    try {
        const parsedUrl = new URL(url);
        return parsedUrl.origin; 
    } catch (error) {
        console.error("Invalid URL:", url, error);
        return null;
    }
}
