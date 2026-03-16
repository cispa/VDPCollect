/**
 * Convert source string representation to id for consumption 
 * by exploit generator.
 * 
 * @param source Source string representation
 * @returns 
 */
const sourceToId = (source) => {
    switch (source) {
        case "location.href": return 1;
        case "location.pathname": return 2;
        case "location.search": return 3;
        case "location.hash": return 4;
        case "document.documentURI": return 6;
        case "document.baseURI": return 7;
        case "document.cookie": return 8;
        case "document.referrer": return 9;
        case "document.domain": return 10;
        case "window.name": return 11;
        case "postMessage": return 12;
        case "localStorage.getItem": return 13;
        case "sessionStorage.getItem": return 14;
        default: return 255;
    }
};


const sinkToId = (sink) => {
    switch (sink) {
        case "eval": return 1;
        case "document.write": return 2;
        case "innerHTML": return 3;
        case "iframe.src": return 4;
        case "script.src": return 8;
        default: return -1;
    }
};

const getRandomInt = (max) => {
    return Math.floor(Math.random() * max);
}

const flowcollect = (flow) => {
    var finding_id = getRandomInt(Number.MAX_SAFE_INTEGER);

    if (!flow.detail) {
        return undefined;
    }

    var finding = {
        finding_id: finding_id,
        sink: flow.detail.sink,
        sources: [],
        url: flow.detail.loc,
        trace: flow.detail.trace,
        storage: flow.storage,
        value: "",
        d1: "",
        d2: "",
        d3: `${flow.detail.stack.source}:${flow.detail.stack.line}:${flow.detail.stack.column}`,
        taintReportJson: ""
    };

    finding.value = flow.detail.str;

    try {
        if (typeof flow.detail.taint === "string") {
            flow.detail.taint = JSON.parse(flow.detail.taint);
        }
    } catch (err) {
        console.log(err);
        return undefined;
    }

    flow.detail.taint.forEach((element) => {
        let start = element.begin;
        let end = element.end;

        var taint = element.flow.pop();

        var parentFlow = element.flow.pop();
        var hasEscaping = 0;
        var hasEncodingURI = 0;
        var hasEncodingURIComponent = 0;

        while (parentFlow && parentFlow.operation && (parentFlow.operation !== flow.detail.sink)) {
            if (parentFlow.operation === "encodeURI") {
                hasEncodingURI = 1;
            }
            if (parentFlow.operation === "encodeURIComponent") {
                hasEncodingURIComponent = 1;
            }
            if (parentFlow.operation === "escape") {
                hasEscaping = 1;
            }
            parentFlow = element.flow.pop();
        }

        var source = {
            id: 0,
            finding_id: finding_id,
            start,
            end,
            source: sourceToId(taint.operation),
            source_name: taint.operation,
            value_part: flow.detail.str.slice(start, end),
            hasEscaping: hasEscaping,
            hasEncodingURI: hasEncodingURI,
            hasEncodingURIComponent: hasEncodingURIComponent,
        };

        finding.sources.push(source);
    });

    return finding;
};

const prepareFinding = (findingId, sinkId, sources, url, storage, value, d1, d2, d3) => {
    const modified = {
        finding_id: findingId,
        sink_id: sinkId,
        sources: sources,
        url: url,
        storage: storage,
        value: value,
        d1: d1,
        d2: d2,
        d3: d3
    };

    return modified;
};

function collectStorage() {
    var storage = {
        cookies: [],
        storage: []
    }
    if (document.cookie !== "") {
        var keyValuePairs = document.cookie.split(';');
        for (var i = 0; i < keyValuePairs.length; i++) {
            storage.cookies.push([
                keyValuePairs[i].substring(0, keyValuePairs[i].indexOf('=')),
                keyValuePairs[i].substring(keyValuePairs[i].indexOf('=') + 1),
                0
            ])
        }
    }

    // Collect local storage items
    for (var i = 0; i < localStorage.length; i++) {
        storage.storage.push([
            localStorage.key(i),
            localStorage.getItem(localStorage.key(i)),
            0
        ])
    }

    // Collect session storage
    for (var i = 0; i < sessionStorage.length; i++) {
        storage.storage.push([
            sessionStorage.key(i),
            sessionStorage.getItem(sessionStorage.key(i)),
            0
        ])
    }
    return storage;
}

function rewriteTaintReport(report) {
    var storage = collectStorage();

    var flow = {
        detail: {
            loc: report.detail.loc,
            str: report.detail.str,
            sink: report.detail.sink,
            taint: report.detail.str.taint,
            stack: {
                source: report.detail.stack.source,
                line: report.detail.stack.line,
                column: report.detail.stack.column
            },
            trace: report.detail.stack.toString()
        },
        storage,
        ...report
    }
    var finding = flowcollect(flow);
    var prep_finding = prepareFinding(finding.finding_id, sinkToId(finding.sink), finding.sources, finding.url, finding.storage, finding.value, finding.d1, finding.d2, finding.d3)
    console.log("Done preparing");

    const taintDataArray = report.detail.str.taint || []; 

    // Loop over each entry in the taintDataArray
    taintDataArray.forEach((entry) => {
        const taintData = {
            url: window.location.href,
            details: report.detail,
            taintFlows: entry, // Individual flow from taintDataArray
            source: entry['flow'].filter(step => step.source === true).map(step => step.operation)[0],
            sink: report.detail.sink,
            finding: prep_finding
        };

        // Add each taintData object to the batch array
        taintDataBatch.push(taintData);
    });

    // Debounce the send function to send the batch after 100ms
    clearTimeout(debounceTimeout);
    debounceTimeout = setTimeout(() => {
        sendBatchToBackend();  // Send batch when debounce time is over
    }, 100);
}

let taintDataBatch = []; // Store batched taint data
let debounceTimeout;     // Timeout for debouncing the send function

// Maximum number of items in a single batch
const MAX_BATCH_SIZE = 100; // You can adjust this number based on your payload limits

// Function to split the batch and send data to the backend in smaller chunks
function sendBatchToBackend() {
    if (taintDataBatch.length === 0) return;  // If no data in batch, return

    // Log the batch data size for debugging
    console.log(`Sending batch with ${taintDataBatch.length} entries`);

    // Split the batch into smaller chunks
    const chunks = chunkArray(taintDataBatch, MAX_BATCH_SIZE);

    // Send each chunk separately
    chunks.forEach((chunk, index) => {
        sendChunkToBackend(chunk, index + 1, chunks.length);
    });

    // Clear the batch after sending
    taintDataBatch = [];
}

// Function to split the array into smaller chunks
function chunkArray(array, size) {
    const chunks = [];
    for (let i = 0; i < array.length; i += size) {
        chunks.push(array.slice(i, i + size));
    }
    return chunks;
}

// Function to send a single chunk to the backend
function sendChunkToBackend(chunk, chunkIndex, totalChunks) {
    console.log(`Sending chunk ${chunkIndex} of ${totalChunks} with ${chunk.length} entries`);

    fetch('http://localhost:8000/taintreport', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(chunk), // Send the chunk of batched data to the server
    })
    .then(response => response.json())
    .then(responseData => {
        console.log(`Successfully sent chunk ${chunkIndex} of ${totalChunks}:`, responseData);
    })
    .catch(error => {
        console.error(`Error sending chunk ${chunkIndex} of ${totalChunks}:`, error);
    });
}
 
window.addEventListener("__taintreport", rewriteTaintReport);