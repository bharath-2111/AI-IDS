const socket    = io("http://localhost:5000");
const threatIPs = {};
const unknownIps = {};
let threatCount  = 0;
let normalCount  = 0;
let unknownCount = 0;

// ── Batch queue for prediction updates ──────────────────────────────────────
let predictionQueue = [];
let frameScheduled  = false;

function flushPredictions() {
    const table    = document.querySelector("#table tbody");
    const fragment = document.createDocumentFragment();

    while (predictionQueue.length > 0) {
        const data = predictionQueue.shift();
        const conf = typeof data.Confidence === "number" ? data.Confidence.toFixed(3) : "—";
        const row  = document.createElement("tr");

        if (data.Decision === "Normal") {
            normalCount++;
            row.classList.add("row-normal");
        } else if (data.Decision === "Malicious") {
            threatCount++;
            row.classList.add("row-attack");
            threatIPs[data.src_ip] = (threatIPs[data.src_ip] || 0) + 1;
        } else {
            unknownCount++;
            row.classList.add("row-unknown");
            unknownIps[data.src_ip] = (unknownIps[data.src_ip] || 0) + 1;
        }
        if(unknownIps[data.src_ip] > 200){
            threatIPs[data.src_ip] = unknownIps[data.src_ip] ;
            unknownCount -= unknownIps[data.src_ip];
            delete unknownIps[data.src_ip];
        }
        const cells = [data.src_ip, data.dst_ip, data.Class, conf, data.Decision];
        cells.forEach(text => {
            const td = document.createElement("td");
            td.innerText = text;
            row.appendChild(td);
        });

        fragment.appendChild(row);
    }

    // Single DOM write for all queued rows
    table.appendChild(fragment);

    // Trim table once after batch
    while (table.rows.length > 200) table.deleteRow(0);

    // Update counters once after batch
    document.getElementById("threats").innerText = threatCount;
    document.getElementById("normal").innerText  = normalCount;
    document.getElementById("unknown").innerText = unknownCount;

    frameScheduled = false;
}

// ── Helpers ──────────────────────────────────────────────────────────────────
function setStatus(msg, colour = "secondary") {
    const el = document.getElementById("status");
    if (!el) return;
    el.innerText  = msg;
    el.className  = `badge bg-${colour}`;
}
function setButtons(isRunning) {
    document.getElementById("start").disabled = isRunning;
    document.getElementById("stop").disabled  = !isRunning;
}
function showToast(msg, isError = false) {
    const el = document.getElementById("toast-msg");
    if (!el) return;
    el.innerText     = msg;
    el.className     = `alert ${isError ? "alert-danger" : "alert-success"} py-1 px-2`;
    el.style.display = "block";
    setTimeout(() => { el.style.display = "none"; }, 3000);
}
let tagTimeout = null;
function showTag(message, type) {
    const tag = document.getElementById("tag");
    if (!tag) return;
    if (tagTimeout) clearTimeout(tagTimeout);
    tag.style.display = "flex";
    tag.innerText = message;
    tag.classList.remove("alert-success", "alert-danger");
    tag.classList.add(type === "success" ? "alert-success" : "alert-danger");
    tagTimeout = setTimeout(() => { tag.style.display = "none"; }, 2000);
}

// ── Socket events ─────────────────────────────────────────────────────────────
socket.on("connect", () => {
    setStatus("Connected", "success");
    setButtons(false);
});
socket.on("disconnect", () => {
    setStatus("Disconnected", "danger");
    setButtons(false);
});
socket.on("connect_error", () => {
    setStatus("Cannot reach server", "danger");
});

// Queue incoming predictions and flush via rAF (prevents render blocking)
socket.on("predictions", function (data) {
    predictionQueue.push(data);
    if (!frameScheduled) {
        frameScheduled = true;
        requestAnimationFrame(flushPredictions);
    }
});

// ── All button/input listeners in ONE DOMContentLoaded ───────────────────────
document.addEventListener("DOMContentLoaded", () => {

    // Start
    console.log('start');
    document.getElementById("start").addEventListener("click", () => {
        document.getElementById("start").disabled = true;
        socket.emit("start-capturing", {}, (res) => {
            if (res?.error) {
                showToast(res.error, true);
                document.getElementById("start").disabled = false;
            } else {
                setStatus("Sniffing", "warning");
                setButtons(true);
                showToast(res?.status || "Started");
                showTag("Sniffing started", "success");
            }
        });
    });

    // Stop  ← was broken before because it was in a separate DOMContentLoaded
    document.getElementById("stop").addEventListener("click", () => {
        console.log('stop');
        document.getElementById("stop").disabled = true;
        socket.emit("stop-capturing", {}, (res) => {
            if (res?.error) {
                showToast(res.error, true);
                document.getElementById("stop").disabled = false;
            } else {
                setStatus("Connected", "success");
                setButtons(false);
                showToast(res?.status || "Stopped");
                showTag("Sniffing stopped", "danger");
            }
        });
    });

    // Clear
    document.getElementById("clear").addEventListener("click", () => {
        document.querySelector("#table tbody").innerHTML = "";
        threatCount  = 0;
        normalCount  = 0;
        unknownCount = 0;
        predictionQueue = [];   // also clear any pending queue
        document.getElementById("threats").innerText = 0;
        document.getElementById("normal").innerText  = 0;
        document.getElementById("unknown").innerText = 0;
        for (const ip in threatIPs) delete threatIPs[ip];
    });

    // Filter
    function filterSubmit() {
        const ip = document.getElementById("filterField").value.trim();
        if (!ip) {
            socket.emit("clear-filter", {}, (res) => showToast(res?.status || "Filter cleared"));
            return;
        }
        socket.emit("set-filter", ip, (res) => {
            if (res?.error) showToast(res.error, true);
            else showToast(res?.status || `Filter set: ${ip}`);
        });
    }

    const filterBtn   = document.getElementById("filterBtn");
    const filterField = document.getElementById("filterField");
    if (filterBtn)   filterBtn.addEventListener("click", filterSubmit);
    if (filterField) filterField.addEventListener("keydown", (e) => {
        if (e.key === "Enter") filterSubmit();
    });

    // Threat IP modal
    document.getElementById("mips").addEventListener("click", () => {
        const table = document.getElementById("threat-ip-table");
        table.innerHTML = "";
        for (const ip in threatIPs) {
            const row = table.insertRow();
            row.insertCell(0).innerText = ip;
            row.insertCell(1).innerText = threatIPs[ip];
        }
    });

    const threatModal = document.getElementById("threatModal");
    const openBtn     = document.getElementById("mips");
    threatModal.addEventListener("hide.bs.modal", () => {
        openBtn.blur();
        openBtn.focus();
    });
});