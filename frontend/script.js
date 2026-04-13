const socket = io("http://localhost:5000");

const threatIPs  = {};
const unknownIPs = {};

let threatCount  = 0;
let normalCount  = 0;
let unknownCount = 0;

const FLOOD = {
    MALICIOUS_WINDOW_MS : 5000,
    MALICIOUS_THRESHOLD : 10,
    UNKNOWN_WINDOW_MS   : 10000,
    UNKNOWN_THRESHOLD   : 30,
    COOLDOWN_MS         : 15000,
};

const _malTs    = {};
const _unkTs    = {};
const _cooldown = {};

function recordAndCheck(ip, decision) {
    const now = Date.now();

    if (!_cooldown[ip]) _cooldown[ip] = 0;

    if (decision === "Malicious") {

        if (!threatIPs[ip]) {
            fireAlert(ip, "🔴 NEW MALICIOUS IP",
                `<b>${ip}</b> flagged as malicious`,
                "danger", true);
        }

        if (!_malTs[ip]) _malTs[ip] = [];
        _malTs[ip].push(now);

        _malTs[ip] = _malTs[ip].filter(t =>
            now - t < FLOOD.MALICIOUS_WINDOW_MS
        );

        const count = _malTs[ip].length;

        if (count >= FLOOD.MALICIOUS_THRESHOLD) {
            fireAlert(ip, "🚨 ATTACK FLOOD DETECTED",
                `${count} malicious flows from <b>${ip}</b> in 5 sec`,
                "danger");
        }

        if (count >= FLOOD.MALICIOUS_THRESHOLD * 3) {
            fireAlert(ip, "💀 CRITICAL ATTACK (UNCONTROLLED)",
                `${count} malicious flows → <b>${ip}</b> is overwhelming the system`,
                "danger", true);

            threatIPs[ip] = (threatIPs[ip] || 0) + 5;
            threatCount += 1;
            document.getElementById("threats").textContent = threatCount;
            updateThreatBadge();
        }
    }

    if (decision === "Unknown") {

        if (!_unkTs[ip]) _unkTs[ip] = [];
        _unkTs[ip].push(now);

        _unkTs[ip] = _unkTs[ip].filter(t =>
            now - t < FLOOD.UNKNOWN_WINDOW_MS
        );

        const count = _unkTs[ip].length;

        if (count >= FLOOD.UNKNOWN_THRESHOLD) {
            fireAlert(ip, "⚠ SUSPICIOUS FLOOD",
                `${count} unknown flows from <b>${ip}</b> in 10 sec`,
                "warning");
        }

        if (count >= FLOOD.UNKNOWN_THRESHOLD * 2) {
            fireAlert(ip, "🚨 ESCALATED THREAT",
                `Unknown traffic from <b>${ip}</b> turned malicious`,
                "danger", true);

            threatIPs[ip] = (threatIPs[ip] || 0) + 3;
            threatCount += 1;
            document.getElementById("threats").textContent = threatCount;
            updateThreatBadge();

            if (!_malTs[ip]) _malTs[ip] = [];
            _malTs[ip].push(now);
        }
    }
}

let alertQueue   = [];
let alertVisible = false;
let alertTimer   = null;

function fireAlert(ip, title, detail, type, force = false) {
    const now = Date.now();

    if (!force && _cooldown[ip] && now - _cooldown[ip] < FLOOD.COOLDOWN_MS) return;

    _cooldown[ip] = now;
    alertQueue.push({ title, detail, type });

    if (!alertVisible) showNextAlert();
}

function showNextAlert() {
    if (alertQueue.length === 0) {
        alertVisible = false;
        return;
    }

    alertVisible = true;

    const { title, detail, type } = alertQueue.shift();
    const banner = document.getElementById("flood-alert");
    if (!banner) {
        alertVisible = false;
        return;
    }

    banner.className     = `flood-banner active alert-${type}`;
    banner.style.display = "flex";
    banner.innerHTML     = `
        <span><strong>${title}</strong>&nbsp;|&nbsp;${detail}</span>
        <button id="alert-close">✕</button>
    `;

    document.getElementById("alert-close").onclick = () => {
        clearTimeout(alertTimer);
        banner.style.display = "none";
        showNextAlert();
    };

    alertTimer = setTimeout(() => {
        banner.style.display = "none";
        showNextAlert();
    }, 8000);
}

let predictionQueue = [];
let frameScheduled  = false;
const ROWS_PER_FRAME = 40;

function flushPredictions() {
    const tbody    = document.querySelector("#table tbody");
    const fragment = document.createDocumentFragment();
    const batch    = predictionQueue.splice(0, ROWS_PER_FRAME);

    batch.forEach(data => {
        const conf = typeof data.Confidence === "number"
            ? (data.Confidence * 100).toFixed(1) + "%"
            : "—";

        const row = document.createElement("tr");

        if (data.Decision === "Normal") {
            normalCount++;
            row.className = "row-normal";
        } else if (data.Decision === "Malicious") {
            recordAndCheck(data.src_ip, "Malicious");
            threatCount++;
            threatIPs[data.src_ip] = (threatIPs[data.src_ip] || 0) + 1;
            updateThreatBadge();
            row.className = "row-attack";
        } else {
            recordAndCheck(data.src_ip, "Unknown");
            unknownCount++;
            unknownIPs[data.src_ip] = (unknownIPs[data.src_ip] || 0) + 1;
            row.className = "row-unknown";
        }

        [data.src_ip, data.dst_ip, data.Class, data.Threshold ?? "—", conf, data.Decision]
            .forEach(text => {
                const td = document.createElement("td");
                td.textContent = text ?? "—";
                row.appendChild(td);
            });

        fragment.appendChild(row);
    });

    tbody.insertBefore(fragment, tbody.firstChild);

    while (tbody.rows.length > 200) {
        tbody.deleteRow(tbody.rows.length - 1);
    }

    document.getElementById("threats").textContent = threatCount;
    document.getElementById("normal").textContent  = normalCount;
    document.getElementById("unknown").textContent = unknownCount;

    if (predictionQueue.length > 0) {
        requestAnimationFrame(flushPredictions);
    } else {
        frameScheduled = false;
    }
}

function updateThreatBadge() {
    const btn = document.getElementById("mips");
    const badge = btn?.querySelector(".badge");
    if (!badge || !btn) return;

    let count = 0;
    Object.values(threatIPs).forEach(v => count += v);

    badge.textContent = count;
    badge.classList.toggle("active", count > 0);
}

function setStatus(msg, colour = "secondary") {
    const el = document.getElementById("status");
    if (!el) return;
    el.textContent = msg;
    el.className   = `badge bg-${colour}`;
}

function setButtons(isRunning) {
    document.getElementById("start").disabled = isRunning;
    document.getElementById("stop").disabled  = !isRunning;
}

function showToast(msg, isError = false) {
    const el = document.getElementById("toast-msg");
    if (!el) return;

    el.textContent   = msg;
    el.className     = `alert ${isError ? "alert-danger" : "alert-success"} py-1 px-2`;
    el.style.display = "block";

    setTimeout(() => el.style.display = "none", 3000);
}

socket.on("connect", () => {
    console.log("✅ Connected:", socket.id);
    setStatus("Connected", "success");
    setButtons(false);
});

socket.on("disconnect", () => {
    console.log("❌ Disconnected");
    setStatus("Disconnected", "danger");
    setButtons(false);
});

socket.on("connect_error", (err) => {
    console.error("🚨 Connection Error:", err.message);
    setStatus("Cannot reach server", "danger");
});

socket.on("predictions", (data) => {
    const items = Array.isArray(data) ? data : [data];

    items.forEach(item => predictionQueue.push(item));

    if (!frameScheduled) {
        frameScheduled = true;
        requestAnimationFrame(flushPredictions);
    }
});

document.addEventListener("DOMContentLoaded", () => {

    setButtons(false);

    document.getElementById("start").addEventListener("click", () => {
        socket.emit("start-capturing", {}, (res) => {
            if (!res || res.error) {
                showToast(res?.error || "Start failed", true);
                return;
            }

            setStatus("Sniffing", "warning");
            setButtons(true);
            showToast(res.status || "Started");
        });
    });

    document.getElementById("stop").addEventListener("click", () => {
        socket.emit("stop-capturing", {}, (res) => {
            if (!res || res.error) {
                showToast(res?.error || "Stop failed", true);
                return;
            }

            setStatus("Connected", "success");
            setButtons(false);
            showToast(res.status || "Stopped");
        });
    });

    document.getElementById("clear").addEventListener("click", () => {
        document.querySelector("#table tbody").innerHTML = "";

        threatCount = normalCount = unknownCount = 0;
        predictionQueue = [];

        [threatIPs, unknownIPs, _malTs, _unkTs, _cooldown]
            .forEach(obj => Object.keys(obj).forEach(k => delete obj[k]));

        ["threats","normal","unknown"]
            .forEach(id => document.getElementById(id).textContent = 0);

        updateThreatBadge();
    });
});