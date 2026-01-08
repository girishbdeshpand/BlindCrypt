/* BlindCrypt
   Client-side encrypt/decrypt using WebCrypto.
   Format v1: [4 bytes big-endian headerLength][header JSON utf8][ciphertext bytes]
   Format v2: [4 bytes big-endian headerLength][header JSON utf8][ciphertext chunks]
*/

const $ = (id) => document.getElementById(id);

const LEVELS = {
  standard: { iterations: 310000,  words: 4  },
  strong:   { iterations: 600000,  words: 6  },
  high:     { iterations: 1200000, words: 8  },
  critical: { iterations: 2400000, words: 16 },
};

const CHUNK_SIZE = 512 * 1024; // 512 KiB

function setStatus(el, msg, kind = "info") {
  el.textContent = msg;
  el.dataset.kind = kind;
}

function setProgress(pct, msg = "") {
  const bar = $("encProgBar");
  const txt = $("encProgText");
  if (!bar || !txt) return;
  const p = Math.max(0, Math.min(100, Number(pct) || 0));
  bar.style.width = `${p.toFixed(1)}%`;
  txt.textContent = msg || (p > 0 ? `${p.toFixed(1)}%` : "");
}

function b64uEncode(bytes) {
  const bin = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  return btoa(bin).replaceAll("+","-").replaceAll("/","_").replaceAll("=","");
}

function b64uDecode(str) {
  const s = str.replaceAll("-","+").replaceAll("_","/");
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const bin = atob(s + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function utf8Encode(s) {
  return new TextEncoder().encode(s);
}
function utf8Decode(b) {
  return new TextDecoder().decode(b);
}

function u32be(n) {
  const b = new Uint8Array(4);
  b[0] = (n >>> 24) & 0xff;
  b[1] = (n >>> 16) & 0xff;
  b[2] = (n >>> 8) & 0xff;
  b[3] = n & 0xff;
  return b;
}
function readU32be(b, off) {
  return ((b[off] << 24) | (b[off+1] << 16) | (b[off+2] << 8) | (b[off+3])) >>> 0;
}

function concatBytes(...parts) {
  const total = parts.reduce((n,p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

function downloadBytes(bytes, filename) {
  const blob = new Blob([bytes], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

function sampleWords(count) {
  if (!Array.isArray(window.WORDS) || window.WORDS.length < 2048) {
    throw new Error("Word list is missing or incomplete");
  }
  const r = new Uint32Array(count);
  crypto.getRandomValues(r);
  const out = [];
  for (let i = 0; i < count; i++) out.push(window.WORDS[r[i] % window.WORDS.length]);
  return out.join(" ");
}

async function deriveKeyPBKDF2(passphrase, saltBytes, iterations) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    utf8Encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function makeChunkIV(ivBaseBytes, counter) {
  // AES-GCM expects 12-byte IV.
  // Use first 8 bytes as random prefix, last 4 bytes as big-endian chunk counter.
  const iv = new Uint8Array(12);
  iv.set(ivBaseBytes.slice(0, 8), 0);
  iv[8]  = (counter >>> 24) & 0xff;
  iv[9]  = (counter >>> 16) & 0xff;
  iv[10] = (counter >>> 8) & 0xff;
  iv[11] = counter & 0xff;
  return iv;
}

async function encryptFileV2Chunked(file, passphrase, levelKey, onProgress) {
  const level = LEVELS[levelKey] || LEVELS.critical;

  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);

  const ivBase = new Uint8Array(12);
  crypto.getRandomValues(ivBase);

  onProgress?.(1, "Deriving key...");
  const key = await deriveKeyPBKDF2(passphrase, salt, level.iterations);

  const total = file.size;
  const chunkSize = CHUNK_SIZE;
  const chunks = Math.max(1, Math.ceil(total / chunkSize));
  const last = total - (chunks - 1) * chunkSize;

  const cipherParts = [];
  let processed = 0;

  for (let i = 0; i < chunks; i++) {
    const start = i * chunkSize;
    const end = Math.min(total, start + chunkSize);
    const ab = await file.slice(start, end).arrayBuffer();
    const plain = new Uint8Array(ab);

    const iv = makeChunkIV(ivBase, i);

    const cipherBuf = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      plain
    );
    const cipher = new Uint8Array(cipherBuf);
    cipherParts.push(cipher);

    processed += plain.length;
    const pct = 5 + (processed / total) * 95;
    onProgress?.(pct, `${pct.toFixed(1)}%`);
    // yield to UI for smoother progress on slower devices
    await new Promise(r => setTimeout(r, 0));
  }

  const header = {
    v: 2,
    mode: "chunked-aesgcm",
    kdf: "PBKDF2",
    hash: "SHA-256",
    iter: level.iterations,
    alg: "AES-256-GCM",
    salt: b64uEncode(salt),
    iv: b64uEncode(ivBase),
    size: total,
    chunk: chunkSize,
    chunks,
    last,
    name: file.name || "file",
    type: file.type || "application/octet-stream"
  };

  const headerBytes = utf8Encode(JSON.stringify(header));

  // stitch output: header + cipher parts
  const totalCipher = cipherParts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(4 + headerBytes.length + totalCipher);
  out.set(u32be(headerBytes.length), 0);
  out.set(headerBytes, 4);

  let o = 4 + headerBytes.length;
  for (const p of cipherParts) {
    out.set(p, o);
    o += p.length;
  }

  return { bytes: out, header };
}

async function decryptFileAny(fileBytes, passphrase, onProgress) {
  if (fileBytes.length < 5) throw new Error("File too small");

  const headerLen = readU32be(fileBytes, 0);
  const headerStart = 4;
  const headerEnd = headerStart + headerLen;

  if (headerEnd > fileBytes.length) throw new Error("Invalid header length");

  const headerJson = utf8Decode(fileBytes.slice(headerStart, headerEnd));
  let header;
  try { header = JSON.parse(headerJson); }
  catch { throw new Error("Invalid header JSON"); }

  if (!header || (header.v !== 1 && header.v !== 2)) throw new Error("Unsupported format version");

  const salt = b64uDecode(header.salt);
  const iter = Number(header.iter);
  if (!Number.isFinite(iter) || iter < 10000) throw new Error("Invalid KDF settings");

  onProgress?.(1, "Deriving key...");
  const key = await deriveKeyPBKDF2(passphrase, salt, iter);

  if (header.v === 1) {
    const iv = b64uDecode(header.iv);
    const cipher = fileBytes.slice(headerEnd);

    const plainBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      cipher
    );

    onProgress?.(100, "100.0%");
    return { plain: new Uint8Array(plainBuf), header };
  }

  // v2
  const ivBase = b64uDecode(header.iv);
  const totalPlain = Number(header.size);
  const chunkSize = Number(header.chunk);
  const chunks = Number(header.chunks);
  const last = Number(header.last);

  if (![totalPlain, chunkSize, chunks, last].every(Number.isFinite)) throw new Error("Invalid header settings");
  if (chunks < 1 || chunkSize < 1024 || last < 0) throw new Error("Invalid chunk settings");

  const cipherAll = fileBytes.slice(headerEnd);
  const plainParts = [];
  let off = 0;
  let processed = 0;

  for (let i = 0; i < chunks; i++) {
    const plainLen = (i === chunks - 1) ? last : chunkSize;
    const cipherLen = plainLen + 16; // AES-GCM tag
    const cipher = cipherAll.slice(off, off + cipherLen);
    if (cipher.length !== cipherLen) throw new Error("Truncated ciphertext");
    off += cipherLen;

    const iv = makeChunkIV(ivBase, i);
    const plainBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      cipher
    );

    const p = new Uint8Array(plainBuf);
    plainParts.push(p);

    processed += p.length;
    const pct = 5 + (processed / totalPlain) * 95;
    onProgress?.(pct, `${pct.toFixed(1)}%`);
    await new Promise(r => setTimeout(r, 0));
  }

  onProgress?.(100, "100.0%");

  const out = new Uint8Array(totalPlain);
  let o = 0;
  for (const p of plainParts) { out.set(p, o); o += p.length; }

  return { plain: out, header };
}

function setTab(name) {
  const tabs = document.querySelectorAll(".tab");
  const panels = document.querySelectorAll(".panel");

  tabs.forEach(t => {
    const active = t.dataset.tab === name;
    t.classList.toggle("active", active);
    t.setAttribute("aria-selected", active ? "true" : "false");
  });

  panels.forEach(p => p.classList.toggle("show", p.id === name));
}

function updateIterLabel() {
  const levelKey = $("encLevel").value;
  const level = LEVELS[levelKey] || LEVELS.critical;
  $("encIterLabel").textContent = String(level.iterations);
}

function wordSet() {
  if (!Array.isArray(window.WORDS)) return null;
  if (!wordSet.cache) wordSet.cache = new Set(window.WORDS.map(w => w.toLowerCase()));
  return wordSet.cache;
}

function estimatePassphrase(pass) {
  const trimmed = (pass || "").trim();
  if (!trimmed) return { score: 0, text: "-", pct: 0 };

  const parts = trimmed.split(/\s+/).filter(Boolean);
  const wset = wordSet();

  let bits = 0;
  let mode = "chars";

  if (wset && parts.length >= 2 && parts.every(w => wset.has(w.toLowerCase()))) {
    mode = "words";
    bits = 11 * parts.length;
  } else {
    const s = trimmed;
    const hasLower = /[a-z]/.test(s);
    const hasUpper = /[A-Z]/.test(s);
    const hasDigit = /[0-9]/.test(s);
    const hasSymbol = /[^A-Za-z0-9\s]/.test(s);

    let pool = 0;
    if (hasLower) pool += 26;
    if (hasUpper) pool += 26;
    if (hasDigit) pool += 10;
    if (hasSymbol) pool += 33;
    if (pool === 0) pool = 26;

    bits = s.replace(/\s+/g, "").length * Math.log2(pool);
  }

  const target = 11 * 16; // 16 BIP39 words
  const pct = Math.max(0, Math.min(100, (bits / target) * 100));

  let label = "Weak";
  if (pct >= 85) label = "Critical";
  else if (pct >= 60) label = "High";
  else if (pct >= 35) label = "Strong";

  const info = mode === "words"
    ? `${label} (${parts.length} words, ~${bits.toFixed(0)} bits)`
    : `${label} (~${bits.toFixed(0)} bits)`;

  return { score: bits, text: info, pct };
}

function updateStrengthUI() {
  const pass = $("encPass")?.value || "";
  const { pct, text } = estimatePassphrase(pass);

  const fill = $("passStrengthFill");
  const txt = $("passStrengthText");
  const track = document.querySelector("#passStrength .strengthTrack");

  if (fill) fill.style.width = `${pct.toFixed(1)}%`;
  if (txt) txt.textContent = text;
  if (track) track.setAttribute("aria-valuenow", String(Math.round(pct)));
}

function bindUI() {
  document.querySelectorAll(".tab").forEach(btn => {
    btn.addEventListener("click", () => setTab(btn.dataset.tab));
  });

  $("encLevel").addEventListener("change", updateIterLabel);
  updateIterLabel();

  $("encShow").addEventListener("click", () => {
    const i = $("encPass");
    i.type = (i.type === "password") ? "text" : "password";
    $("encShow").textContent = (i.type === "password") ? "Show" : "Hide";
  });

  $("decShow").addEventListener("click", () => {
    const i = $("decPass");
    i.type = (i.type === "password") ? "text" : "password";
    $("decShow").textContent = (i.type === "password") ? "Show" : "Hide";
  });

  $("encPass").addEventListener("input", updateStrengthUI);
  updateStrengthUI();

  $("genPass").addEventListener("click", () => {
    const levelKey = $("encLevel").value;
    const level = LEVELS[levelKey] || LEVELS.critical;
    try {
      const pass = sampleWords(level.words);
      $("encPass").value = pass;
      $("encConfirm").value = "";
      updateStrengthUI();
      setStatus($("encStatus"), "Passphrase generated. Copy it and store it safely.", "info");
    } catch (e) {
      setStatus($("encStatus"), `Passphrase generation failed: ${e?.message || String(e)}`, "bad");
    }
  });

  $("copyPass").addEventListener("click", async () => {
    const pass = $("encPass").value;
    if (!pass) { setStatus($("encStatus"), "Nothing to copy.", "bad"); return; }
    try {
      await navigator.clipboard.writeText(pass);
      setStatus($("encStatus"), "Copied passphrase to clipboard.", "good");
    } catch {
      setStatus($("encStatus"), "Clipboard blocked by browser. Select and copy manually.", "bad");
    }
  });

  $("doEncrypt").addEventListener("click", async () => {
    const st = $("encStatus");
    const btn = $("doEncrypt");
    setStatus(st, "", "info");
    setProgress(0, "");

    const f = $("encFile").files?.[0];
    if (!f) { setStatus(st, "Choose a file first.", "bad"); return; }

    const pass = $("encPass").value;
    const conf = $("encConfirm").value;
    if (!pass) { setStatus(st, "Enter a passphrase or generate one.", "bad"); return; }
    if (pass !== conf) { setStatus(st, "Passphrase confirmation does not match.", "bad"); return; }

    const levelKey = $("encLevel").value;

    try {
      btn.disabled = true;
      setStatus(st, "Encrypting locally...", "info");
      const { bytes } = await encryptFileV2Chunked(
        f,
        pass,
        levelKey,
        (pct, msg) => setProgress(pct, msg)
      );

      const safeName = (f.name && f.name.trim().length) ? f.name.trim() : "file";
      downloadBytes(bytes, `${safeName}.blindcrypt`);

      setProgress(100, "100.0%");
      setStatus(st, "Encrypted file downloaded. Share it and share the passphrase out of band.", "good");
    } catch (e) {
      setProgress(0, "");
      setStatus(st, `Encryption failed: ${e?.message || String(e)}`, "bad");
    } finally {
      btn.disabled = false;
    }
  });

  $("doDecrypt").addEventListener("click", async () => {
    const st = $("decStatus");
    const btn = $("doDecrypt");
    setStatus(st, "", "info");

    $("metaName").textContent = "-";
    $("metaType").textContent = "-";
    $("metaIter").textContent = "-";

    const f = $("decFile").files?.[0];
    if (!f) { setStatus(st, "Choose an encrypted file first.", "bad"); return; }

    const pass = $("decPass").value;
    if (!pass) { setStatus(st, "Enter the passphrase.", "bad"); return; }

    try {
      btn.disabled = true;
      setStatus(st, "Decrypting locally...", "info");

      const bytes = new Uint8Array(await f.arrayBuffer());
      const { plain, header } = await decryptFileAny(
        bytes,
        pass,
        () => {}
      );

      $("metaName").textContent = header.name || "file";
      $("metaType").textContent = header.type || "application/octet-stream";
      $("metaIter").textContent = String(header.iter || "-");

      const outName = header.name || "decrypted.bin";
      const blob = new Blob([plain], { type: header.type || "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = outName;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);

      setStatus(st, "Decryption complete. Download started.", "good");
    } catch (e) {
      setStatus(st, "Decryption failed. Wrong passphrase or file was modified.", "bad");
    } finally {
      btn.disabled = false;
    }
  });
}

bindUI();
