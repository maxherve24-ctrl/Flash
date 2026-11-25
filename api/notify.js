// Serveur de notifications de Flash (fonction Vercel)
// La clé secrète est dans Vercel > Settings > Environment Variables > VAPID_PRIVATE
export const config = { runtime: "edge" };

const PROJECT = "flash-73e38";
const API_KEY = "AIzaSyD2HU_EWo_mWoHwWZbv8oec-_Y7LzQ3CZA";
const ORIGINS = ["https://maxherve24-ctrl.github.io"];
const VAPID_PUBLIC = "BOQZFDxbk5bbIsIvbX3Si8mQ-qXhiFwx0o3m0nnthHmWlEbaNS5A1TEiXrNw6ZWfpnmiK5GuA4HUUl1h8W0rjHs";
const VAPID_X = "5BkUPFuTltsiwi9tfdKLyZD6peGIXDHSjebSee2EeZY";
const VAPID_Y = "lEbaNS5A1TEiXrNw6ZWfpnmiK5GuA4HUUl1h8W0rjHs";
const FS = `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents`;
const enc = new TextEncoder();

const b64u = buf => { let s = ""; const b = new Uint8Array(buf); for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
const unb64u = str => { str = str.replace(/-/g, "+").replace(/_/g, "/"); while (str.length % 4) str += "="; const s = atob(str), o = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) o[i] = s.charCodeAt(i); return o; };
const concat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
function val(v) {
  if (!v) return undefined;
  if ("stringValue" in v) return v.stringValue;
  if ("booleanValue" in v) return v.booleanValue;
  if ("integerValue" in v) return Number(v.integerValue);
  if ("doubleValue" in v) return v.doubleValue;
  if ("arrayValue" in v) return (v.arrayValue.values || []).map(val);
  if ("mapValue" in v) { const o = {}; for (const k in (v.mapValue.fields || {})) o[k] = val(v.mapValue.fields[k]); return o; }
}
async function fsGet(path, token) {
  const r = await fetch(`${FS}/${path}?key=${API_KEY}`, { headers: { Authorization: "Bearer " + token } });
  return r.ok ? r.json() : null;
}

let vapidKey = null;
async function vapidHeader(endpoint) {
  if (!vapidKey) vapidKey = await crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: VAPID_X, y: VAPID_Y, d: process.env.VAPID_PRIVATE, ext: true }, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const head = b64u(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const body = b64u(enc.encode(JSON.stringify({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: "mailto:flash@example.com" })));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, vapidKey, enc.encode(head + "." + body));
  return `vapid t=${head}.${body}.${b64u(sig)}, k=${VAPID_PUBLIC}`;
}
async function hkdf(salt, ikm, info, n) {
  const k = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, k, n * 8));
}
async function encrypt(sub, text) {
  const ua = unb64u(sub.p256dh), auth = unb64u(sub.auth);
  const kp = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const as = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", ua, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, kp.privateKey, 256));
  const ikm = await hkdf(auth, shared, concat(enc.encode("WebPush: info\0"), ua, as), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, enc.encode("Content-Encoding: nonce\0"), 12);
  const aes = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aes, concat(enc.encode(text), new Uint8Array([2]))));
  return concat(salt, new Uint8Array([0, 0, 16, 0, as.length]), as, ct);
}
async function push(sub, payload) {
  const r = await fetch(sub.endpoint, { method: "POST", body: await encrypt(sub, JSON.stringify(payload)),
    headers: { Authorization: await vapidHeader(sub.endpoint), "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", TTL: "86400", Urgency: "high" } });
  return r.status;
}
async function pushTo(uid, payload, token) {
  const list = await fsGet(`pushsubs/${uid}/devices`, token); let n = 0;
  for (const d of (list && list.documents) || []) {
    const s = {}; for (const k in d.fields) s[k] = val(d.fields[k]);
    if (s.endpoint && s.p256dh && s.auth) { try { if (await push(s, payload) < 300) n++; } catch {} }
  }
  return n;
}

export default async function handler(request) {
  const origin = request.headers.get("origin") || "";
  const cors = { "Access-Control-Allow-Origin": ORIGINS.includes(origin) ? origin : ORIGINS[0], "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type", Vary: "Origin" };
  const reply = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { ...cors, "Content-Type": "application/json" } });
  if (request.method === "OPTIONS") return new Response(null, { headers: cors });
  if (request.method === "GET") return reply({ ok: true, service: "Flash notifs", cle: !!process.env.VAPID_PRIVATE });
  if (request.method !== "POST") return reply({ error: "méthode" }, 405);
  if (!process.env.VAPID_PRIVATE) return reply({ error: "VAPID_PRIVATE manquante dans Vercel" }, 500);

  let data; try { data = await request.json(); } catch { return reply({ error: "json" }, 400); }
  const { idToken, chatId, callId } = data || {};
  const id = chatId || callId;
  if (!idToken || !id || !/^[\w-]+$/.test(id)) return reply({ error: "paramètres" }, 400);
  let sender; try { sender = JSON.parse(new TextDecoder().decode(unb64u(idToken.split(".")[1]))).user_id; } catch { return reply({ error: "jeton" }, 401); }

  const meDoc = await fsGet(`members/${sender}`, idToken);
  if (!meDoc) return reply({ error: "accès refusé" }, 403); // jeton invalide ou pas membre
  const pseudo = val(meDoc.fields && meDoc.fields.pseudo) || "Quelqu'un";

  // Appel entrant
  if (callId) {
    const c = await fsGet(`calls/${callId}`, idToken); if (!c) return reply({ error: "accès refusé" }, 403);
    const f = c.fields || {}; if (val(f.from) !== sender) return reply({ error: "pas l'appelant" }, 403);
    const sent = await pushTo(val(f.to), { title: `📞 ${pseudo} t'appelle`, body: val(f.video) ? "Appel vidéo · ouvre Flash pour répondre" : "Appel vocal · ouvre Flash pour répondre", chatId: val(f.chatId) || "" }, idToken);
    return reply({ ok: true, sent });
  }

  // Nouveau message
  const chat = await fsGet(`chats/${chatId}`, idToken); if (!chat) return reply({ error: "accès refusé" }, 403);
  const f = chat.fields || {}, members = val(f.members) || [];
  if (!members.includes(sender) || val(f.lastFrom) !== sender) return reply({ error: "pas l'expéditeur" }, 403);
  const group = !!val(f.group) || members.length > 2;
  const lastRaw = val(f.last), last = typeof lastRaw === "string" ? lastRaw : "";
  const text = val(f.lastImg) ? (last.includes("🎵") ? "📸 Photo avec musique 🎵" : "📸 Photo") : (last || "Nouveau message");
  const payload = { title: group ? (val(f.name) || "Groupe") : pseudo, body: group ? `${pseudo} : ${text}` : text, chatId };
  let sent = 0;
  for (const uid of members) if (uid !== sender) sent += await pushTo(uid, payload, idToken);
  return reply({ ok: true, sent });
}
