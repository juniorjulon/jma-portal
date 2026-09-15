// Cifrado de la bóveda. Todo ocurre en el navegador con WebCrypto: la clave de
// acceso nunca sale del dispositivo y lo que se publica en GitHub es ilegible
// sin ella. Borrar la pantalla de acceso no revela nada porque el contenido
// simplemente no existe en claro dentro de la página.

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const MAGIC = encoder.encode("JMA1");
const KID_BYTES = 8;
const IV_BYTES = 12;
const HEADER_BYTES = MAGIC.length + KID_BYTES + IV_BYTES;
const MIN_ITERATIONS = 100000;
const MAX_ITERATIONS = 5000000;

// OWASP 2023 para PBKDF2-HMAC-SHA256. Cada intento de adivinar la clave cuesta
// lo mismo que un ingreso legítimo, lo que frena la fuerza bruta fuera de línea.
export const PBKDF2_ITERATIONS = 600000;
export const MIN_PASSWORD_LENGTH = 14;

export class VaultCryptoError extends Error {}

export function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

export function bytesToBase64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let index = 0; index < bytes.length; index += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(index, index + chunk));
  }
  return btoa(binary);
}

export function base64ToBytes(text) {
  const binary = atob(String(text || ""));
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export function bytesToBase64Url(bytes) {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlToBytes(text) {
  const normalized = String(text || "").replace(/-/g, "+").replace(/_/g, "/");
  return base64ToBytes(normalized + "=".repeat((4 - (normalized.length % 4)) % 4));
}

export function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function sha256Hex(data) {
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", data)));
}

export function normalizePassword(password) {
  return String(password || "").normalize("NFC").trim();
}

export function randomId(prefix) {
  return `${prefix}${bytesToBase64Url(randomBytes(12))}`;
}

function concatBytes(...parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function additionalData(context, kidBytes) {
  return concatBytes(MAGIC, kidBytes, encoder.encode(`jma-vault:v1:${context}`));
}

async function deriveWrappingKey(password, salt, iterations) {
  const material = await crypto.subtle.importKey(
    "raw",
    encoder.encode(normalizePassword(password)),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// Una llave de contenido: identificador corto (kid) más 256 bits aleatorios.
export async function importContentKey(kidBytes, rawBytes) {
  if (kidBytes.length !== KID_BYTES || rawBytes.length !== 32) {
    throw new VaultCryptoError("La llave de contenido tiene un formato inválido.");
  }
  const key = await crypto.subtle.importKey("raw", rawBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  return { kid: bytesToBase64Url(kidBytes), kidBytes, raw: rawBytes, key };
}

export function generateContentKey() {
  return importContentKey(randomBytes(KID_BYTES), randomBytes(32));
}

export function exportContentKey(contentKey) {
  return { kid: contentKey.kid, key: bytesToBase64(contentKey.raw) };
}

export function importExportedKey(exported) {
  return importContentKey(base64UrlToBytes(exported.kid), base64ToBytes(exported.key));
}

// Conjunto de llaves conocidas. Cifra siempre con la vigente y descifra con
// cualquiera del historial, de modo que cambiar la clave no obliga a volver a
// cifrar los archivos anteriores.
export class KeyChain {
  constructor(current) {
    this.current = current;
    this.keys = new Map([[current.kid, current]]);
  }

  add(contentKey) {
    if (!this.keys.has(contentKey.kid)) {
      this.keys.set(contentKey.kid, contentKey);
    }
  }

  get(kid) {
    return this.keys.get(kid) || null;
  }

  history() {
    return Array.from(this.keys.values()).filter((entry) => entry.kid !== this.current.kid);
  }
}

// Formato binario: "JMA1" | kid (8) | iv (12) | texto cifrado con etiqueta GCM.
// El contexto (catálogo, archivo concreto, ajustes) va como dato autenticado:
// un archivo cifrado no puede hacerse pasar por otro.
export async function sealBytes(contentKey, plaintext, context) {
  const iv = randomBytes(IV_BYTES);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: additionalData(context, contentKey.kidBytes) },
    contentKey.key,
    plaintext
  ));
  return concatBytes(MAGIC, contentKey.kidBytes, iv, ciphertext);
}

export async function openBytes(keyChain, sealed, context) {
  if (!(sealed instanceof Uint8Array) || sealed.length < HEADER_BYTES + 16) {
    throw new VaultCryptoError("El archivo cifrado está incompleto.");
  }
  for (let index = 0; index < MAGIC.length; index += 1) {
    if (sealed[index] !== MAGIC[index]) {
      throw new VaultCryptoError("El archivo no pertenece a esta bóveda.");
    }
  }
  const kidBytes = sealed.subarray(MAGIC.length, MAGIC.length + KID_BYTES);
  const contentKey = keyChain.get(bytesToBase64Url(kidBytes));
  if (!contentKey) {
    throw new VaultCryptoError("El archivo fue cifrado con una llave que esta sesión no conoce.");
  }
  const iv = sealed.subarray(MAGIC.length + KID_BYTES, HEADER_BYTES);
  try {
    return new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: additionalData(context, kidBytes) },
      contentKey.key,
      sealed.subarray(HEADER_BYTES)
    ));
  } catch (_error) {
    throw new VaultCryptoError("El archivo cifrado fue alterado o no corresponde a su registro.");
  }
}

export function sealJson(contentKey, value, context) {
  return sealBytes(contentKey, encoder.encode(JSON.stringify(value)), context);
}

export async function openJson(keyChain, sealed, context) {
  return JSON.parse(decoder.decode(await openBytes(keyChain, sealed, context)));
}

// Una ranura del llavero: la llave de contenido envuelta con una llave derivada
// de la clave de acceso. keyring.json es público; sin la clave no sirve.
export async function createSlot(id, password, contentKey, iterations = PBKDF2_ITERATIONS) {
  const salt = randomBytes(16);
  const iv = randomBytes(IV_BYTES);
  const wrappingKey = await deriveWrappingKey(password, salt, iterations);
  const payload = encoder.encode(JSON.stringify(exportContentKey(contentKey)));
  const data = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: encoder.encode(`jma-vault:v1:slot:${id}`) },
    wrappingKey,
    payload
  ));
  return {
    id,
    kdf: { name: "PBKDF2", hash: "SHA-256", iterations, salt: bytesToBase64(salt) },
    wrap: { name: "AES-GCM", iv: bytesToBase64(iv), data: bytesToBase64(data) }
  };
}

// Devuelve la llave de contenido, o null si la clave no abre esta ranura.
export async function unlockSlot(slot, password) {
  const kdf = slot && slot.kdf;
  const wrap = slot && slot.wrap;
  const iterations = Number(kdf && kdf.iterations);
  if (!kdf || !wrap || kdf.name !== "PBKDF2" || kdf.hash !== "SHA-256" || wrap.name !== "AES-GCM"
    || !Number.isInteger(iterations) || iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
    throw new VaultCryptoError("El llavero de la bóveda tiene un formato no admitido.");
  }

  const wrappingKey = await deriveWrappingKey(password, base64ToBytes(kdf.salt), iterations);
  let payload;
  try {
    payload = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64ToBytes(wrap.iv), additionalData: encoder.encode(`jma-vault:v1:slot:${slot.id}`) },
      wrappingKey,
      base64ToBytes(wrap.data)
    );
  } catch (_error) {
    return null;
  }
  return importExportedKey(JSON.parse(decoder.decode(payload)));
}

// Clave aleatoria legible: 4 grupos de 5 caracteres sin símbolos ambiguos
// (unos 115 bits de entropía). Muestreo por rechazo para no sesgar el alfabeto.
export function generatePassphrase() {
  const alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const limit = 256 - (256 % alphabet.length);
  const characters = [];
  while (characters.length < 20) {
    for (const byte of randomBytes(32)) {
      if (byte < limit && characters.length < 20) {
        characters.push(alphabet[byte % alphabet.length]);
      }
    }
  }
  return [0, 5, 10, 15].map((start) => characters.slice(start, start + 5).join("")).join("-");
}

export function validateNewPassword(password, confirmation) {
  const normalized = normalizePassword(password);
  if (normalized.length < MIN_PASSWORD_LENGTH) {
    return `La clave debe tener al menos ${MIN_PASSWORD_LENGTH} caracteres. Usa el generador o una frase de varias palabras.`;
  }
  if (normalized !== normalizePassword(confirmation)) {
    return "Las dos claves no coinciden.";
  }
  return "";
}
