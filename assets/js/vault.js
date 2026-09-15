// Formato de la bóveda, dentro de <repositorio>/vault/:
//
//   keyring.json   Público. La llave de contenido envuelta con la clave de acceso.
//   catalog.bin    Cifrado. El registro: quién guardó qué, cuándo, y sus archivos.
//   settings.bin   Cifrado. Ajustes de la etapa 2 e historial de llaves.
//   files/*.bin    Cifrados. Un archivo por adjunto, con nombre aleatorio.
//
// Los aportes de la etapa 2 viven en un segundo repositorio con el mismo
// formato (sin keyring ni settings), cifrados con la misma llave.

import {
  KeyChain,
  createSlot,
  exportContentKey,
  generateContentKey,
  importExportedKey,
  openBytes,
  openJson,
  randomId,
  sealBytes,
  sealJson,
  sha256Hex,
  unlockSlot
} from "./crypto.js";
import { LIMITS, sanitizeFileName, typeFor, verifyContent } from "./files.js";

const KEYRING_FILE = "keyring.json";
const CATALOG_FILE = "catalog.bin";
const SETTINGS_FILE = "settings.bin";
const FILES_DIR = "files";
const SLOT_ID = "shared";
const ENTRY_ID = /^e_[A-Za-z0-9_-]{16}$/;
const FILE_ID = /^f_[A-Za-z0-9_-]{16}$/;
const OWNER_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPO_PATTERN = /^[A-Za-z0-9._-]{1,100}$/;
const BRANCH_PATTERN = /^[A-Za-z0-9._/-]{1,100}$/;

export class VaultError extends Error {}

export function emptyCatalog() {
  return { format: "jma-catalog", version: 1, revision: 0, updatedAt: null, entries: [] };
}

function defaultSettings() {
  return { format: "jma-settings", version: 1, contributions: null, keyHistory: [] };
}

function cleanText(value, limit) {
  return typeof value === "string" ? value.normalize("NFC").slice(0, limit) : "";
}

function cleanDate(value) {
  const date = new Date(typeof value === "string" ? value : "");
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

export function sanitizeContributionConfig(value) {
  if (!value || typeof value !== "object") {
    return null;
  }
  const owner = String(value.owner || "").trim();
  const name = String(value.name || "").trim();
  const branch = String(value.branch || "main").trim();
  const token = String(value.token || "").trim();
  if (!OWNER_PATTERN.test(owner) || !REPO_PATTERN.test(name) || !BRANCH_PATTERN.test(branch)
    || !token || token.length > 400 || /\s/.test(token)) {
    return null;
  }
  return { owner, name, branch, token };
}

export class VaultStore {
  // source: "library" (repositorio del sitio) o "contribution" (repositorio de aportes).
  // publicRoot: URL del sitio en GitHub Pages para leer sin token, o null.
  constructor({ source, basePath, publicRoot, repository }) {
    this.source = source;
    this.basePath = String(basePath || "vault").replace(/^\/+|\/+$/g, "");
    this.publicRoot = publicRoot || null;
    this.repository = repository || null;
  }

  path(name) {
    return `${this.basePath}/${name}`;
  }

  get canWrite() {
    return Boolean(this.repository && this.repository.token);
  }

  requireWriter() {
    if (!this.canWrite) {
      throw new VaultError("Esta acción necesita un token de GitHub con permiso de escritura.");
    }
    return this.repository;
  }

  // Con token se lee de la API (siempre al día). Sin token, de GitHub Pages,
  // que tarda alrededor de un minuto en reflejar cada guardado.
  async readRaw(path, ref) {
    if (this.repository && (this.repository.token || !this.publicRoot)) {
      return this.repository.readFile(path, ref);
    }
    if (!this.publicRoot) {
      return null;
    }
    let response;
    try {
      response = await fetch(new URL(path, this.publicRoot), { cache: "no-store", credentials: "omit" });
    } catch (_error) {
      throw new VaultError("No fue posible contactar el sitio. Revisa la conexión.");
    }
    if (response.status === 404) {
      return null;
    }
    if (!response.ok) {
      throw new VaultError(`El sitio respondió con el estado ${response.status}.`);
    }
    return new Uint8Array(await response.arrayBuffer());
  }

  sanitizeCatalog(value) {
    const catalog = emptyCatalog();
    if (!value || typeof value !== "object" || !Array.isArray(value.entries)) {
      return catalog;
    }
    catalog.revision = Number.isInteger(value.revision) && value.revision >= 0 ? value.revision : 0;
    catalog.updatedAt = cleanDate(value.updatedAt);
    const seen = new Set();

    for (const raw of value.entries.slice(0, 5000)) {
      if (!raw || typeof raw !== "object" || !ENTRY_ID.test(raw.id) || seen.has(raw.id)) {
        continue;
      }
      seen.add(raw.id);
      const files = [];
      for (const file of Array.isArray(raw.files) ? raw.files.slice(0, LIMITS.maxFilesPerEntry) : []) {
        const extension = String(file && file.ext || "").toLowerCase();
        const size = Number(file && file.size);
        if (!file || !FILE_ID.test(file.id) || !typeFor(extension) || !/^[0-9a-f]{64}$/.test(file.sha256)
          || !Number.isInteger(size) || size <= 0 || size > LIMITS.maxFileBytes) {
          continue;
        }
        // La ruta se reconstruye desde el identificador; nunca se confía en la guardada.
        files.push({
          id: file.id,
          name: sanitizeFileName(file.name, extension),
          ext: extension,
          size,
          sha256: file.sha256,
          path: this.path(`${FILES_DIR}/${file.id}.bin`)
        });
      }
      catalog.entries.push({
        id: raw.id,
        source: this.source,
        title: cleanText(raw.title, LIMITS.maxTitleLength) || "Sin título",
        text: cleanText(raw.text, LIMITS.maxTextLength),
        author: cleanText(raw.author, LIMITS.maxAuthorLength) || "Sin nombre",
        createdAt: cleanDate(raw.createdAt),
        files
      });
    }
    return catalog;
  }

  async loadCatalog(keyChain, ref) {
    const sealed = await this.readRaw(this.path(CATALOG_FILE), ref);
    if (!sealed) {
      return emptyCatalog();
    }
    return this.sanitizeCatalog(await openJson(keyChain, sealed, `catalog:${this.source}`));
  }

  async sealCatalogBlob(keyChain, catalog) {
    const stored = {
      format: "jma-catalog",
      version: 1,
      revision: catalog.revision,
      updatedAt: catalog.updatedAt,
      entries: catalog.entries.map(({ source, ...entry }) => ({
        ...entry,
        files: entry.files.map(({ path, ...file }) => file)
      }))
    };
    return this.repository.createBlob(await sealJson(keyChain.current, stored, `catalog:${this.source}`));
  }

  async readFile(keyChain, file) {
    const sealed = await this.readRaw(file.path);
    if (!sealed) {
      throw new VaultError("El archivo cifrado todavía no está disponible. Si se guardó hace instantes, espera un minuto.");
    }
    const bytes = await openBytes(keyChain, sealed, `file:${file.id}`);
    if (await sha256Hex(bytes) !== file.sha256) {
      throw new VaultError("La huella del archivo no coincide con el registro. No se entregó.");
    }
    if (!verifyContent(file.ext, bytes)) {
      throw new VaultError("El contenido no corresponde al tipo declarado. No se entregó.");
    }
    return bytes;
  }

  // files: [{ name, ext, bytes }]. Primero sube los archivos cifrados y al final
  // registra la entrada en el catálogo, todo en un solo commit.
  async addEntry(keyChain, draft, files, onProgress = () => {}) {
    const repository = this.requireWriter();
    await repository.ensureInitialized();

    const entry = {
      id: randomId("e_"),
      source: this.source,
      title: cleanText(draft.title, LIMITS.maxTitleLength) || "Sin título",
      text: cleanText(draft.text, LIMITS.maxTextLength),
      author: cleanText(draft.author, LIMITS.maxAuthorLength) || "Sin nombre",
      createdAt: new Date().toISOString(),
      files: []
    };
    const fileChanges = [];

    for (const [index, file] of files.entries()) {
      onProgress({ phase: "encrypt", index: index + 1, total: files.length, name: file.name });
      const id = randomId("f_");
      const sealed = await sealBytes(keyChain.current, file.bytes, `file:${id}`);
      onProgress({ phase: "upload", index: index + 1, total: files.length, name: file.name });
      const sha = await repository.createBlob(sealed);
      const path = this.path(`${FILES_DIR}/${id}.bin`);
      entry.files.push({
        id,
        name: sanitizeFileName(file.name, file.ext),
        ext: file.ext,
        size: file.bytes.length,
        sha256: await sha256Hex(file.bytes),
        path
      });
      fileChanges.push({ path, sha });
    }

    onProgress({ phase: "commit" });
    let savedCatalog = null;
    await repository.commit("Nueva entrada cifrada", async (head) => {
      const catalog = await this.loadCatalog(keyChain, head.commit);
      catalog.entries = catalog.entries.filter((existing) => existing.id !== entry.id).concat(entry);
      catalog.revision += 1;
      catalog.updatedAt = new Date().toISOString();
      savedCatalog = catalog;
      return [...fileChanges, { path: this.path(CATALOG_FILE), sha: await this.sealCatalogBlob(keyChain, catalog) }];
    });
    return { entry, catalog: savedCatalog };
  }

  async removeEntry(keyChain, entryId) {
    const repository = this.requireWriter();
    let savedCatalog = null;
    await repository.commit("Elimina entrada cifrada", async (head) => {
      const catalog = await this.loadCatalog(keyChain, head.commit);
      const entry = catalog.entries.find((candidate) => candidate.id === entryId);
      savedCatalog = catalog;
      if (!entry) {
        return [];
      }
      catalog.entries = catalog.entries.filter((candidate) => candidate.id !== entryId);
      catalog.revision += 1;
      catalog.updatedAt = new Date().toISOString();
      const existing = await repository.listPaths(head.tree, this.path(`${FILES_DIR}/`));
      return [
        { path: this.path(CATALOG_FILE), sha: await this.sealCatalogBlob(keyChain, catalog) },
        ...entry.files.filter((file) => existing.has(file.path)).map((file) => ({ path: file.path, sha: null }))
      ];
    });
    return savedCatalog;
  }

  // Vuelve a cifrar solo el catálogo con la llave vigente (tras cambiar la clave).
  async resealCatalog(keyChain) {
    const repository = this.requireWriter();
    await repository.commit("Actualiza catálogo cifrado", async (head) => {
      const catalog = await this.loadCatalog(keyChain, head.commit);
      if (!catalog.revision && !catalog.entries.length) {
        return [];
      }
      catalog.revision += 1;
      catalog.updatedAt = new Date().toISOString();
      return [{ path: this.path(CATALOG_FILE), sha: await this.sealCatalogBlob(keyChain, catalog) }];
    });
  }
}

// ----- Llavero y ajustes (solo en la biblioteca) -----

function parseKeyring(bytes) {
  let keyring;
  try {
    keyring = JSON.parse(new TextDecoder().decode(bytes));
  } catch (_error) {
    throw new VaultError("El llavero de la bóveda está dañado.");
  }
  if (!keyring || keyring.format !== "jma-vault" || keyring.version !== 1 || !Array.isArray(keyring.slots)) {
    throw new VaultError("El llavero de la bóveda tiene un formato no admitido.");
  }
  return keyring;
}

export async function fetchKeyring(library) {
  const bytes = await library.readRaw(library.path(KEYRING_FILE));
  return bytes ? parseKeyring(bytes) : null;
}

async function buildKeyringBlob(repository, password, contentKey) {
  const keyring = {
    format: "jma-vault",
    version: 1,
    cipher: "AES-256-GCM, llave envuelta con PBKDF2-SHA256",
    slots: [await createSlot(SLOT_ID, password, contentKey)]
  };
  return repository.createBlob(new TextEncoder().encode(`${JSON.stringify(keyring, null, 2)}\n`));
}

export async function loadSettings(library, keyChain, ref) {
  const sealed = await library.readRaw(library.path(SETTINGS_FILE), ref);
  if (!sealed) {
    return defaultSettings();
  }
  const value = await openJson(keyChain, sealed, "settings");
  return {
    ...defaultSettings(),
    contributions: sanitizeContributionConfig(value && value.contributions),
    keyHistory: Array.isArray(value && value.keyHistory) ? value.keyHistory.slice(0, 100) : []
  };
}

async function sealSettingsBlob(repository, keyChain, settings) {
  return repository.createBlob(await sealJson(keyChain.current, settings, "settings"));
}

// Suma al llavero las llaves anteriores, para leer lo cifrado antes de un cambio de clave.
export async function applyKeyHistory(keyChain, settings) {
  for (const exported of settings.keyHistory) {
    try {
      keyChain.add(await importExportedKey(exported));
    } catch (_error) {
      // Una llave dañada del historial solo afecta a los archivos que cifró.
    }
  }
}

// Devuelve { keyChain, settings }, null si la clave no corresponde, o lanza
// VaultError si la bóveda no existe.
export async function unlockVault(library, password) {
  const keyring = await fetchKeyring(library);
  if (!keyring) {
    throw new VaultError("La bóveda todavía no está configurada.");
  }
  for (const slot of keyring.slots) {
    const contentKey = await unlockSlot(slot, password);
    if (contentKey) {
      return openWithKey(library, contentKey);
    }
  }
  return null;
}

export async function openWithKey(library, contentKey) {
  const keyChain = new KeyChain(contentKey);
  const settings = await loadSettings(library, keyChain);
  await applyKeyHistory(keyChain, settings);

  // Prueba real de la llave: el catálogo tiene que descifrar. Sin esto, una
  // sesión inventada a mano en sessionStorage abriría la interfaz, aunque fuera
  // vacía, y la pantalla de acceso dejaría de significar algo.
  const sealed = await library.readRaw(library.path(CATALOG_FILE));
  if (!sealed) {
    throw new VaultError("No se encontró el catálogo cifrado de la bóveda.");
  }
  const catalog = library.sanitizeCatalog(await openJson(keyChain, sealed, "catalog:library"));
  return { keyChain, settings, catalog };
}

export async function createVault(library, password) {
  const repository = library.requireWriter();
  await repository.ensureInitialized();
  const contentKey = await generateContentKey();
  const keyChain = new KeyChain(contentKey);
  const catalog = emptyCatalog();
  catalog.updatedAt = new Date().toISOString();

  await repository.commit("Crea bóveda cifrada", async (head) => {
    if (await repository.readFile(library.path(KEYRING_FILE), head.commit)) {
      throw new VaultError("La bóveda ya existe en este repositorio. Ingresa con su clave.");
    }
    return [
      { path: library.path(KEYRING_FILE), sha: await buildKeyringBlob(repository, password, contentKey) },
      { path: library.path(CATALOG_FILE), sha: await library.sealCatalogBlob(keyChain, catalog) }
    ];
  });
  return { keyChain, settings: defaultSettings(), catalog };
}

export async function saveContributionSettings(library, keyChain, contributions) {
  const repository = library.requireWriter();
  let saved = null;
  await repository.commit("Actualiza ajustes cifrados", async (head) => {
    const settings = await loadSettings(library, keyChain, head.commit);
    settings.contributions = contributions ? sanitizeContributionConfig(contributions) : null;
    saved = settings;
    return [{ path: library.path(SETTINGS_FILE), sha: await sealSettingsBlob(repository, keyChain, settings) }];
  });
  return saved;
}

// Cambiar la clave genera una llave de contenido nueva. Lo nuevo queda cifrado
// con ella, y la anterior pasa al historial cifrado dentro de settings.bin: quien
// solo conoce la clave vieja deja de leer todo lo que se guarde desde ahora.
export async function changePassword(library, keyChain, newPassword) {
  const repository = library.requireWriter();
  const newKey = await generateContentKey();
  const nextChain = new KeyChain(newKey);
  keyChain.keys.forEach((contentKey) => nextChain.add(contentKey));
  let saved = null;

  await repository.commit("Actualiza llavero de la bóveda", async (head) => {
    const settings = await loadSettings(library, keyChain, head.commit);
    const catalog = await library.loadCatalog(keyChain, head.commit);
    settings.keyHistory = nextChain.history().map(exportContentKey);
    catalog.revision += 1;
    catalog.updatedAt = new Date().toISOString();
    saved = settings;
    return [
      { path: library.path(KEYRING_FILE), sha: await buildKeyringBlob(repository, newPassword, newKey) },
      { path: library.path(SETTINGS_FILE), sha: await sealSettingsBlob(repository, nextChain, settings) },
      { path: library.path(CATALOG_FILE), sha: await library.sealCatalogBlob(nextChain, catalog) }
    ];
  });
  return { keyChain: nextChain, settings: saved };
}
