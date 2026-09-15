// Interfaz del portal. No guarda ningún dato en claro: pide la clave, descifra
// en memoria y vuelve a cifrar todo lo que se sube.

import config from "./config.js";
import {
  exportContentKey,
  generatePassphrase,
  importExportedKey,
  normalizePassword,
  validateNewPassword
} from "./crypto.js";
import { GitHubRepository } from "./github.js";
import {
  ACCEPT_ATTRIBUTE,
  LIMITS,
  formatBytes,
  inspectFile,
  extensionOf,
  screenshotName,
  stripJpegMetadata,
  typeFor
} from "./files.js";
import {
  VaultError,
  VaultStore,
  changePassword,
  createVault,
  emptyCatalog,
  fetchKeyring,
  openWithKey,
  sanitizeContributionConfig,
  saveContributionSettings,
  unlockVault
} from "./vault.js";

const SESSION_KEY = "jma-vault-key";
const AUTHOR_KEY = "jma-author-name";
const TOKEN_KEY = "jma-admin-token";

// Sin servidor propio no se puede fijar frame-ancestors, así que la página se
// niega a funcionar dentro de un marco ajeno.
if (window.top !== window.self) {
  document.body.textContent = "Esta página no puede mostrarse dentro de otro sitio.";
  throw new Error("framed");
}

const elements = {};
const state = {
  keyChain: null,
  settings: null,
  library: null,
  contributions: null,
  libraryCatalog: emptyCatalog(),
  contributionCatalog: emptyCatalog(),
  entries: [],
  filter: "all",
  search: "",
  pendingFiles: [],
  previewUrls: [],
  busy: false,
  refreshTimer: null,
  idleTimer: null,
  lastActivity: Date.now()
};

function element(id) {
  const node = document.getElementById(id);
  if (!node) {
    throw new Error(`Falta el elemento ${id} en la página.`);
  }
  return node;
}

function safeStorage(storage, action, key, value) {
  try {
    if (action === "get") return storage.getItem(key);
    if (action === "set") storage.setItem(key, value);
    if (action === "remove") storage.removeItem(key);
  } catch (_error) {
    // Un navegador sin almacenamiento sigue funcionando, solo pide la clave más veces.
  }
  return null;
}

function formatDate(value, withTime = false) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "Sin fecha";
  }
  return new Intl.DateTimeFormat("es-PE", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    ...(withTime ? { hour: "2-digit", minute: "2-digit" } : {})
  }).format(date);
}

function normalizeForSearch(value) {
  return String(value || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase();
}

function showToast(message) {
  elements.toast.textContent = message;
  elements.toast.classList.add("is-visible");
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => elements.toast.classList.remove("is-visible"), 3200);
}

function setMessage(node, message, kind = "") {
  node.textContent = message;
  node.classList.toggle("is-success", kind === "success");
  node.classList.toggle("is-error", kind === "error");
}

function describeError(error) {
  return (error && error.message) || "Ocurrió un error inesperado.";
}

function setUploadFieldsHidden(hidden) {
  elements.uploadForm.querySelectorAll(".field-group, .drop-zone, .checkbox-row, .intake-actions").forEach((node) => {
    node.hidden = hidden;
  });
}

// ----- Repositorio y almacenes -----

function detectRepository() {
  if (config.repository && config.repository.owner && config.repository.name) {
    return { owner: config.repository.owner, name: config.repository.name };
  }
  const host = /^([A-Za-z0-9-]+)\.github\.io$/.exec(location.hostname);
  if (!host) {
    return null;
  }
  const firstSegment = location.pathname.split("/").filter(Boolean)[0];
  const isProjectSite = firstSegment && !firstSegment.includes(".");
  return { owner: host[1], name: isProjectSite ? firstSegment : `${host[1]}.github.io` };
}

function buildLibraryStore(token) {
  const repository = detectRepository();
  return new VaultStore({
    source: "library",
    basePath: config.vaultPath,
    publicRoot: new URL(".", location.href).href,
    repository: repository
      ? new GitHubRepository({ apiBase: config.apiBase, owner: repository.owner, name: repository.name, branch: config.branch, token })
      : null
  });
}

function buildContributionStore(contributions) {
  if (!contributions) {
    return null;
  }
  return new VaultStore({
    source: "contribution",
    basePath: config.vaultPath,
    publicRoot: null,
    repository: new GitHubRepository({
      apiBase: config.apiBase,
      owner: contributions.owner,
      name: contributions.name,
      branch: contributions.branch,
      token: contributions.token
    })
  });
}

function storedAdminToken() {
  return safeStorage(localStorage, "get", TOKEN_KEY) || safeStorage(sessionStorage, "get", TOKEN_KEY) || "";
}

function isAdmin() {
  return Boolean(state.library && state.library.canWrite);
}

// ----- Carga y render del catálogo -----

async function loadCatalogs({ silent = false } = {}) {
  if (!state.keyChain) {
    return;
  }
  try {
    const libraryCatalog = await state.library.loadCatalog(state.keyChain);
    if (libraryCatalog.revision >= state.libraryCatalog.revision) {
      state.libraryCatalog = libraryCatalog;
    }
  } catch (error) {
    if (!silent) {
      showToast(`No se pudo leer la biblioteca: ${describeError(error)}`);
    }
  }

  if (state.contributions) {
    try {
      const contributionCatalog = await state.contributions.loadCatalog(state.keyChain);
      if (contributionCatalog.revision >= state.contributionCatalog.revision) {
        state.contributionCatalog = contributionCatalog;
      }
    } catch (error) {
      if (!silent) {
        showToast(`No se pudieron leer los aportes: ${describeError(error)}`);
      }
    }
  } else {
    state.contributionCatalog = emptyCatalog();
  }
  refreshEntries();
}

function refreshEntries() {
  state.entries = [...state.libraryCatalog.entries, ...state.contributionCatalog.entries]
    .sort((left, right) => String(right.createdAt || "").localeCompare(String(left.createdAt || "")));
  renderStatistics();
  renderEntries();
}

function renderStatistics() {
  const files = state.entries.reduce((total, entry) => total + entry.files.length, 0);
  const contributions = state.contributionCatalog.entries.length;
  const pad = (value) => String(value).padStart(2, "0");
  elements.metricEntries.textContent = pad(state.entries.length);
  elements.metricFiles.textContent = pad(files);
  elements.metricContributions.textContent = pad(contributions);
  elements.statEntries.textContent = pad(state.entries.length);
  elements.statFiles.textContent = pad(files);
  elements.statLibrary.textContent = pad(state.libraryCatalog.entries.length);
  elements.statContributions.textContent = pad(contributions);

  const updated = [state.libraryCatalog.updatedAt, state.contributionCatalog.updatedAt]
    .filter(Boolean)
    .sort()
    .pop();
  elements.catalogUpdated.textContent = updated
    ? `Última actualización: ${formatDate(updated, true)}`
    : "Bóveda sin actualizaciones registradas";
}

function matchesFilter(entry) {
  if (state.filter === "all") {
    return true;
  }
  if (state.filter === "library" || state.filter === "contribution") {
    return entry.source === state.filter;
  }
  return entry.files.some((file) => {
    const type = typeFor(file.ext);
    return type && type.kind === state.filter;
  });
}

function matchesSearch(entry) {
  if (!state.search) {
    return true;
  }
  const haystack = normalizeForSearch([
    entry.title,
    entry.author,
    entry.text,
    ...entry.files.map((file) => file.name)
  ].join(" "));
  return haystack.includes(state.search);
}

function createFileRow(entry, file) {
  const row = document.createElement("div");
  row.className = "file-row";

  const badge = document.createElement("span");
  badge.className = "file-badge";
  const type = typeFor(file.ext);
  badge.textContent = type ? type.label : file.ext.toUpperCase();

  const name = document.createElement("span");
  name.className = "file-name";
  name.textContent = file.name;
  name.title = file.name;

  const size = document.createElement("span");
  size.className = "file-size";
  size.textContent = formatBytes(file.size);

  const actions = document.createElement("span");
  actions.className = "file-actions";
  if (type && type.viewable) {
    const view = document.createElement("button");
    view.type = "button";
    view.className = "card-action";
    view.textContent = "Ver";
    view.addEventListener("click", () => openFileViewer(entry, file));
    actions.append(view);
  }
  const download = document.createElement("button");
  download.type = "button";
  download.className = "card-action primary";
  download.textContent = "Descargar";
  download.addEventListener("click", () => downloadFile(entry, file, download));
  actions.append(download);

  row.append(badge, name, size, actions);
  return row;
}

function createEntryCard(entry) {
  const card = document.createElement("article");
  card.className = "document-card";
  card.dataset.source = entry.source;

  const topLine = document.createElement("div");
  topLine.className = "card-topline";
  const source = document.createElement("span");
  source.className = "source-badge";
  source.textContent = entry.source === "library" ? "Biblioteca" : "Aporte";
  const date = document.createElement("span");
  date.className = "topic-label";
  date.textContent = formatDate(entry.createdAt, true);
  topLine.append(source, date);

  const heading = document.createElement("h3");
  heading.textContent = entry.title;

  const author = document.createElement("p");
  author.className = "entry-author";
  author.textContent = `Guardado por ${entry.author}`;

  const text = document.createElement("p");
  text.className = "document-description";
  text.textContent = entry.text ? entry.text.slice(0, 240) + (entry.text.length > 240 ? "…" : "") : "Sin texto.";

  const files = document.createElement("div");
  files.className = "file-list";
  entry.files.forEach((file) => files.append(createFileRow(entry, file)));

  const actions = document.createElement("div");
  actions.className = "card-actions";
  const open = document.createElement("button");
  open.type = "button";
  open.className = "card-action";
  open.textContent = "Ver detalle";
  open.addEventListener("click", () => openEntryViewer(entry));
  actions.append(open);

  const store = entry.source === "library" ? state.library : state.contributions;
  if (store && store.canWrite) {
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "card-action danger";
    remove.textContent = "Eliminar";
    remove.addEventListener("click", () => removeEntry(entry, remove));
    actions.append(remove);
  }

  card.append(topLine, heading, author, text);
  if (entry.files.length) {
    card.append(files);
  }
  card.append(actions);
  return card;
}

function renderEntries() {
  const visible = state.entries.filter((entry) => matchesFilter(entry) && matchesSearch(entry));
  elements.documentsGrid.replaceChildren(...visible.map(createEntryCard));
  elements.emptyState.hidden = visible.length > 0;
  elements.resultCount.textContent = `${visible.length} entrada${visible.length === 1 ? "" : "s"}`;
  if (!state.entries.length) {
    elements.emptyTitle.textContent = "Todavía no hay nada guardado";
    elements.emptyText.textContent = isAdmin()
      ? "Usa la sección Guardar para subir el primer documento."
      : "Cuando se publique contenido aparecerá aquí.";
  } else {
    elements.emptyTitle.textContent = "Ningún resultado";
    elements.emptyText.textContent = "Ajusta el filtro o la búsqueda.";
  }
}

// ----- Descarga y vista de archivos -----

function trackUrl(url) {
  state.previewUrls.push(url);
  return url;
}

function releaseUrls() {
  state.previewUrls.forEach((url) => URL.revokeObjectURL(url));
  state.previewUrls = [];
}

function storeFor(entry) {
  return entry.source === "library" ? state.library : state.contributions;
}

async function decryptFile(entry, file) {
  const store = storeFor(entry);
  if (!store) {
    throw new VaultError("El repositorio de esa entrada no está disponible en esta sesión.");
  }
  return store.readFile(state.keyChain, file);
}

async function downloadFile(entry, file, button) {
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "Descifrando…";
  try {
    const bytes = await decryptFile(entry, file);
    const type = typeFor(file.ext);
    const url = URL.createObjectURL(new Blob([bytes], { type: type ? type.mime : "application/octet-stream" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = file.name;
    link.rel = "noopener";
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 20000);
    showToast(`${file.name} descifrado en tu dispositivo.`);
  } catch (error) {
    showToast(describeError(error));
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

function renderMarkdown(container, text) {
  if (!window.marked || !window.DOMPurify) {
    const fallback = document.createElement("pre");
    fallback.className = "plain-text";
    fallback.textContent = text;
    container.append(fallback);
    return;
  }
  const rendered = window.marked.parse(text, { gfm: true, breaks: false });
  container.innerHTML = window.DOMPurify.sanitize(rendered, {
    USE_PROFILES: { html: true },
    FORBID_TAGS: ["style", "script", "iframe", "object", "embed", "form", "input", "button", "textarea", "select", "option", "svg", "math"],
    FORBID_ATTR: ["style", "srcset", "formaction"],
    ALLOW_DATA_ATTR: false
  });
  container.querySelectorAll("a").forEach((link) => {
    const href = String(link.getAttribute("href") || "");
    if (/^https?:\/\//i.test(href)) {
      link.target = "_blank";
      link.rel = "noopener noreferrer";
    } else {
      link.removeAttribute("href");
    }
  });
}

function openDialog() {
  if (typeof elements.documentDialog.showModal === "function") {
    if (!elements.documentDialog.open) {
      elements.documentDialog.showModal();
    }
  } else {
    elements.documentDialog.setAttribute("open", "");
  }
}

function closeDialog() {
  releaseUrls();
  if (typeof elements.documentDialog.close === "function" && elements.documentDialog.open) {
    elements.documentDialog.close();
  } else {
    elements.documentDialog.removeAttribute("open");
  }
  elements.viewerBody.replaceChildren();
}

function openEntryViewer(entry) {
  releaseUrls();
  elements.viewerTitle.textContent = entry.title;
  elements.viewerType.textContent = entry.source === "library" ? "Biblioteca" : "Aporte";
  elements.viewerTopic.textContent = `${entry.author} · ${formatDate(entry.createdAt, true)}`;
  elements.viewerLoading.hidden = true;
  elements.viewerBody.replaceChildren();

  if (entry.text) {
    const text = document.createElement("p");
    text.className = "plain-text";
    text.textContent = entry.text;
    elements.viewerBody.append(text);
  }
  if (entry.files.length) {
    const heading = document.createElement("h3");
    heading.textContent = "Archivos";
    const list = document.createElement("div");
    list.className = "file-list";
    entry.files.forEach((file) => list.append(createFileRow(entry, file)));
    elements.viewerBody.append(heading, list);
  }
  openDialog();
}

async function openFileViewer(entry, file) {
  releaseUrls();
  elements.viewerTitle.textContent = file.name;
  elements.viewerType.textContent = typeFor(file.ext) ? typeFor(file.ext).label : file.ext.toUpperCase();
  elements.viewerTopic.textContent = `${entry.author} · ${formatDate(entry.createdAt, true)}`;
  elements.viewerBody.replaceChildren();
  elements.viewerLoading.hidden = false;
  openDialog();

  try {
    const bytes = await decryptFile(entry, file);
    const type = typeFor(file.ext);
    if (type.kind === "image") {
      const image = document.createElement("img");
      image.src = trackUrl(URL.createObjectURL(new Blob([bytes], { type: type.mime })));
      image.alt = file.name;
      elements.viewerBody.append(image);
    } else {
      const text = new TextDecoder().decode(bytes);
      if (file.ext === "md") {
        renderMarkdown(elements.viewerBody, text);
      } else {
        const pre = document.createElement("pre");
        pre.className = "plain-text";
        pre.textContent = text;
        elements.viewerBody.append(pre);
      }
    }
  } catch (error) {
    const heading = document.createElement("h3");
    heading.textContent = "No se pudo abrir";
    const detail = document.createElement("p");
    detail.textContent = describeError(error);
    elements.viewerBody.append(heading, detail);
  } finally {
    elements.viewerLoading.hidden = true;
  }
}

async function removeEntry(entry, button) {
  if (!window.confirm(`¿Eliminar "${entry.title}" de forma permanente?`)) {
    return;
  }
  button.disabled = true;
  try {
    const store = storeFor(entry);
    const catalog = await store.removeEntry(state.keyChain, entry.id);
    if (entry.source === "library") {
      state.libraryCatalog = catalog;
    } else {
      state.contributionCatalog = catalog;
    }
    refreshEntries();
    showToast("Entrada eliminada.");
  } catch (error) {
    showToast(describeError(error));
  } finally {
    button.disabled = false;
  }
}

// ----- Registro en CSV -----

function csvCell(value) {
  const text = String(value === null || value === undefined ? "" : value);
  const guarded = /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;
  return `"${guarded.replace(/"/g, '""')}"`;
}

function exportRegistry() {
  const rows = [["Fecha", "Origen", "Autor", "Titulo", "Texto", "Archivo", "Tipo", "Tamano (bytes)", "SHA-256"]];
  for (const entry of state.entries) {
    const base = [
      entry.createdAt || "",
      entry.source === "library" ? "Biblioteca" : "Aporte",
      entry.author,
      entry.title,
      entry.text.replace(/\r?\n/g, " ")
    ];
    if (!entry.files.length) {
      rows.push([...base, "", "", "", ""]);
      continue;
    }
    for (const file of entry.files) {
      rows.push([...base, file.name, (typeFor(file.ext) || { label: file.ext }).label, file.size, file.sha256]);
    }
  }
  const csv = "﻿" + rows.map((row) => row.map(csvCell).join(";")).join("\r\n");
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = `registro-bóveda-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 20000);
  showToast("Registro descargado. Contiene fecha, autor y huella de cada archivo.");
}

// ----- Subida -----

function renderPendingFiles() {
  const previews = state.pendingFiles.map((item, index) => {
    const preview = document.createElement("article");
    preview.className = "image-preview";
    const type = typeFor(item.ext);

    if (type.kind === "image") {
      const image = document.createElement("img");
      image.src = item.previewUrl;
      image.alt = item.name;
      preview.append(image);
    } else {
      const placeholder = document.createElement("div");
      placeholder.className = "file-placeholder";
      placeholder.textContent = type.label;
      preview.append(placeholder);
    }

    const meta = document.createElement("div");
    meta.className = "image-preview-meta";
    meta.title = item.name;
    meta.textContent = `${item.name} · ${formatBytes(item.file.size)}`;

    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "remove-image";
    remove.setAttribute("aria-label", `Quitar ${item.name}`);
    remove.textContent = "×";
    remove.addEventListener("click", () => {
      const [removed] = state.pendingFiles.splice(index, 1);
      if (removed.previewUrl) {
        URL.revokeObjectURL(removed.previewUrl);
      }
      renderPendingFiles();
    });

    preview.append(meta, remove);
    return preview;
  });
  elements.filePreviewGrid.replaceChildren(...previews);
}

async function addFiles(fileList) {
  const rejected = [];
  for (let file of Array.from(fileList || [])) {
    if (state.pendingFiles.length >= LIMITS.maxFilesPerEntry) {
      rejected.push(`Máximo ${LIMITS.maxFilesPerEntry} archivos por entrada.`);
      break;
    }
    const inspection = await inspectFile(file);
    if (!inspection.ok) {
      rejected.push(inspection.reason);
      continue;
    }
    if (elements.stripMetadata.checked && inspection.type.mime === "image/jpeg") {
      try {
        file = await stripJpegMetadata(file);
      } catch (_error) {
        // Si el navegador no puede reprocesar la imagen, se sube tal cual.
      }
    }
    const total = state.pendingFiles.reduce((sum, item) => sum + item.file.size, 0) + file.size;
    if (total > LIMITS.maxEntryBytes) {
      rejected.push(`La entrada supera ${formatBytes(LIMITS.maxEntryBytes)} en total.`);
      break;
    }
    state.pendingFiles.push({
      file,
      name: file.name,
      ext: inspection.extension,
      previewUrl: inspection.type.kind === "image" ? URL.createObjectURL(file) : ""
    });
  }
  elements.fileInput.value = "";
  renderPendingFiles();
  setMessage(
    elements.uploadMessage,
    rejected.length ? rejected[0] : `${state.pendingFiles.length} archivo${state.pendingFiles.length === 1 ? "" : "s"} listo${state.pendingFiles.length === 1 ? "" : "s"}.`,
    rejected.length ? "error" : ""
  );
}

function resetUploadForm(message = "", kind = "") {
  state.pendingFiles.forEach((item) => item.previewUrl && URL.revokeObjectURL(item.previewUrl));
  state.pendingFiles = [];
  elements.uploadTitleField.value = "";
  elements.uploadText.value = "";
  elements.characterCount.textContent = "0 / 20,000";
  elements.fileInput.value = "";
  elements.filePreviewGrid.replaceChildren();
  elements.uploadProgress.hidden = true;
  elements.uploadProgress.value = 0;
  setMessage(elements.uploadMessage, message, kind);
}

function selectedDestination() {
  const canLibrary = isAdmin();
  const canContribute = Boolean(state.contributions && state.contributions.canWrite);
  if (canLibrary && canContribute) {
    return elements.destinationContribution.checked ? "contribution" : "library";
  }
  if (canLibrary) {
    return "library";
  }
  return canContribute ? "contribution" : null;
}

function updateUploadAvailability() {
  const canLibrary = isAdmin();
  const canContribute = Boolean(state.contributions && state.contributions.canWrite);
  const enabled = canLibrary || canContribute;

  elements.destinationGroup.hidden = !(canLibrary && canContribute);
  setUploadFieldsHidden(!enabled);
  elements.uploadNotice.hidden = enabled;
  if (!enabled) {
    elements.uploadNotice.textContent = "Por ahora solo quien administra el repositorio puede guardar contenido. Cuando se active la recepción de aportes, este formulario quedará disponible para todos.";
  }
  if (canLibrary && !canContribute) {
    elements.destinationLibrary.checked = true;
  }
  if (!canLibrary && canContribute) {
    elements.destinationContribution.checked = true;
  }
}

async function submitUpload(event) {
  event.preventDefault();
  if (state.busy) {
    return;
  }
  const destination = selectedDestination();
  if (!destination) {
    setMessage(elements.uploadMessage, "No tienes permiso para guardar en esta bóveda.", "error");
    return;
  }
  const author = elements.uploadAuthor.value.trim();
  const title = elements.uploadTitleField.value.trim();
  const text = elements.uploadText.value.trim();
  if (!author) {
    setMessage(elements.uploadMessage, "Escribe tu nombre: queda registrado junto a la fecha.", "error");
    elements.uploadAuthor.focus();
    return;
  }
  if (!title) {
    setMessage(elements.uploadMessage, "Ponle un título a la entrada.", "error");
    elements.uploadTitleField.focus();
    return;
  }
  if (!text && !state.pendingFiles.length) {
    setMessage(elements.uploadMessage, "Agrega texto o al menos un archivo.", "error");
    return;
  }

  const store = destination === "library" ? state.library : state.contributions;
  state.busy = true;
  elements.submitUpload.disabled = true;
  elements.clearUpload.disabled = true;
  elements.uploadProgress.hidden = false;
  elements.uploadProgress.value = 2;
  safeStorage(localStorage, "set", AUTHOR_KEY, author);

  try {
    const files = [];
    for (const item of state.pendingFiles) {
      files.push({ name: item.name, ext: item.ext, bytes: new Uint8Array(await item.file.arrayBuffer()) });
    }
    const total = files.length || 1;
    const { catalog } = await store.addEntry(state.keyChain, { title, text, author }, files, (progress) => {
      if (progress.phase === "commit") {
        elements.uploadProgress.value = 95;
        setMessage(elements.uploadMessage, "Registrando en la bóveda…");
        return;
      }
      const done = progress.index - (progress.phase === "encrypt" ? 1 : 0);
      elements.uploadProgress.value = Math.min(90, 5 + Math.round((done / total) * 85));
      setMessage(
        elements.uploadMessage,
        `${progress.phase === "encrypt" ? "Cifrando" : "Subiendo"} ${progress.index} de ${progress.total}: ${progress.name}`
      );
    });
    elements.uploadProgress.value = 100;

    if (destination === "library") {
      state.libraryCatalog = catalog;
    } else {
      state.contributionCatalog = catalog;
    }
    refreshEntries();
    resetUploadForm(
      destination === "library"
        ? "Guardado y cifrado. Quien tenga la clave lo verá en aproximadamente un minuto, cuando GitHub Pages publique el cambio."
        : "Aporte guardado y cifrado. Queda registrado con tu nombre y la fecha.",
      "success"
    );
    showToast("Contenido guardado en la bóveda cifrada.");
  } catch (error) {
    elements.uploadProgress.hidden = true;
    setMessage(elements.uploadMessage, describeError(error), "error");
  } finally {
    state.busy = false;
    elements.submitUpload.disabled = false;
    elements.clearUpload.disabled = false;
  }
}

// ----- Sesión -----

function persistSession() {
  safeStorage(sessionStorage, "set", SESSION_KEY, JSON.stringify(exportContentKey(state.keyChain.current)));
}

async function openPortal({ fromSession = false } = {}) {
  elements.portal.hidden = false;
  elements.portal.removeAttribute("inert");
  document.body.classList.remove("is-locked");
  elements.lockScreen.hidden = true;
  elements.accessCode.value = "";
  setMessage(elements.accessMessage, "");
  updateAdminUi();
  updateUploadAvailability();
  refreshEntries();
  if (!fromSession) {
    elements.heroTitle.focus({ preventScroll: true });
  }
  startRefreshTimer();
  await loadCatalogs({ silent: true });
}

function lockPortal(message = "") {
  state.keyChain = null;
  state.settings = null;
  state.contributions = null;
  state.libraryCatalog = emptyCatalog();
  state.contributionCatalog = emptyCatalog();
  state.entries = [];
  safeStorage(sessionStorage, "remove", SESSION_KEY);
  releaseUrls();
  resetUploadForm();
  closeDialog();
  window.clearInterval(state.refreshTimer);
  state.refreshTimer = null;
  elements.documentsGrid.replaceChildren();
  elements.portal.hidden = true;
  elements.portal.setAttribute("inert", "");
  document.body.classList.add("is-locked");
  elements.lockScreen.hidden = false;
  elements.accessCode.disabled = false;
  elements.unlockButton.disabled = false;
  setMessage(elements.accessMessage, message, message ? "error" : "");
  elements.accessCode.focus();
}

function startRefreshTimer() {
  window.clearInterval(state.refreshTimer);
  const seconds = Math.max(15, Number(config.refreshSeconds) || 60);
  state.refreshTimer = window.setInterval(() => loadCatalogs({ silent: true }), seconds * 1000);
}

function noteActivity() {
  state.lastActivity = Date.now();
}

function startIdleWatch() {
  const minutes = Math.max(1, Number(config.idleLockMinutes) || 30);
  window.clearInterval(state.idleTimer);
  state.idleTimer = window.setInterval(() => {
    if (state.keyChain && !state.busy && Date.now() - state.lastActivity > minutes * 60000) {
      lockPortal(`Se cerró la sesión tras ${minutes} minutos sin actividad.`);
    }
  }, 30000);
}

async function handleUnlock(event) {
  event.preventDefault();
  const password = normalizePassword(elements.accessCode.value);
  if (!password) {
    setMessage(elements.accessMessage, "Escribe la clave de acceso.", "error");
    return;
  }
  elements.unlockButton.disabled = true;
  elements.accessCode.disabled = true;
  setMessage(elements.accessMessage, "Descifrando… puede tomar un segundo.");
  await new Promise((resolve) => window.setTimeout(resolve, 30));

  try {
    const opened = await unlockVault(state.library, password);
    if (!opened) {
      setMessage(elements.accessMessage, "Clave incorrecta.", "error");
      elements.accessCode.select();
      return;
    }
    await applySession(opened);
    await openPortal();
  } catch (error) {
    setMessage(elements.accessMessage, describeError(error), "error");
  } finally {
    elements.unlockButton.disabled = false;
    elements.accessCode.disabled = false;
  }
}

async function applySession({ keyChain, settings, catalog }) {
  state.keyChain = keyChain;
  state.settings = settings;
  if (catalog) {
    state.libraryCatalog = catalog;
  }
  state.contributions = buildContributionStore(settings.contributions);
  persistSession();
  if (state.settings.contributions) {
    elements.contributionOwner.value = state.settings.contributions.owner;
    elements.contributionRepo.value = state.settings.contributions.name;
    elements.contributionBranch.value = state.settings.contributions.branch;
  }
}

async function restoreSession() {
  const stored = safeStorage(sessionStorage, "get", SESSION_KEY);
  if (!stored) {
    return false;
  }
  try {
    const contentKey = await importExportedKey(JSON.parse(stored));
    const opened = await openWithKey(state.library, contentKey);
    await applySession(opened);
    await openPortal({ fromSession: true });
    return true;
  } catch (_error) {
    safeStorage(sessionStorage, "remove", SESSION_KEY);
    return false;
  }
}

// ----- Administración -----

function updateAdminUi() {
  const token = state.library.repository ? state.library.repository.token : "";
  const repositoryLabel = state.library.repository ? state.library.repository.label : "repositorio no detectado";
  elements.adminStatus.textContent = token
    ? `Conectado a ${repositoryLabel} con permiso de escritura.`
    : `Sin conectar (${repositoryLabel}). Solo lectura.`;
  elements.adminStatus.classList.toggle("is-connected", Boolean(token));
  elements.contributionsForm.hidden = !token;
  elements.passwordForm.hidden = !token;
}

async function connectAdmin(event) {
  event.preventDefault();
  const token = elements.adminToken.value.trim();
  if (!token) {
    setMessage(elements.adminMessage, "Pega el token de GitHub.", "error");
    return;
  }
  if (!state.library.repository) {
    setMessage(elements.adminMessage, "No se pudo detectar el repositorio. Configúralo en assets/js/config.js.", "error");
    return;
  }
  elements.adminConnect.disabled = true;
  setMessage(elements.adminMessage, "Verificando el token…");
  try {
    const probe = new GitHubRepository({
      apiBase: config.apiBase,
      owner: state.library.repository.owner,
      name: state.library.repository.name,
      branch: config.branch,
      token
    });
    const info = await probe.verifyWriteAccess();
    state.library.repository = probe;
    elements.adminToken.value = "";
    safeStorage(sessionStorage, "set", TOKEN_KEY, token);
    if (elements.adminRemember.checked) {
      safeStorage(localStorage, "set", TOKEN_KEY, token);
    }
    updateAdminUi();
    updateUploadAvailability();
    renderEntries();
    setMessage(
      elements.adminMessage,
      info.isPrivate
        ? "Token válido. Atención: este repositorio es privado, así que GitHub Pages podría no servir el sitio."
        : "Token válido. Ya puedes publicar en la biblioteca.",
      "success"
    );
    await loadCatalogs({ silent: true });
  } catch (error) {
    setMessage(elements.adminMessage, describeError(error), "error");
  } finally {
    elements.adminConnect.disabled = false;
  }
}

function disconnectAdmin() {
  safeStorage(localStorage, "remove", TOKEN_KEY);
  safeStorage(sessionStorage, "remove", TOKEN_KEY);
  if (state.library.repository) {
    state.library.repository.token = "";
  }
  updateAdminUi();
  updateUploadAvailability();
  renderEntries();
  setMessage(elements.adminMessage, "Token retirado de este dispositivo.", "success");
}

async function saveContributions(event) {
  event.preventDefault();
  const contributions = sanitizeContributionConfig({
    owner: elements.contributionOwner.value,
    name: elements.contributionRepo.value,
    branch: elements.contributionBranch.value,
    token: elements.contributionToken.value
  });
  if (!contributions) {
    setMessage(elements.contributionsMessage, "Revisa usuario, repositorio, rama y token.", "error");
    return;
  }
  elements.contributionsSave.disabled = true;
  setMessage(elements.contributionsMessage, "Verificando el repositorio de aportes…");
  try {
    const probe = new GitHubRepository({ apiBase: config.apiBase, ...contributions, owner: contributions.owner, name: contributions.name });
    await probe.verifyWriteAccess();
    state.settings = await saveContributionSettings(state.library, state.keyChain, contributions);
    state.contributions = buildContributionStore(state.settings.contributions);
    elements.contributionToken.value = "";
    updateUploadAvailability();
    await loadCatalogs();
    setMessage(elements.contributionsMessage, "Aportes activados. Cualquiera con la clave ya puede guardar.", "success");
  } catch (error) {
    setMessage(elements.contributionsMessage, describeError(error), "error");
  } finally {
    elements.contributionsSave.disabled = false;
  }
}

async function disableContributions() {
  elements.contributionsDisable.disabled = true;
  try {
    state.settings = await saveContributionSettings(state.library, state.keyChain, null);
    state.contributions = null;
    state.contributionCatalog = emptyCatalog();
    updateUploadAvailability();
    refreshEntries();
    setMessage(elements.contributionsMessage, "Aportes desactivados. Recuerda revocar el token en GitHub.", "success");
  } catch (error) {
    setMessage(elements.contributionsMessage, describeError(error), "error");
  } finally {
    elements.contributionsDisable.disabled = false;
  }
}

async function submitPasswordChange(event) {
  event.preventDefault();
  const problem = validateNewPassword(elements.newPassword.value, elements.newPasswordConfirm.value);
  if (problem) {
    setMessage(elements.passwordMessage, problem, "error");
    return;
  }
  elements.changePasswordButton.disabled = true;
  setMessage(elements.passwordMessage, "Generando llave nueva…");
  try {
    const result = await changePassword(state.library, state.keyChain, normalizePassword(elements.newPassword.value));
    state.keyChain = result.keyChain;
    state.settings = result.settings;
    persistSession();
    if (state.contributions && state.contributions.canWrite) {
      try {
        await state.contributions.resealCatalog(state.keyChain);
      } catch (_error) {
        showToast("La clave cambió, pero no se pudo actualizar el catálogo de aportes. Vuelve a intentarlo.");
      }
    }
    elements.newPassword.value = "";
    elements.newPasswordConfirm.value = "";
    elements.generatedNewKey.hidden = true;
    await loadCatalogs();
    setMessage(elements.passwordMessage, "Clave cambiada. Compártela por un canal seguro y revoca los tokens que ya no uses.", "success");
  } catch (error) {
    setMessage(elements.passwordMessage, describeError(error), "error");
  } finally {
    elements.changePasswordButton.disabled = false;
  }
}

async function submitSetup(event) {
  event.preventDefault();
  const token = elements.setupToken.value.trim();
  const problem = validateNewPassword(elements.setupPassword.value, elements.setupPasswordConfirm.value);
  if (!token) {
    setMessage(elements.setupMessage, "Pega el token de GitHub.", "error");
    return;
  }
  if (problem) {
    setMessage(elements.setupMessage, problem, "error");
    return;
  }
  if (!state.library.repository) {
    setMessage(elements.setupMessage, "No se pudo detectar el repositorio. Configúralo en assets/js/config.js.", "error");
    return;
  }

  elements.setupSubmit.disabled = true;
  setMessage(elements.setupMessage, "Creando la bóveda cifrada…");
  try {
    state.library.repository.token = token;
    await state.library.repository.verifyWriteAccess();
    const created = await createVault(state.library, normalizePassword(elements.setupPassword.value));
    safeStorage(sessionStorage, "set", TOKEN_KEY, token);
    state.libraryCatalog = created.catalog;
    await applySession(created);
    elements.setupToken.value = "";
    elements.setupPassword.value = "";
    elements.setupPasswordConfirm.value = "";
    elements.generatedKey.hidden = true;
    await openPortal();
    showToast("Bóveda creada. Guarda la clave en un gestor de contraseñas.");
  } catch (error) {
    state.library.repository.token = storedAdminToken();
    setMessage(elements.setupMessage, describeError(error), "error");
  } finally {
    elements.setupSubmit.disabled = false;
  }
}

// ----- Arranque -----

function cacheElements() {
  const ids = [
    "lockScreen", "lockIntro", "accessForm", "accessCode", "toggleCode", "unlockButton", "accessMessage",
    "capsHint", "lockMetaText", "setupToggle", "setupPanel", "setupToken", "setupPassword",
    "setupPasswordConfirm", "generatePassword", "generatedKey", "setupSubmit", "setupMessage",
    "portal", "headerOwner", "heroOwner", "heroTitle", "logoutButton", "metricEntries", "metricFiles",
    "metricContributions", "catalogUpdated", "statEntries", "statFiles", "statLibrary", "statContributions",
    "documentSearch", "filterList", "resultCount", "refreshCatalog", "exportRegistry", "documentsGrid",
    "emptyState", "emptyTitle", "emptyText", "uploadForm", "uploadNotice", "destinationGroup",
    "destinationLibrary", "destinationContribution", "uploadAuthor", "uploadTitleField", "uploadText",
    "characterCount", "fileInput", "dropZone", "stripMetadata", "filePreviewGrid", "uploadMessage",
    "uploadProgress", "clearUpload", "submitUpload", "adminDetails", "adminTokenForm", "adminToken",
    "adminRemember", "adminConnect", "adminDisconnect", "adminStatus", "adminMessage", "contributionsForm",
    "contributionOwner", "contributionRepo", "contributionBranch", "contributionToken", "contributionsSave",
    "contributionsDisable", "contributionsMessage", "passwordForm", "newPassword", "newPasswordConfirm",
    "generateNewPassword", "generatedNewKey", "changePasswordButton", "passwordMessage", "documentDialog",
    "viewerTitle", "viewerType", "viewerTopic", "viewerLoading", "viewerBody", "closeViewer", "toast",
    "footerYear", "dropHint"
  ];
  ids.forEach((id) => {
    elements[id] = element(id);
  });
}

function bindEvents() {
  elements.accessForm.addEventListener("submit", handleUnlock);
  elements.toggleCode.addEventListener("click", () => {
    const show = elements.accessCode.type === "password";
    elements.accessCode.type = show ? "text" : "password";
    elements.toggleCode.textContent = show ? "Ocultar" : "Mostrar";
    elements.toggleCode.setAttribute("aria-pressed", String(show));
    elements.accessCode.focus();
  });
  ["keydown", "keyup"].forEach((name) => {
    elements.accessCode.addEventListener(name, (event) => {
      if (typeof event.getModifierState === "function") {
        elements.capsHint.hidden = !event.getModifierState("CapsLock");
      }
    });
  });

  elements.setupToggle.addEventListener("click", () => {
    const open = elements.setupPanel.hidden;
    elements.setupPanel.hidden = !open;
    elements.setupToggle.setAttribute("aria-expanded", String(open));
  });
  elements.setupPanel.addEventListener("submit", submitSetup);
  elements.generatePassword.addEventListener("click", () => {
    const passphrase = generatePassphrase();
    elements.setupPassword.value = passphrase;
    elements.setupPasswordConfirm.value = passphrase;
    elements.generatedKey.hidden = false;
    elements.generatedKey.textContent = `Clave generada: ${passphrase} · cópiala ahora, no se vuelve a mostrar.`;
  });
  elements.generateNewPassword.addEventListener("click", () => {
    const passphrase = generatePassphrase();
    elements.newPassword.value = passphrase;
    elements.newPasswordConfirm.value = passphrase;
    elements.generatedNewKey.hidden = false;
    elements.generatedNewKey.textContent = `Clave generada: ${passphrase} · cópiala ahora, no se vuelve a mostrar.`;
  });

  elements.logoutButton.addEventListener("click", () => lockPortal("Sesión cerrada."));
  elements.documentSearch.addEventListener("input", () => {
    state.search = normalizeForSearch(elements.documentSearch.value);
    renderEntries();
  });
  elements.filterList.addEventListener("click", (event) => {
    const button = event.target.closest("[data-filter]");
    if (!button) {
      return;
    }
    state.filter = button.dataset.filter;
    elements.filterList.querySelectorAll("[data-filter]").forEach((node) => {
      const active = node === button;
      node.classList.toggle("is-active", active);
      node.setAttribute("aria-pressed", String(active));
    });
    renderEntries();
  });
  elements.refreshCatalog.addEventListener("click", () => loadCatalogs());
  elements.exportRegistry.addEventListener("click", exportRegistry);

  elements.uploadText.addEventListener("input", () => {
    elements.characterCount.textContent = `${elements.uploadText.value.length.toLocaleString("es-PE")} / 20,000`;
  });
  elements.fileInput.addEventListener("change", () => addFiles(elements.fileInput.files));
  ["dragenter", "dragover"].forEach((name) => {
    elements.dropZone.addEventListener(name, (event) => {
      event.preventDefault();
      elements.dropZone.classList.add("is-dragging");
    });
  });
  ["dragleave", "drop"].forEach((name) => {
    elements.dropZone.addEventListener(name, (event) => {
      event.preventDefault();
      elements.dropZone.classList.remove("is-dragging");
    });
  });
  elements.dropZone.addEventListener("drop", (event) => addFiles(event.dataTransfer.files));
  elements.uploadForm.addEventListener("paste", (event) => {
    const pasted = Array.from(event.clipboardData ? event.clipboardData.files : []);
    if (!pasted.length) {
      return;
    }
    event.preventDefault();
    const named = pasted.map((file) => {
      const extension = extensionOf(file.name) || (file.type === "image/jpeg" ? "jpg" : "png");
      return file.name && extensionOf(file.name)
        ? file
        : new File([file], screenshotName(new Date(), extension), { type: file.type });
    });
    addFiles(named);
  });
  elements.clearUpload.addEventListener("click", () => resetUploadForm("Formulario limpio."));
  elements.uploadForm.addEventListener("submit", submitUpload);

  elements.adminTokenForm.addEventListener("submit", connectAdmin);
  elements.adminDisconnect.addEventListener("click", disconnectAdmin);
  elements.contributionsForm.addEventListener("submit", saveContributions);
  elements.contributionsDisable.addEventListener("click", disableContributions);
  elements.passwordForm.addEventListener("submit", submitPasswordChange);

  elements.closeViewer.addEventListener("click", closeDialog);
  elements.documentDialog.addEventListener("close", () => {
    releaseUrls();
    elements.viewerBody.replaceChildren();
  });
  elements.documentDialog.addEventListener("click", (event) => {
    if (event.target === elements.documentDialog) {
      closeDialog();
    }
  });

  ["click", "keydown", "pointermove"].forEach((name) => {
    document.addEventListener(name, noteActivity, { passive: true });
  });
  window.addEventListener("pagehide", releaseUrls);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && state.keyChain) {
      loadCatalogs({ silent: true });
    }
  });
}

async function initialize() {
  cacheElements();
  document.title = config.title;
  elements.headerOwner.textContent = config.owner;
  elements.heroOwner.textContent = config.owner;
  elements.footerYear.textContent = String(new Date().getFullYear());
  elements.fileInput.accept = ACCEPT_ATTRIBUTE;
  elements.uploadAuthor.value = safeStorage(localStorage, "get", AUTHOR_KEY) || "";
  bindEvents();
  startIdleWatch();

  state.library = buildLibraryStore(storedAdminToken());

  if (!window.isSecureContext || !window.crypto || !window.crypto.subtle) {
    setMessage(elements.accessMessage, "Este navegador no permite descifrar aquí. Abre el portal por HTTPS en un navegador actualizado.", "error");
    elements.unlockButton.disabled = true;
    return;
  }

  if (await restoreSession()) {
    return;
  }

  try {
    const keyring = await fetchKeyring(state.library);
    if (!keyring) {
      elements.setupToggle.hidden = false;
      elements.lockIntro.textContent = "Esta bóveda todavía no está configurada. Si administras el repositorio, créala aquí.";
      elements.accessForm.hidden = true;
      return;
    }
  } catch (error) {
    setMessage(elements.accessMessage, describeError(error), "error");
    return;
  }
  elements.accessCode.focus();
}

initialize().catch((error) => {
  const message = document.getElementById("accessMessage");
  if (message) {
    message.textContent = describeError(error);
  }
});
