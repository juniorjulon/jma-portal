// Tipos de archivo admitidos. Se valida la extensión y también la firma real del
// contenido, al subir y al descargar. Quedan fuera los formatos que pueden
// ejecutar código (HTML, SVG, ejecutables) y los de Office con macros.

const ZIP = [[0x50, 0x4b, 0x03, 0x04]];

function asciiAt(bytes, start, end) {
  return String.fromCharCode.apply(null, bytes.subarray(start, end));
}

export const FILE_TYPES = new Map([
  ["docx", { label: "DOCX", kind: "word", mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", signatures: ZIP }],
  ["xlsx", { label: "XLSX", kind: "excel", mime: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", signatures: ZIP }],
  ["pptx", { label: "PPTX", kind: "powerpoint", mime: "application/vnd.openxmlformats-officedocument.presentationml.presentation", signatures: ZIP }],
  ["pdf", { label: "PDF", kind: "pdf", mime: "application/pdf", signatures: [[0x25, 0x50, 0x44, 0x46, 0x2d]] }],
  ["csv", { label: "CSV", kind: "excel", mime: "text/csv", text: true }],
  ["txt", { label: "TXT", kind: "text", mime: "text/plain", text: true, viewable: true }],
  ["md", { label: "MD", kind: "text", mime: "text/markdown", text: true, viewable: true }],
  ["png", { label: "PNG", kind: "image", mime: "image/png", viewable: true, signatures: [[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]] }],
  ["jpg", { label: "JPG", kind: "image", mime: "image/jpeg", viewable: true, signatures: [[0xff, 0xd8, 0xff]] }],
  ["jpeg", { label: "JPG", kind: "image", mime: "image/jpeg", viewable: true, signatures: [[0xff, 0xd8, 0xff]] }],
  ["gif", { label: "GIF", kind: "image", mime: "image/gif", viewable: true, signatures: [[0x47, 0x49, 0x46, 0x38, 0x37, 0x61], [0x47, 0x49, 0x46, 0x38, 0x39, 0x61]] }],
  ["webp", { label: "WEBP", kind: "image", mime: "image/webp", viewable: true, check: (bytes) => bytes.length >= 12 && asciiAt(bytes, 0, 4) === "RIFF" && asciiAt(bytes, 8, 12) === "WEBP" }]
]);

export const KIND_LABELS = Object.freeze({
  word: "Word",
  excel: "Excel y datos",
  powerpoint: "PowerPoint",
  pdf: "PDF",
  image: "Imágenes",
  text: "Texto"
});

export const ACCEPT_ATTRIBUTE = Array.from(FILE_TYPES.keys()).map((extension) => `.${extension}`).join(",");

export const LIMITS = Object.freeze({
  maxFileBytes: 25 * 1024 * 1024,
  maxFilesPerEntry: 10,
  maxEntryBytes: 50 * 1024 * 1024,
  maxTitleLength: 140,
  maxAuthorLength: 80,
  maxTextLength: 20000
});

export function extensionOf(name) {
  const match = /\.([a-z0-9]{1,8})$/i.exec(String(name || ""));
  return match ? match[1].toLowerCase() : "";
}

export function typeFor(extension) {
  return FILE_TYPES.get(String(extension || "").toLowerCase()) || null;
}

export function formatBytes(bytes) {
  const size = Number(bytes) || 0;
  if (size < 1024) {
    return `${size} B`;
  }
  if (size < 1024 * 1024) {
    return `${(size / 1024).toFixed(size < 10 * 1024 ? 1 : 0)} KB`;
  }
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
}

// Nombre seguro para guardar en disco: sin rutas, caracteres reservados ni
// nombres especiales de Windows, y siempre con la extensión del tipo real.
export function sanitizeFileName(name, extension) {
  let base = String(name || "")
    .normalize("NFC")
    .replace(/[\u0000-\u001f\u007f<>:"/\\|?*]+/g, " ")
    .replace(/\.[a-z0-9]{1,8}$/i, "")
    .replace(/\s+/g, " ")
    .replace(/^[.\s]+|[.\s]+$/g, "");
  if (!base) {
    base = "archivo";
  }
  if (/^(con|prn|aux|nul|com\d|lpt\d)$/i.test(base)) {
    base = `_${base}`;
  }
  return `${base.slice(0, 120)}.${extension}`;
}

export function verifyContent(extension, bytes) {
  const type = typeFor(extension);
  if (!type || !bytes || !bytes.length) {
    return false;
  }
  if (type.text) {
    return !bytes.subarray(0, 4096).includes(0);
  }
  if (type.check) {
    return type.check(bytes);
  }
  return type.signatures.some((signature) =>
    bytes.length >= signature.length && signature.every((byte, index) => bytes[index] === byte)
  );
}

export async function inspectFile(file) {
  const extension = extensionOf(file.name);
  const type = typeFor(extension);
  if (!type) {
    return { ok: false, reason: `${file.name}: formato no admitido.` };
  }
  if (!file.size) {
    return { ok: false, reason: `${file.name}: el archivo está vacío.` };
  }
  if (file.size > LIMITS.maxFileBytes) {
    return { ok: false, reason: `${file.name}: supera el máximo de ${formatBytes(LIMITS.maxFileBytes)} por archivo.` };
  }
  const head = new Uint8Array(await file.slice(0, 4096).arrayBuffer());
  if (!verifyContent(extension, head)) {
    return { ok: false, reason: `${file.name}: el contenido no corresponde a un archivo ${type.label}.` };
  }
  return { ok: true, extension, type };
}

// Las fotos de celular llevan coordenadas GPS y datos del equipo en EXIF.
// Volver a dibujar la imagen en un lienzo produce un JPG limpio.
export async function stripJpegMetadata(file) {
  if (typeof createImageBitmap !== "function") {
    return file;
  }
  const bitmap = await createImageBitmap(file);
  try {
    const canvas = document.createElement("canvas");
    canvas.width = bitmap.width;
    canvas.height = bitmap.height;
    canvas.getContext("2d").drawImage(bitmap, 0, 0);
    const blob = await new Promise((resolve) => canvas.toBlob(resolve, "image/jpeg", 0.92));
    return blob ? new File([blob], file.name, { type: "image/jpeg", lastModified: file.lastModified }) : file;
  } finally {
    if (typeof bitmap.close === "function") {
      bitmap.close();
    }
  }
}

export function screenshotName(date, extension) {
  const pad = (value) => String(value).padStart(2, "0");
  const stamp = `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}-${pad(date.getHours())}${pad(date.getMinutes())}${pad(date.getSeconds())}`;
  return `captura-${stamp}.${extension}`;
}
