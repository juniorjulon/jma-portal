// Tipos de archivo. El portal acepta cualquier formato. Los conocidos se
// reconocen por la extensión y, si tienen una firma fiable, se comprueba que el
// contenido la lleve, al subir y al descargar. Solo las imágenes y el texto se
// muestran dentro del portal; todo lo demás se entrega como descarga.
//
// Los formatos que pueden ejecutar código (HTML, SVG, programas, scripts y
// Office con macros) se aceptan marcados como riesgosos: nunca se abren aquí,
// se descargan como datos binarios y piden confirmación antes.

const OCTET = "application/octet-stream";
const ZIP = [[0x50, 0x4b, 0x03, 0x04], [0x50, 0x4b, 0x05, 0x06], [0x50, 0x4b, 0x07, 0x08]];
const OLE = [[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]];
const GZIP = [[0x1f, 0x8b]];
const JPEG = [[0xff, 0xd8, 0xff]];
const TIFF = [[0x49, 0x49, 0x2a, 0x00], [0x4d, 0x4d, 0x00, 0x2a], [0x49, 0x49, 0x2b, 0x00], [0x4d, 0x4d, 0x00, 0x2b]];

function asciiAt(bytes, start, end) {
  return String.fromCharCode.apply(null, bytes.subarray(start, end));
}

function riff(form) {
  return (bytes) => bytes.length >= 12 && asciiAt(bytes, 0, 4) === "RIFF" && asciiAt(bytes, 8, 12) === form;
}

const isoMedia = (bytes) => bytes.length >= 12 && asciiAt(bytes, 4, 8) === "ftyp";

// Los .doc y .xls viejos no se verifican: muchos sistemas exportan tablas HTML o
// texto con esas extensiones. Audio y video tampoco: sus cabeceras varían demasiado.
export const FILE_TYPES = new Map([
  ["docx", { label: "DOCX", kind: "word", mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", signatures: ZIP }],
  ["dotx", { label: "DOTX", kind: "word", mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.template", signatures: ZIP }],
  ["doc", { label: "DOC", kind: "word", mime: "application/msword" }],
  ["odt", { label: "ODT", kind: "word", mime: "application/vnd.oasis.opendocument.text", signatures: ZIP }],
  ["rtf", { label: "RTF", kind: "word", mime: "application/rtf", signatures: [[0x7b, 0x5c, 0x72, 0x74, 0x66]] }],
  ["pages", { label: "PAGES", kind: "word", mime: OCTET }],
  ["xlsx", { label: "XLSX", kind: "excel", mime: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", signatures: ZIP }],
  ["xltx", { label: "XLTX", kind: "excel", mime: "application/vnd.openxmlformats-officedocument.spreadsheetml.template", signatures: ZIP }],
  ["xls", { label: "XLS", kind: "excel", mime: "application/vnd.ms-excel" }],
  ["ods", { label: "ODS", kind: "excel", mime: "application/vnd.oasis.opendocument.spreadsheet", signatures: ZIP }],
  ["numbers", { label: "NUMBERS", kind: "excel", mime: OCTET }],
  ["csv", { label: "CSV", kind: "excel", mime: "text/csv", text: true, viewable: true }],
  ["tsv", { label: "TSV", kind: "excel", mime: "text/tab-separated-values", text: true, viewable: true }],
  ["pptx", { label: "PPTX", kind: "powerpoint", mime: "application/vnd.openxmlformats-officedocument.presentationml.presentation", signatures: ZIP }],
  ["ppsx", { label: "PPSX", kind: "powerpoint", mime: "application/vnd.openxmlformats-officedocument.presentationml.slideshow", signatures: ZIP }],
  ["potx", { label: "POTX", kind: "powerpoint", mime: "application/vnd.openxmlformats-officedocument.presentationml.template", signatures: ZIP }],
  ["ppt", { label: "PPT", kind: "powerpoint", mime: "application/vnd.ms-powerpoint", signatures: OLE }],
  ["odp", { label: "ODP", kind: "powerpoint", mime: "application/vnd.oasis.opendocument.presentation", signatures: ZIP }],
  ["key", { label: "KEY", kind: "powerpoint", mime: OCTET }],
  ["docm", { label: "DOCM", kind: "word", mime: OCTET, risky: true, signatures: ZIP }],
  ["dotm", { label: "DOTM", kind: "word", mime: OCTET, risky: true, signatures: ZIP }],
  ["xlsm", { label: "XLSM", kind: "excel", mime: OCTET, risky: true, signatures: ZIP }],
  ["xltm", { label: "XLTM", kind: "excel", mime: OCTET, risky: true, signatures: ZIP }],
  ["xlam", { label: "XLAM", kind: "excel", mime: OCTET, risky: true, signatures: ZIP }],
  ["xlsb", { label: "XLSB", kind: "excel", mime: OCTET, risky: true, signatures: ZIP }],
  ["pptm", { label: "PPTM", kind: "powerpoint", mime: OCTET, risky: true, signatures: ZIP }],
  ["potm", { label: "POTM", kind: "powerpoint", mime: OCTET, risky: true, signatures: ZIP }],
  ["ppsm", { label: "PPSM", kind: "powerpoint", mime: OCTET, risky: true, signatures: ZIP }],
  ["pdf", { label: "PDF", kind: "pdf", mime: "application/pdf", signatures: [[0x25, 0x50, 0x44, 0x46, 0x2d]] }],
  ["zip", { label: "ZIP", kind: "archive", mime: "application/zip", signatures: ZIP }],
  ["rar", { label: "RAR", kind: "archive", mime: "application/vnd.rar", signatures: [[0x52, 0x61, 0x72, 0x21, 0x1a, 0x07]] }],
  ["7z", { label: "7Z", kind: "archive", mime: "application/x-7z-compressed", signatures: [[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]] }],
  ["gz", { label: "GZ", kind: "archive", mime: "application/gzip", signatures: GZIP }],
  ["tgz", { label: "TGZ", kind: "archive", mime: "application/gzip", signatures: GZIP }],
  ["bz2", { label: "BZ2", kind: "archive", mime: "application/x-bzip2", signatures: [[0x42, 0x5a, 0x68]] }],
  ["xz", { label: "XZ", kind: "archive", mime: "application/x-xz", signatures: [[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]] }],
  ["tar", { label: "TAR", kind: "archive", mime: "application/x-tar" }],
  ["png", { label: "PNG", kind: "image", mime: "image/png", viewable: true, signatures: [[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]] }],
  ["jpg", { label: "JPG", kind: "image", mime: "image/jpeg", viewable: true, signatures: JPEG }],
  ["jpeg", { label: "JPG", kind: "image", mime: "image/jpeg", viewable: true, signatures: JPEG }],
  ["gif", { label: "GIF", kind: "image", mime: "image/gif", viewable: true, signatures: [[0x47, 0x49, 0x46, 0x38, 0x37, 0x61], [0x47, 0x49, 0x46, 0x38, 0x39, 0x61]] }],
  ["webp", { label: "WEBP", kind: "image", mime: "image/webp", viewable: true, check: riff("WEBP") }],
  ["bmp", { label: "BMP", kind: "image", mime: "image/bmp", viewable: true, signatures: [[0x42, 0x4d]] }],
  ["avif", { label: "AVIF", kind: "image", mime: "image/avif", viewable: true, check: isoMedia }],
  ["heic", { label: "HEIC", kind: "image", mime: "image/heic", check: isoMedia }],
  ["heif", { label: "HEIF", kind: "image", mime: "image/heif", check: isoMedia }],
  ["tif", { label: "TIFF", kind: "image", mime: "image/tiff", signatures: TIFF }],
  ["tiff", { label: "TIFF", kind: "image", mime: "image/tiff", signatures: TIFF }],
  ["svg", { label: "SVG", kind: "image", mime: OCTET, risky: true }],
  ["txt", { label: "TXT", kind: "text", mime: "text/plain", text: true, viewable: true }],
  ["md", { label: "MD", kind: "text", mime: "text/markdown", text: true, viewable: true }],
  ["json", { label: "JSON", kind: "text", mime: "application/json", text: true, viewable: true }],
  ["xml", { label: "XML", kind: "text", mime: "application/xml", text: true, viewable: true }],
  ["log", { label: "LOG", kind: "text", mime: "text/plain", text: true, viewable: true }],
  ["yaml", { label: "YAML", kind: "text", mime: "application/yaml", text: true, viewable: true }],
  ["yml", { label: "YAML", kind: "text", mime: "application/yaml", text: true, viewable: true }],
  ["html", { label: "HTML", kind: "other", mime: OCTET, risky: true }],
  ["htm", { label: "HTML", kind: "other", mime: OCTET, risky: true }],
  ["eml", { label: "EML", kind: "other", mime: "message/rfc822" }],
  ["msg", { label: "MSG", kind: "other", mime: "application/vnd.ms-outlook", signatures: OLE }],
  ["ics", { label: "ICS", kind: "other", mime: "text/calendar", text: true }],
  ["vcf", { label: "VCF", kind: "other", mime: "text/vcard", text: true }],
  ["epub", { label: "EPUB", kind: "other", mime: "application/epub+zip", signatures: ZIP }],
  ["mp3", { label: "MP3", kind: "media", mime: "audio/mpeg" }],
  ["m4a", { label: "M4A", kind: "media", mime: "audio/mp4" }],
  ["aac", { label: "AAC", kind: "media", mime: "audio/aac" }],
  ["wav", { label: "WAV", kind: "media", mime: "audio/wav" }],
  ["flac", { label: "FLAC", kind: "media", mime: "audio/flac" }],
  ["ogg", { label: "OGG", kind: "media", mime: "audio/ogg" }],
  ["opus", { label: "OPUS", kind: "media", mime: "audio/opus" }],
  ["mp4", { label: "MP4", kind: "media", mime: "video/mp4" }],
  ["m4v", { label: "M4V", kind: "media", mime: "video/mp4" }],
  ["mov", { label: "MOV", kind: "media", mime: "video/quicktime" }],
  ["avi", { label: "AVI", kind: "media", mime: "video/x-msvideo" }],
  ["mkv", { label: "MKV", kind: "media", mime: "video/x-matroska" }],
  ["webm", { label: "WEBM", kind: "media", mime: "video/webm" }]
]);

// Extensiones sin tipo propio que igual cuentan como riesgosas: páginas web,
// programas, scripts e imágenes de disco que Windows o macOS ejecutan o montan.
const RISKY_EXTENSIONS = new Set([
  "xhtml", "shtml", "mht", "mhtml", "svgz", "hta", "exe", "msi", "msix", "msp", "appx", "com", "scr", "pif",
  "cpl", "dll", "sys", "bat", "cmd", "ps1", "psm1", "psd1", "vbs", "vbe", "js", "jse", "mjs", "wsf", "wsh",
  "lnk", "url", "reg", "inf", "chm", "jar", "apk", "app", "dmg", "pkg", "deb", "rpm", "sh", "command",
  "iso", "img", "vhd", "vhdx", "xll", "application", "gadget"
]);

export const KIND_LABELS = Object.freeze({
  word: "Word",
  excel: "Excel y datos",
  powerpoint: "PowerPoint",
  pdf: "PDF",
  archive: "Comprimidos",
  image: "Imágenes",
  text: "Texto",
  media: "Audio y video",
  other: "Otros"
});

// Extensión guardada en el catálogo: vacía si el archivo no tiene.
export const EXTENSION_PATTERN = /^[a-z0-9]{0,8}$/;

export const LIMITS = Object.freeze({
  maxFileBytes: 25 * 1024 * 1024,
  maxFilesPerEntry: 10,
  maxEntryBytes: 50 * 1024 * 1024,
  maxTitleLength: 140,
  maxAuthorLength: 80,
  maxTextLength: 20000
});

// Windows ignora puntos y espacios finales, así que "factura.exe ." es un .exe.
export function extensionOf(name) {
  const match = /\.([a-z0-9]{1,8})$/i.exec(String(name || "").replace(/[.\s]+$/, ""));
  return match ? match[1].toLowerCase() : "";
}

// Cualquier otra extensión se acepta como archivo genérico, solo para descargar.
export function typeFor(extension) {
  const key = String(extension || "").toLowerCase();
  return FILE_TYPES.get(key) || {
    label: key ? key.toUpperCase() : "ARCHIVO",
    kind: "other",
    mime: OCTET,
    risky: RISKY_EXTENSIONS.has(key)
  };
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
    .replace(/\s+/g, " ")
    .replace(/[.\s]+$/, "");
  if (extension) {
    base = base.replace(/\.[a-z0-9]{1,8}$/i, "");
  }
  base = base.replace(/^[.\s]+|[.\s]+$/g, "");
  if (!base) {
    base = "archivo";
  }
  if (/^(con|prn|aux|nul|com\d|lpt\d)$/i.test(base)) {
    base = `_${base}`;
  }
  return extension ? `${base.slice(0, 120)}.${extension}` : base.slice(0, 120);
}

// Excel y el Bloc de notas a veces guardan texto en UTF-16; la marca inicial lo indica.
function utf16Encoding(bytes) {
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) {
    return "utf-16le";
  }
  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
    return "utf-16be";
  }
  return "";
}

export function decodeText(bytes) {
  return new TextDecoder(utf16Encoding(bytes) || "utf-8").decode(bytes);
}

export function verifyContent(extension, bytes) {
  if (!bytes || !bytes.length) {
    return false;
  }
  const type = typeFor(extension);
  if (type.text) {
    const head = bytes.subarray(0, 4096);
    return Boolean(utf16Encoding(head)) || !head.includes(0);
  }
  if (type.check) {
    return type.check(bytes);
  }
  if (type.signatures) {
    return type.signatures.some((signature) =>
      bytes.length >= signature.length && signature.every((byte, index) => bytes[index] === byte)
    );
  }
  return true;
}

export async function inspectFile(file) {
  const extension = extensionOf(file.name);
  const type = typeFor(extension);
  if (!file.size) {
    return { ok: false, reason: `${file.name}: está vacío o es una carpeta. Las carpetas se suben comprimidas en ZIP.` };
  }
  if (file.size > LIMITS.maxFileBytes) {
    return { ok: false, reason: `${file.name}: supera el máximo de ${formatBytes(LIMITS.maxFileBytes)} por archivo.` };
  }
  let head;
  try {
    head = new Uint8Array(await file.slice(0, 4096).arrayBuffer());
  } catch (_error) {
    return { ok: false, reason: `${file.name}: no se pudo leer. Si es una carpeta, comprímela en ZIP.` };
  }
  if (!verifyContent(extension, head)) {
    return { ok: false, reason: `${file.name}: el contenido no corresponde a un archivo ${type.label}. Revisa la extensión o súbelo comprimido en ZIP.` };
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
