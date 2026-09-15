// Configuración pública del portal. Este archivo se publica: nunca escribas aquí
// claves de acceso ni tokens de GitHub.
export default Object.freeze({
  title: "Junior's Market Analysis",
  owner: "Name",

  // Repositorio que publica este sitio y guarda la biblioteca cifrada.
  // Con null se detecta solo desde la dirección https://<usuario>.github.io/<repositorio>/.
  // Si usas un dominio propio, escríbelo así: { owner: "usuario", name: "repositorio" }.
  repository: null,
  branch: "main",
  vaultPath: "vault",
  apiBase: "https://api.github.com",

  // Cada cuánto se vuelve a consultar el catálogo y tras cuántos minutos sin
  // actividad se cierra la sesión.
  refreshSeconds: 60,
  idleLockMinutes: 30
});
