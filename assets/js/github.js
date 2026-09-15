// Cliente mínimo de la API de GitHub para escribir en la bóveda. Cada guardado
// es un único commit atómico (archivos cifrados más catálogo). Si otra persona
// guardó en el mismo instante, se vuelve a leer el catálogo y se reintenta, sin
// perder ninguna de las dos entradas.

export class GitHubError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

function encodePath(path) {
  return String(path).split("/").map((segment) => encodeURIComponent(segment)).join("/");
}

function bytesToBase64Async(bytes) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const dataUrl = String(reader.result);
      resolve(dataUrl.slice(dataUrl.indexOf(",") + 1));
    };
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(new Blob([bytes]));
  });
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export class GitHubRepository {
  constructor({ apiBase, owner, name, branch, token }) {
    this.apiBase = String(apiBase || "https://api.github.com").replace(/\/+$/, "");
    this.owner = owner;
    this.name = name;
    this.branch = branch || "main";
    this.token = token || "";
  }

  get label() {
    return `${this.owner}/${this.name}`;
  }

  describeStatus(status, detail, response) {
    if (status === 401) {
      return "GitHub rechazó el token: no es válido o ya venció.";
    }
    if (status === 403 && response && response.headers.get("x-ratelimit-remaining") === "0") {
      return "Se alcanzó el límite de solicitudes de GitHub. Intenta en unos minutos.";
    }
    if (status === 403) {
      return `El token no tiene permiso de escritura (Contents: Read and write) sobre ${this.label}.`;
    }
    if (status === 404) {
      return `No se encontró ${this.label}, o el token no tiene acceso a ese repositorio.`;
    }
    return detail ? `GitHub respondió: ${detail}` : `GitHub respondió con el estado ${status}.`;
  }

  async request(method, path, { json, accept, allowStatus = [] } = {}) {
    const headers = { Accept: accept || "application/vnd.github+json" };
    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`;
    }
    let body;
    if (json !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(json);
    }

    let response;
    try {
      response = await fetch(`${this.apiBase}/repos/${encodeURIComponent(this.owner)}/${encodeURIComponent(this.name)}${path}`, {
        method,
        headers,
        body,
        cache: "no-store",
        credentials: "omit",
        referrerPolicy: "no-referrer"
      });
    } catch (_error) {
      throw new GitHubError("No fue posible conectar con GitHub. Revisa la conexión.", 0);
    }

    if (!response.ok && !allowStatus.includes(response.status)) {
      let detail = "";
      try {
        detail = String((await response.json()).message || "");
      } catch (_error) {
        detail = "";
      }
      throw new GitHubError(this.describeStatus(response.status, detail, response), response.status);
    }
    return response;
  }

  async postJson(path, json) {
    return (await this.request("POST", path, { json })).json();
  }

  // Devuelve { commit, tree } de la rama, o null si el repositorio está vacío.
  async getHead() {
    const refResponse = await this.request("GET", `/git/ref/heads/${encodePath(this.branch)}`, { allowStatus: [409] });
    if (refResponse.status === 409) {
      return null;
    }
    const reference = await refResponse.json();
    const commit = await (await this.request("GET", `/git/commits/${reference.object.sha}`)).json();
    return { commit: commit.sha, tree: commit.tree.sha };
  }

  // La API de objetos Git no funciona en un repositorio sin commits; el primero
  // se crea con la API de contenidos.
  async ensureInitialized() {
    if (await this.getHead()) {
      return;
    }
    const readme = "# Bóveda cifrada\n\nContenido cifrado de Junior's Market Analysis. Sin la clave de acceso estos archivos son ilegibles.\n";
    await this.request("PUT", "/contents/README.md", {
      json: {
        message: "Inicializa bóveda cifrada",
        content: btoa(unescape(encodeURIComponent(readme))),
        branch: this.branch
      },
      allowStatus: [422]
    });
  }

  async readFile(path, ref) {
    const query = `?ref=${encodeURIComponent(ref || this.branch)}`;
    const response = await this.request("GET", `/contents/${encodePath(path)}${query}`, {
      accept: "application/vnd.github.raw+json",
      allowStatus: [404]
    });
    if (response.status === 404) {
      return null;
    }
    return new Uint8Array(await response.arrayBuffer());
  }

  async listPaths(treeSha, prefix) {
    const tree = await (await this.request("GET", `/git/trees/${treeSha}?recursive=1`)).json();
    return new Set((tree.tree || [])
      .filter((item) => item.type === "blob" && String(item.path).startsWith(prefix))
      .map((item) => item.path));
  }

  async createBlob(bytes) {
    const content = await bytesToBase64Async(bytes);
    return (await this.postJson("/git/blobs", { content, encoding: "base64" })).sha;
  }

  // Prueba real de escritura: crear un blob exige Contents: Read and write, y un
  // blob que ningún commit referencia no altera el repositorio.
  async verifyWriteAccess() {
    const info = await (await this.request("GET", "")).json();
    if (info.permissions && info.permissions.push === false) {
      throw new GitHubError(`Tu cuenta no tiene permiso de escritura en ${this.label}.`, 403);
    }
    await this.ensureInitialized();
    await this.createBlob(new TextEncoder().encode("jma-write-check"));
    return { isPrivate: Boolean(info.private) };
  }

  // build(head) devuelve [{ path, sha }] (sha null elimina la ruta). Se vuelve a
  // invocar en cada reintento para trabajar siempre sobre la versión vigente.
  async commit(message, build, attempts = 5) {
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      let head = await this.getHead();
      if (!head) {
        await this.ensureInitialized();
        head = await this.getHead();
      }

      const changes = await build(head);
      if (!changes.length) {
        return head.commit;
      }

      const tree = await this.postJson("/git/trees", {
        base_tree: head.tree,
        tree: changes.map((change) => ({ path: change.path, mode: "100644", type: "blob", sha: change.sha }))
      });
      const commit = await this.postJson("/git/commits", { message, tree: tree.sha, parents: [head.commit] });
      const update = await this.request("PATCH", `/git/refs/heads/${encodePath(this.branch)}`, {
        json: { sha: commit.sha, force: false },
        allowStatus: [409, 422]
      });
      if (update.ok) {
        return commit.sha;
      }
      await delay(300 * attempt + Math.floor(Math.random() * 300));
    }
    throw new GitHubError("Varias personas guardaron al mismo tiempo y no se pudo completar. Intenta nuevamente.", 409);
  }
}
