# Junior's Market Analysis

Portal privado de documentos publicado con GitHub Pages.

Todo el contenido de `vault/` está **cifrado con AES-256-GCM** en el navegador de quien
lo sube. El repositorio guarda únicamente el resultado cifrado: sin la clave de acceso,
los archivos de esta carpeta no dicen nada, ni siquiera el nombre de los documentos.

- `index.html`, `assets/` son la aplicación. No contienen datos ni credenciales.
- `vault/keyring.json` es público y solo guarda la llave de cifrado envuelta con
  PBKDF2-SHA256 (600 000 iteraciones) sobre la clave de acceso.
- `vault/catalog.bin`, `vault/settings.bin` y `vault/files/*.bin` están cifrados.

La clave de acceso no se guarda en ningún archivo de este repositorio y no se puede
recuperar: si se pierde, el contenido cifrado se pierde con ella.
