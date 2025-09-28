# 🤝 Roblox Friend Manager

**Roblox Friend Manager** es una herramienta escrita en **Python** que te permite gestionar tus solicitudes de amistad de Roblox desde una interfaz gráfica moderna.

✨ **Características principales**:
- Iniciar sesión con tu token `.ROBLOSECURITY`.
- Ver contador de solicitudes pendientes.
- Aceptar todas las solicitudes en un clic.
- Rechazar todas las solicitudes en un clic.
- Modo automático: aceptar o rechazar en bucle mientras llegan nuevas solicitudes.
- Visualizar usuarios **agregados** y **rechazados** con su **avatar, nombre y displayName**.
- Interfaz compacta y elegante creada con **Tkinter** + **ttkbootstrap**.

⚠️ **Aviso importante**  
Nunca compartas tu token `.ROBLOSECURITY`. Equivale a tu contraseña y da acceso completo a tu cuenta.

---

## 📸 Capturas de pantalla
<img width="1911" height="1030" alt="Fotooo" src="https://github.com/user-attachments/assets/5c5481ba-9045-4721-b88d-e0e681dc9874" />
---

## 🚀 Instalación

Clona el repositorio y entra en la carpeta:

```bash
git clone https://github.com/Kayy9961/Roblox-Friend-Manager.git
cd Roblox-Friend-Manager
```

Crea un entorno virtual (opcional pero recomendado):

```bash
python -m venv venv
source venv/bin/activate
venv\Scripts\activate
```

Instala las dependencias necesarias:

```bash
pip install -r requirements.txt
```

---

## 📦 Dependencias

- `requests`
- `pillow`
- `tkinter` (viene con Python en la mayoría de sistemas)
- `ttkbootstrap` (para la interfaz moderna)

Ejemplo instalación manual:

```bash
pip install requests pillow ttkbootstrap
```

---

## ▶️ Uso

Ejecuta el programa con:

```bash
python app.py
```

1. Introduce tu token `.ROBLOSECURITY`.
2. Haz clic en **Iniciar sesión**.
3. Usa los botones para aceptar o rechazar solicitudes.
4. Activa los modos automáticos si quieres gestionar en tiempo real.

---

## 🛡️ Seguridad

- El token **no se guarda ni se envía a ningún servidor** que no sea el oficial de Roblox.
- El uso de este software es bajo tu propia responsabilidad.
- Recomendamos **activar 2FA** en tu cuenta de Roblox.

---

## 📜 Licencia

Este proyecto está publicado bajo la licencia **MIT**. Puedes usarlo y modificarlo libremente.

---

## 💡 Créditos

Desarrollado en Python usando:
- [Tkinter](https://docs.python.org/3/library/tkinter.html)
- [ttkbootstrap](https://github.com/israel-dryer/ttkbootstrap)
- [Requests](https://docs.python-requests.org/en/master/)
- [Pillow](https://python-pillow.org/)
