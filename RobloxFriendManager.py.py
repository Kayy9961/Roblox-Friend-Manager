import time
import threading
import requests
from io import BytesIO
from PIL import Image, ImageTk
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime

USE_TTKBOOTSTRAP = True
try:
    import ttkbootstrap as tb
    from ttkbootstrap.constants import *
except Exception:
    USE_TTKBOOTSTRAP = False

AUTH_URL = "https://users.roblox.com/v1/users/authenticated"
REQ_COUNT_URL = "https://friends.roblox.com/v1/user/friend-requests/count"
REQ_LIST_URL = "https://friends.roblox.com/v1/my/friends/requests"
USER_INFO_URL_TMPL = "https://users.roblox.com/v1/users/{user_id}"
ACCEPT_URL_TMPL = "https://friends.roblox.com/v1/users/{user_id}/accept-friend-request"
DECLINE_URL_TMPL = "https://friends.roblox.com/v1/users/{user_id}/decline-friend-request"
AVATAR_URL_TMPL = "https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds={uid}&size=150x150&format=Png&isCircular=true"

class RobloxClient:
    def __init__(self):
        self.s = requests.Session()
        self.s.headers.update({"User-Agent": "Mozilla/5.0 (gestor-solicitudes/8.3)", "Accept": "application/json, text/plain, */*"})
        self.csrf = None
        self.csrf_lock = threading.Lock()

    def set_cookie(self, roblosec: str):
        self.s.cookies.set(".ROBLOSECURITY", roblosec.strip(), domain=".roblox.com")

    def _ensure_csrf(self):
        with self.csrf_lock:
            if self.csrf:
                return
            r = self.s.post("https://auth.roblox.com/v2/logout")
            token = r.headers.get("x-csrf-token") or r.headers.get("X-Csrf-Token")
            if token:
                self.csrf = token
                self.s.headers["X-Csrf-Token"] = token

    def _post_csrf(self, url, **kwargs):
        self._ensure_csrf()
        r = self.s.post(url, **kwargs)
        if r.status_code == 403:
            token = r.headers.get("x-csrf-token") or r.headers.get("X-Csrf-Token")
            if token:
                with self.csrf_lock:
                    self.csrf = token
                    self.s.headers["X-Csrf-Token"] = token
                r = self.s.post(url, **kwargs)
        return r

    def whoami(self):
        r = self.s.get(AUTH_URL, timeout=12)
        if r.status_code == 401:
            raise RuntimeError("No autenticado (401).")
        r.raise_for_status()
        return r.json()

    def get_pending_count(self) -> int:
        r = self.s.get(REQ_COUNT_URL, timeout=12)
        if r.status_code in (429, 502, 503, 504):
            time.sleep(1.0)
            r = self.s.get(REQ_COUNT_URL, timeout=12)
        r.raise_for_status()
        return int(r.json().get("count", 0))

    def iter_pending_requests(self, limit=100):
        cursor = None
        while True:
            params = {"limit": limit}
            if cursor:
                params["cursor"] = cursor
            r = self.s.get(REQ_LIST_URL, params=params, timeout=15)
            if r.status_code in (429, 502, 503, 504):
                time.sleep(1.0)
                continue
            r.raise_for_status()
            payload = r.json()
            for it in payload.get("data", []):
                yield it
            cursor = payload.get("nextPageCursor")
            if not cursor:
                break

    def get_user_info(self, user_id: int):
        r = self.s.get(USER_INFO_URL_TMPL.format(user_id=user_id), timeout=10)
        if r.status_code == 200:
            return r.json()
        return {"id": user_id, "name": "?", "displayName": ""}

    def get_avatar_image(self, user_id: int):
        r = self.s.get(AVATAR_URL_TMPL.format(uid=user_id), timeout=10)
        if r.status_code != 200:
            return None
        data = r.json()
        try:
            url = data["data"][0]["imageUrl"]
        except Exception:
            return None
        if not url:
            return None
        img_resp = self.s.get(url, timeout=10)
        if img_resp.status_code != 200:
            return None
        return Image.open(BytesIO(img_resp.content))

    def accept_request(self, user_id: int):
        return self._post_csrf(ACCEPT_URL_TMPL.format(user_id=user_id), timeout=12)

    def decline_request(self, user_id: int):
        return self._post_csrf(DECLINE_URL_TMPL.format(user_id=user_id), timeout=12)

class App(tb.Window if USE_TTKBOOTSTRAP else tk.Tk):
    def __init__(self):
        if USE_TTKBOOTSTRAP:
            super().__init__(themename="flatly")
        else:
            super().__init__()
        self.title("Roblox Friend Manager — Discord.gg/KayyShopV2")
        self.geometry("1920x1080")
        self.minsize(820, 480)

        self.client = RobloxClient()
        self.me = None

        self.auto_event = threading.Event()
        self.auto_mode = tk.StringVar(value="none")
        self.auto_thread = None

        self.img_cache_small = {}
        self.img_cache_user = None

        self._build_ui()

    def _build_ui(self):
        header = ttk.Frame(self, padding=(8, 6, 8, 4))
        header.pack(side=tk.TOP, fill=tk.X)
        title = ttk.Label(header, text="Roblox Friend Manager", font=("Segoe UI Semibold", 14))
        title.pack(side=tk.LEFT)
        brand = ttk.Label(header, text="9961", foreground="#6c757d")
        brand.pack(side=tk.RIGHT)

        priority = ttk.Frame(self, padding=(8, 0, 8, 6))
        priority.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(priority, text="AUTO:", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, padx=(0,6))
        self.btn_auto_accept = ttk.Button(priority, text="Auto-Aceptar", command=self.toggle_auto_accept, state="disabled")
        self.btn_auto_decline = ttk.Button(priority, text="Auto-Rechazar", command=self.toggle_auto_decline, state="disabled")
        self.btn_auto_stop = ttk.Button(priority, text="Detener", command=self.stop_auto_all, state="disabled")
        self.lbl_auto_state = ttk.Label(priority, text="Auto: inactivo")
        self.btn_auto_accept.grid(row=0, column=1, padx=4)
        self.btn_auto_decline.grid(row=0, column=2, padx=4)
        self.btn_auto_stop.grid(row=0, column=3, padx=4)
        self.lbl_auto_state.grid(row=0, column=4, padx=6, sticky="w")
        priority.grid_columnconfigure(4, weight=1)

        auth = ttk.Frame(self, padding=(8, 0, 8, 6))
        auth.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(auth, text="Token .ROBLOSECURITY:").grid(row=0, column=0, sticky="w")
        self.token_var = tk.StringVar()
        self.token_entry = ttk.Entry(auth, textvariable=self.token_var, show="•", width=52)
        self.token_entry.grid(row=0, column=1, padx=6, sticky="we")
        self.btn_login = ttk.Button(auth, text="Iniciar sesión", command=self.on_login)
        self.btn_login.grid(row=0, column=2, padx=6)
        auth.grid_columnconfigure(1, weight=1)

        user_panel = ttk.Frame(self, padding=(8, 0, 8, 6))
        user_panel.pack(side=tk.TOP, fill=tk.X)
        self.avatar_label = ttk.Label(user_panel)
        self.avatar_label.pack(side=tk.LEFT, padx=(0, 10))
        info_frame = ttk.Frame(user_panel)
        info_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.lbl_user = ttk.Label(info_frame, text="No autenticado", font=("Segoe UI", 10, "bold"))
        self.lbl_user.pack(anchor="w", pady=(0,2))
        self.lbl_count = ttk.Label(info_frame, text="Solicitudes pendientes: 0")
        self.lbl_count.pack(anchor="w")
        self.btn_refresh = ttk.Button(user_panel, text="Refrescar", command=self.refresh_counter, state="disabled")
        self.btn_refresh.pack(side=tk.RIGHT)

        actions = ttk.Frame(self, padding=(8, 0, 8, 6))
        actions.pack(side=tk.TOP, fill=tk.X)
        self.btn_accept_all = ttk.Button(actions, text="Aceptar todas", command=self.on_aceptar_todas, state="disabled")
        self.btn_decline_all = ttk.Button(actions, text="Rechazar todas", command=self.on_rechazar_todas, state="disabled")
        self.btn_clear_log = ttk.Button(actions, text="Limpiar log", command=self.clear_log, state="normal")
        for i, w in enumerate([self.btn_accept_all, self.btn_decline_all, self.btn_clear_log]):
            w.grid(row=0, column=i, padx=6, pady=3, sticky="w")

        center = ttk.PanedWindow(self, orient=tk.VERTICAL)
        center.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=8, pady=8)

        tables = ttk.Frame(center)
        center.add(tables, weight=3)
        self.tree_added = self._make_tree_section(tables, "Usuarios agregados")
        self.tree_declined = self._make_tree_section(tables, "Usuarios rechazados")
        self._grid_two_columns(tables, self.tree_added["frame"], self.tree_declined["frame"])

        log_frame = ttk.Frame(center)
        center.add(log_frame, weight=2)
        self.txt_log = tk.Text(log_frame, wrap="word", height=6, bd=0, padx=6, pady=4, relief="flat", font=("Segoe UI", 9))
        vsb = ttk.Scrollbar(log_frame, orient="vertical", command=self.txt_log.yview)
        self.txt_log.configure(yscrollcommand=vsb.set)
        self.txt_log.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self.txt_log.tag_configure("time", foreground="#6c757d")
        self.txt_log.tag_configure("ok", foreground="#198754")
        self.txt_log.tag_configure("info", foreground="#0d6efd")
        self.txt_log.tag_configure("warn", foreground="#ff8800")
        self.txt_log.tag_configure("err", foreground="#dc3545")
        self.txt_log.tag_configure("bold", font=("Segoe UI", 9, "bold"))

        self.status_var = tk.StringVar(value="Listo.")
        status = ttk.Label(self, textvariable=self.status_var, anchor="w", padding=(8, 4))
        status.pack(side=tk.BOTTOM, fill=tk.X)

        if USE_TTKBOOTSTRAP:
            style = tb.Style()
        else:
            style = ttk.Style()
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
        style.configure("Treeview", rowheight=34, padding=(2, 2))

    def _make_tree_section(self, parent, title):
        frame = ttk.Labelframe(parent, text=title, padding=(8, 8, 8, 8))
        columns = ("username", "display")
        tree = ttk.Treeview(frame, columns=columns, show="tree headings", height=10)
        tree.heading("#0", text="UserId / Avatar")
        tree.heading("username", text="Username")
        tree.heading("display", text="DisplayName")
        tree.column("#0", width=180, anchor="w")
        tree.column("username", width=200, anchor="w")
        tree.column("display", width=210, anchor="w")
        vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(4, 6), pady=(4, 4))
        vsb.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 4), pady=(4, 4))
        return {"frame": frame, "tree": tree}

    def _grid_two_columns(self, parent, a, b):
        parent.columnconfigure(0, weight=1, uniform="cols")
        parent.columnconfigure(1, weight=1, uniform="cols")
        a.grid(row=0, column=0, sticky="nsew", padx=(0, 8), pady=(0, 6))
        b.grid(row=0, column=1, sticky="nsew", padx=(8, 0), pady=(0, 6))

    def _ts(self):
        return datetime.now().strftime("%H:%M:%S")

    def log(self, kind, msg):
        icon = {"ok": "✅", "info": "ℹ️", "warn": "⚠️", "err": "❌"}.get(kind, "•")
        self.txt_log.insert(tk.END, f"[{self._ts()}] ", ("time",))
        self.txt_log.insert(tk.END, f"{icon} ", (kind,))
        self.txt_log.insert(tk.END, msg + "\n", (kind,))
        self.txt_log.see(tk.END)

    def clear_log(self):
        self.txt_log.delete("1.0", tk.END)
        self.log("info", "Log limpiado.")

    def set_status(self, msg):
        self.status_var.set(msg)
        self.update_idletasks()

    def set_controls_enabled(self, enabled):
        state = "normal" if enabled else "disabled"
        for w in [self.btn_accept_all, self.btn_decline_all, self.btn_refresh,
                  self.btn_auto_accept, self.btn_auto_decline, self.btn_auto_stop]:
            w.config(state=state)

    def get_small_avatar(self, uid: int):
        if uid in self.img_cache_small:
            return self.img_cache_small[uid]
        img = self.client.get_avatar_image(uid)
        if not img:
            return None
        img = img.resize((24, 24), Image.LANCZOS)
        tkimg = ImageTk.PhotoImage(img)
        self.img_cache_small[uid] = tkimg
        return tkimg

    def on_login(self):
        token = self.token_var.get().strip()
        if not token:
            messagebox.showwarning("Aviso", "Introduce tu token .ROBLOSECURITY.")
            return
        self.client.set_cookie(token)
        self.set_status("Autenticando…")
        self.set_controls_enabled(False)
        def worker():
            try:
                me = self.client.whoami()
                uid = me.get("id")
                name = me.get("name") or me.get("username")
                disp = me.get("displayName")
                shown = f"{name} ({disp})" if disp and disp != name else name
                self.me = {"id": uid, "name": name, "displayName": disp}
                avatar_img = self.client.get_avatar_image(uid)
                if avatar_img:
                    avatar_img = avatar_img.resize((52, 52), Image.LANCZOS)
                    avatar = ImageTk.PhotoImage(avatar_img)
                    self.img_cache_user = avatar
                    self.after(0, lambda: self.avatar_label.configure(image=avatar))
                cnt = self.client.get_pending_count()
                self.after(0, lambda: (
                    self.lbl_user.config(text=f"Autenticado como: {shown} | id={uid}"),
                    self.lbl_count.config(text=f"Solicitudes pendientes: {cnt}"),
                    self.set_controls_enabled(True),
                    self.btn_auto_accept.config(state="normal"),
                    self.btn_auto_decline.config(state="normal"),
                    self.set_status("Listo."),
                    self.log("ok", f"Sesión iniciada como {shown}.")
                ))
            except Exception as e:
                self.after(0, lambda: (
                    self.set_controls_enabled(False),
                    self.log("err", f"No se pudo autenticar: {e}"),
                    self.set_status("Error"),
                    messagebox.showerror("Error", f"No se pudo autenticar:\n{e}")
                ))
        threading.Thread(target=worker, daemon=True).start()

    def refresh_counter(self):
        if not self.me:
            return
        self.set_status("Actualizando contador…")
        def worker():
            try:
                cnt = self.client.get_pending_count()
                self.after(0, lambda: (
                    self.lbl_count.config(text=f"Solicitudes pendientes: {cnt}"),
                    self.set_status("Listo."),
                    self.log("info", f"Contador actualizado: {cnt}.")
                ))
            except Exception as e:
                self.after(0, lambda: (
                    self.log("warn", f"No se pudo actualizar el contador: {e}"),
                    self.set_status("Listo.")
                ))
        threading.Thread(target=worker, daemon=True).start()

    def on_aceptar_todas(self):
        self.set_status("Aceptando…")
        def worker():
            added = 0
            for req in self.client.iter_pending_requests(limit=100):
                uid = req.get("id") or req.get("userId")
                info = self.client.get_user_info(uid)
                name = info.get("name", "?")
                disp = info.get("displayName", "")
                img = self.get_small_avatar(uid)
                self.after(0, lambda u=uid, n=name, d=disp: self.log("info", f"Aceptando: {u}  {n} [{d}]"))
                r = self.client.accept_request(uid)
                if r.status_code == 200:
                    added += 1
                    self.after(0, lambda u=uid, n=name, d=disp, im=img: self.tree_added["tree"].insert("", tk.END, text=str(u), image=im, values=(n, d)))
                else:
                    self.after(0, lambda: self.log("warn", f"Error {r.status_code}: {r.text[:200]}"))
                time.sleep(0.07)
            self.after(0, lambda: (self.set_status("Listo."), self.log("ok", f"✅ Aceptadas: {added}")))
            self._post_action_refresh()
        threading.Thread(target=worker, daemon=True).start()

    def on_rechazar_todas(self):
        self.set_status("Rechazando…")
        def worker():
            declined = 0
            for req in self.client.iter_pending_requests(limit=100):
                uid = req.get("id") or req.get("userId")
                info = self.client.get_user_info(uid)
                name = info.get("name", "?")
                disp = info.get("displayName", "")
                img = self.get_small_avatar(uid)
                self.after(0, lambda u=uid, n=name, d=disp: self.log("info", f"Rechazando: {u}  {n} [{d}]"))
                r = self.client.decline_request(uid)
                if r.status_code == 200:
                    declined += 1
                    self.after(0, lambda u=uid, n=name, d=disp, im=img: self.tree_declined["tree"].insert("", tk.END, text=str(u), image=im, values=(n, d)))
                else:
                    self.after(0, lambda: self.log("warn", f"Error {r.status_code}: {r.text[:200]}"))
                time.sleep(0.07)
            self.after(0, lambda: (self.set_status("Listo."), self.log("ok", f"✅ Rechazadas: {declined}")))
            self._post_action_refresh()
        threading.Thread(target=worker, daemon=True).start()

    def _post_action_refresh(self):
        def worker():
            try:
                cnt = self.client.get_pending_count()
                self.after(0, lambda: self.lbl_count.config(text=f"Solicitudes pendientes: {cnt}"))
            except Exception:
                pass
        threading.Thread(target=worker, daemon=True).start()

    def toggle_auto_accept(self):
        if self.auto_mode.get() == "accept" and not self.auto_event.is_set():
            self.stop_auto_all()
            return
        self.start_auto(mode="accept")

    def toggle_auto_decline(self):
        if self.auto_mode.get() == "decline" and not self.auto_event.is_set():
            self.stop_auto_all()
            return
        self.start_auto(mode="decline")

    def start_auto(self, mode: str):
        if not self.me:
            messagebox.showwarning("Aviso", "Inicia sesión primero.")
            return
        self.stop_auto_all()
        self.auto_mode.set(mode)
        self.auto_event.clear()
        self.btn_auto_stop.config(state="normal")
        self._set_auto_buttons_text()
        self.lbl_auto_state.config(text=f"Auto: {mode}")
        self.log("info", f"Modo automático iniciado: {mode}.")
        self.auto_thread = threading.Thread(target=self._auto_loop, args=(mode,), daemon=True)
        self.auto_thread.start()

    def stop_auto_all(self):
        self.auto_event.set()
        self.auto_mode.set("none")
        self._set_auto_buttons_text()
        self.lbl_auto_state.config(text="Auto: inactivo")
        self.btn_auto_stop.config(state="disabled")
        self.log("ok", "✅ Auto detenido.")

    def _set_auto_buttons_text(self):
        self.btn_auto_accept.config(text="Auto-Aceptar" if self.auto_mode.get() != "accept" else "Detener")
        self.btn_auto_decline.config(text="Auto-Rechazar" if self.auto_mode.get() != "decline" else "Detener")

    def _auto_loop(self, mode: str):
        while not self.auto_event.is_set():
            for req in self.client.iter_pending_requests(limit=100):
                if self.auto_event.is_set() or self.auto_mode.get() != mode:
                    break
                uid = req.get("id") or req.get("userId")
                info = self.client.get_user_info(uid)
                name = info.get("name", "?")
                disp = info.get("displayName", "")
                img = self.get_small_avatar(uid)
                if mode == "accept":
                    self.after(0, lambda u=uid, n=name, d=disp: self.log("ok", f"✅ (auto) Aceptando: {u}  {n} [{d}]"))
                    r = self.client.accept_request(uid)
                    if r.status_code == 200:
                        self.after(0, lambda u=uid, n=name, d=disp, im=img: self.tree_added["tree"].insert("", tk.END, text=str(u), image=im, values=(n, d)))
                    else:
                        self.after(0, lambda: self.log("warn", f"Error {r.status_code}: {r.text[:200]}"))
                elif mode == "decline":
                    self.after(0, lambda u=uid, n=name, d=disp: self.log("warn", f"⛔ (auto) Rechazando: {u}  {n} [{d}]"))
                    r = self.client.decline_request(uid)
                    if r.status_code == 200:
                        self.after(0, lambda u=uid, n=name, d=disp, im=img: self.tree_declined["tree"].insert("", tk.END, text=str(u), image=im, values=(n, d)))
                    else:
                        self.after(0, lambda: self.log("warn", f"Error {r.status_code}: {r.text[:200]}"))
                time.sleep(0.07)
            try:
                cnt = self.client.get_pending_count()
                self.after(0, lambda: self.lbl_count.config(text=f"Solicitudes pendientes: {cnt}"))
            except Exception:
                pass
            for _ in range(12):
                if self.auto_event.is_set() or self.auto_mode.get() != mode:
                    break
                time.sleep(0.1)

    def _clear_tree(self, tree):
        for it in tree.get_children():
            tree.delete(it)

if __name__ == "__main__":
    App().mainloop()
