"""Main application window — sidebar navigation + view switcher."""

import customtkinter as ctk
try:
    import tkinterdnd2 as _dnd
    _DND_AVAILABLE = True
except ImportError:
    _DND_AVAILABLE = False
from .theme import C, F
from .views.encrypt_view import EncryptView
from .views.decrypt_view import DecryptView
from .views.hash_view import HashView
from .views.security_view import SecurityView
from .views.about_view import AboutView

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

NAV_ITEMS = [
    ("🔒", "Chiffrer",    EncryptView),
    ("🔓", "Déchiffrer",  DecryptView),
    ("#️⃣", "Hachage",     HashView),
    ("🛡",  "Sécurité",   SecurityView),
    ("ℹ️",  "À propos",   AboutView),
]


class App(ctk.CTk):
    """
    Fenêtre principale.
    Si tkinterdnd2 est disponible, active le drag & drop natif via
    le mécanisme TkinterDnD.DnDWrapper greffé sur la fenêtre CTk.
    """

    def __init__(self):
        super().__init__()
        # Active le drag & drop si tkinterdnd2 est installé
        if _DND_AVAILABLE:
            try:
                self.TkdndVersion = _dnd.TkinterDnD._require(self)
            except Exception:
                pass
        self.title("secure-encrypto  •  v2.0")
        self.geometry("1100x780")
        self.minsize(900, 650)
        self.configure(fg_color=C['bg'])

        self._views: dict = {}
        self._active_view = None
        self._active_btn  = None

        self._build()
        self._switch_view(0)

    # ──────────────────────────────────────────────────────────────────────
    # Layout
    # ──────────────────────────────────────────────────────────────────────

    def _build(self):
        # ── Sidebar ───────────────────────────────────────────────────────
        self._sidebar = ctk.CTkFrame(
            self, width=220, fg_color=C['sidebar'],
            corner_radius=0,
        )
        self._sidebar.pack(side='left', fill='y')
        self._sidebar.pack_propagate(False)

        # Logo area
        logo_frame = ctk.CTkFrame(self._sidebar, fg_color='transparent')
        logo_frame.pack(fill='x', padx=18, pady=(24, 0))

        ctk.CTkLabel(
            logo_frame, text="🔐", font=('Segoe UI Emoji', 28),
        ).pack(side='left')

        title_col = ctk.CTkFrame(logo_frame, fg_color='transparent')
        title_col.pack(side='left', padx=(10, 0))
        ctk.CTkLabel(
            title_col, text="secure-encrypto",
            font=('Segoe UI', 14, 'bold'), text_color=C['text'],
        ).pack(anchor='w')
        ctk.CTkLabel(
            title_col, text="v2.0",
            font=F['tiny'], text_color=C['muted'],
        ).pack(anchor='w')

        # Divider
        ctk.CTkFrame(self._sidebar, height=1, fg_color=C['border']).pack(
            fill='x', padx=18, pady=(20, 16)
        )

        # Nav buttons
        self._nav_buttons = []
        for i, (icon, label, _view) in enumerate(NAV_ITEMS):
            btn = self._make_nav_btn(icon, label, i)
            self._nav_buttons.append(btn)

        # Bottom info
        ctk.CTkFrame(self._sidebar, fg_color='transparent').pack(fill='y', expand=True)
        ctk.CTkFrame(self._sidebar, height=1, fg_color=C['border']).pack(fill='x', padx=18, pady=(0, 12))
        ctk.CTkLabel(
            self._sidebar, text="AES-256-GCM • Argon2id",
            font=F['tiny'], text_color=C['muted'],
        ).pack(pady=(0, 6))
        ctk.CTkLabel(
            self._sidebar, text="MIT License",
            font=F['tiny'], text_color=C['muted'],
        ).pack(pady=(0, 18))

        # ── Content area ──────────────────────────────────────────────────
        self._content = ctk.CTkFrame(
            self, fg_color=C['bg'], corner_radius=0,
        )
        self._content.pack(side='left', fill='both', expand=True)

        # Pre-build all views (hidden initially)
        for i, (_icon, _label, ViewClass) in enumerate(NAV_ITEMS):
            frame = ctk.CTkFrame(self._content, fg_color='transparent')
            view  = ViewClass(frame)
            view.pack(fill='both', expand=True, padx=28, pady=24)
            self._views[i] = frame

    def _make_nav_btn(self, icon: str, label: str, index: int) -> ctk.CTkButton:
        btn = ctk.CTkButton(
            self._sidebar,
            text=f"  {icon}  {label}",
            anchor='w',
            height=46,
            font=F['body'],
            fg_color='transparent',
            text_color=C['subtext'],
            hover_color=C['hover'],
            corner_radius=8,
            command=lambda i=index: self._switch_view(i),
        )
        btn.pack(fill='x', padx=12, pady=2)
        return btn

    # ──────────────────────────────────────────────────────────────────────
    # Navigation
    # ──────────────────────────────────────────────────────────────────────

    def _switch_view(self, index: int):
        # Hide current
        if self._active_view is not None:
            self._active_view.pack_forget()

        # Reset previous button style
        if self._active_btn is not None:
            self._active_btn.configure(
                fg_color='transparent',
                text_color=C['subtext'],
                font=F['body'],
            )

        # Show new view
        self._active_view = self._views[index]
        self._active_view.pack(fill='both', expand=True)

        # Highlight button
        btn = self._nav_buttons[index]
        btn.configure(
            fg_color=C['hover'],
            text_color=C['text'],
            font=('Segoe UI', 13, 'bold'),
        )
        self._active_btn = btn


def run():
    app = App()
    app.mainloop()
