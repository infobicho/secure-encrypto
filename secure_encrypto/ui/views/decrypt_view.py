"""Decryption view — decrypt .senc files."""

import os
import threading
from tkinter import filedialog, messagebox
import customtkinter as ctk
try:
    import tkinterdnd2 as _dnd
    _DND_AVAILABLE = True
except ImportError:
    _DND_AVAILABLE = False

from ..theme import C, F
from ...core.engine import CryptoEngine, DecryptionError


def _card(parent, title: str = "", pady_inner=(0, 16)):
    outer = ctk.CTkFrame(
        parent, fg_color=C['card'], corner_radius=12,
        border_width=1, border_color=C['border'],
    )
    outer.pack(fill='x', pady=(0, 14))
    if title:
        ctk.CTkLabel(outer, text=title, font=F['heading'], text_color=C['text']).pack(
            anchor='w', padx=18, pady=(14, 0))
        ctk.CTkFrame(outer, height=1, fg_color=C['border']).pack(fill='x', padx=18, pady=(10, 0))
    inner = ctk.CTkFrame(outer, fg_color='transparent')
    inner.pack(fill='x', padx=18, pady=pady_inner)
    return inner


class DecryptView(ctk.CTkScrollableFrame):

    def __init__(self, parent):
        super().__init__(
            parent, fg_color='transparent',
            scrollbar_button_color=C['border'],
            scrollbar_button_hover_color=C['border_light'],
        )
        self._show_pwd = False
        self._build()

    def _build(self):
        # Header
        hdr = ctk.CTkFrame(self, fg_color='transparent')
        hdr.pack(fill='x', pady=(0, 18))
        ctk.CTkLabel(hdr, text="🔓  Déchiffrement", font=F['display'], text_color=C['text']).pack(side='left')
        ctk.CTkLabel(hdr, text="AES-256-GCM • Vérification d'intégrité", font=F['small'],
                     text_color=C['accent']).pack(side='right', anchor='s', pady=6)

        # File picker card
        fc = _card(self, "📂  Fichier .senc à déchiffrer")
        self._file_var = ctk.StringVar()

        row = ctk.CTkFrame(fc, fg_color='transparent')
        row.pack(fill='x', pady=(8, 0))

        self._file_entry = ctk.CTkEntry(
            row, textvariable=self._file_var,
            placeholder_text="Sélectionnez un fichier .senc…",
            height=42, font=F['body'],
            fg_color=C['bg'], border_color=C['border'], text_color=C['text'],
        )
        self._file_entry.pack(side='left', fill='x', expand=True, padx=(0, 10))

        ctk.CTkButton(
            row, text="📂  Ouvrir", width=100, height=42, font=F['body'],
            fg_color=C['hover'], hover_color=C['border'],
            command=self._pick_file, corner_radius=8,
        ).pack(side='left')

        # File info panel
        self._info_frame = _card(self, "📋  Informations du fichier chiffré")
        self._info_box = ctk.CTkTextbox(
            self._info_frame, height=130, font=F['mono_sm'],
            fg_color=C['bg'], border_color=C['border'], border_width=1,
            text_color=C['subtext'],
        )
        self._info_box.pack(fill='x', pady=(8, 0))
        self._info_box.insert('end', "Sélectionnez un fichier .senc pour voir ses informations…\n")
        self._info_box.configure(state='disabled')

        # Bind file selection
        self._file_var.trace_add('write', self._on_file_change)

        # Password card
        pc = _card(self, "🔑  Mot de passe de déchiffrement")

        row_p = ctk.CTkFrame(pc, fg_color='transparent')
        row_p.pack(fill='x', pady=(8, 0))

        self._pwd_var = ctk.StringVar()
        self._pwd_entry = ctk.CTkEntry(
            row_p, textvariable=self._pwd_var, show='•',
            placeholder_text="Entrez le mot de passe utilisé lors du chiffrement…",
            height=42, font=F['body'],
            fg_color=C['bg'], border_color=C['border'], text_color=C['text'],
        )
        self._pwd_entry.pack(side='left', fill='x', expand=True, padx=(0, 8))

        self._eye_btn = ctk.CTkButton(
            row_p, text="👁", width=42, height=42, font=('Segoe UI Emoji', 16),
            fg_color=C['hover'], hover_color=C['border'],
            command=self._toggle_pwd, corner_radius=8,
        )
        self._eye_btn.pack(side='left')

        # Output folder card
        oc = _card(self, "📁  Dossier de sortie")
        self._outdir_var = ctk.StringVar()

        row_o = ctk.CTkFrame(oc, fg_color='transparent')
        row_o.pack(fill='x', pady=(8, 0))

        ctk.CTkEntry(
            row_o, textvariable=self._outdir_var,
            placeholder_text="Dossier de destination (vide = même dossier que le .senc)…",
            height=42, font=F['body'],
            fg_color=C['bg'], border_color=C['border'], text_color=C['text'],
        ).pack(side='left', fill='x', expand=True, padx=(0, 10))

        ctk.CTkButton(
            row_o, text="📁  Choisir", width=100, height=42, font=F['body'],
            fg_color=C['hover'], hover_color=C['border'],
            command=self._pick_outdir, corner_radius=8,
        ).pack(side='left')

        # Action card
        ac = _card(self, "", pady_inner=(14, 14))

        self._btn = ctk.CTkButton(
            ac, text="🔓  Déchiffrer maintenant",
            height=52, font=F['title'],
            fg_color='#1a5c2e', hover_color=C['success'],
            corner_radius=10,
            command=self._start_decrypt,
        )
        self._btn.pack(fill='x')

        self._prog = ctk.CTkProgressBar(
            ac, height=6, corner_radius=3,
            progress_color=C['success'], fg_color=C['border'],
        )
        self._prog.pack(fill='x', pady=(12, 0))
        self._prog.set(0)

        self._status = ctk.CTkLabel(ac, text="Prêt.", font=F['small'], text_color=C['subtext'])
        self._status.pack(pady=(6, 0))

        # Security notice
        notice = _card(self, "")
        ctk.CTkLabel(
            notice,
            text="🛡  Le tag d'authentification GCM est vérifié automatiquement.\n"
                 "Toute altération du fichier sera détectée et le déchiffrement sera refusé.",
            font=F['tiny'], text_color=C['muted'], justify='left',
        ).pack(anchor='w', pady=(4, 4))
        self._setup_dnd()

    # ── Drag & drop ───────────────────────────────────────────────────────
    def _setup_dnd(self):
        """Enregistre la zone de dépôt drag & drop sur le champ fichier."""
        if not _DND_AVAILABLE:
            return
        try:
            self._file_entry.drop_target_register(_dnd.DND_FILES)
            self._file_entry.dnd_bind('<<Drop>>', self._on_dnd_drop)
            self._file_entry.configure(
                placeholder_text="Glissez un .senc ici ou cliquez sur Ouvrir →"
            )
        except Exception:
            pass

    def _on_dnd_drop(self, event):
        """Réception d'un fichier .senc glissé-déposé."""
        path = event.data.strip()
        # Sur Windows les chemins avec espaces sont entourés d'accolades {}
        if path.startswith('{') and path.endswith('}'):
            path = path[1:-1]
        if not os.path.exists(path) and ' ' in path:
            parts = path.split()
            for part in parts:
                if os.path.exists(part):
                    path = part
                    break
        if os.path.isfile(path):
            self._file_var.set(path)

    def _pick_file(self):
        p = filedialog.askopenfilename(
            title="Sélectionner un fichier .senc",
            filetypes=[("Fichiers chiffrés", "*.senc"), ("Tous les fichiers", "*.*")],
        )
        if p:
            self._file_var.set(p)

    def _pick_outdir(self):
        p = filedialog.askdirectory(title="Dossier de destination")
        if p:
            self._outdir_var.set(p)

    def _toggle_pwd(self):
        self._show_pwd = not self._show_pwd
        self._pwd_entry.configure(show='' if self._show_pwd else '•')
        self._eye_btn.configure(text='🙈' if self._show_pwd else '👁')

    def _on_file_change(self, *_):
        path = self._file_var.get().strip()
        self._info_box.configure(state='normal')
        self._info_box.delete('1.0', 'end')

        if not path or not os.path.isfile(path):
            self._info_box.insert('end', "Sélectionnez un fichier .senc pour voir ses informations…\n")
            self._info_box.configure(state='disabled')
            return

        info = CryptoEngine.get_file_info(path)
        if info.get('valid'):
            size_mb = info['encrypted_size'] / (1024 * 1024)
            self._info_box.insert('end',
                f"✅  Fichier .senc valide\n"
                f"Fichier original  : {info['original_name']}\n"
                f"Taille chiffrée   : {size_mb:.2f} MB  ({info['encrypted_size']:,} octets)\n"
                f"Argon2id          : {info['argon2_memory_mb']} MB RAM · "
                f"{info['argon2_time_cost']} itérations · "
                f"{info['argon2_parallelism']} threads\n"
                f"Version format    : v{info['version']}\n"
            )
        else:
            self._info_box.insert('end', f"❌  {info.get('error', 'Fichier invalide')}\n")

        self._info_box.configure(state='disabled')

    def _start_decrypt(self):
        path = self._file_var.get().strip()
        pwd  = self._pwd_var.get()

        if not path:
            messagebox.showwarning("Champ manquant", "Sélectionnez un fichier .senc.")
            return
        if not os.path.isfile(path):
            messagebox.showerror("Erreur", "Fichier introuvable.")
            return
        if not pwd:
            messagebox.showwarning("Champ manquant", "Entrez le mot de passe.")
            return

        outdir = self._outdir_var.get().strip() or os.path.dirname(os.path.abspath(path))

        self._btn.configure(state='disabled', text="⏳  Déchiffrement en cours…")
        self._prog.set(0)
        self._status.configure(text="Dérivation Argon2id… (~2s)", text_color=C['subtext'])

        threading.Thread(target=self._do_decrypt, args=(path, pwd, outdir), daemon=True).start()

    def _do_decrypt(self, path, pwd, outdir):
        try:
            os.makedirs(outdir, exist_ok=True)

            def cb(v):
                self._prog.set(v)
                if v < 0.5:
                    self._status.configure(text="Dérivation Argon2id…")
                elif v < 0.9:
                    self._status.configure(text="Déchiffrement AES-256-GCM + vérif. intégrité…")
                else:
                    self._status.configure(text="Écriture du fichier…")

            result = CryptoEngine.decrypt_file(path, outdir, pwd, cb)

            self._prog.set(1.0)
            name = os.path.basename(result)
            self._status.configure(
                text=f"✅  Déchiffré → {name}",
                text_color=C['success'],
            )
            messagebox.showinfo("Déchiffrement réussi ✅",
                f"Fichier déchiffré avec succès.\n\n"
                f"Intégrité : ✅  Vérifiée (GCM auth tag)\n"
                f"Sortie    : {result}"
            )
        except DecryptionError as e:
            self._prog.set(0)
            self._status.configure(text="❌  Échec du déchiffrement", text_color=C['error'])
            messagebox.showerror("Déchiffrement échoué ❌",
                f"{e}\n\nVérifiez que :\n"
                "• Le mot de passe est correct\n"
                "• Le fichier n'est pas corrompu\n"
                "• Le fichier est bien un .senc créé par secure-encrypto"
            )
        except Exception as e:
            self._status.configure(text="❌  Erreur inattendue", text_color=C['error'])
            messagebox.showerror("Erreur inattendue", str(e))
        finally:
            self._reset_btn()

    def _reset_btn(self):
        self._btn.configure(state='normal', text="🔓  Déchiffrer maintenant")
