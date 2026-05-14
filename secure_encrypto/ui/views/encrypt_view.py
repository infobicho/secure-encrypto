"""Encryption view — file and folder encryption."""

import os
import queue
import threading
from tkinter import filedialog, messagebox
import customtkinter as ctk
try:
    import tkinterdnd2 as _dnd
    _DND_AVAILABLE = True
except ImportError:
    _DND_AVAILABLE = False

from ..theme import C, F
from ...core.engine import CryptoEngine, EncryptionError
from ...core.secure_wipe import secure_delete
from ...utils.password_strength import check_strength, generate_password


def _card(parent, title: str = "", pady_inner=(0, 16)):
    outer = ctk.CTkFrame(
        parent, fg_color=C['card'], corner_radius=12,
        border_width=1, border_color=C['border'],
    )
    outer.pack(fill='x', pady=(0, 14))

    if title:
        ctk.CTkLabel(
            outer, text=title, font=F['heading'], text_color=C['text'],
        ).pack(anchor='w', padx=18, pady=(14, 0))
        ctk.CTkFrame(outer, height=1, fg_color=C['border']).pack(
            fill='x', padx=18, pady=(10, 0)
        )

    inner = ctk.CTkFrame(outer, fg_color='transparent')
    inner.pack(fill='x', padx=18, pady=pady_inner)
    return inner


class EncryptView(ctk.CTkScrollableFrame):

    def __init__(self, parent):
        super().__init__(
            parent, fg_color='transparent',
            scrollbar_button_color=C['border'],
            scrollbar_button_hover_color=C['border_light'],
        )
        self._show_pwd = False
        self._build()

    def _build(self):
        hdr = ctk.CTkFrame(self, fg_color='transparent')
        hdr.pack(fill='x', pady=(0, 18))
        ctk.CTkLabel(
            hdr, text="🔒  Chiffrement", font=F['display'], text_color=C['text'],
        ).pack(side='left')
        ctk.CTkLabel(
            hdr, text="AES-256-GCM • Argon2id", font=F['small'],
            text_color=C['accent'],
        ).pack(side='right', anchor='s', pady=6)

        # File picker
        fc = _card(self, "📂  Fichier ou dossier à chiffrer")
        self._file_var = ctk.StringVar()

        row = ctk.CTkFrame(fc, fg_color='transparent')
        row.pack(fill='x', pady=(8, 0))

        self._file_entry = ctk.CTkEntry(
            row, textvariable=self._file_var,
            placeholder_text="Glissez un fichier ou cliquez sur un bouton →",
            height=42, font=F['body'],
            fg_color=C['bg'], border_color=C['border'],
            text_color=C['text'],
        )
        self._file_entry.pack(side='left', fill='x', expand=True, padx=(0, 10))

        ctk.CTkButton(
            row, text="📄", width=42, height=42, font=('Segoe UI Emoji', 18),
            fg_color=C['hover'], hover_color=C['border'],
            command=self._pick_file, corner_radius=8,
        ).pack(side='left', padx=(0, 6))
        ctk.CTkButton(
            row, text="📁", width=42, height=42, font=('Segoe UI Emoji', 18),
            fg_color=C['hover'], hover_color=C['border'],
            command=self._pick_folder, corner_radius=8,
        ).pack(side='left')

        # Password card
        pc = _card(self, "🔑  Mot de passe de chiffrement")

        row1 = ctk.CTkFrame(pc, fg_color='transparent')
        row1.pack(fill='x', pady=(8, 0))

        self._pwd_var = ctk.StringVar()
        self._pwd_var.trace_add('write', self._on_pwd_change)

        self._pwd_entry = ctk.CTkEntry(
            row1, textvariable=self._pwd_var, show='•',
            placeholder_text="Mot de passe...",
            height=42, font=F['body'],
            fg_color=C['bg'], border_color=C['border'],
            text_color=C['text'],
        )
        self._pwd_entry.pack(side='left', fill='x', expand=True, padx=(0, 8))

        self._eye_btn = ctk.CTkButton(
            row1, text="👁", width=42, height=42, font=('Segoe UI Emoji', 16),
            fg_color=C['hover'], hover_color=C['border'],
            command=self._toggle_pwd, corner_radius=8,
        )
        self._eye_btn.pack(side='left', padx=(0, 6))

        ctk.CTkButton(
            row1, text="🎲", width=42, height=42, font=('Segoe UI Emoji', 16),
            fg_color=C['hover'], hover_color=C['border'],
            command=self._gen_pwd, corner_radius=8,
        ).pack(side='left')

        ctk.CTkLabel(
            pc, text="Confirmer le mot de passe",
            font=F['small'], text_color=C['subtext'],
        ).pack(anchor='w', pady=(12, 4))

        self._pwd2_var = ctk.StringVar()
        self._pwd2_entry = ctk.CTkEntry(
            pc, textvariable=self._pwd2_var, show='•',
            placeholder_text="Répétez le mot de passe...",
            height=42, font=F['body'],
            fg_color=C['bg'], border_color=C['border'],
            text_color=C['text'],
        )
        self._pwd2_entry.pack(fill='x', pady=(0, 12))

        # Strength meter
        self._bar = ctk.CTkProgressBar(
            pc, height=8, corner_radius=4,
            progress_color=C['error'], fg_color=C['border'],
        )
        self._bar.pack(fill='x')
        self._bar.set(0)

        meter_row = ctk.CTkFrame(pc, fg_color='transparent')
        meter_row.pack(fill='x', pady=(6, 0))

        self._level_lbl = ctk.CTkLabel(
            meter_row, text="", font=F['small'], text_color=C['subtext'],
        )
        self._level_lbl.pack(side='left')

        self._entropy_lbl = ctk.CTkLabel(
            meter_row, text="", font=F['tiny'], text_color=C['muted'],
        )
        self._entropy_lbl.pack(side='right')

        self._feedback_lbl = ctk.CTkLabel(
            pc, text="", font=F['tiny'], text_color=C['subtext'],
            wraplength=600, justify='left',
        )
        self._feedback_lbl.pack(anchor='w', pady=(4, 0))

        # Options card
        oc = _card(self, "⚙️  Options")

        self._delete_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            oc, text="Suppression sécurisée (3 passes) du fichier original après chiffrement",
            variable=self._delete_var,
            text_color=C['text'], font=F['body'],
            checkmark_color='white', fg_color=C['accent'],
            hover_color=C['accent_hover'],
        ).pack(anchor='w', pady=(8, 2))

        ctk.CTkLabel(
            oc,
            text=(
                "⚠️  SSD/NVMe : la suppression sécurisée est 'best effort' — "
                "le wear-leveling peut conserver des copies dans des blocs inaccessibles au logiciel. "
                "Seul le chiffrement intégral du disque (ex: LUKS, BitLocker) garantit une protection totale."
            ),
            font=F['tiny'], text_color=C['warning'],
            wraplength=620, justify='left',
        ).pack(anchor='w', padx=(28, 0), pady=(0, 8))

        self._same_dir_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            oc, text="Enregistrer le fichier .senc dans le même dossier que l'original",
            variable=self._same_dir_var,
            text_color=C['text'], font=F['body'],
            checkmark_color='white', fg_color=C['accent'],
            hover_color=C['accent_hover'],
        ).pack(anchor='w', pady=(0, 8))

        # Action card
        ac = _card(self, "", pady_inner=(14, 14))

        self._btn = ctk.CTkButton(
            ac, text="🔒  Chiffrer maintenant",
            height=52, font=F['title'],
            fg_color=C['accent'], hover_color=C['accent_hover'],
            corner_radius=10,
            command=self._start_encrypt,
        )
        self._btn.pack(fill='x')

        self._prog = ctk.CTkProgressBar(
            ac, height=6, corner_radius=3,
            progress_color=C['success'], fg_color=C['border'],
        )
        self._prog.pack(fill='x', pady=(12, 0))
        self._prog.set(0)

        self._status = ctk.CTkLabel(
            ac, text="Prêt.", font=F['small'], text_color=C['subtext'],
        )
        self._status.pack(pady=(6, 0))
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
                placeholder_text="Glissez un fichier ici ou cliquez sur un bouton →"
            )
        except Exception:
            pass

    def _on_dnd_drop(self, event):
        """Réception d'un fichier glissé-déposé."""
        path = event.data.strip()
        # Sur Windows les chemins avec espaces sont entourés d'accolades {}
        if path.startswith('{') and path.endswith('}'):
            path = path[1:-1]
        # Sur certains systèmes plusieurs fichiers sont séparés par des espaces :
        # on prend uniquement le premier
        if not os.path.exists(path) and ' ' in path:
            parts = path.split()
            for part in parts:
                if os.path.exists(part):
                    path = part
                    break
        if os.path.exists(path):
            self._file_var.set(path)

    def _pick_file(self):
        p = filedialog.askopenfilename(title="Sélectionner un fichier à chiffrer")
        if p:
            self._file_var.set(p)

    def _pick_folder(self):
        p = filedialog.askdirectory(title="Sélectionner un dossier à chiffrer")
        if p:
            self._file_var.set(p)

    def _toggle_pwd(self):
        self._show_pwd = not self._show_pwd
        ch = '' if self._show_pwd else '•'
        self._pwd_entry.configure(show=ch)
        self._pwd2_entry.configure(show=ch)
        self._eye_btn.configure(text='🙈' if self._show_pwd else '👁')

    def _gen_pwd(self):
        pwd = generate_password(length=22, use_special=True)
        self._pwd_var.set(pwd)
        self._pwd2_var.set(pwd)
        self._pwd_entry.configure(show='')
        self._pwd2_entry.configure(show='')
        self._show_pwd = True
        self._eye_btn.configure(text='🙈')

    def _on_pwd_change(self, *_):
        pwd = self._pwd_var.get()
        if not pwd:
            self._bar.set(0)
            self._bar.configure(progress_color=C['error'])
            self._level_lbl.configure(text="", text_color=C['subtext'])
            self._entropy_lbl.configure(text="")
            self._feedback_lbl.configure(text="")
            return

        r = check_strength(pwd)
        self._bar.set(r.score / 100)
        self._bar.configure(progress_color=r.color)
        self._level_lbl.configure(
            text=f"Force : {r.level}  ({r.score}/100)",
            text_color=r.color,
        )
        self._entropy_lbl.configure(text=f"~{r.entropy:.0f} bits d'entropie")
        self._feedback_lbl.configure(
            text='\n'.join(f"• {fb}" for fb in r.feedback[:3])
        )

    def _start_encrypt(self):
        path = self._file_var.get().strip()
        pwd  = self._pwd_var.get()
        pwd2 = self._pwd2_var.get()

        if not path:
            messagebox.showwarning("Champ manquant", "Sélectionnez un fichier ou dossier.")
            return
        if not os.path.exists(path):
            messagebox.showerror("Erreur", "Ce chemin n'existe pas.")
            return
        if not pwd:
            messagebox.showwarning("Champ manquant", "Entrez un mot de passe.")
            return
        if pwd != pwd2:
            messagebox.showerror("Erreur", "Les mots de passe ne correspondent pas.")
            return
        if len(pwd) < 8:
            if not messagebox.askyesno(
                "Avertissement",
                "Mot de passe très court (moins de 8 caractères).\nContinuer quand même ?"
            ):
                return

        self._btn.configure(state='disabled', text="⏳  Chiffrement en cours...")
        self._prog.set(0)
        self._status.configure(text="Dérivation Argon2id en cours… (~2s)", text_color=C['subtext'])

        threading.Thread(target=self._do_encrypt, args=(path, pwd), daemon=True).start()

    def _do_encrypt(self, path, pwd):
        try:
            if self._same_dir_var.get():
                base = os.path.basename(path.rstrip('/\\'))
                out  = os.path.join(os.path.dirname(os.path.abspath(path)), base + '.senc')
            else:
                # filedialog must run on the Tkinter main thread — schedule via after()
                result_q: queue.Queue = queue.Queue()

                def _ask_saveas():
                    p = filedialog.asksaveasfilename(
                        defaultextension='.senc',
                        filetypes=[('Fichier chiffré secure-encrypto', '*.senc')],
                    )
                    result_q.put(p)

                self.after(0, _ask_saveas)
                out = result_q.get()   # blocks worker thread until dialog closes
                if not out:
                    self._reset_btn()
                    return

            def cb(v):
                self.after(0, lambda: self._prog.set(v))
                if v < 0.5:
                    self.after(0, lambda: self._status.configure(text="Dérivation Argon2id…"))
                elif v < 0.9:
                    self.after(0, lambda: self._status.configure(text="Chiffrement AES-256-GCM…"))

            CryptoEngine.encrypt_file(path, out, pwd, cb)

            if self._delete_var.get():
                self._status.configure(text="Suppression sécurisée (3 passes)…")
                secure_delete(path)

            self._prog.set(1.0)
            self._status.configure(
                text=f"✅  Terminé → {os.path.basename(out)}",
                text_color=C['success'],
            )
            messagebox.showinfo("Chiffrement réussi ✅",
                f"Votre fichier a été chiffré avec succès.\n\n"
                f"Algorithme : AES-256-GCM\n"
                f"KDF        : Argon2id (128 MB, 3 passes)\n"
                f"Sortie     : {out}"
            )
        except EncryptionError as e:
            self._status.configure(text=f"❌ {e}", text_color=C['error'])
            messagebox.showerror("Erreur de chiffrement", str(e))
        except Exception as e:
            self._status.configure(text="❌ Erreur inattendue", text_color=C['error'])
            messagebox.showerror("Erreur inattendue", str(e))
        finally:
            self._reset_btn()

    def _reset_btn(self):
        self._btn.configure(state='normal', text="🔒  Chiffrer maintenant")
