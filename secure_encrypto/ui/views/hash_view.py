"""Hash view — file checksums and password hashing."""

import os
import hashlib
import threading
from tkinter import filedialog, messagebox
import customtkinter as ctk

from ..theme import C, F

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
    _HAS_ARGON2 = True
except ImportError:
    _HAS_ARGON2 = False


def _card(parent, title="", pady_inner=(0, 14)):
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


def _hash_file(path: str, algorithm: str) -> str:
    h = hashlib.new(algorithm)
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


class HashView(ctk.CTkScrollableFrame):

    def __init__(self, parent):
        super().__init__(
            parent, fg_color='transparent',
            scrollbar_button_color=C['border'],
            scrollbar_button_hover_color=C['border_light'],
        )
        self._build()

    def _build(self):
        hdr = ctk.CTkFrame(self, fg_color='transparent')
        hdr.pack(fill='x', pady=(0, 18))
        ctk.CTkLabel(hdr, text="#️⃣  Hachage", font=F['display'], text_color=C['text']).pack(side='left')
        ctk.CTkLabel(hdr, text="SHA-256 / SHA-512 / Argon2id", font=F['small'],
                     text_color=C['accent']).pack(side='right', anchor='s', pady=6)

        self._build_file_hasher()
        self._build_argon2_section()
        self._build_compare_section()

    def _build_file_hasher(self):
        fc = _card(self, "📄  Calcul d'empreinte de fichier")

        row = ctk.CTkFrame(fc, fg_color='transparent')
        row.pack(fill='x', pady=(8, 0))

        self._fhash_var = ctk.StringVar()
        ctk.CTkEntry(
            row, textvariable=self._fhash_var,
            placeholder_text="Sélectionnez un fichier…",
            height=42, font=F['body'],
            fg_color=C['bg'], border_color=C['border'], text_color=C['text'],
        ).pack(side='left', fill='x', expand=True, padx=(0, 10))

        ctk.CTkButton(
            row, text="📂  Fichier", width=110, height=42, font=F['body'],
            fg_color=C['hover'], hover_color=C['border'],
            command=self._pick_hash_file, corner_radius=8,
        ).pack(side='left')

        alg_row = ctk.CTkFrame(fc, fg_color='transparent')
        alg_row.pack(fill='x', pady=(10, 0))

        ctk.CTkLabel(alg_row, text="Algorithme :", font=F['body'], text_color=C['subtext']).pack(
            side='left', padx=(0, 10))

        self._alg_var = ctk.StringVar(value='sha256')
        for alg, label in [('sha256', 'SHA-256'), ('sha512', 'SHA-512'),
                            ('sha3_256', 'SHA3-256'), ('sha3_512', 'SHA3-512'), ('md5', 'MD5 ⚠')]:
            ctk.CTkRadioButton(
                alg_row, text=label, value=alg, variable=self._alg_var,
                font=F['small'], text_color=C['text'],
                fg_color=C['accent'], hover_color=C['accent_hover'],
            ).pack(side='left', padx=8)

        ctk.CTkButton(
            fc, text="⚡  Calculer l'empreinte",
            height=40, font=F['body'],
            fg_color=C['accent'], hover_color=C['accent_hover'],
            corner_radius=8, command=self._calc_hash,
        ).pack(fill='x', pady=(12, 0))

        self._hash_results = ctk.CTkTextbox(
            fc, height=120, font=F['mono'],
            fg_color=C['bg'], border_color=C['border'],
            text_color=C['text'], border_width=1,
        )
        self._hash_results.pack(fill='x', pady=(10, 0))
        self._hash_results.insert('end', "Les empreintes s'affichent ici…\n")
        self._hash_results.configure(state='disabled')

    def _pick_hash_file(self):
        p = filedialog.askopenfilename(title="Sélectionner un fichier")
        if p:
            self._fhash_var.set(p)

    def _calc_hash(self):
        path = self._fhash_var.get().strip()
        if not path:
            messagebox.showwarning("Champ manquant", "Sélectionnez un fichier.")
            return
        if not os.path.isfile(path):
            messagebox.showerror("Erreur", "Fichier introuvable.")
            return

        alg = self._alg_var.get()
        self._hash_results.configure(state='normal')
        self._hash_results.delete('1.0', 'end')
        self._hash_results.insert('end', "Calcul en cours…\n")
        self._hash_results.configure(state='disabled')

        def run():
            try:
                size = os.path.getsize(path)
                digest = _hash_file(path, alg)
                def update_success():
                    self._hash_results.configure(state='normal')
                    self._hash_results.delete('1.0', 'end')
                    self._hash_results.insert('end',
                        f"Fichier    : {os.path.basename(path)}\n"
                        f"Taille     : {size:,} octets\n"
                        f"Algorithme : {alg.upper()}\n"
                        f"Empreinte  :\n{digest}\n"
                    )
                    if alg == 'md5':
                        self._hash_results.insert('end',
                            "\n⚠  MD5 est cryptographiquement cassé — utilisez SHA-256 ou plus.\n")
                    self._hash_results.configure(state='disabled')

                self.after(0, update_success)
            except Exception as e:
                def update_error():
                    self._hash_results.configure(state='normal')
                    self._hash_results.delete('1.0', 'end')
                    self._hash_results.insert('end', f"Erreur : {e}\n")
                    self._hash_results.configure(state='disabled')

                self.after(0, update_error)

        threading.Thread(target=run, daemon=True).start()

    def _build_argon2_section(self):
        ac = _card(self, "🔐  Hachage de mot de passe (Argon2id)")

        if not _HAS_ARGON2:
            ctk.CTkLabel(
                ac, text="⚠  argon2-cffi non installé. Lancez : pip install argon2-cffi",
                font=F['body'], text_color=C['warning'],
            ).pack(pady=8)
            return

        row = ctk.CTkFrame(ac, fg_color='transparent')
        row.pack(fill='x', pady=(8, 0))

        self._a2_pwd_var = ctk.StringVar()
        ctk.CTkEntry(
            row, textvariable=self._a2_pwd_var, show='•',
            placeholder_text="Mot de passe à hacher…",
            height=42, font=F['body'],
            fg_color=C['bg'], border_color=C['border'], text_color=C['text'],
        ).pack(side='left', fill='x', expand=True, padx=(0, 10))

        ctk.CTkButton(
            row, text="🔐  Hacher", width=110, height=42, font=F['body'],
            fg_color=C['accent'], hover_color=C['accent_hover'],
            command=self._argon2_hash, corner_radius=8,
        ).pack(side='left')

        self._a2_result = ctk.CTkTextbox(
            ac, height=80, font=F['mono_sm'],
            fg_color=C['bg'], border_color=C['border'],
            text_color=C['text'], border_width=1, wrap='none',
        )
        self._a2_result.pack(fill='x', pady=(10, 0))
        self._a2_result.insert('end', "Le hash Argon2id s'affichera ici…\n")
        self._a2_result.configure(state='disabled')

        ctk.CTkLabel(ac, text="Vérifier un hash existant :", font=F['small'],
                     text_color=C['subtext']).pack(anchor='w', pady=(14, 4))

        self._a2_hash_var = ctk.StringVar()
        ctk.CTkEntry(
            ac, textvariable=self._a2_hash_var,
            placeholder_text="Collez un hash Argon2 ici…",
            height=42, font=F['mono_sm'],
            fg_color=C['bg'], border_color=C['border'], text_color=C['text'],
        ).pack(fill='x', pady=(0, 8))

        ctk.CTkButton(
            ac, text="✅  Vérifier",
            height=40, font=F['body'],
            fg_color=C['hover'], hover_color=C['border'],
            corner_radius=8, command=self._argon2_verify,
        ).pack(fill='x')

        self._a2_verify_lbl = ctk.CTkLabel(ac, text="", font=F['body'], text_color=C['subtext'])
        self._a2_verify_lbl.pack(pady=(6, 0))

    def _argon2_hash(self):
        pwd = self._a2_pwd_var.get()
        if not pwd:
            messagebox.showwarning("Champ manquant", "Entrez un mot de passe.")
            return
        ph = PasswordHasher(time_cost=3, memory_cost=131072, parallelism=4)
        self._a2_result.configure(state='normal')
        self._a2_result.delete('1.0', 'end')
        self._a2_result.insert('end', "Calcul en cours…\n")
        self._a2_result.configure(state='disabled')

        def run():
            h = ph.hash(pwd)

            def update_ui():
                self._a2_result.configure(state='normal')
                self._a2_result.delete('1.0', 'end')
                self._a2_result.insert('end', h + "\n")
                self._a2_result.configure(state='disabled')

            self.after(0, update_ui)
        threading.Thread(target=run, daemon=True).start()

    def _argon2_verify(self):
        pwd = self._a2_pwd_var.get()
        h   = self._a2_hash_var.get().strip()
        if not pwd or not h:
            messagebox.showwarning("Champs manquants", "Remplissez le mot de passe et le hash.")
            return
        ph = PasswordHasher()
        try:
            ph.verify(h, pwd)
            self._a2_verify_lbl.configure(
                text="✅  Hash correspondant — mot de passe correct !", text_color=C['success'])
        except VerifyMismatchError:
            self._a2_verify_lbl.configure(text="❌  Hash ne correspond pas.", text_color=C['error'])
        except (VerificationError, InvalidHashError) as e:
            self._a2_verify_lbl.configure(text=f"⚠  Hash invalide : {e}", text_color=C['warning'])

    def _build_compare_section(self):
        cc = _card(self, "🔍  Comparaison de hashes (temps constant)")

        ctk.CTkLabel(
            cc,
            text="Compare deux hashes en temps constant pour éviter les attaques par timing.",
            font=F['tiny'], text_color=C['subtext'], wraplength=600, justify='left',
        ).pack(anchor='w', pady=(6, 10))

        self._cmp1_var = ctk.StringVar()
        ctk.CTkEntry(
            cc, textvariable=self._cmp1_var, placeholder_text="Hash A…",
            height=42, font=F['mono_sm'],
            fg_color=C['bg'], border_color=C['border'], text_color=C['text'],
        ).pack(fill='x', pady=(0, 6))

        self._cmp2_var = ctk.StringVar()
        ctk.CTkEntry(
            cc, textvariable=self._cmp2_var, placeholder_text="Hash B…",
            height=42, font=F['mono_sm'],
            fg_color=C['bg'], border_color=C['border'], text_color=C['text'],
        ).pack(fill='x', pady=(0, 10))

        ctk.CTkButton(
            cc, text="🔍  Comparer",
            height=40, font=F['body'],
            fg_color=C['hover'], hover_color=C['border'],
            corner_radius=8, command=self._compare,
        ).pack(fill='x')

        self._cmp_lbl = ctk.CTkLabel(cc, text="", font=F['body'], text_color=C['subtext'])
        self._cmp_lbl.pack(pady=(8, 0))

    def _compare(self):
        import hmac
        a = self._cmp1_var.get().strip().encode()
        b = self._cmp2_var.get().strip().encode()
        if not a or not b:
            messagebox.showwarning("Champs manquants", "Remplissez les deux hashes.")
            return
        if hmac.compare_digest(a, b):
            self._cmp_lbl.configure(
                text="✅  Identiques (comparaison en temps constant)", text_color=C['success'])
        else:
            self._cmp_lbl.configure(text="❌  Différents", text_color=C['error'])
