"""About view — tool info, security specs, and credits."""

import customtkinter as ctk
from ..theme import C, F

# ─── Repository URL — change this to the actual GitHub URL ───────────────────
REPO_URL = "github.com/secure-encrypto/secure-encrypto"


class AboutView(ctk.CTkScrollableFrame):

    def __init__(self, parent):
        super().__init__(
            parent, fg_color='transparent',
            scrollbar_button_color=C['border'],
            scrollbar_button_hover_color=C['border_light'],
        )
        self._build()

    def _build(self):
        # Hero
        hero = ctk.CTkFrame(
            self, fg_color=C['card'], corner_radius=16,
            border_width=1, border_color=C['border'],
        )
        hero.pack(fill='x', pady=(0, 16))

        ctk.CTkLabel(hero, text="🔐", font=('Segoe UI Emoji', 64)).pack(pady=(28, 0))

        ctk.CTkLabel(
            hero, text="secure-encrypto",
            font=('Segoe UI', 32, 'bold'), text_color=C['text'],
        ).pack()

        ctk.CTkLabel(
            hero, text="v2.0  •  AES-256-GCM  •  Argon2id",
            font=F['body'], text_color=C['accent'],
        ).pack(pady=(4, 0))

        ctk.CTkLabel(
            hero,
            text="Outil de chiffrement de fichiers professionnel\n"
                 "conçu pour résister aux standards de sécurité les plus exigeants.",
            font=F['body'], text_color=C['subtext'],
            justify='center',
        ).pack(pady=(8, 24))

        # Security specs
        self._section("🔬  Spécifications de sécurité", [
            ("Chiffrement",          "AES-256-GCM (AEAD — authentifié + confidentialité)"),
            ("KDF",                  "Argon2id — winner PHC, résistant aux GPU/ASIC"),
            ("Paramètres Argon2id",  "128 MB RAM · 3 itérations · 4 threads parallèles"),
            ("Sel",                  "256 bits aléatoires (CSPRNG) — unique par fichier"),
            ("Nonce",                "96 bits aléatoires — unique par chiffrement"),
            ("Tag d'auth. GCM",      "128 bits — détecte toute altération du ciphertext"),
            ("AAD",                  "Nom du fichier original — intégré à l'authentification"),
            ("Suppression sécurisée","3 passes : 0x00 · 0xFF · aléatoire (DoD 5220.22-M)"),
            ("Comparaison hash",     "hmac.compare_digest — résistant aux timing attacks"),
        ])

        # Features
        self._section("✨  Fonctionnalités", [
            ("Chiffrement fichiers",  "Tout type de fichier — illimité en taille"),
            ("Chiffrement dossiers",  "ZIP + AES-256-GCM en une passe"),
            ("Déchiffrement",         "Vérification d'intégrité automatique"),
            ("Calculateur de hash",   "SHA-256 · SHA-512 · SHA3-256 · SHA3-512"),
            ("Hachage de mots de passe", "Argon2id avec paramètres renforcés"),
            ("Analyse de force",      "Score 0-100 + estimation d'entropie"),
            ("Générateur de mdp",     "20+ caractères, CSPRNG, score ≥80 garanti"),
            ("Scan de sécurité",      "Détection VM, débogueurs, processus suspects"),
        ])

        # Format
        fmt = ctk.CTkFrame(
            self, fg_color=C['card'], corner_radius=12,
            border_width=1, border_color=C['border'],
        )
        fmt.pack(fill='x', pady=(0, 14))
        ctk.CTkLabel(fmt, text="📋  Format de fichier .senc", font=F['heading'],
                     text_color=C['text']).pack(anchor='w', padx=18, pady=(14, 0))
        ctk.CTkFrame(fmt, height=1, fg_color=C['border']).pack(fill='x', padx=18, pady=(10, 0))

        fmt_txt = ctk.CTkTextbox(
            fmt, height=180, font=F['mono_sm'],
            fg_color=C['bg'],
            text_color=C['subtext'], border_width=0,
        )
        fmt_txt.pack(fill='x', padx=18, pady=(0, 14))
        fmt_txt.insert('end',
            "Octets   Contenu\n"
            "──────────────────────────────────────────────────\n"
            "[0:4]    Magic bytes : SENC\n"
            "[4]      Version     : 0x01\n"
            "[5:18]   Argon2id params (mem·time·para·len)\n"
            "[18:50]  Salt        : 32 octets (256-bit)\n"
            "[50:62]  Nonce       : 12 octets (96-bit GCM)\n"
            "[62:64]  Longueur du nom de fichier original\n"
            "[64:N]   Nom du fichier original (UTF-8)\n"
            "[N:]     Ciphertext AES-256-GCM + tag 128-bit\n"
        )
        fmt_txt.configure(state='disabled')

        # GitHub
        gh = ctk.CTkFrame(
            self, fg_color=C['card'], corner_radius=12,
            border_width=1, border_color=C['border'],
        )
        gh.pack(fill='x', pady=(0, 14))
        inner = ctk.CTkFrame(gh, fg_color='transparent')
        inner.pack(fill='x', padx=18, pady=14)

        ctk.CTkLabel(
            inner, text=REPO_URL,
            font=F['mono'], text_color=C['accent'],
        ).pack()
        ctk.CTkLabel(
            inner, text="MIT License — Contributions bienvenues",
            font=F['small'], text_color=C['muted'],
        ).pack(pady=(4, 0))

    def _section(self, title: str, rows: list):
        card = ctk.CTkFrame(
            self, fg_color=C['card'], corner_radius=12,
            border_width=1, border_color=C['border'],
        )
        card.pack(fill='x', pady=(0, 14))
        ctk.CTkLabel(card, text=title, font=F['heading'], text_color=C['text']).pack(
            anchor='w', padx=18, pady=(14, 0))
        ctk.CTkFrame(card, height=1, fg_color=C['border']).pack(fill='x', padx=18, pady=(10, 0))

        for key, val in rows:
            row = ctk.CTkFrame(card, fg_color='transparent')
            row.pack(fill='x', padx=18, pady=3)
            ctk.CTkLabel(
                row, text=key,
                font=('Segoe UI', 12, 'bold'),
                text_color=C['text'], width=200, anchor='w',
            ).pack(side='left')
            ctk.CTkLabel(
                row, text=val,
                font=F['small'], text_color=C['subtext'], anchor='w',
                wraplength=400,
            ).pack(side='left', padx=(8, 0))

        ctk.CTkFrame(card, height=1, fg_color='transparent').pack(pady=(4, 0))
