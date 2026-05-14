"""Security view — environment scanner and security audit."""

import threading
import customtkinter as ctk

from ..theme import C, F
from ...core.environment import scan_environment


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


class SecurityView(ctk.CTkScrollableFrame):

    def __init__(self, parent):
        super().__init__(
            parent, fg_color='transparent',
            scrollbar_button_color=C['border'],
            scrollbar_button_hover_color=C['border_light'],
        )
        self._report = None
        self._build()
        # Auto-scan on open
        threading.Thread(target=self._do_scan, daemon=True).start()

    def _build(self):
        # Header
        hdr = ctk.CTkFrame(self, fg_color='transparent')
        hdr.pack(fill='x', pady=(0, 18))
        ctk.CTkLabel(hdr, text="🛡  Sécurité", font=F['display'], text_color=C['text']).pack(side='left')
        ctk.CTkLabel(hdr, text="Audit de l'environnement", font=F['small'], text_color=C['accent']).pack(
            side='right', anchor='s', pady=6)

        # Status banner
        self._banner = ctk.CTkFrame(
            self, fg_color=C['card'], corner_radius=12,
            border_width=2, border_color=C['border'],
        )
        self._banner.pack(fill='x', pady=(0, 14))

        banner_inner = ctk.CTkFrame(self._banner, fg_color='transparent')
        banner_inner.pack(fill='x', padx=20, pady=18)

        self._status_icon = ctk.CTkLabel(
            banner_inner, text="⏳", font=('Segoe UI Emoji', 36),
        )
        self._status_icon.pack(side='left', padx=(0, 16))

        txt_col = ctk.CTkFrame(banner_inner, fg_color='transparent')
        txt_col.pack(side='left', fill='x', expand=True)

        self._status_title = ctk.CTkLabel(
            txt_col, text="Analyse en cours…",
            font=F['title'], text_color=C['text'], anchor='w',
        )
        self._status_title.pack(anchor='w')

        self._status_sub = ctk.CTkLabel(
            txt_col, text="Scan des processus et de l'environnement…",
            font=F['small'], text_color=C['subtext'], anchor='w',
        )
        self._status_sub.pack(anchor='w', pady=(4, 0))

        # Scan button
        btn_frame = _card(self, "", pady_inner=(10, 10))
        self._scan_btn = ctk.CTkButton(
            btn_frame, text="🔄  Relancer l'analyse",
            height=44, font=F['body'],
            fg_color=C['hover'], hover_color=C['border'],
            corner_radius=8,
            command=self._start_scan,
        )
        self._scan_btn.pack(fill='x')

        # System info card
        self._sys_card = _card(self, "💻  Informations système")
        self._sys_box = ctk.CTkTextbox(
            self._sys_card, height=160, font=F['mono_sm'],
            fg_color=C['bg'], border_color=C['border'], border_width=1,
            text_color=C['subtext'],
        )
        self._sys_box.pack(fill='x', pady=(8, 0))
        self._sys_box.insert('end', "Scan en cours…\n")
        self._sys_box.configure(state='disabled')

        # Processes card
        self._proc_card = _card(self, "🔍  Processus suspects")
        self._proc_box = ctk.CTkTextbox(
            self._proc_card, height=100, font=F['mono_sm'],
            fg_color=C['bg'], border_color=C['border'], border_width=1,
            text_color=C['subtext'],
        )
        self._proc_box.pack(fill='x', pady=(8, 0))
        self._proc_box.insert('end', "Scan en cours…\n")
        self._proc_box.configure(state='disabled')

        # Best practices
        bp = _card(self, "📋  Bonnes pratiques de sécurité")
        practices = [
            ("🔐", "Utilisez toujours un mot de passe de 20+ caractères avec majuscules, chiffres et symboles."),
            ("💾", "Conservez votre mot de passe dans un gestionnaire (Bitwarden, KeePassXC)."),
            ("🗑", "Activez la suppression sécurisée (3 passes) pour les fichiers sensibles."),
            ("🔄", "Ne réutilisez jamais le même mot de passe sur plusieurs fichiers."),
            ("📵", "Ne déchiffrez jamais sur un PC partagé ou en Wi-Fi public non sécurisé."),
            ("💡", "Pour une sécurité maximale : activez le chiffrement complet du disque (BitLocker / LUKS)."),
        ]
        for icon, text in practices:
            row = ctk.CTkFrame(bp, fg_color='transparent')
            row.pack(fill='x', pady=3)
            ctk.CTkLabel(row, text=icon, font=('Segoe UI Emoji', 18), width=30).pack(side='left')
            ctk.CTkLabel(
                row, text=text, font=F['small'], text_color=C['subtext'],
                anchor='w', wraplength=560, justify='left',
            ).pack(side='left', padx=(10, 0))

    def _start_scan(self):
        self._scan_btn.configure(state='disabled', text="⏳  Analyse…")
        self._status_title.configure(text="Analyse en cours…")
        self._status_sub.configure(text="Scan des processus et de l'environnement…")
        self._status_icon.configure(text="⏳")
        threading.Thread(target=self._do_scan, daemon=True).start()

    def _do_scan(self):
        report = scan_environment()
        self._report = report
        self._apply_report(report)

    def _apply_report(self, r: dict):
        # Banner
        status = r.get('status', 'clean')
        if status == 'clean':
            icon, title, sub, border = "✅", "Environnement sûr", "Aucun processus suspect détecté.", C['success']
        elif status == 'warning':
            icon, title, sub, border = "⚠️", "Avertissements détectés", "Vérifiez les détails ci-dessous.", C['warning']
        else:
            icon, title, sub, border = "🚨", "Environnement suspect !", "Des risques de sécurité ont été détectés.", C['error']

        self._status_icon.configure(text=icon)
        self._status_title.configure(text=title, text_color=border)
        self._status_sub.configure(text=sub)
        self._banner.configure(border_color=border)

        # System info
        self._sys_box.configure(state='normal')
        self._sys_box.delete('1.0', 'end')
        self._sys_box.insert('end',
            f"Système         : {r.get('os_info', 'N/A')}\n"
            f"Nom du PC       : {r.get('hostname', 'N/A')}\n"
            f"Architecture    : {r.get('arch', 'N/A')}\n"
            f"CPUs logiques   : {r.get('cpu_count', 'N/A')}\n"
            f"Python          : {r.get('python_version', 'N/A')} "
            f"({r.get('python_impl', 'N/A')})\n"
        )

        warnings = r.get('warnings', [])
        vm_indicators = r.get('vm_indicators', [])
        if vm_indicators:
            self._sys_box.insert('end', f"\n⚠  VM détectée : {', '.join(vm_indicators)}\n")
        for w in warnings:
            self._sys_box.insert('end', f"⚠  {w}\n")
        self._sys_box.configure(state='disabled')

        # Processes
        procs = r.get('suspicious_processes', [])
        self._proc_box.configure(state='normal')
        self._proc_box.delete('1.0', 'end')
        if procs:
            for p in procs:
                self._proc_box.insert('end', f"🚨  {p['name']}  (PID {p['pid']})\n")
        else:
            self._proc_box.insert('end', "✅  Aucun processus suspect détecté.\n")
        self._proc_box.configure(state='disabled')

        self._scan_btn.configure(state='normal', text="🔄  Relancer l'analyse")
