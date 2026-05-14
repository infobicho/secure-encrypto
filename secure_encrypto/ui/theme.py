"""
secure-encrypto UI Theme
GitHub Dark + Cybersecurity aesthetic.
"""

import platform as _platform

# ─── Cross-platform font selection ────────────────────────────────────────────

_SYS = _platform.system()

if _SYS == 'Windows':
    _UI   = 'Segoe UI'
    _MONO = 'Consolas'
elif _SYS == 'Darwin':
    _UI   = 'SF Pro Text'
    _MONO = 'Menlo'
else:                      # Linux and other POSIX
    _UI   = 'Ubuntu'
    _MONO = 'DejaVu Sans Mono'

# ─── Colour palette ───────────────────────────────────────────────────────────

C = {
    # Backgrounds
    'bg':            '#0d1117',
    'sidebar':       '#10161f',
    'card':          '#161b22',
    'card_alt':      '#1c2128',
    'hover':         '#21262d',

    # Borders
    'border':        '#30363d',
    'border_light':  '#3d444d',

    # Accents
    'accent':        '#1f6feb',
    'accent_hover':  '#388bfd',
    'accent_muted':  '#1a4480',

    # Status
    'success':       '#3fb950',
    'success_muted': '#1a3a22',
    'warning':       '#d29922',
    'warning_muted': '#3a2d0a',
    'error':         '#f85149',
    'error_muted':   '#3a1210',

    # Text
    'text':          '#e6edf3',
    'subtext':       '#8b949e',
    'muted':         '#6e7681',

    # Strength meter colours
    'str_0':         '#f85149',   # Very weak
    'str_1':         '#ff9800',   # Weak
    'str_2':         '#d29922',   # Fair
    'str_3':         '#8bc34a',   # Strong
    'str_4':         '#3fb950',   # Very strong
}

# ─── Font tuples ──────────────────────────────────────────────────────────────

F = {
    'display':  (_UI, 24, 'bold'),
    'title':    (_UI, 18, 'bold'),
    'heading':  (_UI, 14, 'bold'),
    'body':     (_UI, 13),
    'small':    (_UI, 11),
    'tiny':     (_UI, 10),
    'mono':     (_MONO, 12),
    'mono_sm':  (_MONO, 11),
}
