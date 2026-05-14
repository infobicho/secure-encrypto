"""
Analyseur d'environnement de sécurité.
Détecte les débogueurs, les machines virtuelles et les processus suspects.
"""

import platform
import os
import sys
from typing import Dict, List, Any

try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False

# Noms des débogueurs et outils d'analyse connus
DEBUGGER_NAMES = {
    'gdb', 'lldb', 'x64dbg', 'x32dbg', 'windbg', 'ollydbg',
    'ida', 'ida64', 'idapro', 'radare2', 'r2', 'cutter',
    'ghidra', 'frida', 'frida-server', 'strace', 'ltrace',
    'dnspy', 'de4dot', 'wireshark', 'fiddler', 'charles',
}

# Indicateurs de VM / hyperviseur dans la chaîne de plateforme
VM_STRINGS = {
    'virtualbox': 'VirtualBox',
    'vmware':     'VMware',
    'qemu':       'QEMU',
    'hyperv':     'Hyper-V',
    'xen':        'Xen',
    'parallels':  'Parallels',
    'vbox':       'VirtualBox',
    'bochs':      'Bochs',
}

# Variables d'environnement spécifiques aux VM
VM_ENV_VARS = {
    'VBOX_MSI_INSTALL_PATH': 'VirtualBox',
    'VBOX_VERSION':          'VirtualBox',
    'VMWARE_HOME':           'VMware',
    'VMWARE_USER_TMP':       'VMware',
}


def scan_environment() -> Dict[str, Any]:
    """
    Analyse l'environnement d'exécution pour détecter des problèmes de sécurité.
    Retourne un dictionnaire de rapport structuré.
    """
    report: Dict[str, Any] = {
        'status':               'clean',
        'suspicious_processes': [],
        'vm_detected':          False,
        'vm_indicators':        [],
        'os_info':              platform.platform(),
        'os_name':              platform.system(),
        'os_version':           platform.version(),
        'arch':                 platform.machine(),
        'python_version':       platform.python_version(),
        'python_impl':          platform.python_implementation(),
        'hostname':             platform.node(),
        'cpu_count':            os.cpu_count() or 0,
        'warnings':             [],
    }

    # ── Vérification des débogueurs dans les processus en cours ──────────
    if _HAS_PSUTIL:
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'status']):
                try:
                    name = (proc.info.get('name') or '').lower().replace('.exe', '')
                    if name in DEBUGGER_NAMES:
                        report['suspicious_processes'].append({
                            'name': proc.info.get('name', name),
                            'pid':  proc.info.get('pid', -1),
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass

    # ── Détection des machines virtuelles ────────────────────────────────
    system_lower = platform.platform().lower()
    for keyword, label in VM_STRINGS.items():
        if keyword in system_lower:
            report['vm_detected'] = True
            if label not in report['vm_indicators']:
                report['vm_indicators'].append(label)

    for var, label in VM_ENV_VARS.items():
        if os.environ.get(var):
            report['vm_detected'] = True
            if label not in report['vm_indicators']:
                report['vm_indicators'].append(f"{label} (env)")

    # ── Un faible nombre de CPU peut indiquer une VM ────────────────────
    if report['cpu_count'] == 1:
        report['warnings'].append(
            "Seul 1 cœur CPU détecté — environnement virtualisé probable."
        )

    # ── Vérification des flags de débogage Python ────────────────────────
    if sys.flags.debug:
        report['warnings'].append("Python démarré avec le flag -d (mode débogage actif).")
    if sys.flags.optimize == 0 and os.environ.get('PYTHONOPTIMIZE'):
        report['warnings'].append("Variable PYTHONOPTIMIZE non définie — assertions actives.")

    # ── Statut final ─────────────────────────────────────────────────────
    if report['suspicious_processes'] or report['vm_detected']:
        report['status'] = 'suspicious'
    elif report['warnings']:
        report['status'] = 'warning'

    return report
