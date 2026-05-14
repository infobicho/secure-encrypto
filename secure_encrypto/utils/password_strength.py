"""
Password strength analysis with entropy estimation and actionable feedback.
"""

import re
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import FrozenSet, List

# ─── Constants ───────────────────────────────────────────────────────────────

# Chemin vers le fichier de mots de passe courants (chargé une seule fois)
_DATA_DIR = Path(__file__).parent.parent.parent / "data"
_COMMON_PASSWORDS_FILE = _DATA_DIR / "common_passwords.txt"

# Cache — chargé au premier appel, jamais rechargé
_COMMON_PASSWORDS_CACHE: FrozenSet[str] | None = None


def _load_common_passwords() -> FrozenSet[str]:
    """
    Charge la liste des mots de passe courants depuis data/common_passwords.txt.
    Si le fichier est absent, retourne le jeu de secours intégré au code.
    Chargé une seule fois, mis en cache pour toute la session.
    """
    global _COMMON_PASSWORDS_CACHE
    if _COMMON_PASSWORDS_CACHE is not None:
        return _COMMON_PASSWORDS_CACHE

    if _COMMON_PASSWORDS_FILE.exists():
        try:
            lines = _COMMON_PASSWORDS_FILE.read_text(encoding="utf-8").splitlines()
            _COMMON_PASSWORDS_CACHE = frozenset(line.strip().lower() for line in lines if line.strip())
            return _COMMON_PASSWORDS_CACHE
        except OSError:
            pass

    # Jeu de secours si le fichier est inaccessible
    _COMMON_PASSWORDS_CACHE = frozenset(_COMMON_PASSWORDS_FALLBACK)
    return _COMMON_PASSWORDS_CACHE


# Jeu de secours intégré (~350 mots) utilisé uniquement si data/ est absent
_COMMON_PASSWORDS_FALLBACK = {
    # Numeric sequences
    '123456', '1234567', '12345678', '123456789', '1234567890',
    '12345', '1234', '123', '111111', '000000', '123123', '121212',
    '112233', '123321', '654321', '1q2w3e', '1q2w3e4r', '1q2w3e4r5t',
    '123qwe', '1234qwer', '1234abcd', '12341234', '11111111', '00000000',
    '123456a', 'a123456', '123456789a', '1234567a', 'abc12345',
    '123456789q', '147258369', '147258', '159357', '123654', '321654',
    '789456123', '741852963', '123456!', '123456abc',
    # Common words
    'password', 'password1', 'password123', 'password!', 'passw0rd',
    'p@ssword', 'p@ssw0rd', 'pa$$word', 'pass', 'passwd',
    'admin', 'admin123', 'administrator', 'root', 'toor', 'guest',
    'user', 'login', 'master', 'superuser', 'access', 'changeme',
    'welcome', 'welcome1', 'welcome123', 'letmein', 'login123',
    'iloveyou', 'monkey', 'dragon', 'sunshine', 'princess', 'shadow',
    'superman', 'batman', 'spiderman', 'pokemon', 'naruto', 'dragon',
    'michael', 'jessica', 'ashley', 'bailey', 'charlie', 'donald',
    'football', 'baseball', 'soccer', 'hockey', 'basketball', 'tennis',
    'mustang', 'corvette', 'ferrari', 'porsche', 'harley', 'yamaha',
    'starwars', 'matrix', 'avatar', 'minecraft', 'fortnite', 'roblox',
    'qwerty', 'qwerty123', 'qwertyuiop', 'qazwsx', '1qaz2wsx', 'zxcvbnm',
    'abc123', 'abcdef', 'abcd1234', 'aaaaaa', 'aaaaaaa', 'aaaaaaaa',
    'hello', 'hello123', 'trustno1', 'secret', 'secret123', 'hunter2',
    'default', 'test', 'test123', 'sample', 'example', 'demo',
    'temp', 'temporary', 'pass123', 'pass@123', 'pass1234',
    'flower', 'babygirl', 'lovely', 'love', 'angel', 'buster',
    'thomas', 'andrew', 'robert', 'daniel', 'george', 'jordan',
    'harley', 'ranger', 'dakota', 'cookie', 'cheese', 'butter',
    'computer', 'internet', 'windows', 'office', 'outlook', 'google',
    'amazon', 'facebook', 'twitter', 'instagram', 'youtube', 'netflix',
    'apple', 'samsung', 'nokia', 'huawei', 'xiaomi', 'lenovo',
    # Date-based patterns
    '2020', '2021', '2022', '2023', '2024', '2025',
    'january', 'february', 'march', 'april', 'summer', 'winter',
    # French common passwords
    'motdepasse', 'soleil', 'bonjour', 'azerty', 'azerty123',
    'azertyuiop', '1azerty', 'azerty1', 'marseille', 'paris',
    'football', 'toulouse', 'bordeaux', 'lyon', 'france', 'france23',
    'nicolas', 'thomas', 'alexis', 'julien', 'matthieu', 'maxime',
    'sophie', 'camille', 'alice', 'amelie', 'emma', 'lea',
    # Special char variations of common words
    'p@ssword1', 'p@$$w0rd', 'passw0rd!', 'Password1', 'Password1!',
    'Admin123!', 'Welcome1!', 'Passw0rd!', 'P@ssw0rd', 'P@ssword1',
}


SEQUENTIAL_PATTERNS = [
    '0123456789', 'abcdefghijklmnopqrstuvwxyz',
    'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
    'qwerty', 'azerty',
]

# Tailles des jeux de caractères pour l'estimation de l'entropie
CHARSET_SIZES = {
    'lower':   26,
    'upper':   26,
    'digit':   10,
    'special': 32,
}


# ─── Type de résultat ─────────────────────────────────────────────────────────

@dataclass
class StrengthResult:
    score:    int          # 0–100
    level:    str          # Niveau lisible par l'utilisateur
    color:    str          # Couleur hexadécimale pour l'interface
    entropy:  float        # Bits d'entropie estimés
    feedback: List[str] = field(default_factory=list)


# ─── Analyse principale ───────────────────────────────────────────────────────

def check_strength(password: str) -> StrengthResult:
    """
    Analyse la force d'un mot de passe.
    Returns a StrengthResult with score (0-100), level, color, and feedback.
    """
    if not password:
        return StrengthResult(0, "Vide", "#f85149", 0.0, ["Entrez un mot de passe"])

    score    = 0
    feedback = []

    has_lower   = bool(re.search(r'[a-z]', password))
    has_upper   = bool(re.search(r'[A-Z]', password))
    has_digit   = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
    length      = len(password)

    # ── Score longueur (0-35 pts) ────────────────────────────────────────
    if length >= 24:   score += 35
    elif length >= 20: score += 30
    elif length >= 16: score += 25
    elif length >= 12: score += 20
    elif length >= 8:  score += 12
    else:
        score += length
        feedback.append(f"Trop court — utilisez au moins 12 caractères ({length} actuels)")

    # ── Diversité des caractères (0-40 pts) ──────────────────────────────
    variety = sum([has_lower, has_upper, has_digit, has_special])
    # Diversity bonus scaled by password length
    diversity_bonus = variety * 10
    if length < 4:
        diversity_bonus = min(diversity_bonus, 5)
    elif length < 8:
        diversity_bonus = min(diversity_bonus, 15)

    score += diversity_bonus

    if not has_upper:
        feedback.append("Ajoutez des majuscules (A-Z)")
    if not has_lower:
        feedback.append("Ajoutez des minuscules (a-z)")
    if not has_digit:
        feedback.append("Ajoutez des chiffres (0-9)")
    if not has_special:
        feedback.append("Ajoutez des caractères spéciaux (!@#$%...)")

    # ── Caractères uniques (0-10 pts) ────────────────────────────────────
    unique_ratio = len(set(password)) / length
    score += int(unique_ratio * 10)

    # ── Pénalité mot de passe courant ────────────────────────────────────
    if password.lower() in _load_common_passwords():
        score = max(0, score - 50)
        feedback.insert(0, "⚠️  Mot de passe très commun — changez-le immédiatement !")

    # ── Pénalité caractères répétés ──────────────────────────────────────
    if re.search(r'(.)\1{2,}', password):
        score = max(0, score - 10)
        feedback.append("Évitez les caractères consécutifs répétés (aaa, 111...)")

    # ── Pénalité séquences prévisibles ───────────────────────────────────
    pwd_lower = password.lower()
    for seq in SEQUENTIAL_PATTERNS:
        for start in range(len(seq) - 2):
            chunk = seq[start:start + 3]
            if chunk in pwd_lower or chunk[::-1] in pwd_lower:
                score = max(0, score - 8)
                feedback.append("Évitez les séquences prévisibles (abc, 123, qwerty...)")
                break

    # ── Estimation d'entropie ────────────────────────────────────────────
    charset_size = 0
    if has_lower:   charset_size += CHARSET_SIZES['lower']
    if has_upper:   charset_size += CHARSET_SIZES['upper']
    if has_digit:   charset_size += CHARSET_SIZES['digit']
    if has_special: charset_size += CHARSET_SIZES['special']
    if charset_size == 0: charset_size = 26

    entropy = length * math.log2(charset_size)

    # ── Normalisation et clamp ───────────────────────────────────────────
    score = min(100, max(0, score))

    # ── Niveau et couleur ────────────────────────────────────────────────
    if score >= 80:
        level, color = "Très fort 🛡️",  "#3fb950"
    elif score >= 60:
        level, color = "Fort ✅",        "#8bc34a"
    elif score >= 40:
        level, color = "Moyen ⚠️",       "#d29922"
    elif score >= 20:
        level, color = "Faible 🔶",      "#ff9800"
    else:
        level, color = "Très faible 🔴", "#f85149"

    if not feedback and score >= 80:
        feedback.append(f"✅  Excellent ! Entropie estimée : {entropy:.0f} bits")
    elif score >= 60 and not any('⚠️' in f or 'Évitez' in f for f in feedback):
        feedback.append(f"Entropie estimée : {entropy:.0f} bits")

    # Dédoublonnage des suggestions
    seen = set()
    unique_feedback = []
    for f in feedback:
        if f not in seen:
            seen.add(f)
            unique_feedback.append(f)

    return StrengthResult(
        score=score,
        level=level,
        color=color,
        entropy=entropy,
        feedback=unique_feedback,
    )


def generate_password(length: int = 20, use_special: bool = True) -> str:
    """
    Génère un mot de passe aléatoire cryptographiquement sûr.
    Utilise le module secrets (CSPRNG du système d'exploitation).
    """
    import secrets
    import string

    alphabet = string.ascii_letters + string.digits
    if use_special:
        # Caractères spéciaux sélectionnés — sans ambiguïté shell
        alphabet += "!@#$%^&*()-_=+[]{}|;:,.<>?"

    while True:
        pwd = ''.join(secrets.choice(alphabet) for _ in range(length))
        # Garantit la présence d'au moins un caractère de chaque type requis
        result = check_strength(pwd)
        if result.score >= 80:
            return pwd


# Public constant for tests and external access
COMMON_PASSWORDS = _load_common_passwords()
