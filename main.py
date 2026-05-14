#!/usr/bin/env python3
"""
secure-encrypto — Entry point

GUI mode  :  python main.py
CLI mode  :  python main.py encrypt <fichier> [-o sortie.senc] [--delete]
             python main.py decrypt <fichier.senc> [-o dossier]
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _run_cli(argv: list) -> int:
    import argparse
    import getpass

    from secure_encrypto.core.engine import CryptoEngine, EncryptionError, DecryptionError
    from secure_encrypto.core.secure_wipe import secure_delete

    parser = argparse.ArgumentParser(
        prog='secure-encrypto',
        description='Chiffrement de fichiers AES-256-GCM + Argon2id',
    )
    sub = parser.add_subparsers(dest='cmd', metavar='<commande>')

    # ── encrypt ──────────────────────────────────────────────────────────────
    enc = sub.add_parser('encrypt', help='Chiffrer un fichier ou dossier')
    enc.add_argument('input',  help='Fichier ou dossier à chiffrer')
    enc.add_argument('-o', '--output', default=None,
                     help='Fichier de sortie .senc (défaut : <input>.senc)')
    enc.add_argument('-p', '--password', default=None,
                     help='Mot de passe (si absent, saisi de façon sécurisée)')
    enc.add_argument('--delete', action='store_true',
                     help='Suppression sécurisée (3 passes) du fichier original après chiffrement')

    # ── decrypt ──────────────────────────────────────────────────────────────
    dec = sub.add_parser('decrypt', help='Déchiffrer un fichier .senc')
    dec.add_argument('input',  help='Fichier .senc à déchiffrer')
    dec.add_argument('-o', '--output', default=None,
                     help='Dossier de sortie (défaut : même dossier que le .senc)')
    dec.add_argument('-p', '--password', default=None,
                     help='Mot de passe (si absent, saisi de façon sécurisée)')

    args = parser.parse_args(argv)

    if args.cmd is None:
        parser.print_help()
        return 1

    # ── resolve password ──────────────────────────────────────────────────────
    try:
            pwd = args.password or getpass.getpass('Mot de passe : ')
            if args.cmd == 'encrypt':
                pwd2 = getpass.getpass('Confirmer    : ')
                if pwd != pwd2:
                    print('Erreur : les mots de passe ne correspondent pas.', file=sys.stderr)
                    return 1
    except KeyboardInterrupt:
        print('\nAnnulé.', file=sys.stderr)
        return 1

    # ── encrypt ──────────────────────────────────────────────────────────────
    if args.cmd == 'encrypt':
        if not os.path.exists(args.input):
            print(f'Erreur : chemin introuvable — {args.input}', file=sys.stderr)
            return 1
        base = os.path.basename(args.input.rstrip('/\\'))
        out  = args.output or os.path.join(os.path.dirname(os.path.abspath(args.input)), base + '.senc')

        def progress(v):
            bar = int(v * 30)
            sys.stdout.write(f'\r[{"█" * bar}{"░" * (30 - bar)}] {int(v * 100):3d}%')
            sys.stdout.flush()

        try:
            CryptoEngine.encrypt_file(args.input, out, pwd, progress)
            print(f'\n✅  Chiffré → {out}')
            if args.delete:
                print('   Suppression sécurisée en cours…')
                secure_delete(args.input)
                print('   Fichier original supprimé (3 passes).')
            return 0
        except EncryptionError as e:
            print(f'\n❌  {e}', file=sys.stderr)
            return 1

    # ── decrypt ──────────────────────────────────────────────────────────────
    if args.cmd == 'decrypt':
        if not os.path.isfile(args.input):
            print(f'Erreur : fichier introuvable — {args.input}', file=sys.stderr)
            return 1
        outdir = args.output or os.path.dirname(os.path.abspath(args.input))
        os.makedirs(outdir, exist_ok=True)

        def progress(v):
            bar = int(v * 30)
            sys.stdout.write(f'\r[{"█" * bar}{"░" * (30 - bar)}] {int(v * 100):3d}%')
            sys.stdout.flush()

        try:
            result = CryptoEngine.decrypt_file(args.input, outdir, pwd, progress)
            print(f'\n✅  Déchiffré → {result}')
            return 0
        except DecryptionError as e:
            print(f'\n❌  {e}', file=sys.stderr)
            return 1

    return 0


if __name__ == '__main__':
    # If arguments are passed → CLI mode; otherwise → GUI mode
    cli_args = sys.argv[1:]
    if cli_args:
        sys.exit(_run_cli(cli_args))
    else:
        from secure_encrypto.ui.app import run
        run()
