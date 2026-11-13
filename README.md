# Linux Security Auditor

Script Python d'audit de sécurité pour serveurs Linux.
Il génère un rapport HTML avec un score de sécurité global.

## Ce que le script vérifie

- **Utilisateurs et accès** : UID 0, mots de passe vides, groupe sudo, connexion SSH root
- **Réseau et ports** : ports dangereux, pare-feu UFW
- **Fichiers sensibles** : permissions de `/etc/passwd`, `/etc/shadow`...
- **Modules de sécurité** : AppArmor (Ubuntu/Debian), SELinux (CentOS)
- **Mises à jour de sécurité** : `apt` sur Ubuntu/Debian, `yum` sur CentOS
- **Brute force SSH** : tentatives de connexion échouées

## Prérequis

- Serveur Linux (Ubuntu, Debian, CentOS...)
- Python 3
- Droits sudo

## Installation

Ubuntu / Debian :

```bash
sudo apt install git python3-jinja2 -y
```

CentOS :

```bash
sudo yum install git python3-jinja2 -y
```

Puis récupérer le projet :

```bash
git clone https://github.com/flapassrck/linux-security-auditor.git
cd linux-security-auditor
```

## Configuration : whitelist des admins

Avant le premier audit, modifie le fichier `whitelist.json` pour définir les administrateurs autorisés :

```json
{
    "admins_autorises": ["florian", "root"]
}
```

Tout utilisateur du groupe sudo qui n'est pas dans cette liste est signalé comme suspect.

## Utilisation

Depuis le dossier du projet, lance l'audit :

```bash
sudo python3 audit.py
```

Le rapport `rapport_audit.html` est généré dans le dossier du projet.
Une copie est aussi enregistrée dans `historique/` (voir plus bas).

## Historique des rapports

Chaque audit crée deux fichiers dans le dossier `historique/` :

- un fichier HTML pour la consultation visuelle
- un fichier JSON pour la comparaison entre deux audits

Exemple :

```
historique/
├── rapport_20260521_183045.html
├── rapport_20260521_183045.json
├── rapport_20260522_091200.html
└── rapport_20260522_091200.json
```

### Comparer les deux derniers audits

```bash
python3 audit.py --comparer
```

Il faut avoir lancé au moins 2 audits pour utiliser la comparaison.

## Récupérer le rapport sur Windows

Depuis PowerShell :

```powershell
scp username@192.168.x.x:/home/username/linux-security-auditor/rapport_audit.html C:\Users\username\Desktop\
```

Ou depuis VS Code connecté en Remote SSH :

1. Clic droit sur `rapport_audit.html`
2. Cliquer sur **Download**
3. Ouvrir le fichier dans le navigateur

## Sécurité

Le rapport contient des informations sensibles sur ton serveur (utilisateurs, ports ouverts, failles). Ne le partage pas publiquement et ne le commit pas sur GitHub (ajoute `rapport_audit.html` et `historique/` à ton `.gitignore`).

## Structure du projet

```
linux-security-auditor/
├── audit.py          → script principal
├── template.html     → template du rapport
├── style.css         → style du rapport
├── whitelist.json    → admins autorisés
├── requirements.txt  → dépendances Python (jinja2)
├── README.md         → ce fichier
└── historique/       → rapports générés automatiquement
```
