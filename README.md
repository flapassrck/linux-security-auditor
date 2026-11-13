# Linux Security Auditor

Script Python d'audit de sécurité pour serveurs Linux.
Il analyse la machine, génère un rapport HTML et calcule un score de sécurité global.

## Ce que le script vérifie

| Catégorie | Détail |
|---|---|
| Utilisateurs et accès | UID 0, mots de passe vides, groupe sudo, connexion SSH root |
| Réseau | ports dangereux, pare-feu UFW, service Fail2ban |
| Fichiers sensibles | permissions de `/etc/passwd`, `/etc/shadow`... |
| Modules de sécurité | AppArmor (Debian/Ubuntu), SELinux (CentOS/RHEL) |
| Mises à jour | mises à jour de sécurité en attente (`apt` ou `yum`) |
| Brute force SSH | tentatives de connexion échouées |

> Le pare-feu vérifié est UFW. La détection de `firewalld` (CentOS, Fedora) sera ajoutée plus tard.

## Compatibilité

| Famille | Distributions | Statut |
|---|---|---|
| Debian | Debian, Ubuntu | Compatible |
| Red Hat | CentOS, Rocky, Alma, Fedora | Compatible (pare-feu `firewalld` non détecté pour l'instant) |
| Autres | Arch, openSUSE, Alpine... | Non pris en charge (pas de `apt` ni de `yum`) |

Une distribution avec `systemd` est nécessaire.

## Prérequis

- Un serveur Linux Debian/Ubuntu ou CentOS/Rocky/Alma/Fedora
- Python 3 (déjà présent par défaut sur ces systèmes)
- Un accès `sudo`

## Installation

### 1. Installer git et jinja2

Debian / Ubuntu :

```bash
sudo apt update
sudo apt install git python3-jinja2 -y
```

CentOS / Rocky / Alma / Fedora :

```bash
sudo dnf install git python3-jinja2 -y
```

> Sur CentOS 7, remplace `dnf` par `yum`. Si `python3-jinja2` est introuvable :
> ```bash
> sudo yum install python3-pip -y
> sudo pip3 install jinja2
> ```

### 2. Récupérer le projet

```bash
git clone https://github.com/flapassrck/linux-security-auditor.git
cd linux-security-auditor
```

## Configuration

Avant le premier audit, modifie `whitelist.json` pour y mettre les administrateurs autorisés :

```json
{
    "admins_autorises": ["florian", "root"]
}
```

Tout membre du groupe sudo (ou wheel) absent de cette liste est signalé comme suspect.
Remplace `florian` par ton nom d'utilisateur (commande `whoami`).

## Utilisation

> **Important :** lance toujours le script depuis le dossier du projet, sinon `whitelist.json` et le template sont introuvables.

### Lancer un audit

```bash
sudo python3 audit.py
```

Le rapport `rapport_audit.html` est créé dans le dossier du projet.

## Historique des rapports

Le dossier `historique/` n'existe pas au départ : il apparaît après le premier audit.

Chaque audit y enregistre deux fichiers :

- un fichier **HTML** pour la consultation
- un fichier **JSON** pour la comparaison entre deux audits

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

### Option 1 : PowerShell

À lancer sur ton PC Windows (pas sur le serveur) :

```powershell
scp username@192.168.x.x:/home/username/linux-security-auditor/rapport_audit.html C:\Users\TonNom\Desktop\
```

Valeurs à remplacer :

| Valeur | À mettre | Comment la trouver (sur le serveur) |
|---|---|---|
| `username` (2 fois) | ton utilisateur Linux | `whoami` |
| `192.168.x.x` | l'adresse IP du serveur | `hostname -I` |
| `/home/username/linux-security-auditor` | le dossier du projet | `pwd` |
| `C:\Users\TonNom\Desktop\` | le dossier de destination sur Windows | ton Bureau |

Si SSH n'utilise pas le port 22, ajoute `-P NUMERO_PORT` juste après `scp`.

### Option 2 : VS Code (Remote SSH)

1. Clic droit sur `rapport_audit.html`
2. Cliquer sur **Download**
3. Ouvrir le fichier dans le navigateur

## Dépannage

| Problème | Solution |
|---|---|
| `ModuleNotFoundError: No module named 'jinja2'` | Refaire l'installation de `python3-jinja2` (ou `pip3 install jinja2` sur CentOS 7) |
| `whitelist.json introuvable` | Lancer le script depuis le dossier `linux-security-auditor` |
| `scp` : `Permission denied` sur le rapport | Sur le serveur : `sudo chown $USER rapport_audit.html` |
| Résultats incomplets ou « inactif » partout | Lancer avec `sudo` : sans les droits root, plusieurs vérifications échouent |
| AppArmor ou SELinux signalé « absent » | Normal si ta distribution utilise l'autre module de sécurité |
| « Pas de pare-feu » sur CentOS/Fedora | Normal : seul UFW est détecté pour l'instant, pas `firewalld` |

## Sécurité

Le rapport contient des informations sensibles sur ton serveur (utilisateurs, ports ouverts, failles). Ne le partage pas et ne le commit pas sur GitHub. Ajoute ceci à ton `.gitignore` :

```
rapport_audit.html
historique/
```

## Évolutions prévues

- [ ] Détection du pare-feu `firewalld`

## Structure du projet

```
linux-security-auditor/
├── audit.py          → script principal
├── template.html     → template du rapport
├── style.css         → style du rapport
├── whitelist.json    → admins autorisés
├── requirements.txt  → dépendances Python (jinja2)
└── README.md         → ce fichier
```

Le dossier `historique/` est créé par le script après le premier audit.
