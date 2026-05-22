# Linux Security Auditor

Script Python d'audit de sécurité pour serveurs Linux.
Génère un rapport HTML avec un score de sécurité global.

## Prérequis

- Python 3
- Serveur Linux (CentOS, Ubuntu...)
- Droits sudo

## Installation

### 1. Installer git

Sur Ubuntu :

    sudo apt install git -y

Sur CentOS :

    sudo yum install git -y

### 2. Cloner le projet

    git clone https://github.com/flapassrck/linux-security-auditor.git
    cd linux-security-auditor

### 3. Installer pip3

Sur Ubuntu :

    sudo apt install python3-pip --fix-missing -y

Sur CentOS :

    sudo yum install python3-pip -y

### 4. Installer les dépendances

Sur Ubuntu :

    sudo pip3 install -r requirements.txt --break-system-packages

Sur CentOS :

    sudo pip3 install -r requirements.txt

## Utilisation

Se placer dans le dossier du projet :

    cd linux-security-auditor

Lancer le script :

    sudo python3 audit.py

Le rapport rapport_audit.html est généré dans le dossier du projet.

Comparer les 2 derniers rapports :

    python3 audit.py --comparer

## Whitelist des admins

Modifier le fichier whitelist.json pour définir les administrateurs autorisés :

    {
        "admins_autorises": ["florian", "root"]
    }

Tout utilisateur dans le groupe sudo absent de cette liste sera signalé comme suspect.

## Historique des rapports

Chaque audit génère automatiquement deux fichiers dans le dossier historique/ :
- Un fichier HTML pour la consultation visuelle
- Un fichier JSON pour la comparaison entre deux audits

Exemple :

    historique/
    ├── rapport_20260521_183045.html
    ├── rapport_20260521_183045.json
    ├── rapport_20260522_091200.html
    └── rapport_20260522_091200.json

Il faut avoir lancé au moins 2 audits pour pouvoir utiliser la comparaison.

## Récupérer le rapport sur Windows

Depuis PowerShell Windows :

    scp username@192.168.x.x:/home/username/linux-security-auditor/rapport_audit.html C:\Users\username\Desktop\

Ou depuis VS Code connecté en Remote SSH :
- Clic droit sur rapport_audit.html
- Cliquer sur Download
- Ouvrir dans le navigateur

## Ce que le script vérifie

- Utilisateurs et accès (UID 0, mots de passe vides, sudo, SSH root)
- Réseau et ports (ports dangereux, pare-feu UFW)
- Fichiers sensibles (permissions /etc/passwd, /etc/shadow...)
- Mises à jour de sécurité (apt sur Ubuntu, yum sur CentOS)
- Tentatives de brute force SSH

## Structure du projet

    linux-security-auditor/
    ├── audit.py          → script principal
    ├── template.html     → template du rapport
    ├── style.css         → style du rapport
    ├── whitelist.json    → admins autorisés
    ├── requirements.txt  → dépendances Python
    ├── README.md         → ce fichier
    └── historique/       → rapports générés automatiquement
