# Auditeur de sécurité Linux
Script Python d'audit de sécurité pour serveurs Linux.
Génère un rapport HTML avec un score de sécurité global.

#   Prérequis
- Python 3
- Serveur Linux (Ubuntu, CentOS...)
- Droits sudo

#   Installation
## Installer git
Sur Ubuntu :
```bash
    sudo apt install git -y
```
Sur CentOS :
```bash
    sudo yum install git -y
```
## Cloner le projet
```bash
    git clone https://github.com/flapassrck/projet_audit.git
    cd projet_audit
```

#   Installer pip3
Sur Ubuntu :
```bash
    sudo apt install python3-pip -y
```
Sur CentOS :
```bash
    sudo yum install python3-pip -y
```

#   Installer les dépendances
```bash
    sudo pip3 install -r requirements.txt
```

#   Utilisation
```bash
    sudo python3 audit.py
```

Le rapport rapport_audit.html est généré dans le dossier projet_audit.

#   Exporter le rapport sur Windows
## Option 1 — SCP
```bash
    scp utilisateur@192.168.x.x:/home/username/projet_audit/rapport_audit.html C:\Users\username\Desktop\
```
## Option 2 — VS Code Remote SSH
1. Clic droit sur rapport_audit.html dans l'explorateur VS Code
2. Cliquer sur Download
3. Ouvrir le fichier dans le navigateur

#   Ce que le script vérifie
- Utilisateurs et accès (UID 0, mots de passe vides, sudo, SSH root)
- Réseau et ports (ports dangereux, pare-feu UFW)
- Fichiers sensibles (permissions /etc/passwd, /etc/shadow...)
- Mises à jour de sécurité manquantes
- Tentatives de brute force SSH

#   Structure du projet
    projet_audit/
    ├── audit.py          → script principal
    ├── template.html     → template du rapport
    ├── style.css         → style du rapport
    ├── requirements.txt  → dépendances Python
    └── README.md         → Explication du script