#!/usr/bin/env python3

###########################################
#  AUDITEUR DE SÉCURITÉ AUTOMATIQUE LINUX #
###########################################

"""
Auditeur de sécurité Linux automatique
Ce script analyse la sécurité d'un serveur Linux puis génère un rapport HTML avec score
"""

#   Modules importés
import pwd
import grp
import subprocess
import socket
import datetime
import json
from pathlib import Path

#   Couleurs pour le terminal Linux
VERT = "\033[92m"
JAUNE = '\033[93m'
ROUGE = '\033[91m'
CYAN = '\033[96m'
GRAS = '\033[1m'
RESET = '\033[0m'

#   Fonctions messages et titres
def ok(msg):
    print(f"{VERT}✅ {RESET} {msg}")
def attention(msg):
    print(f"{JAUNE}⚠️ {RESET} {msg}")
def probleme(msg):
    print(f"{ROUGE}❌ {RESET} {msg}")
def info(msg):
    print(f"{CYAN}ℹ️ {RESET} {msg}")
def titre(msg):
    print(f"{GRAS}{CYAN}{'='*50}\n{msg.center(50)}\n{'='*50}{RESET}")

#   Résultat d'une vérification (status, détails, points obtenus, points max)
class Check:
    def __init__(self, label, status, detail="", points=0, max_points=10, recommandation=""):
        self.label          = label
        self.status         = status
        self.detail         = detail
        self.points         = points
        self.max_points     = max_points
        self.recommandation = recommandation

#   MODULE 1 : Utilisateurs & Accès
def audit_users():
    titre("MODULE 1 - Utilisateurs & Accès")
    resultats = []

#   Vérification 1 : Comptes avec UID 0
    utilisateurs_uid0 = [i.pw_name for i in pwd.getpwall() if i.pw_uid == 0]
    if utilisateurs_uid0 == ["root"]:
        ok("Un seul compte UID 0 (root)")
        resultats.append(Check("Comptes UID 0", "ok", "Seulement root", 10, 10))
    else:
        users_suspects = [j for j in utilisateurs_uid0 if j != "root"]
        attention(f"Comptes UID 0 suspects : {', '.join(users_suspects)}")
        resultats.append(Check(
            "Comptes UID 0", "attention",
            f"Suspects : {', '.join(users_suspects)}",
            0, 10,
            "Seul le compte root doit avoir l'UID 0. Modifier l'UID du compte suspect avec : sudo usermod -u 1001 nom_user"
        ))

#   Vérification 2 : Comptes sans mot de passe
    try:
        shadow = Path("/etc/shadow").read_text()
        mdp_vide = []
        for ligne in shadow.splitlines():
            parts = ligne.split(":")
            if len(parts) >= 2 and parts[1] == "":
                mdp_vide.append(parts[0])
        if mdp_vide:
            attention(f"Comptes sans mot de passe : {', '.join(mdp_vide)}")
            resultats.append(Check(
                "Comptes sans mot de passe", "attention",
                f"{', '.join(mdp_vide)}",
                0, 10,
                "Un compte sans mot de passe est accessible par n'importe qui. Définir un mot de passe avec : sudo passwd nom_user"
            ))
        else:
            ok("Aucun compte sans mot de passe")
            resultats.append(Check("Comptes sans mot de passe", "ok", "Aucun compte sans mot de passe", 10, 10))
    except PermissionError:
        probleme("Impossible d'acceder au fichier /etc/shadow")
        resultats.append(Check("Comptes sans mot de passe", "probleme", "Nécessite de se connecter en sudo", 0, 10))

#   Vérification 3 : Membres du groupe sudo
    try:
        with open("whitelist.json", "r") as f:
            whitelist = json.load(f)
        admins_autorises = whitelist.get("admins_autorises", [])
    except FileNotFoundError:
        admins_autorises = []
        attention("whitelist.json introuvable — tous les membres sudo seront signalés")

    groupe_trouve = None
    for nom_groupe in ["sudo", "wheel"]:
        try:
            groupe = grp.getgrnam(nom_groupe)
            groupe_trouve = nom_groupe
            sudo_membres = groupe.gr_mem
            break
        except KeyError:
            continue

    if groupe_trouve is None:
        info("Groupe sudo ou wheel non trouvé")
        resultats.append(Check("Groupe sudo", "ok", "Groupe inexistant", 10, 10))
    else:
        suspects = [m for m in sudo_membres if m not in admins_autorises]
        if suspects:
            probleme(f"Membre(s) sudo non autorisé(s) : {', '.join(suspects)}")
            resultats.append(Check(
                "Groupe sudo", "probleme",
                f"Suspects : {', '.join(suspects)}",
                0, 10,
                "Cet utilisateur a les droits administrateur sans être dans la whitelist. Le retirer du groupe sudo avec : sudo deluser nom_user sudo (Ubuntu) ou sudo gpasswd -d nom_user wheel (CentOS)"
            ))
        elif sudo_membres:
            attention(f"Membres du groupe {groupe_trouve} : {', '.join(sudo_membres)}")
            resultats.append(Check(
                f"Groupe sudo", "attention",
                f"Membres : {', '.join(sudo_membres)}",
                5, 10,
                "Vérifier que tous les membres de ce groupe ont bien besoin des droits administrateur. Mettre à jour la whitelist.json si nécessaire."
            ))
        else:
            ok(f"Groupe {groupe_trouve} vide")
            resultats.append(Check(f"Groupe sudo", "ok", "Aucun membre", 10, 10))

#   Vérification 4 : Connexions SSH root
    sshd_config = Path("/etc/ssh/sshd_config")
    if sshd_config.exists():
        contenue = sshd_config.read_text()
        if "PermitRootLogin yes" in contenue:
            probleme("SSH - connexion root autorisée")
            resultats.append(Check(
                "SSH - PermitRootLogin", "probleme",
                "Root login activé",
                0, 10,
                "Autoriser la connexion SSH en root est dangereux car root est la première cible des attaques. Modifier /etc/ssh/sshd_config : remplacer 'PermitRootLogin yes' par 'PermitRootLogin no' puis redémarrer SSH avec : sudo systemctl restart sshd"
            ))
        elif "PermitRootLogin no" in contenue:
            ok("SSH - connexion root desactivé")
            resultats.append(Check("SSH - PermitRootLogin", "ok", "Root login desactivé", 10, 10))
        else:
            attention("SSH - PermitRootLogin non défini")
            resultats.append(Check(
                "SSH - PermitRootLogin", "attention",
                "Root login non défini",
                7, 10,
                "La valeur par défaut peut varier selon les systèmes. Définir explicitement 'PermitRootLogin no' dans /etc/ssh/sshd_config puis redémarrer SSH avec : sudo systemctl restart sshd"
            ))
    else:
        attention("Fichier sshd_config introuvable")
        resultats.append(Check("SSH - PermitRootLogin", "attention", "Fichier introuvable", 5, 10))

    return resultats

#   Module 2 : Réseaux & Ports
def audit_network():
    titre("MODULE 2 - Réseaux & Ports")
    resultats = []

#   Vérification 1 : ports dangereux
    ports_dangereux = {21: "FTP", 23: "Telnet", 512: "rexec", 513: "rlogin", 514: "rsh"}
    try:
        sortie = subprocess.check_output(["ss", "-tlnp"], text=True, stderr=subprocess.DEVNULL)

        ports_ouverts = []
        for lignes in sortie.splitlines()[1:]:
            parts = lignes.split()
            if len(parts) >= 4:
                address = parts[3]
                port = int(address.rsplit(":", 1)[-1])
                ports_ouverts.append(port)

        dangereux_trouvees = {p: ports_dangereux[p] for p in ports_ouverts if p in ports_dangereux}

        if dangereux_trouvees:
            for port, service in dangereux_trouvees.items():
                probleme(f"Port dangereux ouvert : {port} ({service})")
            resultats.append(Check(
                "Port dangereux", "probleme",
                f"Ouverts : {', '.join(str(p) for p in dangereux_trouvees)}",
                0, 10,
                "Ces services transmettent les données sans chiffrement et représentent un risque de sécurité. Désactiver chaque service avec : sudo systemctl disable --now nom_service et vérifier qu'il ne redémarre pas au prochain boot."
            ))
        else:
            ok(f"Aucun port dangereux ({len(ports_ouverts)} ports ouverts)")
            resultats.append(Check(f"Port dangereux", "ok", f"({len(ports_ouverts)} ports ouverts)", 10, 10))
    except (subprocess.CalledProcessError, FileNotFoundError):
        attention("Impossible d'exécuter 'ss'")
        resultats.append(Check("Port dangereux", "attention", "Impossible d'exécuter 'ss'", 5, 10))

#   Vérification 2 : Statut du pare-feu UFW
    try:
        status_ufw = subprocess.check_output(["ufw", "status"], text=True, stderr=subprocess.DEVNULL)
        if "active" in status_ufw.lower():
            ok("Pare-feu UFW actif")
            resultats.append(Check("Pare-feu UFW", "ok", "UFW actif", 10, 10))
        else:
            probleme("Pare-feu UFW inactif")
            resultats.append(Check(
                "Pare-feu UFW", "probleme",
                "UFW inactif",
                0, 10,
                "Sans pare-feu, toutes les connexions entrantes sont acceptées par défaut. Activer UFW avec : sudo ufw enable puis autoriser SSH pour ne pas perdre l'accès : sudo ufw allow 22/tcp"
            ))
    except (subprocess.CalledProcessError, FileNotFoundError):
        attention("UFW non disponible")
        resultats.append(Check("Pare-feu UFW", "attention", "UFW absent", 5, 10))

    return resultats

#   Module 3 : Fichiers sensibles
def audit_files():
    titre("MODULE 3 - Fichiers sensibles")
    resultats = []

#   Vérification : Fichiers sensibles
    fichiers_sensibles = {
        "/etc/passwd":          ("644", "root"),
        "/etc/sudoers":         ("440", "root"),
        "/etc/ssh/sshd_config": ("600", "root"),
    }

    if Path("/etc/redhat-release").exists():
        fichiers_sensibles["/etc/shadow"] = ("000", "root")
    else:
        fichiers_sensibles["/etc/shadow"] = ("640", "root")

    for cheminfichier, (perms_attendue, owner_attendue) in fichiers_sensibles.items():
        p = Path(cheminfichier)
        if not p.exists():
            info(f"Fichier {cheminfichier} introuvable")
            continue

        stat = p.stat()
        perms_actuels = oct(stat.st_mode)[-3:]
        try:
            owner_actuel = pwd.getpwuid(stat.st_uid).pw_name
        except KeyError:
            owner_actuel = str(stat.st_uid)

        issues = []
        if perms_actuels != perms_attendue:
            issues.append(f"Permissions {perms_actuels} (attendues {perms_attendue})")
        if owner_actuel != owner_attendue:
            issues.append(f"Propriétaire {owner_actuel} (attendu {owner_attendue})")

        if issues:
            probleme(f"Fichier {cheminfichier} : {', '.join(issues)}")
            resultats.append(Check(
                f"Permissions {cheminfichier}", "probleme",
                ', '.join(issues),
                0, 10,
                f"Des permissions trop ouvertes sur ce fichier peuvent permettre à un utilisateur malveillant de le lire ou le modifier. Corriger avec : sudo chmod {perms_attendue} {cheminfichier} puis vérifier avec : ls -la {cheminfichier}"
            ))
        else:
            ok(f"{cheminfichier} : correct")
            resultats.append(Check(f"Permissions {cheminfichier}", "ok", "OK", 10, 10))

    return resultats

#   Module 4 : Mise à jour de sécurité
def audit_updates():
    titre("MODULE 4 — Mises à jour de sécurité")
    resultats = []

    if Path("/etc/debian_version").exists():
        try:
            subprocess.check_output(["apt-get", "update", "-qq"], stderr=subprocess.DEVNULL)
            sortie = subprocess.check_output(["apt-get", "-s", "upgrade"], text=True, stderr=subprocess.DEVNULL)
            updates = [l for l in sortie.splitlines() if l.startswith("Inst")]
            nb = len(updates)
            if nb == 0:
                ok("Système à jour !")
                resultats.append(Check("Mises à jour", "ok", "Aucune mise à jour", 10, 10))
            else:
                probleme(f"{nb} mise(s) à jour disponible(s) !")
                resultats.append(Check(
                    "Mises à jour", "probleme",
                    f"{nb} mise(s) à jour(s) en attente",
                    0, 10,
                    "Des paquets non mis à jour peuvent contenir des failles de sécurité connues. Mettre à jour le système avec : sudo apt upgrade -y puis redémarrer si le noyau a été mis à jour : sudo reboot"
                ))
        except Exception:
            attention("Impossible de vérifier les mises à jour")
            resultats.append(Check("Mises à jour", "attention", "Vérification impossible", 5, 10))

    elif Path("/etc/redhat-release").exists():
        try:
            subprocess.check_output(["yum", "check-update"], text=True, stderr=subprocess.DEVNULL)
            ok("Système à jour !")
            resultats.append(Check("Mises à jour", "ok", "Aucune mise à jour", 10, 10))
        except subprocess.CalledProcessError as e:
            if e.returncode == 100:
                sortie = e.output if e.output else ""
                updates = [l for l in sortie.splitlines() if l and not l.startswith(" ") and not l.startswith("Loaded")]
                nb = len(updates)
                probleme(f"{nb} mise(s) à jour(s) disponible(s) !")
                resultats.append(Check(
                    "Mises à jour", "probleme",
                    f"{nb} mise(s) à jour(s) en attente",
                    0, 10,
                    "Des paquets non mis à jour peuvent contenir des failles de sécurité connues. Mettre à jour le système avec : sudo yum update -y puis redémarrer si le noyau a été mis à jour : sudo reboot"
                ))
            else:
                attention("Impossible de vérifier les mises à jour")
                resultats.append(Check("Mises à jour", "attention", "Vérification impossible", 5, 10))
    else:
        attention("OS non reconnu")
        resultats.append(Check("Mises à jour", "attention", "OS non supporté", 5, 10))

    return resultats

#   Module 5 : Tentative de connexion SSH par Force Brute
def audit_ssh_logs():
    titre("MODULE 5 - Tentative Force Brute")
    resultats = []

#   Vérification : Tentative de connexion SSH par Force Brute
    fichiers_log = ["/var/log/secure", "/var/log/auth.log"]
    log_trouve = None

    for log in fichiers_log:
        if Path(log).exists():
            log_trouve = log
            break

    if log_trouve is None:
        attention("Aucun fichier de logs SSH trouvé")
        resultats.append(Check("Logs SSH", "attention", "Aucun fichier de logs SSH rencontré", 5, 10))
        return resultats

    try:
        contenu = Path(log_trouve).read_text(errors="ignore")
        tentatives = [l for l in contenu.splitlines() if "Failed password" in l]
        nb = len(tentatives)

        if nb == 0:
            ok("Aucune tentative de connexion échouée")
            resultats.append(Check("Brute force SSH", "ok", "Aucune tentative", 10, 10))
        elif nb < 20:
            attention(f"{nb} tentatives échouées detectées")
            resultats.append(Check(
                "Brute force SSH", "attention",
                f"{nb} tentatives",
                5, 10,
                "Des tentatives de connexion échouées ont été détectées. Installer fail2ban pour bloquer automatiquement les IPs suspectes : sudo apt install fail2ban -y (Ubuntu) ou sudo yum install fail2ban -y (CentOS) puis démarrer le service : sudo systemctl enable --now fail2ban"
            ))
        else:
            probleme(f"{nb} tentatives échouées - possible brute force")
            resultats.append(Check(
                "Brute force SSH", "probleme",
                f"{nb} tentatives",
                0, 10,
                "Un grand nombre de tentatives de connexion échouées indique une attaque en cours. Installer fail2ban immédiatement : sudo apt install fail2ban -y (Ubuntu) ou sudo yum install fail2ban -y (CentOS) puis démarrer le service : sudo systemctl enable --now fail2ban"
            ))

        if tentatives:
            info("3 dernières tentatives :")
            for ligne in tentatives[-3:]:
                info(ligne.strip())
    except PermissionError:
        attention("Logs innaccessibles - relance en sudo")
        resultats.append(Check("Brute force SSH", "attention", "Nécessite de relancer en sudo", 5, 10))

    return resultats

#   Calcul le score global de tous les checks
def compte_score(all_checks):
    total_points = sum(c.points for c in all_checks)
    total_max    = sum(c.max_points for c in all_checks)
    score = int((total_points / total_max) * 100) if total_max > 0 else 0

    return score, total_points, total_max

#    Générer le rapport HTML
def generate_html_report(all_checks, score, hostname):
    from jinja2 import Environment, FileSystemLoader

    now = datetime.datetime.now().strftime("%d/%m/%Y à %H:%M")

    if score >= 80:
        score_color = "#00ff88"
        score_label = "Bon"
    elif score >= 50:
        score_color = "#ffaa00"
        score_label = "Moyen"
    else:
        score_color = "#ff3355"
        score_label = "Critique"

    env = Environment(loader=FileSystemLoader("."))
    css = Path("style.css").read_text()
    template = env.get_template("template.html")

    html = template.render(
        css=css,
        hostname=hostname,
        now=now,
        score=score,
        score_color=score_color,
        score_label=score_label,
        checks=all_checks,
        status_icons={"ok": "✅", "attention": "⚠️", "probleme": "❌"},
        status_colors={"ok": "#00ff88", "attention": "#ffaa00", "probleme": "#ff3355"},
        status_background={"ok": "#0a2e1a", "attention": "#2e2000", "probleme": "#2e0a14"},
    )

    chemin_rapport = Path("rapport_audit.html")
    chemin_rapport.write_text(html, encoding="utf-8")

    return chemin_rapport

#    Fonction principale
def main():
    debut = datetime.datetime.now()

    all_checks = []
    all_checks += audit_users()
    all_checks += audit_network()
    all_checks += audit_files()
    all_checks += audit_updates()
    all_checks += audit_ssh_logs()

    score, pts, max_pts = compte_score(all_checks)
    titre("Résultat de l'analyse")
    if score >= 80:
        ok(f"Score final : {score}/100 — Sécurité satisfaisante")
    elif score >= 50:
        attention(f"Score final : {score}/100 — Des améliorations nécessaires")
    else:
        probleme(f"Score final : {score}/100 — Niveau critique !")

    rapport = generate_html_report(all_checks, score, socket.gethostname())
    info(f"Rapport généré : {rapport.resolve()}")

    fin = datetime.datetime.now()
    duree = (fin - debut).total_seconds()
    info(f"Durée d'exécution : {duree:.2f} secondes")

main()
