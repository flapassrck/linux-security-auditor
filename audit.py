#!/usr/bin/env python3

###########################################
#  AUDITEUR DE SÉCURITÉ AUTOMATIQUE LINUX #
###########################################

"""
Auditeur de sécurité Linux automatique
Ce script analyse la sécurité d'un serveur Linux puis génère un rapport HTML avec score
"""

#   Modules importés
import os
import pwd
import grp
import subprocess
import socket
import datetime
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
    print(f"{JAUNE}⚠️ {RESET}  {msg}")
def probleme(msg):
    print(f"{ROUGE}❌ {RESET} {msg}")
def info(msg):
    print(f"{CYAN}ℹ️ {RESET}  {msg}")
def titre(msg):
    print(f"{GRAS}{CYAN}{'='*50}\n{msg.center(50)}\n{'='*50}{RESET}")

#   Résultat d'une vérification (status, détails, points obtenus, points max)
class Check:
    def __init__(self, label, status, detail="", points=0, max_points=10):
        self.label      = label
        self.status     = status
        self.detail     = detail
        self.points     = points
        self.max_points = max_points

#   MODULE 1 : Utilisateurs & Accès
def audit_users():
    titre("MODULE 1 - Utilisateurs & Accès")
    resultats = []

#   Vérification 1 : Comptes avec UID 0
    uid0_users = [i.pw_name for i in pwd.getpwall() if i.pw_uid == 0]
    if uid0_users == ["root"]:
        ok("Un seul compte UID 0 (root)")
        resultats.append(Check("Comptes UID 0", "Ok", "Seulement root", 10, 10))
    else:
        extra = [j for j in uid0_users if j != "root"]
        attention(f"Comptes UID 0 suspects : {', '.join(extra)}")
        resultats.append(Check("Comptes UID 0", "Attention", f"Suspects : {', '.join(extra)}", 0, 10))

#   Vérification 2 : Comptes sans mot de passe
    try:
        shadow = Path("/etc/shadow").read_text()
        empty_mdp = []
        for line in shadow.splitlines():
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] == "":
                empty_mdp.append(parts[0])
        if empty_mdp:
            attention(f"Comptes sans mot de passe : {', '.join(empty_mdp)}")
            resultats.append(Check("Comptes sans mot de passe", "Attention", f"{', '.join(empty_mdp)}", 0, 10))
        else:
            ok("Aucun compte sans mot de passe")
            resultats.append(Check("Comptes sans mot de passe", "Ok", "Aucun compte sans mot de passe", 10, 10))
    except PermissionError:
        probleme("Impossible d'acceder au fichier /etc/shadow")
        resultats.append(Check("Comptes sans mot de passe", "Problème", "Nécessite de se connecter en sudo", 0, 10))

#   Vérification 3 : Membres du groupe sudo
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
        info(f"Groupe sudo ou wheel non trouvé")
        resultats.append(Check(f"Groupe sudo", "Ok", "Groupe inexistant", 10, 10))
    elif sudo_membres:
        attention(f"Membres du groupe {groupe_trouve} : {', '.join(sudo_membres)}")
        resultats.append(Check(f"Groupe sudo", "Attention", f"Membres : {', '.join(sudo_membres)}", 5, 10))
    else:
        ok(f"Groupe {groupe_trouve} vide")
        resultats.append(Check(f"Groupe sudo", "Ok", f"Aucun membre", 10, 10))

#   Vérification 4 : Connexions SSH root
    sshd_config = Path("/etc/ssh/sshd_config")
    if sshd_config.exists():
        contenue = sshd_config.read_text()
        if "PermitRootLogin yes" in contenue:
            probleme("SSH - connexion root autorisée")
            resultats.append(Check("SSH - PermitRootLogin", "Problème", "Root login activé", 0, 10))
        elif "PermitRootLogin no" in contenue:
            ok("SSH - connexion root desactivé")
            resultats.append(Check("SSH - PermitRootLogin", "Ok", "Root login desactivé", 10, 10))
        else:
            attention("SSH - PermitRootLogin non défini")
            resultats.append(Check("SSH - PermitRootLogin", "Attention", "Root login non défini", 7, 10))
    else:
        attention("Fichier sshd_config introuvable")
        resultats.append(Check("SSH - PermitRootLogin", "Attention", "Fichier introuvable", 5, 10))
    
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
            resultats.append(Check(f"Port dangereux", "Problème", f"Ouverts : {', '.join(str(p) for p in ports_ouverts)}", 0, 10))
        else:
            ok(f"Aucun port dangereux ({len(ports_ouverts)} ports ouverts)")
            resultats.append(Check(f"Port dangereux", "Ok", f"({len(ports_ouverts)} ports ouverts)", 10, 10))
    except (subprocess.CalledProcessError, FileNotFoundError):
        attention("Impossible d'exécuter 'ss'")
        resultats.append(Check(f"Port dangereux", "Attention", "Impossible d'exécuter 'ss'", 5, 10))

#   Vérification 2 : Statut du pare-feu UFW
    try:
        status_ufw = subprocess.check_output(["ufw", "status"], text=True, stderr=subprocess.DEVNULL)
        if "active" in status_ufw.lower():
            ok("Pare-feu UFW actif")
            resultats.append(Check("Pare-feu UFW", "Ok", "UFW actif", 10, 10))
        else:
            probleme("Pare-feu UFW inactif")
            resultats.append(Check("Pare-feu UFW", "Problème", "UFW inactif", 0, 10))
    except (subprocess.CalledProcessError, FileNotFoundError):
        attention("UFW non disponible")
        resultats.append(Check("Pare-feu UFW", "Attention", "UFW absent", 5, 10))
    
    return resultats

#   Module 3 : Fichiers sensibles
def audit_files():
    titre("MODULE 3 - Fichiers sensibles")
    resultats = []

#   Vérification : Fichiers sensibles

    fichiers_sensibles = {
        "/etc/passwd":          ("644", "root"),
        "/etc/shadow":          ("000", "root"),
        "/etc/sudoers":         ("440", "root"),
        "/etc/ssh/sshd_config": ("600", "root"),
    }
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
            resultats.append(Check(f"Permissions {cheminfichier}", "Problème", ', '.join(issues), 0, 10))
        else:
            ok(f"{cheminfichier} : correct")
            resultats.append(Check(f"Permissions {cheminfichier}", "Ok", "OK", 10, 10))

    return resultats

#   Module 4 : Mise à jour de sécurité
def audit_updates():
    titre("MODULE 4 - Mise à jour de sécurité")
    resultats = []

#   Vérification : Mise à jour de sécurité
    try:
        subprocess.check_output(["yum", "check-update"], text=True, stderr=subprocess.DEVNULL)
        ok("Système à jour ! ")
        resultats.append(Check("Mises à jour", "Ok", "Aucune mise à jour en attente", 10, 10))
    except subprocess.CalledProcessError as e:
        if e.returncode == 100:
            sortie = e.output
            updates = [l for l in sortie.splitlines() if l and not l.startswith(" ")]
            probleme(f"{len(updates)} mise(s) à jour disponible(s)")
            resultats.append(Check("Mises à jour", "Problème", f"{len(updates)} mises à jour en attente", 0, 10))
        else:
            attention("Impossible de vérifier les mises à jour")
            resultats.append(Check("Mises à jour", "Attention", "Vérification impossible", 5, 10))
    except FileNotFoundError:
        attention("yum introuvable sur le système")
        resultats.append(Check("Mises à jour", "Attention", "yum introuvable", 5, 10))

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

    if log_trouve == None:
        attention("Aucun fichier de logs SSH trouvé")
        resultats.append(Check("Logs SSH", "Attention", "Aucun fichier de logs SSH rencontré", 5, 10))

    try:
        contenu = Path(log_trouve).read_text(errors="ignore")
        tentatives = [l for l in contenu.splitlines() if "Failed password" in l]
        nb = len(tentatives)

        if nb == 0:
            ok("Aucune tentative de connexion échouées")
            resultats.append(Check("Brute force SSH", "Ok", "Aucune tentative", 10, 10))
        elif nb < 20:
            attention(f"{nb} tentatives échouées detectées")
            resultats.append(Check("Brute force SSH", "Attention", f"{nb} tentatives", 5, 10))
        else:
            probleme(f"{nb} tentatives échouées - possible brute force")
            resultats.append(Check("Brute force SSH", "Problème", f"{nb} tentatives", 0, 10))

        if tentatives:
            info("3 dernières tentatives :")
            for ligne in tentatives[-3:]:
                info(ligne.strip())
    except PermissionError:
        attention("Logs innaccessibles - relance en sudo")
        resultats.append(Check("Brute force SSH", "Attention", "Nécessite de relancer en sudo", 5, 10))

    return resultats

def compte_score(all_checks):
    total_points = sum(c.points for c in all_checks)
    total_max    = sum(c.max_points for c in all_checks)
    score = int((total_points / total_max) * 100) if total_max > 0 else 0
    return score, total_points, total_max


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
    template = env.get_template("template.html")

    html = template.render(
        hostname=hostname,
        now=now,
        score=score,
        score_color=score_color,
        score_label=score_label,
        checks=all_checks,
        status_icons={"Ok": "✅", "Attention": "⚠️", "Problème": "❌"},
        status_colors={"ok": "#00ff88", "warn": "#ffaa00", "fail": "#ff3355"},
        status_background={"ok": "#0a2e1a", "warn": "#2e2000", "fail": "#2e0a14"},
    )

    report_path = Path("rapport_audit.html")
    report_path.write_text(html, encoding="utf-8")
    return report_path
    
def main():
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
    info(f"Rapport générée : {rapport.resolve()}")

main()

