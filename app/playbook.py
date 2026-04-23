from __future__ import annotations

PLAYBOOKS: dict[str, list[str]] = {
    "failed-login-attempt": [
        "Verifier la frequence des echecs depuis la meme IP et le meme user.",
        "Comparer avec historique des connexions legitimes.",
        "Verifier si d'autres endpoints sensibles sont probes depuis cette IP.",
    ],
    "possible-bruteforce": [
        "Bloquer temporairement l'IP au niveau WAF/firewall.",
        "Appliquer rate limiting et captcha sur endpoint login.",
        "Forcer reset/rotation des credentials comptes cibles.",
    ],
    "possible-account-compromise": [
        "Verifier l'activite post-login (IP, geoloc, actions sensibles).",
        "Suspendre la session et forcer MFA/password reset.",
        "Rechercher les memes indicateurs sur d'autres comptes.",
    ],
    "injection-or-traversal": [
        "Analyser la requete brute et bloquer payloads equivalents.",
        "Verifier logs applicatifs/DB pour erreurs et extraction de donnees.",
        "Lancer revue ciblée des endpoints concernes.",
    ],
    "suspicious-user-agent": [
        "Confirmer si l'UA correspond a un outil de scan connu.",
        "Correlier avec pics de 404/403/5xx sur la meme IP.",
        "Mettre en place une regle de blocage ou challenge.",
    ],
    "admin-access-denied": [
        "Verifier tentative d'acces admin non autorisee.",
        "Identifier la source et repetitivite des tentatives.",
        "Renforcer ACL/IP allowlist sur interfaces admin.",
    ],
    "error-spike-5xx": [
        "Verifier si attaque applicative ou panne technique.",
        "Corriger endpoint fautif et activer protection WAF.",
        "Surveiller recurrence et impact business.",
    ],
}


def get_playbook(alert_type: str) -> list[str]:
    return PLAYBOOKS.get(alert_type, ["Aucun playbook specifique. Proceder a l'investigation manuelle."])
