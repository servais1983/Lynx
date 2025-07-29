#!/usr/bin/env python3
# Script Python Propre - Démonstration Lynx
# Ce fichier ne contient aucun pattern suspect

import os
import sys

def safe_function():
    """Fonction propre sans patterns malveillants"""
    data = "Données normales sans patterns suspects"
    print(data)
    return data

# Configuration propre
config = {
    "name": "safe_demo",
    "version": "1.0",
    "description": "Script Python propre pour test"
}

# Code principal propre
if __name__ == "__main__":
    print("Démarrage du script propre")
    result = safe_function()
    print(f"Résultat: {result}")
    print("Script propre terminé")

# Aucun pattern suspect :
# - Pas de string1, string2, string3
# - Pas de patterns de malware
# - Pas de fonctions dangereuses
# - Code entièrement sécurisé 