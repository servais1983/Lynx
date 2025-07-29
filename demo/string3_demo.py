#!/usr/bin/env python3
# Fichier Python de démonstration
# Contient le pattern string3 pour tester Lynx

import os
import sys

def test_function():
    """Fonction de test avec string3 pattern"""
    data = "string3 pattern detected in this Python file"
    print(data)
    return data

# Configuration
config = {
    "name": "demo",
    "version": "1.0",
    "description": "Fichier de test avec string3"
}

# Code principal
if __name__ == "__main__":
    print("Démarrage du script de démonstration")
    result = test_function()
    print(f"string3 trouvé: {result}")
    print("Script terminé") 