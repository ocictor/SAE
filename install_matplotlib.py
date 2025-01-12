import subprocess
import sys

def run_command(command):
    """Exécute une commande et retourne le résultat"""
    try:
        result = subprocess.run(
            command,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return False, e.stderr

def main():
    print("=== Installation de Matplotlib ===\n")
    
    # Vérifier Python
    print("Vérification de Python...")
    success, output = run_command("python --version")
    if success:
        print(f"✓ Python détecté: {output.strip()}")
    else:
        print("✗ Python n'est pas installé correctement")
        print("Veuillez installer Python depuis python.org")
        input("\nAppuyez sur Entrée pour fermer...")
        return
    
    # Liste des commandes à essayer
    commands = [
        "python -m pip install matplotlib",
        "python -m pip install --user matplotlib",
        "python -m pip install matplotlib --no-cache-dir",
        "py -m pip install matplotlib"
    ]
    
    # Essayer chaque commande
    print("\nTentative d'installation de matplotlib...")
    success = False
    
    for cmd in commands:
        print(f"\nEssai avec: {cmd}")
        success, output = run_command(cmd)
        if success:
            print("✓ Installation réussie!")
            break
        else:
            print(f"✗ Cette méthode a échoué")

    if not success:
        print("\n⚠️ L'installation a échoué.")
        print("Suggestions:")
        print("1. Vérifiez votre connexion internet")
        print("2. Essayez d'exécuter en tant qu'administrateur")
        print("3. Vérifiez que Python est dans le PATH système")
    
    print("\nAppuyez sur Entrée pour fermer...")
    input()

if __name__ == "__main__":
    main()