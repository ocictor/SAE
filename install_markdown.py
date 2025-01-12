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
    print("=== Installation de Markdown ===\n")
    
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
    
    # Installer markdown
    commands = [
        "python -m pip install markdown",
        "python -m pip install --user markdown",
        "python -m pip install markdown --no-cache-dir"
    ]
    
    print("\nTentative d'installation de markdown...")
    success = False
    
    for cmd in commands:
        print(f"\nEssai avec: {cmd}")
        success, output = run_command(cmd)
        if success:
            print("✓ Installation réussie!")
            break
        else:
            print(f"✗ Cette méthode a échoué")
    
    if success:
        print("\nVérification de l'installation...")
        try:
            import markdown
            test_text = "# Test\nCeci est un **test**."
            html = markdown.markdown(test_text)
            print("✓ Markdown fonctionne correctement!")
        except ImportError:
            print("✗ Impossible d'importer markdown")
            success = False
    
    if not success:
        print("\n⚠️ L'installation a échoué.")
        print("Suggestions:")
        print("1. Vérifiez votre connexion internet")
        print("2. Essayez d'exécuter en tant qu'administrateur")
    
    print("\nAppuyez sur Entrée pour fermer...")
    input()

if __name__ == "__main__":
    main()