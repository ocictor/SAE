import subprocess
import sys

def run_command(command):
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
       return False, e.stderrFalse

def main():
   print("=== Installation de Pandas ===\n")
   
   print("Vérification de Python...")
   success, output = run_command("python --version")
   if success:
       print(f"✓ Python détecté: {output.strip()}")
   else:
       print("✗ Python n'est pas installé correctement")
       print("Veuillez installer Python depuis python.org")
       input("\nAppuyez sur Entrée pour fermer...")
       return

   commands = [
       "python -m pip install pandas",
       "python -m pip install --user pandas",
       "python -m pip install pandas --no-cache-dir"
   ]
   
   print("\nTentative d'installation de pandas...")
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
           import pandas as pd
           test_df = pd.DataFrame({'test': [1, 2, 3]})
           print("✓ Pandas fonctionne correctement!")
       except ImportError:
           print("✗ Impossible d'importer pandas")
           success = False
   
   if not success:
       print("\n⚠️ L'installation a échoué.")
       print("Suggestions:")
       print("1. Vérifiez votre connexion internet")
       print("2. Essayez d'exécuter en tant qu'administrateur")
       print("3. Installez Anaconda qui inclut pandas")
   
   input("\nAppuyez sur Entrée pour fermer...")

if __name__ == "__main__":
   main()