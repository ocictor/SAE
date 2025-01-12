import matplotlib.pyplot as plt
from datetime import datetime

def parse_ics_datetime(dt_str):
    """Convertit une date au format ICS en objet datetime"""
    try:
        year = int(dt_str[0:4])
        month = int(dt_str[4:6])
        day = int(dt_str[6:8])
        return datetime(year, month, day)
    except (IndexError, ValueError):
        return None

def extract_tp_sessions(filename):
    """Extrait les séances de TP de R1.07 pour le groupe A1"""
    sessions = []
    current_event = None
    
    print(f"Lecture du fichier {filename}...")
    with open(filename, 'r', encoding='utf-8') as file:
        for line in file:
            line = line.strip()
            if line == "BEGIN:VEVENT":
                current_event = {}
            elif line == "END:VEVENT":
                if current_event:
                    summary = current_event.get('SUMMARY', '')
                    description = current_event.get('DESCRIPTION', '')
                    
                    # Debug: afficher les événements trouvés
                    if "R1.07" in summary:
                        print(f"\nTrouvé un événement R1.07:")
                        print(f"Summary: {summary}")
                        print(f"Description: {description}")
                    
                    # Vérifier si c'est un TP de R1.07 pour le groupe A1
                    if ("R1.07" in summary and 
                        "A1" in description and 
                        "TP" in description):
                        
                        date = parse_ics_datetime(current_event.get('DTSTART', ''))
                        if date:
                            sessions.append(date)
                            print(f"-> Ajouté comme séance de TP!")
                current_event = None
            elif current_event is not None and ':' in line:
                key, value = line.split(':', 1)
                current_event[key] = value
    
    print(f"\nNombre total de séances trouvées: {len(sessions)}")
    return sessions

def count_sessions_by_month(sessions):
    """Compte le nombre de séances par mois"""
    months_count = {9: 0, 10: 0, 11: 0, 12: 0}  # Septembre à Décembre
    
    for session in sessions:
        if session.month in months_count:
            months_count[session.month] += 1
    
    return months_count

def create_bar_chart(months_count):
    """Crée un graphique en barres du nombre de séances par mois"""
    months_names = {
        9: 'Septembre',
        10: 'Octobre',
        11: 'Novembre',
        12: 'Décembre'
    }
    
    # Préparer les données pour le graphique
    months = [months_names[m] for m in sorted(months_count.keys())]
    counts = [months_count[m] for m in sorted(months_count.keys())]
    
    # Créer le graphique
    plt.figure(figsize=(10, 6))
    bars = plt.bar(months, counts)
    
    # Personnaliser le graphique
    plt.title('Nombre de séances de TP R1.07 (Groupe A1) par mois')
    plt.xlabel('Mois')
    plt.ylabel('Nombre de séances')
    
    # Ajouter les valeurs sur les barres
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height)}',
                ha='center', va='bottom')
    
    # Ajuster la mise en page
    plt.tight_layout()
    
    # Sauvegarder le graphique
    plt.savefig('sessions_r107_tp_a1.png')
    print("\nGraphique sauvegardé sous 'sessions_r107_tp_a1.png'")

def main():
    filename = "ADE_RT1_Septembre2023_Decembre2023.ics"  # Changement du nom de fichier
    try:
        # Extraire les séances
        sessions = extract_tp_sessions(filename)
        
        if not sessions:
            print("\nAucune séance de TP R1.07 trouvée pour le groupe A1")
            return
        
        # Compter les séances par mois
        months_count = count_sessions_by_month(sessions)
        
        # Afficher les résultats
        print("\nNombre de séances de TP R1.07 par mois :")
        for month in sorted(months_count.keys()):
            print(f"Mois {month}: {months_count[month]} séances")
        
        # Créer et sauvegarder le graphique
        create_bar_chart(months_count)
        
    except FileNotFoundError:
        print(f"\nErreur: Le fichier {filename} n'a pas été trouvé.")
        print("Assurez-vous d'avoir téléchargé le fichier depuis Moodle.")
    except Exception as e:
        print(f"\nErreur lors du traitement: {str(e)}")

if __name__ == "__main__":
    main()