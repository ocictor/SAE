def parse_ics_datetime(dt_str):
    """Convertit une date au format ICS en format lisible"""
    if not dt_str:  # Vérification si la chaîne est vide
        return "01-01-2024", "00:00"  # Valeurs par défaut
    
    try:
        year = dt_str[0:4]
        month = dt_str[4:6]
        day = dt_str[6:8]
        hour = dt_str[9:11]
        minute = dt_str[11:13]
        return f"{day}-{month}-{year}", f"{hour}:{minute}"
    except IndexError:
        return "01-01-2024", "00:00"  # En cas d'erreur de format

def calculate_duration(start_dt, end_dt):
    """Calcule la durée entre deux dates ICS"""
    try:
        # Convertir en minutes depuis minuit
        start_minutes = int(start_dt[9:11]) * 60 + int(start_dt[11:13])
        end_minutes = int(end_dt[9:11]) * 60 + int(end_dt[11:13])
        
        # Calculer la différence
        duration_minutes = end_minutes - start_minutes
        if duration_minutes < 0:  # Si la durée est négative
            duration_minutes = 0
            
        hours = duration_minutes // 60
        minutes = duration_minutes % 60
        
        return f"{hours:02d}:{minutes:02d}"
    except (IndexError, ValueError):
        return "00:00"  # En cas d'erreur de format

def extract_event_info(filename):
    """Extrait les informations d'un événement depuis un fichier ICS"""
    event_data = {
        'uid': '',
        'dtstart': '',
        'dtend': '',
        'summary': '',
        'location': '',
        'description': ''
    }
    
    in_event = False
    with open(filename, 'r', encoding='utf-8') as file:
        for line in file:
            line = line.strip()
            if line == "BEGIN:VEVENT":
                in_event = True
                continue
            elif line == "END:VEVENT":
                in_event = False
                break
                
            if in_event and ':' in line:
                key, value = line.split(':', 1)
                key = key.lower()  # Convertir en minuscules pour la comparaison
                if key in event_data:
                    event_data[key] = value
    
    return event_data

def format_pseudo_csv(event_data):
    """Formate les données de l'événement en pseudo-CSV"""
    # Extraire la date et l'heure de début
    date, heure = parse_ics_datetime(event_data['dtstart'])
    
    # Calculer la durée
    duree = calculate_duration(event_data['dtstart'], event_data['dtend'])
    
    # Déterminer la modalité (par défaut CM)
    modalite = "CM"
    if "TD" in event_data['description']:
        modalite = "TD"
    elif "TP" in event_data['description']:
        modalite = "TP"
    
    # Extraire le professeur et le groupe de la description
    description_parts = event_data['description'].split('\\n')
    prof = "vide"
    groupe = "vide"
    
    for part in description_parts:
        if not part.startswith('(') and not part.startswith('\\'):
            if "RT1-" in part:
                groupe = part.strip()
            elif part.strip():
                prof = part.strip()
    
    # Construire la chaîne pseudo-CSV
    pseudo_csv = f"{event_data['uid']};{date};{heure};{duree};{modalite};"
    pseudo_csv += f"{event_data['summary']};{event_data['location']};{prof};{groupe}"
    
    return pseudo_csv

def main():
    filename = "evenementSAE_15.ics"
    try:
        print("Lecture du fichier", filename)
        
        # Extraire les informations de l'événement
        event_data = extract_event_info(filename)
        
        # Afficher les données brutes pour le débogage
        print("\nDonnées extraites :")
        for key, value in event_data.items():
            print(f"{key}: {value}")
        
        # Formater en pseudo-CSV
        result = format_pseudo_csv(event_data)
        
        # Afficher le résultat
        print("\nRésultat au format pseudo-CSV :")
        print(result)
        
    except FileNotFoundError:
        print(f"Erreur: Le fichier {filename} n'a pas été trouvé.")
    except Exception as e:
        print(f"Erreur lors du traitement: {str(e)}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    main()