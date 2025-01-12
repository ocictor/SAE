def parse_ics_datetime(dt_str):
    """Convertit une date au format ICS en format lisible"""
    year = dt_str[0:4]
    month = dt_str[4:6]
    day = dt_str[6:8]
    hour = dt_str[9:11]
    minute = dt_str[11:13]
    return f"{day}-{month}-{year}", f"{hour}:{minute}"

def calculate_duration(start_dt, end_dt):
    """Calcule la durée entre deux dates ICS"""
    start_minutes = int(start_dt[9:11]) * 60 + int(start_dt[11:13])
    end_minutes = int(end_dt[9:11]) * 60 + int(end_dt[11:13])
    duration_minutes = end_minutes - start_minutes
    hours = duration_minutes // 60
    minutes = duration_minutes % 60
    return f"{hours:02d}:{minutes:02d}"

def extract_events(filename):
    """Extrait tous les événements d'un fichier ICS"""
    events = []
    current_event = None
    
    with open(filename, 'r', encoding='utf-8') as file:
        for line in file:
            line = line.strip()
            if line == "BEGIN:VEVENT":
                current_event = {}
            elif line == "END:VEVENT":
                if current_event:
                    events.append(current_event)
                current_event = None
            elif current_event is not None and ':' in line:
                key, value = line.split(':', 1)
                current_event[key] = value
    
    return events

def format_pseudo_csv(event):
    """Formate un événement en format pseudo-CSV"""
    # Extraire la date et l'heure
    date, heure = parse_ics_datetime(event['DTSTART'])
    
    # Calculer la durée
    duree = calculate_duration(event['DTSTART'], event['DTEND'])
    
    # Déterminer la modalité
    modalite = "CM"
    if "TD" in event.get('DESCRIPTION', ''):
        modalite = "TD"
    elif "TP" in event.get('DESCRIPTION', ''):
        modalite = "TP"
    
    # Extraire les informations de la description
    description = event.get('DESCRIPTION', '')
    description_parts = description.split('\\n')
    prof = "vide"
    groupe = "vide"
    
    for part in description_parts:
        if not part.startswith('(') and not part.startswith('\\'):
            if "RT1-" in part:
                groupe = part.strip()
            elif part.strip():
                prof = part.strip()
    
    # Construire la chaîne pseudo-CSV
    return f"{event.get('UID', 'vide')};{date};{heure};{duree};{modalite};" \
           f"{event.get('SUMMARY', 'vide')};{event.get('LOCATION', 'vide')};{prof};{groupe}"

def main():
    filename = "evenementSAE_15.ics"  # Correction du nom du fichier
    try:
        # Extraire tous les événements
        events = extract_events(filename)
        
        # Convertir chaque événement en format pseudo-CSV
        for event in events:
            pseudo_csv = format_pseudo_csv(event)
            print(pseudo_csv)
            
    except FileNotFoundError:
        print(f"Erreur: Le fichier {filename} n'a pas été trouvé.")
    except Exception as e:
        print(f"Erreur lors du traitement: {str(e)}")

if __name__ == "__main__":
    main()