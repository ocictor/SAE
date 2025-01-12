def parse_ics_datetime(dt_str):
    """Convertit une date au format ICS en format lisible"""
    if not dt_str:
        return "01-01-2024", "00:00"
    
    try:
        year = dt_str[0:4]
        month = dt_str[4:6]
        day = dt_str[6:8]
        hour = dt_str[9:11]
        minute = dt_str[11:13]
        return f"{day}-{month}-{year}", f"{hour}:{minute}"
    except IndexError:
        return "01-01-2024", "00:00"

def calculate_duration(start_dt, end_dt):
    """Calcule la durée entre deux dates ICS"""
    try:
        start_minutes = int(start_dt[9:11]) * 60 + int(start_dt[11:13])
        end_minutes = int(end_dt[9:11]) * 60 + int(end_dt[11:13])
        duration_minutes = end_minutes - start_minutes
        hours = duration_minutes // 60
        minutes = duration_minutes % 60
        return f"{hours:02d}:{minutes:02d}"
    except (IndexError, ValueError):
        return "00:00"

def extract_r107_sessions(filename):
    """Extrait les séances de R1.07"""
    sessions = []
    current_event = None
    
    with open(filename, 'r', encoding='utf-8') as file:
        for line in file:
            line = line.strip()
            if line == "BEGIN:VEVENT":
                current_event = {}
            elif line == "END:VEVENT":
                if current_event:
                    # Vérifier si c'est un événement R1.07 pour le groupe A1
                    if "R1.07" in current_event.get('SUMMARY', '') and "A1" in current_event.get('DESCRIPTION', ''):
                        date, heure = parse_ics_datetime(current_event.get('DTSTART', ''))
                        duree = calculate_duration(current_event.get('DTSTART', ''), current_event.get('DTEND', ''))
                        
                        # Déterminer le type de séance
                        type_seance = "CM"
                        if "TD" in current_event.get('DESCRIPTION', ''):
                            type_seance = "TD"
                        elif "TP" in current_event.get('DESCRIPTION', ''):
                            type_seance = "TP"
                            
                        sessions.append({
                            'date': date,
                            'heure': heure,
                            'duree': duree,
                            'type': type_seance
                        })
                current_event = None
            elif current_event is not None and ':' in line:
                key, value = line.split(':', 1)
                current_event[key] = value
    
    return sessions

def main():
    filename = "evenementSAE_15.ics"
    try:
        # Extraire les séances R1.07
        sessions = extract_r107_sessions(filename)
        
        # Afficher les résultats dans un format tableau
        print("\nSéances R1.07 pour le groupe A1:")
        print("=" * 50)
        print(f"{'Date':^12} | {'Heure':^8} | {'Durée':^8} | {'Type':^6}")
        print("-" * 50)
        
        for session in sorted(sessions, key=lambda x: x['date']):
            print(f"{session['date']:^12} | {session['heure']:^8} | {session['duree']:^8} | {session['type']:^6}")
            
    except FileNotFoundError:
        print(f"Erreur: Le fichier {filename} n'a pas été trouvé.")
    except Exception as e:
        print(f"Erreur lors du traitement: {str(e)}")

if __name__ == "__main__":
    main()