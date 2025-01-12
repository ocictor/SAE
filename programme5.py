import markdown
from datetime import datetime
import os

def parse_ics_datetime(dt_str):
    """Convertit une date au format ICS en format lisible"""
    try:
        year = int(dt_str[0:4])
        month = int(dt_str[4:6])
        day = int(dt_str[6:8])
        hour = int(dt_str[9:11])
        minute = int(dt_str[11:13])
        return f"{day:02d}-{month:02d}-{year}", f"{hour:02d}:{minute:02d}"
    except (IndexError, ValueError):
        return "01-01-2024", "00:00"

def calculate_duration(start_dt, end_dt):
    """Calcule la durée entre deux dates ICS"""
    try:
        start_minutes = int(start_dt[9:11]) * 60 + int(start_dt[11:13])
        end_minutes = int(end_dt[9:11]) * 60 + int(end_dt[11:13])
        duration_minutes = max(0, end_minutes - start_minutes)
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
                    if "R1.07" in current_event.get('SUMMARY', '') and "A1" in current_event.get('DESCRIPTION', ''):
                        date, heure = parse_ics_datetime(current_event.get('DTSTART', ''))
                        duree = calculate_duration(current_event.get('DTSTART', ''), current_event.get('DTEND', ''))
                        
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
    
    return sorted(sessions, key=lambda x: x['date'])

def generate_markdown_report(sessions):
    """Génère le rapport en format Markdown"""
    markdown_content = """# Rapport des séances R1.07

## Tableau des séances

| Date | Heure | Durée | Type |
|------|--------|--------|------|
"""
    
    for session in sessions:
        markdown_content += f"| {session['date']} | {session['heure']} | {session['duree']} | {session['type']} |\n"
    
    markdown_content += """
## Graphique des séances

![Graphique des séances de TP](sessions_r107_tp_a1.png)
"""
    
    return markdown_content

def generate_html(markdown_content):
    """Génère le fichier HTML final avec style"""
    # Convertir le Markdown en HTML
    html_content = markdown.markdown(markdown_content, extensions=['tables'])
    
    # Ajouter le style CSS et créer le document HTML complet
    complete_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Rapport R1.07</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: center;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        h1, h2 {{
            color: #333;
        }}
        img {{
            max-width: 100%;
            height: auto;
            margin: 20px 0;
        }}
    </style>
</head>
<body>
{html_content}
</body>
</html>"""
    
    return complete_html

def main():
    filename = "ADE_RT1_Septembre2023_Decembre2023.ics"  # Changement pour utiliser le fichier complet
    try:
        # Vérifier que le graphique existe
        if not os.path.exists("sessions_r107_tp_a1.png"):
            print("Attention: Le graphique 'sessions_r107_tp_a1.png' n'a pas été trouvé.")
            print("Exécutez d'abord le Programme4.py pour générer le graphique.")
            return
        
        # Extraire les séances
        sessions = extract_r107_sessions(filename)
        
        if not sessions:
            print("Aucune séance R1.07 trouvée pour le groupe A1")
            return
            
        # Générer le contenu Markdown
        markdown_content = generate_markdown_report(sessions)
        
        # Convertir en HTML
        html_content = generate_html(markdown_content)
        
        # Sauvegarder le fichier HTML
        with open('rapport_r107.html', 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        print("Rapport HTML généré avec succès : rapport_r107.html")
        
    except FileNotFoundError:
        print(f"Erreur: Le fichier {filename} n'a pas été trouvé.")
    except Exception as e:
        print(f"Erreur lors du traitement: {str(e)}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    main()