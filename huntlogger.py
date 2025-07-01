from flask import Flask, render_template, request, jsonify, send_file,session,redirect
import sqlite3
import os
import re
import json
import csv
import pandas as pd
from datetime import datetime, timedelta
import shutil
from werkzeug.utils import secure_filename
import hashlib


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Database configuration
DB_FILE = "hunts_ed.db"
BACKUP_DIR = "backups"

# Hunt catalog by level
HUNT_CATALOG = {
    'ED': {
        8: ["Rotworms Liberty Bay/Darashia", "Swamp Trolls Port Hope/Venore",
           "Crocodiles Port Hope", "Larva Ankh (Sorcerer)", "Ankh Library Tomb (Sorcerer)"],
        12: ["Edron Forgotten Tomb", "Drefia Surface", "Amazon Camp (Profit)",
            "Cormaya Dwarf Mines"],
        13: ["Cyclops Mistrock/Mount Sternum"],
        14: ["Tarantulas Port Hope", "Poacher's Cave (Poachers + Hunters)",
            "Coryms Port Hope (Stealth Ring)"],
        15: ["Stonerefiners (Stealth Ring)", "Minotaurs Darashia (Stealth Ring)",
            "Cyclopolis", "Elves Yalahar"],
        20: ["Edron Earth Elementals", "Mutated Humans Yala"],
        28: ["Gargoyle Cave Meriana", "Upper Spike"],
        30: ["Coryms Port Hope (AOE)", "Chor", "Laguna Islands (Profit)",
            "Apes Banuta (Profit)", "Stonerefiners (AOE)", "Dryad Gardens",
            "Carniphilas Port Hope", "Mummy/Bonebeasts MOSL -3"],
        50: ["LB Wyrms SD", "Yalahar Cults", "Peninsula Tomb", "Haunted Treelings Vengoth",
            "Water Elementals Port Hope", "Nibelor Crystal Spiders",
            "Mother of Scarabs Lair", "Lion's Rock Lions"],
        60: ["Middle Spike"],
        70: ["Mutated Tigers Yalahar (Profit)", "Krailos Ogres Surface"],
        80: ["Giant Spiders Port Hope", "Ice Witch Temple", "Muggy Plains",
            "Issavi Surafce (SD)", "Hive Surface", "Feyrist Surface"],
        100: ["Old Masonry (Death portal)", "Quaras Liberty Bay", "Grimvale -4",
             "Krailos Bug Cave", "Putrid Mummy", "Calassa", "Sunken Quarter",
             "Souleater Mountain", "Edron Vampire Crypt", "Dragon Lords POI",
             "Dragon Lords Fenrock", "Edron Old Fortress -2", "Ravenous Lava Lurkers"],
        110: ["Exotic Cave", "Iksupan", "Edron Were South"],
        120: ["Lizard Chosens", "Lizard City", "Brimstone Bugs WOTE",
             "Edron Old Fortress -3", "Carlin Cults"],
        130: ["Goroma Medusa/Serpents (Talahu)", "Oramond East Minos",
             "Behemoths Forbidden Lands", "Dark Faun Cave Feyrist", "Glooth Bandits",
             "Elder Wyrms Drefia"],
        150: ["Deeplings Library Fiehonja", "Oramond West"],
        200: ["Okolnir (Sorcerer)", "Deeper Banuta (Sorcerer)", "Goroma Demons Avalanche",
             "Mini Rosha", "Pirats"],
        250: ["Diremaw Task Area (AOE)", "INQ Hellfires + Spectres", "Yalahar Grim Reapers",
             "Lower Spike", "Carnivors"],
        300: ["Draken Walls", "Winter Court", "Summer Court", "Werehyaenas",
             "Candia Nibblemaws", "Burster Spectres", "Oramond Wildlife Raid",
             "Gazer Spectre", "Drefia Grim Reapers (Sorcerer)"],
        350: ["Werelions"],
        400: ["Falcons", "Oramond Fury", "Ripper Spectres", "Warzone 4", "Warzone 5",
             "Warzone 6", "Cobras", "Oskayaat Weretigers", "Oskayaat Werecrocodiles"],
        500: ["Iksupan", "Dream Labrynith", "Marapur Turtles", "Otherworld",
             "Oramond Catacombs", "Girtablilu", "Issavi Goannas", "Flimsy Lost Souls",
             "Marapur Nagas"],
        600: ["Crypt Wardens -2", "Crypt Warriors", "Cursed Prospector", "Ingol",
             "Warzone 1/2/3"],
        700: ["Warzone 7"]
    }
}

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Usuário e senha são obrigatórios'}), 400

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hash_password(password)))
        conn.commit()
        return jsonify({'success': True, 'message': 'Usuário registrado com sucesso'})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Nome de usuário já em uso'}), 400
    finally:
        conn.close()
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user and user[1] == hash_password(password):
        session['user_id'] = user[0]
        return jsonify({'success': True, 'message': 'Login realizado com sucesso', 'user_id': user[0]})
    else:
        return jsonify({'error': 'Credenciais inválidas'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'success': True, 'message': 'Logout realizado com sucesso'})


def init_db():
    """Initialize database with all required tables"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Main hunts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS hunts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            data TEXT NOT NULL,
            duracao TEXT,
            xp INTEGER DEFAULT 0,
            xp_h INTEGER DEFAULT 0,
            raw_xp INTEGER DEFAULT 0,
            raw_xp_h INTEGER DEFAULT 0,
            dano_causado INTEGER DEFAULT 0,
            dano_sofrido INTEGER DEFAULT 0,
            cura INTEGER DEFAULT 0,
            lucro INTEGER DEFAULT 0,
            tipos_dano TEXT,
            fontes_dano TEXT,
            monstros TEXT,
            itens TEXT,
            notas TEXT,
            local_hunt TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Hunt catalog table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS hunt_catalog (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vocation TEXT NOT NULL,
            level INTEGER NOT NULL,
            hunt_name TEXT NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Goals table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS goals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            target_value INTEGER NOT NULL,
            current_value INTEGER DEFAULT 0,
            goal_type TEXT NOT NULL,
            deadline DATE,
            completed BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Indexes for performance
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_hunts_data ON hunts(data)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_hunts_xp_h ON hunts(xp_h)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_hunts_lucro ON hunts(lucro)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_catalog_level ON hunt_catalog(level)")

    # Populate hunt catalog if empty
    cursor.execute("SELECT COUNT(*) FROM hunt_catalog")
    if cursor.fetchone()[0] == 0:
        populate_hunt_catalog(cursor)

    conn.commit()
    conn.close()


def populate_hunt_catalog(cursor):
    """Populate the hunt catalog table with default data"""
    for vocation, levels in HUNT_CATALOG.items():
        for level, hunts in levels.items():
            for hunt_name in hunts:
                cursor.execute("""
                    INSERT INTO hunt_catalog (vocation, level, hunt_name) 
                    VALUES (?, ?, ?)
                """, (vocation, level, hunt_name))

def create_backup():
    """Create automatic backup of the database"""
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(BACKUP_DIR, f"hunts_backup_{timestamp}.db")
    shutil.copy2(DB_FILE, backup_file)
    return backup_file
def parse_hunt_log(text):
    """Parsers and calculates XP/h from XP Gain and Raw XP Gain correctly."""
    import json
    import re
    from datetime import datetime

    def extract(pattern, default="0"):
        try:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).replace(",", "").replace(".", "")
            return default
        except:
            return default

    def extract_list(pattern, section_name):
        try:
            if section_name in text:
                section = text.split(section_name)[1].split('\n\n')[0]
                return re.findall(pattern, section)
            return []
        except:
            return []

    required_markers = ['XP Gain:', 'Session:', 'Damage:', 'Healing:']
    if not all(marker in text for marker in required_markers):
        raise ValueError("Log format not recognized. Please check if you pasted the correct hunt log.")

    try:
        # Extrações principais
        xp_gain = int(extract(r"XP Gain:\s*([\d,]+)", "0"))
        raw_xp_gain = int(extract(r"Raw XP Gain:\s*([\d,]+)", "0"))
        session_str = extract(r"Session:\s*(\d+):(\d+)", "0:0")

        h, m = map(int, session_str.split(":"))
        session_minutes = max(h * 60 + m, 1)

        xp_h = (xp_gain * 60) // session_minutes
        raw_xp_h = (raw_xp_gain * 60) // session_minutes

        monsters_killed = extract_list(r"(\d+)x ([a-zA-Z ]+)", "")
        looted_items = []
        if "Looted Items:" in text:
            looted_items = re.findall(r"(\d+)x (a .+)", text.split("Looted Items:")[1])

        damage_types = []
        if "Damage Types" in text:
            section = text.split("Damage Types")[1].split("Damage Sources")[0] if "Damage Sources" in text else text.split("Damage Types")[1]
            damage_types = re.findall(r"\s+([a-zA-Z ]+)\s+([\d,]+)\s+\((\d+\.\d+)%\)", section)

        damage_sources = []
        if "Damage Sources" in text:
            section = text.split("Damage Sources")[1]
            damage_sources = re.findall(r"\s+([a-zA-Z ()]+)\s+([\d,]+)\s+\((\d+\.\d+)%\)", section)

        return {
            "data": datetime.now().strftime("%d/%m/%Y"),
            "xp": xp_gain,
            "xp_h": xp_h,
            "raw_xp": raw_xp_gain,
            "raw_xp_h": raw_xp_h,
            "dano_causado": int(extract(r"Damage:\s*([\d,]+)", "0")),
            "dano_sofrido": int(extract(r"Total:\s*([\d,]+)", "0")),
            "cura": int(extract(r"Healing:\s*([\d,]+)", "0")),
            "lucro": int(extract(r"Balance:\s*([\d,\-]+)", "0")),
            "duracao": f"{h:02d}:{m:02d}h",
            "tipos_dano": json.dumps(damage_types),
            "fontes_dano": json.dumps(damage_sources),
            "monstros": json.dumps(monsters_killed),
            "itens": json.dumps(looted_items),
        }

    except Exception as e:
        raise ValueError(f"Error parsing log: {str(e)}")


# Routes
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect('/login.html')
    return render_template('index.html')


@app.route('/api/hunts', methods=['GET'])
def get_hunts():
    """Get all hunts with filtering and pagination"""
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))
    
    # Filters
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    min_xp_h = request.args.get('min_xp_h')
    min_lucro = request.args.get('min_lucro')
    local_hunt = request.args.get('local_hunt')
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Build query with filters
    query = "SELECT * FROM hunts WHERE 1=1"
    params = []
    
    if date_from:
        query += " AND data >= ?"
        params.append(date_from)
    
    if date_to:
        query += " AND data <= ?"
        params.append(date_to)
    
    if min_xp_h:
        query += " AND xp_h >= ?"
        params.append(int(min_xp_h))
    
    if min_lucro:
        query += " AND lucro >= ?"
        params.append(int(min_lucro))
    
    if local_hunt:
        query += " AND local_hunt LIKE ?"
        params.append(f"%{local_hunt}%")
    
    # Count total records
    count_query = f"SELECT COUNT(*) FROM ({query})"
    cursor.execute(count_query, params)
    total = cursor.fetchone()[0]
    
    # Add pagination
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([per_page, (page - 1) * per_page])
    
    cursor.execute(query, params)
    hunts = cursor.fetchall()
    conn.close()
    
    # Convert to dict format
    hunt_list = []
    for hunt in hunts:
        hunt_dict = {
            'id': hunt[0],
            'data': hunt[1],
            'duracao': hunt[2],
            'xp': hunt[3],
            'xp_h': hunt[4],
            'dano_causado': hunt[5],
            'dano_sofrido': hunt[6],
            'cura': hunt[7],
            'lucro': hunt[8],
            'tipos_dano': json.loads(hunt[9]) if hunt[9] else [],
            'fontes_dano': json.loads(hunt[10]) if hunt[10] else [],
            'monstros': json.loads(hunt[11]) if hunt[11] else [],
            'itens': json.loads(hunt[12]) if hunt[12] else [],
            'notas': hunt[13],
            'local_hunt': hunt[14] if len(hunt) > 14 else ''
        }
        hunt_list.append(hunt_dict)
    
    return jsonify({
        'hunts': hunt_list,
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': (total + per_page - 1) // per_page
    })

@app.route('/api/hunts', methods=['POST'])
def save_hunt():
    """Salvar uma nova hunt vinculada ao usuário autenticado"""
    if 'user_id' not in session:
        return jsonify({'error': 'Usuário não autenticado'}), 401

    data = request.json
    user_id = session['user_id']

    fields = (
        'data', 'duracao', 'xp', 'xp_h', 'raw_xp', 'raw_xp_h', 'dano_causado', 'dano_sofrido',
        'cura', 'lucro', 'tipos_dano', 'fontes_dano', 'monstros', 'itens', 'notas', 'local_hunt'
    )
    values = [data.get(field, None) for field in fields]

    try:
        create_backup()

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute(f"""
            INSERT INTO hunts (user_id, {', '.join(fields)})
            VALUES (?, {', '.join(['?'] * len(fields))})
        """, [user_id] + values)
        conn.commit()
        conn.close()

        return jsonify({'success': True, 'message': 'Hunt registrada com sucesso'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/hunts/<int:hunt_id>', methods=['PUT'])
def update_hunt(hunt_id):
    """Update an existing hunt"""
    try:
        data = request.json
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Build update query dynamically
        fields = []
        values = []
        
        for field in ['notas', 'local_hunt', 'xp', 'xp_h', 'lucro']:
            if field in data:
                fields.append(f"{field} = ?")
                values.append(data[field])
        
        if not fields:
            return jsonify({'error': 'No fields to update'}), 400
        
        fields.append("updated_at = ?")
        values.append(datetime.now().isoformat())
        values.append(hunt_id)
        
        query = f"UPDATE hunts SET {', '.join(fields)} WHERE id = ?"
        cursor.execute(query, values)
        
        if cursor.rowcount == 0:
            return jsonify({'error': 'Hunt not found'}), 404
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Hunt updated successfully'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/hunts/<int:hunt_id>', methods=['DELETE'])
def delete_hunt(hunt_id):
    """Delete a hunt"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM hunts WHERE id = ?", (hunt_id,))
        
        if cursor.rowcount == 0:
            return jsonify({'error': 'Hunt not found'}), 404
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Hunt deleted successfully'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/statistics')
def get_statistics():
    """Get hunt statistics"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Basic stats
    cursor.execute("""
        SELECT 
            COUNT(*) as total_hunts,
            SUM(xp) as total_xp,
            AVG(xp_h) as avg_xp_h,
            MAX(xp_h) as max_xp_h,
            SUM(lucro) as total_profit,
            AVG(lucro) as avg_profit,
            MAX(lucro) as max_profit,
            MIN(lucro) as min_profit
        FROM hunts
    """)
    
    stats = cursor.fetchone()
    
    # Recent performance (last 7 days)
    week_ago = (datetime.now() - timedelta(days=7)).strftime("%d/%m/%Y")
    cursor.execute("""
        SELECT AVG(xp_h), AVG(lucro), COUNT(*)
        FROM hunts 
        WHERE data >= ?
    """, (week_ago,))
    
    recent_stats = cursor.fetchone()
    
    # Monthly progression
    cursor.execute("""
        SELECT 
            substr(data, 4, 7) as month_year,
            AVG(xp_h) as avg_xp_h,
            AVG(lucro) as avg_profit,
            COUNT(*) as hunt_count
        FROM hunts 
        GROUP BY substr(data, 4, 7)
        ORDER BY month_year DESC
        LIMIT 6
    """)
    
    monthly_data = cursor.fetchall()
    
    conn.close()
    
    return jsonify({
        'total_hunts': stats[0] or 0,
        'total_xp': stats[1] or 0,
        'avg_xp_h': round(stats[2] or 0, 2),
        'max_xp_h': stats[3] or 0,
        'total_profit': stats[4] or 0,
        'avg_profit': round(stats[5] or 0, 2),
        'max_profit': stats[6] or 0,
        'min_profit': stats[7] or 0,
        'recent_avg_xp_h': round(recent_stats[0] or 0, 2),
        'recent_avg_profit': round(recent_stats[1] or 0, 2),
        'recent_hunt_count': recent_stats[2] or 0,
        'monthly_progression': [
            {
                'month': row[0],
                'avg_xp_h': round(row[1], 2),
                'avg_profit': round(row[2], 2),
                'hunt_count': row[3]
            } for row in monthly_data
        ]
    })


@app.route('/api/logout', methods=['POST'])
@app.route('/api/logout', methods=['POST'])

def user_logout():
    session.pop('user_id', None)
    # Retorne apenas sucesso, o redirecionamento será feito pelo frontend
    return jsonify({'success': True, 'message': 'Logout realizado com sucesso'})

@app.route('/api/check-login')
def check_login():
    if 'user_id' in session:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return jsonify({'logged_in': True, 'username': user[0]})
    return jsonify({'logged_in': False})

@app.route('/api/catalog-locations', methods=['GET'])
def get_catalog_locations():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT hunt_name FROM hunt_catalog ORDER BY hunt_name ASC")
    locais = [row[0] for row in cursor.fetchall()]
    conn.close()
    return jsonify(locais)

@app.route('/api/hunt-catalog')
def get_hunt_catalog():
    """Get hunt catalog"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM hunt_catalog ORDER BY level, hunt_name")
    catalog = cursor.fetchall()
    conn.close()
    
    catalog_dict = {}
    for item in catalog:
        vocation = item[1]
        level = item[2]
        hunt_name = item[3]
        
        if vocation not in catalog_dict:
            catalog_dict[vocation] = {}
        if level not in catalog_dict[vocation]:
            catalog_dict[vocation][level] = []
        
        catalog_dict[vocation][level].append({
            'id': item[0],
            'name': hunt_name,
            'description': item[4] or ''
        })
    
    return jsonify(catalog_dict)

@app.route('/api/hunt-catalog', methods=['POST'])
def add_hunt_to_catalog():
    """Add new hunt to catalog"""
    try:
        data = request.json
        vocation = data.get('vocation', 'ED')
        level = int(data.get('level', 0))
        hunt_name = data.get('hunt_name', '')
        description = data.get('description', '')
        
        if not hunt_name:
            return jsonify({'error': 'Hunt name is required'}), 400
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO hunt_catalog (vocation, level, hunt_name, description)
            VALUES (?, ?, ?, ?)
        """, (vocation, level, hunt_name, description))
        
        hunt_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Hunt added to catalog successfully',
            'hunt_id': hunt_id
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/hunt-catalog/<int:catalog_id>', methods=['DELETE'])
def delete_hunt_from_catalog(catalog_id):
    """Delete hunt from catalog"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM hunt_catalog WHERE id = ?", (catalog_id,))
        
        if cursor.rowcount == 0:
            return jsonify({'error': 'Hunt not found in catalog'}), 404
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Hunt removed from catalog'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/<format>')
def export_data(format):
    """Export data in different formats"""
    try:
        conn = sqlite3.connect(DB_FILE)
        
        if format == 'csv':
            df = pd.read_sql_query("SELECT * FROM hunts ORDER BY id DESC", conn)
            filename = f"hunts_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            df.to_csv(filename, index=False)
            conn.close()
            return send_file(filename, as_attachment=True)
        
        elif format == 'excel':
            df = pd.read_sql_query("SELECT * FROM hunts ORDER BY id DESC", conn)
            filename = f"hunts_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
            df.to_excel(filename, index=False)
            conn.close()
            return send_file(filename, as_attachment=True)
        
        elif format == 'txt':
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM hunts ORDER BY id DESC")
            hunts = cursor.fetchall()
            
            filename = f"hunts_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                for hunt in hunts:
                    f.write(f"Registro da Hunt #{hunt[0]}\n")
                    f.write(f"Data da Hunt: {hunt[1]}\n")
                    f.write(f"Duração da sessão: {hunt[2]}\n")
                    f.write(f"Experiência obtida: {hunt[3]} XP\n")
                    f.write(f"Taxa de XP/hora: {hunt[4]} XP/h\n")
                    f.write(f"Dano causado: {hunt[5]}\n")
                    f.write(f"Dano recebido: {hunt[6]}\n")
                    f.write(f"Total de cura realizada: {hunt[7]}\n")
                    f.write(f"Balanço financeiro: {hunt[8]} gp\n")
                    f.write(f"Local da Hunt: {hunt[14] if len(hunt) > 14 else 'N/A'}\n")
                    f.write(f"Observações: {hunt[13]}\n")
                    f.write(f"{'='*80}\n\n")
            
            conn.close()
            return send_file(filename, as_attachment=True)
        
        else:
            return jsonify({'error': 'Invalid export format'}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/login.html')
def login_page():
    return render_template('login.html')

@app.route('/register.html')
def register_page():
    return render_template('register.html')

@app.route('/api/hunt-locations', methods=['GET'])
def get_hunt_locations():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT local_hunt FROM hunts WHERE local_hunt IS NOT NULL AND TRIM(local_hunt) != '' ORDER BY local_hunt ASC")
    locais = [row[0] for row in cursor.fetchall()]
    conn.close()
    return jsonify(locais)


if __name__ == '__main__':
    # Ensure backup directory exists
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    
    # Initialize database
    init_db()
    
    # Run the app
    app.run(debug=True, host='0.0.0.0', port=5000)


    if __name__ == '__main__':
   
        init_db()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
