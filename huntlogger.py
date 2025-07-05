from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for
import sqlite3
import os
import re
import json
import pandas as pd
from datetime import datetime, timedelta
import shutil
from werkzeug.utils import secure_filename
import hashlib
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hunt-logger-secret-key-2024'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max file size

# Configurações
DB_FILE = "hunts.db"
BACKUP_DIR = "backups"
UPLOAD_DIR = "uploads/videos"
ALLOWED_EXTENSIONS = {'mp4', 'avi', 'mov', 'mkv', 'webm', 'flv'}

def hash_password(password):
    """Hash da senha usando SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def allowed_file(filename):
    """Verifica se o arquivo tem extensão permitida"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def init_db():
    """Inicializa o banco de dados com as tabelas necessárias"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Tabela de usuários
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Tabela principal de hunts
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS hunts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            data TEXT NOT NULL,
            duracao TEXT NOT NULL,
            local_hunt TEXT NOT NULL,
            xp INTEGER DEFAULT 0,
            xp_h INTEGER DEFAULT 0,
            raw_xp INTEGER DEFAULT 0,
            raw_xp_h INTEGER DEFAULT 0,
            lucro INTEGER DEFAULT 0,
            monstros TEXT,
            itens TEXT,
            video_filename TEXT,
            notas TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Tabela de locais de caça (dinâmica baseada no que o usuário caça)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS hunt_locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            location_name TEXT NOT NULL,
            first_hunt_date TEXT,
            total_hunts INTEGER DEFAULT 1,
            avg_xp_h INTEGER DEFAULT 0,
            avg_profit INTEGER DEFAULT 0,
            best_xp_h INTEGER DEFAULT 0,
            best_profit INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, location_name)
        )
    """)

    # Índices para performance
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_hunts_user_data ON hunts(user_id, data)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_hunts_xp_h ON hunts(xp_h DESC)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_hunts_lucro ON hunts(lucro DESC)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_locations_user ON hunt_locations(user_id)")

    conn.commit()
    conn.close()

def create_backup():
    """Cria backup automático do banco de dados"""
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(BACKUP_DIR, f"hunts_backup_{timestamp}.db")
    shutil.copy2(DB_FILE, backup_file)
    return backup_file

def parse_hunt_log(text):
    """Analisa e extrai dados do log de hunt usando Hunt Analyser"""
    def extract_number(pattern, default=0):
        try:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return int(match.group(1).replace(",", "").replace(".", ""))
            return default
        except:
            return default

    def extract_list(pattern, text_section):
        try:
            return re.findall(pattern, text_section)
        except:
            return []

    # Verificar se é um log válido
    required_markers = ['XP Gain:', 'Session:', 'Balance:']
    if not all(marker in text for marker in required_markers):
        raise ValueError("Formato de log não reconhecido. Verifique se colou o log correto do Hunt Analyser.")

    try:
        # Extrair dados principais
        xp_gain = extract_number(r"XP Gain:\s*([\d,]+)")
        raw_xp_gain = extract_number(r"Raw XP Gain:\s*([\d,]+)")
        
        # Extrair tempo de sessão
        session_match = re.search(r"Session:\s*(\d+):(\d+)", text)
        if session_match:
            hours = int(session_match.group(1))
            minutes = int(session_match.group(2))
            session_minutes = max(hours * 60 + minutes, 1)
            duracao = f"{hours:02d}:{minutes:02d}h"
        else:
            session_minutes = 60
            duracao = "01:00h"

        # Calcular XP/h
        xp_h = (xp_gain * 60) // session_minutes if session_minutes > 0 else 0
        raw_xp_h = (raw_xp_gain * 60) // session_minutes if session_minutes > 0 else 0

        # Extrair lucro
        lucro = extract_number(r"Balance:\s*([\d,\-]+)")

        # Extrair monstros mortos
        monsters_killed = []
        if "Killed Monsters:" in text:
            killed_section = text.split("Killed Monsters:")[1]
            if "Looted Items:" in killed_section:
                killed_section = killed_section.split("Looted Items:")[0]
            monsters_killed = extract_list(r"(\d+)x\s+(.+)", killed_section)

        # Extrair itens coletados
        looted_items = []
        if "Looted Items:" in text:
            looted_section = text.split("Looted Items:")[1]
            looted_items = extract_list(r"(\d+)x\s+(.+)", looted_section)

        return {
            "data": datetime.now().strftime("%d/%m/%Y"),
            "duracao": duracao,
            "xp": xp_gain,
            "xp_h": xp_h,
            "raw_xp": raw_xp_gain,
            "raw_xp_h": raw_xp_h,
            "lucro": lucro,
            "monstros": json.dumps(monsters_killed),
            "itens": json.dumps(looted_items),
        }

    except Exception as e:
        raise ValueError(f"Erro ao processar log: {str(e)}")

def update_hunt_location(user_id, location_name, xp_h, lucro):
    """Atualiza ou cria estatísticas do local de caça"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Verificar se o local já existe
    cursor.execute("""
        SELECT id, total_hunts, avg_xp_h, avg_profit, best_xp_h, best_profit
        FROM hunt_locations 
        WHERE user_id = ? AND location_name = ?
    """, (user_id, location_name))
    
    location = cursor.fetchone()
    
    if location:
        # Atualizar estatísticas existentes
        location_id, total_hunts, avg_xp_h, avg_profit, best_xp_h, best_profit = location
        
        new_total_hunts = total_hunts + 1
        new_avg_xp_h = ((avg_xp_h * total_hunts) + xp_h) // new_total_hunts
        new_avg_profit = ((avg_profit * total_hunts) + lucro) // new_total_hunts
        new_best_xp_h = max(best_xp_h, xp_h)
        new_best_profit = max(best_profit, lucro)
        
        cursor.execute("""
            UPDATE hunt_locations 
            SET total_hunts = ?, avg_xp_h = ?, avg_profit = ?, 
                best_xp_h = ?, best_profit = ?, updated_at = ?
            WHERE id = ?
        """, (new_total_hunts, new_avg_xp_h, new_avg_profit, 
              new_best_xp_h, new_best_profit, datetime.now().isoformat(), location_id))
    else:
        # Criar novo local
        cursor.execute("""
            INSERT INTO hunt_locations 
            (user_id, location_name, first_hunt_date, total_hunts, avg_xp_h, avg_profit, best_xp_h, best_profit)
            VALUES (?, ?, ?, 1, ?, ?, ?, ?)
        """, (user_id, location_name, datetime.now().strftime("%d/%m/%Y"), 
              xp_h, lucro, xp_h, lucro))
    
    conn.commit()
    conn.close()

# === ROTAS DE AUTENTICAÇÃO ===

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Usuário e senha são obrigatórios'}), 400

    if len(password) < 6:
        return jsonify({'error': 'Senha deve ter pelo menos 6 caracteres'}), 400

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", 
                      (username, hash_password(password)))
        conn.commit()
        return jsonify({'success': True, 'message': 'Usuário registrado com sucesso'})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Nome de usuário já existe'}), 400
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
        session['username'] = username
        return jsonify({'success': True, 'message': 'Login realizado com sucesso'})
    else:
        return jsonify({'error': 'Credenciais inválidas'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True, 'message': 'Logout realizado com sucesso'})

@app.route('/api/check-login')
def check_login():
    if 'user_id' in session:
        return jsonify({'logged_in': True, 'username': session.get('username', '')})
    return jsonify({'logged_in': False})

# === ROTAS PRINCIPAIS ===

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect('/login.html')
    return render_template('index.html')

@app.route('/login.html')
def login_page():
    return render_template('login.html')

@app.route('/register.html')
def register_page():
    return render_template('register.html')

# === ROTAS DE HUNTS ===

@app.route('/api/hunts', methods=['GET'])
def get_hunts():
    if 'user_id' not in session:
        return jsonify({'error': 'Não autorizado'}), 401
        
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        offset = (page - 1) * per_page

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Contar total de hunts
        cursor.execute("SELECT COUNT(*) FROM hunts WHERE user_id = ?", (session['user_id'],))
        total = cursor.fetchone()[0]
        
        # Buscar hunts paginadas
        cursor.execute("""
            SELECT id, data, duracao, local_hunt, xp, xp_h, raw_xp, raw_xp_h, 
                   lucro, video_filename, notas, created_at
            FROM hunts 
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        """, (session['user_id'], per_page, offset))
        
        hunts = []
        for row in cursor.fetchall():
            hunts.append({
                'id': row[0],
                'data': row[1],
                'duracao': row[2],
                'local_hunt': row[3],
                'xp': row[4],
                'xp_h': row[5],
                'raw_xp': row[6],
                'raw_xp_h': row[7],
                'lucro': row[8],
                'video_filename': row[9],
                'notas': row[10],
                'created_at': row[11]
            })
        
        total_pages = (total + per_page - 1) // per_page
        
        return jsonify({
            'hunts': hunts,
            'page': page,
            'total_pages': total_pages,
            'total': total
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/hunts', methods=['POST'])
def save_hunt():
    if 'user_id' not in session:
        return jsonify({'error': 'Não autorizado'}), 401

    data = request.json
    log_text = data.get("log_text", "")
    local_hunt = data.get("local_hunt", "")
    notas = data.get("notas", "")
    
    if not log_text:
        return jsonify({'error': 'Log da hunt é obrigatório'}), 400
    
    if not local_hunt:
        return jsonify({'error': 'Local da hunt é obrigatório'}), 400

    try:
        # Processar o log
        parsed = parse_hunt_log(log_text)
        
        # Criar backup antes de salvar
        create_backup()

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Salvar hunt
        cursor.execute("""
            INSERT INTO hunts (user_id, data, duracao, local_hunt, xp, xp_h, raw_xp, raw_xp_h, 
                              lucro, monstros, itens, notas)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (session['user_id'], parsed['data'], parsed['duracao'], local_hunt,
              parsed['xp'], parsed['xp_h'], parsed['raw_xp'], parsed['raw_xp_h'],
              parsed['lucro'], parsed['monstros'], parsed['itens'], notas))
        
        conn.commit()
        conn.close()
        
        # Atualizar estatísticas do local
        update_hunt_location(session['user_id'], local_hunt, parsed['xp_h'], parsed['lucro'])

        return jsonify({'success': True, 'message': 'Hunt registrada com sucesso'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/hunts/<int:hunt_id>', methods=['PUT'])
def update_hunt(hunt_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Não autorizado'}), 401
        
    try:
        data = request.json
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Verificar se a hunt pertence ao usuário
        cursor.execute("SELECT id FROM hunts WHERE id = ? AND user_id = ?", 
                      (hunt_id, session['user_id']))
        if not cursor.fetchone():
            return jsonify({'error': 'Hunt não encontrada'}), 404
        
        # Campos que podem ser atualizados
        fields = []
        values = []
        
        for field in ['local_hunt', 'notas']:
            if field in data:
                fields.append(f"{field} = ?")
                values.append(data[field])
        
        if not fields:
            return jsonify({'error': 'Nenhum campo para atualizar'}), 400
        
        fields.append("updated_at = ?")
        values.append(datetime.now().isoformat())
        values.append(hunt_id)
        
        query = f"UPDATE hunts SET {', '.join(fields)} WHERE id = ?"
        cursor.execute(query, values)
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Hunt atualizada com sucesso'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/hunts/<int:hunt_id>', methods=['DELETE'])
def delete_hunt(hunt_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Não autorizado'}), 401
        
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Verificar se a hunt pertence ao usuário
        cursor.execute("SELECT video_filename FROM hunts WHERE id = ? AND user_id = ?", 
                      (hunt_id, session['user_id']))
        hunt = cursor.fetchone()
        
        if not hunt:
            return jsonify({'error': 'Hunt não encontrada'}), 404
        
        # Deletar arquivo de vídeo se existir
        if hunt[0]:
            video_path = os.path.join(UPLOAD_DIR, hunt[0])
            if os.path.exists(video_path):
                os.remove(video_path)
        
        # Deletar hunt
        cursor.execute("DELETE FROM hunts WHERE id = ?", (hunt_id,))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Hunt deletada com sucesso'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# === ROTAS DE UPLOAD DE VÍDEO ===

@app.route('/api/upload-video/<int:hunt_id>', methods=['POST'])
def upload_video(hunt_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Não autorizado'}), 401
        
    if 'video' not in request.files:
        return jsonify({'error': 'Nenhum arquivo enviado'}), 400
    
    file = request.files['video']
    if file.filename == '':
        return jsonify({'error': 'Nenhum arquivo selecionado'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'Tipo de arquivo não permitido'}), 400
    
    try:
        # Verificar se a hunt existe e pertence ao usuário
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM hunts WHERE id = ? AND user_id = ?", 
                      (hunt_id, session['user_id']))
        
        if not cursor.fetchone():
            return jsonify({'error': 'Hunt não encontrada'}), 404
        
        # Criar diretório de upload se não existir
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        
        # Gerar nome único para o arquivo
        file_extension = file.filename.rsplit('.', 1)[1].lower()
        unique_filename = f"{hunt_id}_{uuid.uuid4().hex}.{file_extension}"
        file_path = os.path.join(UPLOAD_DIR, unique_filename)
        
        # Salvar arquivo
        file.save(file_path)
        
        # Atualizar hunt com o nome do arquivo
        cursor.execute("UPDATE hunts SET video_filename = ? WHERE id = ?", 
                      (unique_filename, hunt_id))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Vídeo enviado com sucesso'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/video/<filename>')
def serve_video(filename):
    """Serve arquivos de vídeo"""
    try:
        video_path = os.path.join(UPLOAD_DIR, filename)
        if os.path.exists(video_path):
            return send_file(video_path)
        else:
            return jsonify({'error': 'Vídeo não encontrado'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# === ROTAS DE ESTATÍSTICAS ===

@app.route('/api/statistics')
def get_statistics():
    if 'user_id' not in session:
        return jsonify({'error': 'Não autorizado'}), 401
        
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Estatísticas gerais
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
        FROM hunts WHERE user_id = ?
    """, (session['user_id'],))
    
    stats = cursor.fetchone()
    
    # Performance recente (últimos 7 dias)
    week_ago = (datetime.now() - timedelta(days=7)).strftime("%d/%m/%Y")
    cursor.execute("""
        SELECT AVG(xp_h), AVG(lucro), COUNT(*)
        FROM hunts 
        WHERE user_id = ? AND data >= ?
    """, (session['user_id'], week_ago))
    
    recent_stats = cursor.fetchone()
    
    # Top 5 locais por XP/h
    cursor.execute("""
        SELECT location_name, avg_xp_h, best_xp_h, total_hunts
        FROM hunt_locations 
        WHERE user_id = ?
        ORDER BY avg_xp_h DESC
        LIMIT 5
    """, (session['user_id'],))
    
    top_locations = cursor.fetchall()
    
    # Progressão mensal
    cursor.execute("""
        SELECT 
            substr(data, 4, 7) as month_year,
            AVG(xp_h) as avg_xp_h,
            AVG(lucro) as avg_profit,
            COUNT(*) as hunt_count
        FROM hunts 
        WHERE user_id = ?
        GROUP BY substr(data, 4, 7)
        ORDER BY substr(data, 7, 4) DESC, substr(data, 4, 2) DESC
        LIMIT 12
    """, (session['user_id'],))
    
    monthly_data = cursor.fetchall()
    
    conn.close()
    
    return jsonify({
        'total_hunts': stats[0] or 0,
        'total_xp': stats[1] or 0,
        'avg_xp_h': round(stats[2] or 0, 0),
        'max_xp_h': stats[3] or 0,
        'total_profit': stats[4] or 0,
        'avg_profit': round(stats[5] or 0, 0),
        'max_profit': stats[6] or 0,
        'min_profit': stats[7] or 0,
        'recent_avg_xp_h': round(recent_stats[0] or 0, 0),
        'recent_avg_profit': round(recent_stats[1] or 0, 0),
        'recent_hunt_count': recent_stats[2] or 0,
        'top_locations': [
            {
                'name': row[0],
                'avg_xp_h': round(row[1], 0),
                'best_xp_h': row[2],
                'total_hunts': row[3]
            } for row in top_locations
        ],
        'monthly_progression': [
            {
                'month': row[0],
                'avg_xp_h': round(row[1], 0),
                'avg_profit': round(row[2], 0),
                'hunt_count': row[3]
            } for row in monthly_data
        ]
    })

@app.route('/api/hunt-locations')
def get_hunt_locations():
    """Retorna locais de caça já utilizados pelo usuário"""
    if 'user_id' not in session:
        return jsonify({'error': 'Não autorizado'}), 401
        
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT location_name 
        FROM hunt_locations 
        WHERE user_id = ? 
        ORDER BY total_hunts DESC, location_name ASC
    """, (session['user_id'],))
    
    locations = [row[0] for row in cursor.fetchall()]
    conn.close()
    
    return jsonify(locations)

# === ROTAS DE EXPORTAÇÃO ===

@app.route('/api/export/<format>')
def export_data(format):
    if 'user_id' not in session:
        return jsonify({'error': 'Não autorizado'}), 401
        
    try:
        conn = sqlite3.connect(DB_FILE)
        
        if format == 'csv':
            df = pd.read_sql_query(
                "SELECT * FROM hunts WHERE user_id = ? ORDER BY created_at DESC", 
                conn, params=(session['user_id'],))
            filename = f"hunts_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            df.to_csv(filename, index=False)
            conn.close()
            return send_file(filename, as_attachment=True)
        
        elif format == 'excel':
            df = pd.read_sql_query(
                "SELECT * FROM hunts WHERE user_id = ? ORDER BY created_at DESC", 
                conn, params=(session['user_id'],))
            filename = f"hunts_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
            df.to_excel(filename, index=False)
            conn.close()
            return send_file(filename, as_attachment=True)
        
        else:
            return jsonify({'error': 'Formato de exportação inválido'}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Criar diretórios necessários
    os.makedirs(BACKUP_DIR, exist_ok=True)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    
    # Inicializar banco de dados
    init_db()
    
    # Executar aplicação
    app.run(debug=True, host='0.0.0.0', port=5000)
