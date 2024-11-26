from flask import Flask, request, jsonify, make_response
from autenticacion import hash_password, check_password, create_jwt, verify_jwt
import psycopg2
from config import Config
import time

app = Flask(__name__)
app.config.from_object(Config)

# Conexión a la base de datos
def get_db_connection():
    conn = psycopg2.connect(
        host=app.config['DB_HOST'],
        database=app.config['DB_NAME'],
        user=app.config['DB_USER'],
        password=app.config['DB_PASSWORD']
    )
    return conn

# Almacenar los intentos fallidos de inicio de sesión
user_attempts = {}
MAX_ATTEMPTS = 5
BLOCK_TIME = 300  # Bloquear por 5 minutos

# Ruta para registrar un nuevo usuario
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'usuario')  # El rol por defecto es 'usuario'

    if not email or not password:
        return jsonify({"error": "El correo y la contraseña son obligatorios"}), 400

    # Verificar si el correo ya está registrado
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    existing_user = cursor.fetchone()

    if existing_user:
        return jsonify({"error": "El correo electrónico ya está registrado"}), 400

    # Insertar usuario en la base de datos
    password_hash = hash_password(password)
    cursor.execute("INSERT INTO users (email, password_hash, role) VALUES (%s, %s, %s)", 
                (email, password_hash, role))
    conn.commit()
    conn.close()

    return jsonify({"message": "Usuario registrado exitosamente"}), 201

# Ruta para iniciar sesión
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "El correo y la contraseña son obligatorios"}), 400

    # Verificar si el usuario está bloqueado por intentos fallidos
    if email in user_attempts and user_attempts[email]['attempts'] >= MAX_ATTEMPTS:
        if time.time() - user_attempts[email]['last_attempt'] < BLOCK_TIME:
            return jsonify({"error": "Número máximo de intentos alcanzado. Intenta nuevamente más tarde."}), 403

    # Verificar si el usuario existe
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()

    if not user:
        # Aumentar el contador de intentos fallidos
        if email not in user_attempts:
            user_attempts[email] = {'attempts': 0, 'last_attempt': time.time()}
        user_attempts[email]['attempts'] += 1
        user_attempts[email]['last_attempt'] = time.time()
        conn.close()
        return jsonify({"error": "Credenciales incorrectas"}), 401

    user_id, _, stored_password_hash, role = user

    # Verificar la contraseña
    if not check_password(stored_password_hash, password):
        # Aumentar el contador de intentos fallidos
        if email not in user_attempts:
            user_attempts[email] = {'attempts': 0, 'last_attempt': time.time()}
        user_attempts[email]['attempts'] += 1
        user_attempts[email]['last_attempt'] = time.time()
        conn.close()
        return jsonify({"error": "Credenciales incorrectas"}), 401

    # Restablecer intentos fallidos después de un inicio de sesión exitoso
    if email in user_attempts:
        user_attempts[email] = {'attempts': 0, 'last_attempt': time.time()}

    # Crear el token JWT
    token = create_jwt(user_id, role)
    conn.close()

    # Guardar el token JWT en una cookie HttpOnly y Secure
    response = make_response(jsonify({"message": "Inicio de sesión exitoso", "token": token}), 200)
    response.set_cookie('session', token, httponly=True, secure=True)

    return response

# Ruta protegida que solo pueden acceder administradores
@app.route('/admin', methods=['GET'])
def admin():
    token = request.cookies.get('session')  # Obtener el token de la cookie
    if not token:
        return jsonify({"error": "Token requerido"}), 403
    
    payload = verify_jwt(token)

    if not payload:
        return jsonify({"error": "Token inválido o expirado"}), 403

    if payload['role'] != 'administrador':
        return jsonify({"error": "Acceso denegado"}), 403

    return jsonify({"message": "Acceso permitido para administradores"}), 200

if __name__ == '__main__':
    app.run(debug=True)
