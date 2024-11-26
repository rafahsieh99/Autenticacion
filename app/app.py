from flask import Flask, request, jsonify, make_response
from autenticacion import hash_password, check_password, create_jwt, verify_jwt
import psycopg2

app = Flask(__name__)
app.config.from_object('config.Config')

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
    conn = psycopg2.connect(
        host='localhost',
        database='mi_base_de_datos',
        user='mi_usuario',
        password='mi_contraseña'
    )
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

    return jsonify({"message": "Usuario registrado exitosamente"}), 201

# Ruta para iniciar sesión
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "El correo y la contraseña son obligatorios"}), 400

    # Verificar si el usuario existe
    conn = psycopg2.connect(
        host='localhost',
        database='mi_base_de_datos',
        user='mi_usuario',
        password='mi_contraseña'
    )
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()

    if not user:
        return jsonify({"error": "Credenciales incorrectas"}), 401

    user_id, _, stored_password_hash, role = user

    # Verificar la contraseña
    if not check_password(stored_password_hash, password):
        return jsonify({"error": "Credenciales incorrectas"}), 401

    # Crear el token JWT
    token = create_jwt(user_id, role)
    
    return jsonify({"message": "Inicio de sesión exitoso", "token": token}), 200

# Ruta protegida que solo pueden acceder administradores
@app.route('/admin', methods=['GET'])
def admin():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"error": "Token requerido"}), 403
    
    token = token.split(" ")[1]  # El token viene en el formato "Bearer <token>"
    payload = verify_jwt(token)

    if not payload:
        return jsonify({"error": "Token inválido o expirado"}), 403

    if payload['role'] != 'administrador':
        return jsonify({"error": "Acceso denegado"}), 403

    return jsonify({"message": "Acceso permitido para administradores"}), 200

if __name__ == '__main__':
    app.run(debug=True)
s