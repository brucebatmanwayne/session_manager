from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Set up JWT secret key
app.config['JWT_SECRET_KEY'] = 'your_secret_key_here'
jwt = JWTManager(app)

# In-memory "database" for demo purposes
users_db = {}

@app.route('/register', methods=['POST'])
def register():
    # Get username and password from request
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    if not username or not password:
        return jsonify({"msg": "Username and password are required"}), 400

    if username in users_db:
        return jsonify({"msg": "User already exists"}), 400

    # Hash the password and store the user
    hashed_password = generate_password_hash(password)
    users_db[username] = hashed_password

    return jsonify({"msg": "User registered successfully!"}), 201


@app.route('/login', methods=['POST'])
def login():
    # Get username and password from request
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    if not username or not password:
        return jsonify({"msg": "Username and password are required"}), 400

    # Check if user exists
    stored_password = users_db.get(username)
    if not stored_password or not check_password_hash(stored_password, password):
        return jsonify({"msg": "Invalid username or password"}), 401

    # Create JWT token for the user
    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)


@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    # Get the current logged-in user's identity from the JWT
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


if __name__ == '__main__':
    app.run(debug=True)
