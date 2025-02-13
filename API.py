from flask import Flask, request, jsonify, render_template
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'my_super_secret_key_1234'  # Секретний ключ для JWT
jwt = JWTManager(app)

@app.route("/")
def home():
    return render_template("index.html")

# Дані зберігаються в пам'яті
users = []
items = []


# Моделі (тільки для структури)
class User:
    def __init__(self, username, password, role):
        self.username = username
        self.password = password
        self.role = role


class Item:
    def __init__(self, name, description):
        self.id = len(items) + 1
        self.name = name
        self.description = description


# Реєстрація користувача
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    # Перевірка, чи користувач вже існує
    if any(user.username == data['username'] for user in users):
        return jsonify({'message': 'User already exists'}), 400

    hashed_password = generate_password_hash(data['password'])
    new_user = User(username=data['username'], password=hashed_password, role=data['role'])
    users.append(new_user)

    return jsonify({'message': 'User registered successfully'}), 201


# Логін та генерація токена
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = next((user for user in users if user.username == data['username']), None)

    if user and check_password_hash(user.password, data['password']):
        # Генеруємо JWT-токен з identity (тільки username) та claims (роль)
        access_token = create_access_token(identity=user.username, additional_claims={"role": user.role})
        return jsonify(access_token=access_token), 200

    return jsonify({'message': 'Invalid credentials'}), 401


# Створення предмета (тільки для Admin)
@app.route('/items', methods=['POST'])
@jwt_required()
def create_item():
    claims = get_jwt()
    if claims["role"] != "Admin":
        return jsonify({'message': 'Access denied'}), 403

    data = request.get_json()
    new_item = Item(name=data['name'], description=data['description'])
    items.append(new_item)

    return jsonify({'message': 'Item created successfully'}), 201


# Отримання списку предметів
@app.route('/items', methods=['GET'])
@jwt_required()
def get_items():
    return jsonify([{'id': item.id, 'name': item.name, 'description': item.description} for item in items]), 200


# Оновлення предмета (тільки для Admin)
@app.route('/items/<int:item_id>', methods=['PATCH'])
@jwt_required()
def update_item(item_id):
    claims = get_jwt()
    if claims["role"] != "Admin":
        return jsonify({'message': 'Access denied'}), 403

    item = next((item for item in items if item.id == item_id), None)
    if not item:
        return jsonify({'message': 'Item not found'}), 404

    data = request.get_json()
    item.name = data.get('name', item.name)
    item.description = data.get('description', item.description)

    return jsonify({'message': 'Item updated successfully'}), 200


# Видалення предмета (тільки для Admin)
@app.route('/items/<int:item_id>', methods=['DELETE'])
@jwt_required()
def delete_item(item_id):
    claims = get_jwt()
    if claims["role"] != "Admin":
        return jsonify({'message': 'Access denied'}), 403

    item = next((item for item in items if item.id == item_id), None)
    if not item:
        return jsonify({'message': 'Item not found'}), 404

    items.remove(item)

    return jsonify({'message': 'Item deleted successfully'}), 200


if __name__ == '__main__':
    app.run(debug=True)
