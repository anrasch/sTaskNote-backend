from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import jwt
import datetime
from functools import wraps
from flask_cors import CORS
from flask_migrate import Migrate


app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Sicherstellen, dass das Verzeichnis für die Datenbank existiert
os.makedirs(os.path.dirname('database/sTaskNote.db'), exist_ok=True)

database_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'database/sTaskNote.db'))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{database_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Datenbankmodell für Benutzer (User)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Datenbankmodell für Aufgaben (Tasks)
class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Datenbankmodell für Notizen (Notes)
class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Token erforderlich Decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['user_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Route zur Registrierung eines neuen Benutzers
@app.route('/register', methods=['POST', 'OPTIONS'])
def register():
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Methods", "POST, OPTIONS")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type")
        return response
    
    try:
        data = request.get_json()
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'message': 'User already exists'}), 400
        hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
        new_user = User(username=data['username'], password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        print(f"Error: {e}")  # Ausgabe des Fehlers für Debugging-Zwecke
        return jsonify({'message': 'Internal Server Error'}), 500

# Route zur Anmeldung eines Benutzers
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Invalid username or password'}), 401
    token = jwt.encode({'user_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, app.config['SECRET_KEY'], algorithm="HS256")
    return jsonify({'token': token})

# Route zum Erstellen einer neuen Aufgabe
@app.route('/tasks', methods=['POST'])
@token_required
def create_task(current_user):
    data = request.get_json()
    new_task = Task(title=data['title'], user_id=current_user.id)
    db.session.add(new_task)
    db.session.commit()
    return jsonify({"message": "Task created", "task": {"id": new_task.id, "title": new_task.title, "completed": new_task.completed}}), 201

# Route zum Abrufen aller Aufgaben
@app.route('/tasks', methods=['GET'])
@token_required
def get_tasks(current_user):
    tasks = Task.query.filter_by(user_id=current_user.id).all()
    result = [{"id": task.id, "title": task.title, "completed": task.completed} for task in tasks]
    return jsonify(result)

# Route zum Bearbeiten einer Aufgabe
@app.route('/tasks/<int:id>', methods=['PUT'])
@token_required
def update_task(current_user, id):
    task = Task.query.filter_by(id=id, user_id=current_user.id).first()
    if not task:
        return jsonify({'message': 'Task not found'}), 404
    data = request.get_json()
    task.title = data.get('title', task.title)
    task.completed = data.get('completed', task.completed)
    db.session.commit()
    return jsonify({"message": "Task updated", "task": {"id": task.id, "title": task.title, "completed": task.completed}})

# Route zum Löschen einer Aufgabe
@app.route('/tasks/<int:id>', methods=['DELETE'])
@token_required
def delete_task(current_user, id):
    task = Task.query.filter_by(id=id, user_id=current_user.id).first()
    if not task:
        return jsonify({'message': 'Task not found'}), 404
    db.session.delete(task)
    db.session.commit()
    return jsonify({"message": "Task deleted"})

# Route zum Erstellen einer neuen Notiz
@app.route('/notes', methods=['POST'])
@token_required
def create_note(current_user):
    data = request.get_json()
    new_note = Note(content=data['content'], task_id=data.get('task_id'), user_id=current_user.id)
    db.session.add(new_note)
    db.session.commit()
    return jsonify({"message": "Note created", "note": {"id": new_note.id, "content": new_note.content, "task_id": new_note.task_id}}), 201

# Route zum Abrufen aller Notizen
@app.route('/notes', methods=['GET'])
@token_required
def get_notes(current_user):
    notes = Note.query.filter_by(user_id=current_user.id).all()
    result = [{"id": note.id, "content": note.content, "task_id": note.task_id} for note in notes]
    return jsonify(result)

# Route zum Bearbeiten einer Notiz
@app.route('/notes/<int:id>', methods=['PUT'])
@token_required
def update_note(current_user, id):
    note = Note.query.filter_by(id=id, user_id=current_user.id).first()
    if not note:
        return jsonify({'message': 'Note not found'}), 404
    data = request.get_json()
    note.content = data.get('content', note.content)
    note.task_id = data.get('task_id', note.task_id)
    db.session.commit()
    return jsonify({"message": "Note updated", "note": {"id": note.id, "content": note.content, "task_id": note.task_id}})

# Route zum Löschen einer Notiz
@app.route('/notes/<int:id>', methods=['DELETE'])
@token_required
def delete_note(current_user, id):
    note = Note.query.filter_by(id=id, user_id=current_user.id).first()
    if not note:
        return jsonify({'message': 'Note not found'}), 404
    db.session.delete(note)
    db.session.commit()
    return jsonify({"message": "Note deleted"})

# Route zum Abrufen aller Notizen, die einer bestimmten Aufgabe zugeordnet sind
@app.route('/tasks/<int:task_id>/notes', methods=['GET'])
@token_required
def get_notes_for_task(current_user, task_id):
    notes = Note.query.filter_by(task_id=task_id, user_id=current_user.id).all()
    result = [{"id": note.id, "content": note.content, "task_id": note.task_id} for note in notes]
    return jsonify(result)

# Route zum Verknüpfen einer bestehenden Notiz mit einer Aufgabe
@app.route('/tasks/<int:task_id>/notes/<int:note_id>', methods=['PUT'])
@token_required
def link_note_to_task(current_user, task_id, note_id):
    task = Task.query.filter_by(id=task_id, user_id=current_user.id).first()
    note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
    if not task or not note:
        return jsonify({'message': 'Task or Note not found'}), 404
    note.task_id = task.id
    db.session.commit()
    return jsonify({"message": "Note linked to task", "note": {"id": note.id, "content": note.content, "task_id": note.task_id}})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
