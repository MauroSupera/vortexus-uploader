import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, abort, jsonify, session
from werkzeug.utils import secure_filename
import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import argparse

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=7)  # Session lasts 7 days
app.config['MAX_SIMULTANEOUS_UPLOADS'] = 3  # Default max simultaneous uploads

# Create uploads directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize database
db = SQLAlchemy(app)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class AllowedExtension(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    extension = db.Column(db.String(20), unique=True, nullable=False)
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Folder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('folder.id'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    # Relationships
    files = db.relationship('File', backref='folder', lazy=True)
    subfolders = db.relationship('Folder', backref=db.backref('parent', remote_side=[id]), lazy=True)

# Define models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    storage_limit = db.Column(db.Integer, default=104857600)  # Default 100MB in bytes
    storage_used = db.Column(db.Integer, default=0)  # Storage used in bytes
    max_simultaneous_uploads = db.Column(db.Integer, default=3)
    files = db.relationship('File', backref='owner', lazy=True)
    folders = db.relationship('Folder', backref='owner', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def has_storage_space(self, file_size):
        return (self.storage_used + file_size) <= self.storage_limit

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    size = db.Column(db.Integer, nullable=False)  # Size in bytes
    folder_id = db.Column(db.Integer, db.ForeignKey('folder.id'), nullable=True)
    upload_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='completed')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create admin user if not exists
def create_admin():
    with app.app_context():
        db.create_all()
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', email='admin@example.com', is_admin=True)
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()

def get_file_info(user_id=None):
    """Get information about uploaded files"""
    if user_id:
        files = File.query.filter_by(user_id=user_id).all()
    else:
        files = File.query.all()
    
    file_info = []
    for file in files:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        if os.path.isfile(file_path):
            file_url = url_for('get_file', filename=file.filename, _external=True)
            owner = User.query.get(file.user_id)
            file_info.append({
                'id': file.id,
                'name': file.filename,
                'original_name': file.original_filename,
                'size': file.size,
                'date': file.upload_date,
                'url': file_url,
                'owner': owner.username
            })
    return file_info

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        
        # Check if username or email already exists
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Nome de usuário já existe.')
            return redirect(url_for('register'))
        
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email já está em uso.')
            return redirect(url_for('register'))
        
        # Create new user
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Conta criada com sucesso! Faça login para continuar.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'true'
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user, remember=remember)
            if remember:
                # Set session to permanent and extend lifetime
                session.permanent = True
                app.permanent_session_lifetime = datetime.timedelta(days=30)  # Extended to 30 days for remember me
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Credenciais inválidas')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    # Clear session
    session.clear()
    logout_user()
    flash('Você foi desconectado com sucesso')
    return redirect(url_for('index'))

@app.route('/dashboard')
@app.route('/folder/<int:folder_id>')
@login_required
def dashboard(folder_id=None):
    current_folder = None
    ancestors = []
    if folder_id:
        current_folder = Folder.query.get_or_404(folder_id)
        if current_folder.user_id != current_user.id:
            abort(403)
        # Build ancestors list
        temp = current_folder
        while temp:
            ancestors.insert(0, temp)
            temp = temp.parent

    folders = Folder.query.filter_by(
        user_id=current_user.id,
        parent_id=folder_id
    ).all()

    files = File.query.filter_by(
        user_id=current_user.id,
        folder_id=folder_id
    ).all()

    # Calculate storage usage
    storage_used = sum(file.size for file in current_user.files) / 1024 / 1024  # Convert to MB
    storage_limit = current_user.storage_limit / 1024 / 1024  # Convert to MB
    storage_percent = (storage_used / storage_limit) * 100 if storage_limit > 0 else 0

    # Get allowed extensions
    allowed_extensions = AllowedExtension.query.all()

    return render_template('dashboard.html',
                         current_folder=current_folder,
                         ancestors=ancestors,
                         folders=folders,
                         files=files,
                         storage_used=storage_used,
                         storage_limit=storage_limit,
                         storage_percent=storage_percent,
                         allowed_extensions=allowed_extensions,
                         max_uploads=current_user.max_simultaneous_uploads)

@app.route('/admin/panel')
@login_required
def admin_panel():
    if not current_user.is_admin:
        abort(403)
    
    users = User.query.filter(User.id != current_user.id).all()
    total_storage = sum(user.storage_used for user in users)
    total_storage_mb = total_storage / (1024 * 1024)
    
    # Get all files for admin
    all_files = File.query.all()
    
    # Get allowed extensions
    extensions = AllowedExtension.query.order_by(AllowedExtension.extension).all()
    
    return render_template('admin/panel.html',
                         users=users,
                         total_storage_mb=total_storage_mb,
                         all_files=all_files,
                         extensions=extensions)

@app.route('/admin/upload', methods=['POST'])
@login_required
def admin_upload():
    if not current_user.is_admin:
        abort(403)
    
    if 'file' not in request.files:
        flash('Nenhum arquivo selecionado')
        return redirect(url_for('admin_panel'))
    
    file = request.files['file']
    folder_id = request.form.get('folder_id')
    
    if file.filename == '':
        flash('Nenhum arquivo selecionado')
        return redirect(url_for('admin_panel'))
    
    if file:
        original_filename = secure_filename(file.filename)
        name, ext = os.path.splitext(original_filename)
        unique_filename = f"{name}_{secrets.token_hex(4)}{ext}"
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        
        # Get actual file size after saving
        actual_size = os.path.getsize(file_path)
        
        # Create file record
        new_file = File(
            filename=unique_filename,
            original_filename=original_filename,
            size=actual_size,
            user_id=current_user.id,
            folder_id=folder_id
        )
        
        # Update admin's storage used
        current_user.storage_used += actual_size
        
        db.session.add(new_file)
        db.session.commit()
        
        flash('Arquivo enviado com sucesso!')
    
    return redirect(url_for('admin_panel'))

@app.route('/folder/create', methods=['POST'])
@login_required
def create_folder():
    name = request.form.get('name')
    parent_id = request.form.get('parent_id')
    
    if not name:
        flash('Nome da pasta é obrigatório')
        return redirect(url_for('dashboard', folder_id=parent_id if parent_id else None))
    
    folder = Folder(name=name, user_id=current_user.id)
    if parent_id:
        try:
            parent_id = int(parent_id)
            parent = Folder.query.get_or_404(parent_id)
            if parent.user_id != current_user.id:
                abort(403)
            folder.parent_id = parent_id
        except (ValueError, TypeError):
            folder.parent_id = None
    
    db.session.add(folder)
    db.session.commit()
    flash('Pasta criada com sucesso')
    return redirect(url_for('dashboard', folder_id=folder.parent_id if folder.parent_id else None))

@app.route('/folder/move/<int:folder_id>', methods=['POST'])
@login_required
def move_folder(folder_id):
    folder = Folder.query.get_or_404(folder_id)
    if folder.user_id != current_user.id:
        abort(403)
    
    new_parent_id = request.form.get('new_parent_id')
    if new_parent_id:
        new_parent = Folder.query.get_or_404(new_parent_id)
        if new_parent.user_id != current_user.id:
            abort(403)
        folder.parent_id = new_parent_id
    else:
        folder.parent_id = None
    
    db.session.commit()
    flash('Pasta movida com sucesso')
    return redirect(url_for('dashboard', folder_id=folder.parent_id))

@app.route('/folder/delete/<int:folder_id>', methods=['POST'])
@login_required
def delete_folder(folder_id):
    folder = Folder.query.get_or_404(folder_id)
    if folder.user_id != current_user.id:
        abort(403)
    
    parent_id = folder.parent_id
    db.session.delete(folder)
    db.session.commit()
    flash('Pasta excluída com sucesso')
    return redirect(url_for('dashboard', folder_id=parent_id))

@app.route('/file/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('Nenhum arquivo selecionado')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    if file.filename == '':
        flash('Nenhum arquivo selecionado')
        return redirect(url_for('dashboard'))
    
    folder_id = request.form.get('folder_id')
    if folder_id:
        folder = Folder.query.get_or_404(folder_id)
        if folder.user_id != current_user.id:
            abort(403)
    
    # Check file extension
    ext = os.path.splitext(file.filename)[1].lower().lstrip('.')
    allowed_extensions = [e.extension.lower() for e in AllowedExtension.query.all()]
    if ext not in allowed_extensions:
        flash(f'Extensão .{ext} não permitida')
        return redirect(url_for('dashboard', folder_id=folder_id))
    
    # Check simultaneous uploads
    active_uploads = File.query.filter_by(
        user_id=current_user.id,
        status='uploading'
    ).count()
    if active_uploads >= current_user.max_simultaneous_uploads:
        flash('Limite de uploads simultâneos atingido')
        return redirect(url_for('dashboard', folder_id=folder_id))
    
    # Check storage limit
    file_size = len(file.read())
    file.seek(0)
    if current_user.storage_used + file_size > current_user.storage_limit:
        flash('Limite de armazenamento excedido')
        return redirect(url_for('dashboard', folder_id=folder_id))
    
    # Save file
    filename = secure_filename(file.filename)
    unique_filename = f"{uuid.uuid4()}_{filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    file.save(file_path)
    
    # Create file record
    file_record = File(
        filename=unique_filename,
        original_filename=filename,
        size=file_size,
        user_id=current_user.id,
        folder_id=folder_id,
        status='completed'
    )
    db.session.add(file_record)
    db.session.commit()
    
    flash('Arquivo enviado com sucesso')
    return redirect(url_for('dashboard', folder_id=folder_id))

@app.route('/file/move/<int:file_id>', methods=['POST'])
@login_required
def move_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        abort(403)
    
    new_folder_id = request.form.get('new_folder_id')
    if new_folder_id:
        new_folder = Folder.query.get_or_404(new_folder_id)
        if new_folder.user_id != current_user.id:
            abort(403)
        file.folder_id = new_folder_id
    else:
        file.folder_id = None
    
    db.session.commit()
    flash('Arquivo movido com sucesso')
    return redirect(url_for('dashboard', folder_id=file.folder_id))

@app.route('/file/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        abort(403)
    
    folder_id = file.folder_id
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    
    db.session.delete(file)
    db.session.commit()
    flash('Arquivo excluído com sucesso')
    return redirect(url_for('dashboard', folder_id=folder_id))

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    file = File.query.filter_by(filename=filename).first_or_404()
    if file.user_id != current_user.id and not current_user.is_admin:
        abort(403)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True, download_name=file.original_filename)

@app.route('/share/<filename>')
def share_file(filename):
    file = File.query.filter_by(filename=filename).first_or_404()
    original_name = file.original_filename
    extension = os.path.splitext(original_name)[1]
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=False, download_name=original_name)

@app.route('/api/generate-share-link/<int:file_id>')
@login_required
def generate_share_link(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id and not current_user.is_admin:
        abort(403)
    extension = os.path.splitext(file.original_filename)[1]
    share_url = url_for('share_file', filename=file.filename, _external=True)
    return jsonify({'url': share_url})

@app.route('/admin/extensions', methods=['GET', 'POST'])
@login_required
def manage_extensions():
    if not current_user.is_admin:
        abort(403)
    
    if request.method == 'POST':
        action = request.form.get('action')
        extension = request.form.get('extension', '').lower().strip('.')
        
        if action == 'add':
            if extension:
                ext = AllowedExtension.query.filter_by(extension=extension).first()
                if not ext:
                    ext = AllowedExtension(extension=extension)
                    db.session.add(ext)
                    db.session.commit()
                    flash(f'Extensão .{extension} adicionada com sucesso!')
                else:
                    flash(f'Extensão .{extension} já existe!')
        
        elif action == 'toggle':
            ext_id = request.form.get('extension_id')
            if ext_id:
                ext = AllowedExtension.query.get(ext_id)
                if ext:
                    ext.enabled = not ext.enabled
                    db.session.commit()
                    status = 'ativada' if ext.enabled else 'desativada'
                    flash(f'Extensão .{ext.extension} {status} com sucesso!')
        
        elif action == 'delete':
            ext_id = request.form.get('extension_id')
            if ext_id:
                ext = AllowedExtension.query.get(ext_id)
                if ext:
                    db.session.delete(ext)
                    db.session.commit()
                    flash(f'Extensão .{ext.extension} removida com sucesso!')
    
    extensions = AllowedExtension.query.order_by(AllowedExtension.extension).all()
    return render_template('admin/extensions.html', extensions=extensions)

@app.route('/admin/user/<int:user_id>/settings', methods=['POST'])
@login_required
def update_user_settings(user_id):
    if not current_user.is_admin:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    
    storage_limit = request.form.get('storage_limit')
    max_uploads = request.form.get('max_simultaneous_uploads')
    
    if storage_limit:
        try:
            user.storage_limit = int(float(storage_limit) * 1024 * 1024)  # Convert MB to bytes
        except ValueError:
            flash('Valor inválido para limite de armazenamento')
    
    if max_uploads:
        try:
            user.max_simultaneous_uploads = int(max_uploads)
        except ValueError:
            flash('Valor inválido para uploads simultâneos')
    
    db.session.commit()
    flash('Configurações atualizadas com sucesso!')
    return redirect(url_for('admin_panel'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated and current_user.is_admin:
        return redirect(url_for('admin_panel'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'true'
        
        user = User.query.filter_by(username=username, is_admin=True).first()
        
        if user and user.check_password(password):
            login_user(user, remember=remember)
            if remember:
                # Set session to permanent and extend lifetime
                session.permanent = True
                app.permanent_session_lifetime = datetime.timedelta(days=30)  # Extended to 30 days for remember me
            return redirect(url_for('admin_panel'))
        else:
            flash('Credenciais administrativas inválidas')
    return render_template('admin_login.html')

@app.route('/admin/user/add', methods=['GET', 'POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        flash('Acesso negado')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        is_admin = 'is_admin' in request.form
        storage_limit_mb = int(request.form.get('storage_limit', 1024))
        
        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Nome de usuário já existe')
            return redirect(url_for('add_user'))
        
        if User.query.filter_by(email=email).first():
            flash('Email já está em uso')
            return redirect(url_for('add_user'))
        
        # Create new user
        new_user = User(
            username=username, 
            email=email, 
            is_admin=is_admin,
            storage_limit=storage_limit_mb * 1024 * 1024  # Convert MB to bytes
        )
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash(f'Usuário {username} criado com sucesso')
        return redirect(url_for('admin_panel'))
    
    return render_template('add_user.html')

@app.route('/admin/user/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        flash('Acesso negado')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        is_admin = 'is_admin' in request.form
        storage_limit_mb = int(request.form.get('storage_limit', 1024))
        
        # Check if username is changed and already exists
        if username != user.username and User.query.filter_by(username=username).first():
            flash('Nome de usuário já existe')
            return redirect(url_for('edit_user', user_id=user_id))
        
        # Check if email is changed and already exists
        if email != user.email and User.query.filter_by(email=email).first():
            flash('Email já está em uso')
            return redirect(url_for('edit_user', user_id=user_id))
        
        # Update user
        user.username = username
        user.email = email
        user.is_admin = is_admin
        user.storage_limit = storage_limit_mb * 1024 * 1024  # Convert MB to bytes
        
        if password:
            user.set_password(password)
        
        db.session.commit()
        
        flash(f'Usuário {username} atualizado com sucesso')
        return redirect(url_for('admin_panel'))
    
    storage_limit_mb = user.storage_limit / (1024 * 1024)
    return render_template('edit_user.html', user=user, storage_limit=storage_limit_mb)

@app.route('/admin/user/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('Acesso negado')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    
    # Prevent deleting yourself
    if user.id == current_user.id:
        flash('Você não pode excluir sua própria conta')
        return redirect(url_for('admin_panel'))
    
    # Delete all user files
    for file in user.files:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
    
    # Delete user
    db.session.delete(user)
    db.session.commit()
    
    flash(f'Usuário {user.username} e todos os seus arquivos foram excluídos')
    return redirect(url_for('admin_panel'))

def parse_args():
    parser = argparse.ArgumentParser(description='Sistema de Upload de Arquivos')
    parser.add_argument('--port', type=int, default=4012,
                      help='Porta para executar o servidor (padrão: 4012)')
    parser.add_argument('--host', type=str, default='0.0.0.0',
                      help='Host para executar o servidor (padrão: 0.0.0.0)')
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()
    
    # Criar diretório de uploads se não existir
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Criar banco de dados se não existir
    with app.app_context():
        db.create_all()
        create_admin()
    
    # Iniciar o servidor com os parâmetros fornecidos
    print(f"Iniciando servidor em {args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=True)
