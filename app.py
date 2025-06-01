from flask import Flask, render_template, redirect, url_for, flash, request, session, jsonify
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, IntegerField, FieldList, FormField, HiddenField
from wtforms.validators import DataRequired, Email, Length
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import case
import os

app = Flask(__name__)
bootstrap = Bootstrap(app)

# Конфигурация базы данных
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:nbver1702@localhost:5432/quiz'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'nbver1702'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Пожалуйста, войдите для доступа к этой странице.'

# Формы
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')

class RegistrationForm(FlaskForm):
    name = StringField('Имя', validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Зарегистрироваться')

class AnswerForm(FlaskForm):
    answer = StringField('Вариант ответа', validators=[DataRequired(message="Поле обязательно для заполнения")])
    is_correct = BooleanField('Правильный ответ')

class QuestionForm(FlaskForm):
    class Meta:
        csrf = False # Временно отключаем CSRF для тестирования

    question = StringField('Вопрос', validators=[
        DataRequired(message="Введите текст вопроса"),
        Length(min=3, max=200, message="Вопрос должен содержать от 3 до 200 символов")
    ])
    answers = FieldList(FormField(AnswerForm), min_entries=4, max_entries=4)
    submit = SubmitField('Добавить вопрос')

    def validate(self, extra_validators=None):
        if not super().validate(extra_validators=extra_validators):
            return False

        if not self.question.data.strip():
            self.question.errors.append('Введите текст вопроса')
            return False

        has_correct_answer = False
        has_empty_answer = False
        
        for answer_form in self.answers:
            if not answer_form.answer.data.strip():
                answer_form.answer.errors.append('Введите текст ответа')
                has_empty_answer = True
            if answer_form.is_correct.data:
                has_correct_answer = True

        if has_empty_answer:
            return False

        if not has_correct_answer:
            self.answers.errors.append('Выберите хотя бы один правильный ответ')
            return False

        return True


class QuizForm(FlaskForm):
    name = StringField('Название', validators=[DataRequired(), Length(min=2, max=100)])
    description = StringField('Описание', validators=[DataRequired()])
    minutes = IntegerField('Время (в минутах)', validators=[DataRequired()])
    submit = SubmitField('Сохранить')

# Модели базы данных
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    results = db.relationship('Result', backref='user', lazy=True)
    quiz_attempts = db.relationship('QuizUser', backref='user', lazy=True)

class Quiz(db.Model):
    __tablename__ = 'quizzes'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    minutes = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    questions = db.relationship('Question', backref='quiz', lazy=True, cascade='all, delete-orphan')
    attempts = db.relationship('QuizUser', backref='quiz', lazy=True, cascade='all, delete-orphan')

class Question(db.Model):
    __tablename__ = 'questions'
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(200), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quizzes.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    answers = db.relationship('Answer', backref='question', lazy=True, cascade='all, delete-orphan')

class Answer(db.Model):
    __tablename__ = 'answers'
    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.Integer, db.ForeignKey('questions.id'), nullable=False)
    answer = db.Column(db.String(200), nullable=False)
    is_correct = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    results = db.relationship('Result', backref='answer', lazy=True, cascade='all, delete-orphan')

class Result(db.Model):
    __tablename__ = 'results'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quizzes.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('questions.id'), nullable=False)
    answer_id = db.Column(db.Integer, db.ForeignKey('answers.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class QuizUser(db.Model):
    __tablename__ = 'quiz_user'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quizzes.id'), nullable=False)
    score = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    quizzes = Quiz.query.all()
    completed_quizzes = {}
    
    if current_user.is_authenticated:
        # Получаем все результаты пользователя
        user_results = db.session.query(
            Result.quiz_id,
            db.func.count(Question.id).label('total_questions'),
            db.func.sum(case((Answer.is_correct, 1), else_=0)).label('correct_answers')
        ).join(Question, Result.question_id == Question.id)\
         .join(Answer, Result.answer_id == Answer.id)\
         .filter(Result.user_id == current_user.id)\
         .group_by(Result.quiz_id).all()
        
        # Рассчитываем процент правильных ответов для каждого квиза
        for quiz_id, total_questions, correct_answers in user_results:
            if total_questions > 0:
                score = round((correct_answers / total_questions) * 100)
                completed_quizzes[quiz_id] = {
                    'score': score,
                    'total_questions': total_questions,
                    'correct_answers': correct_answers
                }
    
    return render_template('index.html', quizzes=quizzes, completed_quizzes=completed_quizzes)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        flash('Неверный email или пароль', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        user = User(name=form.name.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    # Удаляем все ключи таймеров из сессии при выходе пользователя
    keys_to_remove = [key for key in session if key.startswith('quiz_') and key.endswith('_start_time')]
    for key in keys_to_remove:
        del session[key]

    logout_user()
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    # Получаем результаты всех пройденных квизов
    quiz_results = QuizUser.query.filter_by(user_id=current_user.id).order_by(QuizUser.created_at.desc()).all()
    return render_template('profile.html', quiz_results=quiz_results)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('У вас нет прав для доступа к этой странице', 'danger')
        return redirect(url_for('index'))
    quizzes = Quiz.query.all()
    return render_template('admin.html', quizzes=quizzes)

@app.route('/quiz/<int:quiz_id>')
@login_required
def quiz_details(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    return render_template('quiz.html', quiz=quiz)

@app.route('/quiz/list')
@login_required
def quiz_list():
    if not current_user.is_admin:
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('index'))
    
    quizzes = Quiz.query.all()
    return render_template('quiz_list.html', quizzes=quizzes)

@app.route('/quiz/create', methods=['GET', 'POST'])
@login_required
def create_quiz():
    if not current_user.is_admin:
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('index'))
    
    form = QuizForm()
    if form.validate_on_submit():
        try:
            quiz = Quiz(
                name=form.name.data,
                description=form.description.data,
                minutes=form.minutes.data
            )
            db.session.add(quiz)
            db.session.commit()
            flash('Квиз успешно создан! Теперь вы можете добавить вопросы.', 'success')
            return redirect(url_for('manage_questions', quiz_id=quiz.id))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при создании квиза: {str(e)}', 'danger')
    
    return render_template('quiz_form.html', form=form, is_edit=False)

@app.route('/quiz/<int:quiz_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_quiz(quiz_id):
    if not current_user.is_admin:
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('index'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    form = QuizForm(obj=quiz)
    
    if form.validate_on_submit():
        quiz.name = form.name.data
        quiz.description = form.description.data
        quiz.minutes = form.minutes.data
        db.session.commit()
        flash('Квиз успешно обновлен!', 'success')
        return redirect(url_for('quiz_list'))
    
    return render_template('quiz_form.html', form=form, is_edit=True, quiz=quiz)

@app.route('/quiz/<int:quiz_id>/questions', methods=['GET', 'POST'])
@login_required
def manage_questions(quiz_id):
    if not current_user.is_admin:
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('index'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    form = QuestionForm()
    
    if request.method == 'POST':
        if form.validate():
            try:
                # Создаем вопрос
                question = Question(
                    question=form.question.data.strip(),
                    quiz_id=quiz.id
                )
                db.session.add(question)
                db.session.flush()  # Получаем ID вопроса

                # Добавляем ответы
                for answer_form in form.answers:
                    answer = Answer(
                        question_id=question.id,
                        answer=answer_form.answer.data.strip(),
                        is_correct=answer_form.is_correct.data
                    )
                    db.session.add(answer)

                db.session.commit()
                flash('Вопрос успешно добавлен!', 'success')
                return redirect(url_for('manage_questions', quiz_id=quiz.id))
                
            except Exception as e:
                db.session.rollback()
                app.logger.error(f'Ошибка при добавлении вопроса: {str(e)}')
                flash(f'Произошла ошибка при добавлении вопроса. Пожалуйста, попробуйте еще раз.', 'danger')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f'Ошибка в поле {field}: {error}', 'danger')
    
    # При GET запросе или после обработки POST (если валидация не прошла)
    # Рендерим шаблон. Если validate_on_submit() был False, form содержит ошибки.
    return render_template('manage_questions.html', form=form, quiz=quiz)

@app.route('/question/<int:question_id>/delete', methods=['POST'])
@login_required
def delete_question(question_id):
    if not current_user.is_admin:
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('index'))
    
    question = Question.query.get_or_404(question_id)
    quiz_id = question.quiz_id
    
    try:
        db.session.delete(question)
        db.session.commit()
        flash('Вопрос успешно удален!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при удалении вопроса: {str(e)}', 'danger')
    
    return redirect(url_for('manage_questions', quiz_id=quiz_id))

@app.route('/admin/users')
@login_required
def manage_users():
    if not current_user.is_admin:
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('index'))
    
    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/admin/user/<int:user_id>/toggle_admin', methods=['POST'])
@login_required
def toggle_user_admin(user_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Недостаточно прав'}), 403

    user = User.query.get_or_404(user_id)
    
    # Не позволяем админу убрать права самого себя через эту функцию
    if user.id == current_user.id:
         return jsonify({'success': False, 'message': 'Вы не можете изменить свою собственную роль через эту функцию.'}), 400

    try:
        user.is_admin = not user.is_admin
        db.session.commit()
        return jsonify({'success': True, 'is_admin': user.is_admin, 'message': 'Роль пользователя успешно изменена'})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Ошибка при изменении роли пользователя {user_id}: {str(e)}')
        return jsonify({'success': False, 'message': 'Произошла ошибка при изменении роли пользователя'}), 500

@app.route('/admin/user/<int:user_id>/delete', methods=['DELETE'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Недостаточно прав'}), 403

    user = User.query.get_or_404(user_id)
    
    # Не позволяем админу удалить самого себя
    if user.id == current_user.id:
        return jsonify({'success': False, 'message': 'Вы не можете удалить самого себя.'}), 400

    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Пользователь успешно удален'})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Ошибка при удалении пользователя {user_id}: {str(e)}')
        return jsonify({'success': False, 'message': 'Произошла ошибка при удалении пользователя'}), 500

@app.route('/admin/statistics')
@login_required
def statistics():
    if not current_user.is_admin:
        flash('У вас нет доступа к этой странице', 'danger')
        return redirect(url_for('index'))
    
    # Получаем статистику по квизам
    quiz_stats = db.session.query(
        Quiz.id,
        Quiz.name,
        db.func.count(Result.id).label('total_attempts'),
        db.func.avg(db.case((Answer.is_correct, 1), else_=0)).label('avg_score')
    ).outerjoin(Question)\
     .outerjoin(Result)\
     .outerjoin(Answer, Result.answer_id == Answer.id)\
     .group_by(Quiz.id, Quiz.name)\
     .all()
    
    return render_template('statistics.html', quiz_stats=quiz_stats)

@app.route('/quiz/<int:quiz_id>/start')
@login_required
def start_quiz(quiz_id):
    attempt = QuizUser.query.filter_by(
        user_id=current_user.id,
        quiz_id=quiz_id
    ).first()
    
    if attempt:
        flash('Вы уже проходили этот тест', 'warning')
        return redirect(url_for('index'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    
    # Сохраняем время начала квиза в сессии ТОЛЬКО если его там еще нет
    if f'quiz_{quiz_id}_start_time' not in session:
        session[f'quiz_{quiz_id}_start_time'] = datetime.now().timestamp()
    
    return render_template('quiz.html', quiz=quiz)

@app.route('/quiz/<int:quiz_id>/submit', methods=['POST'])
@login_required
def submit_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    score = 0
    total_questions = len(quiz.questions)
    
    # Проверяем, не истекло ли время
    time_limit = quiz.minutes * 60  # в секундах
    start_time = session.get(f'quiz_{quiz_id}_start_time')
    if start_time and (datetime.now() - datetime.fromtimestamp(start_time)).total_seconds() > time_limit:
        flash('Время на выполнение квиза истекло!', 'warning')
    
    if QuizUser.query.filter_by(user_id=current_user.id, quiz_id=quiz_id).first():
        flash('Вы уже отправили результаты этого теста', 'danger')
        return redirect(url_for('index'))

    for question in quiz.questions:
        answer_id = request.form.get(f'question_{question.id}')
        if not answer_id:
            continue
            
        answer = Answer.query.get(int(answer_id))
        if answer and answer.is_correct:
            score += 1
        
        result = Result(
            user_id=current_user.id,
            quiz_id=quiz.id,
            question_id=question.id,
            answer_id=int(answer_id)
        )
        db.session.add(result)

    quiz_user = QuizUser(
        user_id=current_user.id,
        quiz_id=quiz.id,
        score=score
    )
    db.session.add(quiz_user)
    db.session.commit()

    percentage = (score / total_questions) * 100
    flash(f'Вы завершили квиз! Ваш результат: {score} из {total_questions} ({percentage:.1f}%)', 'success')
    
    # Удаляем время начала квиза из сессии после завершения
    if f'quiz_{quiz_id}_start_time' in session:
        del session[f'quiz_{quiz_id}_start_time']
        
    return redirect(url_for('index'))

@app.route('/quiz/<int:quiz_id>/delete', methods=['DELETE'])
@login_required
def delete_quiz(quiz_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Недостаточно прав'}), 403
    
    quiz = Quiz.query.get_or_404(quiz_id)
    try:
        db.session.delete(quiz)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(email='admin@example.com').first():
            admin = User(
                name='Admin',
                email='admin@example.com',
                password=generate_password_hash('adminpassword'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            print('Администратор создан успешно!')
    app.run(debug=True, host='0.0.0.0', port=8080)