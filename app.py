importfrom wtforms import StringField, PasswordField, SubmitField, BooleanField, IntegerField
from wtforms.validators import DataRequired, Email, Length
from wtforms.fields import FieldList, FormField
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hashfrom flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, IntegerField
from wtforms.validators import DataRequired, Email, Length
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
bootstrap = Bootstrap(app)

# Конфигурация базы данных
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://timyrnikolaev:nbver1702@localhost:5432/quiz'
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

# Формы для работы с квизами
class QuizForm(FlaskForm):
    name = StringField('Название', validators=[DataRequired(), Length(min=2, max=100)])
    description = StringField('Описание', validators=[DataRequired()])
    minutes = IntegerField('Время (в минутах)', validators=[DataRequired()])
    submit = SubmitField('Сохранить')

class QuestionForm(FlaskForm):
    question = StringField('Вопрос', validators=[DataRequired()])
    answers = FieldList(FormField(AnswerForm), min_entries=4)
    submit = SubmitField('Добавить вопрос')

class AnswerForm(FlaskForm):
    answer = StringField('Вариант ответа', validators=[DataRequired()])
    is_correct = BooleanField('Правильный ответ')

# Модели базы данных
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False, unique=True)
    email_verified_at = db.Column(db.DateTime)
    password = db.Column(db.String, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    remember_token = db.Column(db.String)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Quiz(db.Model):
    __tablename__ = 'quizzes'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    description = db.Column(db.Text)
    minutes = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    questions = db.relationship('Question', backref='quiz', lazy=True)

class Question(db.Model):
    __tablename__ = 'questions'
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String, nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quizzes.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    answers = db.relationship('Answer', backref='question', lazy=True)

class Answer(db.Model):
    __tablename__ = 'answers'
    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.Integer, db.ForeignKey('questions.id'), nullable=False)
    answer = db.Column(db.String, nullable=False)
    is_correct = db.Column(db.Boolean, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Result(db.Model):
    __tablename__ = 'results'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quizzes.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('questions.id'), nullable=False)
    answer_id = db.Column(db.Integer, db.ForeignKey('answers.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class QuizUser(db.Model):
    __tablename__ = 'quiz_user'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quizzes.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    quizzes = Quiz.query.all()
    return render_template('index.html', quizzes=quizzes)

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
        hashed_password = generate_password_hash(form.password.data)
        user = User(name=form.name.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

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
def quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    return render_template('quiz.html', quiz=quiz)

@app.route('/admin/quiz/create', methods=['GET', 'POST'])
@login_required
def create_quiz():
    if not current_user.is_admin:
        flash('У вас нет прав для доступа к этой странице', 'danger')
        return redirect(url_for('index'))
    
    form = QuizForm()
    if form.validate_on_submit():
        quiz = Quiz(
            name=form.name.data,
            description=form.description.data,
            minutes=form.minutes.data
        )
        db.session.add(quiz)
        db.session.commit()
        flash('Квиз успешно создан!', 'success')
        return redirect(url_for('admin'))
    return render_template('quiz_form.html', form=form, title='Создать квиз')

@app.route('/admin/quiz/<int:quiz_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_quiz(quiz_id):
    if not current_user.is_admin:
        flash('У вас нет прав для доступа к этой странице', 'danger')
        return redirect(url_for('index'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    form = QuizForm()
    
    if form.validate_on_submit():
        quiz.name = form.name.data
        quiz.description = form.description.data
        quiz.minutes = form.minutes.data
        db.session.commit()
        flash('Квиз успешно обновлен!', 'success')
        return redirect(url_for('admin'))
    
    elif request.method == 'GET':
        form.name.data = quiz.name
        form.description.data = quiz.description
        form.minutes.data = quiz.minutes
    
    return render_template('quiz_form.html', form=form, title='Редактировать квиз')

@app.route('/admin/quiz/<int:quiz_id>/delete', methods=['POST'])
@login_required
def delete_quiz(quiz_id):
    if not current_user.is_admin:
        flash('У вас нет прав для доступа к этой странице', 'danger')
        return redirect(url_for('index'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    db.session.delete(quiz)
    db.session.commit()
    flash('Квиз успешно удален!', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/quiz/<int:quiz_id>/questions', methods=['GET', 'POST'])
@login_required
def manage_questions(quiz_id):
    if not current_user.is_admin:
        flash('У вас нет прав для доступа к этой странице', 'danger')
        return redirect(url_for('index'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    form = QuestionForm()

    if form.validate_on_submit():
        question = Question(question=form.question.data, quiz_id=quiz_id)
        db.session.add(question)
        db.session.flush()  # Чтобы получить id вопроса

        for answer_form in form.answers:
            answer = Answer(
                question_id=question.id,
                answer=answer_form.answer.data,
                is_correct=answer_form.is_correct.data
            )
            db.session.add(answer)

        db.session.commit()
        flash('Вопрос успешно добавлен!', 'success')
        return redirect(url_for('manage_questions', quiz_id=quiz_id))

    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    return render_template('manage_questions.html', quiz=quiz, form=form, questions=questions)

@app.route('/admin/question/<int:question_id>/delete', methods=['POST'])
@login_required
def delete_question(question_id):
    if not current_user.is_admin:
        flash('У вас нет прав для доступа к этой странице', 'danger')
        return redirect(url_for('index'))

    question = Question.query.get_or_404(question_id)
    quiz_id = question.quiz_id
    
    # Удаляем связанные ответы
    Answer.query.filter_by(question_id=question_id).delete()
    
    db.session.delete(question)
    db.session.commit()
    
    flash('Вопрос успешно удален!', 'success')
    return redirect(url_for('manage_questions', quiz_id=quiz_id))

@app.route('/quiz/<int:quiz_id>/start', methods=['GET'])
@login_required
def start_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    return render_template('quiz.html', quiz=quiz)

@app.route('/quiz/<int:quiz_id>/submit', methods=['POST'])
@login_required
def submit_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    score = 0
    total_questions = len(quiz.questions)

    for question in quiz.questions:
        answer_id = request.form.get(f'question-{question.id}')
        if answer_id:
            answer = Answer.query.get(int(answer_id))
            if answer and answer.is_correct:
                score += 1
            
            # Сохраняем ответ пользователя
            result = Result(
                user_id=current_user.id,
                quiz_id=quiz.id,
                question_id=question.id,
                answer_id=int(answer_id)
            )
            db.session.add(result)

    # Записываем что пользователь прошел квиз
    quiz_user = QuizUser(
        user_id=current_user.id,
        quiz_id=quiz.id
    )
    db.session.add(quiz_user)
    db.session.commit()

    percentage = (score / total_questions) * 100
    flash(f'Вы завершили квиз! Ваш результат: {score} из {total_questions} ({percentage:.1f}%)', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)
