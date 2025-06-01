from app import app, db, User
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import generate_password_hash

def check_db_connection():
    try:
        with app.app_context():
            # Проверяем подключение к базе данных
            db.session.execute(text('SELECT 1'))
            print("✅ Подключение к базе данных успешно установлено!")
            return True
    except SQLAlchemyError as e:
        print("❌ Ошибка подключения к базе данных:")
        print(str(e))
        return False

def initialize_database():
    try:
        with app.app_context():
            db.create_all()
            print("✅ Таблицы базы данных успешно созданы!")

            # Проверяем, существует ли администратор с заданным email
            if not User.query.filter_by(email='admin@mail.ru').first():
                # Создаем нового администратора
                admin = User(
                    name='Admin',
                    email='admin@mail.ru',
                    password=generate_password_hash('admin', method='pbkdf2:sha256'),
                    is_admin=True
                )
                db.session.add(admin)
                db.session.commit()
                print("✅ Администратор с email admin@mail.ru создан успешно!")
            else:
                print("ℹ️ Администратор с email admin@mail.ru уже существует.")

    except SQLAlchemyError as e:
        db.session.rollback()
        print("❌ Ошибка при инициализации базы данных:")
        print(str(e))

if __name__ == '__main__':
    if check_db_connection():
        initialize_database()
    else:
        print("❌ Невозможно инициализировать базу данных из-за ошибки подключения")
