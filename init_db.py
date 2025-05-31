from app import app, db
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

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
    except SQLAlchemyError as e:
        print("❌ Ошибка при создании таблиц:")
        print(str(e))

if __name__ == '__main__':
    if check_db_connection():
        initialize_database()
    else:
        print("❌ Невозможно создать таблицы из-за ошибки подключения к базе данных")
