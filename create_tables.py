import sqlite3
from werkzeug.security import generate_password_hash

def create_tables():
    try:
        conn = sqlite3.connect('daytabase.db')
        cursor = conn.cursor()
        
        # First, drop existing tables (careful with this in production!)
        cursor.executescript('''
            DROP TABLE IF EXISTS subtasks;
            DROP TABLE IF EXISTS tasks;
            DROP TABLE IF EXISTS categories;
            DROP TABLE IF EXISTS users;
        ''')
        
        # Create users table
        cursor.execute('''
        CREATE TABLE users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_name TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create categories table with user_id
        cursor.execute('''
        CREATE TABLE categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(name, user_id)
        )
        ''')
        
        # Create tasks table with user_id
        cursor.execute('''
        CREATE TABLE tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task TEXT NOT NULL,
            description TEXT,
            deadline DATETIME,
            priority TEXT CHECK(priority IN('low', 'medium', 'high', 'deepwork')) NOT NULL,
            start_time TEXT,
            end_time TEXT,
            done BOOLEAN DEFAULT 0,
            category_id INTEGER,
            user_id INTEGER NOT NULL,
            FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE SET NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        ''')
        
        # Create subtasks table
        cursor.execute('''
        CREATE TABLE subtasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subtask TEXT NOT NULL,
            description TEXT,
            deadline DATETIME,
            priority TEXT CHECK(priority IN ('low', 'medium', 'high', 'deepwork')) NOT NULL,
            start_time TEXT,
            end_time TEXT,
            done BOOLEAN DEFAULT 0,
            category_id INTEGER,
            task_id INTEGER NOT NULL,
            parent_id INTEGER,
            level INTEGER NOT NULL,
            FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE SET NULL,
            FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
            FOREIGN KEY (parent_id) REFERENCES subtasks(id) ON DELETE CASCADE
        )
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS completed (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT NOT NULL,
        task_name TEXT NOT NULL,
        task_description TEXT,
        is_subtask BOOLEAN NOT NULL,
        parent_task_name TEXT,
        user_id INTEGER NOT NULL,
        completed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        ''')
        
        print("Tables created successfully!")
        conn.commit()
        
    except sqlite3.Error as e:
        print(f"Error occurred: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    create_tables()