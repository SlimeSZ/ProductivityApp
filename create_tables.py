import sqlite3
from werkzeug.security import generate_password_hash

def create_tables():
    try:
        conn = sqlite3.connect('daytabase.db')
        cursor = conn.cursor()
        
        #users/customers table
        conn.execute('''
        CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_name TEXT NOT NULL,
        email TEXT NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        
                    )
    ''')
        
        #categories table
        conn.execute('''
        CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE
                    )
    ''')
        
        #tasks table
        conn.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task TEXT NOT NULL,
        description TEXT,
        deadline DATETIME,
        priority TEXT CHECK(priority IN('low', 'medium', 'high', 'deepwork')) NOT NULL,
        start_time TEXT,
        end_time TEXT,
        done BOOLEAN DEFAULT 0,
        category_id INTEGER,
        FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE SET NULL
        
                    )
    ''')
        
        #subtasks table
        conn.execute('''
        CREATE TABLE IF NOT EXISTS subtasks (
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
    
    except sqlite3.Error as e:
        print(F"Error occured as: {e}")
    finally:
        if conn:
            conn.commit()    
            conn.close()
    #task prio


if __name__ == "__main__":
    create_tables()