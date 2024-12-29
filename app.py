from flask import Flask, redirect, render_template, url_for, request, jsonify
import sqlite3
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime 
from config import SECRET_KEY


app = Flask(__name__)
app.secret_key = SECRET_KEY

#Login Configuration
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data[0]
        self.username = user_data[1]
        self.email = user_data[2]

@login_manager.user_loader
def load_user(user_id):
    try:   
        conn = sqlite3.connect('daytabase.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user_data = c.fetchone()
    except sqlite3.Error as e:
        print(f'Error as {e}... ')
    finally:
        if conn:
            conn.close()
        if user_data:
            return User(user_data)
        return None

#login route & function
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        conn = None
        try:
            conn = sqlite3.connect('daytabase.db')
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE user_name = ? OR email = ?', (username, email))
            #user data to be passed into login configuration ()
            user_data = cursor.fetchone()
            if user_data and check_password_hash(user_data[3], password):
                user = User(user_data)
                login_user(user)
                return redirect(url_for('user_dashboard'))
            else:
                return render_template('login.html', error="An error occured during login")
        except sqlite3.Error as e:
            print(f'{e}')
        except Exception as e:
            print(f'{e}')
        finally:
            if conn:
                conn.close()
    return render_template('login.html')

#logout route & function
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

#register account route & function
@app.route('/register-account', methods=['GET', 'POST'])
def register_account():
    #register account handling
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_pw = generate_password_hash(password)

        conn = None
        try:
            conn = sqlite3.connect('daytabase.db')
            cursor = conn.cursor()
            cursor.execute('''
            INSERT INTO users (user_name, email, password)
            VALUES (?, ?, ?)
    ''', (username, email, hashed_pw))
            conn.commit()

            #auto login after registration handling
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            user_data = cursor.fetchone()
            if user_data:
                user = User(user_data)
                login_user(user)
                return redirect(url_for('user_dashboard'))
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_template('register.html', error="Username or email already Taken! ")
        except Exception as e:
            print(f'{e}')
        except sqlite3.Error as e:
            print(f'{e}')
        finally:
            if conn:
                conn.close()

    return render_template('register.html')             


#Add category func
@app.route('/add-category', methods=['POST'])
@login_required  # Add this decorator
def add_category():
    category_name = request.form.get('category_name')
    if not category_name:
        return jsonify({'error': 'Category Name is Required'}), 400

    try:
        conn = sqlite3.connect('daytabase.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO categories (name, user_id) VALUES (?, ?)', 
                      (category_name, current_user.id))
        conn.commit()
        new_id = cursor.lastrowid
        return jsonify({'id': new_id, 'name': category_name}), 200
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Category Already Exists'}), 400
    finally:
        conn.close()


#user dashboard function
@app.route('/user-dashboard')
@login_required
def user_dashboard():
    try:
        conn = sqlite3.connect('daytabase.db')
        cursor = conn.cursor()
        
        # Get categories for the current user
        cursor.execute('SELECT * FROM categories WHERE user_id = ?', (current_user.id,))
        categories = cursor.fetchall()
        print("Categories:", categories)  # Debug print
        
        # Get tasks for the current user
        cursor.execute('''
        SELECT t.*, c.name as category_name 
        FROM tasks t 
        LEFT JOIN categories c ON t.category_id = c.id
        WHERE t.user_id = ?
        ORDER BY t.id DESC
        ''', (current_user.id,))
        tasks = cursor.fetchall()
        print("Tasks:", tasks)  # Debug print
        
        # Get subtasks for the current user's tasks
        cursor.execute('''
        SELECT s.* 
        FROM subtasks s
        JOIN tasks t ON s.task_id = t.id
        WHERE t.user_id = ?
        ORDER BY s.task_id, s.level, s.id
        ''', (current_user.id,))
        subtasks = cursor.fetchall()
        print("Subtasks:", subtasks)  # Debug print
        
        return render_template('user_dashboard.html', 
                             categories=categories,
                             tasks=tasks,
                             subtasks=subtasks)
    except Exception as e:
        print(f"Dashboard Error: {e}")
        return f"Error loading dashboard: {str(e)}", 500
    finally:
        if conn:
            conn.close()

            
#CRUD
#Create/Add task function
@app.route('/add-task', methods=['POST'])
@login_required
def add_task():
    task_name = request.form.get('task')
    description = request.form.get('description') or None
    deadline = request.form.get('deadline') or None
    priority = request.form.get('priority')
    category_id = request.form.get('category_id')
    start_time = request.form.get('start_time') or None
    end_time = request.form.get('end_time') or None
    
    if not task_name or not priority or not category_id:
        return jsonify({'error': 'Task name, priority, and category are required'}), 400
        
    try:
        conn = sqlite3.connect('daytabase.db')
        cursor = conn.cursor()
        
        # Verify the category belongs to the current user
        cursor.execute('SELECT id FROM categories WHERE id = ? AND user_id = ?', 
                      (category_id, current_user.id))
        if not cursor.fetchone():
            return jsonify({'error': 'Invalid category'}), 400
            
        cursor.execute('''
        INSERT INTO tasks (
            task, description, deadline, priority, 
            category_id, start_time, end_time, done, user_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (task_name, description, deadline, priority, 
              category_id, start_time, end_time, False, current_user.id))
        conn.commit()
        new_id = cursor.lastrowid
        return jsonify({'id': new_id, 'task': task_name}), 200
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return jsonify({'error': str(e)}), 400
    finally:
        if conn:
            conn.close()

@app.route('/toggle-task/<int:task_id>')
@login_required
def mark_task_done(task_id):
    try:
        conn = sqlite3.connect('daytabase.db')
        cursor = conn.cursor()
        
        # Get current task status and verify ownership
        cursor.execute("SELECT done FROM tasks WHERE id = ? AND user_id = ?", 
                      (task_id, current_user.id))
        result = cursor.fetchone()
        
        if not result:
            return jsonify({'error': 'Unauthorized'}), 403
            
        current_status = result[0]
        new_status = not current_status
        
        # Update task status
        cursor.execute("UPDATE tasks SET done = ? WHERE id = ? AND user_id = ?", 
                      (new_status, task_id, current_user.id))
        
        # Mark all subtasks with the same status
        mark_subtasks_as_done(cursor, task_id, new_status, current_user.id)
        
        conn.commit()
        return jsonify({'success': True})
    except sqlite3.Error as e:
        return jsonify({'error': str(e)}), 400
    finally:
        if conn:
            conn.close()

@app.route('/toggle-subtask/<int:subtask_id>')
@login_required
def mark_subtask_done(subtask_id):
    try:
        conn = sqlite3.connect('daytabase.db')
        cursor = conn.cursor()
        
        # Verify the subtask belongs to a task owned by the current user
        cursor.execute('''
            SELECT s.done FROM subtasks s
            JOIN tasks t ON s.task_id = t.id
            WHERE s.id = ? AND t.user_id = ?
        ''', (subtask_id, current_user.id))
        
        result = cursor.fetchone()
        if not result:
            return jsonify({'error': 'Unauthorized'}), 403
            
        current_status = result[0]
        new_status = not current_status
        
        # Update the subtask status
        cursor.execute('''
            UPDATE subtasks SET done = ?
            WHERE id = ? AND EXISTS (
                SELECT 1 FROM tasks t 
                WHERE t.id = subtasks.task_id 
                AND t.user_id = ?
            )
        ''', (new_status, subtask_id, current_user.id))
        
        # Mark all child subtasks with the same status
        mark_child_subtasks_as_done(cursor, subtask_id, new_status, current_user.id)
        
        conn.commit()
        return jsonify({'success': True})
    except sqlite3.Error as e:
        return jsonify({'error': str(e)}), 400
    finally:
        if conn:
            conn.close()

def mark_subtasks_as_done(cursor, task_id, status, user_id):
    cursor.execute("""
        UPDATE subtasks SET done = ? 
        WHERE task_id = ?
        AND EXISTS (
            SELECT 1 FROM tasks t 
            WHERE t.id = subtasks.task_id 
            AND t.user_id = ?
        )
    """, (status, task_id, user_id))
    
    # Get all direct subtasks
    cursor.execute("""
        SELECT id FROM subtasks 
        WHERE task_id = ?
        AND EXISTS (
            SELECT 1 FROM tasks t 
            WHERE t.id = subtasks.task_id 
            AND t.user_id = ?
        )
    """, (task_id, user_id))
    
    subtasks = cursor.fetchall()
    for subtask in subtasks:
        mark_child_subtasks_as_done(cursor, subtask[0], status, user_id)


def mark_child_subtasks_as_done(cursor, parent_subtask_id, status, user_id):
    cursor.execute("""
        WITH RECURSIVE subtree AS (
            SELECT id FROM subtasks 
            WHERE parent_id = ?
            AND EXISTS (
                SELECT 1 FROM tasks t 
                WHERE t.id = subtasks.task_id 
                AND t.user_id = ?
            )
            UNION ALL
            SELECT s.id FROM subtasks s
            JOIN subtree st ON s.parent_id = st.id
        )
        UPDATE subtasks 
        SET done = ?
        WHERE id IN (SELECT id FROM subtree)
    """, (parent_subtask_id, user_id, status))

#Create/Add sub-task function
@app.route('/add-subtask', methods=['POST'])
@login_required
def add_subtask():
    subtask_name = request.form.get('subtask')
    description = request.form.get('description') or None
    deadline = request.form.get('deadline') or None
    priority = request.form.get('priority')
    category_id = request.form.get('category_id')
    task_id = request.form.get('task_id')
    parent_id = request.form.get('parent_id')
    start_time = request.form.get('start_time') or None
    end_time = request.form.get('end_time') or None
    
    if not subtask_name or not priority:
        return jsonify({'error': 'Sub task name and priority are required'}), 400
    
    try:
        conn = sqlite3.connect('daytabase.db')
        cursor = conn.cursor()
        
        # Verify the parent task belongs to the current user
        cursor.execute('SELECT id FROM tasks WHERE id = ? AND user_id = ?', 
                      (task_id, current_user.id))
        if not cursor.fetchone():
            return jsonify({'error': 'Unauthorized access to task'}), 403
            
        # If there's a parent subtask, verify it belongs to the specified task
        if parent_id:
            cursor.execute('SELECT level FROM subtasks WHERE id = ? AND task_id = ?', 
                         (parent_id, task_id))
            parent_result = cursor.fetchone()
            if not parent_result:
                return jsonify({'error': 'Invalid parent subtask'}), 400
            parent_level = parent_result[0]
            level = parent_level + 1
        else:
            level = 1

        cursor.execute('''
        INSERT INTO subtasks (
            subtask, description, deadline, priority, 
            category_id, task_id, parent_id, level, 
            start_time, end_time, done
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (subtask_name, description, deadline, priority, 
              category_id, task_id, parent_id, level, 
              start_time, end_time, False))
        conn.commit()

        new_id = cursor.lastrowid
        return jsonify({
            'id': new_id,
            'subtask': subtask_name,
            'level': level,
            'parent_id': parent_id
        }), 200

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return jsonify({'error': str(e)}), 400
    finally:
        if conn:
            conn.close()




@app.route('/edit-task/<int:task_id>', methods=['POST', 'GET'])
@login_required
def edit_task(task_id):
    conn = sqlite3.connect('daytabase.db')
    try:
        cursor = conn.cursor()
        if request.method == 'GET':
            cursor.execute('SELECT * FROM tasks WHERE id = ? AND user_id = ?', 
                         (task_id, current_user.id))
            task = cursor.fetchone()
            return jsonify(task) if task else ('Task not found', 404)
            
        if request.method == 'POST':
            # Verify task ownership
            cursor.execute('SELECT id FROM tasks WHERE id = ? AND user_id = ?', 
                         (task_id, current_user.id))
            if not cursor.fetchone():
                return jsonify({'error': 'Unauthorized'}), 403
                
            task_data = request.form
            cursor.execute('''
            UPDATE tasks 
            SET task = ?, description = ?, deadline = ?, priority = ?, 
                start_time = ?, end_time = ?, category_id = ?
            WHERE id = ? AND user_id = ?
            ''', (task_data['task'], task_data.get('description'), 
                  task_data.get('deadline'), task_data['priority'],
                  task_data.get('start_time'), task_data.get('end_time'),
                  task_data.get('category_id'), task_id, current_user.id))
            conn.commit()
            return jsonify({'success': True})
    except sqlite3.Error as e:
        print(f"Error occurred: {e}")
        return jsonify({'error': str(e)}), 400
    finally:
        conn.close()


@app.route('/edit-subtask/<int:subtask_id>', methods=['POST', 'GET'])
@login_required
def edit_subtask(subtask_id):
    conn = sqlite3.connect('daytabase.db')
    try:
        cursor = conn.cursor()
        
        # First verify the subtask belongs to a task owned by the current user
        cursor.execute('''
            SELECT s.* FROM subtasks s
            JOIN tasks t ON s.task_id = t.id
            WHERE s.id = ? AND t.user_id = ?
        ''', (subtask_id, current_user.id))
        
        if request.method == 'GET':
            subtask = cursor.fetchone()
            return jsonify(subtask) if subtask else ('Subtask not found', 404)
            
        if request.method == 'POST':
            if not cursor.fetchone():
                return jsonify({'error': 'Unauthorized'}), 403
                
            subtask_data = request.form
            cursor.execute('''
            UPDATE subtasks 
            SET subtask = ?, description = ?, deadline = ?, priority = ?,
                start_time = ?, end_time = ?, category_id = ?
            WHERE id = ? AND EXISTS (
                SELECT 1 FROM tasks t 
                WHERE t.id = subtasks.task_id 
                AND t.user_id = ?
            )
            ''', (subtask_data['subtask'], subtask_data.get('description'),
                  subtask_data.get('deadline'), subtask_data['priority'],
                  subtask_data.get('start_time'), subtask_data.get('end_time'),
                  subtask_data.get('category_id'), subtask_id, current_user.id))
            conn.commit()
            return jsonify({'success': True})
    except sqlite3.Error as e:
        print(f"Error occurred: {e}")
        return jsonify({'error': str(e)}), 400
    finally:
        conn.close()


@app.route('/delete-task/<int:task_id>')
@login_required
def delete_task(task_id):
    try:
        conn = sqlite3.connect('daytabase.db')
        c = conn.cursor()
        # Verify task ownership before deletion
        c.execute("SELECT id FROM tasks WHERE id = ? AND user_id = ?", 
                 (task_id, current_user.id))
        if not c.fetchone():
            return jsonify({'error': 'Unauthorized'}), 403
            
        c.execute("DELETE FROM subtasks WHERE task_id = ?", (task_id,))
        c.execute("DELETE FROM tasks WHERE id = ? AND user_id = ?", 
                 (task_id, current_user.id))
        conn.commit()
        return jsonify({'success': True})
    except sqlite3.Error as e:
        print(f"Error occurred: {e}")
        return jsonify({'error': str(e)}), 400
    finally:
        conn.close()


@app.route('/delete-subtask/<int:subtask_id>')
@login_required
def delete_subtask(subtask_id):
    try:
        conn = sqlite3.connect('daytabase.db')
        c = conn.cursor()
        
        # Verify the subtask belongs to a task owned by the current user
        c.execute('''
            SELECT s.id FROM subtasks s
            JOIN tasks t ON s.task_id = t.id
            WHERE s.id = ? AND t.user_id = ?
        ''', (subtask_id, current_user.id))
        
        if not c.fetchone():
            return jsonify({'error': 'Unauthorized'}), 403
            
        # Delete the subtask and its children only if authorized
        c.execute("""
            WITH RECURSIVE subtree AS (
                SELECT id FROM subtasks 
                WHERE id = ? 
                AND EXISTS (
                    SELECT 1 FROM tasks t 
                    WHERE t.id = subtasks.task_id 
                    AND t.user_id = ?
                )
                UNION ALL
                SELECT s.id FROM subtasks s
                INNER JOIN subtree st ON s.parent_id = st.id
            ) 
            DELETE FROM subtasks 
            WHERE id IN subtree
        """, (subtask_id, current_user.id))
        
        conn.commit()
        return jsonify({'success': True})
    except sqlite3.Error as e:
        print(f"Error occurred: {e}")
        return jsonify({'error': str(e)}), 400
    finally:
        conn.close()

@app.route('/', methods=['GET', 'POST'])
def home():
    if current_user.is_authenticated:
        return redirect(url_for('user_dashboard'))
    return render_template('index.html')
    
if __name__ == "__main__":
    app.run(debug=True)