from flask import Flask, redirect, render_template, url_for, request, jsonify
import sqlite3
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
from typing import Tuple
from itsdangerous.url_safe import URLSafeSerializer
from itsdangerous.exc import SignatureExpired, BadSignature

app = Flask(__name__)
app.secret_key = 'Secret Key'


serializer = URLSafeSerializer(app.secret_key)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, user_data: Tuple[int, str, str]):
        if not user_data or len(user_data) < 3:
            raise ValueError("Invalid User Data for login Process")

        self.id: int = user_data[0]
        self.username: str = user_data[1]
        self.email: str = user_data[2]
     
@login_manager.user_loader
def load_user(user_id):
    try:
        #with statement ensures no need for conn.close since the conn is auto closed whether exception error or block is exited
        with sqlite3.connect('daytabase.db') as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            user_data = cursor.fetchone()
            return User(user_data) if user_data else None
    except sqlite3.Error as e:
        print(f"{e}")
        return None
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        if not username or not email or not password:
            return render_template('login.html', error="Username/Email & PW are required fields")
        
        try:
            with sqlite3.connect('daytabase.db') as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM users WHERE user_name = ? OR email = ?', (username, email))
                user_data = cursor.fetchone()
                if user_data and check_password_hash(user_data[3], password):
                    user = User(user_data)
                    login_user(user)
                    return redirect(url_for('user_dashboard'))
                else:
                    return render_template('login.html', error="Invalid Credentials")
        except sqlite3.Error as e:
            print(f"DB error: {e}")
            return render_template('login.html', error="An internal error occured")
        except Exception as e:
            print(f"Unexpected error as {e}")
            return render_template('login.html', error="Unexpected Error occured")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))
    
@app.route('/register-account', methods=['GET', 'POST'])
def register_account():
    if request.method == 'POST':
        username = request.form.get('username')    
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not username or not email or not password:
            return render_template('register.html', error="All fields are required")
        
        try:
            hashed_pw = generate_password_hash(password)
            with sqlite3.connect('daytabase.db') as conn:
                cursor = conn.cursor()
                cursor.execute('''
                INSERT into USERS (user_name, email, password) VALUES (?, ?, ?)
                ''', (username, email, hashed_pw))
                conn.commit()

                #autologin if successful registration
                cursor.execute('SELECT * FROM users WHERE email = ?', (email, ))
                user_data = cursor.fetchone()
                if user_data:
                    user = User(user_data)
                    login_user(user)
                    return redirect(url_for('user_dashboard'))
        except sqlite3.IntegrityError:
            return render_template('register.html', error="Username or email already taken")
        except sqlite3.Error as e:
            print(f"DB error as {e}")
            return render_template('register.html', error="An internal error occured")
        except Exception as e:
            print(f"Unexpectd error as {e}")
            return render_template('register.html', error="Unexpected error occured")
    return render_template('register.html')

#request password reset
@app.route('/reset-password', methods=['GET', 'POST'])
def request_password_reset():
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            return render_template('reset_password_request.html', error="Email is Required")
        
        try:
            with sqlite3.connect('daytabase.db') as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM users WHERE email = ?', (email, ))
                user_data = cursor.fetchone()
                if user_data:
                    token = serializer.dumps(email, salt='password-reset-salt')
                    # Here, you'd send the token to the user's email (pseudo-code)
                    # send_email(email, f"Reset your password: {url_for('reset_password', token=token, _external=True)}")
                    return render_template('reset_password_request.html', message="A password reset link has been sent to your email")
                else:
                    return render_template('reset_password_request.html', error="Email not found.")

        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return render_template('reset_password_request.html', error="An internal error occurred. Please try again.")

    # Render the password reset request page for GET requests
    return render_template('reset_password_request.html')

#actual password reset
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
        if request.method == 'POST':
            new_password = request.form.get('password')
            if not new_password:
                return render_template('reset_password.html', error="Password is required.", token=token)

            hashed_pw = generate_password_hash(new_password)

            # Update the user's password in the database
            with sqlite3.connect('daytabase.db') as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET password = ? WHERE email = ?', (hashed_pw, email))
                conn.commit()

                return redirect(url_for('login'))

        # Render the reset password page for GET requests
        return render_template('reset_password.html', token=token)

    except SignatureExpired:  # Now using the properly imported exception
        return render_template('reset_password_request.html', 
                             error="The password reset link has expired.")
    except BadSignature:  # Now using the properly imported exception
        return render_template('reset_password_request.html', 
                             error="Invalid password reset link.")


#---------------------------------------------------------
#--------------------ADD Tasks, Subtasks, & Categories------------------------
#---------------------------------------------------------

@app.route('/add-category', methods=['POST'])
@login_required
def add_category():
    category_name = request.form.get('category_name')
    if not category_name:
        return jsonify({'error': 'Category Name is Required'}), 400
    try:
        with sqlite3.connect('daytabase.db') as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO categories (name, user_id) VALUES (?, ?)', (category_name, current_user.id))
            
            conn.commit()
            new_id = cursor.lastrowid #get id of latest category added by user
            return jsonify({'id': new_id, 'name': category_name}), 200
    except sqlite3.IntegrityError as e:
        return jsonify({'error': 'Category already exists'}), 400
    except sqlite3.Error as e:
        # Handle general database errors
        print(f"Database error: {e}")
        return jsonify({'error': 'An internal error occurred'}), 500

@app.route('/add-task', methods=['POST'])
@login_required  # Add this decorator
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
        with sqlite3.connect('daytabase.db') as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT id FROM categories WHERE id = ?', (category_id,))
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
        return jsonify({'error': 'Subtask name and priority are required'}), 400
    
    try:
        with sqlite3.connect('daytabase.db') as conn:
            cursor = conn.cursor()

            # Verify the parent task belongs to the current user
            cursor.execute('SELECT id FROM tasks WHERE id = ? AND user_id = ?', 
                         (task_id, current_user.id))
            if not cursor.fetchone():
                return jsonify({'error': 'Unauthorized access to task'}), 403

            # If there's a parent_id, verify it belongs to the specified task
            if parent_id:
                cursor.execute('''
                    SELECT level FROM subtasks s
                    JOIN tasks t ON s.task_id = t.id 
                    WHERE s.id = ? AND t.user_id = ? AND s.task_id = ?
                ''', (parent_id, current_user.id, task_id))
                parent_row = cursor.fetchone()
                if parent_row is None:
                    return jsonify({'error': 'Parent subtask not found or unauthorized'}), 404
                parent_level = parent_row[0]
                level = parent_level + 1
            else:
                level = 1
            
            cursor.execute('''
            INSERT INTO subtasks (
            subtask, description, deadline, priority, start_time, end_time, done, category_id, task_id, parent_id, level
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (subtask_name, description, deadline, priority, start_time, end_time, False, category_id, task_id, parent_id, level))
            conn.commit()

            new_id = cursor.lastrowid
            return jsonify({
                'id': new_id,
                'subtask': subtask_name,
                'level': level,
                'parent id': parent_id
            }), 200
        
    except sqlite3.IntegrityError as e:
        print(f"Integrity Error: {e}")
        return jsonify({'error': 'Database integrity error occurred'}), 400

    except sqlite3.Error as e:
        print(f"Database Error: {e}")
        return jsonify({'error': 'An internal database error occurred'}), 500

    except Exception as e:
        print(f"Unexpected Error: {e}")
        return jsonify({'error': 'An unexpected error occurred. Please try again later.'}), 500
            

#---------------------------------------------------------
#--------------------Update Tasks & Subtasks------------------------
#---------------------------------------------------------

@app.route('/edit-task/<int:task_id>', methods=['POST', 'GET'])
@login_required
def edit_task(task_id):
    try:
        with sqlite3.connect('daytabase.db') as conn:
            cursor = conn.cursor()

            if request.method == 'GET':
                cursor.execute('SELECT * FROM tasks WHERE id = ? AND user_id = ?', (task_id, current_user.id))
                task = cursor.fetchone()
                if task is None:
                    return jsonify({'error': 'Task not found'}), 404

                return jsonify({
                    'id': task[0],
                    'task': task[1],
                    'description': task[2],
                    'deadline': task[3],
                    'priority': task[4],
                    'start_time': task[5],
                    'end_time': task[6],
                    'done': task[7],
                    'category_id': task[8]
                }), 200

            elif request.method == 'POST':
                task_data = request.form
                if not task_data.get('task') or not task_data.get('priority'):
                    return jsonify({'error': 'Task name and priority are required'}), 400

                cursor.execute('''
                UPDATE tasks SET
                task = ?,
                description = ?, 
                deadline = ?, 
                priority = ?, 
                start_time = ?, 
                end_time = ?, 
                category_id = ?
                WHERE id = ? AND user_id = ?
                ''', (
                    task_data['task'],
                    task_data.get('description'),
                    task_data.get('deadline'),
                    task_data['priority'],
                    task_data.get('start_time'),
                    task_data.get('end_time'),
                    task_data.get('category_id'),
                    task_id,
                    current_user.id
                ))
                conn.commit()
                return jsonify({'success': True})
            
    except sqlite3.Error as e:
        return jsonify({'error': str(e)}), 400
    
@app.route('/edit-subtask/<int:subtask_id>', methods=['POST', 'GET'])
@login_required
def edit_subtask(subtask_id):
    try:
        with sqlite3.connect('daytabase.db') as conn:
            cursor = conn.cursor()

            ownership_check = '''
                SELECT s.* FROM subtasks s
                JOIN tasks t ON s.task_id = t.id
                WHERE s.id = ? AND t.user_id = ?
            '''
            
            if request.method == 'GET':
                cursor.execute(ownership_check, (subtask_id, current_user.id))
                subtask = cursor.fetchone()
                if not subtask:
                    return jsonify(subtask) if subtask else ('Subtask Not found', 404)
                return jsonify(subtask)

            if request.method == 'POST':
                cursor.execute(ownership_check, (subtask_id, current_user.id))
                if not cursor.fetchone():
                    return jsonify({'error': 'Unauthorized Access'}), 403
                
                subtask_data = request.form
                cursor.execute('''
                UPDATE subtasks SET subtask = ?, description = ?, deadline = ?, priority = ?,
                start_time = ?, end_time = ?, category_id = ?
                WHERE id = ?
                ''', (subtask_data['subtask'], subtask_data.get('description'),
                    subtask_data.get('deadline'), subtask_data['priority'],
                    subtask_data.get('start_time'), subtask_data.get('end_time'),
                    subtask_data.get('category_id'), subtask_id))
                conn.commit()
                return jsonify({'success': True})
    except sqlite3.Error as e:
        print(f"Error occured {e}")
        return jsonify({'error': str(e)}), 400
    

#---------------------------------------------------------
#--------------------Delete Tasks, subtasks, & child tasks recursively----------
#---------------------------------------------------------

@app.route('/delete-task/<int:task_id>')
@login_required
def delete_task(task_id):
    try:
        with sqlite3.connect('daytabase.db') as conn:
            cursor = conn.cursor()
            
            #user auth
            cursor.execute("SELECT id FROM tasks WHERE id = ? AND user_id = ?", 
                         (task_id, current_user.id))
            if not cursor.fetchone():
                return jsonify({'error': 'Unauthorized access'}), 403
            
            cursor.execute("DELETE FROM subtasks WHERE task_id = ?", (task_id, ))
            cursor.execute("DELETE FROM tasks WHERE id = ?", (task_id, ))
            conn.commit()
            return jsonify({'success': True})
    except sqlite3.Error as e:
        return jsonify({'error': str(e)}), 400


@app.route('/delete-subtask/<int:subtask_id>')
@login_required
def delete_subtask(subtask_id):
    try:
        with sqlite3.connect('daytabase.db') as conn:
            cursor = conn.cursor()

            cursor.execute('''
            SELECT s.id FROM subtasks s JOIN tasks t ON s.task_id = t.id WHERE s.id = ? AND t.user_id = ?
            ''', (subtask_id, current_user.id))
            if not cursor.fetchone():
                return jsonify({'error': 'Unauthorized access'}), 403

            cursor.execute("""
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
        return jsonify({'error': str(e)}), 400



#---------------------------------------------------------
#------SET Tasks, Subtasks, & Child Tasks... As done------
#---------------------------------------------------------

@app.route('/toggle-task/<int:task_id>')
@login_required
def mark_task_done(task_id):
    try:
        with sqlite3.connect('daytabase.db') as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT done, task, description FROM tasks WHERE id = ? AND user_id = ?', 
                         (task_id, current_user.id))
            task = cursor.fetchone()
            if task is None:
                return jsonify({'error': 'Task not found'}), 404
            current_status = task[0] #note we are already in the done column here because of the latest query
            #the [0] is not fetching the first col in the table, rather it gets the corresponding ids done value

            task_name = task[1]
            task_description = task[2]

            #not operation flips 0 --> 1 & vice versa
            new_status = not current_status
            cursor.execute("UPDATE tasks SET done = ? WHERE id = ?", (new_status, task_id))

            #for journal entry
            today = datetime.now().strftime('%Y-%m-%d')

            if new_status:
                # Add main task to journal
                cursor.execute('''
                    INSERT INTO completed (date, task_name, task_description, is_subtask, parent_task_name, user_id)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (today, task_name, task_description, False, None, current_user.id))
            else:  # Task is being unchecked
                # Remove task and its subtasks from journal
                cursor.execute('''
                    DELETE FROM completed 
                    WHERE user_id = ? AND (task_name = ? OR parent_task_name = ?)
                ''', (current_user.id, task_name, task_name))


            mark_subtasks_of_task_as_done(cursor, task_id, new_status)
            conn.commit()
            return jsonify({'success': True, 'task_id': task_id, 'new_status': new_status}), 200

    except sqlite3.Error as e:
        print(f"Database Error: {e}")
        return jsonify({'error': 'A database error occurred. Please try again later.'}), 500

    except Exception as e:
        print(f"Unexpected Error: {e}")
        return jsonify({'error': 'An unexpected error occurred. Please try again later.'}), 500

#mark subtasks of a task as done as well when that task is set as done
def mark_subtasks_of_task_as_done(cursor, task_id, status):
    #update all direct subtasks of a task
    cursor.execute("UPDATE subtasks SET done = ? WHERE task_id = ?", (status, task_id))
    #fetch all subtasks of that task
    cursor.execute("SELECT id FROM subtasks WHERE task_id = ?", (task_id, ))

    direct_subtasks = cursor.fetchall()
    for subtask in direct_subtasks:
        mark_all_child_subtasks_as_done(cursor, subtask[0], status)

@app.route('/toggle-subtask/<int:subtask_id>')
@login_required
def mark_subtask_done(subtask_id):
    try:
        with sqlite3.connect('daytabase.db') as conn:
            cursor = conn.cursor()
            
            # Get subtask and parent task info
            cursor.execute("""
                SELECT s.done, s.subtask, s.description, t.task
                FROM subtasks s
                JOIN tasks t ON s.task_id = t.id
                WHERE s.id = ? AND t.user_id = ?
            """, (subtask_id, current_user.id))
            
            result = cursor.fetchone()
            if result is None:
                return jsonify({'error': 'Subtask not found'}), 404
                
            current_status = result[0]
            subtask_name = result[1]
            subtask_description = result[2]
            parent_task_name = result[3]
            
            new_status = not current_status
            cursor.execute("UPDATE subtasks SET done = ? WHERE id = ?", 
                         (new_status, subtask_id))

            # Handle journal entry
            today = datetime.now().strftime('%Y-%m-%d')
            if new_status:
                cursor.execute('''
                    INSERT INTO completed (
                        date, task_name, task_description, 
                        is_subtask, parent_task_name, user_id
                    ) VALUES (?, ?, ?, ?, ?, ?)
                ''', (today, subtask_name, subtask_description, 
                      True, parent_task_name, current_user.id))
            else:
                cursor.execute('''
                    DELETE FROM completed 
                    WHERE user_id = ? AND task_name = ? AND is_subtask = ?
                ''', (current_user.id, subtask_name, True))

            mark_all_child_subtasks_as_done(cursor, subtask_id, new_status)
            conn.commit()
            return jsonify({'success': True, 'subtask_id': subtask_id, 
                          'new_status': new_status}), 200

    except sqlite3.Error as e:
        print(f"Database Error: {e}")
        return jsonify({'error': 'A database error occurred.'}), 500

def mark_all_child_subtasks_as_done(cursor, parent_subtask_id, status):
    cursor.execute("""
    WITH RECURSIVE subtree AS (
        SELECT id FROM subtasks WHERE parent_id = ?
        UNION ALL
        SELECT s.id FROM subtasks s JOIN subtree st ON s.parent_id = st.id           
        )
        UPDATE subtasks SET done = ? WHERE id IN (SELECT id FROM subtree)
    """, (parent_subtask_id, status))


#---------------------------------------------------------
#--------------------Home, Journal, & User Dashboard Configs------------------------
#---------------------------------------------------------

#helper functions for Dashboard----------------------------------------

def get_user_categories(user_id):
    query = 'SELECT * FROM categories WHERE user_id = ?'
    try:
        with sqlite3.connect('daytabase.db') as conn:
            cursor = conn.cursor()
            return cursor.execute(query, (user_id, )).fetchall()
    except Exception as e:
        print(f"Error retrieving categories: {e}")
        return []  

def get_user_tasks(user_id):
    query = '''
    SELECT t.*, c.name as category_name FROM tasks t
    LEFT JOIN categories c ON t.category_id = c.id
    WHERE t.user_id = ?
    ORDER BY t.id DESC
    '''
    try:
        with sqlite3.connect('daytabase.db') as conn:
            cursor = conn.cursor()
            return cursor.execute(query, (user_id, )).fetchall()
    except Exception as e:
        print(f"Error retreieving tasks: {e}")
        return []

def get_user_subtasks(user_id):
    query = '''
    SELECT s.* FROM subtasks s JOIN tasks t ON s.task_id = t.id WHERE t.user_id = ?
    ORDER BY s.task_id, s.level, s.id
    '''
    try:
        with sqlite3.connect('daytabase.db') as conn:
            cursor = conn.cursor()
            return cursor.execute(query, (user_id, )).fetchall()
    except Exception as e:
        print(f"Error retreiving subtasks: {e}")
        return []


@app.route('/user-dashboard')
@login_required
def user_dashboard():
    try:
        categories = get_user_categories(current_user.id)
        tasks = get_user_tasks(current_user.id)
        subtasks = get_user_subtasks(current_user.id)
        return render_template('user_dashboard.html', categories=categories, tasks=tasks, subtasks=subtasks)
    except Exception as e:
        print(f"Dashboard error: {e}")
        return f"Error loading dashboard: {str(e)}", 500



#journal func
@app.route('/journal')
@login_required
def journal():
    try:
        with sqlite3.connect('daytabase.db') as conn:
            cursor = conn.cursor()
            cursor.execute('''
            SELECT date, task_name, task_description, is_subtask, parent_task_name 
            FROM completed 
            WHERE user_id = ? 
            ORDER BY date DESC, completed_at DESC
            ''', (current_user.id, ))
            entries = cursor.fetchall()
            achievements = {}
            for entry in entries:
                date = entry[0]
                if date not in achievements:
                    achievements[date] = []
                achievements[date].append({
                'task_name': entry[1],
                'task_description': entry[2],
                'is_subtask': entry[3],
                'parent_task_name': entry[4]
                })
            return render_template('journal.html', achievements=achievements)
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return "Error loading journal", 500



#home func
@app.route('/', methods=['GET', 'POST'])
def home():
    if current_user.is_authenticated:
        return redirect(url_for('user_dashboard'))
    return render_template('index.html')

if __name__ == "__main__":
    app.run(debug=True)