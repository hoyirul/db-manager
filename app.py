import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, render_template, request, redirect, url_for, flash, session
from middleware import AuthMiddleware
from flask_wtf import CSRFProtect
from flask_cors import CORS

app = Flask(__name__)
# hex key untuk session
app.secret_key = "secret_key"

csrf = CSRFProtect(app)
CORS(app, resources={r"/*": {"origins": "*"}}, methods=["GET", "POST", "PUT", "DELETE"])

# Middleware untuk memeriksa apakah user sudah login atau belum
auth = AuthMiddleware()

# Fungsi untuk membuat koneksi ke database PostgreSQL
def create_connection():
    return psycopg2.connect(
        # with session
        host=session['host'],  # Ganti dengan host DB
        port=session['port'],  # Ganti dengan port DB
        database=session['database'],  # Ganti dengan nama DB
        user=session['username'],  # Ganti dengan username DB
        password=session['password']  # Ganti dengan password DB
    )

@app.route('/login', methods=['GET', 'POST'])
@auth.unauthorized
def login():
    if request.method == 'POST':
        try:
            host = request.form['host']
            port = request.form['port']
            database = request.form['database']
            username = request.form['username']
            password = request.form['password']

            conn = psycopg2.connect(
                host=host,
                port=port,
                database=database,
                user=username,
                password=password
            )

            # jika berhasil terhubung maka simpan ke session jika tidak maka munculkan errornya
            if conn:
                flash("Connected successfully", "success")
                session['logged_in'] = True
                session['host'] = host
                session['port'] = port
                session['database'] = database
                session['username'] = username
                session['password'] = password
                # return to home
                return redirect(url_for('main'))
            else:
                flash("Error connecting to database", "danger")
        except Exception as e:
            flash(str(e), "danger")

    return render_template('pages/auth/login.html')

@app.route('/logout', methods=['POST'])
@auth.authorized
def logout():
    session.clear()
    flash("Logged out successfully", "warning")
    return redirect(url_for('login'))

@app.route('/', methods=['GET'])
@auth.authorized
def main():
    return render_template('pages/home/index.html')

@app.route('/users', methods=['GET', 'POST'])
@auth.authorized
def users():
    # can view and delete users
    if request.method == 'POST':
        username = request.form['username']
        conn = create_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(f"DROP USER {username}")
            conn.commit()
            flash(f"User {username} deleted successfully", "warning")
            return redirect(url_for('users'))
        except Exception as e:
            flash(str(e), "danger")
        finally:
            cursor.close()
            conn.close()

    conn = create_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT usename, usecreatedb, usesuper, passwd FROM pg_user")
    users = cursor.fetchall()
    cursor.close()
    conn.close()

    data = {
        "title": "List Users",
        "users": users
    }

    return render_template('pages/users/index.html', data=data)

@app.route('/users/create', methods=['GET', 'POST'])
@auth.authorized
def create_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_superuser = request.form.get('is_superuser', False)
        is_createdb = request.form.get('is_createdb', False)

        conn = create_connection()
        cursor = conn.cursor()

        try:
            query = f"CREATE USER {username} WITH PASSWORD '{password}'"
            if is_superuser:
                query += " SUPERUSER"
            if is_createdb:
                query += " CREATEDB"
            cursor.execute(query)
            conn.commit()
            flash(f"User {username} created successfully", "success")
            return redirect(url_for('users'))
        except Exception as e:
            flash(str(e), "danger")
        finally:
            cursor.close()
            conn.close()
    
    data = {
        "title": "Create User"
    }

    return render_template('pages/users/create.html', data=data)

@app.route('/users/<username>/edit', methods=['GET', 'POST'])
@auth.authorized
def edit_user(username):
    conn = create_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute(f"SELECT usename, usecreatedb, usesuper, passwd FROM pg_user WHERE usename = '{username}'")
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if request.method == 'POST':
        password = request.form['password']
        is_superuser = request.form.get('is_superuser', False)
        is_createdb = request.form.get('is_createdb', False)

        print(is_superuser, is_createdb)

        conn = create_connection()
        cursor = conn.cursor()

        try:
            query = f"ALTER USER {username} WITH PASSWORD '{password}'"
            if is_superuser:
                query += " SUPERUSER"
            else:
                query += " NOSUPERUSER"
            if is_createdb:
                query += " CREATEDB"
            else:
                query += " NOCREATEDB"
            cursor.execute(query)
            conn.commit()
            flash(f"User {username} updated successfully", "success")
            return redirect(url_for('users'))
        except Exception as e:
            flash(str(e), "danger")
        finally:
            cursor.close()
            conn.close()

    data = {
        "title": "Edit User",
        "user": user
    }

    return render_template('pages/users/edit.html', data=data)


@app.route('/roles', methods=['GET', 'POST'])
def roles():
    conn = create_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    # rolname != like 'pg_%' untuk menghindari role bawaan dari PostgreSQL
    cursor.execute("SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin FROM pg_roles where rolname not like 'pg_%'")
    roles = cursor.fetchall()
    cursor.close()
    conn.close()

    data = {
        "title": "List Roles",
        "roles": roles
    }

    return render_template('pages/roles/index.html', data=data)

@app.route('/databases', methods=['GET', 'POST'])
def databases():
    if request.method == 'POST':
        db_name = request.form['db_name']
        conn = create_connection()
        cursor = conn.cursor()

        conn.autocommit = True

        try:
            cursor.execute(f"DROP DATABASE {db_name}")
            conn.commit()
            flash(f"Database {db_name} deleted successfully", "warning")
            return redirect(url_for('databases'))
        except Exception as e:
            flash(str(e), "danger")
        finally:
            cursor.close()
            conn.close()

    conn = create_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT datname FROM pg_database WHERE datname NOT IN ('template0', 'template1')")
    databases = cursor.fetchall()
    cursor.close()
    conn.close()

    data = {
        "title": "List Databases",
        "databases": databases
    }

    return render_template('pages/databases/index.html', data=data)

@app.route('/databases/create', methods=['GET', 'POST'])
def create_database():
    if request.method == 'POST':
        print(request.form)
        db_name = request.form['db_name']
        owner = request.form['owner']
        conn = create_connection()
        cursor = conn.cursor()

        # Setel autocommit ke True untuk perintah CREATE DATABASE
        conn.autocommit = True  # <-- Perubahan ini

        try:
            # Jalankan perintah CREATE DATABASE
            cursor.execute(f"CREATE DATABASE {db_name} WITH OWNER {owner}")
            flash(f"Database {db_name} created successfully", "success")
        except Exception as e:
            flash(f"Error creating database: {str(e)}", "danger")
        finally:
            cursor.close()
            conn.close()

        return redirect(url_for('databases'))

    conn = create_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT usename FROM pg_user")
    users = cursor.fetchall()
    cursor.close()
    conn.close()

    data = {
        "title": "Create Database",
        "users": users
    }

    return render_template('pages/databases/create.html', data=data)

# Menampilkan table yang ada di database
@app.route('/databases/<db_name>/tables', methods=['GET'])
def tables(db_name):
    conn = psycopg2.connect(
        host="localhost",
        database=db_name,
        user="mochammadhairullah",
        password="password"
    )
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public'")
    tables = cursor.fetchall()
    cursor.close()
    conn.close()

    data = {
        "title": f"List Tables of {db_name}",
        "tables": tables,
        "db_name": db_name,
    }

    return render_template('pages/databases/tables.html', data=data)

# Menampilkan kolom yang ada di table
@app.route('/databases/<db_name>/tables/<table_name>/columns', methods=['GET'])
def columns(db_name, table_name):
    conn = psycopg2.connect(
        host="localhost",
        database=db_name,
        user="mochammadhairullah",
        password="password"
    )
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute(f"SELECT column_name, data_type FROM information_schema.columns WHERE table_name = '{table_name}'")
    columns = cursor.fetchall()
    cursor.close()
    conn.close()

    print(columns)

    data = {
        "title": f"List Columns of {table_name}",
        "columns": columns,
        "db_name": db_name,
        "table_name": table_name
    }

    return render_template('pages/databases/columns.html', data=data)

# Memberikan grant permission ke role
@app.route('/roles/<role_name>/grant', methods=['GET'])
def grant_role(role_name):
    conn = create_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT datname FROM pg_database WHERE datname NOT IN ('template0', 'template1')")
    databases = cursor.fetchall()
    cursor.close()
    conn.close()

    print(databases)

    data = {
        "title": f"Grant Role {role_name}",
        "databases": databases,
        "role_name": role_name
    }

    return render_template('pages/grants/roles/grant.html', data=data)

# Memberikan Grant dan Revoke permission ke role
@app.route('/roles/<role_name>/<db_name>/<type>', methods=['GET'])
def grant_revoke_role(role_name, db_name, type):
    conn = create_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    try:
        if type == "grant":
            cursor.execute("GRANT ALL PRIVILEGES ON DATABASE %s TO %s", (db_name, role_name))
        else:
            cursor.execute("REVOKE ALL PRIVILEGES ON DATABASE %s FROM %s", (db_name, role_name))

        conn.commit()
        flash(f"Role {role_name} {type}ed to {db_name} successfully", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect('/roles/' + role_name + '/grant')


# Memberikan grant permission ke user
@app.route('/users/<username>/grant', methods=['GET', 'POST'])
def grant_user(username):
    if request.method == 'POST':
        db_name = request.form['db_name']
        conn = create_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(f"GRANT {username} TO {db_name}")
            conn.commit()
            flash(f"User {username} granted to {db_name} successfully", "success")
            return redirect(url_for('users'))
        except Exception as e:
            flash(str(e), "danger")
        finally:
            cursor.close()
            conn.close()

    conn = create_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT datname FROM pg_database WHERE datname NOT IN ('template0', 'template1')")
    databases = cursor.fetchall()
    cursor.close()
    conn.close()

    data = {
        "title": f"Grant User {username}",
        "databases": databases
    }

    return render_template('pages/users/grant.html', data=data)

# Memberikan grant permission ke role SELECT, UPDATE, DELETE, INSERT
@app.route('/roles/<role_name>/grant/permission', methods=['GET', 'POST'])
def grant_role_permission(role_name):
    if request.method == 'POST':
        db_name = request.form['db_name']
        table_name = request.form['table_name']
        permission = request.form['permission']
        conn = create_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(f"GRANT {permission} ON {table_name} TO {role_name}")
            conn.commit()
            flash(f"Permission {permission} granted to {role_name} on {table_name} successfully", "success")
            return redirect(url_for('roles'))
        except Exception as e:
            flash(str(e), "danger")
        finally:
            cursor.close()
            conn.close()

    conn = create_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT datname FROM pg_database WHERE datname NOT IN ('template0', 'template1')")
    databases = cursor.fetchall()
    cursor.close()
    conn.close()

    data = {
        "title": f"Grant Permission to Role {role_name}",
        "databases": databases
    }

    return render_template('pages/roles/permission.html', data=data)

# Memberikan grant permission ke user SELECT, UPDATE, DELETE, INSERT
@app.route('/users/<username>/grant/permission', methods=['GET', 'POST'])
def grant_user_permission(username):
    if request.method == 'POST':
        db_name = request.form['db_name']
        table_name = request.form['table_name']
        permission = request.form['permission']
        conn = create_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(f"GRANT {permission} ON {table_name} TO {username}")
            conn.commit()
            flash(f"Permission {permission} granted to {username} on {table_name} successfully", "success")
            return redirect(url_for('users'))
        except Exception as e:
            flash(str(e), "danger")
        finally:
            cursor.close()
            conn.close()

    conn = create_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT datname FROM pg_database WHERE datname NOT IN ('template0', 'template1')")
    databases = cursor.fetchall()
    cursor.close()
    conn.close()

    data = {
        "title": f"Grant Permission to User {username}",
        "databases": databases
    }

    return render_template('pages/users/permission.html', data=data)

# Agar role tertentu bisa melihat beberapa table saja sesuai dengan permission yang diberikan
@app.route('/roles/<role_name>/grant/table', methods=['GET', 'POST'])
def grant_role_table(role_name):
    if request.method == 'POST':
        db_name = request.form['db_name']
        table_name = request.form['table_name']
        conn = create_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(f"GRANT USAGE ON SCHEMA public TO {role_name}")
            cursor.execute(f"GRANT SELECT ON {table_name} TO {role_name}")
            conn.commit()
            flash(f"Role {role_name} granted to {table_name} successfully", "success")
            return redirect(url_for('roles'))
        except Exception as e:
            flash(str(e), "danger")
        finally:
            cursor.close()
            conn.close()

    conn = create_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT datname FROM pg_database WHERE datname NOT IN ('template0', 'template1')")
    databases = cursor.fetchall()
    cursor.close()
    conn.close()

    data = {
        "title": f"Grant Role {role_name} to Table",
        "databases": databases
    }

    return render_template('pages/roles/table.html', data=data)

if __name__ == '__main__':
    app.run(debug=True)
