import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, render_template, request, redirect, url_for, flash, session
from middlewares.middleware import AuthMiddleware
from flask_wtf import CSRFProtect
from flask_cors import CORS
from utils.errors import ErrorHelper
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
# hex key untuk session
app.secret_key = os.getenv("SECRET_KEY")

csrf = CSRFProtect(app)
CORS(app, resources={r"/*": {"origins": "*"}}, methods=["GET", "POST", "PUT", "DELETE"])

# Middleware untuk memeriksa apakah user sudah login atau belum
auth = AuthMiddleware()

# Session Globaly
@app.context_processor
def inject_session():
    return dict(session=session)

# Registrasi handler error
errorHelper = ErrorHelper()
@app.errorhandler(404)
def not_found_error(error):
    return errorHelper.not_found_error(error=error)

@app.errorhandler(500)
def internal_error(error):
    return errorHelper.internal_error(error=error)

@app.errorhandler(405)
def method_not_allowed(error):
    return errorHelper.method_not_allowed(error=error)

@app.errorhandler(400)
def bad_request(error):
    return errorHelper.bad_request(error=error)

# Fungsi untuk membuat koneksi ke database PostgreSQL
def create_connection(database_name=None):
    return psycopg2.connect(
        # with session
        host=session['host'],  # Ganti dengan host DB
        port=session['port'],  # Ganti dengan port DB
        database=session['database'] if database_name == None else database_name,
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

            # check apakah jika superuser atau tidak jika tidak maka muncul flash kalau iya bisa masuk
            cursor = conn.cursor()
            cursor.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
            is_superuser = cursor.fetchone()[0]
            cursor.close()

            if not is_superuser:
                flash("You are not a superuser", "danger")
                return render_template('pages/auth/login.html')

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
    try:
        conn = create_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT current_database()")
        current_database = cursor.fetchone()['current_database']
        # count user, roles, databases
        cursor.execute("SELECT COUNT(*) FROM pg_user")
        user_count = cursor.fetchone()['count']
        cursor.execute("SELECT COUNT(*) FROM pg_roles")
        role_count = cursor.fetchone()['count']
        cursor.execute("SELECT COUNT(*) FROM pg_database WHERE datname NOT IN ('template0', 'template1')")
        database_count = cursor.fetchone()['count']
        cursor.close()
        conn.close()

        data = {
            "title": "Home",
            "current_database": current_database,
            "user_count": user_count,
            "role_count": role_count,
            "database_count": database_count
        }

        return render_template('pages/home/index.html', data=data)
    except Exception as e:
        flash(str(e), "danger")
        return redirect('/')

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
@auth.authorized
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
@auth.authorized
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
@auth.authorized
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
@auth.authorized
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
@auth.authorized
def columns(db_name, table_name):
    conn = psycopg2.connect(
        host=session['host'],
        port=session['port'],
        database=db_name,
        user=session['username'],
        password=session['password']
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


@app.route('/databases/<db_name>/grant', methods=['GET', 'POST'])
@auth.authorized
def database_permission_grant(db_name):
    conn = create_connection(database_name=db_name)
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    if request.method == 'POST':
        # Ambil data dari form
        role = request.form['role']  # Role yang dipilih
        privileges = request.form.getlist('privileges')  # Privileges yang dipilih
        selected_tables = request.form.getlist('tables')  # Tabel yang dipilih
        grant_option = 'WITH GRANT OPTION' if 'grant_option' in request.form else ''

        print(role, privileges, selected_tables, grant_option)
        
        # Jika memilih ALL PRIVILEGES, kita set semua privileges
        if 'ALL' in privileges:
            privileges = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']
        
        # Untuk setiap tabel yang dipilih, buat query GRANT
        grant_query = f"GRANT {', '.join(privileges)} ON TABLE {', '.join(selected_tables)} TO {role} {grant_option};"
        try:
            # Koneksi ke PostgreSQL
            cur = conn.cursor()
            cur.execute(grant_query)
            conn.commit()
            cur.close()
            conn.close()

            flash(f"GRANT query executed: {grant_query}", 'success')
        except Exception as e:
            flash(f"Error executing query: {e}", 'danger')

        return redirect(f'/databases/{db_name}/grant?role={role}')

    # Jika request adalah GET, tampilkan form untuk grant permissions
    try:
        cursor.execute("SELECT rolname FROM pg_roles WHERE rolname not like 'pg_%' and rolsuper = false;")
        roles = cursor.fetchall()

        role = request.args.get('role')  # Ambil role dari parameter URL
        if role:
            # Ambil privileges dan tabel yang dimiliki oleh role
            cursor.execute("""
                SELECT 
                    grantee, 
                    table_name,
                    privilege_type
                FROM 
                    information_schema.role_table_grants
                WHERE 
                    grantee = %s AND table_schema = 'public';
            """, (role,))
            
            privileges_data = cursor.fetchall()

            # Ambil daftar tabel yang ada di schema public
            cursor.execute("""
                SELECT table_name 
                FROM information_schema.tables
                WHERE table_schema = 'public';
            """)
            tables_data = cursor.fetchall()

            # Set privilege yang dimiliki role
            privileges = [priv['privilege_type'] for priv in privileges_data]
            # Set tabel yang dapat diakses oleh role
            accessible_tables = [priv['table_name'] for priv in privileges_data]

            conn.close()

            # Pass data ke template
            data = {
                "title": f"Grant Permissions to {db_name}",
                "db_name": db_name,
                "roles": roles,
                "privileges": privileges,
                "tables": tables_data,
                "accessible_tables": accessible_tables  # Menambahkan daftar tabel yang dapat diakses
            }
            return render_template('pages/databases/grant.html', data=data)

        # Ambil semua tabel jika belum ada role yang dipilih
        cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';")
        tables = cursor.fetchall()

        conn.close()
        return render_template('pages/databases/grant.html', data={
            "title": f"Grant Permissions to {db_name}",
            "db_name": db_name,
            "roles": roles,
            "tables": tables
        })

    except Exception as e:
        flash(f"Error fetching data: {e}", 'danger')
        return redirect(url_for('databases'))

@app.route('/databases/<db_name>/revoke', methods=['GET', 'POST'])
@auth.authorized
def database_permission_revoke(db_name):
    conn = create_connection(database_name=db_name)
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    if request.method == 'POST':
        # Ambil data dari form
        role = request.form['role']  # Role yang dipilih
        privileges = request.form.getlist('privileges')  # Privileges yang dipilih
        selected_tables = request.form.getlist('tables')  # Tabel yang dipilih
        
        # Jika memilih ALL PRIVILEGES, kita set semua privileges
        if 'ALL' in privileges:
            privileges = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']
        
        # Untuk setiap tabel yang dipilih, buat query REVOKE
        revoke_query = f"REVOKE {', '.join(privileges)} ON TABLE {', '.join(selected_tables)} FROM {role};"
        try:
            # Koneksi ke PostgreSQL
            cur = conn.cursor()
            cur.execute(revoke_query)
            conn.commit()
            cur.close()
            conn.close()

            flash(f"REVOKE query executed: {revoke_query}", 'success')
        except Exception as e:
            flash(f"Error executing query: {e}", 'danger')

        return redirect(f'/databases/{db_name}/revoke?role={role}')

    # Jika request adalah GET, tampilkan form untuk revoke permissions
    try:
        cursor.execute("SELECT rolname FROM pg_roles WHERE rolname not like 'pg_%' and rolsuper = false;")
        roles = cursor.fetchall()

        role = request.args.get('role')  # Ambil role dari parameter URL
        if role:
            # Ambil privileges dan tabel yang dimiliki oleh role
            cursor.execute("""
                SELECT 
                    grantee, 
                    table_name,
                    privilege_type
                FROM 
                    information_schema.role_table_grants
                WHERE 
                    grantee = %s AND table_schema = 'public';
            """, (role,))
            
            privileges_data = cursor.fetchall()

            # Ambil daftar tabel yang ada di schema public
            cursor.execute("""
                SELECT table_name 
                FROM information_schema.tables
                WHERE table_schema = 'public';
            """)
            tables_data = cursor.fetchall()

            # Set privilege yang dimiliki role
            privileges = [priv['privilege_type'] for priv in privileges_data]
            # Set tabel yang dapat diakses oleh role
            accessible_tables = [priv['table_name'] for priv in privileges_data]

            conn.close()

            # Pass data ke template
            data = {
                "title": f"Revoke Permissions to {db_name}",
                "db_name": db_name,
                "roles": roles,
                "privileges": privileges,
                "tables": tables_data,
                "accessible_tables": accessible_tables  # Menambahkan daftar tabel yang dapat diakses
            }
            return render_template('pages/databases/revoke.html', data=data)

        # Ambil semua tabel jika belum ada role yang dipilih
        cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';")
        tables = cursor.fetchall()

        conn.close()
        return render_template('pages/databases/revoke.html', data={
            "title": f"Revoke Permissions to {db_name}",
            "db_name": db_name,
            "roles": roles,
            "tables": tables
        })

    except Exception as e:
        flash(f"Error fetching data: {e}", 'danger')
        return redirect(url_for('databases'))

@app.route('/roles/<role_name>/grant', methods=['GET', 'POST'])
@auth.authorized
def role_permission_grant(role_name):
    try:
        conn = create_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        # Ambil daftar privileges yang umum
        privileges = ['ALL', 'CREATE', 'CONNECT', 'TEMPORARY']

        # Ambil database yang dapat diakses
        cursor.execute("""
            SELECT datname
            FROM pg_database
            WHERE datistemplate = false and datname != 'postgres';
        """)
        databases = cursor.fetchall()

        # Ambil hak akses untuk role terhadap database (untuk semua database)
        cursor.execute("""
            SELECT 
                r.rolname AS role,
                d.datname AS database,
                pg_catalog.has_database_privilege(r.rolname, d.datname, 'CONNECT') AS can_connect,
                pg_catalog.has_database_privilege(r.rolname, d.datname, 'CREATE') AS can_create,
                pg_catalog.has_database_privilege(r.rolname, d.datname, 'TEMPORARY') AS can_use_temp_tables
            FROM 
                pg_catalog.pg_roles r
            JOIN 
                pg_catalog.pg_database d ON pg_catalog.has_database_privilege(r.rolname, d.datname, 'CONNECT')
            WHERE 
                r.rolname = %s
            ORDER BY 
                role, database;
        """, (role_name,))
        role_privileges = cursor.fetchall()

        # Untuk halaman POST, ambil data dari form
        if request.method == 'POST':
            role = role_name
            privileges_selected = request.form.getlist('privileges')  # Privileges yang dipilih
            database_name = request.form.get('database_name')  # Nama database yang dipilih
            grant_option = 'WITH GRANT OPTION' if 'grant_option' in request.form else ''

            # Buat query GRANT untuk role
            if 'ALL' in privileges_selected:
                privileges_selected = ['CREATE', 'CONNECT', 'TEMPORARY']

            grant_query = f"GRANT {', '.join(privileges_selected)} ON DATABASE {database_name} TO {role} {grant_option};"

            # Eksekusi query GRANT
            cursor.execute(grant_query)
            conn.commit()

            flash(f"GRANT query executed: {grant_query}", 'success')
            return redirect(url_for('role_permission', role_name=role_name))  # Redirect setelah submit

        # Tutup koneksi
        conn.close()

        # Data yang akan dikirimkan ke template
        data = {
            'title': f"Grant Permissions for {role_name}",
            'role_name': role_name,
            'privileges': privileges,
            'databases': databases,
            'role_privileges': role_privileges  # Data hak akses role terhadap database
        }

        return render_template('pages/roles/grant.html', data=data)

    except Exception as e:
        flash(f"Error: {e}", 'danger')
        return redirect(url_for('roles'))  # Ganti 'home' dengan rute yang sesuai jika terjadi error

@app.route('/roles/<role_name>/revoke', methods=['GET', 'POST'])
@auth.authorized
def role_permission_revoke(role_name):
    try:
        conn = create_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        # Ambil daftar privileges yang umum
        privileges = ['ALL', 'CREATE', 'CONNECT', 'TEMPORARY']

        # Ambil database yang dapat diakses
        cursor.execute("""
            SELECT datname
            FROM pg_database
            WHERE datistemplate = false and datname != 'postgres';
        """)
        databases = cursor.fetchall()

        # Ambil hak akses untuk role terhadap database (untuk semua database)
        cursor.execute("""
            SELECT 
                r.rolname AS role,
                d.datname AS database,
                pg_catalog.has_database_privilege(r.rolname, d.datname, 'CONNECT') AS can_connect,
                pg_catalog.has_database_privilege(r.rolname, d.datname, 'CREATE') AS can_create,
                pg_catalog.has_database_privilege(r.rolname, d.datname, 'TEMPORARY') AS can_use_temp_tables
            FROM 
                pg_catalog.pg_roles r
            JOIN 
                pg_catalog.pg_database d ON pg_catalog.has_database_privilege(r.rolname, d.datname, 'CONNECT')
            WHERE 
                r.rolname = %s
            ORDER BY 
                role, database;
        """, (role_name,))
        role_privileges = cursor.fetchall()

        # Untuk halaman POST, ambil data dari form
        if request.method == 'POST':
            role = request.form.get('role')  # Role yang dipilih
            privileges_selected = request.form.getlist('privileges')  # Privileges yang dipilih
            database_name = request.form.get('database_name')  # Nama database yang dipilih

            # Buat query REVOKE untuk role
            if 'ALL' in privileges_selected:
                privileges_selected = ['CREATE', 'CONNECT', 'TEMPORARY']

            revoke_query = f"REVOKE {', '.join(privileges_selected)} ON DATABASE {database_name} FROM {role};"

            # Eksekusi query REVOKE
            cursor.execute(revoke_query)
            conn.commit()

            flash(f"REVOKE query executed: {revoke_query}", 'success')
            return redirect(url_for('role_permission', role_name=role_name))  # Redirect setelah submit

        # Tutup koneksi
        conn.close()

        # Data yang akan dikirimkan ke template
        data = {
            'title': f"Revoke Permissions for {role_name}",
            'role_name': role_name,
            'privileges': privileges,
            'databases': databases,
            'role_privileges': role_privileges  # Data hak akses role terhadap database
        }

        return render_template('pages/roles/revoke.html', data=data)

    except Exception as e:
        flash(f"Error: {e}", 'danger')
        return redirect(url_for('roles'))  # Ganti 'home' dengan rute yang sesuai jika terjadi error

if __name__ == '__main__':
    # Mendapatkan nilai dari variabel lingkungan
    app_name = os.getenv("APP_NAME")
    debug_mode = os.getenv("APP_ENV")
    host_ip = os.getenv("APP_HOST")
    app_port = os.getenv("APP_PORT")  # Menambah variabel untuk port

    # Menentukan host dan port berdasarkan mode (development/production)
    if debug_mode == 'development':
        host = host_ip
        port = 5000 if app_port is None else int(app_port)
    else:
        host = host_ip
        port = 80 if app_port is None else int(app_port)

    app.run(debug = True if debug_mode == 'development' else False, host=host, port=port)
