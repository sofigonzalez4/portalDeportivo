from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from dotenv import load_dotenv
import os
import bcrypt

app = Flask(__name__)
load_dotenv()

app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')

mysql = MySQL(app)
app.secret_key = os.getenv('SECRET_KEY') 

@app.route('/')
def main():
    return redirect(url_for('login'))

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        nombre = request.form['nombre']
        apellido = request.form['apellido']
        correo = request.form['correo']
        clave = request.form['clave']
        
        hashed_pass = bcrypt.hashpw(clave.encode('utf-8'), bcrypt.gensalt())

        try:
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO users (nombre, apellido, correo, contraseña) VALUES (%s, %s, %s, %s)",
                        (nombre, apellido, correo, hashed_pass.decode('utf-8')))
            mysql.connection.commit()
            cur.close()
            flash('Registro exitoso. Puedes iniciar sesión ahora.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Error al guardar los datos: {e}', 'danger')
            return redirect(url_for('registro'))

    return render_template('registro.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        correo = request.form['correo']
        clave = request.form['clave']
        
        cur = mysql.connection.cursor()
        cur.execute("SELECT contraseña FROM users WHERE correo = %s", (correo,))
        result = cur.fetchone()
        cur.close()

        if result and bcrypt.checkpw(clave.encode('utf-8'), result[0].encode('utf-8')):
            session['correo'] = correo
            flash('Inicio de sesión exitoso.', 'success')
            return redirect(url_for('display'))
        else:
            flash('Correo o contraseña incorrectos.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('correo', None)
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(port=5000, debug=True)
