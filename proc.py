#!/usr/bin/python
# -*- coding: utf-8 -*-
import os, psutil, unicodedata, datetime
from flask import Flask, jsonify, abort, make_response, request
from flask.ext.httpauth import HTTPBasicAuth
from subprocess import call, Popen
from OpenSSL import SSL

OPT_SSL = False  # Activar HTTPS
OPT_ACL = False # Activar ACL

if OPT_SSL:
    context = SSL.Context(SSL.SSLv23_METHOD)
    context.use_privatekey_file('server.key') 
    context.use_certificate_file('server.crt')

app = Flask(__name__)

auth = HTTPBasicAuth()

@auth.get_password
def get_password(username):
    if username == 'pablo':
        return 'pablo'
    return None

@auth.error_handler
def unauthorized():
    return make_response(jsonify({'Error': 'Acceso no autorizado'}), 401)

procs = []

def load_procs():
    procs[:] = [] # Vacío la lista de procesos
    for proc in psutil.process_iter():  
        procs.append({
                'pid': proc.pid,
                'name': proc.name,
                'cmd': ' '.join(proc.cmdline), 
                'nice': proc.nice,
                'user': proc.username,
                'status': proc.status,
                'cpu%': proc.get_cpu_percent(interval = 0),
                'mem%': round(proc.get_memory_percent(), 1),
                'start': datetime.datetime.fromtimestamp(proc.create_time).strftime("%Y-%m-%d %H:%M:%S"),
                'tty': proc.terminal
            })
    

### Obtener todos los procesos ###

@app.route('/v1.0/procs', methods=['GET'])
def get_procs():
    load_procs()
    return jsonify({'procs': procs})


### Obtener un proceso por su PID ###

@app.route('/v1.0/procs/<int:pid>', methods=['GET'])
def get_pid(pid):
    load_procs()
    proc = filter(lambda p: p['pid'] == pid, procs)
    if len(proc) == 0:
        abort(404)
    return jsonify({'proc': proc[0]})


### Lanzar un proceso ###

@app.route('/v1.0/procs', methods=['POST'])
@auth.login_required # Requiere autenticación
def start_proc():
    if not request.json or not 'cmd' in request.json:
        abort(400)
    if OPT_ACL: # sudo como el usuario identificado
        cmd = 'sudo -u '+auth.username()+' '+request.json.get('cmd') 
    else: cmd = request.json.get('cmd')
    cmd = cmd.split()
    try:
        pid = Popen(cmd).pid
        if OPT_ACL: # Debe retornar el PID del proceso hijo de sudo
            p = psutil.Process(pid)
            while(p.status != 'sleeping'): # Espero a que sudo forkee y se duerma
                continue
            child = p.get_children()
            if len(child) > 0:
                pid = child[0].pid
    except OSError:
        abort(500)
    return jsonify({'pid': pid}), 201


### Cambiar la prioridad a un proceso basado en su PID ###

@app.route('/v1.0/procs/<int:pid>', methods=['PUT'])
@auth.login_required # Requiere autenticación
def renice_proc(pid):  
    load_procs()
    proc = filter(lambda p: p['pid'] == pid, procs)
    if len(proc) == 0:
        abort(404)
    if not request.json:
        abort(400)
    if 'pid' in request.json and type(request.json['pid']) != unicode:
        abort(400)
    if 'nice' in request.json and type(request.json['nice']) is not unicode:
        abort(400)
    if  int(request.json['nice']) < -20 or int(request.json['nice']) > 19: # Rango de valores nice
        abort(400)
    if OPT_ACL: # Si no es root o el proceso no pertenece al usuario
        if (auth.username() != 'root' and auth.username() != proc[0]['user']):
            abort(403)
    try:
        p = psutil.Process(pid)
        p.set_nice(int(request.json.get('nice')))
        proc[0]['nice'] = p.get_nice()
    except psutil.AccessDenied:
        abort(403) # Permisos insuficientes
    return jsonify({'proc': proc[0]})


### Matar un proceso basado en su PID ###

@app.route('/v1.0/procs/<int:pid>', methods=['DELETE'])
@auth.login_required # Requiere autenticación
def kill_proc(pid):
    load_procs()
    proc = filter(lambda p: p['pid'] == pid, procs)
    if len(proc) == 0:
        abort(404)    
    if pid == os.getpid(): # Comparo con mi PID para no inmolarme
        abort(403)
    if OPT_ACL: # Si no es root o el proceso no pertenece al usuario
        if (auth.username() != 'root' and auth.username() != proc[0]['user']):
            abort(403)
    p = psutil.Process(pid)    
    try:
        p.terminate() # SIGTERM
        p.wait(timeout=0.1)
    except psutil.AccessDenied:
        abort(403) # Permisos insuficientes
    except psutil.TimeoutExpired:
        p.kill() # SIGKILL
    return jsonify({'result': True})


### Manejadores de códigos de retorno HTTP ###

@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'Error': 'Proceso no encontrado'}), 404)

@app.errorhandler(403)
def forbidden(error):
    return make_response(jsonify({'Error': 'Acceso denegado'}), 403)

@app.errorhandler(400)
def bad_request(error):
    return make_response(jsonify({'Error': 'Peticion incorrecta'}), 400)

if __name__ == '__main__':
    if OPT_ACL and not OPT_SSL: exit('Debe activar HTTPS para utilizar ACL')
    if OPT_SSL: app.run(host='0.0.0.0', port=5001, debug=True, ssl_context=context)
    else: app.run(host='0.0.0.0', port=5000, debug=True)
