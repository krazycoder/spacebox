"""Spacebox"""

import json
import os
import posixpath
import Queue
import sys

from sqlite3 import dbapi2 as sqlite3
from flask import Flask, request, session, g, redirect, url_for, abort, \
     render_template, flash, _app_ctx_stack

from dropbox.client import DropboxClient, DropboxOAuth2Flow

DEBUG = True
DATABASE = 'app.db'
SECRET_KEY = 'development key'

# Fill this in!
DROPBOX_APP_KEY = 'nd17zk0ho91g30n'
DROPBOX_APP_SECRET = 'g28lix8n4w26so4'

app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_envvar('FLASKR_SETTINGS', silent=True)

# Ensure db directory exists.
try:
    os.makedirs(app.instance_path)
except OSError:
    pass

def human_readable(bytes):
  if bytes < 1024:
    return '%.0f Bytes' % bytes
  elif bytes < 1048576:
    return '%.2f KB' % (bytes / 1024)
  elif bytes < 1073741824:
    return '%.2f MB' % (bytes / 1048576)
  else:
    return '%.2f GB' % (bytes / 1073741824)

def quota_info(client):
  acc_info = client.account_info()
  normal = acc_info['quota_info']['normal']
  shared = acc_info['quota_info']['shared']
  used = int(normal + shared)
  quota = acc_info['quota_info']['quota']
  return used, quota

def get_size(dir_entry):
  bytes = 0
  if dir_entry['children']: 
    for child in dir_entry['children']:
      bytes += get_size(child)
  else:
    bytes = dir_entry['bytes']
  return bytes
  
def get_metadata(client, path):
  metadata = client.metadata(path)
  dir_path = metadata['path']
  result = {'name': str(os.path.basename(dir_path)),
            'path': dir_path,
            'bytes': 0,
            'children': []}
  if 'contents' in metadata:
    for dir_entry in metadata['contents']:
      path = dir_entry['path']
      dir_entry_bytes = dir_entry['bytes']
      modified = dir_entry['modified']
      if dir_entry_bytes is 0:
        child = get_metadata(client, path)
      else:
        child = {'name': str(os.path.basename(path)),
                 'path': path,
                 'bytes': dir_entry_bytes,
                 'type': str(dir_entry['mime_type'].split('/')[0]),
                 'children': []}
      result['children'].append(child)
    result['bytes'] = get_size(result)
  return result

def get_data_by_contents(metadata, used_bytes):
  json_dict = {}
  json_dict['root'] = []
  for child in metadata['children']:
    child_dict = {}
    child_dict['name'] = child['name']
    child_dict['y'] = float((child['bytes'] * 100) / used_bytes)
    if child['children']:
      child_dict['drilldown'] = child['name']
    json_dict['root'].append(child_dict)

  q = Queue.Queue()
  q.put(metadata)
  json_dict['drilldowns'] = []
  while not q.empty():
    drilldown_dict = {}
    elem = q.get()
    drilldown_dict['id'] = elem['name']
    drilldown_dict['name'] = elem['path']
    drilldown_dict['data'] = []
    for child in elem['children']:
      child_dict = {}
      child_dict['name'] = child['name']
      child_dict['y'] = float((child['bytes'] * 100) / used_bytes)
      if child['children']:
        child_dict['drilldown'] = child['name']
      drilldown_dict['data'].append(child_dict)
      q.put(child)
    json_dict['drilldowns'].append(drilldown_dict)
  return json.JSONEncoder().encode(json_dict)

def get_data_by_types(metadata, used_bytes):
  type_dict = {}
  q = Queue.Queue()
  q.put(metadata)
  while not q.empty():
    elem = q.get()
    try:
      type = elem['type']
      if type in type_dict:
        type_dict[type] += elem['bytes']
      else:
        type_dict[type] = elem['bytes']
    except KeyError:
      continue
    finally:
      for child in elem['children']:
        q.put(child)
    
  type_list = []
  for type, size in type_dict.items():
    type_list.append([type, float((size * 100) / used_bytes)])
  return json.JSONEncoder().encode(type_list)

def init_db():
  with app.app_context():
    db = get_db()
    with app.open_resource("schema.sql", mode="r") as f:
      db.cursor().executescript(f.read())
    db.commit()

def get_db():
  top = _app_ctx_stack.top
  if not hasattr(top, 'sqlite_db'):
    sqlite_db = sqlite3.connect(os.path.join(app.instance_path, app.config['DATABASE']))
    sqlite_db.row_factory = sqlite3.Row
    top.sqlite_db = sqlite_db
  return top.sqlite_db

def get_access_token():
  username = session.get('user')
  if username is None:
      return None
  db = get_db()
  row = db.execute('SELECT access_token FROM users WHERE username = ?', [username]).fetchone()
  if row is None:
    return None
  return row[0]

@app.route('/')
def home():
  if 'user' not in session:
    return redirect(url_for('login'))
  access_token = get_access_token()
  real_name = None
  if access_token is not None:
    client = DropboxClient(access_token)
    account_info = client.account_info()
    real_name = account_info["display_name"]
  return render_template('index.html', real_name=real_name)

@app.route('/dropbox-auth-finish')
def dropbox_auth_finish():
  username = session.get('user')
  if username is None:
    abort(403)
  try:
    access_token, user_id, url_state = get_auth_flow().finish(request.args)
  except DropboxOAuth2Flow.BadRequestException, e:
    abort(400)
  except DropboxOAuth2Flow.BadStateException, e:
    abort(400)
  except DropboxOAuth2Flow.CsrfException, e:
    abort(403)
  except DropboxOAuth2Flow.NotApprovedException, e:
    flash('Not approved?  Why not')
    return redirect(url_for('home'))
  except DropboxOAuth2Flow.ProviderException, e:
    app.logger.exception("Auth error" + e)
    abort(403)
  db = get_db()
  data = [access_token, username]
  db.execute('UPDATE users SET access_token = ? WHERE username = ?', data)
  db.commit()
  return redirect(url_for('home'))

@app.route('/dropbox-auth-start')
def dropbox_auth_start():
  if 'user' not in session:
    abort(403)
  return redirect(get_auth_flow().start())

@app.route('/dropbox-logout')
def dropbox_logout():
  username = session.get('user')
  if username is None:
    abort(403)
  db = get_db()
  db.execute('UPDATE users SET access_token = NULL WHERE username = ?', [username])
  db.commit()
  return redirect(url_for('home'))

def get_auth_flow():
  redirect_uri = url_for('dropbox_auth_finish', _external=True)
  return DropboxOAuth2Flow(DROPBOX_APP_KEY, DROPBOX_APP_SECRET, redirect_uri,
                           session, 'dropbox-auth-csrf-token')

@app.route('/login', methods=['GET', 'POST'])
def login():
  error = None
  if request.method == 'POST':
    username = request.form['username']
    if username:
      db = get_db()
      db.execute('INSERT OR IGNORE INTO users (username) VALUES (?)', [username])
      db.commit()
      session['user'] = username
      flash('You were logged in')
      return redirect(url_for('home'))
    else:
      flash("You must provide a username")
  return render_template('login.html', error=error)

@app.route('/logout')
def logout():
  session.pop('user', None)
  flash('You were logged out')
  return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
  if 'user' not in session:
    return redirect(url_for('login'))
  access_token = get_access_token()
  client = DropboxClient(access_token)
  used_bytes, quota_bytes = quota_info(client)
  return render_template('dashboard.html',
                         used=human_readable(used_bytes),
                         quota=human_readable(quota_bytes),
                         utilization=float((used_bytes * 100) / quota_bytes))

@app.route('/contents')
def contents():
  if 'user' not in session:
    return redirect(url_for('login'))
  access_token = get_access_token()
  client = DropboxClient(access_token)
  used_bytes, _ = quota_info(client)
  metadata = get_metadata(client, '')
  return get_data_by_contents(metadata, used_bytes)

@app.route('/types')
def types():
  if 'user' not in session:
    return redirect(url_for('login'))
  access_token = get_access_token()
  client = DropboxClient(access_token)
  used_bytes, _ = quota_info(client)
  metadata = get_metadata(client, '')
  return get_data_by_types(metadata, used_bytes)

def main():
  init_db()
  app.run()

if __name__ == '__main__':
  main()
