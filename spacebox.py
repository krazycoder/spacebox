"""Spacebox"""

import json
import os
import posixpath
import Queue
import sys

from flask import Flask, request, session, g, redirect, url_for, abort, \
     render_template, flash, _app_ctx_stack

from dropbox.client import DropboxClient, DropboxOAuth2Flow

DEBUG = True
SECRET_KEY = 'development key'

# Fill this in!
DROPBOX_APP_KEY = 'nd17zk0ho91g30n'
DROPBOX_APP_SECRET = 'g28lix8n4w26so4'

app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_envvar('FLASKR_SETTINGS', silent=True)

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
  # Read the client metadata information and construct a dictionary
  # of type - 'name', 'path', 'bytes' and 'children'. Each object in
  # the children list is internally an object of the same type. For
  # files or leaf nodes w/o any children, we also capture their type.
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
  # Construct the JSON data in the format that HighCharts needs.
  # The chart's data series is set to the root directory files.
  # Thereafter, all sub-directories and files are mentioned in the
  # drilldown section which are rendered as clickable options in
  # the main chart.
  json_dict['root'] = []
  for child in metadata['children']:
    child_dict = {}
    child_dict['name'] = child['name']
    child_dict['y'] = float((child['bytes'] * 100) / used_bytes)
    if child['children']:
      child_dict['drilldown'] = child['name']
    json_dict['root'].append(child_dict)
  # Add drilldown information by traversing through all the nodes
  # in the directory structure.
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
  # Aggregate the usage information based on the file types.
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

@app.route('/')
def home():
  real_name = None
  if 'access_token' in session and session['access_token'] is not None:
    access_token = session['access_token']
    client = DropboxClient(access_token)
    account_info = client.account_info()
    real_name = account_info['display_name']
  return render_template('index.html', real_name=real_name)

@app.route('/dropbox-auth-finish')
def dropbox_auth_finish():
  try:
    error = request.args.get('error')
    if error is not None:
      raise DropboxOAuth2Flow.NotApprovedException()
    code = request.args.get('code')
    state = request.args.get('state')
    access_token, user_id, url_state = get_auth_flow().finish(
        {'code':code, 'state':state})
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
    app.logger.exception('Auth error' + e)
    abort(403)
  session['access_token'] = access_token
  return redirect(url_for('home'))

@app.route('/dropbox-auth-start')
def dropbox_auth_start():
  return redirect(get_auth_flow().start())

@app.route('/dropbox-logout')
def dropbox_logout():
  session['access_token'] = None
  return redirect(url_for('home'))

def get_auth_flow():
  redirect_uri = url_for('dropbox_auth_finish', _external=True)
  return DropboxOAuth2Flow(DROPBOX_APP_KEY, DROPBOX_APP_SECRET, redirect_uri,
                           session, 'dropbox-auth-csrf-token')

@app.route('/dashboard')
def dashboard():
  if 'access_token' not in session or session['access_token'] is None:
    return redirect(url_for('home'))
  access_token = session['access_token']
  client = DropboxClient(access_token)
  used_bytes, quota_bytes = quota_info(client)
  session['used_bytes'] = used_bytes
  session['metadata'] = get_metadata(client, '')
  return render_template('dashboard.html',
                         used=human_readable(used_bytes),
                         quota=human_readable(quota_bytes),
                         utilization=float((used_bytes * 100) / quota_bytes))

@app.route('/contents')
def contents():
  if 'access_token' not in session or session['access_token'] is None:
    return redirect(url_for('home'))
  return get_data_by_contents(session['metadata'], session['used_bytes'])

@app.route('/types')
def types():
  if 'access_token' not in session or session['access_token'] is None:
    return redirect(url_for('home'))
  return get_data_by_types(session['metadata'], session['used_bytes'])

def main():
  app.run()

if __name__ == '__main__':
  main()
