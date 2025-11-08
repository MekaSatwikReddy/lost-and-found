import os
import bcrypt
import jwt
import uuid
import datetime
from functools import wraps
from flask import Flask, request, jsonify, g
from flask_cors import CORS

# --- Setup ---
app = Flask(__name__)
# Enable CORS for all routes, allowing your frontend to connect
CORS(app)
# This is your JWT secret key
app.config['SECRET_KEY'] = 'your-super-secret-key-that-should-be-in-a-env-file'
PORT = 3001 # Runs on the same port as the Node.js example

# --- Mock Database ---
# This replaces a real database for demonstration purposes.
# It's pre-filled with the same data.

def hash_password(password):
  """Hashes a password with bcrypt."""
  salt = bcrypt.gensalt()
  hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
  return hashed.decode('utf-8') # Store as a string

db = {
  'users': [
    {
      'id': 'user-123',
      'email': 'user@test.com',
      # Password is 'password123'
      'passwordHash': hash_password('password123'),
      'firstName': 'Test',
      'lastName': 'User'
    }
  ],
  'items': [
    {
      'id': '1',
      'itemName': 'Brown Leather Wallet',
      'itemType': 'LOST',
      'description': 'Lost my wallet, it has my driver\'s license. Last seen near the main library.',
      'location': 'Main Library, Downtown',
      'date': '2025-11-07',
      'contactInfo': 'user@test.com', # This is the sensitive data
      'authorId': 'user-123',
    },
    {
      'id': '2',
      'itemName': 'Set of Keys',
      'itemType': 'FOUND',
      'description': 'Found a set of keys with a blue carabiner on the park bench.',
      'location': 'Central Park - Bench #14',
      'date': '2025-11-06',
      'contactInfo': 'finder@test.com', # This is the sensitive data
      'authorId': 'user-456',
    },
    # ... (other items from the mock DB) ...
  ]
}

# --- RBAC: Authentication Middleware ---
# This function runs *before every request*.
# It checks for a JWT and, if valid, attaches the user object to `g.user`.
# `g` is Flask's special object for holding data during a single request.
# This is the Python/Flask equivalent of the `authenticateUser` middleware in Node.js.

@app.before_request
def authenticate_user():
  """Check for a valid JWT and attach the user to `g.user`."""
  auth_header = request.headers.get('Authorization')
  g.user = None
  
  if auth_header:
    try:
      token_type, token = auth_header.split(' ')
      if token_type.lower() != 'bearer':
        return
        
      # Verify the token
      payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
      
      # Find the user in our mock DB
      user_id = payload.get('id')
      user = next((u for u in db['users'] if u['id'] == user_id), None)
      
      if user:
        # IMPORTANT: Attach user to request *without* password hash
        user_without_password = user.copy()
        user_without_password.pop('passwordHash', None)
        g.user = user_without_password
        
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, ValueError, Exception):
      # Token is invalid, expired, or malformed
      g.user = None


# --- RBAC: Route Protection Decorator ---
# This is a Python "decorator" that we can add to any route to protect it.
# It implements **Gate 1** of your security plan.

def require_auth(f):
  """A decorator to protect routes that require authentication."""
  @wraps(f)
  def decorated_function(*args, **kwargs):
    if g.user is None:
      return jsonify({'message': 'Unauthorized. You must be logged in for this action.'}), 401
    return f(*args, **kwargs)
  return decorated_function


# --- AUTHENTICATION ENDPOINTS (Core Requirement 1) ---

@app.route('/auth/register', methods=['POST'])
def register_user():
  data = request.get_json()
  email = data.get('email')
  password = data.get('password')
  first_name = data.get('firstName')

  if not email or not password or not first_name:
    return jsonify({'message': 'Email, password, and first name are required.'}), 400

  # Check if user already exists
  if next((u for u in db['users'] if u['email'] == email), None):
    return jsonify({'message': 'User with this email already exists.'}), 400
    
  # Create new user
  new_user = {
    'id': str(uuid.uuid4()),
    'email': email,
    'passwordHash': hash_password(password),
    'firstName': first_name,
    'lastName': data.get('lastName', '')
  }
  db['users'].append(new_user)
  print(f'New user registered: {new_user["email"]}')

  # Create JWT
  token = jwt.encode({
    'id': new_user['id'], 
    'email': new_user['email'],
    'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
  }, app.config['SECRET_KEY'])
  
  user_response = new_user.copy()
  user_response.pop('passwordHash', None)
  
  return jsonify({'token': token, 'user': user_response}), 201

@app.route('/auth/login', methods=['POST'])
def login_user():
  data = request.get_json()
  email = data.get('email')
  password = data.get('password')

  user = next((u for u in db['users'] if u['email'] == email), None)
  
  # Check if user exists and password is correct
  if not user or not bcrypt.checkpw(password.encode('utf-8'), user['passwordHash'].encode('utf-8')):
    return jsonify({'message': 'Invalid email or password.'}), 401
    
  # Create JWT
  token = jwt.encode({
    'id': user['id'], 
    'email': user['email'],
    'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
  }, app.config['SECRET_KEY'])
  
  user_response = user.copy()
  user_response.pop('passwordHash', None)
  
  return jsonify({'token': token, 'user': user_response}), 200

@app.route('/api/users/me', methods=['GET'])
@require_auth  # This route is now protected
def get_current_user():
  # The `@require_auth` decorator already checked for a user.
  # The `@app.before_request` hook already attached `g.user`.
  # We just return the user object.
  return jsonify(g.user), 200


# --- ITEM ENDPOINTS (Core Requirements 2, 3, 4) ---

@app.route('/api/items', methods=['GET'])
def get_items():
  """
  Get All Items (Browsing & Search)
  This is a PUBLIC route.
  Implements Core Requirement 3.
  Implements RBAC **Gate 2**: Hides contactInfo from unauthenticated users.
  """
  search_term = request.args.get('search', '').lower()
  filter_type = request.args.get('type', 'ALL')
  
  items = db['items'][:] # Make a copy
  
  # Filter by type (LOST/FOUND)
  if filter_type != 'ALL':
    items = [item for item in items if item['itemType'] == filter_type]
    
  # Filter by search term
  if search_term:
    items = [
      item for item in items if
      search_term in item['itemName'].lower() or
      search_term in item['description'].lower() or
      search_term in item['location'].lower()
    ]
    
  # --- RBAC GATE 2 LOGIC ---
  # `g.user` was set by our `authenticate_user` function.
  # If `g.user` is None, the user is not logged in.
  
  is_authenticated = g.user is not None
  safe_items = []
  
  for item in items:
    if is_authenticated:
      # User is logged in, append the full item
      safe_items.append(item)
    else:
      # User is NOT logged in, hide contact info
      item_without_contact = item.copy()
      item_without_contact.pop('contactInfo', None) # Remove the sensitive key
      safe_items.append(item_without_contact)
      
  # Return the processed items, newest first
  safe_items.reverse()
  return jsonify(safe_items), 200


@app.route('/api/items', methods=['POST'])
@require_auth # This route is now protected
def post_item():
  """
  Post a New Item
  This is a PROTECTED route.
  Implements Core Requirement 2.
  Implements RBAC **Gate 1**: Requires authentication to post.
  """
  data = request.get_json()
  
  required_fields = ['itemName', 'itemType', 'location', 'date', 'contactInfo']
  if not all(field in data for field in required_fields):
    return jsonify({'message': 'Missing required fields.'}), 400
    
  # `@require_auth` decorator guarantees `g.user` exists.
  new_item = {
    'id': str(uuid.uuid4()),
    'authorId': g.user['id'], # Securely set author from token, not from body
    'itemName': data['itemName'],
    'itemType': data['itemType'],
    'description': data.get('description', ''),
    'location': data['location'],
    'date': data['date'],
    'contactInfo': data['contactInfo'],
  }
  
  db['items'].append(new_item)
  print(f'New item posted: {new_item["itemName"]}')
  
  return jsonify(new_item), 201


# --- Start Server ---
if __name__ == '__main__':
  print(f"Lost & Found AI (Python/Flask) running on http://localhost:{PORT}")
  print("This is a mock server. Data will reset on restart.")
  print("Test login with user@test.com and password123")
  print("---")
  print("Available Endpoints:")
  print("  POST /auth/register")
  print("  POST /auth/login")
  print("  GET  /api/users/me (Protected)")
  print("  GET  /api/items (Public, hides contact info)")
  print("  POST /api/items (Protected)")
  app.run(port=PORT, debug=True)