from flask_cors import CORS
from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import pickle
import numpy as np
import pandas

path = '.'  # for local host

# path = 'home/LalithAdavi/mysite/res'  # for pythonanywhere deployment

pt = pickle.load(open(path + '/res/pt.pkl', 'rb'))
books = pickle.load(open(path + '/res/comp_books.pkl', 'rb'))
scores = pickle.load(open(path + '/res/scores.pkl', 'rb'))

app = Flask(__name__)
cors = CORS(app, resources={r'/*': {'origin': '*'}})

# Set up the secret key for JWT
app.config['JWT_SECRET_KEY'] = 'your_secret_key_here'  # Change this to a secret key of your choice

# Initialize Bcrypt for password hashing and JWT Manager for JWT handling
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Path for storing user data (in pickle file format)
user_data_path = './res/users.pkl'  # Adjust this path to your location

# Load users from the pickle file
def load_users():
    try:
        with open(user_data_path, 'rb') as f:
            return pickle.load(f)
    except FileNotFoundError:
        return {}

# Save users to the pickle file
def save_users(users):
    with open(user_data_path, 'wb') as f:
        pickle.dump(users, f)


@app.route('/')
def index_ui():
    return jsonify('welcome'), 200


@app.route('/top50_api')
def top50_api():
    x = books.sort_values(by='avg_rating', ascending=False)
    data = [
        list(x['Book-Title'].values),
        list(x['Book-Author'].values),
        list(x['Image-URL-L'].values),
        list(x['num_ratings'].values),
        list(format(i, ".2f") for i in x['avg_rating'].values)
    ]
    res = []
    for i in range(50):
        res.append({'Book-title': str(data[0][i]),
                    'Book-author': str(data[1][i]),
                    'Image-URL-M': str(data[2][i]),
                    'num_ratings': str(data[3][i]),
                    'avg_ratings': str(data[4][i]),})
    return jsonify(res), 200


@app.route('/reccomendations_api', methods=['post'])
def reccomendations_api():
    book_name = request.json['name']
    if len(np.where(pt.index == book_name)[0]) == 0:
        return jsonify({'status': 0, 'books': []}), 200

    idx = np.where(pt.index == book_name)[0][0]
    items = sorted(list(enumerate(scores[idx])), key=lambda x: x[1], reverse=True)[1:20]
    data = []

    for i in items:
        item = []
        temp = books[books['Book-Title'] == pt.index[i[0]]]
        item.extend(list(temp.drop_duplicates('Book-Title')['Book-Title'].values))
        item.extend(list(temp.drop_duplicates('Book-Title')['Book-Author'].values))
        item.extend(list(temp.drop_duplicates('Book-Title')['Image-URL-L'].values))
        item.extend(list(temp.drop_duplicates('Book-Title')['num_ratings'].values.astype('str')))
        item.extend(list(temp.drop_duplicates('Book-Title')['avg_rating'].values.astype('str')))
        data.append(item)
    res = []
    for i in data:
        if len(i) == 0:
            continue
        res.append({'Book-title': i[0],
                    'Book-author': i[1],
                    'Image-URL-M': i[2],
                    'num_ratings': i[3],
                    'avg_rating': i[4]
                    })
    data = data[:10]
    return jsonify({'status': 1, 'books': res}), 200


@app.route('/book_names')
def book_names_api():
    return jsonify({'BookNames': list(books['Book-Title'])}), 200


# Step 5: Create the Signup Endpoint
@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()

    # Validate required fields
    if not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing required fields'}), 400

    # Load existing users
    users = load_users()

    # Check if the user already exists
    if data['email'] in users:
        return jsonify({'message': 'Email already exists'}), 400

    # Hash the password
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

    # Add the new user
    users[data['email']] = {'username': data['username'], 'password': hashed_password}

    # Save the users
    save_users(users)

    return jsonify({'message': 'User created successfully'}), 201


# Step 6: Create the Login Endpoint
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()

    # Validate required fields
    if not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing required fields'}), 400

    # Load users from pickle file
    users = load_users()

    # Check if the user exists
    user = users.get(data['email'])
    if not user:
        return jsonify({'message': 'Invalid email or password'}), 401

    # Check if the password matches
    if not bcrypt.check_password_hash(user['password'], data['password']):
        return jsonify({'message': 'Invalid email or password'}), 401

    # Generate JWT token
    access_token = create_access_token(identity=data['email'])

    return jsonify({'access_token': access_token}), 200


# Step 7: Protect Routes with JWT (Optional)
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    # Get the current user's email from the JWT token
    current_user = get_jwt_identity()

    return jsonify({'message': f'Welcome, {current_user}!'}), 200


# comment below code for pythonanywhere deployment
if __name__ == '__main__':
    app.run(debug=True)
