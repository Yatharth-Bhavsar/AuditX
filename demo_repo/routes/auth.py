from flask import Blueprint, request, jsonify
from .models import get_db

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.json
    # Gap 1 — DPDP §8(3) Data Minimization:
    # Registration route collects: email, password, phone, dob, 
    # gender, religion, mother_maiden_name, voter_id
    # Of these, religion, mother_maiden_name, and voter_id are 
    # collected but never used in any downstream function.
    email = data.get('email')
    password = data.get('password')
    phone = data.get('phone')
    
    # Gap 2 — DPDP §9 Children's Data:
    # No age check before collecting personal data.
    # Registration accepts any dob without verifying age >= 18.
    dob = data.get('dob')
    
    gender = data.get('gender')
    religion = data.get('religion')
    mother_maiden_name = data.get('mother_maiden_name')
    voter_id = data.get('voter_id')

    conn = get_db()
    conn.execute(
        "INSERT INTO users (email, password, phone, dob, gender, religion, mother_maiden_name, voter_id) VALUES (?,?,?,?,?,?,?,?)",
        (email, password, phone, dob, gender, religion, mother_maiden_name, voter_id)
    )
    conn.commit()
    conn.close()

    return jsonify({"message": "User registered"}), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    # Gap 3 — DPDP §8(3) + PCI-REQ6 Input Validation:
    # Login route takes username directly into a string-formatted 
    # SQL query without parameterization.
    conn = get_db()
    try:
        query = f"SELECT * FROM users WHERE email='{email}'"
        user = conn.execute(query).fetchone()
        
        if user and user['password'] == password:
            return jsonify({"token": "fake-jwt-token"}), 200
        else:
            return jsonify({"error": "Invalid credentials"}), 401
    finally:
        conn.close()
