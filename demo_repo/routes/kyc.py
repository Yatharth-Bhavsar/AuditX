from flask import Blueprint, request, jsonify
from .models import get_db

kyc_bp = Blueprint('kyc', __name__)

@kyc_bp.route('/submit', methods=['POST'])
def submit_kyc():
    data = request.json
    
    # Gap 6 — RBI-KYC Data Minimization:
    # KYC submission route collects: pan_number, aadhaar_number, 
    # voter_id, driving_licence, passport_number, religion, caste
    # All stored in kyc_records table. No documented purpose 
    # for caste, religion fields.
    user_id = data.get('user_id')
    pan_number = data.get('pan_number')
    aadhaar_number = data.get('aadhaar_number')
    voter_id = data.get('voter_id')
    driving_licence = data.get('driving_licence')
    passport_number = data.get('passport_number')
    religion = data.get('religion')
    caste = data.get('caste')

    conn = get_db()
    conn.execute(
        "INSERT INTO kyc_records (user_id, pan_number, aadhaar_number, voter_id, driving_licence, passport_number, religion, caste) VALUES (?,?,?,?,?,?,?,?)",
        (user_id, pan_number, aadhaar_number, voter_id, driving_licence, passport_number, religion, caste)
    )
    conn.commit()
    conn.close()

    return jsonify({"message": "KYC submitted successfully"}), 201

# Gap 7 — DPDP §8(7) Retention / Erasure:
# No data deletion endpoint or retention policy anywhere 
# in the codebase. Data stored indefinitely.
