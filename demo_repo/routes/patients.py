from flask import Blueprint, request, jsonify
import logging

patients_bp = Blueprint('patients', __name__)
logger = logging.getLogger('healthcare')

# Vulnerable to R08 (Sensitive URL Path) & R02 (PII Logging)
@patients_bp.route('/api/v1/patients/aadhaar/<aadhaar_number>/records', methods=['GET'])
def get_patient_records(aadhaar_number):
    
    # R02: Logging sensitive identifier
    logger.info(f"Accessing health records for Aadhaar: {aadhaar_number}")
    
    # Mock response
    return jsonify({
        "status": "success",
        "data": {
            "patient_id": "PT-99812",
            "last_visit": "2023-11-04",
            "diagnosis": "Hypertension under control"
        }
    })

# Unauthenticated state-changing route (triggers R07 Rate Limiting and R05 Auth)
@patients_bp.route('/api/v1/patients/<int:patient_id>/prescriptions', methods=['POST'])
def add_prescription(patient_id):
    medication = request.json.get('medication')
    dosage = request.json.get('dosage')
    
    # Missing input validation (MC03)
    # Missing error handling (MC04)
    # Direct DB execution mock
    # db.execute(f"INSERT INTO prescriptions (pid, med, dose) VALUES ({patient_id}, '{medication}', '{dosage}')")
    
    return jsonify({"message": "Prescription added successfully"}), 201
