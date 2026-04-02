from flask import Flask, request, jsonify
import logging

import os

app = Flask(__name__)
# R10 Fixed
DEBUG = False 
# R04 Fixed
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-safe-key') 

logger = logging.getLogger('demo_app')
# NOT doing logging_basicConfig triggers MC01 (missing controls)

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy"})

# Unauthenticated sensitive route triggers R05
@app.route('/api/v1/kyc', methods=['POST'])
def submit_kyc():
    aadhaar = request.json.get('aadhaar')
    card_number = request.json.get('card_number')
    
    # R02: PII logged
    logger.info(f"Received KYC for aadhaar: {aadhaar} with card {card_number}")
    
    # TAINT FIXED: Parameterized query
    query = "INSERT INTO users (kyc) VALUES (?)"
    # execute(query, (aadhaar,))
    
    return jsonify({"status": "received"})

if __name__ == '__main__':
    app.run(debug=DEBUG)
