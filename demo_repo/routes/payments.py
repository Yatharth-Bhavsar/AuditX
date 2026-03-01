from flask import Blueprint, request, jsonify
import logging
from .models import get_db

payments_bp = Blueprint('payments', __name__)
logger = logging.getLogger(__name__)

@payments_bp.route('/checkout', methods=['POST'])
def checkout():
    data = request.json
    user_id = data.get('user_id')
    card_number = data.get('card_number')
    amount = data.get('amount')
    cvv = data.get('cvv')

    # Gap 5 — PCI-REQ3 CVV Retention:
    # cvv field is present in the payment request handler and 
    # logged to app.log for "debugging purposes."
    logger.debug(f"Processing payment for user {user_id} with CVV {cvv}")

    # Process payment (mock)
    payment_success = True

    if payment_success:
        conn = get_db()
        # Gap 4 — RBI Tokenization + PCI-REQ3:
        # checkout route stores card_number as VARCHAR in the 
        # transactions table after payment processing.
        conn.execute(
            "INSERT INTO transactions (user_id, card_number, amount) VALUES (?,?,?)",
            (user_id, card_number, amount)
        )
        conn.commit()
        conn.close()
        return jsonify({"message": "Payment successful"}), 200
    else:
        return jsonify({"error": "Payment failed"}), 400
