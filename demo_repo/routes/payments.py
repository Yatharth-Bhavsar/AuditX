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

    # Secured logging: No longer storing CVV
    logger.debug(f"Processing payment for user {user_id}")

    # Process payment (mock)
    payment_success = True

    if payment_success:
        conn = get_db()
        # Secured: Using dummy token instead of raw card
        payment_token = f"tok_{user_id}_{amount}"
        conn.execute(
            "INSERT INTO transactions (user_id, payment_token, amount) VALUES (?,?,?)",
            (user_id, payment_token, amount)
        )
        conn.commit()
        conn.close()
        return jsonify({"message": "Payment successful"}), 200
    else:
        return jsonify({"error": "Payment failed"}), 400
