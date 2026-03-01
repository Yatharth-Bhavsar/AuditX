from flask import Flask

app = Flask(__name__)
app.config.from_object('config.Config')

# Register blueprints/routes
from routes.auth import auth_bp
from routes.payments import payments_bp
from routes.kyc import kyc_bp

app.register_blueprint(auth_bp, url_prefix='/api/auth')
app.register_blueprint(payments_bp, url_prefix='/api/payments')
app.register_blueprint(kyc_bp, url_prefix='/api/kyc')

if __name__ == '__main__':
    app.run(debug=True, port=5000)
