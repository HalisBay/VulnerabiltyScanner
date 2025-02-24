from flask import Flask
from scanner import scanner_bp 
from config.config import DevelopmentConfig

app = Flask(__name__)
app.config.from_object(DevelopmentConfig)

app.register_blueprint(scanner_bp, url_prefix="/api")

if __name__ == '__main__':
    app.run(debug=True)
