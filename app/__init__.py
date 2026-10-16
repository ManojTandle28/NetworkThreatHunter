import os
from flask import Flask, render_template
from app.config import Config
from app.database import init_db

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Ensure required folders exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(os.path.dirname(app.config['DATABASE_PATH']), exist_ok=True)

    # Initialize SQLite database schema
    init_db(app.config['DATABASE_PATH'])

    # Register Blueprints
    from app.routes.main import main_bp
    from app.routes.explorer import explorer_bp
    from app.routes.alerts import alerts_bp
    from app.routes.exports import exports_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(explorer_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(exports_bp)

    # Custom Jinja Filters
    @app.template_filter('number_format')
    def number_format(val):
        if val is None:
            return "0"
        try:
            return f"{int(val):,}"
        except (ValueError, TypeError):
            return str(val)

    @app.template_filter('filesizeformat')
    def format_bytes(size):
        if not size:
            return "0 B"
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"

    # Safe error handlers
    @app.errorhandler(404)
    def handle_not_found(e):
        return render_template('error.html', error_code=404, title="Page Not Found",
                               message="The requested resource or page does not exist."), 404

    @app.errorhandler(413)
    def handle_file_too_large(e):
        max_mb = app.config['MAX_CONTENT_LENGTH'] // (1024 * 1024)
        return render_template('error.html', error_code=413, title="File Size Exceeded",
                               message=f"The uploaded capture file exceeds the maximum permitted size of {max_mb} MB."), 413

    @app.errorhandler(500)
    def handle_server_error(e):
        return render_template('error.html', error_code=500, title="Analysis Service Error",
                               message="An unexpected internal error occurred while processing your request. Please try again or verify the capture integrity."), 500

    return app
