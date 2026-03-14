"""
Password Strength and Breach Detection Tool
============================================
Backend: Flask (Python)
Author: Academic Cybersecurity Project
Description: Evaluates password strength, detects breach exposure (simulated),
             assigns a score, and generates security recommendations.
"""

import hashlib
import json
import re
import os
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
# Home page route
@app.route("/")
def home():
    return render_template("index.html")

# ─────────────────────────────────────────────
# Load Simulated Breach Database
# ─────────────────────────────────────────────
def load_breach_db():
    """Load the hashed breach database from JSON file."""
    db_path = os.path.join(os.path.dirname(__file__), 'breach_db.json')
    with open(db_path, 'r') as f:
        data = json.load(f)
    return set(data.get('hashed_passwords', []))

BREACH_DB = load_breach_db()

# ─────────────────────────────────────────────
# Common Passwords List (plain for pattern check)
# ─────────────────────────────────────────────
COMMON_PASSWORDS = {
    'password', '123456', 'qwerty', 'abc123', 'letmein',
    'welcome', 'monkey', 'dragon', 'master', 'sunshine',
    'admin', 'login', 'pass', 'test', 'guest', 'hello'
}

# ─────────────────────────────────────────────
# Module 1: Password Hashing
# ─────────────────────────────────────────────
def hash_password(password: str) -> str:
    """Hash password using SHA-256 for secure comparison."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

# ─────────────────────────────────────────────
# Module 2: Password Analysis
# ─────────────────────────────────────────────
def analyze_password(password: str) -> dict:
    """
    Analyze password characteristics.
    Returns a dictionary of boolean flags and metadata.
    """
    length = len(password)

    has_uppercase    = bool(re.search(r'[A-Z]', password))
    has_lowercase    = bool(re.search(r'[a-z]', password))
    has_digits       = bool(re.search(r'\d', password))
    has_special      = bool(re.search(r'[^A-Za-z0-9]', password))

    # Pattern Detection
    has_repetition   = bool(re.search(r'(.)\1{2,}', password))  # e.g. aaa, 111
    has_sequential   = _detect_sequential(password)
    is_common        = password.lower() in COMMON_PASSWORDS

    # Length Category
    if length < 8:
        length_category = 'Weak'
    elif length < 12:
        length_category = 'Moderate'
    else:
        length_category = 'Strong'

    return {
        'length': length,
        'length_category': length_category,
        'has_uppercase': has_uppercase,
        'has_lowercase': has_lowercase,
        'has_digits': has_digits,
        'has_special': has_special,
        'has_repetition': has_repetition,
        'has_sequential': has_sequential,
        'is_common': is_common,
    }

def _detect_sequential(password: str) -> bool:
    """Detect sequential patterns like 1234 or abcd."""
    p = password.lower()
    for i in range(len(p) - 3):
        chunk = p[i:i+4]
        codes = [ord(c) for c in chunk]
        if all(codes[j+1] - codes[j] == 1 for j in range(len(codes)-1)):
            return True
    return False

# ─────────────────────────────────────────────
# Module 3: Breach Detection
# ─────────────────────────────────────────────
def check_breach(password: str) -> bool:
    """
    Check if password hash exists in simulated breach database.
    NEVER compares or stores plain-text passwords.
    """
    hashed = hash_password(password)
    return hashed in BREACH_DB

# ─────────────────────────────────────────────
# Module 4: Strength Scoring Engine
# ─────────────────────────────────────────────
def calculate_score(analysis: dict, breached: bool) -> tuple:
    """
    Calculate numeric strength score based on analysis.
    Returns (score, category, breakdown).
    """
    score = 0
    breakdown = []

    # Length scoring
    if analysis['length'] >= 8:
        score += 2
        breakdown.append(('Length ≥ 8', +2))
    if analysis['length'] >= 12:
        score += 2
        breakdown.append(('Length ≥ 12', +2))

    # Character type scoring
    if analysis['has_uppercase']:
        score += 1
        breakdown.append(('Uppercase letters', +1))
    if analysis['has_lowercase']:
        score += 1
        breakdown.append(('Lowercase letters', +1))
    if analysis['has_digits']:
        score += 1
        breakdown.append(('Numbers', +1))
    if analysis['has_special']:
        score += 2
        breakdown.append(('Special characters', +2))

    # Penalties
    if breached:
        score -= 5
        breakdown.append(('Found in breach database', -5))
    if analysis['is_common']:
        score -= 5
        breakdown.append(('Common password detected', -5))
    if analysis['has_sequential']:
        score -= 2
        breakdown.append(('Sequential pattern detected', -2))
    if analysis['has_repetition']:
        score -= 2
        breakdown.append(('Repeated characters detected', -2))

    # Clamp score at 0 minimum
    score = max(0, score)

    # Categorize
    if score <= 3:
        category = 'Weak'
    elif score <= 7:
        category = 'Medium'
    elif score <= 10:
        category = 'Strong'
    else:
        category = 'Very Strong'

    return score, category, breakdown

# ─────────────────────────────────────────────
# Module 5: Recommendation Generator
# ─────────────────────────────────────────────
def generate_recommendations(analysis: dict, breached: bool) -> list:
    """Generate targeted security recommendations based on weaknesses."""
    recommendations = []

    if breached:
        recommendations.append({
            'type': 'critical',
            'text': 'Change this password immediately — it has appeared in known data breaches.'
        })

    if analysis['is_common']:
        recommendations.append({
            'type': 'critical',
            'text': 'This is a commonly used password. Avoid dictionary words and well-known patterns.'
        })

    if analysis['length'] < 12:
        recommendations.append({
            'type': 'warning',
            'text': f"Increase your password length to at least 12 characters (currently {analysis['length']})."
        })

    if not analysis['has_uppercase']:
        recommendations.append({
            'type': 'warning',
            'text': 'Add uppercase letters (A–Z) to strengthen your password.'
        })

    if not analysis['has_lowercase']:
        recommendations.append({
            'type': 'warning',
            'text': 'Add lowercase letters (a–z) to your password.'
        })

    if not analysis['has_digits']:
        recommendations.append({
            'type': 'warning',
            'text': 'Include at least one number (0–9) in your password.'
        })

    if not analysis['has_special']:
        recommendations.append({
            'type': 'warning',
            'text': 'Add special characters (e.g. @, #, $, !) to significantly improve strength.'
        })

    if analysis['has_sequential']:
        recommendations.append({
            'type': 'info',
            'text': 'Avoid sequential patterns (e.g. 1234, abcd) as they are easy to guess.'
        })

    if analysis['has_repetition']:
        recommendations.append({
            'type': 'info',
            'text': 'Avoid repeating characters (e.g. aaa, 111).'
        })

    # General awareness tips (always shown)
    recommendations.append({'type': 'tip', 'text': 'Never reuse passwords across multiple accounts.'})
    recommendations.append({'type': 'tip', 'text': 'Enable Two-Factor Authentication (2FA) wherever possible.'})
    recommendations.append({'type': 'tip', 'text': 'Consider using a trusted password manager to generate and store unique passwords.'})

    return recommendations

# ─────────────────────────────────────────────
# Flask Routes
# ─────────────────────────────────────────────

@app.route('/', methods=['GET'])
def index():
    """Serve the main homepage."""
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    """
    POST /analyze
    Receives password, runs full analysis pipeline, returns JSON result.
    Passwords are NEVER logged or stored.
    """
    data = request.get_json(silent=True)

    # Input validation
    if not data or 'password' not in data:
        return jsonify({'error': 'No password provided.'}), 400

    password = data['password']

    if not isinstance(password, str) or len(password.strip()) == 0:
        return jsonify({'error': 'Password must be a non-empty string.'}), 400

    if len(password) > 256:
        return jsonify({'error': 'Password exceeds maximum allowed length.'}), 400

    # Pipeline execution
    analysis   = analyze_password(password)
    breached   = check_breach(password)
    score, category, breakdown = calculate_score(analysis, breached)
    recommendations = generate_recommendations(analysis, breached)

    # Build response (DO NOT include raw password in response)
    result = {
        'score': score,
        'category': category,
        'breached': breached,
        'analysis': {
            'length': analysis['length'],
            'length_category': analysis['length_category'],
            'has_uppercase': analysis['has_uppercase'],
            'has_lowercase': analysis['has_lowercase'],
            'has_digits': analysis['has_digits'],
            'has_special': analysis['has_special'],
            'has_repetition': analysis['has_repetition'],
            'has_sequential': analysis['has_sequential'],
            'is_common': analysis['is_common'],
        },
        'score_breakdown': breakdown,
        'recommendations': recommendations,
    }

    return jsonify(result), 200


import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
