# Password Strength & Breach Detection Tool

> A cybersecurity web application that evaluates password strength, detects breach exposure, assigns a score, and generates security recommendations.

---

## Project Structure

```
password_strength_tool/
│
├── app.py              ← Flask backend (main application)
├── breach_db.json      ← Simulated breach database (SHA-256 hashed passwords)
│
├── templates/
│    └── index.html     ← Frontend HTML template
│
├── static/
│    └── style.css      ← Styling
│
└── README.md           ← This file
```

---

## Requirements

- Python 3.7+
- Flask

Install dependencies:

```bash
pip install flask
```

---

## How to Run

1. Navigate to the project folder:
```bash
cd password_strength_tool
```

2. Run the Flask server:
```bash
python app.py
```

3. Open your browser and visit:
```
http://127.0.0.1:5000
```

---

## System Flow

```
User enters password
       ↓
Password Analysis Module    → Length, character types, patterns
       ↓
Breach Detection Module     → SHA-256 hash comparison
       ↓
Strength Scoring Engine     → Numeric score + category
       ↓
Recommendation Generator    → Targeted security advice
       ↓
Frontend Display            → Color-coded results
```

---

## Scoring System

| Criterion              | Points |
|------------------------|--------|
| Length ≥ 8             | +2     |
| Length ≥ 12            | +2     |
| Uppercase letters      | +1     |
| Lowercase letters      | +1     |
| Numbers                | +1     |
| Special characters     | +2     |
| Found in breach DB     | -5     |
| Common password        | -5     |
| Sequential patterns    | -2     |
| Repeated characters    | -2     |

### Strength Categories

| Score | Category    |
|-------|-------------|
| 0–3   | Weak        |
| 4–7   | Medium      |
| 8–10  | Strong      |
| 11+   | Very Strong |

---

## Test Passwords

| Password           | Expected Category |
|--------------------|-------------------|
| `123456`           | Weak              |
| `password`         | Weak              |
| `Pass1234`         | Medium            |
| `J@inish2026`      | Strong            |
| `J@inish#Secure2026!` | Very Strong    |

---

## Security Notes

- Passwords are **never logged or stored** in plain text
- All breach comparisons use **SHA-256 hashing**
- The breach database contains **hashed values only**
- Input is validated server-side before processing
- The breach database is **simulated** for academic purposes

---

## API Endpoints

| Method | Route      | Description                      |
|--------|------------|----------------------------------|
| GET    | `/`        | Serve the homepage               |
| POST   | `/analyze` | Analyze password and return JSON |

### POST /analyze — Request Body
```json
{ "password": "YourPasswordHere" }
```

### POST /analyze — Response
```json
{
  "score": 9,
  "category": "Strong",
  "breached": false,
  "analysis": { ... },
  "score_breakdown": [ ... ],
  "recommendations": [ ... ]
}
```

---

## Academic Notes

This project demonstrates:
- **Secure password hashing** (hashlib SHA-256)
- **RESTful API design** (Flask)
- **Modular backend architecture** (separated analysis, detection, scoring, recommendation modules)
- **Client-server communication** (Fetch API / JSON)
- **Cybersecurity best practices** awareness

---

*Cybersecurity Academic Project — Password Strength & Breach Detection Tool*