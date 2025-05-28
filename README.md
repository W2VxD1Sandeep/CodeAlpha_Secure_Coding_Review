# 🔐 Secure Coding Review - Flask Web Application

This project was developed during my internship at **CodeAlpha** to demonstrate secure coding practices in a real-world web application using **Python (Flask)**. It includes a presentation PDF and a Flask app that showcases how to prevent common security vulnerabilities in modern web development.

## 📄 Project Overview

The main objective was to **review, identify, and fix security issues** in code while following industry-standard best practices.

Key security topics addressed:
- Identify and fix vulnerabilities
- Ensure compliance with secure coding standards
- Prevent common exploits (e.g., XSS, SQLi, CSRF)

## 💻 Application Features

- User Signup & Login System
- Secure File Upload
- Comment Form with Input Sanitization
- User Bio Update
- Security Mitigations Integrated

## 🔒 Security Measures Implemented

| Vulnerability         | Fix Implemented                     

| SQL Injection         | ✅ Parameterized Queries             
| Plaintext Passwords   | ✅ Password Hashing                  
| Cross-Site Scripting  | ✅ Output Escaping  
| CSRF Attacks          | ✅ CSRF Protection via Flask-WTF     

## 🧰 Tools & Techniques Used

- **Bandit** – Static analysis for security issues in Python code
- **Pylint** – Code quality checker for Python
- **Flask-WTF** – Secure form handling and CSRF protection
- **SAST** tools – Static application security testing (e.g., SonarQube)

🎓 What I Learned
	•	Think like an attacker
	•	Always validate user input
	•	Automate security checks during development
	•	Secure coding is not an extra task – it’s essential
