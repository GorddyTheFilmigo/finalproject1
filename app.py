import openai
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify, send_from_directory
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from bson.objectid import ObjectId
from bson.son import SON
from pymongo import MongoClient
import os
import io
import csv
import secrets
import string
from dateutil.relativedelta import relativedelta
import requests
from random import choice
from flask_wtf import FlaskForm

app = Flask(__name__)
app.config["SECRET_KEY"] = "your-secret-key"
app.config["MONGO_URI"] = "mongodb://localhost:27017/firmmanager"
app.config["UPLOAD_FOLDER"] = "static/uploads/resumes"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# MongoDB configuration
app.config["MONGO_URI"] = "mongodb://localhost:27017/firmmanager"
mongo = PyMongo(app)

# Uploads folder (for application resumes/documents)
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# ======================
# Helper Functions for Employee Creation
# ======================
def generate_username(name, email=None):
    """Generate a unique username based on name and email"""
    # Try first.last format from name
    name_parts = name.lower().split()
    if len(name_parts) >= 2:
        base_username = f"{name_parts[0]}.{name_parts[-1]}"
    else:
        base_username = name_parts[0] if name_parts else (email.split('@')[0] if email else 'user')
    
    # Check if username exists, add number if needed
    counter = 1
    username = base_username
    while mongo.db.users.find_one({"username": username}):
        username = f"{base_username}{counter}"
        counter += 1
    
    return username

def generate_temp_password(length=12):
    """Generate a secure temporary password"""
    alphabet = string.ascii_letters + string.digits + "!@#$%"
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password

def generate_password(length=12):
    """Generate a secure random password"""
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password

# ======================
# Create Default Admin if None Exists
# ======================
admin_checked = False

@app.before_request
def ensure_default_admin():
    global admin_checked
    if not admin_checked:
        admin_exists = mongo.db.users.find_one({"role": "admin"})
        if not admin_exists:
            mongo.db.users.insert_one({
                "name": "Default Admin",
                "email": "admin@firm.com",
                "password": generate_password_hash("ChangeMe123"),
                "role": "admin",
                "created_at": datetime.utcnow(),
                "force_update": True
            })
        admin_checked = True

# ======================
# Home Page
# ======================
@app.route("/")
def home():
    open_positions = list(mongo.db.positions.find({"status": "open"}))
    return render_template("home.html", open_positions=open_positions)

# ======================
# Job Application Route (NEW)
# ======================
@app.route("/apply_job", methods=["POST"])
def apply_job():
    # Fields expected from the form
    position = request.form.get("position", "")
    name = request.form.get("name", "")
    email = request.form.get("email", "")
    qualifications = request.form.get("qualifications", "")
    resume = request.files.get("resume")

    # Basic validation
    if not name or not email or not qualifications:
        flash("Please fill all required fields.", "danger")
        return redirect(url_for("home"))

    resume_filename = None
    if resume and resume.filename != "":
        # Secure filename and save to uploads folder
        filename = secure_filename(resume.filename)
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        resume.save(save_path)
        resume_filename = filename

    application = {
        "position": position,
        "name": name,
        "email": email,
        "qualifications": qualifications,
        "resume_filename": resume_filename,
        "status": "Submitted",
        "submitted_at": datetime.utcnow()
    }
    mongo.db.job_applications.insert_one(application)

    # Increment applicant count if position exists (non-breaking)
    if position:
        mongo.db.positions.update_one({"title": position}, {"$inc": {"applicants": 1}})

    flash("Application submitted successfully! HR will review it.", "success")
    return redirect(url_for("home"))

# ======================
# Register
# ======================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        role = request.form.get("role")

        if not name or not email or not password or not role:
            flash("All fields are required!", "danger")
            return redirect(url_for("register"))

        user = mongo.db.users.find_one({"email": email})
        if user:
            flash("Email already exists!", "danger")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)
        mongo.db.users.insert_one({
            "name": name,
            "email": email,
            "password": hashed_password,
            "role": role,
            "created_at": datetime.utcnow(),
            "force_update": False
        })
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

# ======================
# Login
# ======================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Check for both email and username login
        login_field = request.form.get("email")  # Can be email or username
        password = request.form.get("password")

        # Try to find user by email first, then by username
        user = mongo.db.users.find_one({"email": login_field}) or mongo.db.users.find_one({"username": login_field})

        if user and check_password_hash(user["password"], password):
            # Update first login status if this is their first time
            if not user.get("first_login_completed"):
                mongo.db.users.update_one(
                    {"_id": user["_id"]}, 
                    {
                        "$set": {
                            "first_login_completed": True,
                            "first_login_date": datetime.utcnow(),
                            "last_login_date": datetime.utcnow()
                        }
                    }
                )
            else:
                # Update last login
                mongo.db.users.update_one(
                    {"_id": user["_id"]}, 
                    {"$set": {"last_login_date": datetime.utcnow()}}
                )

            # Check if admin account needs update
            if user["role"] == "admin":
                created_at = user.get("created_at")
                force_update = user.get("force_update", False)
                if force_update or (created_at and datetime.utcnow() > created_at + timedelta(days=180)):
                    flash("Admin account must be updated before proceeding.", "warning")
                    session["force_update"] = str(user["_id"])
                    return redirect(url_for("update_admin"))

            session["user"] = {
                "name": user["name"],
                "email": user["email"],
                "role": user["role"]
            }
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid email/username or password!", "danger")
        return redirect(url_for("login"))

    return render_template("login.html")

# ======================
# Employee First Login (HR-provided credentials)
# ======================
@app.route("/employee_first_login", methods=["POST"])
def employee_first_login():
    username = request.form.get("username")
    temp_password = request.form.get("temp_password")

    if not username or not temp_password:
        flash("Username and temporary password are required.", "danger")
        return redirect(url_for("home"))

    # Find employee by username
    user = mongo.db.users.find_one({"username": username, "role": "employee"})

    if not user:
        flash("Invalid username or not an employee account.", "danger")
        return redirect(url_for("home"))

    # Check if this is first login (temp_password matches stored hash)
    if not check_password_hash(user["password"], temp_password):
        flash("Incorrect temporary password.", "danger")
        return redirect(url_for("home"))

    # Check if first login already completed
    if user.get("first_login_completed", False):
        flash("This account has already been activated. Please use regular login.", "info")
        return redirect(url_for("home"))

    # Store user in session temporarily for password reset
    session["pending_first_login"] = {
        "user_id": str(user["_id"]),
        "username": user["username"],
        "name": user.get("name", "Employee"),
        "email": user.get("email", ""),
        "role": "employee"
    }

    flash("Temporary credentials verified. Please set your new password.", "info")
    return redirect(url_for("employee_reset_password_page"))


# ======================
# Employee Reset Password Page (GET)
# ======================
@app.route("/employee_reset_password")
def employee_reset_password_page():
    if "pending_first_login" not in session:
        flash("Unauthorized access.", "danger")
        return redirect(url_for("home"))

    return render_template("employee_reset_password.html")


# ======================
# Employee Reset Password (POST)
# ======================
@app.route("/employee_reset_password", methods=["POST"])
def employee_reset_password():
    if "pending_first_login" not in session:
        flash("Session expired. Please try again.", "danger")
        return redirect(url_for("home"))

    new_password = request.form.get("new_password")
    confirm_password = request.form.get("confirm_password")

    if new_password != confirm_password:
        flash("Passwords do not match.", "danger")
        return redirect(url_for("employee_reset_password_page"))

    if len(new_password) < 6:
        flash("Password must be at least 6 characters.", "danger")
        return redirect(url_for("employee_reset_password_page"))

    user_id = session["pending_first_login"]["user_id"]
    hashed = generate_password_hash(new_password)

    # Update user: set new password, mark first login complete
    mongo.db.users.update_one(
        {"_id": ObjectId(user_id)},
        {
            "$set": {
                "password": hashed,
                "first_login_completed": True,
                "first_login_date": datetime.utcnow(),
                "last_login_date": datetime.utcnow()
            }
        }
    )

    # Move to full session
    user_data = session["pending_first_login"]
    session.pop("pending_first_login", None)
    session["user"] = {
        "name": user_data["name"],
        "email": user_data["email"],
        "role": user_data["role"]
    }

    flash("Password set successfully! Welcome to FirmManager Pro.", "success")
    return redirect(url_for("dashboard"))  # Redirects to employee dashboard


# ======================
# Update Admin
# ======================
@app.route("/update_admin", methods=["GET", "POST"])
def update_admin():
    if "force_update" not in session:
        return redirect(url_for("login"))

    admin_id = session["force_update"]
    admin_user = mongo.db.users.find_one({"_id": ObjectId(admin_id)})

    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")

        update_data = {
            "name": name,
            "email": email,
            "password": generate_password_hash(password),
            "created_at": datetime.utcnow(),  # reset timestamp
            "force_update": False
        }

        mongo.db.users.update_one({"_id": ObjectId(admin_id)}, {"$set": update_data})
        session.pop("force_update", None)
        flash("Admin account updated successfully. Please log in again.", "success")
        return redirect(url_for("login"))

    return render_template("update_admin.html", admin=admin_user)

# ======================
# Dashboard (Role-Based)
# ======================
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")

    user = session["user"]

    if user["role"] == "admin":
        clients_cursor = mongo.db.users.find({"role": "client"})
        clients = [
            {
                "name": c.get("name", "N/A"),
                "email": c.get("email", "N/A"),
                "active": c.get("active", False)
            }
            for c in clients_cursor
        ]

        employees_cursor = mongo.db.users.find({"role": "employee"})
        employees = [
            {
                "name": e.get("name", "N/A"),
                "email": e.get("email", "N/A"),
                "department": e.get("department", "N/A")
            }
            for e in employees_cursor
        ]

        return render_template(
            "dashboard_admin.html",
            user=user,
            clients=clients,
            employees=employees
        )

    elif user["role"] == "employee":
        return render_template("dashboard_employee.html", user=user)

    elif user["role"] == "hr":
        return redirect(url_for("hr_dashboard"))

    else:  # client
        return render_template("dashboard_client.html", user=user)

# ======================
# Employee Submissions (to HR)
# ======================
@app.route("/employee/leaves", methods=["POST"])
def submit_leave():
    if "user" not in session:
        return redirect("/login")
    leave = {
        "employee_name": session["user"]["name"],
        "type": request.form.get("type", "Leave"),
        "dates": f"{request.form['from_date']} to {request.form['to_date']}",
        "reason": request.form["reason"],
        "from_date": request.form["from_date"],
        "to_date": request.form["to_date"],
        "status": "Pending",
        "submitted_at": datetime.utcnow()
    }
    mongo.db.leaves.insert_one(leave)
    flash("Leave request submitted!", "success")
    return redirect(url_for("dashboard"))

@app.route("/employee/claims", methods=["POST"])
def submit_claim():
    if "user" not in session:
        return redirect("/login")
    claim = {
        "employee_name": session["user"]["name"],
        "type": request.form["type"],
        "amount": request.form["amount"],
        "details": request.form.get("details", ""),
        "status": "Pending",
        "submitted_at": datetime.utcnow()
    }
    mongo.db.claims.insert_one(claim)
    flash("Claim submitted!", "success")
    return redirect(url_for("dashboard"))

@app.route("/employee/performance", methods=["POST"])
def submit_performance():
    if "user" not in session:
        return redirect("/login")
    perf = {
        "employee_name": session["user"]["name"],
        "feedback": request.form["feedback"],
        "status": "Pending",
        "submitted_at": datetime.utcnow()
    }
    mongo.db.performance.insert_one(perf)
    flash("Performance feedback submitted!", "success")
    return redirect(url_for("dashboard"))

# ======================
# HR DASHBOARD AND ROUTES (CONSOLIDATED - NO DUPLICATES)
# ======================

@app.route('/hr/dashboard')
def hr_dashboard():
    """Render HR Dashboard"""
    if "user" not in session:
        return redirect(url_for("login"))
    if not (session["user"]["role"] in ["admin", "hr"] or session.get("hr_access", False)):
        flash("Access denied!", "danger")
        return redirect(url_for("dashboard"))
    
    employees = list(mongo.db.users.find({"role": "employee"}))
    leave_requests = list(mongo.db.leaves.find())
    claims = list(mongo.db.claims.find())
    positions = list(mongo.db.positions.find())
    job_applications = list(mongo.db.job_applications.find())
    reports = list(mongo.db.hr_reports.find({'department': 'HR'}))
    documents = list(mongo.db.documents.find({'department': 'HR'}))
    
    return render_template('hr_dashboard.html',
                         employees=employees,
                         leave_requests=leave_requests,
                         claims=claims,
                         positions=positions,
                         job_applications=job_applications,
                         reports=reports,
                         documents=documents)

@app.route('/hr/create_employee', methods=['POST'])
def create_employee():
    """Create new employee profile"""
    try:
        data = request.json
        
        # Check if employee already exists
        if mongo.db.users.find_one({'email': data['employee_email']}):
            return jsonify({'success': False, 'error': 'Employee with this email already exists'})
        
        if mongo.db.users.find_one({'employee_id': data['employee_id']}):
            return jsonify({'success': False, 'error': 'Employee ID already exists'})
        
        # Generate credentials if auto-generate is enabled
        credentials = None
        if data.get('generate_auto_password', True):
            username = generate_username(data['employee_name'], data['employee_email'])
            password = generate_password()
            credentials = {
                'username': username,
                'password': password
            }
        else:
            username = data.get('username')
            password = data.get('temporary_password')
            credentials = {
                'username': username,
                'password': password
            }
        
        # Create employee document
        employee_doc = {
            'name': data['employee_name'],
            'email': data['employee_email'],
            'employee_id': data['employee_id'],
            'department': data['department'],
            'position': data['position'],
            'base_salary': float(data['base_salary']),
            'hire_date': data['hire_date'],
            'phone': data.get('phone', ''),
            'manager': data.get('manager', ''),
            'username': credentials['username'],
            'password': generate_password_hash(credentials['password']),
            'role': 'employee',
            'status': 'Active',
            'first_login': False,
            'first_login_completed': False,
            'last_login': None,
            'created_at': datetime.utcnow()
        }
        
        result = mongo.db.users.insert_one(employee_doc)
        
        return jsonify({
            'success': True,
            'employee_id': str(result.inserted_id),
            'credentials': {'username': credentials['username'], 'password': credentials['password']}
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/hr/get_employees', methods=['GET'])
def get_employees():
    """Get all employees"""
    try:
        employees = list(mongo.db.users.find({"role": "employee"}))
        # Convert ObjectId to string
        for emp in employees:
            emp['_id'] = str(emp['_id'])
        
        return jsonify({'success': True, 'employees': employees})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/hr/process_payroll', methods=['POST'])
def process_payroll():
    """Process payroll for selected employees"""
    if "user" not in session or not (session["user"]["role"] in ["admin", "hr"] or session.get("hr_access", False)):
        return jsonify({"success": False, "error": "Access denied"}), 403

    try:
        data = request.json
        payroll_data = data.get('payroll_data', [])
        
        if not payroll_data:
            return jsonify({"success": False, "error": "No payroll data provided"}), 400
        
        # Insert payroll records
        for payroll in payroll_data:
            payroll['created_at'] = datetime.utcnow()
            payroll['processed_by'] = session["user"]["name"]
            payroll['processed_at'] = datetime.utcnow()
            
            # Check if exists for month and employee
            existing = mongo.db.payroll.find_one({
                "payroll_month": payroll["payroll_month"],
                "employee_id": payroll["employee_id"]
            })
            if existing:
                mongo.db.payroll.update_one({"_id": existing["_id"]}, {"$set": payroll})
            else:
                mongo.db.payroll.insert_one(payroll)
        
        return jsonify({
            'success': True,
            'message': f'Processed payroll for {len(payroll_data)} employees',
            'inserted_count': len(payroll_data)
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/hr/load_payroll_data', methods=['POST'])
def load_payroll_data():
    """Load payroll data for specified period"""
    if "user" not in session or not (session["user"]["role"] in ["admin", "hr"] or session.get("hr_access", False)):
        return jsonify({"success": False, "error": "Access denied"}), 403

    try:
        data = request.json
        period = data.get('period')
        custom_month = data.get('custom_month')
        
        # Determine the date range based on period
        if period == 'current':
            target_month = datetime.utcnow().strftime('%Y-%m')
        elif period == 'previous':
            target_month = (datetime.utcnow() + relativedelta(months=-1)).strftime('%Y-%m')
        elif period == 'custom' and custom_month:
            target_month = custom_month
        else:
            return jsonify({'success': False, 'error': 'Invalid period selection'})
        
        # Query payroll data
        payroll_data = list(mongo.db.payroll.find({'payroll_month': target_month}))
        
        # Convert ObjectId to string
        for payroll in payroll_data:
            payroll['_id'] = str(payroll['_id'])
        
        # Calculate summary
        total_monthly_payroll = sum(float(p.get('net_pay', 0)) for p in payroll_data)
        total_tax = sum(float(p.get('tax', 0)) for p in payroll_data)
        pending_count = sum(1 for p in payroll_data if p.get('status') == 'Pending')
        
        summary = {
            'total_monthly_payroll': total_monthly_payroll,
            'payroll_employees_count': len(payroll_data),
            'pending_payroll_count': pending_count,
            'total_tax_deductions': total_tax
        }
        
        return jsonify({
            'success': True,
            'payroll_data': payroll_data,
            'summary': summary
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/hr/send_payroll_to_finance', methods=['POST'])
def send_payroll_to_finance():
    """Send payroll data to Finance Department"""
    if "user" not in session or not (session["user"]["role"] in ["admin", "hr"] or session.get("hr_access", False)):
        return jsonify({"success": False, "error": "Access denied"}), 403

    try:
        data = request.json
        period = data.get('period')
        custom_month = data.get('custom_month')
        
        # Determine target month
        if period == 'current':
            target_month = datetime.utcnow().strftime('%Y-%m')
        elif period == 'previous':
            target_month = (datetime.utcnow() + relativedelta(months=-1)).strftime('%Y-%m')
        elif period == 'custom' and custom_month:
            target_month = custom_month
        else:
            return jsonify({'success': False, 'error': 'Invalid period selection'})
        
        # Get payroll data
        payroll_data = list(mongo.db.payroll.find({'payroll_month': target_month}))
        
        # Create finance notification/report
        finance_report = {
            'type': 'payroll',
            'month': target_month,
            'total_amount': sum(float(p.get('net_pay', 0)) for p in payroll_data),
            'employee_count': len(payroll_data),
            'sent_by': session["user"]["name"],
            'sent_at': datetime.utcnow(),
            'status': 'Pending Review'
        }
        
        mongo.db.finance_reports.insert_one(finance_report)
        
        # Update status
        mongo.db.payroll.update_many(
            {"payroll_month": target_month},
            {"$set": {"status": "Sent to Finance"}}
        )
        
        return jsonify({
            'success': True,
            'message': f'Payroll for {target_month} sent to Finance Department'
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/hr/send_payment_report_to_manager', methods=['POST'])
def send_payment_report_to_manager():
    """Send payment report to Manager"""
    if "user" not in session or not (session["user"]["role"] in ["admin", "hr"] or session.get("hr_access", False)):
        return jsonify({"success": False, "error": "Access denied"}), 403

    try:
        data = request.json
        period = data.get('period')
        custom_month = data.get('custom_month')
        
        # Determine target month
        if period == 'current':
            target_month = datetime.utcnow().strftime('%Y-%m')
        elif period == 'previous':
            target_month = (datetime.utcnow() + relativedelta(months=-1)).strftime('%Y-%m')
        elif period == 'custom' and custom_month:
            target_month = custom_month
        else:
            return jsonify({'success': False, 'error': 'Invalid period selection'})
        
        # Get payroll data
        payroll_data = list(mongo.db.payroll.find({'payroll_month': target_month}))
        
        # Create manager report
        manager_report = {
            'type': 'payment_summary',
            'month': target_month,
            'total_payment': sum(float(p.get('net_pay', 0)) for p in payroll_data),
            'employee_count': len(payroll_data),
            'department_breakdown': {},
            'sent_by': session["user"]["name"],
            'sent_at': datetime.utcnow()
        }
        
        # Calculate department breakdown
        dept_totals = {}
        for payroll in payroll_data:
            dept = payroll.get('department', 'Unknown')
            dept_totals[dept] = dept_totals.get(dept, 0) + float(payroll.get('net_pay', 0))
        
        manager_report['department_breakdown'] = dept_totals
        
        mongo.db.hr_reports.insert_one(manager_report)
        
        return jsonify({
            'success': True,
            'message': f'Payment report for {target_month} sent to Manager'
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/hr/leave_action/<leave_id>', methods=['POST'])
def leave_action(leave_id):
    """Approve or Reject leave request"""
    try:
        data = request.json
        action = data['action']  # 'Approved' or 'Rejected'
        
        result = mongo.db.leaves.update_one(
            {'_id': ObjectId(leave_id)},
            {
                '$set': {
                    'status': action,
                    'reviewed_by': session.get('user', {}).get('name', 'HR Admin'),
                    'reviewed_at': datetime.utcnow()
                }
            }
        )
        
        if result.modified_count > 0:
            return jsonify({'success': True, 'message': f'Leave request {action.lower()}'})
        else:
            return jsonify({'success': False, 'error': 'Leave request not found'})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/hr/claim_action/<claim_id>', methods=['POST'])
def claim_action(claim_id):
    """Approve or Reject claim request"""
    try:
        data = request.json
        action = data['action']  # 'Approved' or 'Rejected'
        
        result = mongo.db.claims.update_one(
            {'_id': ObjectId(claim_id)},
            {
                '$set': {
                    'status': action,
                    'reviewed_by': session.get('user', {}).get('name', 'HR Admin'),
                    'reviewed_at': datetime.utcnow()
                }
            }
        )
        
        if result.modified_count > 0:
            return jsonify({'success': True, 'message': f'Claim request {action.lower()}'})
        else:
            return jsonify({'success': False, 'error': 'Claim request not found'})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/hr/get_leave_requests_count', methods=['GET'])
def get_leave_requests_count():
    """Get count of pending leave requests"""
    try:
        count = mongo.db.leaves.count_documents({'status': 'Pending'})
        return jsonify({'success': True, 'count': count})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/hr/get_claims_count', methods=['GET'])
def get_claims_count():
    """Get count of pending claims"""
    try:
        count = mongo.db.claims.count_documents({'status': 'Pending'})
        return jsonify({'success': True, 'count': count})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/hr/send_credentials_email', methods=['POST'])
def send_credentials_email():
    """Send login credentials to employee via email"""
    try:
        data = request.json
        employee_name = data['employee_name']
        username = data['username']
        password = data['password']
        
        # In production, implement actual email sending
        # For now, just log and return success
        print(f"Sending credentials to {employee_name}")
        print(f"Username: {username}, Password: {password}")
        
        return jsonify({
            'success': True,
            'message': 'Credentials sent successfully via email'
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/hr/reset_password/<employee_id>', methods=['POST'])
def reset_password(employee_id):
    """Reset employee password"""
    try:
        new_password = generate_password()
        
        result = mongo.db.users.update_one(
            {'_id': ObjectId(employee_id)},
            {
                '$set': {
                    'password': generate_password_hash(new_password),
                    'password_reset_required': True,
                    'password_reset_at': datetime.utcnow()
                }
            }
        )
        
        if result.modified_count > 0:
            return jsonify({
                'success': True,
                'new_password': new_password,
                'message': 'Password reset successfully'
            })
        else:
            return jsonify({'success': False, 'error': 'Employee not found'})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/hr/resend_credentials/<employee_id>', methods=['POST'])
def resend_credentials(employee_id):
    """Resend login credentials to employee"""
    try:
        employee = mongo.db.users.find_one({'_id': ObjectId(employee_id)})
        
        if not employee:
            return jsonify({'success': False, 'error': 'Employee not found'})
        
        # In production, send actual email with credentials
        print(f"Resending credentials to {employee['name']}")
        print(f"Username: {employee.get('username', 'N/A')}")
        
        return jsonify({
            'success': True,
            'message': 'Credentials resent successfully'
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/hr/add_position', methods=['POST'])
def add_position():
    """Add new job position"""
    try:
        data = request.json
        
        position_doc = {
            'title': data['position_title'],
            'department': data.get('position_department', 'General'),
            'requirements': data['requirements'],
            'deadline': data['deadline'],
            'applicant_count': 0,
            'status': 'Open',
            'created_by': session.get('user', {}).get('name', 'HR Admin'),
            'created_at': datetime.utcnow()
        }
        
        result = mongo.db.positions.insert_one(position_doc)
        
        return jsonify({
            'success': True,
            'position_id': str(result.inserted_id),
            'message': 'Position added successfully'
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/hr/get_positions_count', methods=['GET'])
def get_positions_count():
    """Get count of open positions"""
    try:
        count = mongo.db.positions.count_documents({'status': 'Open'})
        return jsonify({'success': True, 'count': count})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/hr/set_department_budget', methods=['POST'])
def set_department_budget():
    """Set department budget"""
    try:
        data = request.json
        
        budget_doc = {
            'department': data['department'],
            'amount': float(data['amount']),
            'due_date': data['due_date'],
            'status': 'Pending Approval',
            'requested_by': session.get('user', {}).get('name', 'HR Admin'),
            'requested_at': datetime.utcnow()
        }
        
        result = mongo.db.budget_requests.insert_one(budget_doc)
        
        return jsonify({
            'success': True,
            'budget_id': str(result.inserted_id),
            'message': 'Budget request submitted successfully'
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/hr/payslip/<payroll_id>')
def view_payslip(payroll_id):
    """View payslip for specific payroll record"""
    try:
        payroll = mongo.db.payroll.find_one({'_id': ObjectId(payroll_id)})
        
        if not payroll:
            return "Payslip not found", 404
        
        # Render payslip template
        return render_template('payslip.html', payroll=payroll)
    
    except Exception as e:
        return f"Error loading payslip: {str(e)}", 500

@app.route('/hr/department_report', methods=['POST'])
def department_report():
    """View department report"""
    if "user" not in session or not (session["user"]["role"] in ["admin", "hr"] or session.get("hr_access", False)):
        flash("Access denied!", "danger")
        return redirect(url_for("hr_dashboard"))

    department = request.form.get('department')
    
    # Get all employees in department
    employees = list(mongo.db.users.find({'department': department, 'role': 'employee'}))
    
    # Get department statistics
    total_salary = sum(emp.get('base_salary', 0) for emp in employees)
    
    # Fetch reports for the selected department
    reports_cursor = mongo.db.hr_reports.find({"department": department}).sort("date", -1)
    reports = list(reports_cursor)
    
    report_data = {
        'department': department,
        'employee_count': len(employees),
        'total_salary': total_salary,
        'employees': employees
    }
    
    return render_template('department_reports.html', department=department, reports=reports, report=report_data)

# ======================
# FINANCE
# ======================

@app.route("/finance")
def finance_dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    if not (session["user"]["role"] in ["admin", "finance"] or session.get("finance_access", False)):
        flash("Access denied!", "danger")
        return redirect(url_for("dashboard"))
    
    now = datetime.utcnow()
    start_of_month = datetime(now.year, now.month, 1)
    end_of_month = start_of_month + relativedelta(months=1)

    # ----------------------------
    # ✅ Analytics (from MongoDB)
    # ----------------------------

    # Category breakdown (sum of expenses grouped by category for current month)
    category_pipeline = [
        {"$match": {
            "type": "expense",
            "date": {"$gte": start_of_month, "$lt": end_of_month}
        }},
        {"$group": {"_id": "$category", "total": {"$sum": "$amount"}}},
        {"$sort": SON([("total", -1)])}
    ]
    category_results = list(mongo.db.transactions.aggregate(category_pipeline))
    categories = [{"name": c["_id"], "total": c["total"]} for c in category_results]

    # Monthly income
    income_pipeline = [
        {"$match": {
            "type": "income",
            "date": {"$gte": start_of_month, "$lt": end_of_month}
        }},
        {"$group": {"_id": None, "total_income": {"$sum": "$amount"}}}
    ]
    income_result = list(mongo.db.transactions.aggregate(income_pipeline))
    monthly_income = income_result[0]["total_income"] if income_result else 0

    # Monthly expenses
    expense_pipeline = [
        {"$match": {
            "type": "expense",
            "date": {"$gte": start_of_month, "$lt": end_of_month}
        }},
        {"$group": {"_id": None, "total_expenses": {"$sum": "$amount"}}}
    ]
    expense_result = list(mongo.db.transactions.aggregate(expense_pipeline))
    monthly_expenses = expense_result[0]["total_expenses"] if expense_result else 0

    # Net savings
    net_savings = monthly_income - monthly_expenses

    analytics = {
        "categories": categories,
        "monthly_income": monthly_income,
        "monthly_expenses": monthly_expenses,
        "net_savings": net_savings
    }

    # ----------------------------
    # ✅ Reports
    # ----------------------------
    recent_reports = list(mongo.db.finance_reports.find().sort("date", -1).limit(5))
    reports = {
        "recent": [
            {
                "id": str(r["_id"]),
                "name": r.get("name", "N/A"),
                "date": r.get("date", datetime.utcnow())
            }
            for r in recent_reports
        ]
    }
    
    total_finance_reports = mongo.db.finance_reports.count_documents({})
    recent_finance_reports = []
    total_finance_documents = mongo.db.documents.count_documents({"department": "finance"})
    recent_finance_documents = []

    # ----------------------------
    # ✅ Bills (all departments)
    # ----------------------------
    bills = list(mongo.db.bills.find({
        "department": {"$in": ["HR", "Project Management", "Marketing", "Sales", "Operations"]},
        "due_date": {"$gte": datetime.utcnow()}
    }).sort("due_date", 1))

    formatted_bills = [
        {
            "id": str(b["_id"]),
            "name": b.get("name", "Unnamed Bill"),
            "amount": float(b.get("amount", 0)),
            "due_date": b.get("due_date", datetime.utcnow()),
            "department": b.get("department", "General")
        }
        for b in bills
    ]

    # ----------------------------
    # ✅ Budget Requests (from departments)
    # ----------------------------
    budget_requests_cursor = mongo.db.budget_requests.find().sort("submitted_at", -1)
    budget_requests = []
    for req in budget_requests_cursor:
        budget_requests.append({
            "id": str(req["_id"]),
            "department": req.get("department", "Unknown"),
            "submitted_by": req.get("submitted_by", "N/A"),
            "amount": float(req.get("amount", 0)),
            "purpose": req.get("purpose", ""),
            "status": req.get("status", "Pending"),
            "report_file": req.get("report_file")  # Optional: link to PDF report
        })

    # ----------------------------
    # ✅ User settings
    # ----------------------------
    current_user = mongo.db.users.find_one({"email": session["user"]["email"]})
    notifications = {
        "email": current_user.get("notifications", {}).get("email", False) if current_user else False,
        "sms": current_user.get("notifications", {}).get("sms", False) if current_user else False
    }

    return render_template("finance.html",
                           total_finance_reports=total_finance_reports,
                           recent_finance_reports=recent_finance_reports,
                           total_finance_documents=total_finance_documents,
                           recent_finance_documents=recent_finance_documents,
                           analytics=analytics,
                           reports=reports,
                           bills=formatted_bills,
                           budget_requests=budget_requests,
                           current_user=current_user,
                           notifications=notifications)

# ======================
# BUDGET REQUEST ACTION ROUTES
# ======================

@app.route("/finance/approve_budget/<request_id>")
def approve_budget(request_id):
    mongo.db.budget_requests.update_one(
        {"_id": ObjectId(request_id)},
        {"$set": {"status": "Approved"}}
    )
    flash("Budget request approved.", "success")
    return redirect(url_for("finance_dashboard"))

@app.route("/finance/reject_budget/<request_id>")
def reject_budget(request_id):
    mongo.db.budget_requests.update_one(
        {"_id": ObjectId(request_id)},
        {"$set": {"status": "Rejected"}}
    )
    flash("Budget request rejected.", "warning")
    return redirect(url_for("finance_dashboard"))

@app.route("/finance/view_report/<request_id>")
def view_report(request_id):
    request_data = mongo.db.budget_requests.find_one({"_id": ObjectId(request_id)})
    if not request_data or not request_data.get("report_file"):
        flash("Report not found.", "danger")
        return redirect(url_for("finance_dashboard"))

    # Assuming 'report_file' is stored as binary in MongoDB
    return send_file(
        io.BytesIO(request_data["report_file"]),
        download_name="budget_report.pdf",
        as_attachment=True,
        mimetype='application/pdf'
    )

@app.route("/finance/update-settings", methods=["POST"])
def finance_update_settings():
    if "user" not in session:
        return redirect(url_for("login"))
    if not (session["user"]["role"] in ["admin", "finance"] or session.get("finance_access", False)):
        flash("Access denied!", "danger")
        return redirect(url_for("dashboard"))
    
    # Update user settings
    name = request.form.get("name")
    email = request.form.get("email")
    
    # Update in database (adjust based on your user structure)
    mongo.db.users.update_one(
        {"email": session["user"]["email"]},
        {"$set": {"name": name, "email": email}}
    )
    
    # Update session
    session["user"]["name"] = name
    session["user"]["email"] = email
    
    flash("Settings updated successfully!", "success")
    return redirect(url_for("finance_dashboard"))


@app.route("/finance/update-notifications", methods=["POST"])
def finance_update_notifications():
    if "user" not in session:
        return redirect(url_for("login"))
    if not (session["user"]["role"] in ["admin", "finance"] or session.get("finance_access", False)):
        flash("Access denied!", "danger")
        return redirect(url_for("dashboard"))
    
    email_alerts = request.form.get("emailAlerts") == "on"
    sms_alerts = request.form.get("smsAlerts") == "on"
    
    # Update notification preferences in database
    mongo.db.users.update_one(
        {"email": session["user"]["email"]},
        {"$set": {
            "notifications.email": email_alerts,
            "notifications.sms": sms_alerts
        }}
    )
    
    flash("Notification preferences updated!", "success")
    return redirect(url_for("finance_dashboard"))


@app.route("/finance/generate-report", methods=["POST"])
def finance_generate_report():
    if "user" not in session:
        return redirect(url_for("login"))
    if not (session["user"]["role"] in ["admin", "finance"] or session.get("finance_access", False)):
        flash("Access denied!", "danger")
        return redirect(url_for("dashboard"))
    
    report_type = request.form.get("reportType")
    start_date = request.form.get("startDate")
    end_date = request.form.get("endDate")
    
    # Parse dates
    try:
        start = datetime.strptime(start_date, "%Y-%m-%d") if start_date else None
        end = datetime.strptime(end_date, "%Y-%m-%d") if end_date else None
    except ValueError:
        flash("Invalid date format!", "danger")
        return redirect(url_for("finance_dashboard"))
    
    # Create report document
    report_doc = {
        "name": f"{report_type.replace('_', ' ').title()} Report",
        "type": report_type,
        "start_date": start,
        "end_date": end,
        "date": datetime.utcnow(),
        "generated_by": session["user"]["name"],
        "status": "completed"
    }
    
    result = mongo.db.finance_reports.insert_one(report_doc)
    
    flash(f"Report generated successfully!", "success")
    return redirect(url_for("finance_dashboard"))


@app.route("/finance/download-report/<report_id>")
def finance_download_report(report_id):
    if "user" not in session:
        return redirect(url_for("login"))
    if not (session["user"]["role"] in ["admin", "finance"] or session.get("finance_access", False)):
        flash("Access denied!", "danger")
        return redirect(url_for("dashboard"))
    
    # Fetch report from database
    report = mongo.db.finance_reports.find_one({"_id": ObjectId(report_id)})
    
    if not report:
        flash("Report not found!", "danger")
        return redirect(url_for("finance_dashboard"))
    
    # Generate CSV report
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write headers
    writer.writerow(["Report Type", "Generated By", "Date", "Start Date", "End Date"])
    writer.writerow([
        report.get("type", "N/A"),
        report.get("generated_by", "N/A"),
        report.get("date", datetime.utcnow()).strftime("%Y-%m-%d %H:%M"),
        report.get("start_date", "").strftime("%Y-%m-%d") if report.get("start_date") else "N/A",
        report.get("end_date", "").strftime("%Y-%m-%d") if report.get("end_date") else "N/A"
    ])
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        download_name=f"{report.get('name', 'report')}.csv",
        as_attachment=True
    )

# ======================
# SALES
# ======================
@app.route("/sales")
def sales_dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    if not (session["user"]["role"] in ["admin", "sales"] or session.get("sales_access", False)):
        flash("Access denied!", "danger")
        return redirect(url_for("dashboard"))

    # 1. fetch data
    deals_cursor = mongo.db.deals.find()
    customers_cursor = mongo.db.customers.find()
    leads_cursor = mongo.db.leads.find()
    salespersons_cursor = mongo.db.salespersons.find()

    deals = list(deals_cursor)
    customers = list(customers_cursor)
    leads = list(leads_cursor)
    salespersons = list(salespersons_cursor)

    # Add salesperson_name to deals
    salesperson_dict = {s['_id']: s['name'] for s in salespersons}
    for deal in deals:
        deal['salesperson_name'] = salesperson_dict.get(deal.get('salesperson_id'), 'N/A')

    # 2. summary numbers
    total_revenue = sum(d.get("amount", 0) for d in deals if d.get("stage") == "closed_won")
    active_leads = len(leads)
    open_deals_val = sum(d.get("amount", 0) for d in deals if d.get("stage") not in ("closed_won", "closed_lost"))
    open_deals_cnt = len([d for d in deals if d.get("stage") not in ("closed_won", "closed_lost")])
    conversion_rate = f"{(len([d for d in deals if d.get("stage") == "closed_won"]) / max(len(deals), 1) * 100):.1f}%"

    # 3. pipeline stage counts
    stages = ["lead", "qualified", "proposal", "negotiation", "closed_won", "closed_lost"]
    stage_counts = {s: len([d for d in deals if d.get("stage") == s]) for s in stages}

    # 4. render
    return render_template(
        "sales.html",
        deals=deals,
        customers=customers,
        leads=leads,
        salespersons=salespersons,
        total_revenue=f"{total_revenue:,.0f}",
        active_leads=active_leads,
        open_deals=open_deals_cnt,
        open_deals_value=f"{open_deals_val:,.0f}",
        conversion_rate=conversion_rate,
        leads_count=stage_counts["lead"],
        qualified_count=stage_counts["qualified"],
        proposal_count=stage_counts["proposal"],
        negotiation_count=stage_counts["negotiation"],
        closed_won_count=stage_counts["closed_won"],
        closed_lost_count=stage_counts["closed_lost"]
    )

# ======================
# MARKETING
# ======================
@app.route("/marketing")
def marketing_dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    if not (session["user"]["role"] in ["admin", "marketing"] or session.get("marketing_access", False)):
        flash("Access denied!", "danger")
        return redirect(url_for("dashboard"))

    # 1. fetch data
    campaigns_cursor = mongo.db.campaigns.find()
    campaigns = list(campaigns_cursor)

    # 2. summary numbers (dummy values if collections are empty)
    total_impressions = sum(c.get("impressions", 0) for c in campaigns)
    total_reach       = sum(c.get("reach", 0) for c in campaigns)
    total_engagement  = sum(c.get("engagement", 0) for c in campaigns)
    conversion_rate   = round(
        sum(c.get("conversion_rate", 0) for c in campaigns) / max(len(campaigns), 1), 1
    )

    # 3. render
    return render_template(
        "marketing.html",
        user=session["user"],          # <-- fixes UndefinedError
        campaigns=campaigns,
        total_impressions=f"{total_impressions:,}",
        total_reach=f"{total_reach:,}",
        total_engagement=f"{total_engagement:,}",
        conversion_rate=conversion_rate
    )

# ======================
# OPERATIONS
# ======================
@app.route("/operations")
def operations_dashboard():
    user = {"name": "John Doe", "role": "Operations Manager"}  # Example user
    total_efficiency = 85
    downtime_hours = 12
    throughput = 1200
    cost_savings = 4500

    # Example data
    maintenance_alerts = [
        {"equipment_name": "Machine A", "next_maintenance": "2025-10-05", "risk_level": "high", "ai_recommendation": "Immediate inspection required."},
        {"equipment_name": "Machine B", "next_maintenance": "2025-11-10", "risk_level": "medium", "ai_recommendation": "Schedule maintenance within 2 weeks."},
    ]

    tasks = [
        {"id": 1, "name": "Inventory Audit", "due_date": "2025-09-30", "status": "active", "assigned_to": "Alice", "ai_priority": 80, "description": "Full warehouse audit."},
        {"id": 2, "name": "Update SOP", "due_date": "2025-10-05", "status": "pending", "assigned_to": "Bob", "ai_priority": 60, "description": "Revise production line SOPs."},
    ]

    return render_template(
        "operations.html",
        user=user,
        total_efficiency=total_efficiency,
        downtime_hours=downtime_hours,
        throughput=throughput,
        cost_savings=cost_savings,
        maintenance_alerts=maintenance_alerts,
        tasks=tasks
    )



# ======================
# Project Management Dashboard Route (MongoDB Integration)
# ======================

@app.route("/project_management")
def project_management_dashboard():
    """Main project management dashboard with MongoDB data"""
    if "user" not in session:
        return redirect(url_for("login"))
    if not (session["user"]["role"] in ["admin", "project"] or session.get("projects_access", False)):
        flash("Access denied!", "danger")
        return redirect(url_for("dashboard"))
    
    # This renders the HTML file you created
    return render_template("project_management.html")


# ======================
# Project Management API Endpoints
# ======================

@app.route("/api/projects/all", methods=["GET"])
def get_all_projects():
    """Get all projects from MongoDB"""
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        projects_cursor = mongo.db.pm_projects.find().sort("created_at", -1)
        projects = []
        
        for p in projects_cursor:
            projects.append({
                "id": str(p["_id"]),
                "name": p.get("name", ""),
                "client": p.get("client", ""),
                "description": p.get("description", ""),
                "startDate": p.get("startDate", ""),
                "endDate": p.get("endDate", ""),
                "budget": float(p.get("budget", 0)),
                "spent": float(p.get("spent", 0)),
                "status": p.get("status", "active"),
                "priority": p.get("priority", "medium"),
                "manager": p.get("manager", ""),
                "progress": int(p.get("progress", 0)),
                "department": p.get("department", "Project Management")
            })
        
        return jsonify({"success": True, "projects": projects})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/projects/create", methods=["POST"])
def create_project():
    """Create a new project in MongoDB"""
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        data = request.get_json()
        
        project_doc = {
            "name": data.get("name"),
            "client": data.get("client"),
            "description": data.get("description"),
            "startDate": data.get("startDate"),
            "endDate": data.get("endDate"),
            "budget": float(data.get("budget", 0)),
            "spent": float(data.get("spent", 0)),
            "status": data.get("status", "active"),
            "priority": data.get("priority", "medium"),
            "manager": data.get("manager"),
            "progress": int(data.get("progress", 0)),
            "department": data.get("department", "Project Management"),
            "created_at": datetime.utcnow(),
            "created_by": session["user"]["name"]
        }
        
        result = mongo.db.pm_projects.insert_one(project_doc)
        
        return jsonify({
            "success": True, 
            "message": "Project created successfully",
            "id": str(result.inserted_id)
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/projects/tasks/all", methods=["GET"])
def get_all_tasks():
    """Get all tasks from MongoDB"""
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        tasks_cursor = mongo.db.pm_tasks.find().sort("created_at", -1)
        tasks = []
        
        for t in tasks_cursor:
            tasks.append({
                "id": str(t["_id"]),
                "name": t.get("name", ""),
                "projectId": str(t.get("projectId", "")),
                "project": t.get("project", ""),
                "description": t.get("description", ""),
                "assignedTo": t.get("assignedTo", ""),
                "priority": t.get("priority", "medium"),
                "dueDate": t.get("dueDate", ""),
                "status": t.get("status", "pending")
            })
        
        return jsonify({"success": True, "tasks": tasks})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/projects/tasks/create", methods=["POST"])
def create_task():
    """Create a new task in MongoDB"""
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        data = request.get_json()
        
        task_doc = {
            "name": data.get("name"),
            "projectId": data.get("projectId"),
            "project": data.get("project"),
            "description": data.get("description", ""),
            "assignedTo": data.get("assignedTo"),
            "priority": data.get("priority", "medium"),
            "dueDate": data.get("dueDate"),
            "status": data.get("status", "pending"),
            "created_at": datetime.utcnow(),
            "created_by": session["user"]["name"]
        }
        
        result = mongo.db.pm_tasks.insert_one(task_doc)
        
        return jsonify({
            "success": True, 
            "message": "Task created successfully",
            "id": str(result.inserted_id)
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/projects/team/all", methods=["GET"])
def get_team_members():
    """Get all team members from MongoDB"""
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        team_cursor = mongo.db.pm_team_members.find().sort("created_at", -1)
        team = []
        
        for m in team_cursor:
            team.append({
                "id": str(m["_id"]),
                "name": m.get("name", ""),
                "email": m.get("email", ""),
                "role": m.get("role", ""),
                "department": m.get("department", ""),
                "phone": m.get("phone", "")
            })
        
        return jsonify({"success": True, "team_members": team})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/projects/team/create", methods=["POST"])
def create_team_member():
    """Create a new team member in MongoDB"""
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        data = request.get_json()
        
        member_doc = {
            "name": data.get("name"),
            "email": data.get("email"),
            "role": data.get("role"),
            "department": data.get("department"),
            "phone": data.get("phone", ""),
            "created_at": datetime.utcnow(),
            "created_by": session["user"]["name"]
        }
        
        result = mongo.db.pm_team_members.insert_one(member_doc)
        
        return jsonify({
            "success": True, 
            "message": "Team member added successfully",
            "id": str(result.inserted_id)
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/projects/send-to-finance", methods=["POST"])
def send_projects_to_finance():
    """Send project budget data to finance department"""
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        data = request.get_json()
        projects_data = data.get("projects", [])
        summary = data.get("summary", {})
        
        # Create bills for each project in finance department
        bills_created = []
        
        for project in projects_data:
            bill_doc = {
                "name": f"{project['name']} - Project Budget",
                "department": project.get("department", "Project Management"),
                "due_date": datetime.strptime(project["end_date"], "%Y-%m-%d") if project.get("end_date") else datetime.utcnow(),
                "amount": float(project.get("remaining", 0)),
                "status": project.get("status", "pending"),
                "project_id": project.get("id"),
                "client": project.get("client", ""),
                "manager": project.get("manager", ""),
                "created_at": datetime.utcnow(),
                "created_by": session["user"]["name"],
                "source": "Project Management"
            }
            
            result = mongo.db.bills.insert_one(bill_doc)
            bills_created.append(str(result.inserted_id))
        
        # Create a finance submission record
        submission_doc = {
            "source": "Project Management",
            "timestamp": datetime.utcnow(),
            "submitted_by": session["user"]["name"],
            "summary": summary,
            "projects": projects_data,
            "bills_created": bills_created,
            "status": "submitted"
        }
        
        mongo.db.finance_submissions.insert_one(submission_doc)
        
        return jsonify({
            "success": True, 
            "message": "Budget data sent to finance department successfully",
            "bills_created": len(bills_created)
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/projects/delete/<project_id>", methods=["DELETE"])
def delete_project(project_id):
    """Delete a project from MongoDB"""
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        result = mongo.db.pm_projects.delete_one({"_id": ObjectId(project_id)})
        
        if result.deleted_count > 0:
            return jsonify({"success": True, "message": "Project deleted successfully"})
        else:
            return jsonify({"success": False, "error": "Project not found"}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/projects/tasks/delete/<task_id>", methods=["DELETE"])
def delete_task(task_id):
    """Delete a task from MongoDB"""
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        result = mongo.db.pm_tasks.delete_one({"_id": ObjectId(task_id)})
        
        if result.deleted_count > 0:
            return jsonify({"success": True, "message": "Task deleted successfully"})
        else:
            return jsonify({"success": False, "error": "Task not found"}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ============================
# Employee Dashboard (updated)
# ============================

class CSRFOnlyForm(FlaskForm):
    pass

@app.route("/employee/dashboard/<employee_id>")
def employee_dashboard(employee_id):
    if "user" not in session or session["user"]["role"] != "employee":
        flash("Access denied!", "danger")
        return redirect(url_for("login"))
    
    # Fake/mock data (replace with MongoDB fetch later)
    employee = {
        "id": employee_id,
        "name": "John Doe",
        "is_logged_in": True,
        "login_time": "08:30 AM",
        "today_hours": 5,
        "notifications": [
            {"date": "2025-09-16", "type": "Leave", "message": "Your leave was approved."},
            {"date": "2025-09-15", "type": "Claim", "message": "Reimbursement processed."}
        ],
        "feedback": [
            {"date": "2025-09-14", "comment": "Great performance on Project X"},
            {"date": "2025-09-10", "comment": "Improve time reporting accuracy"}
        ],
        "tasks": [
            {"id": 1, "title": "Prepare sales report", "status": "In Progress", "progress": 60},
            {"id": 2, "title": "Update CRM data", "status": "Pending", "progress": 0}
        ],
        "timesheets": [
            {"date": "2025-09-16", "hours": 8, "note": "Normal workday"},
            {"date": "2025-09-15", "hours": 6, "note": "Half day"}
        ],
        "leaves": [
            {"from": "2025-09-20", "to": "2025-09-22", "reason": "Family Event", "status": "Approved"}
        ],
        "expenses": [
            {"date": "2025-09-12", "amount": "50", "description": "Client meeting lunch"}
        ]
    }
    
    # Map employee data to user object for template
    user = {
        "name": employee["name"],
        "role": "employee",
        "pending_tasks_count": len([task for task in employee["tasks"] if task["status"] == "Pending"]),
        "hours_logged_today": employee["today_hours"],
        "pending_leaves_count": len([leave for leave in employee["leaves"] if leave["status"] == "Pending"])
    }
    
    # Combine notifications and feedback into recent_activities
    recent_activities = []
    for notification in employee["notifications"]:
        recent_activities.append({
            "description": f"{notification['type']}: {notification['message']}",
            "timestamp": datetime.strptime(notification["date"], "%Y-%m-%d")
        })
    for feedback in employee["feedback"]:
        recent_activities.append({
            "description": f"Feedback: {feedback['comment']}",
            "timestamp": datetime.strptime(feedback["date"], "%Y-%m-%d")
        })
    
    # Sort activities by timestamp (most recent first)
    recent_activities.sort(key=lambda x: x["timestamp"], reverse=True)
    
    # Initialize form for CSRF protection
    form = CSRFOnlyForm()
    
    return render_template(
        "dashboard_employee.html", 
        user=user, 
        recent_activities=recent_activities, 
        form=form
    )

@app.template_filter('formatdate')
def format_date(value, format='%m/%d/%Y'):
    if value is None:
        return ""
    return value.strftime(format)

# ======================
# Department Signups and Logins
# ======================

# HR Signup
@app.route("/hr_signup", methods=["POST"])
def hr_signup():
    department = "hr"
    if mongo.db.department_users.count_documents({"department": department}) >= 2:
        flash("Maximum accounts reached for HR department.", "danger")
        return redirect(url_for("dashboard"))
    
    username = request.form.get("username")
    password = request.form.get("password")
    confirm_password = request.form.get("confirm_password")
    
    if not username or not password or not confirm_password:
        flash("All fields are required!", "danger")
        return redirect(url_for("dashboard"))
    
    if password != confirm_password:
        flash("Passwords do not match!", "danger")
        return redirect(url_for("dashboard"))
    
    if mongo.db.department_users.find_one({"username": username}):
        flash("Username already exists!", "danger")
        return redirect(url_for("dashboard"))
    
    hashed_password = generate_password_hash(password)
    mongo.db.department_users.insert_one({
        "department": department,
        "username": username,
        "password": hashed_password,
        "created_at": datetime.utcnow()
    })
    flash("Account created successfully. Please log in.", "success")
    # Redirect to dashboard with parameters to open login modal/tab
    return redirect(url_for("dashboard") + "?open_modal=hrModal&active_tab=hr-login-tab")

# HR Login
@app.route("/hr_login", methods=["POST"])
def hr_login():
    department = "hr"
    username = request.form.get("username")
    password = request.form.get("password")
    
    user = mongo.db.department_users.find_one({"department": department, "username": username})
    if user and check_password_hash(user["password"], password):
        session["hr_access"] = True
        flash("Login successful!", "success")
        return redirect(url_for("hr_dashboard"))
    else:
        flash("Invalid username or password!", "danger")
        return redirect(url_for("dashboard") + "?open_modal=hrModal&active_tab=hr-login-tab")

# Finance Signup
@app.route("/finance_signup", methods=["POST"])
def finance_signup():
    department = "finance"
    if mongo.db.department_users.count_documents({"department": department}) >= 2:
        flash("Maximum accounts reached for Finance department.", "danger")
        return redirect(url_for("dashboard"))
    
    username = request.form.get("username")
    password = request.form.get("password")
    confirm_password = request.form.get("confirm_password")
    
    if not username or not password or not confirm_password:
        flash("All fields are required!", "danger")
        return redirect(url_for("dashboard"))
    
    if password != confirm_password:
        flash("Passwords do not match!", "danger")
        return redirect(url_for("dashboard"))
    
    if mongo.db.department_users.find_one({"username": username}):
        flash("Username already exists!", "danger")
        return redirect(url_for("dashboard"))
    
    hashed_password = generate_password_hash(password)
    mongo.db.department_users.insert_one({
        "department": department,
        "username": username,
        "password": hashed_password,
        "created_at": datetime.utcnow()
    })
    flash("Account created successfully. Please log in.", "success")
    return redirect(url_for("dashboard") + "?open_modal=financeModal&active_tab=finance-login-tab")

# Finance Login
@app.route("/finance_login", methods=["POST"])
def finance_login():
    department = "finance"
    username = request.form.get("username")
    password = request.form.get("password")
    
    user = mongo.db.department_users.find_one({"department": department, "username": username})
    if user and check_password_hash(user["password"], password):
        session["finance_access"] = True
        flash("Login successful!", "success")
        return redirect(url_for("finance_dashboard"))
    else:
        flash("Invalid username or password!", "danger")
        return redirect(url_for("dashboard") + "?open_modal=financeModal&active_tab=finance-login-tab")

# Projects Signup
@app.route("/projects_signup", methods=["POST"])
def projects_signup():
    department = "projects"
    if mongo.db.department_users.count_documents({"department": department}) >= 2:
        flash("Maximum accounts reached for Projects department.", "danger")
        return redirect(url_for("dashboard"))
    
    username = request.form.get("username")
    password = request.form.get("password")
    confirm_password = request.form.get("confirm_password")
    
    if not username or not password or not confirm_password:
        flash("All fields are required!", "danger")
        return redirect(url_for("dashboard"))
    
    if password != confirm_password:
        flash("Passwords do not match!", "danger")
        return redirect(url_for("dashboard"))
    
    if mongo.db.department_users.find_one({"username": username}):
        flash("Username already exists!", "danger")
        return redirect(url_for("dashboard"))
    
    hashed_password = generate_password_hash(password)
    mongo.db.department_users.insert_one({
        "department": department,
        "username": username,
        "password": hashed_password,
        "created_at": datetime.utcnow()
    })
    flash("Account created successfully. Please log in.", "success")
    return redirect(url_for("dashboard") + "?open_modal=projectsModal&active_tab=projects-login-tab")

# Projects Login
@app.route("/projects_login", methods=["POST"])
def projects_login():
    department = "projects"
    username = request.form.get("username")
    password = request.form.get("password")
    
    user = mongo.db.department_users.find_one({"department": department, "username": username})
    if user and check_password_hash(user["password"], password):
        session["projects_access"] = True
        flash("Login successful!", "success")
        return redirect(url_for("project_management_dashboard"))
    else:
        flash("Invalid username or password!", "danger")
        return redirect(url_for("dashboard") + "?open_modal=projectsModal&active_tab=projects-login-tab")

# Sales Signup
@app.route("/sales_signup", methods=["POST"])
def sales_signup():
    department = "sales"
    if mongo.db.department_users.count_documents({"department": department}) >= 2:
        flash("Maximum accounts reached for Sales department.", "danger")
        return redirect(url_for("dashboard"))
    
    username = request.form.get("username")
    password = request.form.get("password")
    confirm_password = request.form.get("confirm_password")
    
    if not username or not password or not confirm_password:
        flash("All fields are required!", "danger")
        return redirect(url_for("dashboard"))
    
    if password != confirm_password:
        flash("Passwords do not match!", "danger")
        return redirect(url_for("dashboard"))
    
    if mongo.db.department_users.find_one({"username": username}):
        flash("Username already exists!", "danger")
        return redirect(url_for("dashboard"))
    
    hashed_password = generate_password_hash(password)
    mongo.db.department_users.insert_one({
        "department": department,
        "username": username,
        "password": hashed_password,
        "created_at": datetime.utcnow()
    })
    flash("Account created successfully. Please log in.", "success")
    return redirect(url_for("dashboard") + "?open_modal=salesModal&active_tab=sales-login-tab")

# Sales Login
@app.route("/sales_login", methods=["POST"])
def sales_login():
    department = "sales"
    username = request.form.get("username")
    password = request.form.get("password")
    
    user = mongo.db.department_users.find_one({"department": department, "username": username})
    if user and check_password_hash(user["password"], password):
        session["sales_access"] = True
        flash("Login successful!", "success")
        return redirect(url_for("sales_dashboard"))
    else:
        flash("Invalid username or password!", "danger")
        return redirect(url_for("dashboard") + "?open_modal=salesModal&active_tab=sales-login-tab")

# Marketing Signup
@app.route("/marketing_signup", methods=["POST"])
def marketing_signup():
    department = "marketing"
    if mongo.db.department_users.count_documents({"department": department}) >= 2:
        flash("Maximum accounts reached for Marketing department.", "danger")
        return redirect(url_for("dashboard"))
    
    username = request.form.get("username")
    password = request.form.get("password")
    confirm_password = request.form.get("confirm_password")
    
    if not username or not password or not confirm_password:
        flash("All fields are required!", "danger")
        return redirect(url_for("dashboard"))
    
    if password != confirm_password:
        flash("Passwords do not match!", "danger")
        return redirect(url_for("dashboard"))
    
    if mongo.db.department_users.find_one({"username": username}):
        flash("Username already exists!", "danger")
        return redirect(url_for("dashboard"))
    
    hashed_password = generate_password_hash(password)
    mongo.db.department_users.insert_one({
        "department": department,
        "username": username,
        "password": hashed_password,
        "created_at": datetime.utcnow()
    })
    flash("Account created successfully. Please log in.", "success")
    return redirect(url_for("dashboard") + "?open_modal=marketingModal&active_tab=marketing-login-tab")

# Marketing Login
@app.route("/marketing_login", methods=["POST"])
def marketing_login():
    department = "marketing"
    username = request.form.get("username")
    password = request.form.get("password")
    
    user = mongo.db.department_users.find_one({"department": department, "username": username})
    if user and check_password_hash(user["password"], password):
        session["marketing_access"] = True
        flash("Login successful!", "success")
        return redirect(url_for("marketing_dashboard"))
    else:
        flash("Invalid username or password!", "danger")
        return redirect(url_for("dashboard") + "?open_modal=marketingModal&active_tab=marketing-login-tab")

# Operations Signup
@app.route("/operations_signup", methods=["POST"])
def operations_signup():
    department = "operations"
    if mongo.db.department_users.count_documents({"department": department}) >= 2:
        flash("Maximum accounts reached for Operations department.", "danger")
        return redirect(url_for("dashboard"))
    
    username = request.form.get("username")
    password = request.form.get("password")
    confirm_password = request.form.get("confirm_password")
    
    if not username or not password or not confirm_password:
        flash("All fields are required!", "danger")
        return redirect(url_for("dashboard"))
    
    if password != confirm_password:
        flash("Passwords do not match!", "danger")
        return redirect(url_for("dashboard"))
    
    if mongo.db.department_users.find_one({"username": username}):
        flash("Username already exists!", "danger")
        return redirect(url_for("dashboard"))
    
    hashed_password = generate_password_hash(password)
    mongo.db.department_users.insert_one({
        "department": department,
        "username": username,
        "password": hashed_password,
        "created_at": datetime.utcnow()
    })
    flash("Account created successfully. Please log in.", "success")
    return redirect(url_for("dashboard") + "?open_modal=operationsModal&active_tab=operations-login-tab")

# Operations Login
@app.route("/operations_login", methods=["POST"])
def operations_login():
    department = "operations"
    username = request.form.get("username")
    password = request.form.get("password")
    
    user = mongo.db.department_users.find_one({"department": department, "username": username})
    if user and check_password_hash(user["password"], password):
        session["operations_access"] = True
        flash("Login successful!", "success")
        return redirect(url_for("operations_dashboard"))
    else:
        flash("Invalid username or password!", "danger")
        return redirect(url_for("dashboard") + "?open_modal=operationsModal&active_tab=operations-login-tab")

# ======================
# Sales APIs
# ======================

# List of predefined sales tips
SALES_TIPS = [
    "Follow up with leads within 24 hours to increase conversion by 300%.",
    "Personalize your pitch based on the customer's pain points.",
    "Use social proof in your proposals to build trust.",
    "Ask open-ended questions to uncover needs.",
    "Offer a limited-time discount to create urgency."
]

@app.route("/api/ai_tip", methods=["GET"])
def ai_tip():
    # For simplicity, return a random tip. To make it AI-generated, you can call xAI API here.
    tip = choice(SALES_TIPS)
    return jsonify({"tip": tip})

@app.route("/api/ask_ai", methods=["POST"])
def ask_ai():
    if "user" not in session or not (session["user"]["role"] in ["admin", "sales"] or session.get("sales_access", False)):
        return jsonify({"response": "Access denied"}), 403

    data = request.get_json()
    query = data.get("query")

    if not query:
        return jsonify({"response": "No query provided"}), 400

    # To integrate with xAI Grok API for intelligent responses
    # Assume XAI_API_KEY is set in environment variables
    api_key = os.getenv("XAI_API_KEY")
    if not api_key:
        # Fallback to simulated response if no API key
        if "close" in query.lower():
            response = "To close a deal: Summarize value, address objections, ask for the sale directly."
        elif "lead" in query.lower():
            response = "For lead generation: Focus on content marketing and LinkedIn outreach."
        else:
            response = "Great question! Remember to always listen more than you talk in sales calls."
        return jsonify({"response": response, "reload": False})

    # System prompt to make Grok detect actions and return structured output
    system_prompt = """
You are a sales AI assistant. If the user's query is a request to add a deal, customer, or lead, respond with JSON in this format:
{"action": "add_deal", "data": {"name": "...", "customer_id": "...", "amount": ..., "stage": "...", "expected_close": "..."}}
or {"action": "add_customer", "data": {"name": "...", "email": "...", "phone": "..."}}
or {"action": "add_lead", "data": {"name": "...", "source": "...", "interest_level": "..."}}
If it's not an add action, respond with {"response": "your text response"}
Parse the query naturally to extract the data.
"""

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "grok-beta",  # Adjust model name as per xAI API docs
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": query}
        ]
    }

    try:
        api_response = requests.post("https://api.x.ai/v1/chat/completions", headers=headers, json=payload)
        api_response.raise_for_status()
        ai_output = api_response.json()["choices"][0]["message"]["content"]

        # Parse AI output (assuming it's JSON)
        import json
        parsed = json.loads(ai_output)

        reload_needed = False
        if "action" in parsed:
            action = parsed["action"]
            data = parsed["data"]
            data["created_at"] = datetime.utcnow()

            if action == "add_deal":
                # Find customer name for display
                customer = mongo.db.customers.find_one({"_id": ObjectId(data["customer_id"])})
                data["customer_name"] = customer["name"] if customer else "Unknown"
                mongo.db.deals.insert_one(data)
                response = "Deal added successfully!"
                reload_needed = True
            elif action == "add_customer":
                mongo.db.customers.insert_one(data)
                response = "Customer added successfully!"
                reload_needed = True
            elif action == "add_lead":
                mongo.db.leads.insert_one(data)
                response = "Lead added successfully!"
                reload_needed = True
            else:
                response = "Unknown action."
        else:
            response = parsed.get("response", "Sorry, I didn't understand.")

        return jsonify({"response": response, "reload": reload_needed})

    except Exception as e:
        # Fallback on error
        return jsonify({"response": f"Error: {str(e)}", "reload": False}), 500

@app.route("/api/deals", methods=["POST"])
def add_deal():
    if "user" not in session or not (session["user"]["role"] in ["admin", "sales"] or session.get("sales_access", False)):
        return jsonify({"message": "Access denied"}), 403

    data = request.get_json()
    # Validate required fields
    required = ["name", "customer_id", "amount", "stage"]
    if not all(k in data for k in required):
        return jsonify({"message": "Missing required fields"}), 400

    # Convert amount to float
    try:
        data["amount"] = float(data["amount"])
    except ValueError:
        return jsonify({"message": "Invalid amount"}), 400

    # Optional expected_close
    if "expected_close" in data and data["expected_close"]:
        try:
            data["expected_close"] = datetime.strptime(data["expected_close"], "%Y-%m-%d")
        except ValueError:
            return jsonify({"message": "Invalid date format"}), 400

    # Find customer name
    customer = mongo.db.customers.find_one({"_id": ObjectId(data["customer_id"])})
    data["customer_name"] = customer["name"] if customer else "Unknown"

    data["created_at"] = datetime.utcnow()
    inserted = mongo.db.deals.insert_one(data)
    return jsonify({"message": "Deal added", "id": str(inserted.inserted_id)}), 201

@app.route("/api/customers", methods=["POST"])
def add_customer():
    if "user" not in session or not (session["user"]["role"] in ["admin", "sales"] or session.get("sales_access", False)):
        return jsonify({"message": "Access denied"}), 403

    data = request.get_json()
    # Validate required fields
    required = ["name", "email"]
    if not all(k in data for k in required):
        return jsonify({"message": "Missing required fields"}), 400

    data["created_at"] = datetime.utcnow()
    inserted = mongo.db.customers.insert_one(data)
    return jsonify({"message": "Customer added", "id": str(inserted.inserted_id)}), 201

@app.route("/api/leads", methods=["POST"])
def add_lead():
    if "user" not in session or not (session["user"]["role"] in ["admin", "sales"] or session.get("sales_access", False)):
        return jsonify({"message": "Access denied"}), 403

    data = request.get_json()
    # Validate required fields
    required = ["name", "source", "interest_level"]
    if not all(k in data for k in required):
        return jsonify({"message": "Missing required fields"}), 400

    data["created_at"] = datetime.utcnow()
    inserted = mongo.db.leads.insert_one(data)
    return jsonify({"message": "Lead added", "id": str(inserted.inserted_id)}), 201

# ======================
# Additional Routes
# ======================

@app.route("/milestones.html")
def milestones():
    # Fetch milestones from DB (exclude _id for clean JSON)
    milestones = list(mongo.db.milestones.find({}, {"_id": 0}))

    # Calculate current stats from orders
    total_orders = mongo.db.orders.count_documents({})
    total_revenue = sum(o.get("total", 0) for o in mongo.db.orders.find({}, {"total": 1, "_id": 0}))

    # Update progress and achievement status dynamically
    for m in milestones:
        target = m.get("target_value", 0)
        achieved = 0

        if m.get("metric") == "orders":
            achieved = total_orders
        elif m.get("metric") == "revenue":
            achieved = total_revenue
        else:
            achieved = m.get("achieved_value", 0)  # fallback

        # Calculate progress
        progress = min(achieved, target)
        progress_percent = round((progress / target) * 100) if target > 0 else 0

        # Update milestone fields
        m["achieved_value"] = achieved
        m["progress_percent"] = progress_percent

        # Auto-mark as completed if target met
        if achieved >= target and not m.get("achieved_at"):
            m["achieved_at"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
            m["status"] = "completed"
            # Optional: persist to DB
            mongo.db.milestones.update_one(
                {"name": m["name"]},
                {"$set": {"achieved_at": datetime.utcnow(), "status": "completed"}}
            )
        elif m.get("status") != "completed":
            # Auto-detect "at risk" if due date is near (<7 days) and not completed
            due_date = m.get("due_date")
            if due_date and isinstance(due_date, str):
                due_date = datetime.fromisoformat(due_date.replace("Z", "+00:00"))
            if due_date and datetime.utcnow() > due_date - timedelta(days=7) and achieved < target:
                m["status"] = "at_risk"
            else:
                m["status"] = "in_progress"

    return render_template("milestones.html", milestones=milestones)


@app.route("/orders.html")
def orders():
    # Fetch deals from MongoDB, sort by newest
    deals_cursor = mongo.db.deals.find().sort("created_at", -1)
    orders = []

    for d in deals_cursor:
        # Map deal stage → order status
        stage = d.get("stage", "")
        if stage == "closed_won":
            status = "Completed"
        elif stage == "closed_lost":
            continue  # Skip lost deals
        else:
            status = "Pending"

        # Format date
        date_str = d.get("created_at")
        if isinstance(date_str, datetime):
            date_str = date_str.strftime("%b %d, %Y")  # e.g., Oct 31, 2025
        else:
            date_str = "N/A"

        # Build order item
        orders.append({
            "id": str(d["_id"]),
            "customer_name": d.get("customer_name", "Unknown Customer"),
            "date": date_str,
            "status": status,
            "total": d.get("amount", 0),
            "product_name": d.get("product_name", "Service/Product"),
            "quantity": d.get("quantity", 1),
            "image": d.get("image_url", "https://via.placeholder.com/80")
        })

    # Calculate totals
    totals = {
        "total": len(orders),
        "pending": sum(1 for o in orders if o["status"] == "Pending"),
        "completed": sum(1 for o in orders if o["status"] == "Completed")
    }

    return render_template("orders.html", totals=totals, orders=orders)

# ------------------------------------------------------------------
#  Inventory  (matches the new inventory.html 1-to-1)
# ------------------------------------------------------------------
@app.route("/inventory.html")
def inventory():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("inventory.html",user=session["user"])


# ----------  API : CRUD + stats  ----------
@app.route("/api/inventory/stats")
def inventory_stats():
    pipeline=[
        {"$group":{
            "_id":"$category",
            "count":{"$sum":1},
            "totalQty":{"$sum":"$quantity"},
            "value":{"$sum":{"$multiply":["$quantity","$price"]}}
        }},
        {"$sort":{"_id":1}}
    ]
    by_cat=list(mongo.db.inventory.aggregate(pipeline))
    total_items   = mongo.db.inventory.count_documents({})
    low_stock     = mongo.db.inventory.count_documents({"$expr":{"$lt":["$quantity","$alert_level"]}})
    total_value   = sum(c["value"] for c in by_cat)

    return jsonify({
        "total_items": total_items,
        "low_stock": low_stock,
        "total_value": total_value,
        "categories": {c["_id"]:c["totalQty"] for c in by_cat}
    })


@app.route("/api/inventory",methods=["GET"])
def list_items():
    page  = int(request.args.get("page",1))
    limit = int(request.args.get("limit",10))
    query = request.args.get("q","")
    sort  = request.args.get("sort","name")
    order = request.args.get("order","asc")

    skip=(page-1)*limit
    filt={"$or":[
        {"name":{"$regex":query,"$options":"i"}},
        {"sku":{"$regex":query,"$options":"i"}},
        {"category":{"$regex":query,"$options":"i"}}
    ]} if query else {}

    cursor=mongo.db.inventory.find(filt).sort(sort,1 if order=="asc" else -1).skip(skip).limit(limit)
    items=[{**item,"_id":str(item["_id"])} for item in cursor]
    total=mongo.db.inventory.count_documents(filt)

    return jsonify({"items":items,"total":total})


@app.route("/api/inventory",methods=["POST"])
def create_item():
    data=request.get_json()
    # basic validation
    required=["name","sku","quantity","price","category","supplier","alert_level"]
    for f in required:
        if f not in data: return jsonify({"error":f"{f} required"}),400
    data["quantity"]  =int(data["quantity"])
    data["price"]     =float(data["price"])
    data["alert_level"]=int(data["alert_level"])
    data["last_updated"]=datetime.utcnow()

    inserted=mongo.db.inventory.insert_one(data)
    return jsonify({"message":"Item created","id":str(inserted.inserted_id)}),201


@app.route("/api/inventory/<item_id>",methods=["GET"])
def get_item(item_id):
    item=mongo.db.inventory.find_one({"_id":ObjectId(item_id)})
    if not item: return jsonify({"error":"Not found"}),404
    item["_id"]=str(item["_id"])
    return jsonify(item)


@app.route("/api/inventory/<item_id>",methods=["PUT"])
def update_item(item_id):
    data=request.get_json()
    data["last_updated"]=datetime.utcnow()
    res=mongo.db.inventory.update_one({"_id":ObjectId(item_id)},{"$set":data})
    if res.matched_count==0: return jsonify({"error":"Not found"}),404
    return jsonify({"message":"Item updated"})


@app.route("/api/inventory/<item_id>",methods=["DELETE"])
def delete_item(item_id):
    res=mongo.db.inventory.delete_one({"_id":ObjectId(item_id)})
    if res.deleted_count==0: return jsonify({"error":"Not found"}),404
    return jsonify({"message":"Item deleted"})

@app.route("/shipments.html")
def shipments():
    return render_template("shipments.html")
    

@app.route("/supplies.html")
def supplies():
    return render_template("supplies.html")

@app.route("/products.html")
def products():
    return render_template("products.html")

@app.route("/sales-center.html")
def sales_center():
    totals = {
        "total": mongo.db.sales.count_documents({}),
        "monthly": mongo.db.sales.count_documents({"date": {"$regex": "^2025-09"}}),
        "top_product": "Coming Soon"
    }
    sales = list(mongo.db.sales.find({}, {"_id": 0}).sort("date", -1).limit(100))
    return render_template("sales-center.html", totals=totals, sales=sales)

@app.route("/libraries.html")
def libraries():
    return render_template("libraries.html")

@app.route("/samples.html")
def samples():
    return render_template("samples.html")

@app.route("/order_home")
def order_home():
    return redirect(url_for("home"))

@app.route("/order_products")
def order_products():
    return render_template("products.html")

@app.route("/order_orders")
def order_orders():
    return redirect(url_for("orders"))

@app.route("/order_customers")
def order_customers():
    customers = list(mongo.db.customers.find())
    return render_template("customers.html", customers=customers)

@app.route("/order_analytics")
def order_analytics():
    return "Analytics page coming soon"

@app.route("/order_promotions")
def order_promotions():
    return "Promotions page coming soon"

@app.route("/order_settings")
def order_settings():
    return "Settings page coming soon"

@app.route("/order_new")
def order_new():
    return "New order form coming soon"

@app.route("/order_detail/<id>")
def order_detail(id):
    deal = mongo.db.deals.find_one({"_id": ObjectId(id)})
    if deal:
        return render_template("order_detail.html", order=deal)
    else:
        flash("Order not found", "danger")
        return redirect(url_for("orders"))

@app.route("/<department>/set-budget", methods=["POST"])
def set_dept_budget(department):
    if "user" not in session:
        return redirect(url_for("login"))
    if not (session["user"]["role"] in ["admin", "hr", "sales", "marketing", "operations", "project_management"]):
        flash("Access denied!", "danger")
        return redirect(url_for("dashboard"))

    amount = float(request.form.get("amount"))
    due_date = request.form.get("due_date")

    # Check if this department already has a budget set → update it instead of creating duplicates
    existing = mongo.db.bills.find_one({"department": department})

    if existing:
        mongo.db.bills.update_one(
            {"_id": existing["_id"]},
            {"$set": {
                "amount": amount,
                "due_date": datetime.strptime(due_date, "%Y-%m-%d"),
                "updated_at": datetime.utcnow()
            }}
        )
        flash(f"{department} budget updated successfully!", "success")
    else:
        mongo.db.bills.insert_one({
            "name": f"{department} Department Budget",
            "amount": amount,
            "department": department,
            "due_date": datetime.strptime(due_date, "%Y-%m-%d"),
            "created_at": datetime.utcnow()
        })
        flash(f"{department} budget set successfully!", "success")

    # Redirect back to that department's dashboard
    return redirect(url_for(f"{department.lower().replace(' ', '_')}_dashboard"))

# ======================
# Serve uploaded files
# ======================
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ======================
# Send Report Route
# ======================
@app.route("/send_report", methods=["POST"])
def send_report():
    if "user" not in session:
        return redirect(url_for("login"))
    
    if session["user"]["role"] != "admin":
        flash("Access denied!", "danger")
        return redirect(url_for("dashboard"))
    
    report_type = request.form.get("report_type")
    
    # Here you can integrate with your email system
    # For now, we'll just simulate success
    
    flash(f"{report_type.upper()} report sent successfully to manager!", "success")
    return redirect(url_for("dashboard"))

# ======================
# Generic Reports Routes (add these if they don't exist)
# ======================
@app.route("/reports/<department>")
def department_reports_view(department):
    if "user" not in session:
        return redirect(url_for("login"))
    
    if session["user"]["role"] != "admin":
        flash("Access denied!", "danger")
        return redirect(url_for("dashboard"))
    
    # Generate report based on department
    if department == "hr":
        return redirect(url_for("hr_dashboard"))
    elif department == "finance":
        return redirect(url_for("finance_dashboard"))
    elif department == "projects":
        return redirect(url_for("project_management_dashboard"))
    elif department == "sales":
        return redirect(url_for("sales_dashboard"))
    elif department == "marketing":
        return redirect(url_for("marketing_dashboard"))
    elif department == "operations":
        return redirect(url_for("operations_dashboard"))
    else:
        flash("Department not found!", "danger")
        return redirect(url_for("dashboard"))

# ======================
# Logout
# ======================
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))

# ======================
# Run App
# ======================
if __name__ == "__main__":
    app.run(debug=True)