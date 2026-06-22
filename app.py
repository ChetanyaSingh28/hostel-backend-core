from flask import Flask, request, jsonify
from flask_cors import CORS
import bcrypt
import jwt
import datetime
from functools import wraps
import razorpay
import requests

# Import database connection
from db import db, cursor
import pymysql
import random
import os
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv
import re
from email_validator import validate_email, EmailNotValidError

def is_valid_email(email):
    # Basic regex validation
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return False
    return True

PASSWORD_ERROR_MSG = (
    "Password must be at least 8 characters and contain at least "
    "one uppercase letter, one number, and one special character"
)

def validate_password(password):
    """Return True if password meets strength requirements."""
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?~`]', password):
        return False
    return True

load_dotenv()

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max for profile pic uploads

# ── Production CORS: restrict to your Vercel frontend URL ──
# Set FRONTEND_URL in your environment (e.g., https://hostelspace.vercel.app)
# In local dev, it falls back to localhost:3000
frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
CORS(app, origins=[frontend_url], supports_credentials=True)

from limiter import limiter
limiter.init_app(app)

@app.before_request
def before_request():
    try:
        db.ping(reconnect=True)
    except:
        pass

from flask import g

@app.teardown_appcontext
def close_db(error):
    if 'cursor' in g:
        try:
            g.cursor.close()
        except:
            pass
    if 'db' in g:
        try:
            g.db.close()
        except:
            pass

SECRET_KEY = os.getenv("JWT_SECRET", "default_secret")
RAZORPAY_KEY = os.getenv("RAZORPAY_KEY", "default_rzp_key")
RAZORPAY_SECRET = os.getenv("RAZORPAY_SECRET", "default_rzp_secret")
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY, RAZORPAY_SECRET))

# ----------------- MIDDLEWARE ----------------- #

def token_required(allowed_roles=None):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = None
            if "Authorization" in request.headers:
                parts = request.headers["Authorization"].split(" ")
                if len(parts) == 2:
                    token = parts[1]

            if not token:
                return jsonify({"message": "Token is missing"}), 401
            try:
                data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
                current_user = data["user"]
                role = data.get("role", "student")
                
                if allowed_roles and role not in allowed_roles:
                    return jsonify({"message": "Unauthorized access for this role"}), 403
            except:
                return jsonify({"message": "Token is invalid"}), 401

            return f(current_user, role, *args, **kwargs)
        return decorated
    return decorator


@app.route("/health", methods=["GET"])
def health_check():
    try:
        db.ping(reconnect=True)
        cursor.execute("SELECT 1")
        cursor.fetchone()
        return jsonify({"status": "healthy", "db": "connected"}), 200
    except Exception as e:
        return jsonify({"status": "unhealthy", "db": "disconnected", "error": str(e)}), 500


# ----------------- AUTHENTICATION ----------------- #

@app.route("/register", methods=["POST"])
@limiter.limit("5 per hour")
def register():
    data = request.json or {}
    name = data.get("name")
    email = data.get("email")
    phone = data.get("phone")
    password_raw = data.get("password")
    role = data.get("role", "student") # 'student', 'admin', 'staff'

    if not name or not email or not phone or not password_raw:
        return jsonify({"message": "Missing required fields"}), 400

    if not validate_password(password_raw):
        return jsonify({"message": PASSWORD_ERROR_MSG}), 400

    try:
        if not is_valid_email(email):
            return jsonify({"message": "Invalid email format"}), 400
        # Validate and normalize email further with email_validator
        valid = validate_email(email)
        email = valid.email
    except EmailNotValidError as e:
        return jsonify({"message": str(e)}), 400

    # Prevent duplicates up front for better error messages
    cursor.execute("SELECT id FROM users WHERE email=%s OR phone=%s", (email, phone))
    existing = cursor.fetchone()
    if existing:
        cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
        if cursor.fetchone():
            return jsonify({"message": "Email already registered"}), 409
        cursor.execute("SELECT id FROM users WHERE phone=%s", (phone,))
        if cursor.fetchone():
            return jsonify({"message": "Phone number already registered"}), 409
        return jsonify({"message": "User already exists"}), 409

    # Hash password and decode to string
    password = bcrypt.hashpw(password_raw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    try:
        sql = "INSERT INTO users(name, email, phone, password, role) VALUES(%s, %s, %s, %s, %s)"
        cursor.execute(sql, (name, email, phone, password, role))
        db.commit()
        return jsonify({"message": "Registered successfully"}), 201
    except Exception as e:
        # Keep generic, but if duplicate got through race, return 409
        if hasattr(e, 'args') and len(e.args) > 0 and isinstance(e.args[0], int) and e.args[0] == 1062:
            return jsonify({"message": "Duplicate entry", "error": str(e)}), 409
        return jsonify({"message": "Registration failed", "error": str(e)}), 500


@app.route("/login", methods=["POST"])
@limiter.limit("5 per 15 minute")
def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")
    role_requested = data.get("role")

    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()

    if user and bcrypt.checkpw(password.encode(), user["password"].encode()):
        db_role = user.get("role", "student")
        if role_requested and role_requested != db_role:
             return jsonify({"message": "Role mismatch. Invalid credentials."}), 403
             
        token = jwt.encode({
            "user": user["id"],
            "role": db_role,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, SECRET_KEY)

        return jsonify({"token": token, "role": db_role, "name": user["name"], "room_id": user.get("room_id")})

    return jsonify({"message": "Invalid login credentials"}), 401

# ----------------- PROFILE ----------------------- #

@app.route("/profile", methods=["GET"])
@token_required()
def get_profile(current_user, role):
    try:
        db.ping(reconnect=True)
        cur = db.cursor(pymysql.cursors.DictCursor)
        cur.execute("SELECT id, name, email, phone, role, room_id, profile_pic, created_at FROM users WHERE id=%s", (current_user,))
        user = cur.fetchone()
        cur.close()
        if not user:
            return jsonify({"message": "User not found"}), 404
        # Convert datetime to string for JSON
        if user.get("created_at"):
            user["created_at"] = user["created_at"].strftime("%Y-%m-%d %H:%M:%S")
        return jsonify(user)
    except Exception as e:
        return jsonify({"message": "Failed to load profile", "error": str(e)}), 500

@app.route("/profile", methods=["PUT"])
@token_required()
def update_profile(current_user, role):
    try:
        db.ping(reconnect=True)
        cur = db.cursor(pymysql.cursors.DictCursor)

        data = request.json or {}
        name = data.get("name")
        email = data.get("email")
        phone = data.get("phone")
        profile_pic = data.get("profile_pic")
        current_password = data.get("current_password")
        new_password = data.get("new_password")

        # Fetch current user
        cur.execute("SELECT * FROM users WHERE id=%s", (current_user,))
        user = cur.fetchone()
        if not user:
            cur.close()
            return jsonify({"message": "User not found"}), 404

        # If changing password, verify current password first
        if new_password:
            if not current_password:
                cur.close()
                return jsonify({"message": "Current password is required to set a new password"}), 400
            if not bcrypt.checkpw(current_password.encode(), user["password"].encode()):
                cur.close()
                return jsonify({"message": "Current password is incorrect"}), 403
            if not validate_password(new_password):
                cur.close()
                return jsonify({"message": PASSWORD_ERROR_MSG}), 400

        # Check for duplicate email/phone (excluding self)
        if email and email != user["email"]:
            cur.execute("SELECT id FROM users WHERE email=%s AND id!=%s", (email, current_user))
            if cur.fetchone():
                cur.close()
                return jsonify({"message": "Email already in use by another account"}), 409

        if phone and phone != user["phone"]:
            cur.execute("SELECT id FROM users WHERE phone=%s AND id!=%s", (phone, current_user))
            if cur.fetchone():
                cur.close()
                return jsonify({"message": "Phone number already in use by another account"}), 409

        # Build update
        updates = []
        values = []
        if name and name != user["name"]:
            updates.append("name=%s")
            values.append(name)
        if email and email != user["email"]:
            updates.append("email=%s")
            values.append(email)
        if phone and phone != user["phone"]:
            updates.append("phone=%s")
            values.append(phone)
        if profile_pic is not None:
            updates.append("profile_pic=%s")
            values.append(profile_pic if profile_pic else None)
        if new_password:
            hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            updates.append("password=%s")
            values.append(hashed)

        if not updates:
            cur.close()
            return jsonify({"message": "No changes to save"}), 200

        values.append(current_user)
        sql = f"UPDATE users SET {', '.join(updates)} WHERE id=%s"
        cur.execute(sql, tuple(values))
        db.commit()

        # Return updated user
        cur.execute("SELECT id, name, email, phone, role, room_id, profile_pic, created_at FROM users WHERE id=%s", (current_user,))
        updated_user = cur.fetchone()
        cur.close()
        if updated_user and updated_user.get("created_at"):
            updated_user["created_at"] = updated_user["created_at"].strftime("%Y-%m-%d %H:%M:%S")

        return jsonify({"message": "Profile updated successfully", "user": updated_user})
    except Exception as e:
        db.rollback()
        return jsonify({"message": "Failed to update profile", "error": str(e)}), 500

@app.route("/send-otp", methods=["POST"])
@limiter.limit("5 per 15 minute")
def send_otp():
    data = request.json
    email_address = data.get("email")
    role = data.get("role")

    if not email_address or not is_valid_email(email_address):
        return jsonify({"message": "Invalid email format"}), 400

    cursor.execute("SELECT * FROM users WHERE email=%s AND role=%s", (email_address, role))
    user = cursor.fetchone()

    if not user:
        return jsonify({"message": "User not found!"}), 404

    # Generate 6 digit OTP
    otp_code = str(random.randint(100000, 999999))
    expiry = datetime.datetime.now() + datetime.timedelta(minutes=5)

    try:
        cursor.execute("UPDATE users SET otp=%s, otp_expiry=%s WHERE id=%s", (otp_code, expiry, user["id"]))
        db.commit()
        
        # MOCK SMS/EMAIL SENT to Terminal
        print(f"\n=======================")
        print(f" EMAIL OTP for {email_address}: {otp_code} ")
        print(f"=======================\n")

        # Optional: Actually send email if environment variables exist
        # To make this work, set SMTP_USER and SMTP_PASSWORD in your environment.
        smtp_user = os.getenv("EMAIL_USER")
        smtp_password = os.getenv("EMAIL_PASS")
        if smtp_user and smtp_password:
            try:
                msg = EmailMessage()
                msg.set_content(f"Your HostelSpace Login OTP is: {otp_code}. It is valid for 5 minutes.")
                msg["Subject"] = "HostelSpace Login OTP"
                msg["From"] = smtp_user
                msg["To"] = email_address

                server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
                server.login(smtp_user, smtp_password)
                server.send_message(msg)
                server.quit()
                print(" -> Real Email broadcasted dynamically via SMTP.")
            except Exception as e:
                print(" -> Failed to send real email:", e)
        
        return jsonify({"message": "OTP sent successfully"})
    except Exception as e:
        return jsonify({"message": "Failed to generate OTP", "error": str(e)}), 500

@app.route("/login-otp", methods=["POST"])
@limiter.limit("5 per 15 minute")
def login_otp():
    data = request.json
    email_address = data.get("email")
    otp = data.get("otp")
    role_requested = data.get("role")

    cursor.execute("SELECT * FROM users WHERE email=%s AND role=%s", (email_address, role_requested))
    user = cursor.fetchone()

    if not user:
        return jsonify({"message": "Invalid credentials"}), 401

    if user["otp"] != str(otp):
        return jsonify({"message": "Invalid OTP"}), 401

    if user["otp_expiry"] and user["otp_expiry"] < datetime.datetime.now():
        return jsonify({"message": "OTP expired"}), 401

    # Clear OTP
    cursor.execute("UPDATE users SET otp=NULL, otp_expiry=NULL WHERE id=%s", (user["id"],))
    db.commit()

    db_role = user.get("role", "student")
    token = jwt.encode({
        "user": user["id"],
        "role": db_role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, SECRET_KEY)

    return jsonify({"token": token, "role": db_role, "name": user["name"], "room_id": user.get("room_id")})

@app.route("/forgot-password", methods=["POST"])
@limiter.limit("3 per hour")
def forgot_password():
    data = request.json
    email = data.get("email")
    if not email or not is_valid_email(email):
        return jsonify({"message": "Invalid email format"}), 400

    cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()
    if not user:
        return jsonify({"message": "User not found"}), 404

    import secrets
    reset_token = secrets.token_hex(20)
    expiry = datetime.datetime.now() + datetime.timedelta(minutes=15)

    cursor.execute("UPDATE users SET reset_token=%s, reset_expiry=%s WHERE id=%s", (reset_token, expiry, user["id"]))
    db.commit()

    # Send Email
    smtp_user = os.getenv("EMAIL_USER")
    smtp_password = os.getenv("EMAIL_PASS")
    if smtp_user and smtp_password:
        try:
            msg = EmailMessage()
            msg.set_content(f"Your password reset link is: {os.getenv('FRONTEND_URL')}/reset-password/{reset_token}")
            msg["Subject"] = "HostelSpace Password Reset"
            msg["From"] = smtp_user
            msg["To"] = email
            server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
            server.quit()
        except:
            pass

    return jsonify({"message": "Password reset link sent to email"})   

@app.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.json
    token = data.get("token")
    new_password = data.get("password")

    if not token or not new_password:
        return jsonify({"message": "Missing token or password"}), 400

    if not validate_password(new_password):
        return jsonify({"message": PASSWORD_ERROR_MSG}), 400

    cursor.execute("SELECT id, reset_expiry FROM users WHERE reset_token=%s", (token,))
    user = cursor.fetchone()

    if not user or user["reset_expiry"] < datetime.datetime.now():
        return jsonify({"message": "Invalid or expired token"}), 400

    hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    cursor.execute("UPDATE users SET password=%s, reset_token=NULL, reset_expiry=NULL WHERE id=%s", (hashed_pw, user["id"]))
    db.commit()
    return jsonify({"message": "Password reset successful"})

# ----------------- ROOMS ----------------- #

@app.route("/rooms", methods=["GET"])
@token_required(allowed_roles=["student", "admin"])
def rooms(current_user, role):
    cursor.execute("SELECT * FROM rooms")
    rooms_data = cursor.fetchall()
    return jsonify(rooms_data)


# ----------------- QR PASS GENERATION ----------------- #

@app.route("/qr-pass", methods=["GET"])
@token_required()
def get_qr_pass(current_user, role):
    try:
        db.ping(reconnect=True)
        # Fetch user and room details
        cursor.execute("""
            SELECT u.name, u.email, u.phone, u.role, r.room_number 
            FROM users u 
            LEFT JOIN rooms r ON u.room_id = r.id 
            WHERE u.id = %s
        """, (current_user,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({"message": "User not found"}), 404
            
        # Formulate QR content
        room_info = user.get("room_number") or "Unassigned"
        qr_content = (
            f"HostelSpace Pass\n"
            f"Name: {user['name']}\n"
            f"Email: {user['email']}\n"
            f"Role: {user['role']}\n"
            f"Room: {room_info}\n"
            f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        
        # Generate QR image base64
        import qrcode
        import io
        import base64
        
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(qr_content)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        buffered = io.BytesIO()
        img.save(buffered)
        img_str = base64.b64encode(buffered.getvalue()).decode('utf-8')
        qr_image = f"data:image/png;base64,{img_str}"
        
        return jsonify({
            "qr_image": qr_image,
            "qr_content": qr_content
        })
    except Exception as e:
        return jsonify({"message": "Failed to generate QR code", "error": str(e)}), 500


# ----------------- PAYMENTS (Razorpay Integrated) ----------------- #

@app.route("/create-order", methods=["POST"])
@token_required(allowed_roles=["student"])
def create_order(current_user, role):
    data = request.json
    room_id = data.get("room_id")
    
    if not room_id:
        return jsonify({"error": "Room ID is required"}), 400
        
    try:
        # Securely fetch amount
        cursor.execute("SELECT price_per_month FROM rooms WHERE id=%s", (room_id,))
        room = cursor.fetchone()
        if not room:
             return jsonify({"error": "Invalid room"}), 404
             
        amount = room["price_per_month"]
        amount_in_paise = int(float(amount)) * 100
        
        # Create order in Razorpay
        order_data = {
            "amount": amount_in_paise,
            "currency": "INR",
            "payment_capture": "1"
        }
        order = razorpay_client.order.create(data=order_data)
        
        # Save order info to database
        sql = "INSERT INTO payments(user_id, amount, order_id, status) VALUES(%s, %s, %s, %s)"
        cursor.execute(sql, (current_user, amount, order["id"], "pending"))
        db.commit()
        
        return jsonify({
            "id": order["id"], 
            "amount": amount_in_paise, 
            "currency": "INR",
            "key": RAZORPAY_KEY
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/students", methods=["GET"])
@token_required(allowed_roles=["admin"])
def get_students(current_user, role):
    cursor.execute("SELECT id, name, email, phone, room_id, role, created_at FROM users WHERE role='student'")
    return jsonify(cursor.fetchall())

@app.route("/students/<int:student_id>", methods=["PUT"])
@token_required(allowed_roles=["admin"])
def update_student(current_user, role, student_id):
    data = request.json
    email = data.get("email")
    if email:
        if not is_valid_email(email):
            return jsonify({"error": "Invalid email format"}), 400
        try:
            valid = validate_email(email)
            email = valid.email
        except EmailNotValidError as e:
            return jsonify({"error": str(e)}), 400

    try:
        cursor.execute("UPDATE users SET name=%s, email=%s, phone=%s, room_id=%s WHERE id=%s AND role='student'", 
                       (data.get("name"), email, data.get("phone"), data.get("room_id"), student_id))
        db.commit()
        return jsonify({"message": "Student updated successfully"})
    except Exception as e:
        return jsonify({"error": "Failed to update student"}), 500

@app.route("/students/<int:student_id>", methods=["DELETE"])
@token_required(allowed_roles=["admin"])
def delete_student(current_user, role, student_id):
    try:
        cursor.execute("SELECT room_id FROM users WHERE id = %s AND role = 'student'", (student_id,))
        student = cursor.fetchone()
        if not student:
            return jsonify({"error": "Student not found"}), 404
        
        room_id = student.get("room_id")
        if room_id:
            cursor.execute("SELECT id FROM rooms WHERE id = %s", (room_id,))
            if cursor.fetchone():
                cursor.execute("UPDATE rooms SET occupancy = GREATEST(0, occupancy - 1) WHERE id = %s", (room_id,))
        
        cursor.execute("DELETE FROM users WHERE id = %s AND role = 'student'", (student_id,))
        db.commit()
        return jsonify({"message": "Student removed successfully"})
    except Exception as e:
        db.rollback()
        return jsonify({"error": str(e)}), 500

# ----------------- CHAT / MESSAGES ----------------- #

@app.route("/messages", methods=["POST"])
@token_required(allowed_roles=["student", "admin", "staff"])
def send_message(current_user, role):
    data = request.json
    receiver_id = data.get("receiver_id")
    message = data.get("message")
    
    if role == "student" and not receiver_id:
        cursor.execute("SELECT id FROM users WHERE role='admin' LIMIT 1")
        admin = cursor.fetchone()
        if admin:
            receiver_id = admin["id"]
        else:
            return jsonify({"error": "No admin exists to receive message"}), 404

    try:
        cursor.execute("INSERT INTO messages (sender_id, receiver_id, message) VALUES (%s, %s, %s)",
                       (current_user, receiver_id, message))
        
        # Add a notification for receiver
        cursor.execute("INSERT INTO notifications (user_id, title, message) VALUES (%s, %s, %s)",
                       (receiver_id, "New Message", f"You have a new message."))
        db.commit()
        return jsonify({"message": "Message sent"})
    except Exception as e:
        return jsonify({"error": "Failed to send message"}), 500

@app.route("/messages/conversations", methods=["GET"])
@token_required(allowed_roles=["admin", "staff"])
def get_conversations(current_user, role):
    # Get distinct users who have chatted with current admin
    sql = '''SELECT DISTINCT u.id, u.name, u.role FROM users u 
             JOIN messages m ON (u.id = m.sender_id OR u.id = m.receiver_id) 
             WHERE u.id != %s AND (m.sender_id = %s OR m.receiver_id = %s)'''
    cursor.execute(sql, (current_user, current_user, current_user))
    return jsonify(cursor.fetchall())

@app.route("/messages/<int:other_user_id>", methods=["GET"])
@token_required(allowed_roles=["student", "admin", "staff"])
def get_messages(current_user, role, other_user_id):
    cursor.execute('''SELECT * FROM messages 
                      WHERE (sender_id=%s AND receiver_id=%s) 
                         OR (sender_id=%s AND receiver_id=%s) 
                      ORDER BY timestamp ASC''', 
                   (current_user, other_user_id, other_user_id, current_user))
    return jsonify(cursor.fetchall())


@app.route("/manual-payment", methods=["POST"])
@token_required(allowed_roles=["admin"])
def manual_payment(current_user, role):
    data = request.json
    student_id = data.get("student_id")
    amount = data.get("amount")
    
    if not student_id or not amount:
        return jsonify({"error": "Student ID and Amount are required"}), 400
        
    try:
        import uuid
        manual_id = "MANUAL_" + str(uuid.uuid4())[:8]
        sql = "INSERT INTO payments(user_id, amount, order_id, payment_id, status) VALUES(%s, %s, %s, %s, %s)"
        cursor.execute(sql, (student_id, amount, manual_id, manual_id, "paid"))
        db.commit()
        return jsonify({"message": "Manual payment logged successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/pay", methods=["POST"])
@token_required(allowed_roles=["student"])
def pay(current_user, role):
    data = request.json
    
    # Razorpay details sent from frontend
    razorpay_order_id = data.get("razorpay_order_id")
    razorpay_payment_id = data.get("razorpay_payment_id")
    razorpay_signature = data.get("razorpay_signature")
    
    if not razorpay_order_id or not razorpay_payment_id or not razorpay_signature:
         return jsonify({"error": "Missing payment verfication data"}), 400
    
    try:
        # Verify the signature
        params_dict = {
            'razorpay_order_id': razorpay_order_id,
            'razorpay_payment_id': razorpay_payment_id,
            'razorpay_signature': razorpay_signature
        }
        razorpay_client.utility.verify_payment_signature(params_dict)
        
        # If successfully verified, update database
        sql = "UPDATE payments SET status=%s, payment_id=%s WHERE order_id=%s AND user_id=%s"
        cursor.execute(sql, ("paid", razorpay_payment_id, razorpay_order_id, current_user))
        
        # Generate QR Data
        cursor.execute("SELECT u.name, r.room_number FROM users u JOIN rooms r ON u.room_id = r.id WHERE u.id=%s", (current_user,))
        room = cursor.fetchone()
        if room:
            qr_data = f"Name: {room['name']}\nRoom: {room['room_number']}"
        else:
            qr_data = "Room: N/A"
        
        db.commit()
        return jsonify({"message": "Payment successful", "qr_data": qr_data})
        
    except razorpay.errors.SignatureVerificationError:
        # Signature mismatch
        cursor.execute("UPDATE payments SET status=%s WHERE order_id=%s AND user_id=%s", ("failed", razorpay_order_id, current_user))
        db.commit()
        return jsonify({"error": "Payment verification failed"}), 400
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ----------------- COMPLAINTS ----------------- #

@app.route("/complaints", methods=["POST"])
@token_required(allowed_roles=["student"])
def add_complaint(current_user, role):
    message = request.json.get("message")
    
    # Check category through AI Service
    try:
        ml_api_url = os.getenv("ML_API_URL", "http://localhost:6000")
        ai_resp = requests.post(f"{ml_api_url}/classify", json={"text": message})
        category = ai_resp.json().get("category", "General") if ai_resp.ok else "Unknown"
    except:
        category = "Unknown"

    try:
        sql = "INSERT INTO complaints(user_id, message, category, status) VALUES(%s, %s, %s, %s)"
        cursor.execute(sql, (current_user, message, category, "Pending"))
        db.commit()
        return jsonify({"message": "Complaint submitted successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/user-complaints", methods=["GET"])
@token_required(allowed_roles=["student"])
def get_user_complaints(current_user, role):
    cursor.execute("SELECT * FROM complaints WHERE user_id=%s ORDER BY id DESC", (current_user,))
    data = cursor.fetchall()
    return jsonify(data)

@app.route("/complaints/all", methods=["GET"])
@token_required(allowed_roles=["admin", "staff"])
def get_all_complaints(current_user, role):
    cursor.execute("SELECT c.*, u.name as st_name FROM complaints c JOIN users u ON c.user_id = u.id ORDER BY id DESC")
    data = cursor.fetchall()
    return jsonify(data)

@app.route("/complaints/<int:complaint_id>", methods=["PUT"])
@token_required(allowed_roles=["admin", "staff"])
def update_complaint_status(current_user, role, complaint_id):
    status = request.json.get("status")
    cursor.execute("UPDATE complaints SET status=%s WHERE id=%s", (status, complaint_id))
    db.commit()
    return jsonify({"message": "Status updated"})


# ----------------- ATTENDANCE ----------------- #

@app.route("/attendance", methods=["GET"])
@token_required(allowed_roles=["student", "admin"])
def get_attendance(current_user, role):
    date_filter = request.args.get("date")
    if role == "student":
        cursor.execute("SELECT * FROM attendance WHERE user_id=%s ORDER BY date DESC", (current_user,))
    else:
        if date_filter:
            sql = """
                SELECT u.id as user_id, u.name, a.status, a.id as attendance_id, %s as date
                FROM users u 
                LEFT JOIN attendance a ON u.id = a.user_id AND a.date = %s
                WHERE u.role = 'student'
            """
            cursor.execute(sql, (date_filter, date_filter))
        else:
            sql = """
                SELECT u.id as user_id, u.name, a.status, a.date
                FROM users u
                JOIN attendance a ON u.id = a.user_id
                WHERE u.role = 'student'
                ORDER BY a.date DESC
            """
            cursor.execute(sql)
    return jsonify(cursor.fetchall())

@app.route("/attendance", methods=["POST"])
@token_required(allowed_roles=["admin"])
def mark_attendance(current_user, role):
    data = request.json
    user_id = data.get("user_id")
    date = data.get("date")
    status = data.get("status", "Present")
    
    try:
        cursor.execute("SELECT id FROM attendance WHERE user_id=%s AND date=%s", (user_id, date))
        exist = cursor.fetchone()
        if exist:
            cursor.execute("UPDATE attendance SET status=%s WHERE id=%s", (status, exist["id"]))
        else:
            cursor.execute("INSERT INTO attendance(user_id, date, status) VALUES(%s, %s, %s)", (user_id, date, status))
        db.commit()
        return jsonify({"message": "Attendance marked"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ----------------- NOTIFICATIONS ----------------- #

@app.route("/notifications", methods=["GET"])
@token_required(allowed_roles=["student", "admin", "staff"])
def get_notifications(current_user, role):
    cursor.execute("SELECT * FROM notifications WHERE user_id=%s ORDER BY created_at DESC", (current_user,))
    return jsonify(cursor.fetchall())

@app.route("/notifications/<int:n_id>/read", methods=["PUT"])
@token_required(allowed_roles=["student", "admin", "staff"])
def read_notification(current_user, role, n_id):
    cursor.execute("UPDATE notifications SET is_read=TRUE WHERE id=%s AND user_id=%s", (n_id, current_user))
    db.commit()
    return jsonify({"message": "Marked as read"})

# ----------------- LEAVE APPLICATIONS ----------------- #

@app.route("/leave-applications", methods=["GET"])
@token_required(allowed_roles=["student", "admin"])
def get_leaves(current_user, role):
    if role == "student":
        cursor.execute("SELECT * FROM leave_applications WHERE user_id=%s ORDER BY created_at DESC", (current_user,))
    else:
        cursor.execute("SELECT l.*, u.name, u.room_id FROM leave_applications l JOIN users u ON l.user_id=u.id ORDER BY created_at DESC")
    return jsonify(cursor.fetchall())

@app.route("/leave-applications", methods=["POST"])
@token_required(allowed_roles=["student"])
def apply_leave(current_user, role):
    data = request.json
    try:
        cursor.execute("INSERT INTO leave_applications (user_id, from_date, to_date, reason) VALUES (%s, %s, %s, %s)",
                       (current_user, data.get("from_date"), data.get("to_date"), data.get("reason")))
        db.commit()
        # notify admin optionally, but keeping it simple
        return jsonify({"message": "Leave application submitted"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/leave-applications/<int:leave_id>", methods=["PUT"])
@token_required(allowed_roles=["admin"])
def update_leave(current_user, role, leave_id):
    status = request.json.get("status")
    cursor.execute("UPDATE leave_applications SET status=%s WHERE id=%s", (status, leave_id))
    
    # notify user
    cursor.execute("SELECT user_id FROM leave_applications WHERE id=%s", (leave_id,))
    res = cursor.fetchone()
    if res:
        cursor.execute("INSERT INTO notifications (user_id, title, message) VALUES (%s, %s, %s)",
                       (res["user_id"], "Leave Application", f"Your leave request has been {status}"))
    db.commit()
    return jsonify({"message": "Leave updated"})

# ----------------- VISITORS ----------------- #

@app.route("/visitors", methods=["GET"])
@token_required(allowed_roles=["student", "admin"])
def get_visitors(current_user, role):
    if role == "student":
        cursor.execute("SELECT * FROM visitors WHERE user_id=%s ORDER BY check_in DESC", (current_user,))
    else:
        cursor.execute("SELECT v.*, u.name as user_name FROM visitors v JOIN users u ON v.user_id=u.id ORDER BY check_in DESC")
    return jsonify(cursor.fetchall())

@app.route("/visitors", methods=["POST"])
@token_required(allowed_roles=["student", "admin"])
def add_visitor(current_user, role):
    data = request.json
    v_name = data.get("visitor_name")
    phone = data.get("phone")
    room_no = data.get("room_no")
    user_id = current_user if role == "student" else data.get("user_id")
    
    try:
        cursor.execute("INSERT INTO visitors (visitor_name, phone, user_id, room_no) VALUES (%s, %s, %s, %s)",
                       (v_name, phone, user_id, room_no))
        db.commit()
        return jsonify({"message": "Visitor added successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/visitors/<int:v_id>/checkout", methods=["PUT"])
@token_required(allowed_roles=["admin"])
def checkout_visitor(current_user, role, v_id):
    cursor.execute("UPDATE visitors SET check_out=CURRENT_TIMESTAMP, status='checked_out' WHERE id=%s", (v_id,))
    db.commit()
    return jsonify({"message": "Visitor checked out"})

# ----------------- ROOMS MANAGEMENT ----------------- #

@app.route("/rooms", methods=["POST"])
@token_required(allowed_roles=["admin"])
def add_room(current_user, role):
    data = request.json
    try:
        cursor.execute("INSERT INTO rooms (room_number, capacity, price_per_month, status) VALUES (%s, %s, %s, %s)",
                       (data.get("room_number"), data.get("capacity"), data.get("price_per_month"), data.get("status", "available")))
        db.commit()
        return jsonify({"message": "Room added successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/rooms/<int:room_id>", methods=["PUT"])
@token_required(allowed_roles=["admin"])
def edit_room(current_user, role, room_id):
    data = request.json
    try:
        cursor.execute("UPDATE rooms SET room_number=%s, capacity=%s, price_per_month=%s, status=%s WHERE id=%s",
                       (data.get("room_number"), data.get("capacity"), data.get("price_per_month"), data.get("status"), room_id))
        db.commit()
        return jsonify({"message": "Room updated"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/rooms/<int:room_id>", methods=["DELETE"])
@token_required(allowed_roles=["admin"])
def delete_room(current_user, role, room_id):
    try:
        cursor.execute("UPDATE users SET room_id = NULL WHERE room_id = %s", (room_id,))
        cursor.execute("DELETE FROM rooms WHERE id=%s", (room_id,))
        db.commit()
        return jsonify({"message": "Room deleted"})
    except Exception as e:
        db.rollback()
        return jsonify({"error": str(e)}), 500

@app.route("/select-room", methods=["POST"])
@token_required(allowed_roles=["student"])
def select_room(current_user, role):
    data = request.json
    room_id = data.get("room_id")
    try:
        cursor.execute("SELECT occupancy, capacity FROM rooms WHERE id=%s", (room_id,))
        room = cursor.fetchone()
        if not room or room["occupancy"] >= room["capacity"]:
            return jsonify({"message": "Room is full or unavailable"}), 400
            
        cursor.execute("UPDATE users SET room_id=%s WHERE id=%s", (room_id, current_user))
        cursor.execute("UPDATE rooms SET occupancy = occupancy + 1 WHERE id=%s", (room_id,))
        db.commit()
        return jsonify({"message": "Room selected successfully!"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ----------------- TRANSACTIONS & EXPENSES ----------------- #

@app.route("/transactions", methods=["GET"])
@token_required(allowed_roles=["student", "admin"])
def get_transactions(current_user, role):
    if role == "student":
        cursor.execute("SELECT * FROM payments WHERE user_id=%s ORDER BY created_at DESC", (current_user,))
    else:
        cursor.execute("SELECT p.*, u.name as user_name FROM payments p JOIN users u ON p.user_id = u.id ORDER BY p.created_at DESC")
    return jsonify(cursor.fetchall())

@app.route("/expenses", methods=["GET"])
@token_required(allowed_roles=["admin"])
def get_expenses(current_user, role):
    cursor.execute("SELECT * FROM expenses ORDER BY date DESC")
    return jsonify(cursor.fetchall())

@app.route("/expenses", methods=["POST"])
@token_required(allowed_roles=["admin"])
def add_expense(current_user, role):
    data = request.json
    try:
        cursor.execute("INSERT INTO expenses (amount, description, date) VALUES (%s, %s, %s)",
                       (data.get("amount"), data.get("description"), data.get("date")))
        db.commit()
        return jsonify({"message": "Expense logged successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ----------------- DASHBOARD STATS ----------------- #

@app.route("/dashboard/stats", methods=["GET"])
@token_required(allowed_roles=["student", "admin"])
def get_dashboard_stats(current_user, role):
    try:
        if role == "admin":
            cursor.execute("SELECT COUNT(id) as count FROM users WHERE role='student'")
            total_students = cursor.fetchone()["count"]
            
            cursor.execute("SELECT SUM(capacity - occupancy) as avail FROM rooms WHERE status='available'")
            avail = cursor.fetchone()["avail"]
            avail_beds = avail if avail else 0
            
            cursor.execute("SELECT COUNT(id) as count FROM complaints WHERE status != 'Resolved'")
            active_complaints = cursor.fetchone()["count"]
            
            # Simple total revenue summing
            cursor.execute("SELECT SUM(amount) as total FROM payments WHERE status='paid'")
            rev = cursor.fetchone()["total"]
            monthly_rev = float(rev) if rev else 0.0
            
            # Fetch last 7 days chart data (Income vs Expenses)
            cursor.execute('''
                SELECT DATE(created_at) as log_date, SUM(amount) as income 
                FROM payments WHERE status='paid' AND created_at >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
                GROUP BY DATE(created_at)
            ''')
            income_rows = cursor.fetchall()
            
            cursor.execute('''
                SELECT DATE(date) as log_date, SUM(amount) as expense
                FROM expenses WHERE date >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
                GROUP BY DATE(date)
            ''')
            expense_rows = cursor.fetchall()
            
            chart_data = []
            for i in range(6, -1, -1):
                d = (datetime.datetime.now() - datetime.timedelta(days=i)).strftime('%Y-%m-%d')
                inc = next((r["income"] for r in income_rows if str(r["log_date"]) == d), 0)
                exp = next((r["expense"] for r in expense_rows if str(r["log_date"]) == d), 0)
                chart_data.append({"name": datetime.datetime.strptime(d, '%Y-%m-%d').strftime('%a'), "income": float(inc), "expenses": float(exp)})

            return jsonify({
                "stats": [
                    {"title": "Total Residents", "value": str(total_students)},
                    {"title": "Available Beds", "value": str(avail_beds)},
                    {"title": "Active Complaints", "value": str(active_complaints)},
                    {"title": "Total Revenue", "value": f"₹{monthly_rev}"}
                ],
                "chart": chart_data
            })
            
        else: # student
            cursor.execute("SELECT r.room_number FROM users u JOIN rooms r ON u.room_id=r.id WHERE u.id=%s", (current_user,))
            room = cursor.fetchone()
            room_no = room["room_number"] if room else "Unassigned"
            
            cursor.execute("SELECT COUNT(id) as present FROM attendance WHERE user_id=%s AND status='Present'", (current_user,))
            present = cursor.fetchone()["present"]
            
            cursor.execute("SELECT COUNT(id) as total FROM attendance WHERE user_id=%s", (current_user,))
            total = cursor.fetchone()["total"]
            
            att_percent = int((present / total) * 100) if total > 0 else 0
            
            # Optionally could add leave statuses or recent transactions here
            return jsonify({
                "stats": [
                    {"title": "Room Status", "value": room_no},
                    {"title": "Attendance %", "value": f"{att_percent}%"}
                ],
                "chart": [] # students dont see financial graphs
            })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Failed to fetch stats"}), 500

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"message": "An internal error occurred"}), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"message": "Rate limit exceeded. Try again later."}), 429

if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "false").lower() in ("true", "1", "yes")
    app.run(debug=debug, host="0.0.0.0", port=int(os.getenv("PORT", 5000)))