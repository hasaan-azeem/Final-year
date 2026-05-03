<h1 align="center">🛡️ WebXGuard</h1>
<p align="center">
  <b>Advanced Web Security Scanner & Continuous Monitoring System</b>
</p>

<p align="center">
  Detect • Monitor • Secure
</p>

---

## 🚀 Overview

**WebXGuard** is a full-stack web security platform designed to identify vulnerabilities in web applications and provide real-time monitoring for continuous protection.

It combines **deep scanning**, **real-time progress tracking**, and **automated monitoring** to help developers and security enthusiasts detect and mitigate security risks efficiently.

---

## ✨ Key Features

### 🔍 Smart Vulnerability Scanner

* Passive & Active scanning modes
* Detects common web vulnerabilities
* Intelligent anti-bot detection system
* Deep crawling and endpoint discovery

### 📡 Real-Time Scan Tracking

* Live scan progress via WebSockets
* No polling, instant updates
* Clean and interactive UI

### 🔄 Continuous Monitoring

* Monitor selected websites continuously
* Automatic re-checking for vulnerabilities
* Alerts on status changes

### 🗄️ Data Management

* PostgreSQL integration
* Scan results stored and tracked
* Domain-based organization

### 🎯 Clean Architecture

* Modular backend (scalable & maintainable)
* API-driven communication
* Separation of scanner & monitoring logic

---

## 🏗️ Tech Stack

### 🔧 Backend

* Python
* FastAPI
* AsyncIO
* PostgreSQL

### 🎨 Frontend

* React
* Tailwind CSS

### ⚙️ Other Tools

* WebSockets (real-time updates)
* REST APIs
* Git & GitHub

---

## 📁 Project Structure

```
WEBXGUARD/
│
├── backend/
│   ├── app/
│   ├── Scanner/
│   ├── network_logs/
│   ├── screenshots/
│   ├── app.py
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   ├── public/
│   ├── components.json
│   └── package.json
│
└── .gitignore
```

---

## ⚙️ Installation & Setup

### 1️⃣ Clone the repository

```bash
git clone https://github.com/hasaan-azeem/Final-year.git
cd Final-year
```

---

### 2️⃣ Backend Setup

```bash
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Run backend:

```bash
uvicorn app:app --reload
```

---

### 3️⃣ Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

---

## 🔐 Environment Variables

Create a `.env` file in backend:

```
DATABASE_URL=your_database_url
SECRET_KEY=your_secret_key
```

⚠️ Never commit `.env` to GitHub

---

## 📊 How It Works

1. User starts a scan from frontend
2. Backend triggers scanner engine
3. Scanner crawls and analyzes target
4. Results stored in database
5. Real-time updates sent via WebSockets
6. Monitoring keeps checking selected domains

---

## 🎯 Use Cases

* Security testing for web apps
* Learning cybersecurity concepts
* Continuous website monitoring
* Academic/FYP demonstration

---

## 🛠️ Future Improvements

* AI-based vulnerability detection
* Email/Slack alerts
* Advanced reporting dashboard
* Multi-user authentication system

---

## 👨‍💻 Author

<p align="center">
  <b>Developed by a team of 3 members</b><br>
  <i>Final Year Project | WebXGuard Team</i>
</p>

---

## ⭐ Support

If you like this project, consider giving it a ⭐ on GitHub!

---

## 📜 License

This project is for educational purposes (FYP).
