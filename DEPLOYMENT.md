# Deployment Guide

เอกสารนี้สรุปขั้นตอน deploy สำหรับโปรเจกต์ SecureShare ที่มี **example module + routes + frontend ตัวอย่าง**

## 1) Environment Variables

ตั้งค่าใน backend:

```env
MONGO_URL=mongodb://localhost:27017
DB_NAME=securefileshare
SECRET_KEY=replace-with-strong-secret
CORS_ORIGINS=https://your-frontend-domain
APP_ENV=production
```

ตั้งค่าใน frontend:

```env
REACT_APP_BACKEND_URL=https://your-api-domain
```

## 2) Deploy Backend (FastAPI)

ติดตั้ง dependencies:

```bash
cd backend
pip install -r requirements.txt
```

รัน service:

```bash
uvicorn server:app --host 0.0.0.0 --port 8000
```

## 3) Deploy Frontend (React)

```bash
cd frontend
yarn install
yarn build
```

จากนั้นนำไฟล์ใน `frontend/build` ไปเสิร์ฟผ่าน web server เช่น Nginx หรือ static hosting

## 4) Health / Smoke Checks

ตรวจสอบระบบหลัง deploy:

```bash
curl https://your-api-domain/api/health/db
curl https://your-api-domain/api/examples/status
curl https://your-api-domain/api/examples/deploy-checklist
```

## 5) Reverse Proxy (ตัวอย่าง Nginx)

- route `/api/*` ไป backend
- route อื่นให้เสิร์ฟ frontend static files
- เปิด HTTPS (Let's Encrypt หรือ cert จาก cloud provider)

## 6) Notes

- `example_routes` ถูกออกแบบมาเพื่อเป็นตัวอย่างโครงสร้างโมดูล routes แบบแยกไฟล์
- frontend tab "Example Module" จะแสดงผลข้อมูลจาก `/api/examples/status` และ `/api/examples/deploy-checklist`
