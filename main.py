import os
import shutil
import random
from fastapi import FastAPI, Depends, HTTPException, Header, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse  # <-- Библиотека для раздачи HTML
from sqlalchemy.orm import Session
from pydantic import BaseModel
from PIL import Image  # <-- Библиотека для работы с графикой (Metadata Scrubber)

import models
import security
from models import SessionLocal, engine

# Создаем папку для файлов
os.makedirs("uploads", exist_ok=True)

app = FastAPI(title="Veritas API", version="1.0")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# Раздаем папку с картинками
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def save_file(file: UploadFile, prefix: str):
    if not file or not file.filename: return None
    ext = file.filename.split('.')[-1]
    safe_name = f"{prefix}_{random.randint(10000, 99999)}.{ext}"
    path = f"uploads/{safe_name}"
    
    # 1. Сохраняем исходный файл на диск
    with open(path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    ext_lower = ext.lower()
    
    # --- СВЕРХВЫНОСЛИВЫЙ ДВИЖОК ОЧИСТКИ МЕТАДАННЫХ (VERITAS SCRUBBER ENGINE) ---
    
    # А. Картинки (JPEG, JPG, PNG)
    if ext_lower in ['jpg', 'jpeg', 'png']:
        try:
            with Image.open(path) as img:
                format_type = img.format
                clean_img = Image.new(img.mode, img.size)
                clean_img.putdata(list(img.getdata()))
                clean_img.save(path, format=format_type)
            print(f"[Veritas Scrubber] Очищен EXIF снимка: {path}")
        except Exception as e:
            print(f"[Veritas Scrubber Error] Картинка {path}: {e}")
            
    # Б. Документы PDF
    elif ext_lower == 'pdf':
        try:
            from pypdf import PdfReader, PdfWriter
            reader = PdfReader(path)
            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            writer.add_metadata({}) 
            with open(path, "wb") as f:
                writer.write(f)
            print(f"[Veritas Scrubber] Стерты метаданные PDF: {path}")
        except Exception as e:
            print(f"[Veritas Scrubber Error] PDF {path}: {e}")
            
    # В. Текстовые документы (DOCX) и Таблицы (XLSX)
    elif ext_lower in ['docx', 'xlsx']:
        try:
            if ext_lower == 'docx':
                from docx import Document
                doc = Document(path)
                props = doc.core_properties
            else:
                import openpyxl
                doc = openpyxl.load_workbook(path)
                props = doc.properties
                
            # Затираем ФИО автора лицензии Office/Windows
            props.author = "" if ext_lower == 'docx' else None
            if ext_lower == 'docx': props.last_modified_by = ""
            else: props.lastModifiedBy = None
            props.title = ""
            props.subject = ""
            
            doc.save(path)
            print(f"[Veritas Scrubber] Стерты свойства автора {ext_upper}: {path}")
        except Exception as e:
            print(f"[Veritas Scrubber Error] Документ {ext_lower} {path}: {e}")
            
    # Г. Презентации PowerPoint (PPTX)
    elif ext_lower == 'pptx':
        try:
            from pptx import Presentation
            prs = Presentation(path)
            props = prs.core_properties
            
            # Удаляем цифровой след создателя слайдов
            props.author = ""
            props.last_modified_by = ""
            props.title = ""
            props.subject = ""
            
            prs.save(path)
            print(f"[Veritas Scrubber] Стерты свойства автора презентации PPTX: {path}")
        except Exception as e:
            print(f"[Veritas Scrubber Error] PPTX {path}: {e}")
            
    # Д. Аудио и Видео улики (MP3, MP4, WAV, M4A)
    elif ext_lower in ['mp3', 'mp4', 'wav', 'm4a']:
        try:
            from mutagen import File as MutagenFile
            media_file = MutagenFile(path)
            if media_file is not None:
                # Полностью жестко удаляем все ID3-теги, метаданные устройства,
                # софт кодирования и скрытые GPS-координаты из атомов медиафайла
                media_file.delete()
                media_file.save()
                print(f"[Veritas Scrubber] Медиафайл полностью очищен от тегов и GPS: {path}")
        except Exception as e:
            print(f"[Veritas Scrubber Error] Медиафайл {path}: {e}")

    return f"/{path}"


def get_ticket_messages(db, ticket_number):
    msgs = db.query(models.Message).filter(models.Message.ticket_number == ticket_number).order_by(models.Message.created_at).all()
    return [{"id": m.id, "sender": m.sender, "text": security.decrypt_text(m.encrypted_text), "file_url": m.file_url, "date": m.created_at} for m in msgs]

class TicketAccess(BaseModel): ticket_number: str; pin_code: str
class StatusUpdate(BaseModel): status: str

# --- ПОЛЬЗОВАТЕЛИ ---
@app.post("/api/tickets/create")
def create_ticket(category: str = Form(...), description: str = Form(...), file: UploadFile = File(None), db: Session = Depends(get_db)):
    ticket_num = f"UT-{random.randint(1000, 9999)}"
    pin_code = security.generate_pin()
    file_url = save_file(file, ticket_num)
    
    new_ticket = models.Ticket(
        ticket_number=ticket_num, hashed_pin=security.get_password_hash(pin_code),
        category=category, encrypted_description=security.encrypt_text(description), file_url=file_url
    )
    db.add(new_ticket)
    db.commit()
    return {"ticket_number": ticket_num, "pin_code": pin_code}

@app.post("/api/tickets/check")
def check_ticket(access: TicketAccess, db: Session = Depends(get_db)):
    ticket = db.query(models.Ticket).filter(models.Ticket.ticket_number == access.ticket_number).first()
    if not ticket or not security.verify_password(access.pin_code, ticket.hashed_pin):
        raise HTTPException(status_code=401, detail="Неверные данные")
    return {
        "ticket_number": ticket.ticket_number, "status": ticket.status, "category": ticket.category, 
        "description": security.decrypt_text(ticket.encrypted_description),
        "file_url": ticket.file_url, "messages": get_ticket_messages(db, ticket.ticket_number)
    }

@app.post("/api/tickets/message")
def user_send_message(ticket_number: str = Form(...), pin_code: str = Form(...), message: str = Form(""), file: UploadFile = File(None), db: Session = Depends(get_db)):
    ticket = db.query(models.Ticket).filter(models.Ticket.ticket_number == ticket_number).first()
    if not ticket or not security.verify_password(pin_code, ticket.hashed_pin): raise HTTPException(status_code=401)
    msg = models.Message(ticket_number=ticket_number, sender="Заявитель", encrypted_text=security.encrypt_text(message), file_url=save_file(file, "msg"))
    db.add(msg)
    db.commit()
    return {"message": "OK"}

@app.delete("/api/tickets/messages/{message_id}")
def user_delete_message(message_id: int, ticket_number: str = Header(...), pin_code: str = Header(...), db: Session = Depends(get_db)):
    ticket = db.query(models.Ticket).filter(models.Ticket.ticket_number == ticket_number).first()
    if not ticket or not security.verify_password(pin_code, ticket.hashed_pin): raise HTTPException(status_code=401)
    msg = db.query(models.Message).filter(models.Message.id == message_id, models.Message.sender == "Заявитель").first()
    if msg:
        db.delete(msg)
        db.commit()
    return {"message": "OK"}

# --- АДМИН ---
ADMIN_PASSWORD = "admin123"

@app.get("/api/admin/tickets")
def get_all_tickets(db: Session = Depends(get_db), admin_key: str = Header(None)):
    if admin_key != ADMIN_PASSWORD: raise HTTPException(status_code=403)
    tickets = db.query(models.Ticket).order_by(models.Ticket.created_at.desc()).all()
    return [{
        "ticket_number": t.ticket_number, "category": t.category, "status": t.status,
        "description": security.decrypt_text(t.encrypted_description), "file_url": t.file_url,
        "messages": get_ticket_messages(db, t.ticket_number)
    } for t in tickets]

@app.patch("/api/admin/tickets/{ticket_number}/status")
def update_status(ticket_number: str, data: StatusUpdate, db: Session = Depends(get_db), admin_key: str = Header(None)):
    if admin_key != ADMIN_PASSWORD: raise HTTPException(status_code=403)
    ticket = db.query(models.Ticket).filter(models.Ticket.ticket_number == ticket_number).first()
    ticket.status = data.status
    db.commit()
    return {"message": "OK"}

@app.post("/api/admin/tickets/{ticket_number}/message")
def admin_send_message(ticket_number: str, message: str = Form(""), file: UploadFile = File(None), db: Session = Depends(get_db), admin_key: str = Header(None)):
    if admin_key != ADMIN_PASSWORD: raise HTTPException(status_code=403)
    msg = models.Message(ticket_number=ticket_number, sender="Офицер", encrypted_text=security.encrypt_text(message), file_url=save_file(file, "admin"))
    db.add(msg)
    db.commit()
    return {"message": "OK"}

@app.delete("/api/admin/messages/{message_id}")
def admin_delete_message(message_id: int, db: Session = Depends(get_db), admin_key: str = Header(None)):
    if admin_key != ADMIN_PASSWORD: raise HTTPException(status_code=403)
    msg = db.query(models.Message).filter(models.Message.id == message_id).first()
    if msg:
        db.delete(msg)
        db.commit()
    return {"message": "OK"}

# ==========================================
# РАЗДАЧА HTML ФАЙЛОВ ДЛЯ ПОЛЬЗОВАТЕЛЕЙ
# ==========================================
@app.get("/")
def serve_index():
    return FileResponse("frontend/index.html")

@app.get("/admin")
def serve_admin():
    return FileResponse("frontend/admin.html")