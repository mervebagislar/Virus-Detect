import requests
from django.conf import settings


def send_message_to_chat(message):
    API_KEY = settings.GEMINI_API_KEY
    
    if not API_KEY:
        raise ValueError("GEMINI_API_KEY environment variable is not set")
    
    API_URL = f'https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent?key={API_KEY}'
    
    headers = {
        'Authorization': f'Bearer {API_KEY}',
        'Content-Type': 'application/json',
    }
    payload = {
        'messages': [{'role': 'user', 'content': message}]
    }
    response = requests.post(API_URL, json=payload, headers=headers)
    response.raise_for_status()  # Hata durumunda istisna fırlat
    return response.json()
