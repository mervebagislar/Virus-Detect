import requests


API_KEY = 'AIzaSyA7kI6gVlyf7Vu9bUXubGH4u7BFLbiBXxI'
API_URL = f'https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent?key={API_KEY}'   # Gerçek API URL'sini kullanın

def send_message_to_chat(message):
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
