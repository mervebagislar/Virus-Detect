#!/usr/bin/env python
"""Django superuser oluşturma scripti"""
import os
import sys
import django
import getpass

# Django ayarlarını yükle
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from django.contrib.auth import get_user_model

User = get_user_model()

def create_superuser(username=None, email=None, password=None):
    print("=" * 50)
    print("Yeni Admin Kullanıcısı Oluşturma")
    print("=" * 50)
    
    # Komut satırı argümanları kontrol et
    if len(sys.argv) > 1:
        username = sys.argv[1] if not username else username
        email = sys.argv[2] if len(sys.argv) > 2 and not email else email
        password = sys.argv[3] if len(sys.argv) > 3 and not password else password
    
    # Kullanıcı adı al
    if not username:
        try:
            username = input("Kullanıcı adı: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nİşlem iptal edildi.")
            return
        if not username:
            print("Hata: Kullanıcı adı boş olamaz!")
            return
    
    # Email al
    if not email:
        try:
            email = input("E-posta adresi: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nİşlem iptal edildi.")
            return
        if not email:
            email = f"{username}@example.com"
            print(f"E-posta boş bırakıldı, varsayılan: {email}")
    
    # Şifre al
    if not password:
        while True:
            try:
                password = getpass.getpass("Şifre: ")
            except (EOFError, KeyboardInterrupt):
                print("\nİşlem iptal edildi.")
                return
            if not password:
                print("Hata: Şifre boş olamaz!")
                continue
            
            try:
                password_confirm = getpass.getpass("Şifre (tekrar): ")
            except (EOFError, KeyboardInterrupt):
                print("\nİşlem iptal edildi.")
                return
            if password != password_confirm:
                print("Hata: Şifreler eşleşmiyor! Tekrar deneyin.")
                continue
            break
    
    # Kullanıcı zaten var mı kontrol et
    if User.objects.filter(username=username).exists():
        print(f'\n⚠️  Kullanıcı "{username}" zaten mevcut!')
        try:
            response = input("Şifresini güncellemek ister misiniz? (e/h): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nİşlem iptal edildi.")
            return
        if response == 'e':
            user = User.objects.get(username=username)
            user.set_password(password)
            user.email = email
            user.is_staff = True
            user.is_superuser = True
            user.save()
            print(f'✅ Kullanıcı "{username}" güncellendi ve şifre değiştirildi.')
        else:
            print("İşlem iptal edildi.")
            return
    else:
        # Yeni superuser oluştur
        try:
            User.objects.create_superuser(username=username, email=email, password=password)
            print(f'✅ Superuser "{username}" başarıyla oluşturuldu!')
        except Exception as e:
            print(f'❌ Hata: {str(e)}')
            return
    
    print(f'\n📋 Giriş bilgileri:')
    print(f'   Kullanıcı adı: {username}')
    print(f'   E-posta: {email}')
    print(f'   Şifre: {"*" * len(password)}')
    print(f'\n🌐 Admin paneline giriş: http://127.0.0.1:8000/admin/')
    print("=" * 50)

if __name__ == "__main__":
    create_superuser()

