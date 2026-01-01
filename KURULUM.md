# Virus-Detect Projesi Kurulum ve Çalıştırma Rehberi

## Gereksinimler
- Python 3.8 veya üzeri
- pip (Python paket yöneticisi)
- Virtual environment (önerilir)

## Kurulum Adımları

### 1. Proje Dizinine Gidin
```bash
cd virustotal
```

### 2. Virtual Environment Oluşturun (Önerilir)
```bash
# Windows
python -m venv venv

# Virtual environment'ı aktifleştirin
# Windows PowerShell
.\venv\Scripts\Activate.ps1

# Windows CMD
venv\Scripts\activate.bat
```

### 3. Bağımlılıkları Yükleyin
```bash
pip install -r requirements.txt
```

### 4. Veritabanı Migrasyonlarını Çalıştırın
```bash
python manage.py makemigrations
python manage.py migrate
```

### 5. Süper Kullanıcı Oluşturun (Admin Paneli İçin)
```bash
python manage.py createsuperuser
```
Kullanıcı adı, e-posta ve şifre girmeniz istenecektir.

### 6. Static Dosyaları Toplayın
```bash
python manage.py collectstatic --noinput
```

### 7. Sunucuyu Başlatın
```bash
python manage.py runserver
```

Sunucu başladıktan sonra tarayıcınızda şu adrese gidin:
- **Ana Sayfa**: http://127.0.0.1:8000/
- **Admin Paneli**: http://127.0.0.1:8000/admin/

---

## Yöntem 2: Docker ile Çalıştırma

### 1. Docker ve Docker Compose Kurulu Olmalı

### 2. .env Dosyası Oluşturun (İsteğe Bağlı)
Proje kök dizininde `.env` dosyası oluşturabilirsiniz. Varsayılan ayarlar ile çalışır.

### 3. Docker Container'ları Başlatın
```bash
cd virustotal
docker-compose up --build
```

### 4. Veritabanı Migrasyonlarını Çalıştırın
Yeni bir terminal açın ve:
```bash
docker-compose exec appseed-app python manage.py migrate
docker-compose exec appseed-app python manage.py createsuperuser
```

Uygulama şu adreste çalışacaktır:
- http://localhost:5085

---

## Sorun Giderme

### Port Zaten Kullanılıyor Hatası
Farklı bir port kullanmak için:
```bash
python manage.py runserver 8001
```

### Bağımlılık Hataları
```bash
pip install --upgrade pip
pip install -r requirements.txt --force-reinstall
```

### Veritabanı Hataları
```bash
# Veritabanını sıfırlamak için (dikkatli kullanın!)
python manage.py flush
python manage.py migrate
```

### Static Dosyalar Görünmüyor
```bash
python manage.py collectstatic
```

---

## Notlar
- Proje varsayılan olarak SQLite veritabanı kullanır
- MySQL kullanmak isterseniz `.env` dosyasında `DB_ENGINE=mysql` ayarlayın
- Admin panelinde 2FA (İki Faktörlü Doğrulama) özelliği mevcuttur
- API anahtarları için `.env` dosyasına bakın (OTX, OpenAI, VirusTotal)

## Önemli Düzeltmeler
Projede yapılan düzeltmeler:
- Model yükleme işlemi lazy loading'e çevrildi (sadece gerektiğinde yüklenir)
- OpenAI import'u lazy hale getirildi (başlangıçta hata vermez)
- Numpy uyumluluk sorunları için hata yönetimi eklendi

## Eksik Bağımlılıklar
Proje çalışırken aşağıdaki paketler gerekebilir (requirements.txt'de yoksa):
```bash
pip install openai requests python-whois joblib scikit-learn numpy
```

