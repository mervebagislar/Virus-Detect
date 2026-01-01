# 🛡️ Virus Detect - Güvenlik Analiz ve Tehdit Tespit Sistemi

<div align="center">

![Virus Detect](apps/static/assets/readMe-img/whitemode.png)

**Kapsamlı güvenlik analiz platformu - Dosya, IP, URL analizi ve Email spam tespiti**

[![Django](https://img.shields.io/badge/Django-3.2.16-green.svg)](https://www.djangoproject.com/)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## 📋 İçindekiler

- [Genel Bakış](#-genel-bakış)
- [Özellikler](#-özellikler)
- [Teknolojiler](#-teknolojiler)
- [Kurulum](#-kurulum)
- [API Entegrasyonları](#-api-entegrasyonları)
- [Machine Learning Modelleri](#-machine-learning-modelleri)
- [İki Faktörlü Doğrulama](#-iki-faktörlü-doğrulama)
- [Ekran Görüntüleri](#-ekran-görüntüleri)
- [Kullanım](#-kullanım)
- [Katkıda Bulunma](#-katkıda-bulunma)
- [Lisans](#-lisans)

---

## 🎯 Genel Bakış

**Virus Detect**, siber güvenlik uzmanları ve geliştiriciler için tasarlanmış kapsamlı bir güvenlik analiz platformudur. Sistem, dosya analizi, IP adresi tehdit istihbaratı, URL analizi ve email spam tespiti gibi çoklu güvenlik hizmetlerini tek bir platformda birleştirir.

### Ana Özellikler

- 🔍 **Dosya Analizi**: VirusTotal ve OTX API'leri ile dosya güvenlik analizi
- 🌐 **IP Tehdit İstihbaratı**: IP adresleri için detaylı güvenlik analizi
- 🔗 **URL Analizi**: Şüpheli URL'lerin güvenlik kontrolü
- 📧 **Email Spam Tespiti**: 10 farklı ML modeli ile email spam tespiti
- 🔐 **İki Faktörlü Doğrulama**: Admin paneli için güvenli giriş

---

## ✨ Özellikler

### 🔒 Güvenlik Özellikleri

- **İki Faktörlü Doğrulama (2FA)**: Admin paneli için TOTP tabanlı 2FA desteği
- **Güvenli Kimlik Doğrulama**: Django'nun güvenli authentication sistemi
- **CSRF Koruması**: Tüm formlar için CSRF token koruması
- **API Key Yönetimi**: Hassas bilgiler için environment variable desteği

### 📊 Analiz Özellikleri

- **Çoklu Motor Analizi**: VirusTotal'ın 70+ antivirüs motoru ile dosya analizi
- **Tehdit İstihbaratı**: OTX AlienVault ile entegre tehdit veritabanı
- **Detaylı Raporlama**: Kapsamlı analiz sonuçları ve görselleştirme
- **Gerçek Zamanlı Analiz**: Asenkron analiz işleme ve sonuç takibi

### 🤖 Machine Learning

- **10 Farklı ML Modeli**: Ensemble learning ile yüksek doğruluk oranı
- **TF-IDF Vectorization**: Gelişmiş metin özellik çıkarımı
- **Yüzdelik Tahmin**: Model konsensüsü ile spam olasılık hesaplama

---

## 🛠️ Teknolojiler

### Backend

- **Django 3.2.16**: Web framework
- **Python 3.8+**: Programlama dili
- **SQLite/PostgreSQL**: Veritabanı
- **Django REST Framework**: API geliştirme (opsiyonel)

### Frontend

- **HTML5/CSS3**: Modern web standartları
- **JavaScript (ES6+)**: İnteraktif kullanıcı arayüzü
- **jQuery**: DOM manipülasyonu ve AJAX işlemleri
- **Bootstrap**: Responsive tasarım framework'ü
- **DataTables**: Gelişmiş tablo görselleştirme
- **Font Awesome**: İkon kütüphanesi

### Machine Learning

- **scikit-learn**: ML model eğitimi ve tahmin
- **joblib**: Model serialization
- **TF-IDF**: Metin vektörleştirme
- **NumPy/Pandas**: Veri işleme

### API Entegrasyonları

- **VirusTotal API v3**: Dosya ve IP analizi
- **OTX AlienVault API**: Tehdit istihbaratı


### Güvenlik

- **django-environ**: Environment variable yönetimi
- **django-two-factor-auth**: 2FA implementasyonu
- **jquery-confirm**: Modal dialog'lar

---

## 🚀 Kurulum

### Gereksinimler

- Python 3.8 veya üzeri
- pip (Python paket yöneticisi)
- Git

### Adım 1: Projeyi Klonlayın

```bash
git clone https://github.com/yourusername/virus-detect.git
cd virus-detect/virustotal
```

### Adım 2: Virtual Environment Oluşturun

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

### Adım 3: Bağımlılıkları Yükleyin

```bash
pip install -r requirements.txt
```

### Adım 4: Environment Variables Ayarlayın

`.env` dosyası oluşturun ve aşağıdaki değişkenleri ekleyin:

```env
SECRET_KEY=your-secret-key-here
DEBUG=True
OTX_API_KEY=your-otx-api-key
VT_API_KEY=your-virustotal-api-key
GEMINI_API_KEY=your-gemini-api-key
```

**API Key'leri Nasıl Alınır?**

- **VirusTotal**: [https://www.virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us)
- **OTX AlienVault**: [https://otx.alienvault.com/api](https://otx.alienvault.com/api)
- **Google Gemini**: [https://makersuite.google.com/app/apikey](https://makersuite.google.com/app/apikey)

### Adım 5: Veritabanını Oluşturun

```bash
python manage.py migrate
```

### Adım 6: Superuser Oluşturun

```bash
python create_superuser.py <username> <email> <password>
```

veya

```bash
python manage.py createsuperuser
```

### Adım 7: Static Dosyaları Toplayın

```bash
python manage.py collectstatic --noinput
```

### Adım 8: Sunucuyu Başlatın

```bash
python manage.py runserver
```

Tarayıcınızda [http://127.0.0.1:8000](http://127.0.0.1:8000) adresine gidin.

---

## 🔌 API Entegrasyonları

### 1. VirusTotal API

VirusTotal API, dosya ve IP adresi analizi için kullanılır. Sistem şu özellikleri sağlar:

- **Dosya Yükleme ve Analiz**: Dosyaları VirusTotal'a yükler ve 70+ antivirüs motoru ile analiz eder
- **IP Adresi Analizi**: IP adreslerinin güvenlik geçmişini kontrol eder
- **Detaylı Raporlama**: Analiz sonuçlarını kategorize eder (malicious, suspicious, clean, undetected)

**Kullanım Örneği:**

```python
# Dosya analizi
vt_upload_url = 'https://www.virustotal.com/api/v3/files'
vt_headers = {'x-apikey': settings.VT_API_KEY}
response = requests.post(vt_upload_url, headers=vt_headers, files=files)
```

### 2. OTX AlienVault API

OTX (Open Threat Exchange) API, tehdit istihbaratı için kullanılır:

- **IP Tehdit Bilgileri**: IP adresleri için pulse bilgileri
- **Dosya Hash Analizi**: Dosya hash'leri için tehdit veritabanı sorgusu
- **URL Analizi**: Şüpheli URL'lerin kontrolü

**Kullanım Örneği:**

```python
otx_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
otx_headers = {'X-OTX-API-KEY': settings.OTX_API_KEY}
response = requests.get(otx_url, headers=otx_headers)
```

### 3. Google Gemini API

Google Gemini API, AI chatbot özelliği için kullanılır:

- **Doğal Dil İşleme**: Kullanıcı sorularını anlama ve yanıtlama
- **Güvenlik Danışmanlığı**: Güvenlik konularında yardımcı bilgi sağlama

**Kullanım Örneği:**

```python
gemini_url = f'https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent?key={API_KEY}'
response = requests.post(gemini_url, json={'contents': [{'parts': [{'text': message}]}]})
```

---

## 🤖 Machine Learning Modelleri

Sistem, email spam tespiti için **10 farklı makine öğrenmesi modeli** kullanır. Her model bağımsız olarak tahmin yapar ve sonuçlar birleştirilerek nihai karar verilir.

### Kullanılan Modeller

1. **SVC (Support Vector Classifier)**: Yüksek doğruluk oranı
2. **KNN (K-Nearest Neighbors)**: Benzerlik tabanlı sınıflandırma
3. **NB (Naive Bayes)**: Olasılık tabanlı sınıflandırma
4. **DT (Decision Tree)**: Kural tabanlı karar ağacı
5. **LR (Logistic Regression)**: İstatistiksel sınıflandırma
6. **RF (Random Forest)**: Ensemble learning
7. **Adaboost**: Adaptive boosting
8. **Bgc (Bagging Classifier)**: Bootstrap aggregating
9. **ETC (Extra Trees Classifier)**: Extremely randomized trees
10. **GBDT (Gradient Boosting Decision Tree)**: Gradient boosting
11. **XGBoost**: Extreme gradient boosting

### Model Eğitimi

Modeller, TF-IDF (Term Frequency-Inverse Document Frequency) vektörleştirme tekniği kullanılarak eğitilmiştir. Email metinleri önce vektörlere dönüştürülür, sonra her model tarafından analiz edilir.

### Tahmin Sistemi

```python
# Email vektörleştirme
email_vector = vectorizer.transform([email_text])

# Her model için tahmin
predictions = {}
for name, model in models.items():
    prediction = model.predict(email_vector)[0]
    predictions[name] = 'spam' if prediction == 1 else 'ham'

# Konsensüs hesaplama
spam_count = sum(1 for p in predictions.values() if p == 'spam')
spam_percentage = (spam_count / total_models * 100)
```

### Model Performansı

Sistem, tüm modellerin tahminlerini birleştirerek daha güvenilir sonuçlar üretir. Eğer modellerin %70'i spam olarak işaretlerse, email spam olarak kabul edilir.

---

## 🔐 İki Faktörlü Doğrulama

Sistem, admin paneli için **TOTP (Time-based One-Time Password)** tabanlı iki faktörlü doğrulama desteği sunar.

### Özellikler

- **QR Kod ile Aktivasyon**: Google Authenticator veya benzeri uygulamalarla kolay kurulum
- **Backup Kodlar**: Acil durumlar için yedek kodlar
- **Güvenli Giriş**: Kullanıcı adı/şifre + 6 haneli kod ile çift katmanlı güvenlik

### Kurulum

1. Admin paneline giriş yapın
2. Profil ayarlarından "Two-Factor Authentication" seçeneğini açın
3. QR kodu telefonunuzdaki authenticator uygulamasına tarayın
4. Doğrulama kodunu girin

### Kullanım

Giriş yaparken:
1. Kullanıcı adı ve şifrenizi girin
2. Authenticator uygulamanızdan 6 haneli kodu girin
3. Başarıyla giriş yapın

![2FA Login](apps/static/assets/readMe-img/login.png)

---

## 📸 Ekran Görüntüleri

### Ana Sayfa ve Giriş

<div align="center">

![Login Page](apps/static/assets/readMe-img/giriş.png)
*Giriş Sayfası*

![Signup Page](apps/static/assets/readMe-img/signup.png)
*Kayıt Sayfası*

</div>

### Dosya Analizi

<div align="center">

![File Analysis](apps/static/assets/readMe-img/analiz_file.png)
*Dosya Yükleme ve Analiz*

![File Analysis Results](apps/static/assets/readMe-img/analiz_file1.png)
*Detaylı Analiz Sonuçları*

![File Analysis Details](apps/static/assets/readMe-img/analiz_file2.png)
*Dosya Özellikleri ve Hash Bilgileri*

![File Analysis Table](apps/static/assets/readMe-img/analiz_file3.png)
*Antivirüs Motor Sonuçları Tablosu*

</div>

### IP Adresi Analizi

<div align="center">

![IP Analysis](apps/static/assets/readMe-img/analiz_ip.png)
*IP Adresi Analiz Sayfası*

![IP Analysis Results](apps/static/assets/readMe-img/analiz_ip2.png)
*IP Tehdit İstihbaratı*

![IP Analysis Details](apps/static/assets/readMe-img/analiz_ip3.png)
*Detaylı IP Bilgileri*

![IP Analysis Map](apps/static/assets/readMe-img/analiz_ip4.png)
*Coğrafi Konum Bilgisi*

![IP Analysis Stats](apps/static/assets/readMe-img/analiz_ip5.png)
*İstatistiksel Analiz*

</div>

### Email Spam Tespiti

<div align="center">

![Email Spam Detection](apps/static/assets/readMe-img/email.png)
*Email Spam Tespit Arayüzü*

</div>

### Admin Paneli

<div align="center">

![Admin Panel](apps/static/assets/readMe-img/admin.png)
*Admin Panel Ana Sayfa*

![Admin Settings](apps/static/assets/readMe-img/admin1.png)
*Admin Ayarları*

![Admin Users](apps/static/assets/readMe-img/admin2.png)
*Kullanıcı Yönetimi*

![Admin Dashboard](apps/static/assets/readMe-img/admin3.png)
*Dashboard ve İstatistikler*

</div>

### Kullanıcı Profili

<div align="center">

![User Profile](apps/static/assets/readMe-img/profile.png)
*Kullanıcı Profil Sayfası*

</div>

---

## 💻 Kullanım

### Dosya Analizi

1. Ana sayfada "Dosya Yükle" butonuna tıklayın
2. Analiz etmek istediğiniz dosyayı seçin
3. Sistem dosyayı VirusTotal'a yükler ve analiz eder
4. Analiz sonuçları detaylı bir şekilde gösterilir

### IP Adresi Analizi

1. Ana sayfada IP adresini girin
2. "Ara" butonuna tıklayın
3. Sistem IP adresi hakkında detaylı bilgi sağlar:
   - Tehdit istihbaratı
   - WHOIS bilgileri
   - Coğrafi konum
   - Güvenlik skorları

### Email Spam Tespiti

1. Email analiz sayfasına gidin
2. Email metnini yapıştırın
3. "Analiz Et" butonuna tıklayın
4. 10 farklı ML modelinin tahminlerini görüntüleyin
5. Spam olasılık yüzdesini kontrol edin


---

## 📁 Proje Yapısı

```
virustotal/
├── apps/
│   ├── authentication/      # Kullanıcı kimlik doğrulama
│   ├── home/                  # Ana sayfa ve analiz view'ları
│   ├── predictor/             # ML model yönetimi
│   ├── admin_two_factor/      # 2FA implementasyonu
│   ├── models/                # Eğitilmiş ML modelleri
│   ├── static/                # CSS, JS, resimler
│   └── templates/             # HTML şablonları
├── core/                      # Django ayarları
├── manage.py                  # Django yönetim scripti
├── requirements.txt           # Python bağımlılıkları
└── README.md                  # Bu dosya
```

---

## 🔧 Geliştirme

### Test Çalıştırma

```bash
python manage.py test
```

### Yeni Model Ekleme

1. Model dosyasını `apps/models/` klasörüne ekleyin
2. `apps/predictor/utils.py` dosyasına model adını ekleyin
3. Modeli yüklemek için `load_models_and_vectorizer()` fonksiyonunu güncelleyin

### API Endpoint Ekleme

1. `apps/home/views.py` dosyasına yeni view ekleyin
2. `apps/home/urls.py` dosyasına URL pattern ekleyin
3. Gerekli template'i oluşturun

---

## 🤝 Katkıda Bulunma

Katkılarınızı bekliyoruz! Lütfen şu adımları izleyin:

1. Projeyi fork edin
2. Feature branch oluşturun (`git checkout -b feature/AmazingFeature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add some AmazingFeature'`)
4. Branch'inizi push edin (`git push origin feature/AmazingFeature`)
5. Pull Request oluşturun


---

## 👥 Yazar

**Virus Detect Development Team**

- GitHub: [@mervebagislar](https://github.com/mervebagislar)
- Email: mervebagislar07@gmail.com

---

## 🙏 Teşekkürler

- [VirusTotal](https://www.virustotal.com/) - Dosya ve IP analizi API'si
- [OTX AlienVault](https://otx.alienvault.com/) - Tehdit istihbaratı platformu
- [Django](https://www.djangoproject.com/) - Web framework
- [scikit-learn](https://scikit-learn.org/) - Machine learning kütüphanesi

---

## 📞 İletişim

Sorularınız veya önerileriniz için:
- Email: mervebagislar07@gmail.com
- https://mervebagislar.com
---

<div align="center">

**⭐ Bu projeyi beğendiyseniz yıldız vermeyi unutmayın! ⭐**

Made with ❤️ by Merve Bağışlar

</div>
