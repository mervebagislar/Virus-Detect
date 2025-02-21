import os
import joblib
from django.conf import settings

# BASE_DIR, manage.py'nin bulunduğu dizini temsil eder
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODEL_DIR = settings.MODEL_DIR
PROJECT_DIR = os.path.dirname(BASE_DIR)
def load_models_and_vectorizer():
    models = {}
    vectorizer = None  # Başlangıçta `None` olarak tanımlayın

    try:
        # Tüm model dosyalarını yükleyin
        models['SVC'] = joblib.load(os.path.join(MODEL_DIR, 'SVC_model.pkl'))
        models['KNN'] = joblib.load(os.path.join(MODEL_DIR, 'KNN_model.pkl'))
        models['NB'] = joblib.load(os.path.join(MODEL_DIR, 'NB_model.pkl'))
        models['DT'] = joblib.load(os.path.join(MODEL_DIR, 'DT_model.pkl'))
        models['LR'] = joblib.load(os.path.join(MODEL_DIR, 'LR_model.pkl'))
        models['RF'] = joblib.load(os.path.join(MODEL_DIR, 'RF_model.pkl'))
        models['Adaboost'] = joblib.load(os.path.join(MODEL_DIR, 'Adaboost_model.pkl'))
        models['Bgc'] = joblib.load(os.path.join(MODEL_DIR, 'Bgc_model.pkl'))
        models['ETC'] = joblib.load(os.path.join(MODEL_DIR, 'ETC_model.pkl'))
        models['GBDT'] = joblib.load(os.path.join(MODEL_DIR, 'GBDT_model.pkl'))
        models['xgb'] = joblib.load(os.path.join(MODEL_DIR, 'xgb_model.pkl'))
    except FileNotFoundError as e:
        print(f"Model dosyası bulunamadı: {e}")

    try:
        vectorizer = joblib.load(os.path.join(MODEL_DIR, 'tfidf_vectorizer.pkl'))
    except FileNotFoundError as e:
        print(f"Vectorizer dosyası bulunamadı: {e}")

    # Dosya yollarını kontrol etmek için print ifadeleri
    print(os.path.join(BASE_DIR, 'models', 'tfidf_vectorizer.pkl'))
    print(os.path.join(BASE_DIR, 'models', 'SVC_model.pkl'))

    return models, vectorizer
