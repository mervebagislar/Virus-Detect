import os
import joblib
from django.conf import settings

# BASE_DIR, manage.py'nin bulunduğu dizini temsil eder
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODEL_DIR = settings.MODEL_DIR
PROJECT_DIR = os.path.dirname(BASE_DIR)
def load_models_and_vectorizer():
    models = {}
    vectorizer = None

    # Model dizinini kontrol et
    if not os.path.exists(MODEL_DIR):
        print(f"Model dizini bulunamadı: {MODEL_DIR}")
        return models, vectorizer

    model_files = {
        'SVC': 'SVC_model.pkl',
        'KNN': 'KNN_model.pkl',
        'NB': 'NB_model.pkl',
        'DT': 'DT_model.pkl',
        'LR': 'LR_model.pkl',
        'RF': 'RF_model.pkl',
        'Adaboost': 'Adaboost_model.pkl',
        'Bgc': 'Bgc_model.pkl',
        'ETC': 'ETC_model.pkl',
        'GBDT': 'GBDT_model.pkl',
        'xgb': 'xgb_model.pkl'
    }

    # Model dosyalarını yükle
    for model_name, filename in model_files.items():
        model_path = os.path.join(MODEL_DIR, filename)
        try:
            if os.path.exists(model_path):
                models[model_name] = joblib.load(model_path)
                print(f"Model yüklendi: {model_name}")
            else:
                print(f"Model dosyası bulunamadı: {model_path}")
        except Exception as e:
            print(f"Model {model_name} yüklenirken hata: {e}")

    # Vectorizer'ı yükle
    vectorizer_path = os.path.join(MODEL_DIR, 'tfidf_vectorizer.pkl')
    try:
        if os.path.exists(vectorizer_path):
            vectorizer = joblib.load(vectorizer_path)
            print(f"Vectorizer yüklendi: {vectorizer_path}")
        else:
            print(f"Vectorizer dosyası bulunamadı: {vectorizer_path}")
    except Exception as e:
        print(f"Vectorizer yüklenirken hata: {e}")

    return models, vectorizer
