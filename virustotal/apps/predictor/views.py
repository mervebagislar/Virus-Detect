from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from .utils import load_models_and_vectorizer
from django.shortcuts import render

# Model ve vectorizer'ı lazy loading ile yükle (sadece gerektiğinde)
models = None
vectorizer = None

def get_models_and_vectorizer():
    global models, vectorizer
    if models is None or vectorizer is None:
        try:
            models, vectorizer = load_models_and_vectorizer()
        except Exception as e:
            print(f"Model yükleme hatası: {e}")
            models = {}
            vectorizer = None
    return models, vectorizer

@csrf_exempt
def predict_email(request):
    if request.method == 'GET':
        # GET isteği için email form sayfasını göster
        return render(request, "predictor/email_form.html")
    
    elif request.method == 'POST':
        try:
            email_text = request.POST.get('email_text', '')
            
            if not email_text:
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.content_type == 'application/json':
                    return JsonResponse({'error': 'Email text is required.'}, status=400)
                else:
                    return render(request, "predictor/email_form.html", {'error': 'Email text is required.'}, status=400)
            
            models, vectorizer = get_models_and_vectorizer()
            
            if vectorizer is None:
                return JsonResponse({'error': 'Vectorizer could not be loaded. Please check model files.'}, status=500)
            
            if not models:
                return JsonResponse({'error': 'Models could not be loaded. Please check model files.'}, status=500)
            
            # Email'i vectorize et
            email_vector = vectorizer.transform([email_text])
            email_vector_dense = email_vector.toarray()
            
            # Tahminleri yap
            predictions = {}
            for name, clf in models.items():
                try:
                    prediction = clf.predict(email_vector_dense)[0]
                    predictions[name] = 'spam' if prediction == 1 else 'ham'
                except Exception as e:
                    print(f"Model {name} tahmin hatası: {e}")
                    predictions[name] = 'error'
            
            # Yüzdelik hesaplama
            total_models = len(predictions)
            spam_count = sum(1 for p in predictions.values() if p == 'spam')
            ham_count = sum(1 for p in predictions.values() if p == 'ham')
            spam_percentage = (spam_count / total_models * 100) if total_models > 0 else 0
            ham_percentage = (ham_count / total_models * 100) if total_models > 0 else 0
            
            # AJAX isteği mi kontrol et
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.content_type == 'application/json':
                return JsonResponse({
                    'success': True,
                    'predictions': predictions,
                    'email_text': email_text,
                    'spam_count': spam_count,
                    'ham_count': ham_count,
                    'spam_percentage': round(spam_percentage, 2),
                    'ham_percentage': round(ham_percentage, 2),
                    'total_models': total_models
                })
            else:
                # Normal form submit - template render
                context = {
                    'predictions': predictions,
                    'email_text': email_text,
                    'spam_count': spam_count,
                    'ham_count': ham_count,
                    'spam_percentage': round(spam_percentage, 2),
                    'ham_percentage': round(ham_percentage, 2),
                    'total_models': total_models
                }
                return render(request, "predictor/email_form.html", context)
            
        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            print(f"Predict email error: {error_trace}")
            return JsonResponse({
                'error': f'An error occurred: {str(e)}',
                'details': error_trace if settings.DEBUG else None
            }, status=500)
    else:
        return JsonResponse({'error': 'Only GET and POST methods are allowed.'}, status=405)
