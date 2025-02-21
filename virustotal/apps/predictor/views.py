from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .utils import load_models_and_vectorizer
from django.shortcuts import render

# Model ve vectorizer'ı yükle
models, vectorizer = load_models_and_vectorizer()

@csrf_exempt
def predict_email(request):
    if request.method == 'POST':
        email_text = request.POST.get('email_text', '')
        
        if email_text:
            email_vector = vectorizer.transform([email_text])
            # Dönüştürme işlemi: dense formata çevrim
            email_vector_dense = email_vector.toarray()
            predictions = {}
            for name, clf in models.items():
                prediction = clf.predict(email_vector_dense)[0]
                predictions[name] = 'spam' if prediction == 1 else 'ham'
            
            return render(request, "predictor/email_form.html", {"predictions": predictions, 'email_text': email_text})
        else:
            return render(request, "predictor/email_form.html", {'error': 'No email text provided.'}, status=400)
    else:
        return render(request, "predictor/email_form.html", {'error': 'Invalid request method.'}, status=405)
