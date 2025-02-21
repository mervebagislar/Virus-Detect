from datetime import datetime
import hashlib
import os
import time
import whois
from django import template
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.template import loader
from django.urls import reverse
from django.core.files.storage import FileSystemStorage
import requests
import openai
from django.views.decorators.csrf import csrf_exempt
from dotenv import load_dotenv


@login_required(login_url="/login/")#Kullanıcının giriş yapması gerekir
def notification_view(request):
    return render(request, 'home/notifications.html') 
load_dotenv()
openai.api_key = settings.OPENAI_API_KEY

def chatbot(request):
    if request.method == 'POST':
        user_message = request.POST.get('message', '')

        try:
            # OpenAI API'ye istek gönder
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a helpful assistant."},  # Sistem mesajı
                    {"role": "user", "content": user_message}
                ]
            )

            # OpenAI'nin yanıtını al
            bot_reply = response.choices[0].message['content'].strip()

            # Yanıtı JSON olarak döndür
            return JsonResponse({'response': bot_reply})

        except Exception as e:
            return JsonResponse({'response': f'Bir hata oluştu: {str(e)}'})

    return JsonResponse({'response': 'Geçersiz istek.'})

@login_required(login_url="/login/")#Kullanıcının giriş yapması gerekir
def index(request):
    context = {'segment': 'index'}#Segment verisi gönderiliyor

    html_template = loader.get_template('home/index.html')#indexi yükler
    return HttpResponse(html_template.render(context, request))

def file_upload(request):
    return render(request, "home/file-upload.html")
@login_required(login_url="/login/")

def get_ip_threat_intel(request):
    if request.method == 'POST':
        ip_address = request.POST.get('ip_address')
        
        if ip_address:
            # OTX API'den tehdit bilgilerini al
            otx_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
            otx_response = requests.get(otx_url, headers={'X-OTX-API-KEY': settings.OTX_API_KEY})
            otx_data = otx_response.json() if otx_response.status_code == 200 else {}
            
            # VirusTotal API'den tehdit bilgilerini al
            vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
            vt_headers = {'x-apikey': settings.VIRUSTOTAL_API_KEY}
            vt_response = requests.get(vt_url, headers=vt_headers)
            vt_data = vt_response.json() if vt_response.status_code == 200 else {}

            # 'last_analysis_results' içindeki analiz sonuçlarını alma
            analysis_results = vt_data.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
            
            # Sonuçları listelemek için
            analysis_list = []
            for engine, result in analysis_results.items():
                analysis_list.append({
                    'engine_name': result.get('engine_name', 'N/A'),
                    'result': result.get('result', 'N/A'),
                    'category': result.get('category', 'N/A'),
                })

            # Sonuçları öncelik sırasına göre sıralayın
            result_order = {'malicious': 0, 'suspicious': 1, 'clean': 2, 'unrated': 3}
            analysis_list = sorted(analysis_list, key=lambda x: result_order.get(x['result'], 4))

            # WHOIS bilgilerini al
            try:
                whois_data_raw = whois.whois(ip_address)
                # Sadece temel bilgileri seçin
                whois_data = {
                    'registrar': whois_data_raw.registrar or 'N/A',
                    'creation_date': (whois_data_raw.creation_date[0].strftime('%Y-%m-%d %H:%M:%S') 
                                      if isinstance(whois_data_raw.creation_date, list) 
                                      and whois_data_raw.creation_date else 'N/A'),
                    'expiration_date': (whois_data_raw.expiration_date[0].strftime('%Y-%m-%d %H:%M:%S') 
                                        if isinstance(whois_data_raw.expiration_date, list) 
                                        and whois_data_raw.expiration_date else 'N/A'),
                    'name_servers': whois_data_raw.name_servers or 'N/A',
                    'status': whois_data_raw.status or 'N/A'
                }
            except Exception as e:
                whois_data = f"WHOIS bilgileri alınamadı: {str(e)}"
            # Ülke kodunu al ve bayrak URL'sini oluştur
            otx_country_code = otx_data.get('country_code', 'N/A').lower()  # Ülke kodunu al ve küçük harfe çevir
            otx_flag_url = f"https://flagcdn.com/16x12/{otx_country_code}.png"  # Bayrak URL'sini oluştur

            crowdsourced_context = vt_data.get('data', {}).get('attributes', {}).get('crowdsourced_context', [])
            # vt_certificate_policies_context= vt_data.get('data', {}).get('attributes', {}).get('last_https_certificate', {}).get('extensions',{}).get('certificate_policies',[]),

            # Check if 'crowdsourced_context' is a list and contains elements
            if isinstance(crowdsourced_context, list) and len(crowdsourced_context) > 0:
                vt_details = crowdsourced_context[0].get('details', 'N/A')
                vt_severity = crowdsourced_context[0].get('severity', 'N/A')
                vt_timestamp = crowdsourced_context[0].get('timestamp', 'N/A')
                vt_title = crowdsourced_context[0].get('title', 'N/A')
            else:
                vt_details = vt_severity = vt_timestamp = vt_title = 'N/A'
            
         
            # Template'e gönderilecek verileri hazırla
            context = {
                # OTX verileri
                'otx_ip_address': otx_data.get('indicator', 'N/A'),
                'otx_country_name': otx_data.get('country_name', 'N/A'),
                'otx_type': otx_data.get("type", 'N/A'),
                'otx_city': otx_data.get('city', 'N/A'),
                'otx_region': otx_data.get('region', 'N/A'),
                'otx_asn': otx_data.get('asn', 'N/A').title(),
                'otx_reputation': otx_data.get('reputation', 'N/A'),
                'otx_latitude': otx_data.get('latitude', 'N/A'),
                'otx_longitude': otx_data.get('longitude', 'N/A'),
                'otx_pulse_info': otx_data.get('pulse_info', {}),
                'otx_continent_code': otx_data.get('continent_code', 'N/A'),
                'otx_country_code': otx_country_code,  # Ülke kodunu zaten aldık ve küçük harfe çevirdik
                'otx_flag_url': otx_flag_url,

                # VirusTotal verileri
                'vt_ip_address': vt_data.get('data', {}).get('id', 'N/A'),
                'vt_type': vt_data.get('data', {}).get('type', 'N/A'),
                'vt_continent': vt_data.get('data', {}).get('attributes', {}).get('continent', 'N/A'),
                'vt_as_owner': vt_data.get('data', {}).get('attributes', {}).get('as_owner', 'N/A'),
                'vt_country': vt_data.get('data', {}).get('attributes', {}).get('country', 'N/A'),
                'vt_network': vt_data.get('data', {}).get('attributes', {}).get('network', 'N/A'),
                'vt_rir': vt_data.get('data', {}).get('attributes', {}).get('regional_internet_registry', 'N/A'),
                'vt_malicious': vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 'N/A'),
                'vt_suspicious': vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('suspicious', 'N/A'),
                'vt_undetected': vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('undetected', 'N/A'),
                'vt_harmless': vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('harmless', 'N/A'),
                'vt_timeout': vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('timeout', 'N/A'),
                'vt_details': vt_details,
                'vt_severity': vt_severity,
                'vt_timestamp': vt_timestamp,
                'vt_title': vt_title,
                'vt_reputation': vt_data.get('data', {}).get('attributes', {}).get('reputation', 'N/A'),
                'vt_jarm': vt_data.get('data', {}).get('attributes', {}).get('jarm', 'N/A'),
                'vt_signature_algorithm': vt_data.get('data', {}).get('attributes', {}).get('last_https_certificate', {}).get('cert_signature',{}).get('signature_algorithm'),
                'vt_signature': vt_data.get('data', {}).get('attributes', {}).get('last_https_certificate', {}).get('cert_signature',{}).get('signature'),
                'vt_key_usage': vt_data.get('data', {}).get('attributes', {}).get('last_https_certificate', {}).get('extensions',{}).get('key_usage'),
                'vt_extended_key_usage': vt_data.get('data', {}).get('attributes', {}).get('last_https_certificate', {}).get('extensions',{}).get('extended_key_usage'),
                'vt_CA': vt_data.get('data', {}).get('attributes', {}).get('last_https_certificate', {}).get('extensions',{}).get('CA'),
                'vt_subject_key_identifier': vt_data.get('data', {}).get('attributes', {}).get('last_https_certificate', {}).get('extensions',{}).get('subject_key_identifier'),
                'vt_keyid': vt_data.get('data', {}).get('attributes', {}).get('last_https_certificate', {}).get('extensions',{}).get('authority_key_identifier',{}).get('keyid'),
                'vt_OCSP': vt_data.get('data', {}).get('attributes', {}).get('last_https_certificate', {}).get('extensions',{}).get('ca_information_access',{}).get('OCSP'),
                'vt_Issuers': vt_data.get('data', {}).get('attributes', {}).get('last_https_certificate', {}).get('extensions',{}).get('ca_information_access',{}).get('CA Issuers'),
                'vt_subject_alternative_name': vt_data.get('data', {}).get('attributes', {}).get('last_https_certificate', {}).get('extensions',{}).get('subject_alternative_name',{}),
                'vt_certificate_policies': vt_data.get('data', {}).get('attributes', {}).get('last_https_certificate', {}).get('extensions',{}).get('certificate_policies',[0]),
                'vt_crl_distribution_points': vt_data.get('data', {}).get('attributes', {}).get('last_https_certificate', {}).get('extensions',{}).get('crl_distribution_points'),
                'vt_algorithm': vt_data.get('data', {}).get('attributes', {}).get('last_https_certificate', {}).get('public_key',{}).get('algorithm'),
                'vt_modulus': vt_data.get('data', {}).get('attributes', {}).get('last_https_certificate', {}).get('public_key',{}).get('rsa',{}).get('modulus'),
                'vt_exponent': vt_data.get('data', {}).get('attributes', {}).get('last_https_certificate', {}).get('public_key',{}).get('rsa',{}).get('exponent'),
                'vt_key_size': vt_data.get('data', {}).get('attributes', {}).get('last_https_certificate', {}).get('public_key',{}).get('rsa',{}).get('key_size'),
                'vt_thumbprint_sha256': vt_data.get('data', {}).get('attributes', {}).get('last_https_certificate', {}).get('thumbprint_sha256'),
                'vt_thumbprint': vt_data.get('data', {}).get('attributes', {}).get('last_https_certificate', {}).get('thumbprint'),
                'vt_serial_number': vt_data.get('data', {}).get('attributes', {}).get('last_https_certificate', {}).get('serial_number'),
                'vt_C': vt_data.get('data', {}).get('attributes', {}).get('last_https_certificate', {}).get('issuer',{}).get('C'),
                'vt_O': vt_data.get('data', {}).get('attributes', {}).get('last_https_certificate', {}).get('issuer',{}).get('O'),
                'vt_CN': vt_data.get('data', {}).get('attributes', {}).get('last_https_certificate', {}).get('issuer',{}).get('CN'),
                
                # Virustotal analiz sonuçları
                'vt_analysis_results': analysis_list,
                
                # WHOIS bilgisi
                'whois': whois_data,
            }

            return render(request, 'home/show_ip_threat_intel.html', context)
    
    return render(request, 'home/notifications.html')

def analyze_url(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        
        if url:
            # OTX API'den URL ile ilgili tehdit bilgilerini al
            api_url = f"https://otx.alienvault.com/api/v1/indicators/url/{url}/general"
            response = requests.get(api_url, headers={'X-OTX-API-KEY': settings.OTX_API_KEY})
            threat_data = response.json()

            context = {
                'url': url,
                'threat_data': threat_data,
            }

            return render(request, 'home/show_url_threat_intel.html', context)

    return render(request, 'index.html')

def format_unix_timestamp(timestamp):
    if timestamp:
        try:
            return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        except (TypeError, ValueError):
            return 'Invalid timestamp'
    return 'No timestamp provided'

def upload_and_analyze(request):
    if request.method == 'POST' and 'file' in request.FILES:
        uploaded_file = request.FILES['file']
        fs = FileSystemStorage()

        # Dosyayı kaydedin
        filename = fs.save(uploaded_file.name, uploaded_file)
        file_path = fs.path(filename)

        # Dosya hash'ini hesaplayın (SHA256)
        file_hash = hashlib.sha256(open(file_path, 'rb').read()).hexdigest()

        # VirusTotal API ile dosyayı yükleme
        vt_upload_url = 'https://www.virustotal.com/api/v3/files'
        vt_upload_headers = {'x-apikey': settings.VIRUSTOTAL_API_KEY}
        with open(file_path, 'rb') as f:
            files = {'file': f}
            vt_upload_response = requests.post(vt_upload_url, headers=vt_upload_headers, files=files)

        # Dosya yükleme yanıtını kontrol etme
        if vt_upload_response.status_code == 200:
            vt_upload_data = vt_upload_response.json()
            vt_analysis_id = vt_upload_data.get('data', {}).get('id', None)

            # Analiz sonuçlarını almak için bekleyin
            if vt_analysis_id:
                analysis_complete = False
                while not analysis_complete:
                    time.sleep(10)  # Analiz sonuçlarının hazır olması için bekleyin

                    # VirusTotal API ile analiz sonuçlarını alma
                    vt_analysis_url = f"https://www.virustotal.com/api/v3/analyses/{vt_analysis_id}"
                    vt_analysis_headers = {'x-apikey': settings.VIRUSTOTAL_API_KEY}
                    vt_analysis_response = requests.get(vt_analysis_url, headers=vt_analysis_headers)
                    

                    
                    if vt_analysis_response.status_code == 200:
                        vt_analysis_data = vt_analysis_response.json().get('data', {}).get('attributes', {})
                        vt_meta_file=vt_analysis_response.json().get('meta',{}).get('file_info',{})
                        vt_analysis_results = vt_analysis_data.get('results', {})
                       
                        

                        analysis_list = []
                        for engine, result in vt_analysis_results.items():
                            engine_update = result.get('engine_update', 'N/A')
                            if engine_update != 'N/A':
                                try:
                                    date_obj = datetime.strptime(engine_update, '%Y%m%d')
                                    engine_update_formatted = date_obj.strftime('%d/%m/%Y')
                                except ValueError:
                                    engine_update_formatted = 'Invalid date'
                            else:
                                    engine_update_formatted = 'N/A'
                            analysis_list.append({
                                'engine_name': result.get('engine_name', 'N/A'),
                                'result': result.get('result', 'N/A'),
                                'category': result.get('category', 'N/A'),
                                'engine_update': engine_update_formatted
                                
                            })
                        
                        vt_item_url = vt_analysis_response.json().get('data', {}).get('links', {}).get('item', '')
                        if vt_item_url:
                            vt_item_response = requests.get(vt_item_url, headers=vt_analysis_headers)
                            if vt_item_response.status_code == 200:
                                vt_item_data = vt_item_response.json()
                                attributes = vt_item_data.get('data', {}).get('attributes', {})
                                # Veriyi formatla
                                last_modification_date = format_unix_timestamp(attributes.get('last_modification_date', 0))
                                last_submission_date = format_unix_timestamp(attributes.get('last_submission_date', 0))

                                # Burada vt_item_data'dan dosya ile ilgili detaylı bilgileri alabilirsiniz
                                # Örneğin dosya ismi, boyutu vb. bilgileri bu şekilde elde edebilirsiniz.
                                
                                file_id = vt_item_data.get('data', {}).get('id', '-')
                                file_type = vt_item_data.get('data', {}).get('type', '-')
                               
                        # Sonuçları öncelik sırasına göre sıralayın
                        result_order = {'malicious': 0, 'suspicious': 1, 'clean': 2, 'unrated': 3}
                        analysis_list = sorted(analysis_list, key=lambda x: result_order.get(x['result'], 4))
                        
                        vt_total_votes = vt_analysis_data.get('stats', {})
                        votes_list = []
                        # Başlangıçta toplam değerleri 0 olarak başlatıyoruz
                        total_malicious = total_suspicious = total_undetected = total_harmless = 0
                        total_timeout = total_confirmed = total_failure = total_unsupported = 0

                        for key, value in vt_total_votes.items():
                            if key == "malicious":
                                malicious_votes = value
                            elif key == "suspicious":
                                suspicious_votes = value
                            elif key == "undetected":
                                undetected_votes = value
                            elif key == "harmless":
                                harmless_votes = value
                            elif key == "timeout":
                                timeout_votes = value
                            elif key == "confirmed-timeout":
                                confirmed_votes = value
                            elif key == "failure":
                                failure_votes = value
                            elif key == "type-unsupported":
                                unsupported_votes = value

                        # Her bir sonucu votes_list'e ekliyoruz
                        votes_list.append({
                            'malicious_votes': malicious_votes,
                            'suspicious_votes': suspicious_votes,
                            'undetected_votes': undetected_votes,
                            'harmless_votes': harmless_votes,
                            'timeout_votes': timeout_votes,
                            'confirmed_votes': confirmed_votes,
                            'failure_votes': failure_votes,
                            'unsupported_votes': unsupported_votes,
                        }),

                            # Her bir oy kategorisini topluyoruz
                        total_malicious += malicious_votes
                        total_suspicious += suspicious_votes
                        total_undetected += undetected_votes
                        total_harmless += harmless_votes
                        total_timeout += timeout_votes
                        total_confirmed += confirmed_votes
                        total_failure += failure_votes
                        total_unsupported += unsupported_votes

                        # Tüm oyların toplamını hesaplıyoruz
                        total_votes = (total_malicious + total_suspicious + total_undetected +
                                    total_harmless + total_timeout + total_confirmed + 
                                    total_failure + total_unsupported)
                        malware_votes=(total_malicious + total_suspicious +
                                    total_confirmed + total_failure + total_unsupported)
                        vt_reputation = 'N/A'  # Reputation genellikle analiz sonuçlarında yer almaz
                        vt_scan_date = vt_analysis_data.get('date', 'N/A')
                        status = vt_analysis_data.get('status', 'unknown')
                        
                        if status in ['completed', 'failed']:
                            # Analyze the detailed response from VirusTotal
                            threats = analyze_virustotal_response(vt_analysis_results)
                            
                            # OTX Yanıtını İşleme
                            otx_url = f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/analysis"
                            otx_headers = {'X-OTX-API-KEY': settings.OTX_API_KEY}
                            otx_response = requests.get(otx_url, headers=otx_headers)

                            if otx_response.status_code == 200:
                                otx_data = otx_response.json()
                                pulse_info = otx_data.get('pulse_info', {})
                                analysis = otx_data.get('analysis', {})
                                file_info = analysis.get('file_info', {})
                            else:
                                pulse_info = {}
                                analysis = {}
                                file_info = {}

                            # Context'e bilgileri ekleyin
                            context = {
                            'sha256': attributes.get('sha256', 'Unknown'),
                            'last_modification_date': last_modification_date,
                            'ssdeep': attributes.get('ssdeep', '-'),
                            'magika': attributes.get('magika', '-'),
                            'tags': ', '.join(attributes.get('tags', [])),
                            'last_submission_date': last_submission_date,
                            'type_tags': ', '.join(attributes.get('type_tags', [])),
                            'unique_sources': attributes.get('unique_sources', '-'),
                            'crowdsourced_yara_results': attributes.get('crowdsourced_yara_results', []),
                            'malicious':attributes.get('last_analysis_stats',{}).get('malicious','-'),
                            'suspicious':attributes.get('last_analysis_stats',{}).get('suspicious','-'),
                            'undetected':attributes.get('last_analysis_stats',{}).get('undetected','-'),
                            'harmless':attributes.get('last_analysis_stats',{}).get('harmless','-'),
                            'timeout':attributes.get('last_analysis_stats',{}).get('timeout','-'),
                            'confirmed-timeout':attributes.get('last_analysis_stats',{}).get('confirmed-timeout','-'),
                            'failure':attributes.get('last_analysis_stats',{}).get('failure','-'),
                            'type_unsupported':attributes.get('last_analysis_stats',{}).get('type-unsupported','-'),
                            'magic': attributes.get('magic', '-'),
                            'names': ', '.join(attributes.get('names', [])),
                            'type_description': attributes.get('type_description', '-'),
                            'sha1': attributes.get('sha1', 'Unknown'),
                            'trid': attributes.get('trid', []),
                            'type_extension': attributes.get('type_extension', '-'),
                            'type_tag': attributes.get('type_tag', '-'),
                            'total_votes': attributes.get('total_votes', {}),
                            'tlsh': attributes.get('tlsh', '-'),
                            'md5': attributes.get('md5', '-'),
                            'size': attributes.get('size', '-'),
                            'meaningful_name': attributes.get('meaningful_name', '-'),
                            'last_analysis_results': attributes.get('last_analysis_results', {}),   
                            'file_name':attributes.get('name', '-'),
                            'file_url': fs.url(filename),
                            'file_hash': file_hash,
                            'file_type': file_type,
                            'size': vt_meta_file.get('size', '-'),
                            'md5': vt_meta_file.get('md5', 'N/A'),
                            'sha1': vt_meta_file.get('sha1', 'N/A'),
                            'sha256': vt_meta_file.get('sha256', 'N/A'),
                            'pulses': pulse_info.get('count', 0),
                            'av_detections': analysis.get('av', {}).get('count', 0),
                            'ids_detections': analysis.get('ids', {}).get('count', 0),
                            'yara_detections': analysis.get('yara', {}).get('count', 0),
                            'alerts': analysis.get('alerts', {}).get('count', 0),
                            'file_score': analysis.get('score', 0),
                            'risk_level': 'Low Risk' if analysis.get('score', 0) < 50 else 'High Risk',
                            'vt_scan_date': vt_scan_date,
                            'vt_total_votes': vt_total_votes,
                            'vt_reputation': vt_reputation,
                            'vt_av_scan_results': threats, 
                            'vt_analysis_results': analysis_list,
                            'votes_list': votes_list,
                            'total_malicious': total_malicious,
                            'total_suspicious': total_suspicious,
                            'total_undetected': total_undetected,
                            'total_harmless': total_harmless,
                            'total_timeout': total_timeout,
                            'total_confirmed': total_confirmed,
                            'total_failure': total_failure,
                            'total_unsupported': total_unsupported,
                            'total_votes': total_votes,
                            'malware_votes':malware_votes
                            }

                            # Virustotal analiz sonuçları
                            print("File Hash:",file_hash)
                            print("OTX Yanıt:", otx_response.json())
                            print("VirusTotal Yükleme Yanıt:", vt_upload_response.json())
                            print("VirusTotal Analiz Yanıt:", vt_analysis_response.json())

                            return render(request, 'home/show_file_threat_intel.html', context)

                    else:
                        vt_analysis_data = {'error': 'VirusTotal analiz sonuçları alınamadı'}
                        context = {'error': 'VirusTotal analiz sonuçları alınamadı'}
                        analysis_complete = True
            else:
                vt_analysis_data = {'error': 'VirusTotal analiz ID alınamadı'}
                context = {'error': 'VirusTotal analiz ID alınamadı'}
        else:
            vt_upload_data = {'error': 'VirusTotal yükleme başarısız oldu'}
            context = {'error': 'VirusTotal yükleme başarısız oldu'}

        return render(request, 'home/show_file_threat_intel.html', context)

    return render(request, 'home/notifications.html')
def make_virustotal_api_call(file):
    headers = {
        'x-apikey': settings.VIRUSTOTAL_API_KEY}
    files = {'file': file}
    response = requests.post('https://www.virustotal.com/api/v3/files', headers=headers, files=files)
    response.raise_for_status()
    return response.json()
def analyze_file(request):
    if request.method == "POST" and 'file' in request.FILES:
        response = make_virustotal_api_call(request.FILES['file'])
        threat_categories = analyze_virustotal_response(response)
        context = {
            'threat_categories': threat_categories,
            'file_name': request.FILES['file'].name,
        }
        return render(request, "home/show_file_threat_intel.html", context)
    return render(request, "home/file_upload.html")

def analyze_virustotal_response(response):
    # Yanıtın içindeki analiz sonuçlarını alın
    analysis_results = response.get('data', {}).get('attributes', {}).get('last_analysis_results', {})

    # Olası tehdit kategorileri
    threat_categories = {
        'malicious': [],
        'suspicious': [],
        'clean': [],
        'undetected': [],
        'unrated': []
    }

    # Her motorun analiz sonucunu döngü ile gezelim
    for engine_name, engine_result in analysis_results.items():
        category = engine_result.get('category', 'unrated')  # Kategori alın, varsayılan 'unrated'
        result = engine_result.get('result', 'No Result')   # Tehdit türünü alın
        method = engine_result.get('method', 'Unknown')     # Kullanılan yöntem

        # Sonuçları kategorilere ekleyin
        if category == 'malicious':
            threat_categories['malicious'].append({
                'engine': engine_name,
                'result': result,
                'method': method
            })
        elif category == 'suspicious':
            threat_categories['suspicious'].append({
                'engine': engine_name,
                'result': result,
                'method': method
            })
        elif category == 'clean':
            threat_categories['clean'].append({
                'engine': engine_name,
                'result': result
            })
        elif category == 'undetected':
            threat_categories['undetected'].append({
                'engine': engine_name,
                'result': result
            })
        else:
            threat_categories['unrated'].append({
                'engine': engine_name,
                'result': result
            })

    return threat_categories

@login_required(login_url="/login/")
def pages(request):
    context = {}
    try:
        load_template = request.path.split('/')[-1]
        if load_template == 'admin':
            return HttpResponseRedirect(reverse('admin:index'))
        context['segment'] = load_template

        html_template = loader.get_template('home/' + load_template)
        return HttpResponse(html_template.render(context, request))
    except template.TemplateDoesNotExist:
        html_template = loader.get_template('home/page-404.html')
        return HttpResponse(html_template.render(context, request))
    except:
        html_template = loader.get_template('home/page-500.html')
        return HttpResponse(html_template.render(context, request))

