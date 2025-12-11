# app.py

import proxy_config as requests  
import requests as original_requests  
from flask import Flask, render_template, request as flask_request, flash, redirect, url_for, session
from flask_cors import CORS
import pickle
import logging
from features import feature_extraction, get_whois_info
from urllib.parse import urlparse
import tldextract
import socket
import ssl
import os
import re  # Импортиран за дезинфекция на URL адреси
import time  # за забавянията
# импортване на моделите
from extensions import db, migrate, login_manager
from models import User
from auth import auth  # блупринт на регистрацията

app = Flask(__name__)
CORS(app)

# блурпинт на регистрацията
app.register_blueprint(auth, url_prefix='/auth')

# Secret key (override via environment variable in production)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'changeme')  

# Database cконфигурация
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///feedback.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Инициализирайте разширения с приложение
db.init_app(app)
migrate.init_app(app, db)
login_manager.init_app(app)
login_manager.login_view = 'auth.login'  

# потребителки лоадер 
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# че инстанце дир. е валидна
if not os.path.exists('instance'):
    os.makedirs('instance')

# сетване на логгер файла
log_file = 'instance/logs.txt'

# създаване на  logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

file_handler = logging.FileHandler(log_file)
file_handler.setLevel(logging.DEBUG)

# Създаване на форматиране и ги добавете към логгера
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

# добавяне на handlers към логгера
if not logger.handlers:
    logger.addHandler(file_handler)

# логване на инфото
app.logger.setLevel(logging.DEBUG)
app.logger.addHandler(file_handler)

# лоадване на моделите
try:
    with open('models/lookup_table.pickle', 'rb') as file:
        lookup_model = pickle.load(file)
    with open('models/RandomForest.pickle', 'rb') as file:
        rf_model = pickle.load(file)
    logger.info('Models loaded successfully.')

    # Проверете дали lookup_model е речник
    if not isinstance(lookup_model, dict):
        logger.error('Lookup model is not a dictionary. Please verify the model structure.')
        lookup_model = None
    else:
        # Normalize keys in lookup_model to lowercase and remove trailing commas
        normalized_lookup = {url.lower().rstrip(','): label for url, label in lookup_model.items()}
        lookup_model = normalized_lookup
        logger.info('Lookup model keys have been normalized.')
except FileNotFoundError as e:
    logger.error(f'Model file not found: {e}')
    lookup_model = None
    rf_model = None
except Exception as e:
    logger.error(f'Error loading models: {e}')
    lookup_model = None
    rf_model = None

def get_subdomains(domain):
    """Fetch subdomains using crt.sh."""
    try:
        url = f"https://crt.sh/?q={domain}&output=json"
        headers = {
            'User-Agent': 'Mozilla/5.0'
        }
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code != 200:
            logger.error(f"Crt.sh query failed with status code: {response.status_code}")
            return []

        subdomains = set()
        for entry in response.json():
            subdomain = entry['name_value']
            # crt.sh може да върне множество записи, разделени с нов ред
            for sd in subdomain.split('\n'):
                subdomains.add(sd.strip())

        return list(subdomains)

    except original_requests.Timeout:
        logger.error(f"crt.sh request timed out for {domain}")
        return []
    except Exception as e:
        logger.error(f"Error fetching subdomains: {e}")
        return []

def get_base_domain(url):
    """Extract the base domain from a URL using tldextract."""
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}"

def resolve_ip(url):
    """Resolve IP address from URL."""
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc.split(':')[0]  
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception as e:
        logger.error(f"Error resolving IP for URL {url}: {e}")
        return None

def check_ssl_expiry(url):
    """Check SSL certificate expiration date."""
    try:
        hostname = urlparse(url).netloc
        hostname = hostname.split(':')[0]  # премахване на порт
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return cert['notAfter']
    except Exception as e:
        logger.error(f"Error checking SSL expiry for URL {url}: {e}")
        return None

ip_location_cache = {}

def fetch_ip_location(ip):
    """Fetch location data for an IP address with caching and retry logic."""
    if ip in ip_location_cache:
        return ip_location_cache[ip]
    try:
        url = f"https://ipinfo.io/{ip}/json"
        headers = {
            'User-Agent': 'Mozilla/5.0'
        }
        max_retries = 3
        retry_delay = 1  # старт със закъснение от 1 секунда
        for attempt in range(max_retries):
            # Използвайте original_requests, за да заобиколите проксито за тази заявка
            response = original_requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                location_data = {
                    'country': data.get('country', ''),
                    'region': data.get('region', ''),
                    'city': data.get('city', ''),
                    'latitude': data.get('loc', '').split(',')[0] if 'loc' in data else '',
                    'longitude': data.get('loc', '').split(',')[1] if 'loc' in data else '',
                    'zip': data.get('postal', ''),
                    'timezone': data.get('timezone', '')
                }
                ip_location_cache[ip] = location_data  # каширане на резултата
                return location_data
            elif response.status_code == 429:
                logger.warning(f"Rate limit exceeded for IP {ip}. Retrying after {retry_delay} seconds...")
                time.sleep(retry_delay)
                retry_delay *= 2  
            else:
                logger.error(f"Failed to fetch location for IP {ip}. Status code: {response.status_code}")
                return {}
        logger.error(f"Max retries exceeded for IP {ip}.")
        return {}
    except Exception as e:
        logger.error(f"Error fetching location data for IP {ip}: {e}")
        return {}

@app.route('/', methods=['GET'])
def homePage():
    show_register_modal = session.pop('show_register_modal', False)
    register_message = session.pop('register_message', None)
    register_error = session.pop('register_error', None)

    show_login_modal = session.pop('show_login_modal', False)
    login_message = session.pop('login_message', None)
    login_error = session.pop('login_error', None)

    return render_template(
        'index.html',
        show_register_modal=show_register_modal,
        register_message=register_message,
        register_error=register_error,
        show_login_modal=show_login_modal,
        login_message=login_message,
        login_error=login_error
    )

@app.route('/predict', methods=['POST'])
def predict():
    if flask_request.method == 'POST':
        # Initialize variables to prevent 'undefined' errors
        status = "Unknown"
        whois_info = {}
        ip_address = None
        ssl_expiry = None
        location_info = {}
        subdomains = []
        ssl_valid = None  # за RandomForest model
        features = None  # за RandomForest model
        prediction = None
        model_used = None
        web_link = ''

        try:
            logger.debug('Content-Type: %s', flask_request.content_type)
            logger.debug('Form Data: %s', flask_request.form)

            if flask_request.content_type != 'application/x-www-form-urlencoded':
                logger.warning('Unsupported Media Type: %s', flask_request.content_type)
                return render_template('result.html',
                                       pred=None,
                                       link=web_link,
                                       status=status,
                                       ip=ip_address,
                                       location_info=location_info,
                                       ssl_valid=ssl_expiry if ssl_expiry else ssl_valid,
                                       model_used=model_used,
                                       whois_info=whois_info,
                                       subdomains=subdomains,
                                       error="Unsupported Media Type.")

            web_link = flask_request.form.get('link')
            logger.info('Received URL for prediction: %s', web_link)

            if not web_link:
                logger.warning('No URL provided in the form data.')
                return render_template('result.html',
                                       pred=None,
                                       link=web_link,
                                       status=status,
                                       ip=ip_address,
                                       location_info=location_info,
                                       ssl_valid=ssl_expiry if ssl_expiry else ssl_valid,
                                       model_used=model_used,
                                       whois_info=whois_info,
                                       subdomains=subdomains,
                                       error="No URL provided. Please enter a valid URL.")

            # **Sanitize the URL**
            web_link = web_link.strip().rstrip(',')  # Премахнете запетая в края
            web_link = re.sub(r'[^\w\:\.\/\?\=\&\-#]', '', web_link)  # Премахнете други нежелани знаци
            web_link = web_link.lower()  # Нормализиране на случая
            logger.info('Sanitized URL for prediction: %s', web_link)

            # Валидирайте и анализирайте URL адреса
            parsed_url = urlparse(web_link)
            if not parsed_url.scheme:
                # Ако не е предоставена схема, примеа се за HTTP
                web_link = 'http://' + web_link
                logger.info(f"No scheme provided. Assuming HTTP: {web_link}")
                parsed_url = urlparse(web_link)

            if not parsed_url.netloc:
                logger.warning('Invalid URL format: %s', web_link)
                return render_template('result.html',
                                       pred=None,
                                       link=web_link,
                                       status=status,
                                       ip=ip_address,
                                       location_info=location_info,
                                       ssl_valid=ssl_expiry if ssl_expiry else ssl_valid,
                                       model_used=model_used,
                                       whois_info=whois_info,
                                       subdomains=subdomains,
                                       error="Please provide a valid URL.")

            # проверка дали е е в лоокъп таблицата
            if lookup_model:
                lookup_result = lookup_model.get(web_link)

                if lookup_result is not None:
                    prediction = lookup_result
                    model_used = 'lookup'
                    logger.info('URL found in lookup_table.pickle with result: %s', prediction)

            # проверка на статус и извличане на информация
            try:
                # Use proxy_config за заявки
                session_requests = requests.Session()
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                                  'AppleWebKit/537.36 (KHTML, like Gecko) '
                                  'Chrome/98.0.4758.102 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Referer': web_link,
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                response = session_requests.get(web_link, headers=headers, timeout=15, allow_redirects=True)

                status_code = response.status_code

                # статус локиката
                if response.ok:
                    status = "Online"
                elif 400 <= status_code < 500:
                    status = "Online"  # Клиентските грешки показват, че сайтът е достъпен
                elif 500 <= status_code < 600:
                    status = "Offline"  #Грешките на сървъра показват, че сайтът може да не работи
                    prediction = 'Not Available'
                else:
                    status = "Unknown"

                final_url = response.url
                logger.info(f"Final URL after potential redirection: {final_url}")

                original_domain = get_base_domain(web_link)
                final_domain = get_base_domain(final_url)

                if final_domain != original_domain:
                    logger.warning(f"Cross-domain redirection detected: {original_domain} -> {final_domain}")
                    #Класифициране като фишинг поради пренасочване между домейни
                    prediction = 'phishing'
                    model_used = 'redirection'

                # Регистрирайте грешки на сървъра, но продължете
                if 500 <= status_code < 600:
                    logger.warning(f"Server error for URL: {web_link} with status code {status_code}")

            except original_requests.Timeout:
                logger.warning(f"Timeout error for URL: {web_link}")
                status = "Offline"
                prediction = 'Not Available'
            except original_requests.RequestException as e:
                logger.error(f"Request exception for URL {web_link}: {e}")
                status = "Offline"
                prediction = 'Not Available'

            logger.info(f"Website status: {status}")

            # ako saita e online
            if status == "Online":
                # извлизане на whois
                try:
                    whois_info = get_whois_info(web_link)
                    if not isinstance(whois_info, dict):
                        logger.warning(f"WHOIS info is not a dictionary for URL: {web_link}")
                        whois_info = {}
                except Exception as e:
                    logger.error(f"Error fetching WHOIS info: {e}")
                    whois_info = {}

                # Разрешете IP адрес
                try:
                    ip_address = resolve_ip(web_link)
                except Exception as e:
                    logger.error(f"Error resolving IP: {e}")
                    ip_address = ''

                # Извличане на локация
                if ip_address:
                    try:
                        location_info = fetch_ip_location(ip_address)
                    except Exception as e:
                        logger.error(f"Error fetching location info: {e}")
                        location_info = {}

                # Check на SSL ако урле хттпс
                if parsed_url.scheme == 'https':
                    try:
                        ssl_expiry = check_ssl_expiry(web_link)
                    except Exception as e:
                        logger.error(f"Error checking SSL expiry: {e}")
                        ssl_expiry = ''

                # Извличане на поддомейни
                try:
                    domain = parsed_url.netloc
                    subdomains = get_subdomains(domain)
                except Exception as e:
                    logger.error(f"Error fetching subdomains: {e}")
                    subdomains = []

                # Ако URL адресът не е в справочната таблица и няма ранна класификация, използвайте модела RandomForest
                if prediction is None:
                    if rf_model:
                        logger.debug('URL not found in lookup_table.pickle, using RandomForest model for prediction')
                        model_used = 'random_forest'
                        try:
                            features, _, _, ssl_valid, *_ = feature_extraction(web_link, rf_model.n_features_in_, return_all=True)
                            prediction_rf = rf_model.predict([features])[0]
                            prediction = 'phishing' if prediction_rf == 1 else 'legitimate'
                            logger.info('Prediction using RandomForest model: %s', prediction)
                        except Exception as e:
                            logger.error('Error during RandomForest prediction: %s', e)
                            return render_template('result.html',
                                                   pred=None,
                                                   link=web_link,
                                                   status=status,
                                                   ip=ip_address,
                                                   location_info=location_info,
                                                   ssl_valid=ssl_expiry if ssl_expiry else ssl_valid,
                                                   model_used=model_used,
                                                   whois_info=whois_info,
                                                   subdomains=subdomains,
                                                   error="Prediction failed due to model error.")
                    else:
                        logger.error('RandomForest model is not loaded.')
                        return render_template('result.html',
                                               pred=None,
                                               link=web_link,
                                               status=status,
                                               ip=ip_address,
                                               location_info=location_info,
                                               ssl_valid=ssl_expiry if ssl_expiry else ssl_valid,
                                               model_used=model_used,
                                               whois_info=whois_info,
                                               subdomains=subdomains,
                                               error="Prediction model not available.")

            else:
                # когато сайта е оффлайн
                logger.info('Site is offline or unreachable. Unable to proceed with further checks.')
                prediction = 'Not Available'

            # определяне на финалното предказване
            if isinstance(prediction, str):
                final_prediction = prediction
            elif prediction == 1:
                final_prediction = 'phishing'
            elif prediction == 0:
                final_prediction = 'legitimate'
            else:
                final_prediction = 'Not Available'
            logger.info('Final Prediction: %s', final_prediction)

            # Set pred_flag accordingly
            if final_prediction == 'phishing':
                pred_flag = True
            elif final_prediction == 'legitimate':
                pred_flag = False
            else:
                pred_flag = None  # не е налично предказването

            return render_template('result.html',
                                   pred=pred_flag,
                                   link=web_link,
                                   status=status,
                                   ip=ip_address,
                                   location_info=location_info,
                                   ssl_valid=ssl_expiry if ssl_expiry else ssl_valid,
                                   model_used=model_used,
                                   whois_info=whois_info,
                                   subdomains=subdomains,
                                   malicious_prediction=final_prediction,
                                   error=None if pred_flag is not None else "Prediction not available due to site being offline.")

        except Exception as e:
            logger.exception('Exception occurred while processing URL: %s', e)
            #Безопасно извличане на променливи с помощта на locals().get()
            return render_template('result.html',
                                   pred=None,
                                   link=web_link,
                                   status=status,
                                   ip=ip_address,
                                   location_info=location_info,
                                   ssl_valid=ssl_expiry if ssl_expiry else ssl_valid,
                                   model_used=model_used,
                                   whois_info=whois_info,
                                   subdomains=subdomains,
                                   error="An unexpected error occurred. Please try again later.")

    return render_template('index.html')


if __name__ == "__main__":
    app.run(debug=True)
