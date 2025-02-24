import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

TIMEOUT = 5  # Timeout süresi
checked_links = set()  # Aynı linkleri tekrar taramamak için

def scan_website(url):
    def check_vulnerabilities(response, url):
        vulnerabilities = []

        # XSS açıklarını kontrol et
        if "<script>" in response.text.lower():
            vulnerabilities.append({"type": "XSS", "severity": "medium", "description": f"Suspected XSS vulnerability: {url}"})

        # Admin paneli tarama
        admin_paths = ["/admin", "/admin/login", "/login", "/wp-admin"]
        for path in admin_paths:
            admin_url = urljoin(url, path)
            try:
                admin_response = requests.get(admin_url, timeout=TIMEOUT)
                if admin_response.status_code == 200 and "login" in admin_response.text.lower():
                    vulnerabilities.append({"type": "Admin Panel Vulnerability", "severity": "high", "description": f"Admin Panel Vulnerability: {admin_url}"})
            except requests.RequestException:
                pass

        # Hata mesajları kontrolü
        error_keywords = ["error", "exception", "warning", "stack trace"]
        if any(keyword in response.text.lower() for keyword in error_keywords):
            vulnerabilities.append({"type": "Error message", "severity": "low", "description": f"Error messages are displayed: {url}"})

        return vulnerabilities

    def scan_link(link_url):
        """Bağlantıları tarar."""
        if link_url in checked_links:
            return []
        checked_links.add(link_url)

        try:
            link_response = requests.get(link_url, timeout=TIMEOUT)
            link_response.raise_for_status()
            return check_vulnerabilities(link_response, link_url)
        except requests.RequestException:
            return [{"type": "Access Error", "severity": "low", "description": f"Connection failed: {link_url}"}]

    def check_sql_injection(url): 
        test_payloads = [
            "' OR 1=1 --", "' UNION SELECT NULL, NULL --",
            "' UNION SELECT username, password FROM users --",
            "' OR IF(1=1, SLEEP(5), 0) --", "' AND 0x41=0x41 --"
        ]
        vulnerabilities = []
        
        for payload in test_payloads:
            test_url = f"{url}?id={payload}"
            try:
                response = requests.get(test_url, timeout=TIMEOUT)
                if any(keyword in response.text.lower() for keyword in ["error", "database", "syntax"]):
                    vulnerabilities.append({"type": "SQL Injection", "severity": "high", "description": f"SQL Injection vulnerability found: {test_url}"})
            except requests.RequestException:
                continue
        
        return vulnerabilities

    def check_https(url):
        if not url.startswith("https://"):
            return [{"type": "Lack of HTTPS", "severity": "medium", "description": f"HTTPS is not used: {url}"}]
        try:
            requests.get(url, timeout=TIMEOUT, verify=True)
            return []
        except requests.exceptions.SSLError:
            return [{"type": "SSL Error", "severity": "high", "description": f"Invalid SSL certificate: {url}"}]
        except requests.RequestException:
            return [{"type": "Connection Error", "severity": "low", "description": f"HTTPS connection could not be established: {url}"}]

    def check_form_validation(url):
        vulnerabilities = []
        try:
            response = requests.get(url, timeout=TIMEOUT)
            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")

            for form in forms:
                action = form.get("action")
                form_url = urljoin(url, action)
                
                # CSRF token kontrolü
                csrf_token = form.find("input", {"name": "csrf_token"}) or form.find("input", {"name": "csrfmiddlewaretoken"})
                if not csrf_token:
                    vulnerabilities.append({"type": "Lack of CSRF", "severity": "medium", "description": f"Lack of CSRF Token: {form_url}"})

                # XSS testi
                form_data = {input_tag.get("name"): "<script>alert('XSS')</script>" for input_tag in form.find_all("input") if input_tag.get("name")}
                if form_data:
                    post_response = requests.post(form_url, data=form_data, timeout=TIMEOUT)
                    if "<script>" in post_response.text:
                        vulnerabilities.append({"type": "XSS (Form)", "severity": "high", "description": f"Form XSS vulnerability found: {form_url}"})

                # SQL Injection testi
                form_data = {input_tag.get("name"): "' OR 1=1 --" for input_tag in form.find_all("input") if input_tag.get("name")}
                if form_data:
                    post_response = requests.post(form_url, data=form_data, timeout=TIMEOUT)
                    if any(keyword in post_response.text.lower() for keyword in ["error", "database", "syntax"]):
                        vulnerabilities.append({"type": "SQL Injection (Form)", "severity": "high", "description": f"Form SQL Injection vulnerability found: {form_url}"})

        except requests.RequestException:
            pass

        return vulnerabilities

    def check_csrf_vulnerabilities(url):
        vulnerabilities = []
    
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            

            forms = soup.find_all("form")
            
            for form in forms:
                action = form.get("action")
                form_url = urljoin(url, action)
                
                # CSRF token'ı kontrolü
                csrf_token = form.find("input", {"name": "csrf_token"})
                csrf_name = form.find("input", {"name": "csrf"})
                csrf_tokens = csrf_token or csrf_name
                
                if not csrf_tokens:
                    vulnerabilities.append(f"CSRF protection is missing: {form_url}")
                    continue
                csrf_value = csrf_tokens.get("value")
                if not csrf_value:
                    vulnerabilities.append(f"CSRF token value is missing or empty: {form_url}")
                    
                test_payload = {csrf_tokens.get("name"): csrf_value}
                
                try:
                    post_response = requests.post(form_url, data=test_payload, timeout=5)
                    
                    if post_response.status_code == 200 and "csrf_token" not in post_response.text.lower():
                        vulnerabilities.append(f"CSRF protection is ineffective: {form_url}")
                    
                except requests.RequestException as e:
                    vulnerabilities.append(f"An error occurred: {str(e)}")
                    continue
            
        except requests.RequestException as e:
            vulnerabilities.append(f"The page could not be accessed: {str(e)}")
        return vulnerabilities

    try:
        response = requests.get(url, timeout=TIMEOUT)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        all_vulnerabilities = []

        all_vulnerabilities.extend(check_vulnerabilities(response, url))
        all_vulnerabilities.extend(check_sql_injection(url))
        all_vulnerabilities.extend(check_https(url))
        all_vulnerabilities.extend(check_form_validation(url))
        all_vulnerabilities.extend(check_csrf_vulnerabilities(url))

        links = [urljoin(url, a["href"]) for a in soup.find_all("a", href=True) if urljoin(url, a["href"]) != url]

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(scan_link, link) for link in links]
            for future in as_completed(futures):
                all_vulnerabilities.extend(future.result())

        return {
            "url": url,
            "status": "Scan completed",
            "vulnerabilities": all_vulnerabilities if all_vulnerabilities else [{"type": "No Vulnerability", "severity": "none", "description": "No vulnerabilities found."}]
        }


    except requests.RequestException:
        return {"url": url, "status": "Error: Site could not be accessed!"}

