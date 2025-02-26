import json
import re
import os

def list_files(extension=".har"):
    """Lijst HAR-bestanden in de map."""
    return [f for f in os.listdir('.') if f.endswith(extension)]


def extract_tokens(response_text):
    """Haal authenticatie tokens uit de response."""
    tokens = {}
    patterns = {
        "access_token": r'["\']access_token["\']\s*:\s*["\']([^"\']+)["\']',
        "refresh_token": r'["\']refresh_token["\']\s*:\s*["\']([^"\']+)["\']',
        "csrf_token": r'["\'](csrf|X-CSRF-Token)["\']\s*:\s*["\']([^"\']+)["\']',
        "authorization": r'["\']Authorization["\']\s*:\s*["\']Bearer ([^"\']+)["\']',
    }
    for key, pattern in patterns.items():
        match = re.search(pattern, response_text, re.IGNORECASE)
        if match:
            tokens[key] = match.group(1)
    return tokens


def parse_har(har_file):
    """Parse de HAR file en haal login-aanvragen op."""
    with open(har_file, 'r', encoding='utf-8') as file:
        har_data = json.load(file)

    requests = []
    tokens = {}
    
    for entry in har_data['log']['entries']:
        request = entry['request']
        response = entry.get('response', {})

        url = request['url']
        method = request['method']
        headers = {h['name']: h['value'] for h in request['headers']}
        cookies = {c['name']: c['value'] for c in request.get('cookies', [])}
        post_data = request.get('postData', {}).get('text', '')

        is_login = any(keyword in url.lower() for keyword in ["/login", "/auth", "/session"])
        
        if 'content' in response and 'text' in response['content']:
            extracted_tokens = extract_tokens(response['content']['text'])
            tokens.update(extracted_tokens)

        requests.append({
            "url": url, "method": method, "headers": headers,
            "cookies": cookies, "post_data": post_data, "is_login": is_login
        })
    
    return requests, tokens


def generate_python_script(requests, tokens, output_file):
    """Genereer een volledig werkend Python login-script."""
    script = [
        "import requests\n\n",
        "session = requests.Session()\n\n"
    ]

    for req in requests:
        script.append(f"response = session.{req['method'].lower()}(")
        script.append(f"    \"{req['url']}\",")

        if req['headers']:
            script.append(f"    headers={json.dumps(req['headers'], indent=4)},")

        if req['cookies']:
            script.append(f"    cookies={json.dumps(req['cookies'], indent=4)},")

        if req['post_data']:
            script.append(f"    data={json.dumps(req['post_data'])},")

        script.append(")\n\n")

    script.append("print(\"Login succesvol!\")\n")

    with open(output_file, 'w', encoding='utf-8') as file:
        file.write("\n".join(script))
    
    print(f"Python login script opgeslagen als {output_file}")


def main():
    """Genereer .svb, .loli, en .py login scripts."""
    print("HAR naar Auto-Login Generator (SilverBullet, OpenBullet, Python)\n")

    files = list_files(".har")
    if not files:
        print("Geen HAR-bestanden gevonden.")
        return

    print("\nBeschikbare HAR-bestanden:")
    for idx, file in enumerate(files, 1):
        print(f"{idx}. {file}")

    choice = int(input("\nKies een HAR-bestand: ")) - 1
    har_file = files[choice]

    base_name = os.path.splitext(har_file)[0]
    py_file = base_name + "_login.py"

    requests, tokens = parse_har(har_file)
    generate_python_script(requests, tokens, py_file)

    print("\n✅ Omzetting voltooid! Je bestanden zijn klaar.")


if __name__ == "__main__":
    main()
