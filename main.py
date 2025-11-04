import os
import math
import random
import secrets
from datetime import datetime, timedelta

# ----------------- Параметри варіанту ---------------
N = 10  # макс користувачів
a = 4  # коефіцієнт в F(x) = e^(a*x)
T = 5  # час життя токена у хвилинах
R = 12 # кількість необхідних цифр в ключах
# ----------------------------------------------------

NAMEUSER_FILE = 'nameuser.txt'
USBOOK_FILE = 'us_book.txt'
ASK_FILE = 'ask.txt'
OUT_FILE = 'out.txt'
PRIMES_FILE = 'primes-to-1m.txt'
PUBLIC_KEY_FILE = 'public_keys.txt'
PRIVATE_KEY_FILE = 'private_keys.txt'

ADMIN_USERNAME = 'admin'
ADMIN_DEFAULT_PASSWORD = 'adminpass'

current_user = None
token = None
token_expiry = None
user_rights = ''


def ensure_files():
    """Створює файли, якщо їх немає та заповнює ask.txt"""
    for fname in [NAMEUSER_FILE, USBOOK_FILE]:
        if not os.path.exists(fname):
            open(fname, 'a', encoding='utf-8').close()

    with open(ASK_FILE, 'w', encoding='utf-8') as f:
        for _ in range(50):
            x = round(random.uniform(1, 50), 4)
            fx = F(x)
            f.write(f"{x} {fx:.12f}\n")

    if not (os.path.exists(PUBLIC_KEY_FILE) and os.path.exists(PRIVATE_KEY_FILE)):
        choose_keys()


def log_action(user, action):
    """Записує події у журнал us_book.txt"""
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(USBOOK_FILE, 'a', encoding='utf-8') as f:
        f.write(f"{ts}|{user}|{action}\n")


def encrypt_field(text):
    """Шифрує текст за допомогою публічного ключа і повертає рядок блоків"""
    enc = rsa_encrypt_message(text)
    return enc


def decrypt_field(enc_text):
    """Дешифрує за допомогою приватного ключа і повертає звичайний рядок"""
    if not enc_text:
        return ''
    dec = rsa_decrypt_blocks(enc_text)
    return dec


def read_users():
    """Зчитує усіх зареєстрованих користувачів"""
    users = {}
    if not os.path.exists(NAMEUSER_FILE):
        return users
    with open(NAMEUSER_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split('|')
            if len(parts) < 4:
                continue
            username = parts[0]
            enc_password = parts[1]
            rights = parts[2]
            disks = parts[3]
            try:
                password = rsa_decrypt_blocks(enc_password) if enc_password else ''
            except Exception as e:
                print(f"Помилка дешифрування паролю для {username}: {e}")
                password = ''
            users[username] = {'password': password, 'rights': rights, 'disks': disks}
    return users


def write_users(users):
    """Записує користувачів"""
    with open(NAMEUSER_FILE, 'w', encoding='utf-8') as f:
        for u, info in users.items():
            try:
                enc_password = encrypt_field(info.get('password', '')) or ''
            except Exception as e:
                print(f"Не вдалось зашифрувати пароль для {u}: {e}")
                enc_password = ''
            try:
                rights = info.get('rights', '') or ''
            except Exception:
                rights = ''
            try:
                disks = info.get('disks', '') or ''
            except Exception:
                disks = ''
            f.write(f"{u}|{enc_password}|{rights}|{disks}\n")


def ensure_admin():
    """Записує адміністратора автоматично в користувачі (якщо він відсутній)"""
    users = read_users()
    if ADMIN_USERNAME not in users:
        users[ADMIN_USERNAME] = {'password': ADMIN_DEFAULT_PASSWORD, 'rights': 'E,R,W,A', 'disks': 'A,B,C,D,E'}
        write_users(users)


def register_user(current_user_param):
    """Функція для андміністратора, яка реєструє нових користувачів"""
    if current_user_param != ADMIN_USERNAME:
        print("Лише адміністратор може створювати користувачів.")
        return
    users = read_users()
    if len(users) >= N:
        print(f"Досягнуто максимуму користувачів ({N}).")
        return
    username = input("Нове ім'я користувача: ").strip()
    if not username or username in users:
        print("Ім’я недійсне або вже існує.")
        return
    password = input("Пароль: ").strip()
    rights = input("Права (через кому, наприклад: E,R,W,A або для звичайного користувача E,R): ").strip() or 'E,R'
    disks = input("Диски (через кому, наприклад: A,B): ").strip() or ''
    users[username] = {'password': password, 'rights': rights, 'disks': disks}
    write_users(users)
    log_action(current_user_param, f"register {username}")
    print("Користувача додано.")


def delete_user(current_user_param):
    """Функція для андміністратора, яка видаляє користувачів"""
    if current_user_param != ADMIN_USERNAME:
        print("Лише адміністратор може видаляти користувачів.")
        return
    users = read_users()
    username = input("Ім’я користувача для видалення: ").strip()
    if username == ADMIN_USERNAME:
        print("Неможливо видалити адміністратора.")
        return
    if username not in users:
        print("Користувача не знайдено.")
        return
    users.pop(username)
    write_users(users)
    log_action(current_user_param, f"delete {username}")
    print(" Користувача видалено.")


def authenticate_user(username):
    """Створює тимчасовий токен"""
    global token, token_expiry
    token = secrets.token_hex(16)
    token_expiry = datetime.now() + timedelta(minutes=T)
    print(f"Токен створено. Дійсний до {token_expiry.strftime('%Y-%m-%d %H:%M:%S')}")


def is_token_valid():
    """Перевіряє токен на його актуальність"""
    global token, token_expiry
    return token is not None and token_expiry is not None and datetime.now() < token_expiry


def identify():
    """Обов'язковий логін користувача"""
    global current_user, user_rights
    users = read_users()
    username = input("Ім'я: ").strip()
    password = input("Пароль: ").strip()
    if username in users and users[username]['password'] == password:
        current_user = username
        user_rights = users[username]['rights']
        log_action(username, "login_ok")
        print("Ідентифікація успішна.")
        authenticate_user(username)
        return True
    else:
        log_action(username, "login_fail")
        print("Невірне ім'я або пароль.")
        current_user = None
        user_rights = ''
        return False


def F(x):
    """Обчислює e^(a*x)"""
    try:
        return math.exp(a * x)
    except OverflowError:
        return float('inf')


def prepare_asks_if_empty():
    """Гарантує наявність ask.txt у форматі 'x fx' (fx з 12 знаками)."""
    if not os.path.exists(ASK_FILE) or os.path.getsize(ASK_FILE) == 0:
        with open(ASK_FILE, 'w', encoding='utf-8') as f:
            for _ in range(50):
                x = random.uniform(0.01, 1.0)
                fx = F(x)
                f.write(f"{x:.4f} {fx:.12f}\n")


def ask_continue_session(username):
    """
    Коли токен сплив — бере X та обчислює Y = e^(a*x).
    Якщо правильно — продовжує сесію (створює новий токен), інакше — викидає користувача
    """
    prepare_asks_if_empty()

    xs = []
    with open(ASK_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 2:
                try:
                    x = float(parts[0])
                    fx_saved = float(parts[1])
                    xs.append((x, fx_saved))
                except ValueError:
                    continue

    if not xs:
        print("Файл ask.txt порожній або пошкоджений.")
        log_action(username, "auth_fail_no_data")
        return False

    x, fx_saved = random.choice(xs)
    fx_calc = F(x)

    print("\nПеревірка токена:")
    print(f"Випадкове значення X = {x:.4f}")
    print(f"Значення з файлу e^(a * x) = {fx_saved:.12f}")
    print(f"Обчислене e^(a * x) = {fx_calc:.12f}")

    if abs(fx_calc - fx_saved) < 1e-12:
        print("Перевірка пройдена — автентифікація успішна.\n")
        authenticate_user(username)
        log_action(username, "auth_ok_auto")
        return True
    else:
        print("Перевірка не пройдена — значення не збігаються.\n")
        log_action(username, "auth_fail_auto")
        return False


def gcd(a, b):
    """Шукає найбільший спільний дільник"""
    if b == 0:
        return a
    else:
        return gcd(b, a % b)


def xgcd(a, b):
    """Розширений алгоритм Евкліда"""
    x, old_x = 0, 1
    y, old_y = 1, 0
    while b != 0:
        quotient = a // b
        a, b = b, a - quotient * b
        old_x, x = x, old_x - quotient * x
        old_y, y = y, old_y - quotient * y
    return a, old_x, old_y


def chooseE(totient):
    """Обирає відкрите число e для RSA"""
    while True:
        e = random.randrange(2, totient)
        if gcd(e, totient) == 1:
            return e


def num_decimal_digits(n: int) -> int:
    """Повертає кількість десяткових цифр в n (n > 0)."""
    return len(str(n))

def choose_keys():
    """
    Обирає p, q з PRIMES_FILE такі, щоб n = p*q мав рівно R десяткових знаків.
    Записує public_keys.txt (n, e) та private_keys.txt (n, d).
    """
    if not os.path.exists(PRIMES_FILE):
        print(f"Файл з простими числами {PRIMES_FILE} не знайдено.")
        return False

    with open(PRIMES_FILE, 'r', encoding='utf-8') as f:
        primes = [int(line.strip()) for line in f if line.strip().isdigit()]
    primes.sort()

    if len(primes) < 2:
        print("Недостатньо простих чисел у файлі.")
        return False

    lower = 10**(R - 1)
    upper = 10**R - 1

    indices = list(range(len(primes)))
    random.shuffle(indices)

    found = False
    p = q = None

    for idx in indices:
        p_candidate = primes[idx]
        q_min = (lower + p_candidate - 1) // p_candidate
        q_max = upper // p_candidate
        if q_min > q_max:
            continue

        possible_q = [q for q in primes if q_min <= q <= q_max and q != p_candidate]
        if possible_q:
            q_candidate = random.choice(possible_q)
            p, q = p_candidate, q_candidate
            found = True
            break

    attempts = 0
    while not found and attempts < 5000:
        p_candidate = random.choice(primes)
        q_candidate = random.choice(primes)
        if p_candidate == q_candidate:
            attempts += 1
            continue
        n_candidate = p_candidate * q_candidate
        if num_decimal_digits(n_candidate) == R:
            p, q = p_candidate, q_candidate
            found = True
            break
        attempts += 1

    if not found:
        print(f"Не вдалося підібрати p і q для {R} цифр. Будуть використані останні два простих.")
        p, q = primes[-1], primes[-2]

    n = p * q
    totient = (p - 1) * (q - 1)
    e = chooseE(totient)
    g, x, _ = xgcd(e, totient)
    d = x + totient if x < 0 else x

    with open(PUBLIC_KEY_FILE, 'w', encoding='utf-8') as f:
        f.write(f"{n}\n{e}\n")
    with open(PRIVATE_KEY_FILE, 'w', encoding='utf-8') as f:
        f.write(f"{n}\n{d}\n")

    print(f"RSA ключі згенеровано (public_keys.txt / private_keys.txt). n має {num_decimal_digits(n)} цифр.")
    log_action('system', 'choose_keys')
    return True


def rsa_encrypt_message(message, file_name=PUBLIC_KEY_FILE, block_size=2):
    """
    Шифрує рядок message. Повертає зашифроване повідомлення у вигляді рядку чисел (через пробіли).
    """
    try:
        with open(file_name, 'r', encoding='utf-8') as fo:
            n = int(fo.readline().strip())
            e = int(fo.readline().strip())
    except FileNotFoundError:
        print('Файл публічного ключа не знайдено.')
        return None

    encrypted_blocks = []
    ciphertext = None

    if len(message) > 0:
        ciphertext = ord(message[0])

    for i in range(1, len(message)):
        if i % block_size == 0:
            encrypted_blocks.append(ciphertext)
            ciphertext = 0
        ciphertext = ciphertext * 1000 + ord(message[i])
    if ciphertext is not None:
        encrypted_blocks.append(ciphertext)

    for i in range(len(encrypted_blocks)):
        encrypted_blocks[i] = str(pow(encrypted_blocks[i], e, n))

    encrypted_message = " ".join(encrypted_blocks)
    return encrypted_message


def rsa_decrypt_blocks(blocks, block_size=2):
    """Дешифрує рядок чисел (з close.txt) і повертає розшифрований рядок"""
    if not os.path.exists(PRIVATE_KEY_FILE):
        print("Файл приватного ключа не знайдено.")
        return None
    with open(PRIVATE_KEY_FILE, 'r', encoding='utf-8') as fo:
        n = int(fo.readline().strip())
        d = int(fo.readline().strip())

    list_blocks = blocks.split()
    int_blocks = [int(s) for s in list_blocks if s.strip()]

    message = ""
    for i in range(len(int_blocks)):
        val = pow(int_blocks[i], d, n)
        tmp = ""
        for c in range(block_size):
            tmp = chr(val % 1000) + tmp
            val //= 1000
        message += tmp
    return message.replace('\x00', '')


def has_right(right_letter):
    """Перевіряє, чи має поточний користувач конкретні права (E, R, W, A)."""
    global user_rights
    if not user_rights:
        return False
    rights_set = set([r.strip().upper() for r in user_rights.split(',') if r.strip()])
    return right_letter.upper() in rights_set


def encrypt_file_action():
    """Отримує текст від користувача для шифрування"""
    global current_user
    if not has_right('E'):
        print("У вас немає права виконання (E) — операція заборонена.")
        return

    user_input_file = f"input_{current_user}.txt"
    user_close_file = f"close_{current_user}.txt"

    text = input("Введіть текст для шифрування: ").strip()
    if not text:
        print("Порожній текст, операція скасована.")
        return

    with open(user_input_file, 'w', encoding='utf-8') as f:
        f.write(text)

    enc = rsa_encrypt_message(text)
    if enc is None:
        return

    with open(user_close_file, 'w', encoding='utf-8') as f:
        f.write(enc)

    print(f"Файл '{user_input_file}' зашифровано -> '{user_close_file}'.")
    log_action(current_user, f"encrypt_file_{user_input_file}")


def decrypt_file_action():
    """Перевіряє чи має користувач права на розшифровку та далі викликає функцію rsa_decrypt_blocks"""
    global current_user
    if not has_right('R') and current_user != ADMIN_USERNAME:
        print("У вас немає права читання (R) — операція заборонена.")
        return

    if current_user == ADMIN_USERNAME:
        target_user = input("Вкажіть ім’я користувача, чий файл потрібно розшифрувати: ").strip()
        user_close_file = f"close_{target_user}.txt"
        user_out_file = f"out_{target_user}.txt"
    else:
        user_close_file = f"close_{current_user}.txt"
        user_out_file = f"out_{current_user}.txt"

    if not os.path.exists(user_close_file):
        print(f"Файл {user_close_file} не знайдено.")
        return

    with open(user_close_file, 'r', encoding='utf-8') as f:
        enc = f.read()

    dec = rsa_decrypt_blocks(enc)
    if dec is None:
        return

    with open(user_out_file, 'w', encoding='utf-8') as f:
        f.write(dec)

    print(f"Файл '{user_close_file}' розшифровано -> '{user_out_file}'.")
    log_action(current_user, f"decrypt_file_{user_close_file}")


def generate_keys_action():
    """Перевіряє чи є можливість у користувача генерувати ключі"""
    global current_user
    if not has_right('W'):
        print("У вас немає права записувати (W) — генерація ключів заборонена.")
        return
    if not has_right('A'):
        print("У вас немає права доповнення (A) — генерація ключів неможлива.")
        return
    ok = choose_keys()
    if ok:
        print("Ключі згенеровано у public_keys.txt / private_keys.txt")


def show_users_action():
    """Перевіряє чи користувач адміністратор - щоб надалі дати йому можливість переглядати користувачів (для дебагу)"""
    global current_user
    if current_user != ADMIN_USERNAME:
        print("Лише адміністратор може переглядати список користувачів.")
        return
    users = read_users()
    print("Користувачі:")
    for u, info in users.items():
        print(f" - {u} | rights: {info['rights']} | disks: {info['disks']}")


def read_catalog_file():
    """Дає можливість переглянути каталог"""
    global current_user
    users = read_users()
    if current_user not in users:
        print("Користувача не знайдено.")
        return

    disks = users[current_user]['disks'].split(',')
    print(f"Доступні категорії: {', '.join(disks)}")

    cat = input("Вкажіть назву категорії (Наприклад: А): ").strip().upper()
    if cat not in disks:
        print("У вас немає доступу до цієї категорії.")
        return

    filename = f"Catalog_{cat}.txt"
    if not os.path.exists(filename):
        print(f"Файл {filename} не знайдено.")
        return

    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()
    print(f"\nВміст файлу {filename}:\n{'-' * 30}\n{content}\n{'-' * 30}")
    log_action(current_user, f"read_catalog_{filename}")


def logout():
    """Завершення поточної сесії користувача"""
    global current_user, user_rights, token, token_expiry
    if current_user:
        log_action(current_user, 'logout')
    print("Ви вийшли із сесії.")
    current_user = None
    user_rights = ''
    token = None
    token_expiry = None


def require_session(func):
    """Декоратор, для перевірки чи залогінився користувач та чи актуальний токен"""

    def wrapper(*args, **kwargs):
        global current_user, user_rights
        if not current_user:
            print("Спочатку виконайте вхід.")
            return
        if not is_token_valid():
            ok = ask_continue_session(current_user)
            if not ok:
                print("Сесію завершено — виконайте повторний вхід.")
                log_action(current_user or 'unknown', 'session_terminated')
                logout()
                return
        return func(*args, **kwargs)

    return wrapper


encrypt_file = require_session(encrypt_file_action)
decrypt_file = require_session(decrypt_file_action)
generate_keys = require_session(generate_keys_action)
read_catalog_file = require_session(read_catalog_file)
register_user_cli = require_session(lambda: register_user(current_user))
delete_user_cli = require_session(lambda: delete_user(current_user))
show_users_cli = require_session(show_users_action)


def admin_menu():
    """Меню адміністратора"""
    print(f"\n=== Меню (адміністратор: {current_user}) ===")
    print("1. Зареєструвати користувача")
    print("2. Видалити користувача")
    print("3. Показати користувачів")
    print("4. Генерація RSA ключів")
    print("5. Шифрування повідомлення")
    print("6. Розшифрування повідомлення (будь-кого)")
    print("7. Перегляд файлів-каталогів")
    print("0. Вихід")


def user_menu():
    """Меню користувача"""
    print(f"\n=== Меню (користувач: {current_user}) ===")
    print("1. Шифрування (input_<username>.txt -> close_<username>.txt)")
    print("2. Розшифрування (close_<username>.txt -> out_<username>.txt)")
    print("3. Перегляд файлів-каталогів (Catalog_*)")
    print("4. Генерація RSA ключів")
    print("0. Вихід")


def main():
    ensure_files()
    ensure_admin()
    global current_user

    while True:
        while not current_user:
            print("\n=== Вхід у систему ===")
            identify()

        if current_user == ADMIN_USERNAME:
            admin_menu()
            ch = input("Вибір: ").strip()
            if ch == '1':
                register_user_cli()
            elif ch == '2':
                delete_user_cli()
            elif ch == '3':
                show_users_cli()
            elif ch == '4':
                generate_keys()
            elif ch == '5':
                encrypt_file()
            elif ch == '6':
                decrypt_file()
            elif ch == '7':
                read_catalog_file()
            elif ch == '0':
                logout()
            else:
                print("Невірна команда.")

        else:
            user_menu()
            ch = input("Вибір: ").strip()
            if ch == '1':
                encrypt_file()
            elif ch == '2':
                decrypt_file()
            elif ch == '3':
                read_catalog_file()
            elif ch == '4':
                generate_keys()
            elif ch == '0':
                logout()
            else:
                print("Невірна команда.")


if __name__ == '__main__':
    main()
