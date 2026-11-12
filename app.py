import json
import os
import smtplib
import socket
import sqlite3
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from functools import wraps

import requests
from flask import (Flask, flash, jsonify, redirect, render_template, request,
                   url_for)
from flask_login import (LoginManager, UserMixin, current_user, login_required,
                         login_user, logout_user)
from flask_wtf import FlaskForm
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import PasswordField, SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, Length, Optional

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'change-me-in-production')

# часовой пояс: по умолчанию Москва, переопределяется переменной TZ
os.environ.setdefault('TZ', 'Europe/Moscow')
try:
    time.tzset()
except AttributeError:  # Windows
    pass

DB_NAME = os.environ.get('DB_NAME', 'port_scanner.db')
SCAN_WORKERS = int(os.environ.get('SCAN_WORKERS', '200'))
SOCKET_TIMEOUT = float(os.environ.get('SOCKET_TIMEOUT', '1.2'))
PROBE_RETRIES = int(os.environ.get('PROBE_RETRIES', '1'))
PROBE_RETRY_DELAY = float(os.environ.get('PROBE_RETRY_DELAY', '0.2'))
# Порти, які не ответили (таймаут/ошибка), перепроверяем после основного прохода
# медленнее и с большим таймаутом: фильтры на маршрутизаторах роняют часть SYN
# при плотном сканировании, и открытый порт иначе остаётся незамеченным.
TCP_CONFIRM_ROUNDS = int(os.environ.get('TCP_CONFIRM_ROUNDS', '2'))
TCP_CONFIRM_TIMEOUT = float(os.environ.get('TCP_CONFIRM_TIMEOUT', '2.5'))
TCP_CONFIRM_DELAY = float(os.environ.get('TCP_CONFIRM_DELAY', '1.0'))
TCP_CONFIRM_WORKERS = int(os.environ.get('TCP_CONFIRM_WORKERS', '100'))
CLOSE_CONFIRM = int(os.environ.get('CLOSE_CONFIRM', '2'))
CHUNK_SIZE = int(os.environ.get('CHUNK_SIZE', '2000'))
SCHED_TICK = int(os.environ.get('SCHED_TICK', '5'))

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                 3306, 3389, 5432, 8080, 8291, 8443]
DEFAULT_PORTS_STR = ','.join(str(p) for p in DEFAULT_PORTS)

DEFAULT_UDP_PORTS = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520,
                     1900, 4500, 5353]
DEFAULT_UDP_PORTS_STR = ','.join(str(p) for p in DEFAULT_UDP_PORTS)

PORT_SERVICES = {
    20: 'FTP-data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 80: 'HTTP',
    110: 'POP3', 123: 'NTP', 135: 'MS RPC', 137: 'NetBIOS', 138: 'NetBIOS',
    139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 162: 'SNMP trap', 389: 'LDAP',
    443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 500: 'IKE', 514: 'Syslog',
    520: 'RIP', 587: 'SMTP submission', 636: 'LDAPS', 993: 'IMAPS',
    995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 1900: 'SSDP',
    2049: 'NFS', 3306: 'MySQL', 3389: 'RDP', 4500: 'IPSec NAT-T',
    5432: 'PostgreSQL', 5353: 'mDNS', 5900: 'VNC', 6379: 'Redis',
    8080: 'HTTP-alt', 8291: 'MikroTik Winbox', 8443: 'HTTPS-alt',
    9200: 'Elasticsearch', 27017: 'MongoDB',
}
app.jinja_env.globals['PORT_SERVICES'] = PORT_SERVICES
DEFAULT_RANGE = '192.168.1.1-254'
DEFAULT_INTERVAL = 60

STATUS_LABELS = {
    'running': 'выполняется',
    'completed': 'завершено',
    'stopped': 'остановлено',
    'interrupted': 'прервано',
    'failed': 'ошибка',
}
app.jinja_env.filters['status_ru'] = lambda s: STATUS_LABELS.get(s, s or '')


def fmt_dt(value):
    """2026-11-12T10:20:19 -> 2026.11.12 10:20:19"""
    if value in (None, ''):
        return '—'
    text = str(value).strip()
    if len(text) >= 19 and text[4] == '-' and text[7] == '-' and text[10] in 'T ':
        return f'{text[0:4]}.{text[5:7]}.{text[8:10]} {text[11:19]}'
    try:
        return datetime.fromisoformat(text).strftime('%Y.%m.%d %H:%M:%S')
    except ValueError:
        return text


app.jinja_env.filters['dt'] = fmt_dt

ROLE_ADMIN = 'admin'
ROLE_SECURITY = 'security'
ROLE_USER = 'user'

ROLE_LABELS = {
    ROLE_ADMIN: 'Администратор',
    ROLE_SECURITY: 'Специалист ИБ',
    ROLE_USER: 'Пользователь',
}

MANAGE_ROLES = (ROLE_ADMIN, ROLE_SECURITY)

app.jinja_env.globals.update(
    ROLE_LABELS=ROLE_LABELS,
    MANAGE_ROLES=MANAGE_ROLES,
    ROLE_ADMIN=ROLE_ADMIN,
    ROLE_SECURITY=ROLE_SECURITY,
    ROLE_USER=ROLE_USER,
)

_stop_flags = {}
_stop_lock = threading.Lock()


def request_stop(log_id):
    with _stop_lock:
        event = _stop_flags.get(log_id)
    if event:
        event.set()
        return True
    return False


# ------------------------------------------------------------------ база данных


def db():
    conn = sqlite3.connect(DB_NAME, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_column(conn, table, column, ddl):
    cols = [r['name'] for r in conn.execute(f'PRAGMA table_info({table})')]
    if column not in cols:
        conn.execute(f'ALTER TABLE {table} ADD COLUMN {column} {ddl}')


def init_db():
    conn = db()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS hosts (
            ip TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS port_state (
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            PRIMARY KEY (ip, port)
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS port_state_udp (
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            misses INTEGER DEFAULT 0,
            PRIMARY KEY (ip, port)
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            message TEXT
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_range TEXT NOT NULL,
            ports TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT,
            status TEXT DEFAULT 'running'
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS scan_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            level TEXT NOT NULL,
            message TEXT NOT NULL
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS paused_ips (
            ip TEXT PRIMARY KEY,
            paused_at TEXT NOT NULL,
            reason TEXT
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_range TEXT NOT NULL,
            ports TEXT NOT NULL,
            workers INTEGER DEFAULT 200,
            interval_minutes INTEGER NOT NULL,
            enabled INTEGER DEFAULT 1,
            last_run TEXT,
            next_run TEXT,
            created_at TEXT NOT NULL
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS host_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL
        )
    ''')
    cur.execute('CREATE INDEX IF NOT EXISTS idx_events_log ON scan_events(log_id, id)')

    ensure_column(conn, 'scan_logs', 'total', 'INTEGER DEFAULT 0')
    ensure_column(conn, 'scan_logs', 'done', 'INTEGER DEFAULT 0')
    ensure_column(conn, 'scan_logs', 'open_found', 'INTEGER DEFAULT 0')
    ensure_column(conn, 'scan_logs', 'workers', 'INTEGER DEFAULT 0')
    ensure_column(conn, 'scan_logs', 'schedule_id', 'INTEGER')
    ensure_column(conn, 'scan_logs', 'udp_total', 'INTEGER DEFAULT 0')
    ensure_column(conn, 'scan_logs', 'udp_done', 'INTEGER DEFAULT 0')
    ensure_column(conn, 'scan_logs', 'udp_phase', 'TEXT')
    ensure_column(conn, 'scan_logs', 'udp_planned', 'INTEGER DEFAULT 0')
    ensure_column(conn, 'scan_logs', 'udp_done_all', 'INTEGER DEFAULT 0')
    ensure_column(conn, 'scan_logs', 'verify_total', 'INTEGER DEFAULT 0')
    ensure_column(conn, 'scan_logs', 'verify_done', 'INTEGER DEFAULT 0')
    ensure_column(conn, 'hosts', 'updated_at', 'TEXT')
    ensure_column(conn, 'users', 'created_at', 'TEXT')
    ensure_column(conn, 'users', 'last_login', 'TEXT')
    ensure_column(conn, 'port_state', 'misses', 'INTEGER DEFAULT 0')
    ensure_column(conn, 'schedules', 'udp_ports', 'TEXT')
    ensure_column(conn, 'scan_logs', 'udp_ports', 'TEXT')
    ensure_column(conn, 'hosts', 'group_id', 'INTEGER')
    ensure_column(conn, 'hosts', 'comment', 'TEXT')

    # разовый бэкфилл адресов из уже собранных открытых портов
    conn.execute('INSERT OR IGNORE INTO hosts (ip, first_seen, last_seen) '
                 'SELECT ip, MIN(first_seen), MAX(last_seen) FROM port_state GROUP BY ip')
    conn.execute('UPDATE hosts SET updated_at = last_seen WHERE updated_at IS NULL')
    conn.execute('UPDATE hosts SET first_seen = last_seen WHERE first_seen IS NULL')

    conn.execute("UPDATE scan_logs SET status = 'interrupted', end_time = ? "
                 "WHERE status = 'running'",
                 (datetime.now().isoformat(timespec='seconds'),))

    cur.execute('SELECT id, password FROM users WHERE username = ?', ('admin',))
    row = cur.fetchone()
    if not row:
        cur.execute('INSERT INTO users (username, password, role, created_at) '
                    'VALUES (?, ?, ?, ?)',
                    ('admin', generate_password_hash('admin123'), ROLE_ADMIN,
                     datetime.now().isoformat(timespec='seconds')))
    elif not str(row['password']).startswith(('pbkdf2:', 'scrypt:', 'argon2')):
        cur.execute('UPDATE users SET password = ? WHERE id = ?',
                    (generate_password_hash(row['password']), row['id']))
    conn.commit()
    conn.close()


init_db()


# ------------------------------------------------------------------ авторизация


class User(UserMixin):
    def __init__(self, row):
        self.id = str(row['id'])
        self.username = row['username']
        self.role = row['role']

    @property
    def role_label(self):
        return ROLE_LABELS.get(self.role, self.role)

    @property
    def can_manage(self):
        return self.role in MANAGE_ROLES

    @property
    def is_admin(self):
        return self.role == ROLE_ADMIN


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Требуется вход в систему'
login_manager.login_message_category = 'warning'


@login_manager.user_loader
def load_user(user_id):
    conn = db()
    row = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return User(row) if row else None


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapper(*args, **kwargs):
            if current_user.role not in roles:
                flash('Недостаточно прав для этого действия', 'danger')
                return redirect(url_for('dashboard'))
            return view(*args, **kwargs)
        return wrapper
    return decorator


# ------------------------------------------------------------------------ формы


class LoginForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')


class ScanForm(FlaskForm):
    ip_range = StringField('Диапазон IP', validators=[Optional()])
    ports = StringField('TCP-порты', validators=[Optional()])
    udp_ports = StringField('UDP-порты', validators=[Optional()])
    workers = StringField('Потоков', validators=[Optional()])
    submit = SubmitField('Сканировать')


class ScheduleForm(FlaskForm):
    ip_range = StringField('Диапазон IP', validators=[DataRequired()])
    ports = StringField('TCP-порты', validators=[Optional()])
    udp_ports = StringField('UDP-порты', validators=[Optional()])
    workers = StringField('Потоков', validators=[Optional()])
    interval_minutes = StringField('Интервал, мин', validators=[DataRequired()])
    submit = SubmitField('Добавить расписание')


class UserForm(FlaskForm):
    username = StringField('Имя пользователя',
                           validators=[DataRequired(), Length(min=3, max=32)])
    password = PasswordField('Пароль',
                             validators=[DataRequired(), Length(min=6, max=128)])
    role = SelectField('Роль', choices=[
        (ROLE_USER, ROLE_LABELS[ROLE_USER]),
        (ROLE_SECURITY, ROLE_LABELS[ROLE_SECURITY]),
        (ROLE_ADMIN, ROLE_LABELS[ROLE_ADMIN]),
    ])
    submit = SubmitField('Добавить пользователя')


# ------------------------------------------------------------------- утилиты IP


def ip_to_int(ip):
    parts = ip.strip().split('.')
    if len(parts) != 4:
        raise ValueError(f'Некорректный IP: {ip}')
    nums = [int(p) for p in parts]
    if any(n < 0 or n > 255 for n in nums):
        raise ValueError(f'Некорректный IP: {ip}')
    return (nums[0] << 24) + (nums[1] << 16) + (nums[2] << 8) + nums[3]


def int_to_ip(num):
    return f'{(num >> 24) & 255}.{(num >> 16) & 255}.{(num >> 8) & 255}.{num & 255}'


def parse_range(text):
    """Принимает 192.168.1.1-254, 192.168.1.10-192.168.1.50, 192.168.1.0/24."""
    text = (text or '').strip()
    if not text:
        text = DEFAULT_RANGE

    if '/' in text:
        base, bits_text = text.split('/', 1)
        try:
            bits = int(bits_text)
        except ValueError:
            raise ValueError('Маска должна быть числом от 0 до 32, например /24')
        if not 0 <= bits <= 32:
            raise ValueError('Маска должна быть от 0 до 32, например /24')
        size = 1 << (32 - bits)
        if size > 4096:
            raise ValueError('Слишком большая подсеть: максимум /20 (4096 адресов)')
        net = ip_to_int(base.strip()) & ~(size - 1) & 0xFFFFFFFF
        return net, net + size - 1

    if '-' not in text:
        ip_to_int(text)  # проверим корректность одиночного адреса
        value = ip_to_int(text)
        return value, value
    left, right = [p.strip() for p in text.split('-', 1)]
    start = ip_to_int(left)
    if '.' in right:
        end = ip_to_int(right)
    else:
        prefix = left.rsplit('.', 1)[0]
        end = ip_to_int(f'{prefix}.{right}')
    if start > end:
        raise ValueError('Начало диапазона больше конца')
    if end - start > 4096:
        raise ValueError('Слишком большой диапазон (максимум 4096 адресов)')
    return start, end


def range_bounds(ip_range):
    """Возвращает {'first', 'last', 'count'} для отображения в таблицах."""
    try:
        start_int, end_int = parse_range(ip_range)
    except ValueError:
        return {'first': '—', 'last': '—', 'count': 0}
    return {
        'first': int_to_ip(start_int),
        'last': int_to_ip(end_int),
        'count': end_int - start_int + 1,
    }


app.jinja_env.globals['range_bounds'] = range_bounds


def parse_ports(text):
    text = (text or '').strip()
    if not text:
        return list(DEFAULT_PORTS)
    ports = set()
    for chunk in text.replace(';', ',').split(','):
        chunk = chunk.strip()
        if not chunk:
            continue
        if '-' in chunk:
            a, b = chunk.split('-', 1)
            a, b = int(a), int(b)
            if a > b:
                a, b = b, a
            ports.update(range(a, b + 1))
        else:
            ports.add(int(chunk))
    ports = sorted(p for p in ports if 1 <= p <= 65535)
    if not ports:
        raise ValueError('Не указаны корректные порты')
    if len(ports) > 2000:
        raise ValueError('Слишком много портов (максимум 2000)')
    return ports


def parse_udp_ports(text):
    text = (text or '').strip()
    if not text:
        return []
    return parse_ports(text)


def parse_workers(text):
    try:
        workers = int((text or '').strip() or SCAN_WORKERS)
    except ValueError:
        workers = SCAN_WORKERS
    return max(1, min(workers, 1000))


def parse_interval(text):
    try:
        minutes = int((text or '').strip())
    except (TypeError, ValueError):
        raise ValueError('Интервал должен быть числом минут')
    if minutes < 1:
        raise ValueError('Интервал должен быть не меньше 1 минуты')
    if minutes > 10080:
        raise ValueError('Интервал не больше 7 дней (10080 минут)')
    return minutes


def paused_set():
    conn = db()
    rows = conn.execute('SELECT ip FROM paused_ips').fetchall()
    conn.close()
    return {r['ip'] for r in rows}


def chunks(seq, size):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


# --------------------------------------------------------------- уведомления

SETTING_DEFAULTS = {
    'telegram_enabled': '0',
    'telegram_token': '',
    'telegram_chat': '',
    'max_enabled': '0',
    'max_token': '',
    'max_chat': '',
    'zabbix_enabled': '0',
    'zabbix_host': '',
    'zabbix_port': '10051',
    'zabbix_server': '',
    'zabbix_key': 'port.scanner',
    'syslog_enabled': '0',
    'syslog_host': '',
    'syslog_port': '514',
    'syslog_proto': 'udp',
    'email_enabled': '0',
    'smtp_host': '',
    'smtp_port': '25',
    'smtp_user': '',
    'smtp_password': '',
    'smtp_tls': '0',
    'smtp_ssl': '0',
    'mail_from': '',
    'mail_to': '',
}

NOTIFY_GROUPS = {
    'telegram': ('telegram_enabled', 'telegram_token', 'telegram_chat'),
    'max': ('max_enabled', 'max_token', 'max_chat'),
    'zabbix': ('zabbix_enabled', 'zabbix_server', 'zabbix_port', 'zabbix_host',
               'zabbix_key'),
    'syslog': ('syslog_enabled', 'syslog_host', 'syslog_port', 'syslog_proto'),
    'email': ('email_enabled', 'smtp_host', 'smtp_port', 'smtp_user',
              'smtp_password', 'smtp_tls', 'smtp_ssl', 'mail_from', 'mail_to'),
}


def get_settings():
    conn = db()
    rows = conn.execute('SELECT key, value FROM settings').fetchall()
    conn.close()
    data = dict(SETTING_DEFAULTS)
    for row in rows:
        data[row['key']] = row['value']
    return data


def save_settings(values):
    conn = db()
    for key in SETTING_DEFAULTS:
        if key in values:
            conn.execute('INSERT INTO settings (key, value) VALUES (?, ?) '
                         'ON CONFLICT(key) DO UPDATE SET value = excluded.value',
                         (key, values[key]))
    conn.commit()
    conn.close()


def send_telegram(cfg, message):
    token = cfg['telegram_token'].strip()
    chat = cfg['telegram_chat'].strip()
    if not token or not chat:
        raise ValueError('не задан токен или chat_id')
    r = requests.post(f'https://api.telegram.org/bot{token}/sendMessage',
                      json={'chat_id': chat, 'text': message,
                            'disable_web_page_preview': True}, timeout=10)
    if r.status_code != 200:
        raise ValueError(f'Telegram ответил {r.status_code}')


def send_max(cfg, message):
    token = cfg['max_token'].strip()
    chat = cfg['max_chat'].strip()
    if not token or not chat:
        raise ValueError('не задан токен или chat_id')
    r = requests.post('https://botapi.max.ru/messages',
                      params={'access_token': token, 'chat_id': chat},
                      json={'text': message}, timeout=10)
    if r.status_code != 200:
        raise ValueError(f'MAX ответил {r.status_code}')


def send_zabbix(cfg, message):
    server = cfg['zabbix_server'].strip()
    host = cfg['zabbix_host'].strip() or 'port-scanner'
    key = cfg['zabbix_key'].strip() or 'port.scanner'
    port = int(cfg['zabbix_port'] or 10051)
    if not server:
        raise ValueError('не задан адрес Zabbix')
    payload = json.dumps({
        'request': 'sender data',
        'data': [{'host': host, 'key': key, 'value': message}],
    }).encode('utf-8')
    header = b'ZBXD\x01' + struct.pack('<Q', len(payload))
    with socket.create_connection((server, port), timeout=10) as sock:
        sock.sendall(header + payload)
        sock.recv(1024)


def send_syslog(cfg, message):
    host = cfg['syslog_host'].strip()
    port = int(cfg['syslog_port'] or 514)
    proto = (cfg['syslog_proto'] or 'udp').lower()
    if not host:
        raise ValueError('не задан сервер Syslog')
    # facility local0 (16) * 8 + severity info (6)
    line = f'<134>1 {datetime.now().isoformat(timespec="seconds")} ' \
           f'port-scanner - - - {message}'
    data = line.encode('utf-8')
    if proto == 'tcp':
        with socket.create_connection((host, port), timeout=10) as sock:
            sock.sendall(data + b'\n')
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(data, (host, port))
        finally:
            sock.close()


def send_email(cfg, message):
    host = (cfg.get('smtp_host') or '').strip()
    port = int(cfg.get('smtp_port') or 25)
    user = (cfg.get('smtp_user') or '').strip()
    password = cfg.get('smtp_password') or ''
    sender = (cfg.get('mail_from') or '').strip() or user
    raw_to = (cfg.get('mail_to') or '').replace(';', ',')
    recipients = [x.strip() for x in raw_to.split(',') if x.strip()]
    if not host or not sender or not recipients:
        raise ValueError('не заданы SMTP-сервер, отправитель или получатели')

    msg = MIMEText(message, 'plain', 'utf-8')
    msg['Subject'] = 'NetProbe: событие'
    msg['From'] = sender
    msg['To'] = ', '.join(recipients)

    if cfg.get('smtp_ssl') == '1':
        server = smtplib.SMTP_SSL(host, port, timeout=15)
    else:
        server = smtplib.SMTP(host, port, timeout=15)
        if cfg.get('smtp_tls') == '1':
            server.starttls()
    try:
        if user:
            server.login(user, password)
        server.sendmail(sender, recipients, msg.as_string())
    finally:
        try:
            server.quit()
        except Exception:  # noqa: BLE001
            pass


CHANNEL_SENDERS = {
    'telegram': send_telegram,
    'max': send_max,
    'zabbix': send_zabbix,
    'syslog': send_syslog,
    'email': send_email,
}


def notify(message, only=None):
    """Рассылает сообщение во включённые каналы. Возвращает список ошибок."""
    cfg = get_settings()
    errors = []
    for name, sender in CHANNEL_SENDERS.items():
        if only and name != only:
            continue
        if cfg.get(f'{name}_enabled') != '1':
            continue
        try:
            sender(cfg, message)
        except Exception as e:  # noqa: BLE001
            errors.append(f'{name}: {e}')
    return errors


def notify_async(message):
    threading.Thread(target=notify, args=(message,), daemon=True).start()



# ------------------------------------------------------------------ сканирование


_REFUSED_CODES = {111, 10061}  # ECONNREFUSED: Linux/BSD и Windows


def probe(ip, port):
    """Проверяет TCP-порт.

    Результат: (ip, port, is_open, error, state), где state —
      'open'     — соединение установилось;
      'refused'  — хост ответил RST, порт точно закрыт;
      'timeout'  — ответа нет (фильтр/потеря пакета) — нужна перепроверка.

    Таймауты повторяем, отказы — нет: RST приходит сразу, повтор ничего
    не изменит и только растягивает скан."""
    attempts = max(1, PROBE_RETRIES + 1)
    err = None
    state = 'timeout'
    for attempt in range(attempts):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT)
        try:
            code = sock.connect_ex((ip, port))
        except OSError as e:
            code, err = -1, str(e)
        finally:
            sock.close()

        if code == 0:
            return ip, port, True, None, 'open'
        if code in _REFUSED_CODES:
            return ip, port, False, None, 'refused'
        state = 'timeout'
        if attempt < attempts - 1:
            time.sleep(PROBE_RETRY_DELAY)

    return ip, port, False, err, state


def confirm_probe(ip, port):
    """Одиночная проверка для второго прохода: длинный таймаут, без спешки."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TCP_CONFIRM_TIMEOUT)
    try:
        code = sock.connect_ex((ip, port))
    except OSError:
        code = -1
    finally:
        sock.close()
    return ip, port, code == 0, None


UDP_TIMEOUT = float(os.environ.get('UDP_TIMEOUT', '0.6'))
UDP_DNS_TIMEOUT = float(os.environ.get('UDP_DNS_TIMEOUT', '1.5'))
UDP_RETRIES = int(os.environ.get('UDP_RETRIES', '2'))
UDP_RETRY_DELAY = float(os.environ.get('UDP_RETRY_DELAY', '0.2'))
UDP_ENABLED = os.environ.get('UDP_ENABLED', '1') != '0'

# некоторые UDP-сервисы молча игнорируют мусор: без корректного запроса порт
# выглядит закрытым. Для популярных протоколов собираем настоящий пакет.
_PROBE_BUILDERS = {}


def _udp_probe(port):
    builder = _PROBE_BUILDERS.get(port)
    if builder:
        return builder()
    return b'\x00', (lambda data: True)


def _dns_probe_payload():
    txid = struct.unpack('!H', os.urandom(2))[0]
    packet = struct.pack('!HHHHHH', txid, 0x0100, 1, 0, 0, 0)
    for label in b'example.com'.split(b'.'):
        packet += bytes([len(label)]) + label
    packet += b'\x00\x00\x01\x00\x01'

    def is_response(data):
        return (len(data) >= 12 and (data[2] & 0x80) == 0x80
                and struct.unpack('!H', data[:2])[0] == txid)

    return packet, is_response


def _mdns_probe_payload():
    txid = struct.unpack('!H', os.urandom(2))[0]
    packet = struct.pack('!HHHHHH', txid, 0x0000, 1, 0, 0, 0)
    for label in b'_services._dns-sd._udp.local'.split(b'.'):
        packet += bytes([len(label)]) + label
    packet += b'\x00\x00\x0c\x80\x01'  # PTR, QU: ответить напрямую

    def is_response(data):
        return len(data) >= 12 and struct.unpack('!H', data[:2])[0] == txid

    return packet, is_response


def _ntp_probe_payload():
    def is_response(data):
        return len(data) >= 48 and (data[0] & 0x07) == 4  # mode 4: сервер

    return b'\x1b' + b'\x00' * 47, is_response


def _snmp_probe_payload():
    packet = bytes.fromhex(
        '302602010004067075626c6963a0190204712b5e2c020100020100300b30090605'
        '2b06010201010500')
    return packet, (lambda data: len(data) >= 10 and data[0] == 0x30)


def _ssdp_probe_payload():
    packet = (b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
              b'MAN: "ssdp:discover"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n')
    return packet, (lambda data: data[:5] in (b'HTTP/',))


def _netbios_probe_payload():
    txid = struct.unpack('!H', os.urandom(2))[0]
    packet = struct.pack('!HHHHHH', txid, 0x0000, 1, 0, 0, 0)
    packet += b'\x20' + b'CK' + b'A' * 30 + b'\x00'  # имя '*'
    packet += b'\x00\x21\x00\x01'                     # NBSTAT, IN

    def is_response(data):
        return len(data) >= 12 and data[:2] == packet[:2]

    return packet, is_response


def _tftp_probe_payload():
    packet = b'\x00\x01' + b'netprobe' + b'\x00' + b'octet' + b'\x00'
    # RRQ: сервер ответит DATA или ERROR, причём с другого порта
    return packet, (lambda data: len(data) >= 4 and data[:2] in (b'\x00\x03',
                                                                b'\x00\x05'))


_PROBE_BUILDERS.update({
    53: _dns_probe_payload,
    69: _tftp_probe_payload,
    123: _ntp_probe_payload,
    137: _netbios_probe_payload,
    161: _snmp_probe_payload,
    162: _snmp_probe_payload,
    1900: _ssdp_probe_payload,
    5353: _mdns_probe_payload,
})

# ответ приходит не с того порта, куда отправляли
UDP_REPLY_FROM_ANY_PORT = {69}


def probe_udp(ip, port, attempts=None):
    """UDP: открытым считаем порт, который ответил на корректный запрос.
    Пакет отправляем несколько раз: UDP теряется, а часть сервисов отвечает
    не с первого раза."""
    attempts = max(1, attempts or UDP_RETRIES)
    timeout = UDP_DNS_TIMEOUT if port == 53 else UDP_TIMEOUT
    for attempt in range(attempts):
        payload, is_response = _udp_probe(port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            if port in UDP_REPLY_FROM_ANY_PORT:
                sock.sendto(payload, (ip, port))
                data, peer = sock.recvfrom(2048)
                if peer[0] == ip and is_response(data):
                    return ip, port, True, None
            else:
                sock.connect((ip, port))
                sock.send(payload)
                if is_response(sock.recv(2048)):
                    return ip, port, True, None
        except OSError:
            pass
        finally:
            sock.close()
        if attempt < attempts - 1:
            time.sleep(UDP_RETRY_DELAY)
    return ip, port, False, None


def apply_udp_batch(conn, log_id, batch, suppress=None, count_miss=True):
    now = datetime.now().isoformat(timespec='seconds')
    suppress = suppress or set()
    opened = 0
    changed = set()

    for ip, port, is_open, _err in batch:
        row = conn.execute('SELECT misses FROM port_state_udp '
                           'WHERE ip = ? AND port = ?', (ip, port)).fetchone()
        if is_open:
            if row:
                conn.execute('UPDATE port_state_udp SET last_seen = ?, misses = 0 '
                             'WHERE ip = ? AND port = ?', (now, ip, port))
            else:
                conn.execute('INSERT INTO port_state_udp '
                             '(ip, port, first_seen, last_seen) VALUES (?, ?, ?, ?)',
                             (ip, port, now, now))
                if ip in suppress:
                    add_event(conn, log_id, 'info',
                              f'первый скан UDP {ip}:{port} — без алерта')
                else:
                    conn.execute('INSERT INTO alerts '
                                 '(ip, port, action, timestamp, message) '
                                 "VALUES (?, ?, 'opened', ?, ?)",
                                 (ip, port, now,
                                  f'Новый открытый UDP-порт {port} на {ip}'))
                    add_event(conn, log_id, 'opened',
                              f'НОВЫЙ ОТКРЫТЫЙ UDP-ПОРТ {ip}:{port}')
                    notify_async(f'Новый открытый UDP-порт {port} на {ip}')
                opened += 1
                changed.add(ip)
        elif row and not count_miss:
            # UDP теряется: промах засчитывает только второй проход
            pass
        elif row:
            misses = (row['misses'] or 0) + 1
            if misses >= CLOSE_CONFIRM:
                conn.execute('DELETE FROM port_state_udp WHERE ip = ? AND port = ?',
                             (ip, port))
                conn.execute('INSERT INTO alerts (ip, port, action, timestamp, message) '
                             "VALUES (?, ?, 'closed', ?, ?)",
                             (ip, port, now, f'UDP-порт {port} закрыт на {ip}'))
                add_event(conn, log_id, 'closed',
                          f'UDP-порт закрыт {ip}:{port} — убран из таблицы')
            else:
                conn.execute('UPDATE port_state_udp SET misses = ? '
                             'WHERE ip = ? AND port = ?', (misses, ip, port))

    for ip in changed:
        conn.execute('UPDATE hosts SET updated_at = ? WHERE ip = ?', (now, ip))
    return opened


def _run_udp_phase(conn, log_id, targets, workers, suppress, attempts,
                   count_miss, stop_event=None):
    """Один проход UDP: возвращает (сколько новых портов, список без ответа)."""
    total = len(targets)
    processed = 0
    opened = 0
    unanswered = []
    batch = []
    conn.execute('UPDATE scan_logs SET udp_total = ?, udp_done = 0 WHERE id = ?',
                 (total, log_id))
    conn.commit()
    with ThreadPoolExecutor(max_workers=max(1, min(workers, total or 1))) as pool:
        futures = [pool.submit(probe_udp, ip, port, attempts)
                   for ip, port in targets]
        for fut in as_completed(futures):
            if stop_event is not None and stop_event.is_set():
                for f in futures:
                    f.cancel()
                break
            res = fut.result()
            batch.append(res)
            if not res[2]:
                unanswered.append((res[0], res[1]))
            if len(batch) >= 100:
                new_ports = apply_udp_batch(conn, log_id, batch, suppress, count_miss)
                opened += new_ports
                processed += len(batch)
                conn.execute('UPDATE scan_logs SET udp_done = ?, '
                             'udp_done_all = COALESCE(udp_done_all, 0) + ?, '
                             'open_found = COALESCE(open_found, 0) + ? WHERE id = ?',
                             (processed, len(batch), new_ports, log_id))
                batch.clear()
                conn.commit()
    if batch:
        new_ports = apply_udp_batch(conn, log_id, batch, suppress, count_miss)
        opened += new_ports
        processed += len(batch)
        conn.execute('UPDATE scan_logs SET udp_done = ?, '
                     'udp_done_all = COALESCE(udp_done_all, 0) + ?, '
                     'open_found = COALESCE(open_found, 0) + ? WHERE id = ?',
                     (processed, len(batch), new_ports, log_id))
        conn.commit()
    return opened, unanswered


def scan_udp(conn, log_id, ips, ports, workers, suppress, stop_event=None):
    """UDP в два прохода: сканирование, затем проверка тех, кто не ответил."""
    if not UDP_ENABLED or not ips:
        return 0
    targets = [(ip, port) for ip in ips for port in ports]
    conn.execute("UPDATE scan_logs SET udp_phase = 'scan' WHERE id = ?", (log_id,))
    conn.commit()
    opened, unanswered = _run_udp_phase(conn, log_id, targets, workers, suppress,
                                        attempts=1, count_miss=False,
                                        stop_event=stop_event)
    add_event(conn, log_id, 'info',
              f'UDP-сканирование: {len(targets)} проверок, новых портов {opened}')

    if unanswered and not (stop_event is not None and stop_event.is_set()):
        conn.execute("UPDATE scan_logs SET udp_phase = 'verify' WHERE id = ?",
                     (log_id,))
        conn.commit()
        add_event(conn, log_id, 'info',
                  f'UDP-проверка без ответа: {len(unanswered)} портов, '
                  f'по {max(1, UDP_RETRIES)} попытки')
        again, _ = _run_udp_phase(conn, log_id, unanswered, workers, suppress,
                                  attempts=max(1, UDP_RETRIES), count_miss=True,
                                  stop_event=stop_event)
        opened += again
        add_event(conn, log_id, 'info',
                  f'UDP-проверка завершена, новых портов: {again}')

    conn.execute("UPDATE scan_logs SET udp_phase = '' WHERE id = ?", (log_id,))
    conn.commit()
    return opened


def add_event(conn, log_id, level, message):
    conn.execute('INSERT INTO scan_events (log_id, timestamp, level, message) '
                 'VALUES (?, ?, ?, ?)',
                 (log_id, datetime.now().isoformat(timespec='seconds'),
                  level, message))


def apply_batch(conn, log_id, batch, suppress=None, count_miss=True):
    now = datetime.now().isoformat(timespec='seconds')
    suppress = suppress or set()

    # каждый проверенный адрес попадает в таблицу, даже без открытых портов
    for ip in {item[0] for item in batch}:
        conn.execute('INSERT INTO hosts (ip, first_seen, last_seen) VALUES (?, ?, ?) '
                     'ON CONFLICT(ip) DO UPDATE SET last_seen = excluded.last_seen',
                     (ip, now, now))

    opened = 0
    changed = set()
    for item in batch:
        ip, port, is_open, error = item[:4]
        state = item[4] if len(item) > 4 else 'open' if is_open else 'timeout'
        if error:
            add_event(conn, log_id, 'warning', f'{ip}:{port} — ошибка: {error}')
            continue

        row = conn.execute('SELECT misses FROM port_state WHERE ip = ? AND port = ?',
                           (ip, port)).fetchone()
        if is_open:
            if row:
                conn.execute('UPDATE port_state SET last_seen = ?, misses = 0 '
                             'WHERE ip = ? AND port = ?', (now, ip, port))
            else:
                conn.execute('INSERT INTO port_state (ip, port, first_seen, last_seen) '
                             'VALUES (?, ?, ?, ?)', (ip, port, now, now))
                if ip in suppress:
                    # первый скан адреса: фиксируем порт, но алерт не шлём
                    add_event(conn, log_id, 'info',
                              f'первый скан {ip}:{port} — без алерта')
                else:
                    conn.execute('INSERT INTO alerts (ip, port, action, timestamp, message) '
                                 "VALUES (?, ?, 'opened', ?, ?)",
                                 (ip, port, now, f'Новый открытый порт {port} на {ip}'))
                    add_event(conn, log_id, 'opened', f'НОВЫЙ ОТКРЫТЫЙ ПОРТ {ip}:{port}')
                    notify_async(f'Новый открытый порт {port} на {ip}')
                opened += 1
                changed.add(ip)
        elif row and not count_miss:
            # таймаут в первом проходе: закрытием не считаем, порт перепроверят
            pass
        elif row:
            misses = (row['misses'] or 0) + 1
            if misses >= CLOSE_CONFIRM:
                conn.execute('DELETE FROM port_state WHERE ip = ? AND port = ?',
                             (ip, port))
                conn.execute('INSERT INTO alerts (ip, port, action, timestamp, message) '
                             "VALUES (?, ?, 'closed', ?, ?)",
                             (ip, port, now, f'Порт {port} закрыт на {ip}'))
                add_event(conn, log_id, 'closed',
                          f'порт закрыт {ip}:{port} — убран из таблицы')
                changed.add(ip)
            else:
                # одиночный таймаут не считается закрытием порта
                conn.execute('UPDATE port_state SET misses = ? '
                             'WHERE ip = ? AND port = ?', (misses, ip, port))
                add_event(conn, log_id, 'info',
                          f'{ip}:{port} не ответил ({misses}/{CLOSE_CONFIRM}) — '
                          f'оставляем в таблице')

    for ip in changed:
        conn.execute('UPDATE hosts SET updated_at = ? WHERE ip = ?', (now, ip))
    return opened


def run_chunk(pool, conn, log_id, chunk, stop_event, done, opened_total,
              suppress=None, uncertain=None):
    futures = [pool.submit(probe, ip, port) for ip, port in chunk]
    batch = []
    opened = 0
    processed = 0
    try:
        for fut in as_completed(futures):
            if stop_event.is_set():
                break
            res = fut.result()
            batch.append(res)
            if uncertain is not None and res[4] == 'timeout':
                uncertain.append((res[0], res[1]))
            processed += 1
            if len(batch) >= 100:
                opened += apply_batch(conn, log_id, batch, suppress, count_miss=False)
                batch.clear()
                conn.execute('UPDATE scan_logs SET done = ?, open_found = ? WHERE id = ?',
                             (done + processed, opened_total + opened, log_id))
                conn.commit()
    finally:
        if stop_event.is_set():
            for f in futures:
                f.cancel()
        if batch:
            opened += apply_batch(conn, log_id, batch, suppress, count_miss=False)
        if processed:
            conn.execute('UPDATE scan_logs SET done = ?, open_found = ? WHERE id = ?',
                         (done + processed, opened_total + opened, log_id))
            conn.commit()
    return opened


def confirm_timeouts(conn, log_id, pairs, workers, suppress=None, stop_event=None):
    """Второй проход по портам, которые не ответили в основном проходе.

    Плотный поток SYN часть маршрутизаторов и провайдеров отбрасывает, и
    открытый порт выглядит закрытым. Такие пары перепроверяем медленнее и с
    длинным таймаутом: нашли — записываем как открытый; не ответил ни разу —
    только тогда считаем порт закрытым."""
    if not pairs:
        return 0
    unique = sorted(set(pairs))
    rounds = max(1, TCP_CONFIRM_ROUNDS)
    processed = 0
    opened = 0
    found_total = 0
    pending = unique
    add_event(conn, log_id, 'info',
              f'Повторная проверка без ответа: {len(unique)} портов, '
              f'до {rounds} круга по {TCP_CONFIRM_TIMEOUT} с')
    conn.execute('UPDATE scan_logs SET verify_total = ?, verify_done = 0 WHERE id = ?',
                 (len(unique), log_id))
    conn.commit()

    for rnd in range(rounds):
        if not pending:
            break
        if rnd:
            time.sleep(TCP_CONFIRM_DELAY)
        conn.execute('UPDATE scan_logs SET verify_total = ?, verify_done = ? '
                     'WHERE id = ?', (processed + len(pending), processed, log_id))
        conn.commit()
        conf_workers = max(1, min(TCP_CONFIRM_WORKERS,
                                  workers or TCP_CONFIRM_WORKERS, len(pending)))
        still = []
        found = []
        done_now = 0
        round_found = 0
        interrupted = False
        with ThreadPoolExecutor(max_workers=conf_workers) as pool:
            futures = [pool.submit(confirm_probe, ip, port) for ip, port in pending]
            for fut in as_completed(futures):
                if stop_event is not None and stop_event.is_set():
                    for f in futures:
                        f.cancel()
                    interrupted = True
                    break
                ip, port, is_open, _ = fut.result()
                done_now += 1
                if is_open:
                    found.append((ip, port, True, None, 'open'))
                    round_found += 1
                else:
                    still.append((ip, port))
                if len(found) >= 50:
                    opened += apply_batch(conn, log_id, found, suppress)
                    found.clear()
                if done_now % 50 == 0:
                    conn.execute('UPDATE scan_logs SET verify_done = ? WHERE id = ?',
                                 (processed + done_now, log_id))
                    conn.commit()
        if found:
            opened += apply_batch(conn, log_id, found, suppress)
        processed += done_now
        found_total += round_found
        conn.execute('UPDATE scan_logs SET verify_total = ?, verify_done = ? '
                     'WHERE id = ?', (processed + len(still), processed, log_id))
        conn.commit()
        add_event(conn, log_id, 'info',
                  f'Круг {rnd + 1}: перепроверено {done_now}, '
                  f'найдено открытыми {round_found}')
        pending = still
        if interrupted:
            break

    if pending and stop_event is not None and stop_event.is_set():
        # сканирование остановили — промахи не считаем
        pending = []

    # порты, которые не ответили даже на медленный запрос, считаем закрытыми
    if pending:
        closed = [(ip, port, False, None, 'timeout') for ip, port in pending]
        for i in range(0, len(closed), 200):
            apply_batch(conn, log_id, closed[i:i + 200], suppress, count_miss=True)
        add_event(conn, log_id, 'info',
                  f'Не ответили ни разу за {rounds} круга: {len(closed)} портов '
                  f'— считаем закрытыми')

    conn.execute('UPDATE scan_logs SET verify_total = ?, verify_done = ? WHERE id = ?',
                 (processed, processed, log_id))
    conn.commit()
    if found_total:
        add_event(conn, log_id, 'info',
                  f'Повторная проверка нашла открытых портов: {found_total}')
    return opened


def known_ips(ips):
    """Адреса, которые уже сканировались ранее (есть в hosts)."""
    conn = db()
    known = set()
    try:
        for chunk in chunks(ips, 500):
            placeholders = ','.join('?' * len(chunk))
            rows = conn.execute(
                f'SELECT ip FROM hosts WHERE ip IN ({placeholders})', chunk).fetchall()
            for row in rows:
                known.add(row['ip'])
    finally:
        conn.close()
    return known


def scan_worker(ips, tcp_ports, udp_ports, log_id, workers):
    ports = tcp_ports
    total = len(ips) * len(ports)
    done = 0
    opened_total = 0
    stop_event = threading.Event()

    # адреса, которые сканируются впервые: алерты по ним не отправляем
    suppress = set(ips) - known_ips(ips)

    with _stop_lock:
        _stop_flags[log_id] = stop_event

    conn = db()
    conn.execute('UPDATE scan_logs SET total = ?, done = 0, open_found = 0, '
                 'udp_total = 0, udp_done = 0, udp_done_all = 0, udp_phase = \'\', '
                 'verify_total = 0, verify_done = 0, '
                 "status = 'running', workers = ? WHERE id = ?",
                 (total, workers, log_id))
    if suppress:
        add_event(conn, log_id, 'info',
                  'Первый скан адресов: {0} — события по ним не создаются'
                  .format(len(suppress)))
    conn.commit()

    status = 'completed'
    try:
        if not ips:
            add_event(conn, log_id, 'warning',
                      'Все адреса диапазона на паузе — сканировать нечего')
            conn.commit()
        else:
            uncertain = []
            with ThreadPoolExecutor(max_workers=workers) as pool:
                chunk = []
                for ip in ips:
                    if stop_event.is_set():
                        status = 'stopped'
                        break
                    for port in ports:
                        chunk.append((ip, port))
                        if len(chunk) >= CHUNK_SIZE:
                            opened_total += run_chunk(pool, conn, log_id, chunk,
                                                      stop_event, done, opened_total,
                                                      suppress, uncertain)
                            done += len(chunk)
                            chunk = []
                            if stop_event.is_set():
                                break
                    if stop_event.is_set():
                        status = 'stopped'
                        break
                if chunk and not stop_event.is_set():
                    opened_total += run_chunk(pool, conn, log_id, chunk,
                                              stop_event, done, opened_total,
                                              suppress, uncertain)
                    done += len(chunk)
            if not stop_event.is_set() and uncertain:
                opened_total += confirm_timeouts(conn, log_id, uncertain, workers,
                                                 suppress, stop_event)
            if not stop_event.is_set() and udp_ports:
                udp_opened = scan_udp(conn, log_id, ips, udp_ports, workers, suppress,
                                      stop_event)
                opened_total += udp_opened
    except Exception as e:  # noqa: BLE001
        add_event(conn, log_id, 'error', f'Сканирование прервано: {e}')
        status = 'failed'
    finally:
        conn.execute('UPDATE scan_logs SET end_time = ?, status = ?, done = ?, '
                     'open_found = ?, total = ? WHERE id = ?',
                     (datetime.now().isoformat(timespec='seconds'), status,
                      done, opened_total, total, log_id))
        if status == 'stopped':
            add_event(conn, log_id, 'warning',
                      f'Остановлено: проверено {done} из {total}, '
                      f'новых открытых портов — {opened_total}')
        else:
            add_event(conn, log_id, 'info',
                      f'Завершено: проверено {done} из {total}, '
                      f'новых открытых портов — {opened_total}')
        conn.commit()
        conn.close()
        with _stop_lock:
            _stop_flags.pop(log_id, None)


def _launch_scan(ips, label, ports_text, ports, udp_text, udp_ports, workers,
                 schedule_id=None):
    """Создаёт задание и запускает воркер для готового списка адресов."""
    paused = paused_set()
    skipped = [ip for ip in ips if ip in paused]
    active = [ip for ip in ips if ip not in paused]

    conn = db()
    cur = conn.execute(
        'INSERT INTO scan_logs (ip_range, ports, udp_ports, start_time, status, '
        'total, workers, schedule_id, udp_planned) '
        'VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)',
        (label, ports_text, udp_text,
         datetime.now().isoformat(timespec='seconds'), 'running', workers,
         schedule_id, len(active) * len(udp_ports) * 2))
    log_id = cur.lastrowid
    add_event(conn, log_id, 'info',
              f'Старт: {len(active)} адресов, TCP-портов {len(ports)}, '
              f'UDP-портов {len(udp_ports)}, {workers} потоков, '
              f'таймаут {SOCKET_TIMEOUT} с')
    if skipped:
        shown = ', '.join(skipped[:10]) + ('…' if len(skipped) > 10 else '')
        add_event(conn, log_id, 'info',
                  f'Пропущено адресов на паузе: {len(skipped)} ({shown})')
    conn.commit()
    conn.close()

    threading.Thread(target=scan_worker,
                     args=(active, ports, udp_ports, log_id, workers),
                     daemon=True).start()
    return log_id


def start_scan(ip_range, ports_text, workers_text=None, schedule_id=None,
               udp_ports_text=None):
    start_int, end_int = parse_range(ip_range)
    ports = parse_ports(ports_text)
    udp_text = (udp_ports_text or '').strip()
    udp_ports = parse_udp_ports(udp_text) if udp_text else []
    workers = parse_workers(workers_text)

    ips = [int_to_ip(i) for i in range(start_int, end_int + 1)]
    return _launch_scan(ips, ip_range or DEFAULT_RANGE,
                        ports_text or DEFAULT_PORTS_STR, ports, udp_text,
                        udp_ports, workers, schedule_id)


def start_scan_ips(ips, ports_text, udp_ports_text=None, workers_text=None,
                   label=None):
    """Сканирование произвольного списка адресов (выбор в таблице)."""
    ports = parse_ports(ports_text)
    udp_text = (udp_ports_text or '').strip()
    udp_ports = parse_udp_ports(udp_text) if udp_text else []
    workers = parse_workers(workers_text)
    label = label or f'{len(ips)} адресов (выбор в таблице)'
    return _launch_scan(ips, label, ports_text or DEFAULT_PORTS_STR, ports,
                        udp_text, udp_ports, workers)


def latest_running_job():
    conn = db()
    row = conn.execute("SELECT id FROM scan_logs WHERE status = 'running' "
                       'ORDER BY id DESC LIMIT 1').fetchone()
    conn.close()
    return row['id'] if row else None


# ----------------------------------------------------- удаление диапазона целиком


def delete_range_results(ip_range):
    """Удаляет всё связанное с диапазоном: порты, алерты, задания, события,
    расписания и записи адресов."""
    try:
        start_int, end_int = parse_range(ip_range)
    except ValueError as e:
        raise ValueError(f'Не удалось разобрать диапазон «{ip_range}»: {e}')

    ips = [int_to_ip(i) for i in range(start_int, end_int + 1)]
    conn = db()
    try:
        log_ids = [r['id'] for r in conn.execute(
            'SELECT id FROM scan_logs WHERE ip_range = ?', (ip_range,))]

        deleted_ports = 0
        deleted_alerts = 0
        deleted_hosts = 0
        for chunk in chunks(ips, 500):
            placeholders = ','.join('?' * len(chunk))
            deleted_ports += conn.execute(
                f'DELETE FROM port_state WHERE ip IN ({placeholders})', chunk).rowcount
            conn.execute(
                f'DELETE FROM port_state_udp WHERE ip IN ({placeholders})', chunk)
            deleted_alerts += conn.execute(
                f'DELETE FROM alerts WHERE ip IN ({placeholders})', chunk).rowcount
            deleted_hosts += conn.execute(
                f'DELETE FROM hosts WHERE ip IN ({placeholders})', chunk).rowcount

        deleted_events = 0
        if log_ids:
            placeholders = ','.join('?' * len(log_ids))
            deleted_events += conn.execute(
                f'DELETE FROM scan_events WHERE log_id IN ({placeholders})',
                log_ids).rowcount
            conn.execute(f'DELETE FROM scan_logs WHERE id IN ({placeholders})', log_ids)

        deleted_schedules = conn.execute(
            'DELETE FROM schedules WHERE ip_range = ?', (ip_range,)).rowcount

        conn.commit()
    finally:
        conn.close()

    return {
        'ips': len(ips),
        'ports': deleted_ports,
        'alerts': deleted_alerts,
        'hosts': deleted_hosts,
        'jobs': len(log_ids),
        'events': deleted_events,
        'schedules': deleted_schedules,
    }


def range_is_scanning(ip_range):
    conn = db()
    row = conn.execute("SELECT 1 FROM scan_logs WHERE ip_range = ? AND status = 'running'",
                       (ip_range,)).fetchone()
    conn.close()
    return bool(row)


def open_ports_count(ip_range):
    try:
        start_int, end_int = parse_range(ip_range)
    except ValueError:
        return 0
    ips = [int_to_ip(i) for i in range(start_int, end_int + 1)]
    conn = db()
    total = 0
    try:
        for chunk in chunks(ips, 500):
            placeholders = ','.join('?' * len(chunk))
            total += conn.execute(
                f'SELECT COUNT(*) AS c FROM port_state WHERE ip IN ({placeholders})',
                chunk).fetchone()['c']
    finally:
        conn.close()
    return total


def purge_removed_ports(ip_range, tcp_removed, udp_removed):
    """Убирает из результатов порты, которые больше не проверяются.
    Если порт остался в другом расписании для этих адресов — запись сохраняется."""
    tcp_removed = {int(p) for p in tcp_removed}
    udp_removed = {int(p) for p in udp_removed}
    if not tcp_removed and not udp_removed:
        return 0
    try:
        start_int, end_int = parse_range(ip_range)
    except ValueError:
        return 0
    ips = {int_to_ip(i) for i in range(start_int, end_int + 1)}
    conn = db()
    deleted = 0
    try:
        keep_tcp = {p: set() for p in tcp_removed}
        keep_udp = {p: set() for p in udp_removed}
        for s in conn.execute('SELECT ip_range, ports, udp_ports FROM schedules'):
            try:
                s_start, s_end = parse_range(s['ip_range'])
                s_tcp = set(parse_ports(s['ports'] or DEFAULT_PORTS_STR))
                s_udp = set(parse_udp_ports(s['udp_ports'] or ''))
            except ValueError:
                continue
            s_ips = {int_to_ip(i) for i in range(s_start, s_end + 1)}
            for port in tcp_removed & s_tcp:
                keep_tcp[port] |= s_ips
            for port in udp_removed & s_udp:
                keep_udp[port] |= s_ips

        for table, pids, keeps in (('port_state', tcp_removed, keep_tcp),
                                   ('port_state_udp', udp_removed, keep_udp)):
            for port in pids:
                target = ips - keeps.get(port, set())
                for chunk in chunks(list(target), 500):
                    placeholders = ','.join('?' * len(chunk))
                    deleted += conn.execute(
                        f'DELETE FROM {table} WHERE port = ? AND '
                        f'ip IN ({placeholders})', [port] + chunk).rowcount
        conn.commit()
    finally:
        conn.close()
    return deleted


def scheduled_ips():
    """IP-адреса, которые покрыты расписанием."""
    conn = db()
    ranges = [r['ip_range'] for r in conn.execute('SELECT ip_range FROM schedules')]
    conn.close()
    ips = set()
    for ip_range in ranges:
        try:
            start_int, end_int = parse_range(ip_range)
        except ValueError:
            continue
        ips.update(int_to_ip(i) for i in range(start_int, end_int + 1))
    return ips


def purge_unscheduled(ip_range):
    """Удаляет результаты диапазона, кроме адресов, оставшихся в расписании."""
    try:
        start_int, end_int = parse_range(ip_range)
    except ValueError:
        return {'ips': 0, 'ports': 0, 'alerts': 0, 'hosts': 0}
    keep = scheduled_ips()
    ips = [ip for ip in (int_to_ip(i) for i in range(start_int, end_int + 1))
           if ip not in keep]
    conn = db()
    ports = alerts = hosts = 0
    try:
        for chunk in chunks(ips, 500):
            placeholders = ','.join('?' * len(chunk))
            ports += conn.execute(
                f'DELETE FROM port_state WHERE ip IN ({placeholders})', chunk).rowcount
            conn.execute(
                f'DELETE FROM port_state_udp WHERE ip IN ({placeholders})', chunk)
            alerts += conn.execute(
                f'DELETE FROM alerts WHERE ip IN ({placeholders})', chunk).rowcount
            hosts += conn.execute(
                f'DELETE FROM hosts WHERE ip IN ({placeholders})', chunk).rowcount
        conn.commit()
    finally:
        conn.close()
    return {'ips': len(ips), 'ports': ports, 'alerts': alerts, 'hosts': hosts}


# ------------------------------------------------------------------ планировщик


def scheduler_tick():
    now = datetime.now()
    conn = db()
    try:
        rows = conn.execute('SELECT * FROM schedules WHERE enabled = 1').fetchall()
        for s in rows:
            next_run = s['next_run']
            if next_run:
                try:
                    if datetime.fromisoformat(next_run) > now:
                        continue
                except ValueError:
                    pass
            running = conn.execute(
                "SELECT 1 FROM scan_logs WHERE schedule_id = ? AND status = 'running'",
                (s['id'],)).fetchone()
            if running:
                continue
            try:
                start_scan(s['ip_range'], s['ports'],
                           str(s['workers'] or SCAN_WORKERS), schedule_id=s['id'],
                           udp_ports_text=(s['udp_ports'] or ''))
            except ValueError:
                conn.execute('UPDATE schedules SET enabled = 0 WHERE id = ?', (s['id'],))
                conn.commit()
                continue
            conn.execute('UPDATE schedules SET last_run = ?, next_run = ? WHERE id = ?',
                         (now.isoformat(timespec='seconds'),
                          (now + timedelta(minutes=s['interval_minutes'])
                           ).isoformat(timespec='seconds'), s['id']))
            conn.commit()
    finally:
        conn.close()


def scheduler_loop():
    while True:
        try:
            scheduler_tick()
        except Exception:  # noqa: BLE001
            pass
        time.sleep(SCHED_TICK)


# --------------------------------------------------------------------- маршруты


@app.route('/')
def index():
    return redirect(url_for('dashboard') if current_user.is_authenticated
                    else url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        conn = db()
        row = conn.execute('SELECT * FROM users WHERE username = ?',
                           (form.username.data,)).fetchone()
        password_ok = False
        if row:
            stored = row['password'] or ''
            if stored.startswith(('pbkdf2:', 'scrypt:', 'argon2')):
                password_ok = check_password_hash(stored, form.password.data)
            elif stored == form.password.data:
                # старый открытый пароль — переводим на хэш
                password_ok = True
                conn.execute('UPDATE users SET password = ? WHERE id = ?',
                             (generate_password_hash(stored), row['id']))
                conn.commit()
        conn.close()
        if password_ok:
            conn = db()
            conn.execute('UPDATE users SET last_login = ? WHERE id = ?',
                         (datetime.now().isoformat(timespec='seconds'), row['id']))
            conn.commit()
            conn.close()
            login_user(User(row))
            flash('Вход выполнен', 'success')
            return redirect(url_for('dashboard'))
        flash('Неверное имя пользователя или пароль', 'danger')
    return render_template('login.html', form=form, title='Вход')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    conn = db()
    host_rows = conn.execute('SELECT ip, first_seen, last_seen, updated_at, '
                             'group_id, comment FROM hosts ORDER BY ip').fetchall()
    port_rows = conn.execute('SELECT ip, port, first_seen, last_seen '
                             'FROM port_state ORDER BY ip, port').fetchall()
    udp_rows = conn.execute('SELECT ip, port, first_seen, last_seen '
                            'FROM port_state_udp ORDER BY ip, port').fetchall()
    paused_rows = conn.execute('SELECT * FROM paused_ips ORDER BY ip').fetchall()
    group_rows = conn.execute('SELECT id, name FROM host_groups '
                              'ORDER BY name COLLATE NOCASE').fetchall()
    last_scan = conn.execute('SELECT * FROM scan_logs ORDER BY id DESC LIMIT 1').fetchone()
    conn.close()

    paused = {r['ip'] for r in paused_rows}
    groups = [{'id': r['id'], 'name': r['name']} for r in group_rows]
    ip_data = {}
    for row in host_rows:
        ip_data[row['ip']] = {
            'ip': row['ip'],
            'ports': [],
            'last_seen': row['last_seen'],
            'updated': row['updated_at'] or row['last_seen'],
            'group_id': row['group_id'],
            'comment': row['comment'] or '',
        }
    for row in port_rows:
        data = ip_data.setdefault(row['ip'], {
            'ip': row['ip'], 'ports': [], 'last_seen': row['last_seen'],
            'updated': row['last_seen'], 'group_id': None, 'comment': ''})
        data['ports'].append({'port': row['port'], 'proto': 'tcp'})
        if row['last_seen'] > data['last_seen']:
            data['last_seen'] = row['last_seen']
    for row in udp_rows:
        data = ip_data.setdefault(row['ip'], {
            'ip': row['ip'], 'ports': [], 'last_seen': row['last_seen'],
            'updated': row['last_seen'], 'group_id': None, 'comment': ''})
        data['ports'].append({'port': row['port'], 'proto': 'udp'})
        if row['last_seen'] > data['last_seen']:
            data['last_seen'] = row['last_seen']
    for r in paused_rows:
        ip_data.setdefault(r['ip'], {'ip': r['ip'], 'ports': [],
                                     'last_seen': '—', 'updated': '—',
                                     'group_id': None, 'comment': ''})

    # в таблице только адреса, которые есть в расписании
    scheduled = scheduled_ips()
    ip_data = {ip: data for ip, data in ip_data.items() if ip in scheduled}

    group_names = {g['id']: g['name'] for g in groups}
    for data in ip_data.values():
        data['group'] = group_names.get(data['group_id'], '')

    # по умолчанию сортируем по последнему обнаружению (свежие сверху)
    ordered = dict(sorted(ip_data.items(),
                          key=lambda kv: kv[1]['updated'] or '', reverse=True))

    running = bool(last_scan and last_scan['status'] == 'running')
    udp53_hosts = sum(1 for d in ordered.values()
                      if any(p['port'] == 53 and p['proto'] == 'udp'
                             for p in d['ports']))
    return render_template('dashboard.html', ip_data=ordered, paused=paused,
                           groups=groups, last_scan=last_scan, running=running,
                           total_hosts=len(ordered),
                           with_open=sum(1 for d in ordered.values() if d['ports']),
                           has_schedules=bool(scheduled),
                           udp53_hosts=udp53_hosts,
                           title='Результаты')


_quick_jobs = {}
_quick_lock = threading.Lock()
QUICK_TTL = 1800


def quick_worker(job_id, ips, tcp_ports, udp_ports, workers):
    job = _quick_jobs.get(job_id)
    if not job:
        return
    tcp_found = {ip: [] for ip in ips}
    udp_found = {ip: [] for ip in ips}
    total = len(ips) * (len(tcp_ports) + len(udp_ports))
    done = 0
    try:
        tasks = []
        for ip in ips:
            for port in tcp_ports:
                tasks.append(('tcp', ip, port))
            for port in udp_ports:
                tasks.append(('udp', ip, port))

        pool_size = max(1, min(workers, total or 1))
        tcp_timeouts = []
        with ThreadPoolExecutor(max_workers=pool_size) as pool:
            futures = {}
            for proto, ip, port in tasks:
                fn = probe if proto == 'tcp' else probe_udp
                futures[pool.submit(fn, ip, port)] = proto
            for fut in as_completed(futures):
                proto = futures[fut]
                res = fut.result()
                ip, port, is_open = res[0], res[1], res[2]
                if is_open:
                    if proto == 'tcp':
                        tcp_found[ip].append(port)
                    else:
                        udp_found[ip].append(port)
                elif proto == 'tcp' and len(res) > 4 and res[4] == 'timeout':
                    tcp_timeouts.append((ip, port))
                done += 1
                if done % 20 == 0 or done == total:
                    job['done'] = done

        # порты без ответа перепроверяем медленнее: фильтры роняют часть SYN
        if tcp_timeouts:
            job['total'] = total + len(tcp_timeouts)
            extra_workers = max(1, min(TCP_CONFIRM_WORKERS, len(tcp_timeouts)))
            with ThreadPoolExecutor(max_workers=extra_workers) as pool:
                futures = [pool.submit(confirm_probe, ip, port)
                           for ip, port in tcp_timeouts]
                for fut in as_completed(futures):
                    ip, port, is_open, _err = fut.result()
                    if is_open:
                        tcp_found[ip].append(port)
                    done += 1
                    if done % 20 == 0 or done == job['total']:
                        job['done'] = done
            job['done'] = done

        job['results'] = []
        for ip in ips:
            job['results'].append({
                'ip': ip,
                'tcp': sorted(tcp_found[ip]),
                'udp': sorted(udp_found[ip]),
                'count': len(tcp_found[ip]) + len(udp_found[ip]),
            })
        job['status'] = 'completed'
    except Exception as e:  # noqa: BLE001
        job['status'] = 'failed'
        job['error'] = str(e)
    finally:
        job['finished'] = time.time()


def cleanup_quick_jobs():
    now = time.time()
    with _quick_lock:
        for job_id, job in list(_quick_jobs.items()):
            finished = job.get('finished')
            if finished and now - finished > QUICK_TTL:
                _quick_jobs.pop(job_id, None)


def _add_schedule(ip, tcp_ports, udp_ports, minutes):
    conn = db()
    exists = conn.execute(
        'SELECT 1 FROM schedules WHERE ip_range = ? AND ports = ? '
        'AND IFNULL(udp_ports, \'\') = ?',
        (ip, tcp_ports, udp_ports)).fetchone()
    if exists:
        conn.close()
        return False
    now = datetime.now()
    stamp = now.isoformat(timespec='seconds')
    conn.execute(
        'INSERT INTO schedules (ip_range, ports, udp_ports, workers, '
        'interval_minutes, enabled, next_run, created_at) '
        'VALUES (?, ?, ?, ?, ?, 1, ?, ?)',
        (ip, tcp_ports, udp_ports, SCAN_WORKERS, minutes, stamp, stamp))
    conn.commit()
    conn.close()
    return True


@app.route('/quick', methods=['GET', 'POST'])
@role_required(*MANAGE_ROLES)
def quick():
    cleanup_quick_jobs()
    form = ScanForm()

    if request.method == 'POST' and form.validate_on_submit():
        try:
            start_int, end_int = parse_range(form.ip_range.data)
            tcp_ports = parse_ports(form.ports.data)
            udp_ports = parse_udp_ports(form.udp_ports.data)
            workers = parse_workers(form.workers.data)
            total = (end_int - start_int + 1) * (len(tcp_ports) + len(udp_ports))
            if total > 4000:
                raise ValueError(
                    'Слишком много проверок ({0}). Максимум 4000 — '
                    'сузьте диапазон или списки портов'.format(total))
            ips = []
            for i in range(start_int, end_int + 1):
                ips.append(int_to_ip(i))
            job_id = 'q{0}'.format(int(time.time() * 1000))
            with _quick_lock:
                _quick_jobs[job_id] = {
                    'id': job_id,
                    'ip_range': form.ip_range.data or DEFAULT_RANGE,
                    'ports_text': form.ports.data or DEFAULT_PORTS_STR,
                    'udp_text': form.udp_ports.data or '',
                    'ips': ips,
                    'workers': workers,
                    'done': 0,
                    'total': total,
                    'status': 'running',
                    'results': None,
                    'started': time.time(),
                }
            threading.Thread(target=quick_worker,
                             args=(job_id, ips, tcp_ports, udp_ports, workers),
                             daemon=True).start()
            return redirect(url_for('quick', job=job_id))
        except ValueError as e:
            flash('Ошибка: {0}'.format(e), 'danger')

    if request.method == 'GET':
        form.ip_range.data = ''
        form.ports.data = DEFAULT_PORTS_STR
        form.udp_ports.data = DEFAULT_UDP_PORTS_STR
        form.workers.data = str(SCAN_WORKERS)

    job = None
    job_id = request.args.get('job')
    if job_id:
        job = _quick_jobs.get(job_id)
        if not job:
            flash('Задание не найдено или истекло', 'info')

    summary = None
    results = None
    if job and job['status'] == 'completed':
        results = job['results']
        summary = {
            'ips': len(job['ips']),
            'checks': job['total'],
            'with_open': sum(1 for r in results if r['count']),
        }

    return render_template('quick.html', form=form, job=job, job_id=job_id,
                           results=results, summary=summary,
                           default_ports=DEFAULT_PORTS_STR,
                           default_udp=DEFAULT_UDP_PORTS_STR,
                           title='Разовое сканирование')


@app.route('/api/quick/status/<job_id>')
@login_required
def quick_status(job_id):
    job = _quick_jobs.get(job_id)
    if not job:
        return jsonify({'status': 'missing'})
    total = job['total'] or 1
    done = job.get('done', 0)
    return jsonify({
        'status': job['status'],
        'done': done,
        'total': job['total'],
        'percent': round(done * 100.0 / total, 1),
    })


@app.route('/quick/add', methods=['POST'])
@role_required(*MANAGE_ROLES)
def quick_add():
    ip = (request.form.get('ip') or '').strip()
    tcp_ports = (request.form.get('ports') or '').strip() or DEFAULT_PORTS_STR
    udp_ports = (request.form.get('udp_ports') or '').strip()
    interval = request.form.get('interval') or str(DEFAULT_INTERVAL)
    back = request.form.get('back') or url_for('quick')
    try:
        ip_to_int(ip)
        parse_ports(tcp_ports)
        parse_udp_ports(udp_ports)
        minutes = parse_interval(interval)
    except ValueError as e:
        flash('Ошибка: {0}'.format(e), 'danger')
        return redirect(back)

    if _add_schedule(ip, tcp_ports, udp_ports, minutes):
        flash('{0} добавлен в расписание (каждые {1} мин). '
              'Результаты появятся в разделе «Результаты» через несколько секунд.'
              .format(ip, minutes), 'success')
    else:
        flash('{0} уже есть в расписании с такими портами'.format(ip), 'info')
    return redirect(back)


@app.route('/quick/add-bulk', methods=['POST'])
@role_required(*MANAGE_ROLES)
def quick_add_bulk():
    tcp_ports = (request.form.get('ports') or '').strip() or DEFAULT_PORTS_STR
    udp_ports = (request.form.get('udp_ports') or '').strip()
    interval = request.form.get('interval') or str(DEFAULT_INTERVAL)
    back = request.form.get('back') or url_for('quick')
    raw = request.form.get('ips') or ''
    raw = raw.replace(';', ',').replace('\r', ',').replace('\n', ',')
    ips = []
    for chunk in raw.split(','):
        chunk = chunk.strip()
        if chunk:
            ips.append(chunk)
    if not ips:
        flash('Не выбрано ни одного адреса', 'danger')
        return redirect(back)
    try:
        parse_ports(tcp_ports)
        parse_udp_ports(udp_ports)
        minutes = parse_interval(interval)
    except ValueError as e:
        flash('Ошибка: {0}'.format(e), 'danger')
        return redirect(back)

    added = 0
    skipped = 0
    for ip in ips:
        try:
            ip_to_int(ip)
        except ValueError:
            skipped += 1
            continue
        if _add_schedule(ip, tcp_ports, udp_ports, minutes):
            added += 1
        else:
            skipped += 1

    if request.headers.get('X-Requested-With') == 'fetch':
        return jsonify({'added': added, 'skipped': skipped,
                        'ports': tcp_ports, 'udp_ports': udp_ports,
                        'interval': minutes})

    flash('Добавлено: {0}. Пропущено (уже есть или ошибка): {1}. '
          'TCP: {2}, UDP: {3}, интервал: {4} мин.'
          .format(added, skipped, tcp_ports, udp_ports or '—', minutes), 'success')
    return redirect(back)


@app.route('/schedules', methods=['GET', 'POST'])
@login_required
def schedules():
    form = ScheduleForm()
    if request.method == 'POST' and not current_user.can_manage:
        flash('Недостаточно прав для изменения расписания', 'danger')
        return redirect(url_for('schedules'))
    if request.method == 'GET':
        form.ip_range.data = DEFAULT_RANGE
        form.ports.data = DEFAULT_PORTS_STR
        form.udp_ports.data = DEFAULT_UDP_PORTS_STR
        form.workers.data = str(SCAN_WORKERS)
        form.interval_minutes.data = str(DEFAULT_INTERVAL)
    if form.validate_on_submit():
        try:
            interval = parse_interval(form.interval_minutes.data)
            parse_range(form.ip_range.data)
            tcp_ports = form.ports.data or DEFAULT_PORTS_STR
            udp_ports = (form.udp_ports.data or '').strip()
            parse_ports(tcp_ports)
            parse_udp_ports(udp_ports)
            workers = parse_workers(form.workers.data)
            now = datetime.now()
            conn = db()
            conn.execute(
                'INSERT INTO schedules (ip_range, ports, udp_ports, workers, '
                'interval_minutes, enabled, next_run, created_at) '
                'VALUES (?, ?, ?, ?, ?, 1, ?, ?)',
                (form.ip_range.data, tcp_ports, udp_ports, workers,
                 interval, (now + timedelta(minutes=interval)
                            ).isoformat(timespec='seconds'),
                 now.isoformat(timespec='seconds')))
            conn.commit()
            conn.close()
            flash(f'Расписание добавлено: каждые {interval} мин', 'success')
            return redirect(url_for('schedules'))
        except ValueError as e:
            flash(f'Ошибка: {e}', 'danger')

    conn = db()
    rows = conn.execute('SELECT * FROM schedules ORDER BY id DESC').fetchall()
    conn.close()
    return render_template('schedules.html', form=form, schedules=rows,
                           default_ports=DEFAULT_PORTS_STR,
                           default_udp=DEFAULT_UDP_PORTS_STR,
                           title='Расписание')


@app.route('/schedules/<int:sid>/toggle', methods=['POST'])
@role_required(*MANAGE_ROLES)
def schedule_toggle(sid):
    conn = db()
    row = conn.execute('SELECT * FROM schedules WHERE id = ?', (sid,)).fetchone()
    if not row:
        conn.close()
        flash('Расписание не найдено', 'danger')
        return redirect(url_for('schedules'))
    enabled = 0 if row['enabled'] else 1
    next_run = row['next_run']
    if enabled:
        next_run = (datetime.now() + timedelta(minutes=row['interval_minutes'])
                    ).isoformat(timespec='seconds')
    conn.execute('UPDATE schedules SET enabled = ?, next_run = ? WHERE id = ?',
                 (enabled, next_run, sid))
    conn.commit()
    conn.close()
    flash('Расписание включено' if enabled else 'Расписание выключено', 'info')
    return redirect(url_for('schedules'))


@app.route('/schedules/<int:sid>/run', methods=['POST'])
@role_required(*MANAGE_ROLES)
def schedule_run(sid):
    conn = db()
    row = conn.execute('SELECT * FROM schedules WHERE id = ?', (sid,)).fetchone()
    running = conn.execute(
        "SELECT id FROM scan_logs WHERE schedule_id = ? AND status = 'running'",
        (sid,)).fetchone()
    conn.close()
    if running:
        flash(f'По расписанию #{sid} уже идёт сканирование (задание #{running["id"]}) — '
              f'дождитесь завершения', 'warning')
        return redirect(url_for('schedules'))
    if not row:
        flash('Расписание не найдено', 'danger')
        return redirect(url_for('schedules'))
    try:
        log_id = start_scan(row['ip_range'], row['ports'],
                            str(row['workers'] or SCAN_WORKERS), schedule_id=sid,
                            udp_ports_text=(row['udp_ports'] or ''))
    except ValueError as e:
        flash(f'Ошибка: {e}', 'danger')
        return redirect(url_for('schedules'))
    conn = db()
    now = datetime.now()
    conn.execute('UPDATE schedules SET last_run = ?, next_run = ? WHERE id = ?',
                 (now.isoformat(timespec='seconds'),
                  (now + timedelta(minutes=row['interval_minutes'])
                   ).isoformat(timespec='seconds'), sid))
    conn.commit()
    conn.close()
    flash(f'Запущено вручную (задание #{log_id}). Прогресс — в разделе «Лог».', 'success')
    return redirect(url_for('schedules'))


@app.route('/schedules/<int:sid>/update', methods=['POST'])
@role_required(*MANAGE_ROLES)
def schedule_update(sid):
    conn = db()
    row = conn.execute('SELECT * FROM schedules WHERE id = ?', (sid,)).fetchone()
    if not row:
        conn.close()
        flash('Расписание не найдено', 'danger')
        return redirect(url_for('schedules'))

    ports = (request.form.get('ports') or '').strip() or DEFAULT_PORTS_STR
    udp_ports = (request.form.get('udp_ports') or '').strip()
    workers_text = (request.form.get('workers') or '').strip()
    interval_text = (request.form.get('interval') or '').strip()

    try:
        parse_ports(ports)
        parse_udp_ports(udp_ports)
        workers = parse_workers(workers_text or str(row['workers'] or SCAN_WORKERS))
        minutes = parse_interval(interval_text or str(row['interval_minutes']))
    except ValueError as e:
        conn.close()
        flash(f'Ошибка: {e}', 'danger')
        return redirect(url_for('schedules'))

    next_run = (datetime.now() + timedelta(minutes=minutes)).isoformat(timespec='seconds')
    conn.execute('UPDATE schedules SET ports = ?, udp_ports = ?, workers = ?, '
                 'interval_minutes = ?, next_run = ? WHERE id = ?',
                 (ports, udp_ports, workers, minutes, next_run, sid))
    conn.commit()
    conn.close()

    # порт убрали из расписания — убираем и из результатов, без пересканирования
    try:
        old_tcp = set(parse_ports(row['ports'] or DEFAULT_PORTS_STR))
        old_udp = set(parse_udp_ports(row['udp_ports'] or ''))
    except ValueError:
        old_tcp, old_udp = set(), set()
    removed_tcp = old_tcp - set(parse_ports(ports))
    removed_udp = old_udp - set(parse_udp_ports(udp_ports))
    purged = purge_removed_ports(row['ip_range'], removed_tcp, removed_udp)

    flash(f'Расписание #{sid} обновлено: порты {ports}, потоков {workers}, '
          f'интервал {minutes} мин', 'success')
    if removed_tcp or removed_udp:
        flash('Из результатов убрано записей по снятым портам: '
              f'{purged}.', 'success')
    return redirect(url_for('schedules'))


@app.route('/schedules/<int:sid>/delete', methods=['POST'])
@role_required(*MANAGE_ROLES)
def schedule_delete(sid):
    conn = db()
    row = conn.execute('SELECT * FROM schedules WHERE id = ?', (sid,)).fetchone()
    if not row:
        conn.close()
        flash('Расписание не найдено', 'danger')
        return redirect(url_for('schedules'))

    ip_range = row['ip_range']
    # останавливаем активные задания этого диапазона, чтобы не писали после удаления
    running = conn.execute("SELECT id FROM scan_logs WHERE ip_range = ? AND "
                           "status = 'running'", (ip_range,)).fetchall()
    conn.execute('DELETE FROM schedules WHERE id = ?', (sid,))
    conn.commit()
    conn.close()
    for r in running:
        request_stop(r['id'])

    stats = purge_unscheduled(ip_range)
    flash(f'Расписание удалено. Из результатов убрано адресов: {stats["ips"]}, '
          f'портов: {stats["ports"]}. Остались только адреса других расписаний.',
          'success')
    return redirect(url_for('schedules'))


@app.route('/logs')
@login_required
def logs():
    conn = db()
    rows = conn.execute('SELECT * FROM scan_logs ORDER BY id DESC LIMIT 50').fetchall()
    conn.close()
    return render_template('logs.html', logs=rows, title='Лог сканирования')


@app.route('/logs/<int:log_id>')
@login_required
def log_detail(log_id):
    conn = db()
    job = conn.execute('SELECT * FROM scan_logs WHERE id = ?', (log_id,)).fetchone()
    events = conn.execute('SELECT * FROM scan_events WHERE log_id = ? '
                          'ORDER BY id', (log_id,)).fetchall()
    conn.close()
    if not job:
        flash('Задание не найдено', 'danger')
        return redirect(url_for('logs'))
    return render_template('log_detail.html', job=job, events=events,
                           title=f'Задание #{log_id}')


@app.route('/alerts')
@login_required
def alerts():
    conn = db()
    rows = conn.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 200').fetchall()
    conn.close()
    return render_template('alerts.html', alerts=rows, title='События')


# ------------------------------------------------------------------- настройки


@app.route('/settings', methods=['GET', 'POST'])
@role_required(*MANAGE_ROLES)
def settings():
    if request.method == 'POST':
        values = {}
        for key in SETTING_DEFAULTS:
            if key.endswith('_enabled') or key in ('smtp_tls', 'smtp_ssl'):
                values[key] = '1' if request.form.get(key) else '0'
            else:
                values[key] = (request.form.get(key) or '').strip()
        save_settings(values)
        flash('Настройки сохранены', 'success')
        return redirect(url_for('settings'))

    return render_template('settings.html', cfg=get_settings(), title='Настройки')


@app.route('/settings/groups')
@role_required(*MANAGE_ROLES)
def settings_groups():
    conn = db()
    rows = conn.execute(
        'SELECT g.id, g.name, COUNT(h.ip) AS hosts '
        'FROM host_groups g LEFT JOIN hosts h ON h.group_id = g.id '
        'GROUP BY g.id, g.name ORDER BY g.name COLLATE NOCASE').fetchall()
    conn.close()
    groups = [{'id': r['id'], 'name': r['name'], 'hosts': r['hosts']} for r in rows]
    return render_template('groups.html', groups=groups,
                           settings_tab='groups', title='Настройки')


@app.route('/settings/test/<channel>', methods=['POST'])
@role_required(*MANAGE_ROLES)
def settings_test(channel):
    sender = CHANNEL_SENDERS.get(channel)
    if not sender:
        flash('Неизвестный канал уведомлений', 'danger')
        return redirect(url_for('settings'))

    # сохраняем то, что ввели в форме, чтобы проверять актуальные значения
    values = {}
    for key in SETTING_DEFAULTS:
        if key.endswith('_enabled') or key in ('smtp_tls', 'smtp_ssl'):
            values[key] = '1' if request.form.get(key) else '0'
        else:
            values[key] = (request.form.get(key) or '').strip()
    save_settings(values)

    try:
        sender(get_settings(), 'Тестовое уведомление от NetProbeа')
    except Exception as e:  # noqa: BLE001
        flash(f'Не отправлено ({channel}): {e}', 'danger')
    else:
        flash(f'Тестовое сообщение отправлено: {channel}', 'success')
    return redirect(url_for('settings'))


# ------------------------------------------------------------------ пользователи


def _user_or_none(user_id):
    conn = db()
    row = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return row


def _admin_count():
    conn = db()
    count = conn.execute('SELECT COUNT(*) AS c FROM users WHERE role = ?',
                         (ROLE_ADMIN,)).fetchone()['c']
    conn.close()
    return count


@app.route('/settings/users', methods=['GET', 'POST'])
@role_required(ROLE_ADMIN)
def users():
    form = UserForm()
    if request.method == 'GET':
        form.role.data = ROLE_USER
    # специалист ИБ не может создавать администраторов
    if not current_user.is_admin:
        form.role.choices = [(ROLE_USER, ROLE_LABELS[ROLE_USER]),
                             (ROLE_SECURITY, ROLE_LABELS[ROLE_SECURITY])]

    if form.validate_on_submit():
        role = form.role.data
        if role == ROLE_ADMIN and not current_user.is_admin:
            flash('Только администратор может создавать администраторов', 'danger')
            return redirect(url_for('users'))
        conn = db()
        exists = conn.execute('SELECT 1 FROM users WHERE username = ?',
                              (form.username.data,)).fetchone()
        if exists:
            conn.close()
            flash('Пользователь с таким именем уже существует', 'danger')
            return redirect(url_for('users'))
        conn.execute('INSERT INTO users (username, password, role, created_at) '
                     'VALUES (?, ?, ?, ?)',
                     (form.username.data, generate_password_hash(form.password.data),
                      role, datetime.now().isoformat(timespec='seconds')))
        conn.commit()
        conn.close()
        flash(f'Пользователь {form.username.data} добавлен '
              f'({ROLE_LABELS.get(role, role)})', 'success')
        return redirect(url_for('users'))

    conn = db()
    rows = conn.execute('SELECT id, username, role, created_at, last_login '
                        'FROM users ORDER BY id').fetchall()
    conn.close()
    return render_template('users.html', form=form, users=rows, title='Пользователи')


@app.route('/settings/users/<int:user_id>/role', methods=['POST'])
@role_required(ROLE_ADMIN)
def user_role(user_id):
    row = _user_or_none(user_id)
    if not row:
        flash('Пользователь не найден', 'danger')
        return redirect(url_for('users'))

    new_role = request.form.get('role')
    if new_role not in ROLE_LABELS:
        flash('Неизвестная роль', 'danger')
        return redirect(url_for('users'))
    if row['role'] == ROLE_ADMIN and not current_user.is_admin:
        flash('Специалист ИБ не может менять администраторов', 'danger')
        return redirect(url_for('users'))
    if new_role == ROLE_ADMIN and not current_user.is_admin:
        flash('Только администратор может назначать администраторов', 'danger')
        return redirect(url_for('users'))
    if row['role'] == ROLE_ADMIN and new_role != ROLE_ADMIN and _admin_count() <= 1:
        flash('Нельзя снять роль с последнего администратора', 'danger')
        return redirect(url_for('users'))

    conn = db()
    conn.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
    conn.commit()
    conn.close()
    flash(f'Роль {row["username"]} изменена на «{ROLE_LABELS[new_role]}»', 'success')
    return redirect(url_for('users'))


@app.route('/settings/users/<int:user_id>/password', methods=['POST'])
@role_required(ROLE_ADMIN)
def user_password(user_id):
    row = _user_or_none(user_id)
    if not row:
        flash('Пользователь не найден', 'danger')
        return redirect(url_for('users'))
    if row['role'] == ROLE_ADMIN and not current_user.is_admin:
        flash('Специалист ИБ не может менять пароль администратора', 'danger')
        return redirect(url_for('users'))

    password = (request.form.get('password') or '').strip()
    if len(password) < 6:
        flash('Пароль должен быть не короче 6 символов', 'danger')
        return redirect(url_for('users'))

    conn = db()
    conn.execute('UPDATE users SET password = ? WHERE id = ?',
                 (generate_password_hash(password), user_id))
    conn.commit()
    conn.close()
    flash(f'Пароль {row["username"]} обновлён', 'success')
    return redirect(url_for('users'))


@app.route('/settings/users/<int:user_id>/delete', methods=['POST'])
@role_required(ROLE_ADMIN)
def user_delete(user_id):
    row = _user_or_none(user_id)
    if not row:
        flash('Пользователь не найден', 'danger')
        return redirect(url_for('users'))
    if row['id'] == int(current_user.id):
        flash('Нельзя удалить собственный аккаунт', 'danger')
        return redirect(url_for('users'))
    if row['role'] == ROLE_ADMIN and not current_user.is_admin:
        flash('Специалист ИБ не может удалять администраторов', 'danger')
        return redirect(url_for('users'))
    if row['role'] == ROLE_ADMIN and _admin_count() <= 1:
        flash('Нельзя удалить последнего администратора', 'danger')
        return redirect(url_for('users'))

    conn = db()
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    flash(f'Пользователь {row["username"]} удалён', 'info')
    return redirect(url_for('users'))


# ------------------------------------------------------------- пауза/возобновление


@app.route('/ip/<ip>/pause', methods=['POST'])
@role_required(*MANAGE_ROLES)
def ip_pause(ip):
    try:
        ip_to_int(ip)
    except ValueError:
        flash('Некорректный IP', 'danger')
        return redirect(request.referrer or url_for('dashboard'))
    conn = db()
    conn.execute('INSERT OR REPLACE INTO paused_ips (ip, paused_at, reason) '
                 'VALUES (?, ?, ?)',
                 (ip, datetime.now().isoformat(timespec='seconds'),
                  request.form.get('reason')))
    conn.commit()
    conn.close()
    flash(f'{ip} поставлен на паузу — сканирование этого адреса пропускается', 'warning')
    return redirect(request.referrer or url_for('dashboard'))


@app.route('/ip/<ip>/scan', methods=['POST'])
@login_required
def ip_scan(ip):
    """Проверить один адрес сейчас (порты — как в последнем сканировании)."""
    try:
        ip_to_int(ip)
    except ValueError:
        flash('Некорректный IP', 'danger')
        return redirect(request.referrer or url_for('dashboard'))
    conn = db()
    last = conn.execute('SELECT ports, udp_ports FROM scan_logs '
                        'ORDER BY id DESC LIMIT 1').fetchone()
    conn.close()
    ports = last['ports'] if last and last['ports'] else DEFAULT_PORTS_STR
    udp_ports = last['udp_ports'] if last and last['udp_ports'] else DEFAULT_UDP_PORTS_STR
    try:
        log_id = start_scan(f'{ip}-{ip}', ports, str(SCAN_WORKERS),
                            udp_ports_text=udp_ports)
    except ValueError as e:
        flash(f'Ошибка: {e}', 'danger')
        return redirect(request.referrer or url_for('dashboard'))
    flash(f'Проверка {ip} запущена (задание #{log_id}, порты: {ports})', 'success')
    return redirect(request.referrer or url_for('dashboard'))


@app.route('/ip/<ip>/resume', methods=['POST'])
@role_required(*MANAGE_ROLES)
def ip_resume(ip):
    conn = db()
    conn.execute('DELETE FROM paused_ips WHERE ip = ?', (ip,))
    conn.commit()
    conn.close()
    flash(f'{ip} снят с паузы', 'success')
    return redirect(request.referrer or url_for('dashboard'))


# ------------------------------------------------ группы адресов и комментарии


@app.route('/api/host/meta', methods=['POST'])
@role_required(*MANAGE_ROLES)
def api_host_meta():
    data = request.get_json(silent=True) or {}
    ip = (data.get('ip') or '').strip()
    try:
        ip_to_int(ip)
    except ValueError:
        return jsonify({'error': 'Некорректный IP'}), 400

    group_id = data.get('group_id')
    if group_id in ('', None):
        group_id = None
    else:
        try:
            group_id = int(group_id)
        except (TypeError, ValueError):
            return jsonify({'error': 'Некорректная группа'}), 400

    comment = (data.get('comment') or '').strip()[:500]

    conn = db()
    if group_id is not None:
        exists = conn.execute('SELECT 1 FROM host_groups WHERE id = ?',
                              (group_id,)).fetchone()
        if not exists:
            conn.close()
            return jsonify({'error': 'Группа не найдена'}), 400
    now = datetime.now().isoformat(timespec='seconds')
    conn.execute('INSERT OR IGNORE INTO hosts (ip, first_seen, last_seen) '
                 'VALUES (?, ?, ?)', (ip, now, now))
    conn.execute('UPDATE hosts SET group_id = ?, comment = ? WHERE ip = ?',
                 (group_id, comment, ip))
    conn.commit()
    conn.close()
    return jsonify({'status': 'ok', 'group_id': group_id, 'comment': comment})


@app.route('/api/groups', methods=['POST'])
@role_required(*MANAGE_ROLES)
def api_group_create():
    data = request.get_json(silent=True) or {}
    name = ' '.join((data.get('name') or '').split())
    if not name:
        return jsonify({'error': 'Введите название группы'}), 400
    name = name[:40]
    conn = db()
    row = conn.execute('SELECT id, name FROM host_groups '
                       'WHERE name = ? COLLATE NOCASE', (name,)).fetchone()
    if row:
        conn.close()
        return jsonify({'id': row['id'], 'name': row['name']})
    cur = conn.execute('INSERT INTO host_groups (name, created_at) VALUES (?, ?)',
                       (name, datetime.now().isoformat(timespec='seconds')))
    conn.commit()
    group_id = cur.lastrowid
    conn.close()
    return jsonify({'id': group_id, 'name': name})


@app.route('/api/groups/<int:group_id>/rename', methods=['POST'])
@role_required(*MANAGE_ROLES)
def api_group_rename(group_id):
    data = request.get_json(silent=True) or {}
    name = ' '.join((data.get('name') or '').split())[:40]
    if not name:
        return jsonify({'error': 'Введите название группы'}), 400
    conn = db()
    if not conn.execute('SELECT 1 FROM host_groups WHERE id = ?',
                        (group_id,)).fetchone():
        conn.close()
        return jsonify({'error': 'Группа не найдена'}), 404
    other = conn.execute('SELECT id FROM host_groups WHERE name = ? COLLATE NOCASE '
                         'AND id <> ?', (name, group_id)).fetchone()
    if other:
        conn.close()
        return jsonify({'error': 'Группа с таким названием уже есть'}), 400
    conn.execute('UPDATE host_groups SET name = ? WHERE id = ?', (name, group_id))
    conn.commit()
    conn.close()
    return jsonify({'id': group_id, 'name': name})


@app.route('/api/groups/<int:group_id>', methods=['DELETE'])
@role_required(*MANAGE_ROLES)
def api_group_delete(group_id):
    conn = db()
    conn.execute('UPDATE hosts SET group_id = NULL WHERE group_id = ?', (group_id,))
    conn.execute('DELETE FROM host_groups WHERE id = ?', (group_id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'ok'})


@app.route('/api/udp/purge', methods=['POST'])
@role_required(*MANAGE_ROLES)
def api_udp_purge():
    """Удаляет записи об открытом UDP-порте у всех адресов.
    Нужно, когда провайдер/роутер перехватывает DNS и порт 53 «открыт» везде."""
    data = request.get_json(silent=True) or {}
    try:
        port = int(data.get('port', 53))
    except (TypeError, ValueError):
        return jsonify({'error': 'Некорректный порт'}), 400
    if not 1 <= port <= 65535:
        return jsonify({'error': 'Некорректный порт'}), 400

    conn = db()
    deleted = conn.execute('DELETE FROM port_state_udp WHERE port = ?',
                           (port,)).rowcount

    schedules_updated = 0
    if data.get('update_schedules'):
        rows = conn.execute('SELECT id, udp_ports FROM schedules '
                            'WHERE udp_ports IS NOT NULL').fetchall()
        for row in rows:
            before = [p.strip() for p in (row['udp_ports'] or '').split(',')
                      if p.strip()]
            after = [p for p in before if p != str(port)]
            if len(after) == len(before):
                continue
            conn.execute('UPDATE schedules SET udp_ports = ? WHERE id = ?',
                         (','.join(after), row['id']))
            schedules_updated += 1

    conn.commit()
    conn.close()
    return jsonify({'status': 'ok', 'deleted': deleted,
                    'schedules_updated': schedules_updated})


@app.route('/api/hosts/bulk', methods=['POST'])
@role_required(*MANAGE_ROLES)
def api_hosts_bulk():
    data = request.get_json(silent=True) or {}
    action = data.get('action')
    ips = []
    for raw in (data.get('ips') or []):
        ip = str(raw).strip()
        try:
            ip_to_int(ip)
        except ValueError:
            continue
        if ip not in ips:
            ips.append(ip)
    if not ips:
        return jsonify({'error': 'Не выбрано ни одного адреса'}), 400
    if len(ips) > 5000:
        return jsonify({'error': 'Слишком много адресов за один раз (максимум 5000)'}), 400

    now = datetime.now().isoformat(timespec='seconds')

    if action == 'scan':
        conn = db()
        last = conn.execute('SELECT ports, udp_ports FROM scan_logs '
                            'ORDER BY id DESC LIMIT 1').fetchone()
        conn.close()
        ports = last['ports'] if last and last['ports'] else DEFAULT_PORTS_STR
        udp_ports = (last['udp_ports'] if last and last['udp_ports']
                     else DEFAULT_UDP_PORTS_STR)
        try:
            log_id = start_scan_ips(ips, ports, udp_ports_text=udp_ports,
                                    workers_text=str(SCAN_WORKERS))
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
        return jsonify({'status': 'started', 'log_id': log_id,
                        'count': len(ips)})

    conn = db()
    if action == 'group':
        group_id = data.get('group_id')
        if group_id in ('', None):
            group_id = None
        else:
            try:
                group_id = int(group_id)
            except (TypeError, ValueError):
                conn.close()
                return jsonify({'error': 'Некорректная группа'}), 400
            if not conn.execute('SELECT 1 FROM host_groups WHERE id = ?',
                                (group_id,)).fetchone():
                conn.close()
                return jsonify({'error': 'Группа не найдена'}), 400
        placeholders = ','.join('?' * len(ips))
        conn.executemany('INSERT OR IGNORE INTO hosts (ip, first_seen, last_seen) '
                         'VALUES (?, ?, ?)', [(ip, now, now) for ip in ips])
        conn.execute(f'UPDATE hosts SET group_id = ? WHERE ip IN ({placeholders})',
                     [group_id] + ips)
        conn.commit()
        conn.close()
        return jsonify({'status': 'ok', 'count': len(ips), 'group_id': group_id})

    if action in ('pause', 'resume'):
        if action == 'pause':
            conn.executemany('INSERT OR REPLACE INTO paused_ips '
                             '(ip, paused_at, reason) VALUES (?, ?, ?)',
                             [(ip, now, None) for ip in ips])
        else:
            placeholders = ','.join('?' * len(ips))
            conn.execute(f'DELETE FROM paused_ips WHERE ip IN ({placeholders})', ips)
        conn.commit()
        conn.close()
        return jsonify({'status': 'ok', 'count': len(ips)})

    conn.close()
    return jsonify({'error': 'Неизвестное действие'}), 400


# -------------------------------------------------------------------------- API


@app.route('/api/alerts')
@login_required
def api_alerts():
    conn = db()
    rows = conn.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 200').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/scan/progress')
@login_required
def api_progress():
    log_id = request.args.get('log_id', type=int)
    conn = db()
    if log_id:
        job = conn.execute('SELECT * FROM scan_logs WHERE id = ?', (log_id,)).fetchone()
    else:
        job = conn.execute('SELECT * FROM scan_logs ORDER BY id DESC LIMIT 1').fetchone()
    conn.close()
    if not job:
        return jsonify({'running': False})

    total = job['total'] or 0
    done = job['done'] or 0
    percent = round(done * 100 / total, 1) if total else 0
    udp_total = job['udp_total'] or 0
    udp_done = job['udp_done'] or 0
    percent_udp = round(udp_done * 100 / udp_total, 1) if udp_total else 0
    verify_total = job['verify_total'] or 0
    verify_done = job['verify_done'] or 0
    percent_verify = round(verify_done * 100 / verify_total, 1) if verify_total else 0
    # общий прогресс: все проверки задания, включая будущие этапы.
    # UDP закладываем с запасом на второй проход, повторную проверку TCP — по
    # размеру основного прохода.
    udp_planned = job['udp_planned'] or 0
    udp_done_all = job['udp_done_all'] or 0
    verify_weight = total if done < total else verify_total
    verify_weight = min(verify_weight, total)
    all_total = total + udp_planned + verify_weight
    all_done = (done + min(verify_done, verify_weight)
                + min(udp_done_all, udp_planned))
    percent_total = round(all_done * 100 / all_total, 1) if all_total else 0
    if job['status'] == 'completed':
        percent_total = 100.0
    phase = 'tcp'
    if job['status'] == 'running' and total and done >= total:
        udp_phase = (job['udp_phase'] or '').strip()
        if verify_total and verify_done < verify_total:
            phase = 'verify'
        elif udp_total and udp_done < udp_total:
            phase = 'udp_verify' if udp_phase == 'verify' else 'udp'
        elif udp_total or verify_total:
            # все проверки закончились, задание закрывается
            phase = 'finishing'
        else:
            phase = 'finishing'
    return jsonify({
        'running': job['status'] == 'running',
        'status': job['status'],
        'phase': phase,
        'udp_total': udp_total,
        'udp_done': udp_done,
        'percent_udp': percent_udp,
        'verify_total': verify_total,
        'verify_done': verify_done,
        'percent_verify': percent_verify,
        'percent_total': percent_total,
        'total_all': all_total,
        'done_all': all_done,
        'log_id': job['id'],
        'ip_range': job['ip_range'],
        'ports': job['ports'],
        'workers': job['workers'] or SCAN_WORKERS,
        'total': total,
        'done': done,
        'open_found': job['open_found'] or 0,
        'percent': percent,
        'start_time': job['start_time'],
        'end_time': job['end_time'],
    })


@app.route('/api/scan/events')
@login_required
def api_events():
    log_id = request.args.get('log_id', type=int)
    after_id = request.args.get('after', type=int, default=0)
    level = request.args.get('level')
    conn = db()
    if not log_id:
        row = conn.execute('SELECT id FROM scan_logs ORDER BY id DESC LIMIT 1').fetchone()
        log_id = row['id'] if row else 0
    sql = 'SELECT * FROM scan_events WHERE log_id = ? AND id > ?'
    params = [log_id, after_id]
    if level:
        sql += ' AND level = ?'
        params.append(level)
    sql += ' ORDER BY id LIMIT 500'
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/scan/stop', methods=['POST'])
@role_required(*MANAGE_ROLES)
def api_stop():
    data = request.get_json(silent=True) or {}
    log_id = data.get('log_id') or request.form.get('log_id', type=int) \
        or latest_running_job()
    if not log_id:
        return jsonify({'error': 'Нет активного сканирования'}), 400
    if request_stop(int(log_id)):
        return jsonify({'status': 'stopping', 'log_id': int(log_id)})
    return jsonify({'error': 'Задание не выполняется'}), 400


@app.route('/scan/stop/<int:log_id>', methods=['POST'])
@role_required(*MANAGE_ROLES)
def stop_scan_form(log_id):
    if request_stop(log_id):
        flash(f'Останавливаю задание #{log_id}…', 'warning')
    else:
        flash('Задание уже не выполняется', 'info')
    return redirect(request.referrer or url_for('logs'))


@app.route('/api/scan', methods=['POST'])
@role_required(*MANAGE_ROLES)
def api_scan():
    data = request.get_json(silent=True) or {}
    try:
        log_id = start_scan(data.get('ip_range'), data.get('ports'),
                            data.get('workers'),
                            udp_ports_text=data.get('udp_ports'))
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    return jsonify({'status': 'started', 'log_id': log_id})


# планировщик запускается вместе с приложением
threading.Thread(target=scheduler_loop, daemon=True).start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
