import asyncio
import base64
import hashlib
import hmac
import html
import http.client
import http.cookiejar
import ipaddress
import json
import os
import queue
import random
import re
import secrets
import ssl
import string
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import streamlit as st
import streamlit.components.v1 as components

# ==============================================================================
# CẤU HÌNH HỆ THỐNG & DỮ LIỆU GỐC (BẢN TỐI ƯU SIÊU MƯỢT 5.000 - 20.000 NGƯỜI DÙNG)
# ==============================================================================

# Danh sách tiền tố tên chuẩn ASCII dùng cho hàm sinh email ngẫu nhiên chống trùng tuyệt đối
COMMON_NAMES = [
    "tuan", "nick", "alpha", "truong", "minh", "alex", "kevin", "huy",
    "lucas", "david", "nam", "ryan", "jason", "khoa", "daniel", "long",
    "son", "phong", "duc", "hoang", "vinh", "khanh", "lam",
    "ba", "cuong", "dat", "hai", "hung", "kien", "linh", "loc",
    "manh", "nghia", "nha", "phat", "phuc", "quang", "quoc", "tai",
    "tam", "tan", "thang", "thanh", "thien", "thinh", "toan", "tri",
    "trung", "tu", "tung", "viet", "vu", "vy", "an", "binh"
]
COMMON_NAMES = [n for n in COMMON_NAMES if n.isascii() and n.isalpha()]
EMAIL_DOMAINS = ["gmail.com", "outlook.com", "icloud.com", "yahoo.com"]

# ĐÚNG 9 DOMAIN DENYLIST CHUẨN
DENYLIST_9_DOMAINS = [
    "firebaseinstallations.googleapis.com",
    "app-measurement.com",
    "api2.amplitude.com",
    "api.amplitude.com",
    "amplitude.com",
    "firebaseremoteconfig.googleapis.com",
    "revenuecat.com",
    "purchase.locket.camera",
    "api.revenuecat.com"
]

# File lưu trữ Thư viện tài khoản (`thu_vien.json`) & IP khách lâu dài trên máy
LIBRARY_FILE = "thu_vien.json"
USED_IPS_FILE = "nextdns_used_ips.json"

# Bảo mật mật khẩu Nhà phát triển:
# Ưu tiên tuyệt đối `st.secrets["DEV_PASSWORD"]` trên Streamlit Cloud, kèm fallback SHA-256 có salt.
DEV_PASSWORD_SHA256 = "6faa4e812762a0a0f2c1a2a873b84db721c62d325d5144a01be7c5bf254dc51b"

# Giới hạn chống dò mật khẩu (Brute-force) lưu cấp Server (không bị reset khi nhấn F5)
MAX_DEV_LOGIN_ATTEMPTS = 5
DEV_LOCKOUT_SECONDS = 60
DEV_ATTEMPT_TTL_SECONDS = 900.0

# Thời gian giữ chỗ tối đa cho 1 IP đang trong quá trình tạo (chống Race Condition bấm nhiều tab)
IN_FLIGHT_TIMEOUT_SECONDS = 45.0

# Điều tiết luồng gọi đồng thời tới `api.nextdns.io/accounts` từ 1 IP Egress của Streamlit Cloud
# ở mức tối ưu (6 luồng song song, thời gian xếp hàng 35s) để khách mượt mà và KHÔNG dính HTTP 429.
GLOBAL_API_SEMAPHORE_LIMIT = 6
SEMAPHORE_ACQUIRE_TIMEOUT = 35.0
_GLOBAL_NEXTDNS_SEMAPHORE: threading.BoundedSemaphore = threading.BoundedSemaphore(GLOBAL_API_SEMAPHORE_LIMIT)

# Khởi tạo sẵn SSL Context toàn cục (1 lần duy nhất) giúp tiết kiệm ~30ms nạp chứng chỉ CA ở mỗi request
_SHARED_SSL_CONTEXT = ssl.create_default_context()

# Sentinel phân biệt chuẩn xác lỗi HTTP 404 (chưa có file trên nhánh GitHub) với file rỗng `[]` / `{}`
_GITHUB_NOT_FOUND = object()

# Khóa luồng (Thread Lock) chống xung đột RAM, ghi đĩa bất đồng bộ và đồng bộ GitHub
FILE_LOCK = threading.RLock()
GITHUB_SYNC_LOCK = threading.Lock()
_GITHUB_PENDING_FILES: dict[str, bytes] = {}
_GITHUB_WORKER_RUNNING = False
_DISK_DIRTY_FLAGS: dict[str, bool] = {LIBRARY_FILE: False, USED_IPS_FILE: False}
_DISK_WORKER_RUNNING = False


def verify_dev_password(input_pwd: str) -> bool:
    """
    Kiểm tra mật khẩu Nhà phát triển an toàn:
    1. Nếu cấu hình `DEV_PASSWORD` trong mục Secrets của streamlit.app -> chỉ đối chiếu với Secret này.
    2. Nếu chưa cấu hình Secret -> fallback đối chiếu qua hàm băm SHA-256 (có salt) bằng hmac.compare_digest.
    """
    if not input_pwd:
        return False
    clean_pwd = input_pwd.strip()

    try:
        secret_pwd = st.secrets.get("DEV_PASSWORD", None)
        if secret_pwd is not None and str(secret_pwd).strip() != "":
            return hmac.compare_digest(
                clean_pwd.encode("utf-8"),
                str(secret_pwd).strip().encode("utf-8"),
            )
    except Exception:
        pass

    hashed = hashlib.sha256(f"nextdns_dev_salt::{clean_pwd}".encode("utf-8")).hexdigest()
    return hmac.compare_digest(hashed, DEV_PASSWORD_SHA256)


def _run_async_with_live_logs(coro_factory, on_log_line=None):
    """
    Thực thi coroutine bất đồng bộ trong 1 worker thread riêng biệt:
    - Ở Chế độ Khách (`on_log_line=None`): chạy trực tiếp với overhead = 0, không nghẽn queue UI.
    - Ở Chế độ Nhà phát triển (`on_log_line` có mặt): truyền log theo thời gian thực (real-time)
      qua `queue.Queue` về luồng chính của Streamlit để cập nhật màn hình Terminal mượt mà từng dòng.
    """
    if on_log_line is None:
        result_box_fast: dict[str, object] = {"value": (None, None, {}), "error": None}

        def _fast_guest_worker():
            try:
                result_box_fast["value"] = asyncio.run(coro_factory(None))
            except Exception as exc:
                result_box_fast["error"] = exc

        t_fast = threading.Thread(target=_fast_guest_worker, daemon=True)
        t_fast.start()
        t_fast.join()
        if result_box_fast["error"] is not None:
            raise result_box_fast["error"]  # type: ignore[misc]
        return result_box_fast["value"]

    log_queue: queue.Queue[str | None] = queue.Queue()
    result_box: dict[str, object] = {"value": (None, None, {}), "error": None}

    def _thread_safe_cb(msg: str):
        log_queue.put(msg)

    def _worker():
        try:
            result_box["value"] = asyncio.run(coro_factory(_thread_safe_cb))
        except Exception as exc:
            result_box["error"] = exc
        finally:
            log_queue.put(None)

    worker_thread = threading.Thread(target=_worker, daemon=True)
    worker_thread.start()

    while True:
        try:
            item = log_queue.get(timeout=0.1)
            if item is None:
                break
            on_log_line(item)
        except queue.Empty:
            if not worker_thread.is_alive():
                break

    while not log_queue.empty():
        rem = log_queue.get_nowait()
        if rem is not None:
            on_log_line(rem)
    worker_thread.join()

    if result_box["error"] is not None:
        raise result_box["error"]  # type: ignore[misc]
    return result_box["value"]


def _generate_strong_password() -> str:
    """Sinh mật khẩu ngẫu nhiên chuẩn mật mã, không bao giờ trùng lặp hay cố định."""
    alphabet = string.ascii_letters + string.digits
    core = "".join(secrets.choice(alphabet) for _ in range(10))
    return f"T{core}9@"


def pick_email_if_unused(max_retries: int = 100) -> tuple[str, str]:
    """
    Sinh email ngẫu nhiên với không gian mẫu > 10^14 tổ hợp:
    - Đảm bảo hàng chục nghìn người dùng đăng nhập cùng lúc KHÔNG BAO GIỜ bị trùng email nội bộ
      và không đụng phải các email ngắn đã có sẵn trên máy chủ NextDNS.
    - Lưu và đối chiếu O(1) trực tiếp trong `store["used_emails"]` dưới `FILE_LOCK`.
    """
    store = _get_shared_memory_store()
    with FILE_LOCK:
        used_emails: set = store["used_emails"]
        for _ in range(max_retries):
            prefix = random.choice(COMMON_NAMES)
            rand_num = random.randint(10000, 99999)
            rand_hex = secrets.token_hex(2)
            domain = random.choice(EMAIL_DOMAINS)
            email = f"{prefix}{rand_num}{rand_hex}@{domain}"
            if email not in used_emails:
                used_emails.add(email)
                return email, _generate_strong_password()

        fallback_email = f"alpha{uuid.uuid4().hex[:10]}@gmail.com"
        used_emails.add(fallback_email)
        return fallback_email, _generate_strong_password()


# ==============================================================================
# BỘ KẾT NỐI HTTP KEEP-ALIVE TỐC ĐỘ CAO (TÁI SỬ DỤNG SOCKET TLS — KHÔNG CẦN THƯ VIỆN NGOÀI)
# ==============================================================================

class _NextDNSKeepAliveSession:
    """
    Hàng đợi kết nối HTTPS Keep-Alive (`http.client.HTTPSConnection`) tái sử dụng Socket TLS:
    - Trong code cũ, `urllib.request.urlopen` phải bắt tay TCP + TLS mới cho từng request (tổng cộng 11 lần
      bắt tay TLS cho 1 khách, tốn 2.5s - 3.5s và dễ bị Cloudflare/NextDNS chặn vì mở nhiều kết nối cùng lúc).
    - Với `_NextDNSKeepAliveSession`, kết nối TLS được giữ ấm (`Connection: keep-alive`), tái sử dụng
      cho cả bước Đăng ký -> Lấy Profile ID -> Bắn 9 Domain Denylist, giúp giảm 60% thời gian chờ cho Khách!
    """

    def __init__(self, host: str = "api.nextdns.io", pool_size: int = 3, timeout: int = 10):
        self.host = host
        self.timeout = timeout
        self._pool: queue.LifoQueue[http.client.HTTPSConnection] = queue.LifoQueue(maxsize=pool_size)
        self.cookies: dict[str, str] = {}
        self._cookie_lock = threading.Lock()

    def _acquire_conn(self) -> http.client.HTTPSConnection:
        try:
            conn = self._pool.get_nowait()
            return conn
        except queue.Empty:
            return http.client.HTTPSConnection(
                self.host,
                port=443,
                timeout=self.timeout,
                context=_SHARED_SSL_CONTEXT,
            )

    def _release_conn(self, conn: http.client.HTTPSConnection):
        try:
            self._pool.put_nowait(conn)
        except queue.Full:
            try:
                conn.close()
            except Exception:
                pass

    def _extract_set_cookies(self, resp: http.client.HTTPResponse):
        set_cookie_headers = resp.msg.get_all("Set-Cookie") or []
        if not set_cookie_headers:
            return
        with self._cookie_lock:
            for hdr in set_cookie_headers:
                first_part = hdr.split(";", 1)[0].strip()
                if "=" in first_part:
                    k, v = first_part.split("=", 1)
                    self.cookies[k.strip()] = v.strip()

    def get_cookie_header(self) -> str:
        with self._cookie_lock:
            return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def request(self, method: str, path: str, headers: dict, payload=None, timeout: int = 10) -> tuple[int, dict, str]:
        body_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8") if payload is not None else None
        req_headers = dict(headers)
        req_headers["Connection"] = "keep-alive"
        if body_bytes is not None:
            req_headers["Content-Length"] = str(len(body_bytes))

        cookie_str = self.get_cookie_header()
        if cookie_str and "Cookie" not in req_headers:
            req_headers["Cookie"] = cookie_str

        # Thử tối đa 2 lần trên socket Keep-Alive (nếu socket cũ vừa bị đóng bởi server thì tự mở socket mới ngay)
        for socket_try in range(2):
            conn = self._acquire_conn()
            conn.timeout = timeout
            try:
                conn.request(method, path, body=body_bytes, headers=req_headers)
                resp = conn.getresponse()
                raw_bytes = resp.read()
                self._extract_set_cookies(resp)
                status = resp.status

                # Giữ lại kết nối nếu server không yêu cầu đóng
                conn_hdr = (resp.getheader("Connection") or "").lower()
                if conn_hdr != "close":
                    self._release_conn(conn)
                else:
                    conn.close()

                raw_str = raw_bytes.decode("utf-8", errors="replace") if raw_bytes else ""
                try:
                    data = json.loads(raw_str) if raw_str else {}
                except Exception:
                    data = {"raw": raw_str}
                return status, data, raw_str

            except (
                http.client.RemoteDisconnected,
                http.client.CannotSendRequest,
                http.client.BadStatusLine,
                ConnectionResetError,
                BrokenPipeError,
                TimeoutError,
                OSError,
            ) as ex:
                try:
                    conn.close()
                except Exception:
                    pass
                if socket_try == 0:
                    continue
                return 0, {"error": str(ex)}, str(ex)
            except Exception as ex:
                try:
                    conn.close()
                except Exception:
                    pass
                return 0, {"error": str(ex)}, str(ex)

        return 0, {"error": "connection_failed"}, "connection_failed"

    def close_all(self):
        while not self._pool.empty():
            try:
                c = self._pool.get_nowait()
                c.close()
            except Exception:
                pass


async def add_9_denylist_fast(
    session: _NextDNSKeepAliveSession,
    pid: str,
    headers: dict,
    log_fn=None,
) -> int:
    """
    Bắn cả 9 domain vào Denylist trên kết nối HTTP Keep-Alive tái sử dụng TLS (SIÊU MƯỢT & ĐẢM BẢO 9/9):
    - Đợt 1: 3 luồng Keep-Alive song song (`Semaphore(3)`) bắn 9 domain trên 3 kết nối TLS giữ ấm.
    - Đợt 2 (Đối chiếu & Bù thông minh): Nếu có domain báo lỗi mạng tạm thời, kiểm tra danh sách thực tế
      trên hồ sơ (`GET /profiles/{pid}/denylist`) rồi bắn bù chính xác những domain còn thiếu.
    """
    path = f"/profiles/{pid}/denylist"
    sem = asyncio.Semaphore(3)
    req_headers = dict(headers)

    async def _post_one(domain: str) -> bool:
        clean_d = domain.strip().lower().removeprefix("https://").removeprefix("http://").strip("/")
        async with sem:
            for attempt in range(3):
                status, _, _ = await asyncio.to_thread(
                    session.request,
                    "POST",
                    path,
                    req_headers,
                    {"id": clean_d, "active": True},
                    9,
                )
                if status in (200, 201, 204, 409):
                    return True
                if status in (429, 500, 502, 503, 504, 0) and attempt < 2:
                    await asyncio.sleep(0.25 * (attempt + 1) + random.uniform(0.05, 0.15))
                    continue
                break
        return False

    pending_domains = list(DENYLIST_9_DOMAINS)
    succeeded: set[str] = set()

    # Đợt 1: Bắn song song trên Keep-Alive Pool
    first_results = await asyncio.gather(*[_post_one(d) for d in pending_domains])
    for d, ok in zip(pending_domains, first_results):
        if ok:
            succeeded.add(d)

    # Đợt bù thông minh nếu chưa đủ 9/9 domain
    for retry_round in range(1, 4):
        missing = [d for d in DENYLIST_9_DOMAINS if d not in succeeded]
        if not missing:
            break

        # Kiểm tra thực tế trên server xem domain nào đã vào được Denylist (tránh trường hợp POST timeout nhưng server đã lưu)
        g_status, g_data, _ = await asyncio.to_thread(
            session.request, "GET", path, req_headers, None, 8
        )
        if g_status == 200 and isinstance(g_data, dict):
            existing_list = g_data.get("data", [])
            if isinstance(existing_list, list):
                for entry in existing_list:
                    if isinstance(entry, dict) and entry.get("active") is not False:
                        d_id = str(entry.get("id", "")).strip().lower()
                        if d_id in DENYLIST_9_DOMAINS:
                            succeeded.add(d_id)

        missing = [d for d in DENYLIST_9_DOMAINS if d not in succeeded]
        if not missing:
            break

        if log_fn:
            log_fn(f"[*] Đang chạy vòng bù #{retry_round} cho {len(missing)} domain còn thiếu...")
        await asyncio.sleep(0.35 * retry_round)
        retry_results = await asyncio.gather(*[_post_one(d) for d in missing])
        for d, ok in zip(missing, retry_results):
            if ok:
                succeeded.add(d)

    return len(succeeded)


async def create_profile(log_callback=None) -> tuple[str | None, str | None, dict]:
    """
    LUỒNG ĐĂNG KÝ TÀI KHOẢN & ADD 9 DOMAIN THẾ HỆ MỚI (KEEP-ALIVE + SMART RECOVERY):
    - Tái sử dụng kết nối TLS giữa bước `POST /accounts`, `GET /accounts/@me` và `POST /denylist`
      giúp giảm hơn 60% thời gian chờ ở Chế độ Khách.
    - Nếu bước tạo tài khoản đã thành công (`pid` đã có), kiên trì hoàn tất đủ 9/9 domain ngay trên
      hồ sơ đó thay vì vứt bỏ tài khoản để tạo lại (tránh tự gây lỗi HTTP 429 trên `/accounts`).
    """
    def log(msg: str):
        if log_callback:
            log_callback(msg)

    log("[*] Đang khởi chạy tiến trình đăng ký tài khoản tốc độ cao (Keep-Alive TLS)...")

    base_headers = {
        "Host": "api.nextdns.io",
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "Origin": "https://my.nextdns.io",
        "Referer": "https://my.nextdns.io/signup",
        "User-Agent": (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1"
        ),
    }

    acquired_sem = await asyncio.to_thread(_GLOBAL_NEXTDNS_SEMAPHORE.acquire, True, SEMAPHORE_ACQUIRE_TIMEOUT)
    if not acquired_sem:
        log("[!] Máy chủ đang xử lý nhiều yêu cầu cùng lúc, vui lòng thử lại sau vài giây.")
        return None, None, {"reason": "SERVER_BUSY"}

    session = _NextDNSKeepAliveSession(host="api.nextdns.io", pool_size=3, timeout=10)
    try:
        for attempt in range(1, 6):
            session.cookies.clear()
            email, password = pick_email_if_unused()

            signup_payload = {
                "email": email,
                "password": password,
                "profile": {
                    "name": "Hồ sơ đầu tiên của tôi",
                    "security": {
                        "threatIntelligenceFeeds": True,
                        "googleSafeBrowsing": True,
                        "cryptojacking": True,
                        "idnHomographs": True,
                        "typosquatting": True,
                        "dga": True,
                        "csam": True,
                    },
                    "privacy": {
                        "blocklists": [{"id": "nextdns-recommended"}],
                        "disguisedTrackers": True,
                        "allowAffiliate": True,
                    },
                    "settings": {
                        "logs": {"enabled": True},
                        "performance": {"ecs": True},
                    },
                },
            }

            log(f"[*] Lần thử {attempt}/5 -> Đang đăng ký tài khoản: {email} | Mật khẩu: {password}")
            s_status, s_data, s_raw = await asyncio.to_thread(
                session.request, "POST", "/accounts", base_headers, signup_payload, 12
            )

            if s_status in (200, 201, 204):
                log("[+] ĐĂNG KÝ TÀI KHOẢN THÀNH CÔNG! (Đang lấy Profile ID trên cùng kết nối Keep-Alive...)")
                pid = None
                acc_api_key = None

                # Thử lấy Profile ID ngay trong phản hồi của /accounts nếu có
                if isinstance(s_data, dict):
                    s_core = s_data.get("data", s_data) if isinstance(s_data.get("data"), dict) else s_data
                    acc_api_key = s_core.get("apiKey")
                    s_profiles = s_core.get("profiles", [])
                    if s_profiles and isinstance(s_profiles, list) and isinstance(s_profiles[0], dict):
                        pid = s_profiles[0].get("id")

                # Nếu chưa có trong response đầu, gọi GET /accounts/@me?withProfiles=true trên socket TLS đã mở sẵn (0ms handshake)
                if not pid:
                    me_status, me_data, me_raw = await asyncio.to_thread(
                        session.request, "GET", "/accounts/@me?withProfiles=true", base_headers, None, 10
                    )
                    if me_status == 200 and isinstance(me_data, dict):
                        core_obj = me_data.get("data", me_data) if isinstance(me_data.get("data"), dict) else me_data
                        acc_api_key = acc_api_key or core_obj.get("apiKey")
                        profiles = core_obj.get("profiles", [])
                        if profiles and isinstance(profiles, list):
                            pid = profiles[0].get("id")
                    else:
                        me_raw = ""

                if not pid:
                    req_headers = {**base_headers, "X-Api-Key": acc_api_key} if acc_api_key else base_headers
                    p_status, p_data, _ = await asyncio.to_thread(
                        session.request, "GET", "/profiles", req_headers, None, 10
                    )
                    if p_status == 200 and isinstance(p_data, dict):
                        plist = p_data.get("data", [])
                        if plist and isinstance(plist, list):
                            pid = plist[0].get("id")

                if not pid:
                    log("[!] Đã tạo tài khoản nhưng chưa lấy được Profile ID -> Thử lại...")
                    continue

                dl_headers = {**base_headers, "X-Api-Key": acc_api_key} if acc_api_key else base_headers
                log(f"[*] Profile ID: {pid} -> Đang bắn 9 domain vào Denylist qua Keep-Alive Pool...")
                added_count = await add_9_denylist_fast(
                    session, pid, dl_headers, log_fn=log
                )

                target_total = len(DENYLIST_9_DOMAINS)
                if added_count < target_total:
                    # Khôi phục trực tiếp trên cùng `pid` sau 0.8s nghỉ thay vì tạo tài khoản mới gây nghẽn `/accounts`
                    log(f"[*] Đạt {added_count}/{target_total} domain -> Chạy nhịp vét cuối trên hồ sơ {pid}...")
                    await asyncio.sleep(0.8)
                    added_count = await add_9_denylist_fast(
                        session, pid, dl_headers, log_fn=log
                    )

                if added_count < target_total:
                    log(f"[!] Mới chặn được {added_count}/{target_total} domain -> Khởi tạo lại hồ sơ mới để đảm bảo đủ 9/9...")
                    continue

                apple_web_link = f"https://apple.nextdns.io/?profile={pid}"
                direct_mc_link = f"https://api.nextdns.io/apple/profile?profile={pid}&sign=1"
                doh_link = f"https://dns.nextdns.io/{pid}"
                blocked_str = f"{added_count}/{target_total}"

                log("==================================================================")
                log(f"[SUCCESS] ĐÃ TẠO TÀI KHOẢN NEXTDNS THẬT & CHẶN ĐỦ {blocked_str} DOMAIN")
                log(f"  • Email đăng nhập Web : {email}")
                log(f"  • Mật khẩu đăng nhập  : {password}")
                log(f"  • Trang đăng nhập     : https://my.nextdns.io/login")
                log(f"  • Profile ID          : {pid}")
                log(f"  • Link Web Apple      : {apple_web_link}")
                log(f"  • Link .mobileconfig  : {direct_mc_link}")
                log(f"  • DNS-over-HTTPS      : {doh_link}")
                log("==================================================================")

                meta = {
                    "pid": pid,
                    "email": email,
                    "password": password,
                    "blocked": blocked_str,
                    "apple_web_link": apple_web_link,
                    "direct_mc_link": direct_mc_link,
                    "doh_link": doh_link,
                }
                return pid, apple_web_link, meta

            elif s_status in (400, 409, 422):
                log(f"[!] Lỗi đăng ký với '{email}' (HTTP {s_status}: {s_raw[:120]}) -> Đổi email khác...")
                continue
            elif s_status == 429 or s_status == 0:
                wait_sec = 1.0 * attempt + random.uniform(0.15, 0.4)
                log(f"[!] NextDNS giới hạn tốc độ tạm thời (HTTP {s_status}) -> Đợi {wait_sec:.1f}s rồi thử lại...")
                await asyncio.sleep(wait_sec)
                continue
            else:
                log(f"[!] Máy chủ NextDNS từ chối đăng ký (HTTP {s_status}): {s_raw[:200]}")
                return None, None, {}

        log("[!] Đã thử tối đa 5 lần nhưng chưa đăng ký được tài khoản mới.")
        return None, None, {}
    finally:
        session.close_all()
        _GLOBAL_NEXTDNS_SEMAPHORE.release()


# ==============================================================================
# HỆ THỐNG XÁC THỰC IP PUBLIC THẬT CỦA KHÁCH & CHỐNG GIẢ MẠO X-FORWARDED-FOR
# ==============================================================================

CLOUDFLARE_IPV4_NETS = [
    ipaddress.ip_network(cidr) for cidr in (
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
    )
]

GCP_LB_IPV4_NETS = [
    ipaddress.ip_network(cidr) for cidr in (
        "34.0.0.0/8",
        "35.184.0.0/13",
        "35.192.0.0/10",
        "130.211.0.0/22",
    )
]

CLOUDFLARE_IPV6_NETS = [
    ipaddress.ip_network(cidr) for cidr in (
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32",
    )
]


def _is_bogus_private_or_loopback_ip(ip_key: str) -> bool:
    """
    Kiểm tra nếu `ip_key` là IP nội bộ / loopback lỗi (127.0.0.1, ::1, 10.x, 192.168.x...)
    hoặc IP của Google Cloud Load Balancer, hoặc các mã `ID_`/`fp_`/`LOCAL_CLIENT`/`SESSION_` tạm thời.
    """
    if not ip_key:
        return True
    clean = ip_key.strip()
    if (
        clean.startswith("ID_")
        or clean.startswith("fp_")
        or clean.startswith("SESSION_")
        or clean == "LOCAL_CLIENT"
    ):
        return True
    base_ip = clean.split("/")[0].strip()
    if base_ip.count(":") == 1 and "." in base_ip:
        base_ip = base_ip.split(":")[0]
    try:
        ip_obj = ipaddress.ip_address(base_ip)
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            return True
        if isinstance(ip_obj, ipaddress.IPv4Address) and any(ip_obj in net for net in GCP_LB_IPV4_NETS):
            return True
        return False
    except ValueError:
        return False


def is_valid_public_EndUser_ip(ip_str: str) -> bool:
    """
    Kiểm tra xem một chuỗi IP có phải là Public IP chuẩn của người dùng cuối hay không.
    Loại bỏ hoàn toàn IP nội bộ (10.x, 192.168.x, 127.x) và các node Proxy của Cloudflare/GCP LB.
    """
    if not ip_str:
        return False
    clean = ip_str.strip()
    if clean.count(":") == 1 and "." in clean:
        clean = clean.split(":")[0]
    try:
        ip_obj = ipaddress.ip_address(clean)
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            return False
        if isinstance(ip_obj, ipaddress.IPv4Address):
            if any(ip_obj in net for net in GCP_LB_IPV4_NETS):
                return False
            return not any(ip_obj in net for net in CLOUDFLARE_IPV4_NETS)
        if isinstance(ip_obj, ipaddress.IPv6Address):
            return not any(ip_obj in net for net in CLOUDFLARE_IPV6_NETS)
        return True
    except ValueError:
        return False


def normalize_ip_key(ip_str: str) -> str:
    """
    Chuẩn hóa IP để cố định 1 lần sử dụng cho mỗi khách mà KHÔNG BAO GIỜ chặn nhầm:
    - Với IPv4: giữ nguyên địa chỉ IPv4 chính xác 100% (`a.b.c.d`).
    - Với IPv6: chuẩn hóa về prefix `/64` (tiêu chuẩn định tuyến cho 1 thuê bao cá nhân).
    """
    clean = ip_str.strip()
    if clean.count(":") == 1 and "." in clean:
        clean = clean.split(":")[0]
    try:
        ip_obj = ipaddress.ip_address(clean)
        if isinstance(ip_obj, ipaddress.IPv6Address):
            net64 = ipaddress.IPv6Network(f"{clean}/64", strict=False)
            return str(net64.network_address) + "/64"
        return str(ip_obj)
    except ValueError:
        return clean


def _get_request_headers() -> dict:
    """Đọc toàn bộ HTTP headers từ `st.context.headers` (hoặc fallback cho Streamlit bản cũ)."""
    try:
        ctx = getattr(st, "context", None)
        if ctx is not None and hasattr(ctx, "headers"):
            return dict(ctx.headers)
    except Exception:
        pass
    try:
        from streamlit.web.server.websocket_headers import _get_websocket_headers
        ws_hdrs = _get_websocket_headers()
        if ws_hdrs:
            return dict(ws_hdrs)
    except Exception:
        pass
    return {}


def detect_ios_in_app_browser() -> str | None:
    """
    Phát hiện nếu người dùng đang mở trang bằng trình duyệt nhúng (In-App Browser)
    trên iPhone/iPad (như Zalo, Messenger, Facebook, Instagram, TikTok, Telegram).
    """
    hdrs = _get_request_headers()
    ua = str(hdrs.get("user-agent") or hdrs.get("User-Agent") or "")
    if not ua:
        return None

    is_ios = any(k in ua for k in ("iPhone", "iPad", "iPod"))
    if not is_ios:
        return None

    in_app_signatures = {
        "Zalo": "Zalo",
        "FBAN": "Facebook / Messenger",
        "FBAV": "Facebook / Messenger",
        "Messenger": "Messenger",
        "Instagram": "Instagram",
        "BytedanceWebview": "TikTok",
        "musical_ly": "TikTok",
        "TikTok": "TikTok",
        "Line/": "LINE",
        "MicroMessenger": "WeChat",
    }
    for sig, app_name in in_app_signatures.items():
        if sig.lower() in ua.lower():
            return app_name
    return None


def extract_ip_from_headers() -> str | None:
    """
    [BẢN VÁ BẢO MẬT CHỐNG IP SPOOFING QUA X-FORWARDED-FOR]:
    1. Nếu có `CF-Connecting-IP` hoặc `True-Client-IP` (Header do Cloudflare Edge đóng dấu 100%, khách không thể giả mạo):
       Trả về NGAY LẬP TỨC địa chỉ IP này (kể cả khi khách dùng Cloudflare WARP / iCloud Private Relay),
       TUYỆT ĐỐI KHÔNG rơi xuống đọc `X-Forwarded-For` để chặn đứng lỗ hổng chèn fake `X-Forwarded-For` khi bật WARP!
    2. Chỉ khi không có `CF-Connecting-IP`, mới phân tích `X-Forwarded-For` từ phải sang trái (bỏ qua các hop của
       Cloudflare / GCP Load Balancer ở bên phải và dừng ngay ở IP Public đầu tiên gặp phải).
    """
    hdrs = _get_request_headers()
    if not hdrs:
        return None

    # 1. Ưu tiên tuyệt đối CF-Connecting-IP / True-Client-IP và trả về ngay lập tức
    for trusted_key in ("cf-connecting-ip", "CF-Connecting-IP", "true-client-ip", "True-Client-IP"):
        val = hdrs.get(trusted_key)
        if val:
            cand = str(val).split(",")[0].strip()
            if is_valid_public_EndUser_ip(cand):
                return normalize_ip_key(cand)
            clean_c = cand.split(":")[0] if cand.count(":") == 1 and "." in cand else cand
            try:
                ip_o = ipaddress.ip_address(clean_c)
                if not (
                    ip_o.is_private
                    or ip_o.is_loopback
                    or ip_o.is_link_local
                    or ip_o.is_multicast
                    or ip_o.is_reserved
                    or ip_o.is_unspecified
                    or (isinstance(ip_o, ipaddress.IPv4Address) and any(ip_o in net for net in GCP_LB_IPV4_NETS))
                ):
                    # Trả về ngay IP WARP / Private Relay từ CF-Connecting-IP, không đọc X-Forwarded-For
                    return normalize_ip_key(str(ip_o))
            except ValueError:
                pass

    # 2. Nếu không có CF-Connecting-IP, phân tích X-Forwarded-For từ phải sang trái
    xff_val = hdrs.get("x-forwarded-for") or hdrs.get("X-Forwarded-For")
    if xff_val:
        xff_parts = [p.strip() for p in str(xff_val).split(",") if p.strip()]
        fallback_warp_from_right = None
        for cand in reversed(xff_parts):
            if is_valid_public_EndUser_ip(cand):
                return normalize_ip_key(cand)
            # Lưu lại IP hợp lệ không thuộc GCP LB gần nhất từ phải sang (nếu là WARP)
            if fallback_warp_from_right is None:
                clean_c = cand.split(":")[0] if cand.count(":") == 1 and "." in cand else cand
                try:
                    ip_o = ipaddress.ip_address(clean_c)
                    if not (
                        ip_o.is_private
                        or ip_o.is_loopback
                        or ip_o.is_link_local
                        or ip_o.is_multicast
                        or ip_o.is_reserved
                        or ip_o.is_unspecified
                        or (isinstance(ip_o, ipaddress.IPv4Address) and any(ip_o in net for net in GCP_LB_IPV4_NETS))
                    ):
                        fallback_warp_from_right = normalize_ip_key(str(ip_o))
                except ValueError:
                    pass
        if fallback_warp_from_right:
            return fallback_warp_from_right

    # 3. Kiểm tra X-Real-IP nếu có
    for real_key in ("x-real-ip", "X-Real-IP"):
        val = hdrs.get(real_key)
        if val:
            cand = str(val).split(",")[0].strip()
            if is_valid_public_EndUser_ip(cand):
                return normalize_ip_key(cand)

    return None


def inject_anti_inspect_protection():
    """
    Lớp bảo vệ giao diện (Anti-DevTools / Anti-ViewSource):
    - Cho phép bấm chuột phải / nhấn giữ (long-press) vào các vùng kết quả `.result-val`, `.library-pre`,
      `<code>`, `<pre>`, `<a>`, `<input>`, `<textarea>` để người dùng trên iPhone lẫn máy tính copy mượt mà.
    """
    components.html(
        """
        <script>
        (function() {
            try {
                const doc = window.parent.document;
                if (doc.__nextdns_shield_attached) return;
                doc.__nextdns_shield_attached = true;

                doc.addEventListener("contextmenu", function(e) {
                    const target = e.target;
                    if (target && target.closest) {
                        const allowed = target.closest("a, input, textarea, code, pre, .result-val, .library-pre");
                        if (allowed) {
                            return true;
                        }
                    }
                    e.preventDefault();
                    return false;
                }, true);

                doc.addEventListener("keydown", function(e) {
                    const key = (e.key || "").toUpperCase();
                    if (
                        e.keyCode === 123 || key === "F12" ||
                        (e.ctrlKey && e.shiftKey && ["I", "J", "C", "K"].includes(key)) ||
                        (e.metaKey && e.altKey && ["I", "J", "C", "U"].includes(key)) ||
                        ((e.ctrlKey || e.metaKey) && ["U", "S"].includes(key))
                    ) {
                        e.preventDefault();
                        e.stopPropagation();
                        return false;
                    }
                }, true);
            } catch (err) {}
        })();
        </script>
        """,
        height=0,
        width=0,
    )


def get_verified_client_identity() -> tuple[str, str, bool]:
    """
    Lấy `(client_ip, session_token, is_verified)` TỨC THÌ 100% Ở SERVER-SIDE:
    - Mỗi phiên trình duyệt có một `session_token` ngẫu nhiên độc nhất (`secrets.token_hex(12)`),
      đảm bảo 2 người dùng iPhone khác nhau KHÔNG BAO GIỜ bị nhận nhầm là cùng một máy!
    """
    if "guest_session_token" not in st.session_state:
        st.session_state["guest_session_token"] = secrets.token_hex(12)

    session_token = st.session_state["guest_session_token"]

    cached_ip = st.session_state.get("verified_client_ip")
    if cached_ip and not str(cached_ip).startswith("SESSION_"):
        return cached_ip, session_token, True

    header_ip = extract_ip_from_headers()
    if header_ip:
        st.session_state["verified_client_ip"] = header_ip
        return header_ip, session_token, True

    fallback_ip = cached_ip or f"SESSION_{session_token[:12]}"
    st.session_state["verified_client_ip"] = fallback_ip
    return fallback_ip, session_token, False


# ==============================================================================
# QUẢN LÝ FILE `thu_vien.json` & `nextdns_used_ips.json` (ORPHAN COMMIT + SENTINEL 404)
# ==============================================================================

def _normalize_library_numbering(lib_list: list[dict]) -> list[dict]:
    """Đảm bảo mọi mục trong `thu_vien.json` đều được đánh Số Thứ Tự chuẩn từ 1 -> N."""
    if not isinstance(lib_list, list):
        return []
    for idx, item in enumerate(lib_list, start=1):
        if isinstance(item, dict):
            item["stt"] = idx
    return lib_list


def _github_sync_config() -> tuple[str, str, str]:
    """
    Đọc cấu hình đồng bộ Private GitHub từ Streamlit Secrets:
    - Mặc định sử dụng nhánh riêng `data` (hoặc `GITHUB_DATA_BRANCH` nếu chỉ định) thay vì `main`
      để Streamlit Cloud TUYỆT ĐỐI KHÔNG tự động reload/reboot app mỗi khi có khách tạo DNS mới!
    """
    try:
        token = str(st.secrets.get("GITHUB_TOKEN", "")).strip()
        repo = str(st.secrets.get("GITHUB_REPO", "")).strip()
        branch = (
            str(st.secrets.get("GITHUB_DATA_BRANCH", "")).strip()
            or str(st.secrets.get("GITHUB_BRANCH", "")).strip()
            or "data"
        )
        return token, repo, branch
    except Exception:
        return "", "", "data"


def _github_pull_Single_branch(filename: str, token: str, repo: str, branch: str, default_val):
    """
    [BẢN VÁ CHỐNG ZOMBIE DATA]:
    - Phân biệt rõ lỗi HTTP 404 (`_GITHUB_NOT_FOUND`) với trường hợp file tồn tại nhưng đã được
      Nhà phát triển xóa rỗng chủ động (`[]` hoặc `{}`).
    """
    url = f"https://api.github.com/repos/{repo}/contents/{filename}?ref={branch}"
    raw_headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.raw+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    meta_headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    for attempt in range(3):
        req = urllib.request.Request(url, headers=raw_headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                raw_bytes = resp.read()
                if not raw_bytes:
                    return default_val
                return json.loads(raw_bytes.decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return _GITHUB_NOT_FOUND
            try:
                meta_req = urllib.request.Request(url, headers=meta_headers, method="GET")
                with urllib.request.urlopen(meta_req, timeout=12) as m_resp:
                    meta = json.loads(m_resp.read().decode("utf-8"))
                    raw_b64 = meta.get("content", "")
                    if raw_b64:
                        return json.loads(base64.b64decode(raw_b64).decode("utf-8"))
                    blob_sha = meta.get("sha")
                    if blob_sha:
                        blob_url = f"https://api.github.com/repos/{repo}/git/blobs/{blob_sha}"
                        b_req = urllib.request.Request(blob_url, headers=meta_headers, method="GET")
                        with urllib.request.urlopen(b_req, timeout=15) as b_resp:
                            b_meta = json.loads(b_resp.read().decode("utf-8"))
                            return json.loads(base64.b64decode(b_meta.get("content", "")).decode("utf-8"))
            except Exception:
                pass
            if attempt < 2:
                time.sleep(0.45 * (attempt + 1))
                continue
            return None
        except Exception:
            if attempt < 2:
                time.sleep(0.45 * (attempt + 1))
                continue
            return None
    return None


def _github_pull_file(filename: str, default_val):
    """
    Tải nội dung file JSON từ Private GitHub Repo khi Streamlit Cloud khởi động:
    1. Ưu tiên đọc từ nhánh dữ liệu (`data` hoặc `GITHUB_DATA_BRANCH`).
    2. Chỉ khi nhánh `data` trả về `_GITHUB_NOT_FOUND` (HTTP 404 - chưa từng tạo file trên nhánh `data`),
       mới kiểm tra nhánh `main` để kế thừa dữ liệu cũ. Nếu nhánh `data` đã có file (dù là `[]` hay `{}` do
       Developer vừa xóa sạch), giữ nguyên trạng thái rỗng đó, tuyệt đối không kéo lại dữ liệu cũ từ `main`!
    """
    token, repo, branch = _github_sync_config()
    if not token or not repo:
        return None

    res = _github_pull_Single_branch(filename, token, repo, branch, default_val)
    if res is not _GITHUB_NOT_FOUND:
        return res

    if branch != "main":
        main_res = _github_pull_Single_branch(filename, token, repo, "main", default_val)
        if main_res is not _GITHUB_NOT_FOUND:
            return main_res

    return default_val


def _ensure_github_branch_exists(base_api: str, headers: dict, branch: str) -> str | None:
    """
    Đảm bảo nhánh `branch` (ví dụ `data`) tồn tại trên GitHub:
    - Nếu đã có: trả về `latest_commit_sha` của nhánh đó.
    - Nếu chưa có (404): tự động lấy SHA từ nhánh mặc định (`main` / `master`) và tạo nhánh `branch` tức thì!
    """
    ref_url = f"{base_api}/git/ref/heads/{branch}"
    try:
        ref_req = urllib.request.Request(ref_url, headers=headers, method="GET")
        with urllib.request.urlopen(ref_req, timeout=10) as r_ref:
            ref_data = json.loads(r_ref.read().decode("utf-8"))
            return ref_data["object"]["sha"]
    except urllib.error.HTTPError as e:
        if e.code != 404:
            return None
    except Exception:
        return None

    base_sha = None
    for fallback_br in ("main", "master"):
        try:
            fb_req = urllib.request.Request(f"{base_api}/git/ref/heads/{fallback_br}", headers=headers, method="GET")
            with urllib.request.urlopen(fb_req, timeout=10) as r_fb:
                fb_data = json.loads(r_fb.read().decode("utf-8"))
                base_sha = fb_data["object"]["sha"]
                break
        except Exception:
            continue

    if not base_sha:
        return None

    try:
        create_ref_payload = json.dumps({
            "ref": f"refs/heads/{branch}",
            "sha": base_sha,
        }).encode("utf-8")
        create_req = urllib.request.Request(
            f"{base_api}/git/refs",
            data=create_ref_payload,
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(create_req, timeout=10) as r_cr:
            cr_data = json.loads(r_cr.read().decode("utf-8"))
            return cr_data["object"]["sha"]
    except urllib.error.HTTPError as he:
        if he.code == 422:
            return base_sha
        return None
    except Exception:
        return None


def _github_batch_commit_via_git_data(files_dict: dict[str, bytes], token: str, repo: str, branch: str) -> bool:
    """
    Gộp cập nhật cả `thu_vien.json` và `nextdns_used_ips.json` vào CÙNG 1 COMMIT duy nhất qua Git Data API:
    - [BẢN VÁ CHỐNG ĐẦY DUNG LƯỢNG GIT]: Khi lưu trên nhánh dữ liệu riêng (`branch != "main"`),
      sử dụng Orphan Commit (`parents: []`) kết hợp `force: True` để nhánh `data` chỉ giữ đúng 1 trạng thái
      mới nhất, giúp dung lượng repo mãi mãi dưới 5MB dù chạy tới 10.000 - 20.000 người dùng!
    """
    if not files_dict:
        return True

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    base_api = f"https://api.github.com/repos/{repo}"
    is_dedicated_data_branch = branch not in ("main", "master")

    for attempt in range(3):
        try:
            latest_commit_sha = _ensure_github_branch_exists(base_api, headers, branch)
            if not latest_commit_sha:
                break

            commit_req = urllib.request.Request(f"{base_api}/git/commits/{latest_commit_sha}", headers=headers, method="GET")
            with urllib.request.urlopen(commit_req, timeout=10) as r_com:
                commit_data = json.loads(r_com.read().decode("utf-8"))
                base_tree_sha = commit_data["tree"]["sha"]

            tree_entries = []
            for fname, fbytes in files_dict.items():
                b64_content = base64.b64encode(fbytes).decode("ascii")
                blob_payload = json.dumps({"content": b64_content, "encoding": "base64"}).encode("utf-8")
                blob_req = urllib.request.Request(f"{base_api}/git/blobs", data=blob_payload, headers=headers, method="POST")
                with urllib.request.urlopen(blob_req, timeout=25) as r_blob:
                    blob_data = json.loads(r_blob.read().decode("utf-8"))
                    tree_entries.append({
                        "path": fname,
                        "mode": "100644",
                        "type": "blob",
                        "sha": blob_data["sha"],
                    })

            tree_payload = json.dumps({
                "base_tree": base_tree_sha,
                "tree": tree_entries,
            }).encode("utf-8")
            tree_req = urllib.request.Request(f"{base_api}/git/trees", data=tree_payload, headers=headers, method="POST")
            with urllib.request.urlopen(tree_req, timeout=15) as r_tree:
                tree_data = json.loads(r_tree.read().decode("utf-8"))
                new_tree_sha = tree_data["sha"]

            file_list_str = ", ".join(files_dict.keys())
            new_commit_payload = json.dumps({
                "message": f"chore(sync): update {file_list_str} [skip ci]",
                "tree": new_tree_sha,
                "parents": [] if is_dedicated_data_branch else [latest_commit_sha],
            }).encode("utf-8")
            new_com_req = urllib.request.Request(f"{base_api}/git/commits", data=new_commit_payload, headers=headers, method="POST")
            with urllib.request.urlopen(new_com_req, timeout=15) as r_ncom:
                new_com_data = json.loads(r_ncom.read().decode("utf-8"))
                new_commit_sha = new_com_data["sha"]

            patch_payload = json.dumps({
                "sha": new_commit_sha,
                "force": True if is_dedicated_data_branch else False,
            }).encode("utf-8")
            patch_req = urllib.request.Request(f"{base_api}/git/refs/heads/{branch}", data=patch_payload, headers=headers, method="PATCH")
            with urllib.request.urlopen(patch_req, timeout=10):
                return True
        except urllib.error.HTTPError as he:
            if he.code in (409, 422) and attempt < 2:
                time.sleep(0.45 * (attempt + 1))
                continue
            break
        except Exception:
            if attempt < 2:
                time.sleep(0.45 * (attempt + 1))
                continue
            break
    return False


def _github_put_single_file_fallback(filename: str, content_bytes: bytes, token: str, repo: str, branch: str):
    """Fallback qua Contents API nếu repo mới khởi tạo chưa có nhánh/commit cho Git Data API."""
    if len(content_bytes) >= 800_000:
        _github_batch_commit_via_git_data({filename: content_bytes}, token, repo, branch)
        return

    url = f"https://api.github.com/repos/{repo}/contents/{filename}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    b64_content = base64.b64encode(content_bytes).decode("ascii")

    for _ in range(3):
        sha = None
        try:
            get_req = urllib.request.Request(f"{url}?ref={branch}", headers=headers, method="GET")
            with urllib.request.urlopen(get_req, timeout=8) as r_get:
                meta = json.loads(r_get.read().decode("utf-8"))
                sha = meta.get("sha")
        except Exception:
            sha = None

        payload = {
            "message": f"chore(sync): update {filename} [skip ci]",
            "content": b64_content,
            "branch": branch,
        }
        if sha:
            payload["sha"] = sha

        put_req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="PUT",
        )
        try:
            with urllib.request.urlopen(put_req, timeout=12):
                return
        except urllib.error.HTTPError as e:
            if e.code == 409:
                time.sleep(0.4)
                continue
            return
        except Exception:
            return


def _reconcile_github_before_push_if_needed(store: dict) -> bool:
    """
    Nếu lúc Streamlit Cloud vừa khởi động mà mạng GitHub bị lỗi (`github_pull_verified == False`),
    trước khi cho phép đẩy bất kỳ commit nào lên GitHub, hàm này sẽ tự động kéo lại dữ liệu gốc trên GitHub
    và gộp (merge) an toàn với các mục vừa được tạo trong RAM.
    """
    if store.get("github_pull_verified", True):
        return True

    token, repo, _ = _github_sync_config()
    if not token or not repo:
        store["github_pull_verified"] = True
        return True

    remote_lib = _github_pull_file(LIBRARY_FILE, [])
    remote_ips = _github_pull_file(USED_IPS_FILE, {})
    if remote_lib is None or remote_ips is None:
        return False

    with FILE_LOCK:
        if isinstance(remote_lib, list) and remote_lib:
            existing_keys = {
                (str(it.get("pid", "")), str(it.get("email", "")))
                for it in remote_lib if isinstance(it, dict)
            }
            merged_lib = list(remote_lib)
            for local_it in store["library"]:
                key = (str(local_it.get("pid", "")), str(local_it.get("email", "")))
                if key not in existing_keys:
                    merged_lib.append(dict(local_it))
                    existing_keys.add(key)
            store["library"] = _normalize_library_numbering(merged_lib)
            for it in store["library"]:
                if isinstance(it, dict) and it.get("email"):
                    store["used_emails"].add(str(it["email"]).strip())
            store["library_version"] = store.get("library_version", 1) + 1

        if isinstance(remote_ips, dict) and remote_ips:
            merged_ips = dict(remote_ips)
            merged_ips.update(store["used_ips"])
            store["used_ips"] = merged_ips

        store["github_pull_verified"] = True
    return True


def _github_enqueue_bytes(store: dict, files_payload: dict[str, bytes]):
    """
    Đẩy ngầm các file JSON về Private GitHub Repo qua hàng đợi tuần tự (Single Batch Worker):
    - [BẢN VÁ CHỐNG KẸT HÀNG ĐỢI]: Nếu mạng GitHub tạm thời chập chờn khi reconcile, worker sẽ
      tự động nghỉ và thử lại tối đa 5 chu kỳ liên tiếp thay vì thoát luồng làm kẹt dữ liệu trong RAM!
    """
    global _GITHUB_WORKER_RUNNING
    token, repo, branch = _github_sync_config()
    if not token or not repo or not files_payload:
        return

    with GITHUB_SYNC_LOCK:
        _GITHUB_PENDING_FILES.update(files_payload)
        if _GITHUB_WORKER_RUNNING:
            return
        _GITHUB_WORKER_RUNNING = True

    def _serialized_worker():
        global _GITHUB_WORKER_RUNNING
        reconcile_retries = 0
        while True:
            time.sleep(1.2)
            with GITHUB_SYNC_LOCK:
                if not _GITHUB_PENDING_FILES:
                    _GITHUB_WORKER_RUNNING = False
                    return
                batch_to_push = dict(_GITHUB_PENDING_FILES)
                _GITHUB_PENDING_FILES.clear()

            was_unverified = not store.get("github_pull_verified", True)
            if not _reconcile_github_before_push_if_needed(store):
                reconcile_retries += 1
                with GITHUB_SYNC_LOCK:
                    for k, v in batch_to_push.items():
                        if k not in _GITHUB_PENDING_FILES:
                            _GITHUB_PENDING_FILES[k] = v
                    if reconcile_retries >= 5:
                        _GITHUB_WORKER_RUNNING = False
                        return
                time.sleep(2.5 * reconcile_retries)
                continue

            reconcile_retries = 0
            if was_unverified:
                with FILE_LOCK:
                    if LIBRARY_FILE in batch_to_push:
                        batch_to_push[LIBRARY_FILE] = json.dumps(
                            list(store["library"]), ensure_ascii=False, separators=(",", ":")
                        ).encode("utf-8")
                        _atomic_write_bytes(LIBRARY_FILE, batch_to_push[LIBRARY_FILE])
                    if USED_IPS_FILE in batch_to_push:
                        batch_to_push[USED_IPS_FILE] = json.dumps(
                            dict(store["used_ips"]), ensure_ascii=False, separators=(",", ":")
                        ).encode("utf-8")
                        _atomic_write_bytes(USED_IPS_FILE, batch_to_push[USED_IPS_FILE])

            ok = _github_batch_commit_via_git_data(batch_to_push, token, repo, branch)
            if not ok:
                for fname, fbytes in batch_to_push.items():
                    try:
                        _github_put_single_file_fallback(fname, fbytes, token, repo, branch)
                    except Exception:
                        pass

    threading.Thread(target=_serialized_worker, daemon=True).start()


def _atomic_write_bytes(filepath: str, raw_bytes: bytes):
    """Ghi file nguyên tử (Atomic Replace qua file tạm) để không bao giờ hỏng file khi đa luồng."""
    tmp_path = f"{filepath}.{threading.get_ident()}.tmp"
    try:
        with open(tmp_path, "wb") as f:
            f.write(raw_bytes)
        os.replace(tmp_path, filepath)
    except Exception:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass


def _schedule_background_persistence(store: dict, target_file: str):
    """
    Ghi đĩa cục bộ và đẩy lên GitHub hoàn toàn ở luồng nền (Debounced Background Persistence):
    - Dùng Shallow Copy O(1) (`list(store["library"])` và `dict(store["used_ips"])`) dưới `FILE_LOCK`.
    - Dùng Compact JSON (`separators=(",", ":")`) giúp giảm 35% kích thước file và tăng gấp đôi tốc độ ghi.
    """
    global _DISK_WORKER_RUNNING
    with FILE_LOCK:
        _DISK_DIRTY_FLAGS[target_file] = True
        if target_file == LIBRARY_FILE:
            store["library_version"] = store.get("library_version", 0) + 1
        if _DISK_WORKER_RUNNING:
            return
        _DISK_WORKER_RUNNING = True

    def _disk_and_gh_worker():
        global _DISK_WORKER_RUNNING
        while True:
            time.sleep(0.25)
            with FILE_LOCK:
                dirty_lib = _DISK_DIRTY_FLAGS.get(LIBRARY_FILE, False)
                dirty_ips = _DISK_DIRTY_FLAGS.get(USED_IPS_FILE, False)
                if not dirty_lib and not dirty_ips:
                    _DISK_WORKER_RUNNING = False
                    return
                _DISK_DIRTY_FLAGS[LIBRARY_FILE] = False
                _DISK_DIRTY_FLAGS[USED_IPS_FILE] = False
                lib_snapshot = list(store["library"]) if dirty_lib else None
                ips_snapshot = dict(store["used_ips"]) if dirty_ips else None

            gh_batch: dict[str, bytes] = {}
            if lib_snapshot is not None:
                lib_bytes = json.dumps(lib_snapshot, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                _atomic_write_bytes(LIBRARY_FILE, lib_bytes)
                gh_batch[LIBRARY_FILE] = lib_bytes

            if ips_snapshot is not None:
                ips_bytes = json.dumps(ips_snapshot, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                _atomic_write_bytes(USED_IPS_FILE, ips_bytes)
                gh_batch[USED_IPS_FILE] = ips_bytes

            if gh_batch:
                _github_enqueue_bytes(store, gh_batch)

    threading.Thread(target=_disk_and_gh_worker, daemon=True).start()


@st.cache_resource
def _get_shared_memory_store() -> dict:
    """
    Bộ nhớ dùng chung toàn cục cho tất cả người truy cập trên cùng máy chủ Streamlit:
    1. Khôi phục chuẩn xác từ Private GitHub Repo kèm cờ bảo vệ `github_pull_verified`.
    2. Tích hợp `in_flight_ips` chống Race Condition khi khách mở nhiều tab bấm cùng lúc.
    3. Tích hợp `dev_lockouts` chống Brute-Force mật khẩu Developer cấp máy chủ (có TTL tự dọn rác).
    """
    used_ips_data = {}
    library_data = []
    used_emails_set = set()

    token, repo, _ = _github_sync_config()
    has_github_cfg = bool(token and repo)

    gh_lib = _github_pull_file(LIBRARY_FILE, []) if has_github_cfg else None
    gh_ips = _github_pull_file(USED_IPS_FILE, {}) if has_github_cfg else None

    github_pull_verified = (not has_github_cfg) or (gh_lib is not None and gh_ips is not None)

    if isinstance(gh_lib, list):
        library_data = _normalize_library_numbering(gh_lib)
        _atomic_write_bytes(LIBRARY_FILE, json.dumps(library_data, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    elif os.path.exists(LIBRARY_FILE):
        try:
            with open(LIBRARY_FILE, "r", encoding="utf-8") as f:
                d = json.load(f)
                if isinstance(d, list):
                    library_data = _normalize_library_numbering(d)
        except Exception:
            library_data = []
    else:
        _atomic_write_bytes(LIBRARY_FILE, b"[]")

    if isinstance(gh_ips, dict):
        used_ips_data = gh_ips
        _atomic_write_bytes(USED_IPS_FILE, json.dumps(used_ips_data, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    elif os.path.exists(USED_IPS_FILE):
        try:
            with open(USED_IPS_FILE, "r", encoding="utf-8") as f:
                d = json.load(f)
                if isinstance(d, dict):
                    used_ips_data = d
        except Exception:
            used_ips_data = {}
    else:
        _atomic_write_bytes(USED_IPS_FILE, b"{}")

    for item in library_data:
        if isinstance(item, dict) and item.get("email"):
            used_emails_set.add(str(item["email"]).strip())

    return {
        "used_ips": used_ips_data,
        "library": library_data,
        "library_version": 1,
        "used_emails": used_emails_set,
        "in_flight_ips": {},
        "dev_lockouts": {},
        "cleaned_legacy_ips": False,
        "github_pull_verified": github_pull_verified,
    }


def _prune_expired_states_locked(store: dict, now_ts: float):
    """
    Dọn dẹp tự động các mục hết hạn trong `in_flight_ips` và `dev_lockouts`
    (bao gồm cả các IP thử sai < 5 lần đã quá hạn `DEV_ATTEMPT_TTL_SECONDS` để chống rò rỉ RAM).
    """
    expired_inflight = [
        ip for ip, ts in store["in_flight_ips"].items()
        if (now_ts - ts) >= IN_FLIGHT_TIMEOUT_SECONDS
    ]
    for ip in expired_inflight:
        store["in_flight_ips"].pop(ip, None)

    if len(store["dev_lockouts"]) > 200:
        expired_locks = [
            k for k, v in store["dev_lockouts"].items()
            if (v.get("lock_until", 0.0) > 0 and now_ts >= v.get("lock_until", 0.0))
            or (now_ts - v.get("last_ts", 0.0) >= DEV_ATTEMPT_TTL_SECONDS)
        ]
        for k in expired_locks:
            store["dev_lockouts"].pop(k, None)


def _persist_used_ips_locked(store: dict):
    """Đánh dấu đồng bộ used_ips xuống đĩa và GitHub ở luồng nền."""
    _schedule_background_persistence(store, USED_IPS_FILE)


def _persist_library_locked(store: dict):
    """Đánh dấu đồng bộ library xuống đĩa và GitHub ở luồng nền."""
    _schedule_background_persistence(store, LIBRARY_FILE)


def load_used_ips() -> dict:
    """Đọc danh sách các IP đã tạo tài khoản (an toàn đa luồng)."""
    store = _get_shared_memory_store()
    with FILE_LOCK:
        return dict(store["used_ips"])


def find_existing_guest_record(used_ips: dict, client_ip: str) -> dict | None:
    """
    Kiểm tra chính xác hồ sơ của khách:
    1. Ưu tiên kiểm tra trong `st.session_state["guest_created_record"]` (tốc độ 0ms, giữ cố định ngay trong phiên).
    2. Đối chiếu chính xác theo địa chỉ IP thật đã xác thực (`client_ip`) trong `used_ips`.
    """
    session_rec = st.session_state.get("guest_created_record")
    if isinstance(session_rec, dict) and session_rec.get("pid"):
        if client_ip and not client_ip.startswith("SESSION_") and client_ip in used_ips:
            return used_ips[client_ip]
        if client_ip.startswith("SESSION_"):
            return session_rec

    if client_ip and client_ip in used_ips:
        return used_ips[client_ip]
    return None


def try_acquire_ip_slot(client_ip: str) -> tuple[bool, str]:
    """
    Khóa giữ chỗ nguyên tử (Atomic Reservation) cho IP trước khi gọi API NextDNS:
    - Chống triệt để lỗi Race Condition khi khách bấm đúp chuột hoặc mở nhiều tab bấm cùng lúc.
    """
    if client_ip.startswith("SESSION_") and st.session_state.get("guest_created_record"):
        return False, "ALREADY_USED"

    store = _get_shared_memory_store()
    now_ts = time.time()
    with FILE_LOCK:
        _prune_expired_states_locked(store, now_ts)
        if not client_ip.startswith("SESSION_") and client_ip in store["used_ips"]:
            return False, "ALREADY_USED"

        in_flight_ts = store["in_flight_ips"].get(client_ip)
        if in_flight_ts is not None and (now_ts - in_flight_ts) < IN_FLIGHT_TIMEOUT_SECONDS:
            return False, "IN_FLIGHT"

        store["in_flight_ips"][client_ip] = now_ts
        return True, "OK"


def release_ip_slot(client_ip: str):
    """Giải phóng trạng thái đang tạo của IP sau khi hoàn tất hoặc khi gặp lỗi mạng."""
    store = _get_shared_memory_store()
    with FILE_LOCK:
        store["in_flight_ips"].pop(client_ip, None)


def save_used_ip(ip: str, record: dict):
    """Lưu cố định IP của khách đã tạo tài khoản và giải phóng khóa in-flight."""
    st.session_state["guest_created_record"] = record
    store = _get_shared_memory_store()
    with FILE_LOCK:
        store["in_flight_ips"].pop(ip, None)
        if ip and not ip.startswith("SESSION_"):
            store["used_ips"][ip] = record
            _persist_used_ips_locked(store)


def clear_all_used_ips():
    """Xóa danh sách IP đã lưu (chỉ dành cho Nhà phát triển)."""
    st.session_state.pop("guest_created_record", None)
    store = _get_shared_memory_store()
    with FILE_LOCK:
        store["used_ips"].clear()
        store["in_flight_ips"].clear()
        _persist_used_ips_locked(store)


def delete_single_used_ip(ip_to_remove: str):
    """Mở khóa cho 1 IP cụ thể (dành cho Nhà phát triển)."""
    store = _get_shared_memory_store()
    with FILE_LOCK:
        store["used_ips"].pop(ip_to_remove, None)
        store["in_flight_ips"].pop(ip_to_remove, None)
        _persist_used_ips_locked(store)


def check_and_record_dev_login(client_ip: str, is_success: bool = False, check_only: bool = False) -> tuple[bool, int, int]:
    """Quản lý chống Brute-Force mật khẩu Developer ở cấp Server (lưu theo IP + chống F5 + TTL dọn rác)."""
    store = _get_shared_memory_store()
    now_ts = time.time()
    key = "FALLBACK_LOCAL_AUTH" if (not client_ip or client_ip.startswith("SESSION_")) else client_ip
    with FILE_LOCK:
        _prune_expired_states_locked(store, now_ts)
        rec = store["dev_lockouts"].get(key, {"fails": 0, "lock_until": 0.0, "last_ts": now_ts})
        if now_ts < rec["lock_until"]:
            remain = int(rec["lock_until"] - now_ts) + 1
            return True, remain, 0

        if check_only:
            left = max(1, MAX_DEV_LOGIN_ATTEMPTS - rec["fails"])
            return False, 0, left

        if is_success:
            store["dev_lockouts"].pop(key, None)
            return False, 0, MAX_DEV_LOGIN_ATTEMPTS

        rec["fails"] = rec.get("fails", 0) + 1
        rec["last_ts"] = now_ts
        left = MAX_DEV_LOGIN_ATTEMPTS - rec["fails"]
        if left <= 0:
            rec["lock_until"] = now_ts + DEV_LOCKOUT_SECONDS
            rec["fails"] = 0
            store["dev_lockouts"][key] = rec
            return True, DEV_LOCKOUT_SECONDS, 0
        else:
            store["dev_lockouts"][key] = rec
            return False, 0, left


# ==============================================================================
# HÀM NHẬP TÊN & BẮN TOÀN BỘ DANH SÁCH LÊN `thu_vien.json` THEO SỐ THỨ TỰ (1 -> N)
# ==============================================================================

def input_customer_name() -> str:
    """Hàm nhập tên người dùng / tên khách hàng trên giao diện trước khi tạo tài khoản."""
    raw_name = st.text_input(
        "⌨ NHẬP TÊN CỦA BẠN:",
        value="",
        placeholder="Nhập tên của bạn (VD: Văn Trường, Minh Anh...)",
        key="customer_name_input",
    )
    clean_name = raw_name.strip()
    return clean_name if clean_name else f"Khách_{time.strftime('%H%M%S')}"


def load_library_from_disk() -> tuple[list[dict], int]:
    """Đọc danh sách tài khoản kèm version từ bộ nhớ chuẩn O(1)."""
    store = _get_shared_memory_store()
    with FILE_LOCK:
        return list(store["library"]), int(store.get("library_version", 1))


def push_to_library(name: str, email: str, password: str, dns_link: str, pid: str = "", doh_link: str = "", ip: str = "") -> dict:
    """Thêm tài khoản mới kèm Số Thứ Tự (`stt`: 1, 2, 3...) vào `thu_vien.json` với độ phức tạp O(1)."""
    store = _get_shared_memory_store()
    with FILE_LOCK:
        last_stt = store["library"][-1].get("stt", len(store["library"])) if store["library"] else 0
        next_stt = max(len(store["library"]) + 1, int(last_stt) + 1)

        if email:
            store["used_emails"].add(email.strip())

        item = {
            "stt": next_stt,
            "name": name,
            "email": email,
            "password": password,
            "dns_link": dns_link,
            "pid": pid,
            "doh_link": doh_link,
            "ip": ip,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        store["library"].append(item)
        _persist_library_locked(store)

    return item


def format_library_text(library_items: list[dict]) -> str:
    """Định dạng danh sách tài khoản theo đúng Số Thứ Tự (1, 2, 3...)."""
    blocks = []
    for idx, item in enumerate(library_items, start=1):
        stt_num = item.get("stt", idx)
        block = (
            f"STT: {stt_num}\n"
            f"Tên: {item.get('name', '')}\n"
            f"Mail: {item.get('email', '')}\n"
            f"Mật khẩu: {item.get('password', '')}\n"
            f"Link dns: {item.get('dns_link', '')}"
        )
        blocks.append(block)
    return "\n\n----------------------------------------\n\n".join(blocks)


def _extract_pid_from_links(dns_link: str, doh_link: str = "", raw_pid: str = "") -> str:
    """Tự động bóc tách Profile ID (pid) từ Link Apple DNS hoặc DoH link nếu bản ghi cũ thiếu pid."""
    clean_pid = str(raw_pid or "").strip().lstrip("#")
    if clean_pid and clean_pid.upper() != "N/A":
        return clean_pid
    for candidate in (dns_link, doh_link):
        s = str(candidate or "").strip()
        if not s:
            continue
        m_prof = re.search(r"[?&]profile=([a-zA-Z0-9_-]+)", s)
        if m_prof:
            return m_prof.group(1)
        m_doh = re.search(r"dns\.nextdns\.io/([a-zA-Z0-9_-]+)", s)
        if m_doh:
            return m_doh.group(1)
        m_path = re.search(r"/profiles/([a-zA-Z0-9_-]+)", s)
        if m_path:
            return m_path.group(1)
    return ""


def normalize_single_library_record(raw_item: dict, fallback_stt: int = 1) -> dict | None:
    """
    Chuẩn hóa 1 object/dict tài khoản bất kỳ về đúng định dạng chuẩn của `thu_vien.json`:
    {
      "stt": int,
      "name": str,
      "email": str,
      "password": str,
      "dns_link": str,
      "pid": str,
      "doh_link": str,
      "ip": str,
      "created_at": str
    }
    """
    if not isinstance(raw_item, dict):
        return None

    def _pick(*keys) -> str:
        for k in keys:
            val = raw_item.get(k)
            if val is not None and str(val).strip() != "":
                return str(val).strip()
        return ""

    name_val = _pick("name", "ten", "Tên", "customer_name", "user")
    email_val = _pick("email", "mail", "Mail", "Email", "username")
    pass_val = _pick("password", "pass", "mat_khau", "Mật khẩu", "pwd")
    dns_link_val = _pick("dns_link", "apple_web_link", "link_dns", "Link dns", "link", "url")
    doh_link_val = _pick("doh_link", "doh", "DNS-over-HTTPS")
    raw_pid_val = _pick("pid", "profile_id", "Profile ID", "id")
    ip_val = _pick("ip", "IP", "client_ip")
    created_at_val = _pick("created_at", "time", "timestamp", "date")

    pid_val = _extract_pid_from_links(dns_link_val, doh_link_val, raw_pid_val)
    if pid_val and not dns_link_val:
        dns_link_val = f"https://apple.nextdns.io/?profile={pid_val}"
    if pid_val and not doh_link_val:
        doh_link_val = f"https://dns.nextdns.io/{pid_val}"

    # Bỏ qua nếu bản ghi hoàn toàn trống (không có email, không có pid và không có link dns)
    if not email_val and not pid_val and not dns_link_val:
        return None

    if ip_val.upper() == "N/A":
        ip_val = ""

    raw_stt = raw_item.get("stt", fallback_stt)
    try:
        stt_int = int(str(raw_stt).strip().lstrip("#"))
        if stt_int <= 0:
            stt_int = fallback_stt
    except Exception:
        stt_int = fallback_stt

    if not name_val:
        name_val = f"Khách_{stt_int}"
    if not created_at_val:
        created_at_val = time.strftime("%Y-%m-%d %H:%M:%S")

    return {
        "stt": stt_int,
        "name": name_val,
        "email": email_val,
        "password": pass_val,
        "dns_link": dns_link_val,
        "pid": pid_val,
        "doh_link": doh_link_val,
        "ip": ip_val,
        "created_at": created_at_val,
    }


def parse_and_normalize_library_input(raw_content: str) -> tuple[list[dict], str]:
    """
    Phân tích dữ liệu đầu vào (tự động nhận diện JSON hoặc Văn bản theo định dạng thư viện/log):
    - Hỗ trợ mảng JSON `[...]`, object JSON `{...}`, hoặc JSON Lines.
    - Hỗ trợ văn bản xuất từ `thu_vien_nextdns.txt` (`STT: ... / Tên: ... / Mail: ... / Mật khẩu: ... / Link dns: ...`).
    - Hỗ trợ văn bản copy trực tiếp từ khung thẻ trên giao diện web hoặc từ Terminal Log.
    Trả về `(danh_sách_đã_chuẩn_hóa, thông_báo_lỗi_nếu_có)`.
    """
    text = (raw_content or "").strip().lstrip("\ufeff")
    if not text:
        return [], "Nội dung trống! Vui lòng chọn file hoặc dán dữ liệu cần thêm."

    parsed_records: list[dict] = []

    # 1. Thử phân tích dưới dạng JSON chuẩn trước
    if text.startswith("[") or text.startswith("{"):
        try:
            loaded = json.loads(text)
            raw_list = []
            if isinstance(loaded, list):
                raw_list = loaded
            elif isinstance(loaded, dict):
                if isinstance(loaded.get("library"), list):
                    raw_list = loaded["library"]
                elif isinstance(loaded.get("data"), list):
                    raw_list = loaded["data"]
                else:
                    raw_list = [loaded]
            for idx, item in enumerate(raw_list, start=1):
                norm = normalize_single_library_record(item, fallback_stt=idx)
                if norm:
                    parsed_records.append(norm)
            if parsed_records:
                return _normalize_library_numbering(parsed_records), ""
        except Exception:
            # Nếu người dùng ghép nhiều mảng JSON hoặc JSON Lines, thử tách tiếp bên dưới
            pass

        # Hỗ trợ trường hợp ghép nhiều mảng JSON `[...][...]` hoặc nhiều object `{...}`
        decoder = json.JSONDecoder()
        pos = 0
        n_len = len(text)
        multi_json_items = []
        while pos < n_len:
            while pos < n_len and text[pos].isspace():
                pos += 1
            if pos >= n_len:
                break
            try:
                obj, next_pos = decoder.raw_decode(text, pos)
                if isinstance(obj, list):
                    multi_json_items.extend(obj)
                elif isinstance(obj, dict):
                    multi_json_items.append(obj)
                pos = next_pos
            except Exception:
                break
        if multi_json_items:
            for idx, item in enumerate(multi_json_items, start=1):
                norm = normalize_single_library_record(item, fallback_stt=idx)
                if norm:
                    parsed_records.append(norm)
            if parsed_records:
                return _normalize_library_numbering(parsed_records), ""

    # 2. Phân tích định dạng Văn bản (Text format chuẩn của Thư viện / Copy từ UI / Terminal Log)
    current_rec: dict[str, str] = {}

    def _flush_current():
        nonlocal current_rec
        if current_rec:
            norm = normalize_single_library_record(current_rec, fallback_stt=len(parsed_records) + 1)
            if norm:
                parsed_records.append(norm)
            current_rec = {}

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # Đường kẻ phân cách `----------------------------------------` hoặc `====...`
        if re.match(r"^[-=_*]{5,}$", line):
            _flush_current()
            continue

        # Dòng tiêu đề thẻ copy từ giao diện: `STT #1 // Tên (IP: 1.2.3.4)   2026-11-04 21:00:00`
        m_card_top = re.match(
            r"^STT\s*#?(\d+)\s*//\s*(.+?)(?:\s*\(IP:\s*([^)]+)\))?(?:\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}))?$",
            line,
            flags=re.IGNORECASE,
        )
        if m_card_top:
            if any(k in current_rec for k in ("email", "dns_link", "pid")):
                _flush_current()
            current_rec["stt"] = m_card_top.group(1).strip()
            current_rec.setdefault("name", m_card_top.group(2).strip())
            if m_card_top.group(3):
                current_rec.setdefault("ip", m_card_top.group(3).strip())
            if m_card_top.group(4):
                current_rec.setdefault("created_at", m_card_top.group(4).strip())
            continue

        # Bỏ ký tự bullet đầu dòng nếu copy từ bảng kết quả (`• Tên: ...`)
        clean_line = re.sub(r"^[•\-*]+\s*", "", line)
        if ":" not in clean_line:
            continue

        key_part, val_part = clean_line.split(":", 1)
        k_lower = key_part.strip().lower()
        val_clean = val_part.strip()

        if k_lower in ("stt", "số thứ tự", "số thứ tự thư viện", "so thu tu"):
            if any(k in current_rec for k in ("email", "dns_link", "pid")):
                _flush_current()
            current_rec["stt"] = val_clean.lstrip("#").strip()
        elif k_lower in ("tên", "ten", "tên hồ sơ", "name", "khách hàng"):
            if "name" in current_rec and any(k in current_rec for k in ("email", "dns_link", "pid")):
                _flush_current()
            current_rec["name"] = val_clean
        elif k_lower in ("mail", "email", "email đăng nhập", "email đăng nhập web"):
            if "email" in current_rec and current_rec["email"] != val_clean:
                _flush_current()
            current_rec["email"] = val_clean
        elif k_lower in ("mật khẩu", "mat khau", "password", "mật khẩu đăng nhập", "pass"):
            current_rec["password"] = val_clean
        elif k_lower in ("link dns", "link profile dns", "link web apple", "dns_link", "apple_web_link", "link"):
            current_rec["dns_link"] = val_clean
        elif k_lower in ("profile id", "pid", "mã hồ sơ"):
            current_rec["pid"] = val_clean
        elif k_lower in ("dns-over-https", "doh", "doh_link"):
            current_rec["doh_link"] = val_clean
        elif k_lower in ("ip", "ip đã cố định", "ip xác thực"):
            current_rec["ip"] = val_clean.split("(")[0].strip()
        elif k_lower in ("created_at", "thời gian", "lúc", "ngày tạo"):
            current_rec["created_at"] = val_clean

    _flush_current()

    if not parsed_records:
        return [], (
            "Không tìm thấy tài khoản hợp lệ! Đảm bảo file .json đúng cấu trúc hoặc văn bản có dạng:\n"
            "STT: 1\nTên: ...\nMail: ...\nMật khẩu: ...\nLink dns: https://apple.nextdns.io/?profile=..."
        )

    return _normalize_library_numbering(parsed_records), ""


def import_items_to_library(
    incoming_items: list[dict],
    replace_all: bool = False,
    skip_duplicates: bool = True,
    sync_ips: bool = False,
) -> dict:
    """
    Cập nhật danh sách tài khoản vào `thu_vien.json` (RAM + Đĩa + Đồng bộ GitHub ngầm):
    - Tự động nối tiếp Số Thứ Tự (`stt` 1 -> N) khớp 100% với định dạng cũ và giữ mạch liên tục cho các lần tạo sau.
    - Chống trùng lặp thông minh theo `pid` hoặc `email` (đồng thời bổ sung các trường còn thiếu nếu bản ghi cũ bị khuyết).
    """
    store = _get_shared_memory_store()
    added_count = 0
    skipped_count = 0
    updated_existing_count = 0
    synced_ip_count = 0

    with FILE_LOCK:
        if replace_all:
            working_lib: list[dict] = []
        else:
            working_lib = [dict(it) for it in store["library"] if isinstance(it, dict)]

        # Lập chỉ mục O(1) theo pid và email để kiểm tra trùng siêu tốc
        pid_to_idx: dict[str, int] = {}
        email_to_idx: dict[str, int] = {}

        for idx, existing in enumerate(working_lib):
            p = str(existing.get("pid", "")).strip().lower()
            e = str(existing.get("email", "")).strip().lower()
            if p:
                pid_to_idx[p] = idx
            if e and e != "n/a":
                email_to_idx[e] = idx

        for raw_new in incoming_items:
            norm_item = normalize_single_library_record(raw_new, fallback_stt=len(working_lib) + 1)
            if not norm_item:
                continue

            p_key = str(norm_item.get("pid", "")).strip().lower()
            e_key = str(norm_item.get("email", "")).strip().lower()
            if e_key == "n/a":
                e_key = ""

            matched_idx = None
            if p_key and p_key in pid_to_idx:
                matched_idx = pid_to_idx[p_key]
            elif e_key and e_key in email_to_idx:
                matched_idx = email_to_idx[e_key]

            if skip_duplicates and matched_idx is not None:
                # Nếu bản ghi hiện có bị thiếu trường (như pid, doh_link, ip, password), tự động bù từ bản ghi import
                target_rec = working_lib[matched_idx]
                enriched = False
                for field in ("pid", "doh_link", "dns_link", "password", "ip", "created_at"):
                    if not target_rec.get(field) and norm_item.get(field):
                        target_rec[field] = norm_item[field]
                        enriched = True
                if (
                    norm_item.get("name")
                    and not str(norm_item["name"]).startswith("Khách_")
                    and str(target_rec.get("name", "")).startswith("Khách_")
                ):
                    target_rec["name"] = norm_item["name"]
                    enriched = True

                if enriched:
                    updated_existing_count += 1
                else:
                    skipped_count += 1
                continue

            new_idx = len(working_lib)
            working_lib.append(norm_item)
            added_count += 1
            if p_key:
                pid_to_idx[p_key] = new_idx
            if e_key:
                email_to_idx[e_key] = new_idx

        # Đánh lại STT chuẩn 1 -> N để lần tạo tài khoản tiếp theo nối tiếp STT (N + 1)
        normalized_lib = _normalize_library_numbering(working_lib)
        store["library"] = normalized_lib

        # Đồng bộ lại tập used_emails
        store["used_emails"] = {
            str(it.get("email", "")).strip()
            for it in normalized_lib
            if isinstance(it, dict) and it.get("email") and str(it.get("email")).strip().upper() != "N/A"
        }

        # Tùy chọn khôi phục luôn IP khách vào nextdns_used_ips.json nếu bản ghi có IP hợp lệ
        if sync_ips:
            for it in normalized_lib:
                ip_addr = str(it.get("ip", "")).strip()
                if ip_addr and ip_addr.upper() != "N/A" and not _is_bogus_private_or_loopback_ip(ip_addr):
                    if ip_addr not in store["used_ips"]:
                        pid_val = str(it.get("pid", "")).strip()
                        apple_link = str(it.get("dns_link", "")).strip() or (
                            f"https://apple.nextdns.io/?profile={pid_val}" if pid_val else ""
                        )
                        mc_link = f"https://api.nextdns.io/apple/profile?profile={pid_val}&sign=1" if pid_val else ""
                        doh_link = str(it.get("doh_link", "")).strip() or (
                            f"https://dns.nextdns.io/{pid_val}" if pid_val else ""
                        )
                        store["used_ips"][ip_addr] = {
                            "stt": it.get("stt", 1),
                            "name": it.get("name", "Khách"),
                            "pid": pid_val,
                            "email": it.get("email", "N/A"),
                            "password": it.get("password", "N/A"),
                            "blocked": "9/9",
                            "apple_web_link": apple_link,
                            "direct_mc_link": mc_link,
                            "doh_link": doh_link,
                            "ip": ip_addr,
                            "cid": "",
                            "created_at": it.get("created_at", time.strftime("%Y-%m-%d %H:%M:%S")),
                        }
                        synced_ip_count += 1
            if synced_ip_count > 0:
                _persist_used_ips_locked(store)

        # Ghi ngay lập tức xuống đĩa cục bộ và kích hoạt đồng bộ ngầm lên GitHub
        _atomic_write_bytes(
            LIBRARY_FILE,
            json.dumps(normalized_lib, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
        )
        _persist_library_locked(store)
        total_now = len(store["library"])

    st.session_state.library = normalized_lib
    return {
        "added": added_count,
        "skipped": skipped_count,
        "updated": updated_existing_count,
        "synced_ips": synced_ip_count,
        "total": total_now,
    }


@st.cache_data(show_spinner=False, max_entries=4)
def _get_cached_export_payloads(lib_version: int, total_count: int) -> tuple[bytes, bytes]:
    """
    Cache kết quả xuất file `.txt` và `.json` theo `(lib_version, total_count)`:
    - Giúp Developer lật trang hoặc gõ tìm kiếm mượt tức thì (0ms).
    """
    store = _get_shared_memory_store()
    with FILE_LOCK:
        snap = list(store["library"])
    txt_bytes = format_library_text(snap).encode("utf-8")
    json_bytes = json.dumps(snap, ensure_ascii=False, indent=2).encode("utf-8")
    return txt_bytes, json_bytes


def render_library_import_section():
    """
    Chức năng dành riêng cho Nhà phát triển:
    - Thêm / Gộp (hoặc Ghi đè) file `.json`, `.txt` hoặc dán trực tiếp văn bản/JSON vào `thu_vien.json`.
    - Tự động chuẩn hóa khớp 100% với định dạng cũ của `thu_vien.json`, đánh lại STT liên tục (1 -> N)
      để các tài khoản tạo mới về sau cứ thế tiếp tục (N+1, N+2...).
    """
    with st.expander("📥 KHÔI PHỤC / THÊM FILE .JSON HOẶC VĂN BẢN VÀO THU_VIEN.JSON [DEVELOPER ONLY]", expanded=False):
        st.caption(
            "Dùng để khôi phục hoặc gộp thêm các tài khoản đã lưu (từ file `.json`, `.txt` hoặc văn bản copy) "
            "vào `thu_vien.json` đúng chuẩn định dạng gốc và tự động nối tiếp Số Thứ Tự (STT 1 ➔ N) cho các lần tạo tiếp theo."
        )

        tab_upload, tab_paste = st.tabs([
            "📂 Tải lên File (.json / .txt)",
            "📝 Dán Văn bản hoặc JSON",
        ])

        uploaded_files = None
        pasted_content = ""

        with tab_upload:
            uploaded_files = st.file_uploader(
                "Chọn 1 hoặc nhiều file (.json hoặc .txt) đã lưu:",
                type=["json", "txt"],
                accept_multiple_files=True,
                key="dev_lib_file_uploader",
            )

        with tab_paste:
            pasted_content = st.text_area(
                "Dán nội dung theo định dạng Thư viện (STT / Tên / Mail / Mật khẩu / Link dns) hoặc mảng JSON:",
                height=190,
                placeholder=(
                    "STT: 1\n"
                    "Tên: Văn Trường\n"
                    "Mail: tuan12345ab@gmail.com\n"
                    "Mật khẩu: Tabc12345679@\n"
                    "Link dns: https://apple.nextdns.io/?profile=abc123\n\n"
                    "----------------------------------------\n\n"
                    "(Hoặc dán trực tiếp nội dung file thu_vien.json vào đây...)"
                ),
                key="dev_lib_paste_textarea",
            )

        col_opt1, col_opt2, col_opt3 = st.columns([1.3, 1.2, 1.2])
        with col_opt1:
            import_mode = st.radio(
                "Chế độ cập nhật:",
                options=[
                    "➕ Gộp nối tiếp vào thu_vien.json hiện tại",
                    "🔄 Ghi đè toàn bộ thu_vien.json bằng dữ liệu mới",
                ],
                index=0,
                key="dev_lib_import_mode",
            )
        with col_opt2:
            skip_dups = st.checkbox(
                "Chống trùng lặp (theo Mail / Profile ID)",
                value=True,
                key="dev_lib_skip_dups",
                help="Tự động bỏ qua nếu tài khoản đã có trong thu_vien.json (hoặc chỉ bù thêm thông tin còn khuyết).",
            )
        with col_opt3:
            sync_ips_opt = st.checkbox(
                "Khôi phục luôn IP khách (nếu có)",
                value=True,
                key="dev_lib_sync_ips",
                help="Nếu trong file .json có lưu địa chỉ IP của khách, tự động cập nhật lại vào danh sách IP đã dùng.",
            )

        if st.button("🚀 XÁC NHẬN CẬP NHẬT VÀO THU_VIEN.JSON & ĐỒNG BỘ GITHUB", use_container_width=True, key="btn_exec_lib_import"):
            combined_records: list[dict] = []
            parse_errors: list[str] = []

            if uploaded_files:
                for uf in uploaded_files:
                    try:
                        raw_bytes = uf.read()
                        raw_str = raw_bytes.decode("utf-8", errors="replace")
                        recs, err = parse_and_normalize_library_input(raw_str)
                        if recs:
                            combined_records.extend(recs)
                        elif err:
                            parse_errors.append(f"File `{uf.name}`: {err}")
                    except Exception as ex:
                        parse_errors.append(f"Lỗi đọc file `{uf.name}`: {ex}")

            if pasted_content and pasted_content.strip():
                recs, err = parse_and_normalize_library_input(pasted_content)
                if recs:
                    combined_records.extend(recs)
                elif err:
                    parse_errors.append(err)

            if not combined_records:
                if parse_errors:
                    for pe in parse_errors:
                        st.error(pe)
                else:
                    st.warning("Vui lòng tải lên ít nhất 1 file (.json / .txt) hoặc dán nội dung vào ô văn bản trước khi bấm cập nhật!")
            else:
                is_replace = import_mode.startswith("🔄")
                stats = import_items_to_library(
                    combined_records,
                    replace_all=is_replace,
                    skip_duplicates=skip_dups,
                    sync_ips=sync_ips_opt,
                )
                st.session_state["lib_import_success_msg"] = (
                    f"✅ Đã cập nhật `{LIBRARY_FILE}` thành công! "
                    f"Thêm mới: **{stats['added']}** tài khoản | "
                    f"Bổ sung thông tin: **{stats['updated']}** | "
                    f"Bỏ qua trùng: **{stats['skipped']}** | "
                    f"Tổng thư viện hiện tại: **{stats['total']}** tài khoản (STT #1 ➔ #{stats['total']}). "
                    f"Tài khoản tạo tiếp theo sẽ tự động nối tiếp từ **STT #{stats['total'] + 1}**!"
                )
                st.rerun()

        if st.session_state.get("lib_import_success_msg"):
            st.success(st.session_state.pop("lib_import_success_msg"))


def render_library_section():
    """
    Hiển thị Thư viện các tài khoản đã tạo từ `thu_vien.json` (CHỈ NHÀ PHÁT TRIỂN XEM ĐƯỢC).
    """
    lib, lib_ver = load_library_from_disk()
    st.session_state.library = lib

    st.markdown(
        f"""
        <div class="library-card">
            <div class="library-header">
                📚 THƯ VIỆN TÀI KHOẢN (`{LIBRARY_FILE}` — {len(lib)} TÀI KHOẢN THEO STT 1 ➔ {len(lib)}) [DEVELOPER ONLY]
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not lib:
        st.markdown(
            f'<div class="library-empty">[LIBRARY EMPTY] Chưa có tài khoản nào trong {LIBRARY_FILE}.</div>',
            unsafe_allow_html=True,
        )
        return

    txt_export_bytes, json_export_bytes = _get_cached_export_payloads(lib_ver, len(lib))

    col_dl_txt, col_dl_json, col_clear = st.columns([1.2, 1.2, 1.2])
    with col_dl_txt:
        st.download_button(
            "⬇ TẢI TOÀN BỘ THƯ VIỆN (.TXT)",
            data=txt_export_bytes,
            file_name="thu_vien_nextdns.txt",
            mime="text/plain",
            use_container_width=True,
        )
    with col_dl_json:
        st.download_button(
            "⬇ TẢI FILE GỐC THU_VIEN.JSON",
            data=json_export_bytes,
            file_name=LIBRARY_FILE,
            mime="application/json",
            use_container_width=True,
        )
    with col_clear:
        if st.button(f"🗑️ XÓA SẠCH THƯ VIỆN ({len(lib)})", use_container_width=True):
            store = _get_shared_memory_store()
            with FILE_LOCK:
                store["library"].clear()
                store["used_emails"].clear()
                st.session_state.library = []
                _persist_library_locked(store)
            st.rerun()

    search_kw = st.text_input(
        "🔍 Tìm kiếm nhanh trong thư viện (theo STT, Tên, Mail, IP, hoặc Profile ID):",
        value="",
        placeholder="Nhập từ khóa cần tìm...",
        key="lib_search_kw",
    ).strip().lower()

    if search_kw:
        filtered_lib = [
            it for it in lib
            if search_kw == str(it.get("stt", "")).lower()
            or search_kw in f"stt {it.get('stt', '')}".lower()
            or search_kw in str(it.get("name", "")).lower()
            or search_kw in str(it.get("email", "")).lower()
            or search_kw in str(it.get("ip", "")).lower()
            or search_kw in str(it.get("pid", "")).lower()
        ]
    else:
        filtered_lib = lib

    page_size = 25
    total_items = len(filtered_lib)
    total_pages = max(1, (total_items + page_size - 1) // page_size)

    if total_pages > 1:
        current_page = st.number_input(
            f"📄 Trang hiển thị (Tổng {total_pages} trang - {total_items} kết quả):",
            min_value=1,
            max_value=total_pages,
            value=1,
            step=1,
        )
    else:
        current_page = 1

    start_idx = (current_page - 1) * page_size
    end_idx = start_idx + page_size
    page_slice = filtered_lib[start_idx:end_idx]

    preview_items = filtered_lib if len(filtered_lib) <= 200 else page_slice
    expander_label = (
        f"📋 XEM & COPY DANH SÁCH THƯ VIỆN ({len(preview_items)}/{len(filtered_lib)} MỤC ĐANG HIỂN THỊ)"
    )
    with st.expander(expander_label, expanded=True):
        if len(filtered_lib) > 200:
            st.caption(
                f"Đang hiển thị {len(page_slice)} tài khoản của Trang {current_page} để trình duyệt mượt nhất. "
                "Bấm nút '⬇ TẢI TOÀN BỘ THƯ VIỆN (.TXT)' phía trên để lấy trọn bộ danh sách."
            )
        st.code(format_library_text(preview_items), language="text")

    for idx, item in enumerate(page_slice, start=start_idx + 1):
        stt_num = item.get("stt", idx)
        name_esc = html.escape(str(item.get("name", "")))
        mail_esc = html.escape(str(item.get("email", "")))
        pass_esc = html.escape(str(item.get("password", "")))
        link_esc = html.escape(str(item.get("dns_link", "")))
        time_esc = html.escape(str(item.get("created_at", "")))
        ip_esc = html.escape(str(item.get("ip", "N/A")))

        st.markdown(
            f"""
            <div class="library-item">
                <div class="library-item-top">
                    <span><b>STT #{stt_num}</b> // {name_esc} <span style="opacity:0.75;">(IP: {ip_esc})</span></span>
                    <span class="library-time">{time_esc}</span>
                </div>
                <div class="library-pre">STT: {stt_num}
Tên: {name_esc}
Mail: {mail_esc}
Mật khẩu: {pass_esc}
Link dns: <a href="{link_esc}" target="_blank" style="color:#00ff41;text-decoration:underline;">{link_esc}</a></div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_ip_management_section():
    """Bảng quản lý IP đã dùng (CHỈ NHÀ PHÁT TRIỂN XEM ĐƯỢC)."""
    used_ips = load_used_ips()
    with st.expander(f"🛡️ QUẢN LÝ IP KHÁCH ĐÃ DÙNG ({len(used_ips)} IP) [DEVELOPER ONLY]"):
        if not used_ips:
            st.caption("Chưa có IP khách nào bị giới hạn.")
        else:
            col_reset_all, col_unlock_one = st.columns([1, 1])
            with col_reset_all:
                if st.button("🔓 RESET TOÀN BỘ GIỚI HẠN IP KHÁCH", use_container_width=True):
                    clear_all_used_ips()
                    st.success("Đã xóa toàn bộ danh sách IP giới hạn!")
                    st.rerun()
            with col_unlock_one:
                unlock_ip_input = st.text_input(
                    "Mở khóa riêng 1 IP:",
                    placeholder="Nhập IP cần mở khóa...",
                    key="unlock_single_ip_input",
                    label_visibility="collapsed",
                )
                if unlock_ip_input and st.button(f"Mở khóa IP {unlock_ip_input.strip()}", use_container_width=True):
                    delete_single_used_ip(unlock_ip_input.strip())
                    st.success(f"Đã mở khóa IP {unlock_ip_input.strip()}!")
                    st.rerun()

            ip_items = list(used_ips.items())[::-1]
            for ip_addr, info in ip_items[:50]:
                st.markdown(
                    f"- **IP:** `{ip_addr}` | **STT:** `#{info.get('stt', 'N/A')}` | **Tên:** `{info.get('name', 'N/A')}` | "
                    f"**Profile ID:** `{info.get('pid', 'N/A')}` | **Lúc:** `{info.get('created_at', '')}`"
                )
            if len(ip_items) > 50:
                st.caption(f"... và {len(ip_items) - 50} IP khác đã được lưu.")


# ==============================================================================
# GIAO DIỆN STREAMLIT + HTML PHONG CÁCH HACKER TERMINAL (SIÊU MƯỢT TRÊN IPHONE)
# ==============================================================================

st.set_page_config(
    page_title="NEXTDNS // HACKER CONSOLE",
    page_icon="💀",
    layout="centered",
    initial_sidebar_state="collapsed",
)

HACKER_HTML_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=JetBrains+Mono:wght@400;700&display=swap');

html, body, [data-testid="stAppViewContainer"], [data-testid="stHeader"] {
    background-color: #050805 !important;
    color: #00ff41 !important;
    font-family: 'JetBrains Mono', 'Share Tech Mono', monospace !important;
    -webkit-text-size-adjust: 100% !important;
}

/* Cho phép bôi đen copy ở các khung kết quả và ô nhập liệu trên iPhone & Máy tính */
input, textarea, code, pre, .result-val, .library-pre, a {
    -webkit-user-select: text !important;
    -moz-user-select: text !important;
    -ms-user-select: text !important;
    user-select: text !important;
}

/* Hiệu ứng màn hình CRT & lưới Hacker */
[data-testid="stAppViewContainer"] {
    background-image:
        radial-gradient(rgba(0, 255, 65, 0.07) 1px, transparent 0),
        linear-gradient(180deg, rgba(0, 20, 5, 0.95) 0%, rgba(2, 6, 2, 0.99) 100%) !important;
    background-size: 24px 24px, 100% 100% !important;
}

/* Ẩn triệt để toàn bộ thanh công cụ, nút View Source / GitHub / Manage App của Streamlit */
#MainMenu,
footer,
header,
[data-testid="stToolbar"],
[data-testid="stToolbarActions"],
[data-testid="stDecoration"],
[data-testid="stStatusWidget"],
[data-testid="stHeaderActionElements"],
[data-testid="manage-app-button"],
.stAppDeployButton,
.stDeployButton,
.viewerBadge_container__r5tak,
.viewerBadge_link__qRIco,
._profileContainer_gzau3_53,
._container_gzau3_1 {
    visibility: hidden !important;
    display: none !important;
    opacity: 0 !important;
    pointer-events: none !important;
}

.block-container {
    padding-top: 1.2rem !important;
    padding-bottom: 2.5rem !important;
    max-width: 820px !important;
}

/* Khung Header Hacker */
.cyber-header {
    border: 1px solid #00ff41;
    background: rgba(0, 20, 0, 0.78);
    box-shadow: 0 0 18px rgba(0, 255, 65, 0.25), inset 0 0 15px rgba(0, 255, 65, 0.08);
    padding: 16px 20px;
    border-radius: 6px;
    margin-bottom: 16px;
    position: relative;
    overflow: hidden;
}

.cyber-header::before {
    content: "ROOT@NEXTDNS-NODE:~# ./auto_signup_denylist.py --keep-alive";
    display: block;
    font-size: 0.74rem;
    color: #00b82e;
    letter-spacing: 1.2px;
    margin-bottom: 6px;
    border-bottom: 1px dashed rgba(0, 255, 65, 0.3);
    padding-bottom: 6px;
}

.cyber-title {
    font-size: 1.35rem;
    font-weight: 700;
    color: #00ff41;
    text-shadow: 0 0 10px rgba(0, 255, 65, 0.75);
    margin: 0;
    letter-spacing: 1px;
}

.cyber-sub {
    font-size: 0.84rem;
    color: #7aff9e;
    margin-top: 6px;
    opacity: 0.9;
}

/* Badge trạng thái Chế độ & IP */
.mode-banner {
    border: 1px solid rgba(0, 255, 65, 0.55);
    background: rgba(0, 16, 4, 0.88);
    border-radius: 6px;
    padding: 10px 14px;
    margin-bottom: 14px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 0.82rem;
    flex-wrap: wrap;
    gap: 8px;
}

.mode-badge-dev {
    color: #020802;
    background: #00ff41;
    font-weight: 700;
    padding: 3px 9px;
    border-radius: 4px;
    box-shadow: 0 0 10px rgba(0, 255, 65, 0.7);
}

.mode-badge-guest {
    color: #00ff41;
    border: 1px solid #00ff41;
    font-weight: 700;
    padding: 3px 9px;
    border-radius: 4px;
}

/* Danh sách 9 domain mục tiêu */
.domain-box {
    border: 1px solid rgba(0, 255, 65, 0.45);
    background: rgba(0, 12, 0, 0.85);
    border-radius: 6px;
    padding: 12px 16px;
    margin-bottom: 16px;
}

.domain-box-title {
    font-size: 0.8rem;
    color: #00ff41;
    font-weight: 700;
    margin-bottom: 8px;
    text-transform: uppercase;
    letter-spacing: 1px;
}

.domain-chips {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
}

.domain-chip {
    font-size: 0.75rem;
    color: #00ff41;
    background: rgba(0, 255, 65, 0.08);
    border: 1px solid rgba(0, 255, 65, 0.4);
    padding: 3px 8px;
    border-radius: 4px;
}

/* Ô nhập Tên & Mật khẩu: BẮT BUỘC font-size >= 16px để Safari trên iPhone KHÔNG tự động zoom màn hình */
div[data-testid="stTextInput"] label, div[data-testid="stRadio"] label, div[data-testid="stNumberInput"] label {
    color: #00ff41 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-weight: 700 !important;
    font-size: 0.88rem !important;
    letter-spacing: 0.8px !important;
}

div[data-testid="stTextInput"] input, div[data-testid="stNumberInput"] input {
    background-color: #020c04 !important;
    color: #00ff41 !important;
    border: 1px solid #00ff41 !important;
    border-radius: 5px !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 16px !important;
    line-height: 1.4 !important;
    padding: 0.55rem 0.8rem !important;
    box-shadow: inset 0 0 8px rgba(0, 255, 65, 0.15) !important;
}

div[data-testid="stTextInput"] input:focus, div[data-testid="stNumberInput"] input:focus, div[data-testid="stTextArea"] textarea:focus {
    box-shadow: 0 0 12px rgba(0, 255, 65, 0.55), inset 0 0 8px rgba(0, 255, 65, 0.25) !important;
    outline: none !important;
}

div[data-testid="stTextArea"] label, div[data-testid="stFileUploader"] label, div[data-testid="stCheckbox"] label {
    color: #00ff41 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-weight: 700 !important;
    font-size: 0.88rem !important;
    letter-spacing: 0.6px !important;
}

div[data-testid="stTextArea"] textarea {
    background-color: #020c04 !important;
    color: #00ff41 !important;
    border: 1px solid #00ff41 !important;
    border-radius: 5px !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 16px !important;
    line-height: 1.45 !important;
    padding: 0.6rem 0.8rem !important;
    box-shadow: inset 0 0 8px rgba(0, 255, 65, 0.15) !important;
}

div[data-testid="stFileUploader"] section {
    background-color: rgba(2, 14, 4, 0.9) !important;
    border: 1px dashed #00ff41 !important;
    border-radius: 6px !important;
    color: #00ff41 !important;
}

/* Nút bấm Streamlit phong cách Hacker */
div.stButton > button, div[data-testid="stDownloadButton"] > button {
    width: 100%;
    background: #001a05 !important;
    color: #00ff41 !important;
    border: 1.5px solid #00ff41 !important;
    border-radius: 5px !important;
    padding: 0.72rem 1rem !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.92rem !important;
    font-weight: 700 !important;
    letter-spacing: 1px !important;
    text-transform: uppercase !important;
    box-shadow: 0 0 14px rgba(0, 255, 65, 0.3) !important;
    transition: all 0.15s ease-in-out !important;
    touch-action: manipulation !important;
}

div.stButton > button:hover, div[data-testid="stDownloadButton"] > button:hover {
    background: #00ff41 !important;
    color: #020802 !important;
    box-shadow: 0 0 25px rgba(0, 255, 65, 0.85) !important;
}

/* Cửa sổ Terminal Console */
.terminal-window {
    border: 1px solid #00ff41;
    border-radius: 6px;
    background: #020502;
    box-shadow: 0 0 20px rgba(0, 255, 65, 0.18);
    margin-top: 14px;
    overflow: hidden;
}

.terminal-bar {
    background: #071f0b;
    border-bottom: 1px solid rgba(0, 255, 65, 0.4);
    padding: 7px 14px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-size: 0.75rem;
    color: #6eff94;
}

.terminal-dots span {
    display: inline-block;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    margin-right: 5px;
}

.dot-red { background: #ff3b30; }
.dot-yellow { background: #ffcc00; }
.dot-green { background: #00ff41; box-shadow: 0 0 6px #00ff41; }

.terminal-body {
    padding: 14px 16px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
    line-height: 1.55;
    color: #00ff41;
    max-height: 360px;
    overflow-y: auto;
    white-space: pre-wrap;
    word-break: break-all;
}

.log-line-ok { color: #00ff41; font-weight: 700; text-shadow: 0 0 6px rgba(0, 255, 65, 0.5); }
.log-line-warn { color: #ff5555; }
.log-line-info { color: #66ff99; }

/* Bảng kết quả sau khi tạo thành công (Tối ưu hiển thị trên màn hình dọc iPhone) */
.result-card {
    border: 1px solid #00ff41;
    background: rgba(0, 24, 6, 0.92);
    border-radius: 6px;
    padding: 16px 18px;
    margin-top: 14px;
    box-shadow: 0 0 22px rgba(0, 255, 65, 0.28);
}

.result-header {
    font-size: 0.96rem;
    font-weight: 700;
    color: #00ff41;
    border-bottom: 1px dashed rgba(0, 255, 65, 0.45);
    padding-bottom: 8px;
    margin-bottom: 12px;
    text-shadow: 0 0 8px rgba(0, 255, 65, 0.6);
}

.result-grid {
    display: grid;
    grid-template-columns: 155px 1fr;
    gap: 7px 10px;
    font-size: 0.82rem;
    margin-bottom: 14px;
}

@media (max-width: 540px) {
    .result-grid {
        grid-template-columns: 1fr;
        gap: 4px;
    }
    .result-label {
        margin-top: 4px;
        font-weight: 700;
    }
}

.result-label {
    color: #7aff9e;
    opacity: 0.85;
}

.result-val {
    color: #ffffff;
    background: rgba(0, 255, 65, 0.1);
    border: 1px solid rgba(0, 255, 65, 0.35);
    padding: 5px 9px;
    border-radius: 4px;
    word-break: break-all;
}

.action-links {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-top: 12px;
}

.cyber-btn-link {
    flex: 1;
    min-width: 210px;
    text-align: center;
    text-decoration: none !important;
    background: #00ff41;
    color: #020802 !important;
    font-weight: 700;
    font-size: 0.86rem;
    padding: 11px 14px;
    border-radius: 5px;
    box-shadow: 0 0 14px rgba(0, 255, 65, 0.6);
    transition: all 0.15s ease;
    touch-action: manipulation;
}

.cyber-btn-link.secondary {
    background: transparent;
    color: #00ff41 !important;
    border: 1px solid #00ff41;
    box-shadow: none;
}

.cyber-btn-link:hover {
    filter: brightness(1.15);
    box-shadow: 0 0 20px rgba(0, 255, 65, 0.95);
}

.ios-guide-box {
    margin-top: 12px;
    border-top: 1px dashed rgba(0, 255, 65, 0.35);
    padding-top: 10px;
    font-size: 0.79rem;
    color: #9effb8;
    line-height: 1.55;
}

/* Cảnh báo giới hạn IP & Cảnh báo In-App Browser trên iPhone */
.ip-limit-box {
    border: 1px solid #ff5555;
    background: rgba(40, 0, 0, 0.78);
    color: #ffaaaa;
    border-radius: 6px;
    padding: 12px 16px;
    margin-top: 10px;
    margin-bottom: 12px;
    font-size: 0.84rem;
    line-height: 1.5;
}

.ios-safari-warn {
    border: 1.5px solid #ffcc00;
    background: rgba(45, 32, 0, 0.88);
    color: #ffe580;
    border-radius: 6px;
    padding: 12px 16px;
    margin-bottom: 14px;
    font-size: 0.84rem;
    line-height: 1.5;
}

/* Khung xác thực IP của khách */
.ip-verify-box {
    border: 1px dashed #00ff41;
    background: rgba(0, 22, 6, 0.82);
    color: #7aff9e;
    border-radius: 6px;
    padding: 12px 16px;
    margin-top: 8px;
    margin-bottom: 14px;
    font-size: 0.84rem;
    line-height: 1.5;
}

/* Khung Thư viện tài khoản */
.library-card {
    border: 1px solid #00ff41;
    background: rgba(0, 18, 4, 0.9);
    border-radius: 6px;
    padding: 12px 16px;
    margin-top: 24px;
    margin-bottom: 10px;
    box-shadow: 0 0 16px rgba(0, 255, 65, 0.2);
}

.library-header {
    font-size: 0.94rem;
    font-weight: 700;
    color: #00ff41;
    letter-spacing: 1px;
    text-shadow: 0 0 8px rgba(0, 255, 65, 0.55);
}

.library-empty {
    border: 1px dashed rgba(0, 255, 65, 0.35);
    background: rgba(0, 10, 2, 0.7);
    border-radius: 6px;
    padding: 14px;
    font-size: 0.82rem;
    color: #7aff9e;
    text-align: center;
    margin-bottom: 14px;
}

.library-item {
    border: 1px solid rgba(0, 255, 65, 0.45);
    background: rgba(2, 12, 4, 0.92);
    border-radius: 6px;
    padding: 12px 15px;
    margin-bottom: 10px;
    box-shadow: inset 0 0 10px rgba(0, 255, 65, 0.06);
}

.library-item-top {
    display: flex;
    justify-content: space-between;
    font-size: 0.78rem;
    color: #7aff9e;
    border-bottom: 1px dashed rgba(0, 255, 65, 0.25);
    padding-bottom: 5px;
    margin-bottom: 8px;
    flex-wrap: wrap;
    gap: 4px;
}

.library-time {
    opacity: 0.75;
}

.library-pre {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.83rem;
    line-height: 1.6;
    color: #ffffff;
    white-space: pre-wrap;
    word-break: break-all;
}
</style>
"""


def render_terminal_html(logs: list[str], status_text: str = "IDLE") -> str:
    if not logs:
        body_html = (
            '<span class="log-line-info">[SYSTEM] Sẵn sàng thực thi. '
            'Nhập tên và nhấn nút [⚡ EXECUTE: TẠO TÀI KHOẢN NEXTDNS &amp; CHẶN 9 DOMAIN] bên trên...</span>'
        )
    else:
        formatted_lines = []
        for line in logs:
            esc = html.escape(line)
            if "[SUCCESS]" in line or "[+]" in line or "====" in line:
                formatted_lines.append(f'<div class="log-line-ok">{esc}</div>')
            elif "[!]" in line:
                formatted_lines.append(f'<div class="log-line-warn">{esc}</div>')
            else:
                formatted_lines.append(f'<div class="log-line-info">{esc}</div>')
        body_html = "".join(formatted_lines)

    return f"""
    <div class="terminal-window">
        <div class="terminal-bar">
            <div class="terminal-dots">
                <span class="dot-red"></span>
                <span class="dot-yellow"></span>
                <span class="dot-green"></span>
                <span style="margin-left:6px;">bash — nextdns_keepalive_engine.py</span>
            </div>
            <div>STATUS: <b>{html.escape(status_text)}</b></div>
        </div>
        <div class="terminal-body">{body_html}</div>
    </div>
    """


def parse_credentials_from_logs(logs: list[str]) -> tuple[str, str, str]:
    """Hàm dự phòng đọc thông tin từ log nếu cần."""
    email_val, pass_val, blocked_val = "N/A", "N/A", "9/9"
    for line in logs:
        if "Email đăng nhập Web :" in line:
            email_val = line.split("Email đăng nhập Web :", 1)[1].strip()
        elif "Mật khẩu đăng nhập  :" in line:
            pass_val = line.split("Mật khẩu đăng nhập  :", 1)[1].strip()
        elif "CHẶN " in line and " DOMAIN" in line:
            m = re.search(r"CHẶN(?:\s+ĐỦ)?\s+(\d+/\d+)\s+DOMAIN", line)
            if m:
                blocked_val = m.group(1)
    return email_val, pass_val, blocked_val


def render_guest_dns_card(res: dict, current_session_token: str = ""):
    """
    Hiển thị kết quả SIÊU MƯỢT cho CHẾ ĐỘ KHÁCH:
    - Bảo mật tên khách giữa các phiên khác nhau dùng chung Wi-Fi (`session_token`).
    - Hiển thị rõ trạng thái `ĐÃ CHẶN ĐỦ 9/9 DOMAIN` và hướng dẫn cài đặt nhanh trên iPhone.
    - Nút `.mobileconfig` dùng `target="_top"` bật hộp thoại cài đặt cấu hình iOS ngay lập tức.
    """
    saved_token = str(res.get("cid", ""))
    is_same_session = (
        bool(saved_token and current_session_token and saved_token == current_session_token)
        or st.session_state.get("my_created_pid") == res.get("pid")
    )

    raw_name = str(res.get("name", "N/A"))
    display_name = raw_name if is_same_session else f"{raw_name[:2]}*** (Đồng bộ theo IP)"
    name_esc = html.escape(display_name)
    ip_esc = html.escape(str(res.get("ip", "N/A")))
    blocked_esc = html.escape(str(res.get("blocked", "9/9")))
    apple_link_esc = html.escape(str(res.get("apple_web_link", "")))
    mc_link_esc = html.escape(str(res.get("direct_mc_link", "")))

    st.markdown(
        f"""
        <div class="result-card">
            <div class="result-header">
                ✅ [DNS PROFILE READY] HỒ SƠ CỦA: {name_esc}
            </div>
            <div class="result-grid">
                <div class="result-label">• Tên hồ sơ:</div>
                <div class="result-val">{name_esc}</div>
                <div class="result-label">• Trạng thái Denylist:</div>
                <div class="result-val" style="color:#00ff41;font-weight:700;">ĐÃ CHẶN ĐỦ {blocked_esc} DOMAIN CHUẨN ✅</div>
                <div class="result-label">• IP đã cố định:</div>
                <div class="result-val">{ip_esc} (1 Lần / IP)</div>
                <div class="result-label">• Link Profile DNS:</div>
                <div class="result-val">
                    <a href="{apple_link_esc}" target="_blank" rel="noopener" style="color:#00ff41;text-decoration:underline;">
                        {apple_link_esc}
                    </a>
                </div>
            </div>
            <div class="action-links">
                <a class="cyber-btn-link" href="{mc_link_esc}" target="_top">
                    ⬇ TẢI CẤU HÌNH DNS (.MOBILECONFIG)
                </a>
                <a class="cyber-btn-link secondary" href="{apple_link_esc}" target="_blank" rel="noopener">
                    🔗 MỞ TRANG APPLE NEXTDNS
                </a>
            </div>
            <div class="ios-guide-box">
                📲 <b>Hướng dẫn cài nhanh trên iPhone/iPad (Safari):</b> Bấm nút <b>⬇ TẢI CẤU HÌNH DNS (.MOBILECONFIG)</b> ở trên ➔ Chọn <b>Cho phép (Allow)</b> ➔ Mở <b>Cài đặt (Settings)</b> ➔ Bấm <b>Đã tải về hồ sơ (Profile Downloaded)</b> ➔ Bấm <b>Cài đặt (Install)</b> là hoàn tất!
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_dev_result_card(res: dict):
    """
    Hiển thị đầy đủ 100% thông tin cho CHẾ ĐỘ NHÀ PHÁT TRIỂN.
    Nút tải `.mobileconfig` dùng `target="_top"` tương thích trực tiếp với Safari trên iPhone.
    """
    stt_val = html.escape(str(res.get("stt", "N/A")))
    st.markdown(
        f"""
        <div class="result-card">
            <div class="result-header">
                [ACCESS GRANTED // STT #{stt_val}] PROFILE ID: {html.escape(res['pid'])} — ĐÃ CHẶN {html.escape(res['blocked'])} DOMAIN
            </div>
            <div class="result-grid">
                <div class="result-label">• Số thứ tự Thư viện:</div>
                <div class="result-val">#{stt_val}</div>
                <div class="result-label">• Tên:</div>
                <div class="result-val">{html.escape(res.get('name', 'N/A'))}</div>
                <div class="result-label">• Email đăng nhập:</div>
                <div class="result-val">{html.escape(res['email'])}</div>
                <div class="result-label">• Mật khẩu:</div>
                <div class="result-val">{html.escape(res['password'])}</div>
                <div class="result-label">• Profile ID:</div>
                <div class="result-val">{html.escape(res['pid'])}</div>
                <div class="result-label">• Link Profile DNS:</div>
                <div class="result-val">{html.escape(res['apple_web_link'])}</div>
                <div class="result-label">• DNS-over-HTTPS:</div>
                <div class="result-val">{html.escape(res['doh_link'])}</div>
            </div>
            <div class="action-links">
                <a class="cyber-btn-link" href="{html.escape(res['direct_mc_link'])}" target="_top">
                    ⬇ TẢI FILE .MOBILECONFIG
                </a>
                <a class="cyber-btn-link secondary" href="{html.escape(res['apple_web_link'])}" target="_blank" rel="noopener">
                    MỞ TRANG APPLE NEXTDNS
                </a>
                <a class="cyber-btn-link secondary" href="https://my.nextdns.io/login" target="_blank" rel="noopener">
                    🔐 ĐĂNG NHẬP MY.NEXTDNS.IO
                </a>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def main():
    st.markdown(HACKER_HTML_CSS, unsafe_allow_html=True)

    if "logs" not in st.session_state:
        st.session_state.logs = []
    if "last_result" not in st.session_state:
        st.session_state.last_result = None
    if "is_developer" not in st.session_state:
        st.session_state.is_developer = False

    # Nhúng khiên bảo vệ giao diện (Đã tối ưu cho cả cảm ứng iPhone và copy trên Desktop)
    inject_anti_inspect_protection()

    # Kiểm tra nếu người dùng mở link trong Zalo / Messenger / TikTok trên iPhone
    in_app_name = detect_ios_in_app_browser()
    if in_app_name:
        st.markdown(
            f"""
            <div class="ios-safari-warn">
                📱 <b>PHÁT HIỆN TRÌNH DUYỆT TRONG ỨNG DỤNG ({html.escape(in_app_name)}):</b><br>
                Trên iPhone, trình duyệt nhúng của <b>{html.escape(in_app_name)}</b> sẽ chặn tải cấu hình <code>.mobileconfig</code>.
                Vui lòng bấm vào biểu tượng <b>•••</b> (hoặc nút Chia sẻ ở góc màn hình) và chọn <b>"Mở bằng trình duyệt Safari"</b> để tải và cài đặt DNS mượt mà!
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Lấy IP thật của khách trực tiếp từ Server Header (0ms, không reload)
    client_ip, session_token, _ = get_verified_client_identity()
    used_ips = load_used_ips()

    # Tự động dọn các IP loopback/private/GCP-LB lỗi hoặc các mã ID_xxxx/fp_xxxx/SESSION_xxxx cũ từng gây chặn nhầm
    store_ref = _get_shared_memory_store()
    if not store_ref.get("cleaned_legacy_ips"):
        with FILE_LOCK:
            removed_any = False
            for bad_ip in list(store_ref["used_ips"].keys()):
                if _is_bogus_private_or_loopback_ip(bad_ip):
                    store_ref["used_ips"].pop(bad_ip, None)
                    removed_any = True
            store_ref["cleaned_legacy_ips"] = True
            if removed_any:
                _persist_used_ips_locked(store_ref)
        used_ips = load_used_ips()

    # Header Hacker
    st.markdown(
        """
        <div class="cyber-header">
            <div class="cyber-title">💀 NEXTDNS // AUTO-SIGNUP &amp; DNS CONSOLE</div>
            <div class="cyber-sub">
                Hệ thống tự động khởi tạo hồ sơ cấu hình NextDNS (Engine Keep-Alive TLS siêu mượt).
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ==========================================================================
    # CHỌN CHẾ ĐỘ: CHẾ ĐỘ KHÁCH / CHẾ ĐỘ NHÀ PHÁT TRIỂN (CHỐNG BRUTE-FORCE CẤP SERVER)
    # ==========================================================================
    col_mode, col_auth = st.columns([1.2, 1.8])
    with col_mode:
        mode_choice = st.radio(
            "🔐 CHỌN CHẾ ĐỘ TRUY CẬP:",
            options=["👤 Chế độ Khách", "🛠️ Chế độ Nhà phát triển"],
            index=1 if st.session_state.is_developer else 0,
            key="mode_selector",
        )

    is_dev_active = False
    with col_auth:
        if mode_choice == "🛠️ Chế độ Nhà phát triển":
            is_locked, remain_sec, _ = check_and_record_dev_login(client_ip, check_only=True)
            if st.session_state.is_developer:
                is_dev_active = True
                st.success("Đã mở khóa Chế độ Nhà phát triển!")
                if st.button("🔒 Khóa / Đăng xuất Developer", key="logout_dev_btn", use_container_width=True):
                    st.session_state.is_developer = False
                    st.session_state.pop("dev_password_input", None)
                    st.rerun()
            elif is_locked:
                st.error(f"Nhập sai quá {MAX_DEV_LOGIN_ATTEMPTS} lần! Vui lòng đợi {remain_sec} giây rồi thử lại.")
            else:
                dev_pwd = st.text_input(
                    "🔑 NHẬP MẬT KHẨU NHÀ PHÁT TRIỂN:",
                    type="password",
                    placeholder="Nhập mật khẩu developer...",
                    key="dev_password_input",
                )
                if dev_pwd:
                    if verify_dev_password(dev_pwd):
                        check_and_record_dev_login(client_ip, is_success=True)
                        st.session_state.is_developer = True
                        st.session_state.pop("dev_password_input", None)
                        is_dev_active = True
                        st.rerun()
                    else:
                        locked_now, lock_sec, left = check_and_record_dev_login(client_ip, is_success=False)
                        if locked_now:
                            st.error(f"Đã khóa tạm thời {lock_sec} giây do nhập sai nhiều lần!")
                        else:
                            st.error(f"Mật khẩu không chính xác! (Còn {left} lần thử)")
                else:
                    st.info("Vui lòng nhập mật khẩu để mở khóa tính năng.")
        else:
            is_dev_active = False

    # Thanh trạng thái Mode & IP hiện tại
    badge_html = (
        '<span class="mode-badge-dev">🛠️ DEVELOPER MODE (UNLIMITED)</span>'
        if is_dev_active
        else '<span class="mode-badge-guest">👤 GUEST MODE (1 LẦN / IP CỐ ĐỊNH)</span>'
    )
    ip_status_badge = f"<b>{html.escape(client_ip)}</b> ✅"
    st.markdown(
        f"""
        <div class="mode-banner">
            <div>TRẠNG THÁI: {badge_html}</div>
            <div>IP XÁC THỰC: {ip_status_badge}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if mode_choice == "🛠️ Chế độ Nhà phát triển" and not is_dev_active:
        return

    # ==========================================================================
    # 1. CHẾ ĐỘ KHÁCH (ƯU TIÊN ĐỘ MƯỢT TUYỆT ĐỐI & ĐẢM BẢO CHẶN ĐỦ 9/9 DOMAIN)
    # ==========================================================================
    if not is_dev_active:
        existing_ip_record = find_existing_guest_record(used_ips, client_ip)

        if existing_ip_record:
            st.markdown(
                f"""
                <div class="ip-limit-box">
                    ⚠️ <b>ĐÃ CỐ ĐỊNH 1 LẦN SỬ DỤNG CHO IP NÀY:</b> Địa chỉ IP <b>{html.escape(client_ip)}</b>
                    đã được xác nhận và sử dụng lượt tạo miễn phí (Mỗi IP chỉ được tạo cố định 1 lần duy nhất).
                    Dưới đây là hồ sơ DNS cố định của bạn:
                </div>
                """,
                unsafe_allow_html=True,
            )
            render_guest_dns_card(existing_ip_record, current_session_token=session_token)
            return

        st.markdown(
            f"""
            <div class="ip-verify-box">
                🛡️ <b>XÁC NHẬN IP HỢP LỆ:</b> IP <b>{html.escape(client_ip)}</b> của bạn chưa sử dụng lượt tạo nào.
                Sau khi bấm tạo, hệ thống sẽ <b>khóa cố định chính xác IP này (1 lần sử dụng duy nhất)</b> khi đã chặn đủ 9/9 domain chuẩn.
            </div>
            """,
            unsafe_allow_html=True,
        )

        customer_name = input_customer_name()
        run_guest_clicked = st.button(f"⚡ XÁC NHẬN IP ({client_ip}) & TẠO LINK PROFILE DNS (1 LẦN DUY NHẤT)")

        if run_guest_clicked:
            acquired, reason = try_acquire_ip_slot(client_ip)
            if not acquired:
                if reason == "ALREADY_USED":
                    st.rerun()
                else:
                    st.warning("Hệ thống đang khởi tạo hồ sơ cho IP của bạn ở một tab khác, vui lòng đợi trong giây lát...")
                    return

            try:
                with st.spinner(f"Đang khởi tạo Link Profile DNS & chặn đủ 9/9 domain cho IP {client_ip}, vui lòng đợi 1-2 giây..."):
                    def _guest_coro(cb):
                        return create_profile(log_callback=cb)

                    pid, apple_web_link, meta = _run_async_with_live_logs(
                        _guest_coro,
                        on_log_line=None,
                    )

                    if pid and apple_web_link:
                        email_val = meta.get("email", "N/A")
                        pass_val = meta.get("password", "N/A")
                        blocked_val = meta.get("blocked", "9/9")
                        direct_mc_link = meta.get("direct_mc_link") or f"https://api.nextdns.io/apple/profile?profile={pid}&sign=1"
                        doh_link = meta.get("doh_link") or f"https://dns.nextdns.io/{pid}"

                        saved_item = push_to_library(
                            name=customer_name,
                            email=email_val,
                            password=pass_val,
                            dns_link=apple_web_link,
                            pid=pid,
                            doh_link=doh_link,
                            ip=client_ip,
                        )

                        result_data = {
                            "stt": saved_item.get("stt", 1),
                            "name": customer_name,
                            "pid": pid,
                            "email": email_val,
                            "password": pass_val,
                            "blocked": blocked_val,
                            "apple_web_link": apple_web_link,
                            "direct_mc_link": direct_mc_link,
                            "doh_link": doh_link,
                            "ip": client_ip,
                            "cid": session_token,
                            "created_at": saved_item.get("created_at", time.strftime("%Y-%m-%d %H:%M:%S")),
                        }

                        save_used_ip(client_ip, result_data)
                        st.session_state["my_created_pid"] = pid
                        st.session_state.last_result = result_data
                        st.rerun()
                    else:
                        release_ip_slot(client_ip)
                        if meta.get("reason") == "SERVER_BUSY":
                            st.warning("Hiện đang có nhiều người tạo cùng lúc. IP của bạn CHƯA bị tính lượt, vui lòng bấm lại sau 3 giây!")
                        else:
                            st.error("Máy chủ NextDNS đang bận tạm thời (IP của bạn CHƯA bị trừ lượt). Vui lòng đợi 10 giây rồi bấm thử lại!")
            except Exception:
                release_ip_slot(client_ip)
                raise
        return

    # ==========================================================================
    # 2. CHẾ ĐỘ NHÀ PHÁT TRIỂN (LOG TRỰC TIẾP REAL-TIME & QUẢN LÝ KHO TÀI KHOẢN)
    # ==========================================================================
    chips_html = "".join(f'<span class="domain-chip">{html.escape(d)}</span>' for d in DENYLIST_9_DOMAINS)
    st.markdown(
        f"""
        <div class="domain-box">
            <div class="domain-box-title">[TARGET] 9 DOMAIN DENYLIST CHUẨN:</div>
            <div class="domain-chips">{chips_html}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    customer_name = input_customer_name()
    run_clicked = st.button("⚡ EXECUTE: TẠO TÀI KHOẢN NEXTDNS & CHẶN 9 DOMAIN")

    terminal_placeholder = st.empty()

    if run_clicked:
        st.session_state.logs = []
        st.session_state.last_result = None
        local_logs: list[str] = []

        def _append_and_stream_ui(msg: str):
            timestamp = time.strftime("%H:%M:%S")
            local_logs.append(f"[{timestamp}] {msg}")
            terminal_placeholder.markdown(
                render_terminal_html(local_logs, status_text="RUNNING..."),
                unsafe_allow_html=True,
            )

        _append_and_stream_ui(f"[*] Tên hồ sơ / khách hàng đã nhận: {customer_name}")

        def _dev_coro(cb):
            return create_profile(log_callback=cb)

        pid, apple_web_link, meta = _run_async_with_live_logs(_dev_coro, on_log_line=_append_and_stream_ui)
        st.session_state.logs = list(local_logs)

        if pid and apple_web_link:
            email_val = meta.get("email") or parse_credentials_from_logs(st.session_state.logs)[0]
            pass_val = meta.get("password") or parse_credentials_from_logs(st.session_state.logs)[1]
            blocked_val = meta.get("blocked") or parse_credentials_from_logs(st.session_state.logs)[2]
            direct_mc_link = meta.get("direct_mc_link") or f"https://api.nextdns.io/apple/profile?profile={pid}&sign=1"
            doh_link = meta.get("doh_link") or f"https://dns.nextdns.io/{pid}"

            saved_item = push_to_library(
                name=customer_name,
                email=email_val,
                password=pass_val,
                dns_link=apple_web_link,
                pid=pid,
                doh_link=doh_link,
                ip=client_ip,
            )

            st.session_state.last_result = {
                "stt": saved_item.get("stt", 1),
                "name": customer_name,
                "pid": pid,
                "email": email_val,
                "password": pass_val,
                "blocked": blocked_val,
                "apple_web_link": apple_web_link,
                "direct_mc_link": direct_mc_link,
                "doh_link": doh_link,
            }

            timestamp = time.strftime("%H:%M:%S")
            st.session_state.logs.append(
                f"[{timestamp}] [+] Đã bắn tài khoản của '{customer_name}' vào {LIBRARY_FILE} thành công! (STT #{saved_item.get('stt', 1)})"
            )

            terminal_placeholder.markdown(
                render_terminal_html(st.session_state.logs, status_text="COMPLETED [OK]"),
                unsafe_allow_html=True,
            )
        else:
            terminal_placeholder.markdown(
                render_terminal_html(st.session_state.logs, status_text="FAILED [!]"),
                unsafe_allow_html=True,
            )
    else:
        status_label = "COMPLETED [OK]" if st.session_state.last_result else "STANDBY"
        terminal_placeholder.markdown(
            render_terminal_html(st.session_state.logs, status_text=status_label),
            unsafe_allow_html=True,
        )

    if st.session_state.last_result:
        render_dev_result_card(st.session_state.last_result)

    # Quản lý IP khách, Khôi phục/Gộp file .json & Thư viện tài khoản (Chỉ Nhà phát triển mới thấy)
    render_ip_management_section()
    render_library_import_section()
    render_library_section()


if __name__ == "__main__":
    main()
