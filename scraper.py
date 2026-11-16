import html
import json
import os
import re
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ==============================================================================
# 1. CẤU HÌNH HỆ THỐNG & DỌN DẸP BỘ NHỚ
# ==============================================================================
STATE_FILE = Path("sent_deals.json")
REQUEST_TIMEOUT = 15
MAX_WORKERS = 12

# Tự động xóa tin nhắn Telegram sau 47 giờ (Telegram Bot API giới hạn xóa dưới 48 giờ)
AUTO_DELETE_HOURS = 47
# Tự động xóa lịch sử link cũ quá 14 ngày trong sent_deals.json để giữ repo nhẹ
RETENTION_DAYS = 14

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json,*/*;q=0.8",
    "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.8,de-DE;q=0.7",
}

HOT_DEAL_KEYWORDS = (
    "mua 1 tặng 1", "mua 1 được 2", "mua 2 tặng 1", "miễn phí", "free", "0đ", "0 đồng",
    "đồng giá", "nửa giá", "1/2 giá", "flash sale", "black friday", "siêu sale",
    "giảm sốc", "deal sốc", "xả kho", "tặng vé", "tặng quà", "voucher", "coupon",
    "buffet", "cửu vân long", "gogi", "kichi", "manwah", "dookki", "hotpot",
    "u22", "hssv", "sinh viên", "lifetime", "student", "nitro", "spotify",
    "netflix", "youtube", "gemini", "chatgpt", "perplexity", "copilot", "pro", "plus",
    "domain", "1€", "0,07€", "$0", "$1", "99 cent", "giveaway", "100% off",
)


def create_resilient_session() -> requests.Session:
    """Khởi tạo HTTP Session có cơ chế tự động Retry khi mạng chập chờn hoặc gặp lỗi 5xx/429."""
    session = requests.Session()
    session.headers.update(HEADERS)
    retry_strategy = Retry(
        total=2,
        backoff_factor=0.6,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=20, pool_maxsize=20)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


# ==============================================================================
# 2. QUẢN LÝ TRẠNG THÁI (STATE & AUTO-PRUNE)
# ==============================================================================
def load_state() -> Dict:
    """Đọc trạng thái từ sent_deals.json (tự động tương thích cả định dạng mảng [] cũ)."""
    default_state = {"deals": {}, "messages": []}
    if not STATE_FILE.exists():
        return default_state
    try:
        raw = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        if isinstance(raw, list):
            now = int(time.time())
            return {"deals": {url: now for url in raw if isinstance(url, str)}, "messages": []}
        if isinstance(raw, dict):
            return {
                "deals": raw.get("deals", {}) if isinstance(raw.get("deals"), dict) else {},
                "messages": raw.get("messages", []) if isinstance(raw.get("messages"), list) else [],
            }
    except Exception as exc:
        print(f"[WARN] Không đọc được {STATE_FILE}: {exc}")
    return default_state


def save_state(state: Dict) -> None:
    """Xóa các deal đã lưu quá RETENTION_DAYS ngày và ghi xuống sent_deals.json."""
    cutoff = int(time.time()) - RETENTION_DAYS * 86400
    state["deals"] = {
        url: ts
        for url, ts in state.get("deals", {}).items()
        if isinstance(ts, (int, float)) and ts >= cutoff
    }
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


# ==============================================================================
# 3. XỬ LÝ TEXT, BỘ LỌC >= 20% & BÓC TÁCH TÓM TẮT CHI TIẾT
# ==============================================================================
def clean_text(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def strip_layout_chrome(soup: BeautifulSoup) -> BeautifulSoup:
    for tag in soup(["header", "nav", "footer", "aside", "script", "style", "noscript", "form", "svg"]):
        tag.decompose()
    return soup


def is_hot_deal_20_plus(title: str, url: str = "") -> bool:
    """Lọc các chương trình giảm từ 20% trở lên, giảm >= 50K, hoặc từ khóa Free / Mua 1 tặng 1 / Pro."""
    combined = f"{title} {url}".lower()
    pct_matches = [int(m) for m in re.findall(r"(\d{1,3})\s*(?:%|phan-tram|phantram|off)", combined)]
    if pct_matches:
        return max(pct_matches) >= 20
    money_k = [int(m) for m in re.findall(r"(?:giảm|tặng|voucher|coupon|ưu đãi|hoàn)\s*(\d{2,4})\s*k\b", combined)]
    if money_k and max(money_k) >= 50:
        return True
    if re.search(r"(?:giảm|tặng|voucher|ưu đãi)\s*(?:đến\s*)?\d+\s*(?:triệu|tr\b)", combined):
        return True
    return any(kw in combined for kw in HOT_DEAL_KEYWORDS)


def extract_title_from_anchor(a_tag) -> str:
    heading = a_tag.find(["h1", "h2", "h3", "h4", "h5"])
    if heading:
        return clean_text(heading.get_text())
    img = a_tag.find("img")
    title = clean_text(a_tag.get("title") or (img.get("alt") if img else "") or a_tag.get_text())
    generic_labels = {
        "chi tiết", "xem thêm", "xem tất cả", "khám phá ngay",
        "read more", "view deal", "mua ngay", "đặt ngay", "khuyến mãi", "get deal",
    }
    if not title or title.lower() in generic_labels:
        parent = a_tag.find_parent(["article", "div", "li", "section"])
        if parent:
            parent_heading = parent.find(["h2", "h3", "h4", "h5"])
            if parent_heading:
                title = clean_text(parent_heading.get_text())
    return title


def fetch_deal_summary(session: requests.Session, url: str, existing_summary: str = "") -> str:
    """
    Truy cập thẳng vào trang bài viết để lấy tóm tắt chi tiết (thời gian, mức giảm, điều kiện)
    giúp người dùng đọc trực tiếp trên Telegram mà không cần bấm vào link.
    """
    if existing_summary and len(existing_summary) >= 35:
        return existing_summary[:280].rstrip() + ("..." if len(existing_summary) > 280 else "")

    try:
        resp = session.get(url, timeout=10)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "lxml")

        meta_desc = (
            soup.find("meta", attrs={"property": "og:description"})
            or soup.find("meta", attrs={"name": "description"})
        )
        meta_text = clean_text(meta_desc["content"]) if (meta_desc and meta_desc.get("content")) else ""

        soup = strip_layout_chrome(soup)
        snippets = []
        noise_words = (
            "cookie", "copyright", "all rights reserved", "đăng nhập",
            "chính sách bảo mật", "giấy chứng nhận", "hotline",
        )
        for p in soup.select("article p, main p, .entry-content p, .post-content p, .the-content p, p"):
            txt = clean_text(p.get_text())
            if len(txt) < 35 or any(nw in txt.lower() for nw in noise_words):
                continue
            snippets.append(txt)
            if len(" ".join(snippets)) >= 240:
                break

        combined = " | ".join(snippets[:2]) if snippets else meta_text
        if combined:
            return combined[:280].rstrip() + ("..." if len(combined) > 280 else "")
    except Exception:
        pass
    return "Nhấn vào tiêu đề trên để xem chi tiết mã ưu đãi và điều kiện áp dụng."


# ==============================================================================
# 4. CÁC BỘ CÀO DỮ LIỆU CHUYÊN BIỆT (HTML + RSS/ATOM + EPIC API)
# ==============================================================================
def scrape_html_source(
    session: requests.Session,
    prefix: str,
    page_url: str,
    must_contain_any: tuple,
    skip_substrings: tuple = (),
    apply_20_filter: bool = True,
    limit: int = 3,
) -> List[Dict[str, str]]:
    deals: List[Dict[str, str]] = []
    try:
        resp = session.get(page_url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        soup = strip_layout_chrome(BeautifulSoup(resp.text, "lxml"))
        seen = set()

        for a_tag in soup.select("a[href]"):
            raw_href = a_tag["href"].strip()
            if not raw_href or raw_href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            href = urljoin(page_url, raw_href)
            if href.rstrip("/") == page_url.rstrip("/") or href in seen:
                continue
            if must_contain_any and not any(tok in href for tok in must_contain_any):
                continue
            if skip_substrings and any(bad in href for bad in skip_substrings):
                continue

            title = extract_title_from_anchor(a_tag)
            if len(title) < 8:
                continue
            if apply_20_filter and not is_hot_deal_20_plus(title, href):
                continue

            seen.add(href)
            deals.append({"title": f"[{prefix}] {title}", "url": href, "summary": ""})
            if len(deals) >= limit:
                break
    except Exception as exc:
        print(f"[WARN] HTML source '{prefix}' lỗi: {exc}")
    return deals


def scrape_rss_source(
    session: requests.Session,
    prefix: str,
    rss_url: str,
    apply_20_filter: bool = True,
    limit: int = 4,
) -> List[Dict[str, str]]:
    """Cào siêu tốc từ RSS 2.0 và Atom Feed (Reddit, OzBargain, Slickdeals, GiveawayOfTheDay)."""
    deals: List[Dict[str, str]] = []
    try:
        resp = session.get(rss_url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        root = ET.fromstring(resp.content)

        items = root.findall(".//item")
        is_atom = False
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        if not items:
            items = root.findall(".//atom:entry", ns)
            is_atom = True

        for entry in items:
            if is_atom:
                title = clean_text(entry.findtext("atom:title", "", ns))
                link_el = entry.find("atom:link", ns)
                url = link_el.attrib.get("href", "") if link_el is not None else ""
                desc_html = entry.findtext("atom:content", "", ns) or entry.findtext("atom:summary", "", ns)
            else:
                title = clean_text(entry.findtext("title", ""))
                url = clean_text(entry.findtext("link", ""))
                desc_html = entry.findtext("description", "")

            if not title or not url:
                continue
            if apply_20_filter and not is_hot_deal_20_plus(title, url):
                continue

            desc_text = clean_text(BeautifulSoup(desc_html, "lxml").get_text(" ")) if desc_html else ""
            deals.append({"title": f"[{prefix}] {title}", "url": url, "summary": desc_text})
            if len(deals) >= limit:
                break
    except Exception as exc:
        print(f"[WARN] RSS source '{prefix}' lỗi: {exc}")
    return deals


def scrape_epic_free_games(session: requests.Session) -> List[Dict[str, str]]:
    """Lấy danh sách Game bản quyền đang phát miễn phí 100% hàng tuần từ JSON API chính thức của Epic Games."""
    api_url = "https://store-site-backend-static.ak.epicgames.com/freeGamesPromotions?locale=en-US&country=VN&allowCountries=VN"
    deals: List[Dict[str, str]] = []
    try:
        resp = session.get(api_url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        elements = resp.json().get("data", {}).get("Catalog", {}).get("searchStore", {}).get("elements", [])
        for el in elements:
            promos = el.get("promotions")
            if not promos or not promos.get("promotionalOffers"):
                continue
            title = clean_text(el.get("title", ""))
            desc = clean_text(el.get("description", ""))
            slug = (
                el.get("productSlug")
                or (el.get("catalogNs", {}).get("mappings") or [{}])[0].get("pageSlug")
                or ""
            )
            url = f"https://store.epicgames.com/en-US/p/{slug}" if slug else "https://store.epicgames.com/free-games"
            if title:
                deals.append({
                    "title": f"[Epic Games Free] {title} (Miễn phí 100%)",
                    "url": url,
                    "summary": f"Game bản quyền đang miễn phí 100% trên Epic Store: {desc}",
                })
    except Exception as exc:
        print(f"[WARN] Epic Games API lỗi: {exc}")
    return deals[:3]


# ==============================================================================
# 5. ĐIỀU PHỐI ĐA LUỒNG 30+ NỀN TẢNG HẢI PHÒNG & QUỐC TẾ
# ==============================================================================
def collect_all_deals(session: requests.Session) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    """Quét song song toàn bộ 30+ nền tảng và gom thành 2 nhóm lớn: Hải Phòng & Quốc Tế."""
    hp_html_targets = [
        # TTTM & Ăn uống, Buffet tại Hải Phòng
        ("AEON Mall HP", "https://aeonmall-haiphong-lechan.com.vn/khuyen-mai/", ("/khuyen-mai/",), ("/page/", "dang-ky-quay-chup", "tim-do-that-lac", "lien-he"), True, 4),
        ("Vincom Imperia HP", "https://vincom.com.vn/vincom-plaza-imperia", ("/uu-dai/", "/khuyen-mai/", "/su-kien/"), ("/gian-hang", "/gioi-thieu"), True, 3),
        ("Vincom Lê Thánh Tông", "https://vincom.com.vn/vincom-plaza-le-thanh-tong", ("/uu-dai/", "/khuyen-mai/", "/su-kien/"), ("/gian-hang", "/gioi-thieu"), True, 2),
        ("Circle K", "https://www.circlek.com.vn/vi/uu-dai-dac-biet/", ("uu-dai", "khuyen-mai", "news-events"), ("/he-thong", "/co-hoi-nghe-nghiep"), False, 3),
        ("Highlands Coffee", "https://www.highlandscoffee.com.vn/vn/tin-khuyen-mai.html", ("/vn/",), ("thuc-don", "he-thong", "nghe-nghiep"), True, 3),
        ("Highlands FlashSale", "https://order.highlandscoffee.com.vn/flash-sale", ("highlandscoffee.com.vn/",), ("/cart", "/account", "/login", "collections/all"), False, 2),
        ("Buffet Cửu Vân Long", "https://cuuvanlong.com/", ("cuuvanlong.com/",), ("lien-he", "tuyen-dung"), True, 2),
        ("Golden Gate Buffet", "https://ggg.com.vn/", ("ggg.com.vn/", "offer.ggg.com.vn"), ("tuyen-dung", "chinh-sach"), True, 3),
        ("Dookki Buffet", "https://dookkivn.net/khuyen-mai-dookki/", ("dookkivn.net/",), ("/menu-dookki", "/lien-he"), False, 2),
        ("PasGo Buffet", "https://pasgo.vn/the-tin-tuc/khuyen-mai-174", ("pasgo.vn/",), ("?page=", "/dang-nhap"), True, 3),
        # Rạp phim, Vé xe & Đồ điện tử
        ("Lotte Cinema", "https://www.lottecinemavn.com/LCHS/Contents/Event/event-list.aspx", ("EventID=",), ("contact.aspx", "Movie-List.aspx"), False, 3),
        ("CGV Cinemas", "https://www.cgv.vn/default/newsoffer/", ("/newsoffer/",), ("/cinox/", "/cgv-membership"), False, 3),
        ("Vexere Sale", "https://blog.vexere.com/tong-hop-chuong-trinh-khuyen-mai-vexere/", ("vexere.com/",), ("/login", "/author/"), True, 2),
        ("Be Group", "https://be.com.vn/tin-tuc/tong-hop-khuyen-mai-va-uu-dai-bebike/", ("be.com.vn/",), ("/ve-chung-toi", "/quy-che"), True, 2),
        ("CellphoneS", "https://cellphones.com.vn/danh-sach-khuyen-mai", ("cellphones.com.vn/",), ("/chinh-sach", "/tra-gop", "/he-thong"), True, 3),
        ("CellphoneS HSSV", "https://cellphones.com.vn/uu-dai-sinh-vien-hoc-sinh", ("cellphones.com.vn/",), ("/chinh-sach",), True, 2),
        ("Thế Giới Di Động", "https://www.thegioididong.com/tin-tuc/tin-khuyen-mai/31", ("/tin-tuc/", "/flashsale"), ("/hoi-dap",), True, 3),
        ("FPT Shop", "https://fptshop.com.vn/tin-tuc/tin-khuyen-mai", ("/tin-tuc/tin-khuyen-mai/",), ("/chinh-sach",), True, 3),
        ("Sự Kiện Hải Phòng", "https://haiphong.gov.vn/du-lich-76022", ("haiphong.gov.vn/",), ("javascript:", "/tag/", "/search"), False, 3),
    ]

    global_html_targets = [
        # Tên miền (Đức / Quốc tế) & Cloud
        ("Checkdomain Đức", "https://www.checkdomain.de/campaign/black-weeks/", ("checkdomain.de/",), ("/agb/", "support@"), False, 2),
        ("IONOS $1 Domain", "https://www.ionos.com/domains/1-dollar-domains", ("ionos.com/",), ("/login", "/help"), False, 2),
        ("Spaceship Domain", "https://www.spaceship.com/promos/", ("spaceship.com/",), ("/login",), False, 2),
        ("Porkbun Domain", "https://porkbun.com/products/deals", ("porkbun.com/tld/", "porkbun.com/event/"), ("/login",), False, 2),
        ("Namecheap Promo", "https://www.namecheap.com/promos/", ("namecheap.com/promos/",), ("/support/",), False, 2),
        ("TLD-List Cheapest", "https://tld-list.com/", ("/tld/",), ("/login",), False, 2),
        # Phần mềm Bản quyền, AI Pro, Student & Streaming
        ("StackSocial Pro", "https://www.stacksocial.com/collections/software", ("/sales/",), ("/cart", "/login"), True, 3),
        ("StackSocial Free", "https://www.stacksocial.com/free", ("/sales/",), ("/cart", "/login"), False, 2),
        ("AppSumo Lifetime", "https://appsumo.com/collections/trending-deals/", ("/products/",), ("/cart", "/plus"), False, 3),
        ("AppSumo Freebies", "https://appsumo.com/collections/freebies/", ("/products/",), ("/cart",), False, 2),
        ("DealMirror AI", "https://dealmirror.com/product-category/software/ai-tools/", ("dealmirror.com/product/",), ("/cart",), False, 2),
        ("SharewareOnSale", "https://sharewareonsale.com/product-tag/giveaway", ("sharewareonsale.com/s/",), ("/cart",), False, 3),
        ("BundleHunt Mac", "https://bundlehunt.com/", ("bundlehunt.com/",), ("/login", "/cart"), False, 2),
        ("Discord Nitro Promo", "https://support.discord.com/hc/en-us/sections/22113084771863-Promotions", ("/articles/",), (), False, 2),
        ("Google AI Student", "https://one.google.com/about/google-ai-plans/", ("one.google.com/",), ("/terms",), False, 2),
        ("GitHub Student Pack", "https://education.github.com/pack", ("education.github.com/",), ("/login",), False, 2),
        ("Perplexity Promos", "https://www.perplexity.ai/help-center/en/articles/11385821-partner-promotions-and-referral-programs", ("perplexity.ai/",), ("/login",), False, 1),
    ]

    global_rss_targets = [
        ("iOS/Mac App Free", "https://www.reddit.com/r/AppHookup/new/.rss", False, 4),
        ("Global Freebies", "https://www.reddit.com/r/freebies/new/.rss", False, 3),
        ("GameDeals Free", "https://www.reddit.com/r/GameDeals/new/.rss", True, 3),
        ("OzBargain Deals", "https://www.ozbargain.com.au/deals/feed", True, 3),
        ("OzBargain Freebies", "https://www.ozbargain.com.au/freebies/feed", False, 3),
        ("GiveawayOfTheDay", "https://www.giveawayoftheday.com/feed/", False, 2),
        ("Slickdeals Hot", "https://slickdeals.net/newsearch.php?mode=frontpage&searcharea=deals&searchin=first&rss=1", True, 3),
    ]

    hp_results: List[Dict[str, str]] = []
    global_results: List[Dict[str, str]] = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_bucket = {}
        for args in hp_html_targets:
            future_to_bucket[executor.submit(scrape_html_source, session, *args)] = "hp"
        for args in global_html_targets:
            future_to_bucket[executor.submit(scrape_html_source, session, *args)] = "global"
        for args in global_rss_targets:
            future_to_bucket[executor.submit(scrape_rss_source, session, *args)] = "global"
        future_to_bucket[executor.submit(scrape_epic_free_games, session)] = "global"

        for fut in as_completed(future_to_bucket):
            bucket = future_to_bucket[fut]
            try:
                items = fut.result()
                if bucket == "hp":
                    hp_results.extend(items)
                else:
                    global_results.extend(items)
            except Exception as exc:
                print(f"[WARN] Một tác vụ cào gặp lỗi: {exc}")

    return hp_results, global_results


# ==============================================================================
# 6. TỰ ĐỘNG XÓA TIN CŨ & BẮN BẢN TIN TELEGRAM KÈM TÓM TẮT THU GỌN
# ==============================================================================
def cleanup_old_telegram_messages(
    session: requests.Session, token: str, chat_id: str, messages_log: List[Dict]
) -> List[Dict]:
    """Xóa các tin nhắn đã gửi quá AUTO_DELETE_HOURS giờ (dưới ngưỡng 48h của Telegram)."""
    now = int(time.time())
    cutoff = now - AUTO_DELETE_HOURS * 3600
    remaining = []

    for msg in messages_log:
        msg_id = msg.get("message_id")
        sent_at = msg.get("sent_at", 0)
        if not msg_id or (now - sent_at >= 48 * 3600):
            continue
        if sent_at <= cutoff:
            try:
                endpoint = f"https://api.telegram.org/bot{token}/deleteMessage"
                resp = session.post(endpoint, json={"chat_id": chat_id, "message_id": msg_id}, timeout=10)
                if resp.ok:
                    print(f"[INFO] Đã tự động xóa tin nhắn Telegram cũ ID={msg_id}")
                    continue
            except Exception as exc:
                print(f"[WARN] Không xóa được tin ID={msg_id}: {exc}")
        remaining.append(msg)
    return remaining


def build_chunks(header_title: str, items: List[Dict[str, str]]) -> List[str]:
    """Định dạng bản tin HTML dùng <blockquote expandable> giúp màn hình điện thoại siêu gọn."""
    if not items:
        return []
    chunks: List[str] = []
    current = f"🔥 <b>{html.escape(header_title)}</b>\n<i>(Tự động dọn tin cũ sau {AUTO_DELETE_HOURS}h)</i>\n\n"

    for item in items:
        safe_title = html.escape(item["title"])
        safe_url = html.escape(item["url"], quote=True)
        safe_summary = html.escape(item.get("summary") or "Xem chi tiết tại link.")
        block = (
            f"• <a href=\"{safe_url}\"><b>{safe_title}</b></a>\n"
            f"<blockquote expandable>📌 {safe_summary}</blockquote>\n\n"
        )
        if len(current) + len(block) > 3800:
            chunks.append(current.strip())
            current = f"🔥 <b>{html.escape(header_title)} (tiếp)</b>\n\n" + block
        else:
            current += block

    if current.strip():
        chunks.append(current.strip())
    return chunks


def send_telegram_chunk(session: requests.Session, token: str, chat_id: str, text: str) -> Optional[int]:
    """Gửi tin nhắn về Telegram và trả về message_id."""
    endpoint = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    try:
        resp = session.post(endpoint, json=payload, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json().get("result", {}).get("message_id")
    except Exception as exc:
        print(f"[ERROR] Gửi Telegram thất bại: {exc}")
        return None


def main() -> None:
    token = os.getenv("TELEGRAM_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()

    session = create_resilient_session()
    state = load_state()
    sent_deals = state["deals"]

    # Bước 1: Tự động xóa tin nhắn cũ trên Telegram
    if token and chat_id and state["messages"]:
        state["messages"] = cleanup_old_telegram_messages(session, token, chat_id, state["messages"])

    # Bước 2: Quét song song 30+ nguồn Hải Phòng & Quốc Tế
    hp_items, global_items = collect_all_deals(session)

    # Bước 3: Khử trùng lặp (chỉ giữ link chưa gửi và không trùng nhau trong cùng phiên)
    seen_in_run = set()
    new_hp: List[Dict[str, str]] = []
    new_global: List[Dict[str, str]] = []

    for it in hp_items:
        u = it["url"]
        if u not in sent_deals and u not in seen_in_run:
            seen_in_run.add(u)
            new_hp.append(it)

    for it in global_items:
        u = it["url"]
        if u not in sent_deals and u not in seen_in_run:
            seen_in_run.add(u)
            new_global.append(it)

    # Giới hạn tối đa mỗi nhóm 18 deal chất lượng nhất trong 1 lần chạy để tránh flood Telegram
    new_hp = new_hp[:18]
    new_global = new_global[:18]
    all_new = new_hp + new_global

    if not all_new:
        print("[INFO] Không có deal mới nào trong lần quét này.")
        save_state(state)
        return

    # Bước 4: Bóc tách tóm tắt chi tiết song song cho toàn bộ deal mới
    print(f"[INFO] Đang bóc tách nội dung chi tiết cho {len(all_new)} deal mới...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {
            executor.submit(fetch_deal_summary, session, item["url"], item.get("summary", "")): item
            for item in all_new
        }
        for fut in as_completed(future_map):
            target_item = future_map[fut]
            target_item["summary"] = fut.result()

    # Bước 5: Tạo 2 bản tin tách biệt (Địa phương Hải Phòng & Quốc tế/Pro)
    all_chunks = (
        build_chunks("BẢN TIN 1: HẢI PHÒNG DEAL HOT (ĂN UỐNG, VÉ XE, ĐIỆN TỬ >= 20%)", new_hp)
        + build_chunks("BẢN TIN 2: QUỐC TẾ (DOMAIN, AI PRO, STREAMING, APP iOS FREE)", new_global)
    )

    if not token or not chat_id:
        print("[WARN] Thiếu TELEGRAM_TOKEN hoặc TELEGRAM_CHAT_ID.")
        for idx, ch in enumerate(all_chunks, 1):
            print(f"--- BẢN TIN #{idx} ---\n{ch}\n")
        return

    now = int(time.time())
    sent_any = False
    for chunk in all_chunks:
        msg_id = send_telegram_chunk(session, token, chat_id, chunk)
        if msg_id:
            sent_any = True
            state["messages"].append({"message_id": msg_id, "sent_at": now})
            time.sleep(0.5)  # Tránh chạm rate-limit của Telegram API

    if sent_any:
        for item in all_new:
            sent_deals[item["url"]] = now
        save_state(state)
        print(f"[INFO] Đã gửi thành công {len(all_new)} deal mới về Telegram!")


if __name__ == "__main__":
    main()
