import html
import json
import os
import re
from pathlib import Path
from typing import Dict, List
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

# Cấu hình đường dẫn lưu lịch sử deal và giới hạn tối đa 200 deal
HISTORY_FILE = Path("sent_deals.json")
MAX_HISTORY = 200
REQUEST_TIMEOUT = 15

# Giả lập User-Agent trình duyệt di động chuẩn để hạn chế bị WAF/Cloudflare chặn
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.8",
}

# Các từ khóa săn deal khủng tương đương hoặc ngon hơn mức giảm >= 20%
HOT_DEAL_KEYWORDS = (
    "mua 1 tặng 1",
    "mua 1 được 2",
    "mua 2 tặng 1",
    "mua 3 tặng 1",
    "miễn phí",
    "free",
    "0đ",
    "0 đồng",
    "đồng giá",
    "nửa giá",
    "1/2 giá",
    "flash sale",
    "black friday",
    "siêu sale",
    "giảm sốc",
    "deal sốc",
    "xả kho",
    "tặng vé",
    "tặng quà",
    "tặng ngay",
    "voucher",
    "coupon",
    "buffet",
    "cửu vân long",
    "gogi",
    "kichi",
    "manwah",
    "dookki",
    "hotpot",
    "u22",
    "hssv",
    "sinh viên",
    "lifetime",
    "student pack",
)


def load_sent_deals() -> List[str]:
    """Đọc danh sách URL các deal đã gửi từ file sent_deals.json."""
    if not HISTORY_FILE.exists():
        return []
    try:
        data = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception as exc:
        print(f"[WARN] Không đọc được {HISTORY_FILE}: {exc}")
        return []


def save_sent_deals(deals: List[str]) -> None:
    """Lưu tối đa 200 deal mới nhất vào file sent_deals.json để giữ repo nhẹ."""
    trimmed = deals[-MAX_HISTORY:]
    HISTORY_FILE.write_text(
        json.dumps(trimmed, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def clean_text(text: str) -> str:
    """Làm sạch khoảng trắng thừa trong chuỗi tiêu đề."""
    return re.sub(r"\s+", " ", text or "").strip()


def strip_layout_chrome(soup: BeautifulSoup) -> BeautifulSoup:
    """Loại bỏ header, nav, footer, sidebar để tránh cào nhầm link menu rác."""
    for tag in soup(["header", "nav", "footer", "aside", "script", "style", "noscript"]):
        tag.decompose()
    return soup


def is_hot_deal_20_plus(title: str, url: str = "") -> bool:
    """
    Bộ lọc thông minh: Chỉ giữ lại deal giảm từ 20% trở lên, giảm tiền mặt lớn (>=50K),
    hoặc chứa từ khóa ưu đãi đặc biệt (Mua 1 tặng 1, Free, Đồng giá, Flash Sale, Buffet...).
    Nếu tiêu đề có ghi % cụ thể mà toàn bộ đều < 20% (ví dụ giảm 5%, 10%) thì loại bỏ.
    """
    combined = f"{title} {url}".lower()

    # 1. Kiểm tra con số % trong tiêu đề/URL (ví dụ: 20%, 30%, 50%...)
    pct_matches = [int(m) for m in re.findall(r"(\d{1,3})\s*(?:%|phan-tram|phantram)", combined)]
    if pct_matches:
        return max(pct_matches) >= 20

    # 2. Kiểm tra mức giảm/tặng tiền mặt lớn (từ 50k - 999k hoặc hàng triệu)
    money_k = [int(m) for m in re.findall(r"(?:giảm|tặng|voucher|coupon|ưu đãi|hoàn)\s*(\d{2,4})\s*k\b", combined)]
    if money_k and max(money_k) >= 50:
        return True
    if re.search(r"(?:giảm|tặng|voucher|ưu đãi)\s*(?:đến\s*)?\d+\s*(?:triệu|tr\b)", combined):
        return True

    # 3. Kiểm tra danh sách từ khóa ưu đãi khủng / đồng giá / buffet
    return any(kw in combined for kw in HOT_DEAL_KEYWORDS)


def extract_title_from_anchor(a_tag) -> str:
    """Trích xuất tiêu đề chuẩn nhất từ thẻ <a> hoặc khối cha gần nhất."""
    heading = a_tag.find(["h2", "h3", "h4", "h5"])
    if heading:
        return clean_text(heading.get_text())

    img = a_tag.find("img")
    title = clean_text(a_tag.get("title") or (img.get("alt") if img else "") or a_tag.get_text())

    generic_labels = {
        "chi tiết", "xem thêm", "xem tất cả", "khám phá ngay",
        "read more", "view deal", "mua ngay", "đặt ngay", "khuyến mãi",
    }
    if not title or title.lower() in generic_labels:
        parent = a_tag.find_parent(["article", "div", "li", "section"])
        if parent:
            parent_heading = parent.find(["h2", "h3", "h4", "h5"])
            if parent_heading:
                title = clean_text(parent_heading.get_text())
    return title


def scrape_generic_links(
    session: requests.Session,
    page_url: str,
    must_contain_any: tuple,
    skip_substrings: tuple = (),
    min_title_len: int = 10,
    apply_20_filter: bool = True,
) -> List[Dict[str, str]]:
    """Hàm lõi bóc tách danh sách bài khuyến mãi an toàn cho từng trang HTML."""
    deals: List[Dict[str, str]] = []
    try:
        resp = session.get(page_url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        soup = strip_layout_chrome(BeautifulSoup(resp.text, "lxml"))

        seen_links = set()
        for a_tag in soup.select("a[href]"):
            raw_href = a_tag["href"].strip()
            if not raw_href or raw_href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue

            href = urljoin(page_url, raw_href)
            if href.rstrip("/") == page_url.rstrip("/") or href in seen_links:
                continue
            if must_contain_any and not any(tok in href for tok in must_contain_any):
                continue
            if skip_substrings and any(bad in href for bad in skip_substrings):
                continue

            title = extract_title_from_anchor(a_tag)
            if len(title) < min_title_len:
                continue

            if apply_20_filter and not is_hot_deal_20_plus(title, href):
                continue

            seen_links.add(href)
            deals.append({"title": title, "url": href})
    except Exception as exc:
        print(f"[WARN] Nguồn {page_url} tạm lỗi hoặc chặn kết nối: {exc}")
    return deals[:6]


def scrape_mall_and_food(session: requests.Session) -> List[Dict[str, str]]:
    """Nhóm 1: TTTM, Chuỗi Đồ Uống & Buffet Hải Phòng (AEON, Vincom, Circle K, Highlands, Cửu Vân Long, Golden Gate, Dookki, PasGo)."""
    results: List[Dict[str, str]] = []
    targets = [
        # AEON Mall Hải Phòng Lê Chân (bao gồm Cửu Vân Long, GoGi, Kichi, Dookki, KOI Thé, Uniqlo...)
        (
            "AEON HP",
            "https://aeonmall-haiphong-lechan.com.vn/khuyen-mai/",
            ("/khuyen-mai/",),
            ("/page/", "dang-ky-quay-chup", "tim-do-that-lac", "lien-he"),
            True,
        ),
        # Vincom Plaza Hải Phòng (Imperia & Lê Thánh Tông)
        (
            "Vincom HP",
            "https://vincom.com.vn/vincom-plaza-imperia",
            ("/uu-dai/", "/khuyen-mai/", "/su-kien/"),
            ("/gian-hang", "/gioi-thieu"),
            True,
        ),
        (
            "Vincom HP",
            "https://vincom.com.vn/vincom-plaza-le-thanh-tong",
            ("/uu-dai/", "/khuyen-mai/", "/su-kien/"),
            ("/gian-hang", "/gioi-thieu"),
            True,
        ),
        # Circle K Việt Nam
        (
            "Circle K",
            "https://www.circlek.com.vn/vi/uu-dai-dac-biet/",
            ("uu-dai", "khuyen-mai", "news-events"),
            ("/he-thong-circle-k", "/co-hoi-nghe-nghiep"),
            False,
        ),
        # Highlands Coffee (Tin khuyến mãi & Flash Sale)
        (
            "Highlands",
            "https://www.highlandscoffee.com.vn/vn/tin-khuyen-mai.html",
            ("/vn/",),
            ("thuc-don", "he-thong", "nghe-nghiep", "gioi-thieu"),
            True,
        ),
        (
            "Highlands FlashSale",
            "https://order.highlandscoffee.com.vn/flash-sale",
            ("highlandscoffee.com.vn/",),
            ("/cart", "/account", "/login", "collections/all"),
            False,
        ),
        # Hệ thống Buffet: Cửu Vân Long, Golden Gate, Dookki, PasGo Hải Phòng
        (
            "Cửu Vân Long",
            "https://cuuvanlong.com/",
            ("cuuvanlong.com/",),
            ("lien-he", "tuyen-dung"),
            True,
        ),
        (
            "Golden Gate",
            "https://ggg.com.vn/",
            ("ggg.com.vn/", "offer.ggg.com.vn"),
            ("tuyen-dung", "ve-chung-toi", "chinh-sach"),
            True,
        ),
        (
            "Dookki",
            "https://dookkivn.net/khuyen-mai-dookki/",
            ("dookkivn.net/",),
            ("/menu-dookki", "/lien-he"),
            False,
        ),
        (
            "PasGo Buffet",
            "https://pasgo.vn/the-tin-tuc/khuyen-mai-174",
            ("pasgo.vn/",),
            ("/dang-nhap", "/dang-ky", "?page="),
            True,
        ),
    ]

    for prefix, url, must_have, skip_list, filter_flag in targets:
        items = scrape_generic_links(session, url, must_have, skip_list, apply_20_filter=filter_flag)
        for item in items[:3]:
            results.append({"title": f"[{prefix}] {item['title']}", "url": item["url"]})
    return results


def scrape_cinema_and_transport(session: requests.Session) -> List[Dict[str, str]]:
    """Nhóm 2: Rạp chiếu phim (Lotte Cinema, CGV) & Phương tiện di chuyển (Vexere, Be)."""
    results: List[Dict[str, str]] = []
    targets = [
        # Lotte Cinema
        (
            "Lotte Cinema",
            "https://www.lottecinemavn.com/LCHS/Contents/Event/event-list.aspx",
            ("EventID=", "event"),
            ("contact.aspx", "Movie-List.aspx"),
            False,
        ),
        # CGV Cinemas
        (
            "CGV",
            "https://www.cgv.vn/default/newsoffer/",
            ("/newsoffer/",),
            ("/cinox/", "/cgv-membership"),
            False,
        ),
        # Vexere (Flash Sale giảm đến 50% & Tổng hợp CTKM)
        (
            "Vexere",
            "https://blog.vexere.com/tong-hop-chuong-trinh-khuyen-mai-vexere/",
            ("vexere.com/",),
            ("/login", "/author/", "/category/"),
            True,
        ),
        # Be Group (Ưu đãi gọi xe beBike/beCar)
        (
            "Be",
            "https://be.com.vn/tin-tuc/tong-hop-khuyen-mai-va-uu-dai-bebike/",
            ("be.com.vn/",),
            ("/ve-chung-toi", "/quy-che", "/cau-hoi"),
            True,
        ),
    ]

    for prefix, url, must_have, skip_list, filter_flag in targets:
        items = scrape_generic_links(session, url, must_have, skip_list, min_title_len=6, apply_20_filter=filter_flag)
        for item in items[:3]:
            results.append({"title": f"[{prefix}] {item['title']}", "url": item["url"]})
    return results


def scrape_electronics(session: requests.Session) -> List[Dict[str, str]]:
    """Nhóm 3: Đồ điện tử, Laptop, Phụ kiện giảm sâu (CellphoneS, Thế Giới Di Động, FPT Shop)."""
    results: List[Dict[str, str]] = []
    targets = [
        (
            "CellphoneS",
            "https://cellphones.com.vn/danh-sach-khuyen-mai",
            ("cellphones.com.vn/",),
            ("/chinh-sach", "/tra-gop", "/he-thong-cua-hang"),
            True,
        ),
        (
            "CellphoneS HSSV",
            "https://cellphones.com.vn/uu-dai-sinh-vien-hoc-sinh",
            ("cellphones.com.vn/",),
            ("/chinh-sach", "/he-thong-cua-hang"),
            True,
        ),
        (
            "TGDĐ",
            "https://www.thegioididong.com/tin-tuc/tin-khuyen-mai/31",
            ("/tin-tuc/", "/flashsale", "/khuyen-mai"),
            ("/hoi-dap", "/chinh-sach"),
            True,
        ),
        (
            "FPT Shop",
            "https://fptshop.com.vn/tin-tuc/tin-khuyen-mai",
            ("/tin-tuc/tin-khuyen-mai/", "/ctkm/"),
            ("/gioi-thieu", "/chinh-sach"),
            True,
        ),
    ]

    for prefix, url, must_have, skip_list, filter_flag in targets:
        items = scrape_generic_links(session, url, must_have, skip_list, apply_20_filter=filter_flag)
        for item in items[:4]:
            results.append({"title": f"[{prefix}] {item['title']}", "url": item["url"]})
    return results


def scrape_pro_platforms(session: requests.Session) -> List[Dict[str, str]]:
    """Nhóm 4: Nền tảng Pro, SaaS, AI & Dev Tools (AppSumo Lifetime Deals, GitHub Student Pack)."""
    results: List[Dict[str, str]] = []
    targets = [
        (
            "AppSumo Lifetime",
            "https://appsumo.com/collections/trending-deals/",
            ("/products/",),
            ("/cart", "/plus", "/account"),
            False,
        ),
        (
            "AppSumo Freebies",
            "https://appsumo.com/collections/freebies/",
            ("/products/",),
            ("/cart", "/plus", "/account"),
            False,
        ),
        (
            "GitHub Pack",
            "https://education.github.com/pack",
            ("education.github.com/pack",),
            ("/login", "/join"),
            False,
        ),
    ]

    for prefix, url, must_have, skip_list, filter_flag in targets:
        items = scrape_generic_links(session, url, must_have, skip_list, min_title_len=5, apply_20_filter=filter_flag)
        for item in items[:4]:
            results.append({"title": f"[{prefix}] {item['title']}", "url": item["url"]})
    return results


def scrape_haiphong_events(session: requests.Session) -> List[Dict[str, str]]:
    """Nhóm 5: Sự kiện, Lễ hội & Ẩm thực địa phương từ Cổng TTĐT TP Hải Phòng."""
    url = "https://haiphong.gov.vn/du-lich-76022"
    deals: List[Dict[str, str]] = []
    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        soup = strip_layout_chrome(BeautifulSoup(resp.text, "lxml"))

        seen_links = set()
        for a_tag in soup.select("a[href]"):
            href = urljoin(url, a_tag["href"].strip())
            title = clean_text(a_tag.get("title") or a_tag.get_text())
            is_article = bool(re.search(r"-\d{5,}$", href.rstrip("/")))
            if "haiphong.gov.vn/" in href and is_article and len(title) >= 25 and href not in seen_links:
                seen_links.add(href)
                deals.append({"title": title, "url": href})
    except Exception as exc:
        print(f"[WARN] Lỗi cào Sự kiện Hải Phòng: {exc}")
    return deals[:5]


def build_telegram_messages(grouped_new_deals: Dict[str, List[Dict[str, str]]]) -> List[str]:
    """
    Định dạng bản tin Telegram bằng HTML, tự động chia nhỏ nếu vượt quá giới hạn 4000 ký tự của Telegram.
    """
    header = "🔥 <b>BẢN TIN SĂN DEAL HẢI PHÒNG & TECH PRO (>= 20%)</b> 🔥\n\n"
    messages: List[str] = []
    current_msg = header

    for category_name, items in grouped_new_deals.items():
        if not items:
            continue
        section_lines = [f"📍 <b>{html.escape(category_name)}</b>"]
        for item in items:
            safe_title = html.escape(item["title"])
            safe_url = html.escape(item["url"], quote=True)
            section_lines.append(f"• <a href=\"{safe_url}\">{safe_title}</a>")
        section_block = "\n".join(section_lines) + "\n\n"

        if len(current_msg) + len(section_block) > 3800:
            messages.append(current_msg.strip())
            current_msg = header + section_block
        else:
            current_msg += section_block

    if current_msg.strip() != header.strip():
        messages.append(current_msg.strip())
    return messages


def send_telegram_message(token: str, chat_id: str, text: str) -> bool:
    """Bắn thông báo về Telegram Bot qua endpoint sendMessage với parse_mode=HTML."""
    endpoint = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    try:
        resp = requests.post(endpoint, json=payload, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return True
    except Exception as exc:
        print(f"[ERROR] Gửi tin nhắn Telegram thất bại: {exc}")
        return False


def main() -> None:
    """Hàm điều phối chính: Cào 5 nhóm nguồn -> Lọc deal >= 20% -> Khử trùng -> Bắn Telegram."""
    token = os.getenv("TELEGRAM_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()

    sent_list = load_sent_deals()
    sent_set = set(sent_list)

    session = requests.Session()
    session.headers.update(HEADERS)

    categories = {
        "🍖 Ăn Uống, Buffet & TTTM Hải Phòng": scrape_mall_and_food,
        "🎬 Rạp Phim & Di Chuyển (Vé Xe / Gọi Xe)": scrape_cinema_and_transport,
        "💻 Đồ Điện Tử, Laptop & Phụ Kiện (Sale >= 20%)": scrape_electronics,
        "🚀 Nền Tảng Pro, AI & Dev Tools": scrape_pro_platforms,
        "🎉 Sự Kiện & Lễ Hội Phố Cảng": scrape_haiphong_events,
    }

    grouped_new_deals: Dict[str, List[Dict[str, str]]] = {}
    newly_found_urls: List[str] = []

    for category_title, scraper_fn in categories.items():
        try:
            fetched_items = scraper_fn(session)
        except Exception as exc:
            print(f"[ERROR] Nhóm '{category_title}' gặp lỗi: {exc}")
            continue

        fresh_items = []
        for item in fetched_items:
            deal_url = item["url"]
            if deal_url not in sent_set:
                fresh_items.append(item)
                sent_set.add(deal_url)
                newly_found_urls.append(deal_url)
        if fresh_items:
            grouped_new_deals[category_title] = fresh_items

    if not newly_found_urls:
        print("[INFO] Không có deal >= 20% nào mới trong lần quét này. Bỏ qua gửi tin nhắn.")
        return

    messages = build_telegram_messages(grouped_new_deals)

    if not token or not chat_id:
        print("[WARN] Thiếu TELEGRAM_TOKEN hoặc TELEGRAM_CHAT_ID trong biến môi trường.")
        for idx, msg in enumerate(messages, 1):
            print(f"--- BẢN TIN #{idx} ---\n{msg}\n")
        return

    all_sent = True
    for msg in messages:
        if not send_telegram_message(token, chat_id, msg):
            all_sent = False

    if all_sent:
        save_sent_deals(sent_list + newly_found_urls)
        print(f"[INFO] Đã gửi thành công {len(newly_found_urls)} deal mới về Telegram!")


if __name__ == "__main__":
    main()
