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

# Giả lập User-Agent trình duyệt chuẩn để tránh bị WAF/Cloudflare chặn
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.8",
}


def load_sent_deals() -> List[str]:
    """Đọc danh sách URL/ID các deal đã gửi từ file sent_deals.json."""
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


def scrape_aeon_haiphong(session: requests.Session) -> List[Dict[str, str]]:
    """Nguồn 1: Cào khuyến mãi từ AEON MALL Hải Phòng Lê Chân (Ẩm thực, Mua sắm)."""
    url = "https://aeonmall-haiphong-lechan.com.vn/khuyen-mai/"
    deals: List[Dict[str, str]] = []
    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "lxml")

        seen_links = set()
        for a_tag in soup.select("a[href]"):
            href = urljoin(url, a_tag["href"].strip())
            # Chỉ lọc các bài viết chi tiết trong chuyên mục khuyến mãi / tin tức
            if not any(seg in href for seg in ("/khuyen-mai/", "/tin-tuc/", "/su-kien/")):
                continue
            if href.rstrip("/") in (
                url.rstrip("/"),
                "https://aeonmall-haiphong-lechan.com.vn/tin-tuc",
                "https://aeonmall-haiphong-lechan.com.vn/su-kien",
            ) or "/page/" in href:
                continue

            # Ưu tiên lấy tiêu đề từ thẻ heading bên trong hoặc thuộc tính title
            heading = a_tag.find(["h2", "h3", "h4"])
            title = clean_text(
                heading.get_text() if heading else (a_tag.get("title") or a_tag.get_text())
            )
            if not title or title.lower() in ("chi tiết", "xem thêm", "khuyến mãi", "tin tức"):
                # Nếu thẻ <a> chỉ bọc chữ "Chi tiết", tìm thẻ tiêu đề ở khối cha gần nhất
                parent = a_tag.find_parent(["div", "article", "li"])
                if parent:
                    parent_heading = parent.find(["h2", "h3", "h4"])
                    if parent_heading:
                        title = clean_text(parent_heading.get_text())

            if len(title) >= 10 and href not in seen_links:
                seen_links.add(href)
                deals.append({"title": title, "url": href})
    except Exception as exc:
        print(f"[ERROR] Lỗi cào AEON Mall Hải Phòng: {exc}")
    return deals[:10]


def scrape_cgv_promos(session: requests.Session) -> List[Dict[str, str]]:
    """Nguồn 2: Cào ưu đãi vé xem phim & combo bắp nước từ cụm rạp CGV."""
    url = "https://www.cgv.vn/default/newsoffer/"
    deals: List[Dict[str, str]] = []
    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "lxml")

        seen_links = set()
        for a_tag in soup.select("a[href*='/newsoffer/']"):
            href = urljoin(url, a_tag["href"].strip())
            if href.rstrip("/") == url.rstrip("/") or href in seen_links:
                continue

            img = a_tag.find("img")
            title = clean_text(
                (img.get("alt") if img else "")
                or a_tag.get("title")
                or a_tag.get_text()
            )
            if not title or title.lower() == "read more":
                # Trích tên chương trình từ slug URL nếu trang chỉ gắn ảnh không có alt text
                slug = href.rstrip("/").split("/")[-1]
                title = f"Ưu đãi CGV: {slug.replace('-', ' ').upper()}"

            if len(title) >= 5:
                seen_links.add(href)
                deals.append({"title": title, "url": href})
    except Exception as exc:
        print(f"[ERROR] Lỗi cào khuyến mãi CGV: {exc}")
    return deals[:10]


def scrape_haiphong_events(session: requests.Session) -> List[Dict[str, str]]:
    """Nguồn 3: Cào sự kiện, lễ hội & du lịch ẩm thực từ Cổng TTĐT TP Hải Phòng."""
    url = "https://haiphong.gov.vn/du-lich-76022"
    deals: List[Dict[str, str]] = []
    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "lxml")

        seen_links = set()
        for a_tag in soup.select("a[href]"):
            href = urljoin(url, a_tag["href"].strip())
            title = clean_text(a_tag.get("title") or a_tag.get_text())

            # Lọc các bài viết sự kiện/du lịch có độ dài tiêu đề hợp lệ
            if (
                "haiphong.gov.vn/" in href
                and href.rstrip("/") != url.rstrip("/")
                and len(title) >= 25
                and not any(skip in href for skip in ("javascript:", "#", "/tag/", "/search"))
                and href not in seen_links
            ):
                seen_links.add(href)
                deals.append({"title": title, "url": href})
    except Exception as exc:
        print(f"[ERROR] Lỗi cào Sự kiện & Du lịch Hải Phòng: {exc}")
    return deals[:10]


def build_telegram_message(grouped_new_deals: Dict[str, List[Dict[str, str]]]) -> str:
    """Định dạng bản tin Telegram bằng HTML, phân nhóm rõ ràng theo từng nguồn."""
    lines = ["🔥 <b>BẢN TIN SĂN DEAL & SỰ KIỆN HẢI PHÒNG MỚI NHẤT</b> 🔥\n"]
    for source_name, items in grouped_new_deals.items():
        if not items:
            continue
        lines.append(f"📍 <b>{html.escape(source_name)}</b>")
        for item in items:
            safe_title = html.escape(item["title"])
            safe_url = html.escape(item["url"], quote=True)
            lines.append(f"• <a href=\"{safe_url}\">{safe_title}</a>")
        lines.append("")
    return "\n".join(lines).strip()


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
        print("[INFO] Đã gửi bản tin Telegram thành công!")
        return True
    except Exception as exc:
        print(f"[ERROR] Gửi tin nhắn Telegram thất bại: {exc}")
        return False


def main() -> None:
    """Hàm điều phối chính: Cào dữ liệu -> Lọc trùng -> Bắn Telegram -> Lưu lịch sử."""
    token = os.getenv("TELEGRAM_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()

    sent_list = load_sent_deals()
    sent_set = set(sent_list)

    session = requests.Session()
    session.headers.update(HEADERS)

    sources = {
        "🛍️ AEON MALL Hải Phòng Lê Chân": scrape_aeon_haiphong,
        "🎬 Rạp Phim CGV (Ưu Đãi & Combo)": scrape_cgv_promos,
        "🎉 Sự Kiện & Ẩm Thực Phố Cảng": scrape_haiphong_events,
    }

    grouped_new_deals: Dict[str, List[Dict[str, str]]] = {}
    newly_found_urls: List[str] = []

    for source_title, scraper_fn in sources.items():
        fetched_items = scraper_fn(session)
        fresh_items = []
        for item in fetched_items:
            deal_url = item["url"]
            if deal_url not in sent_set:
                fresh_items.append(item)
                sent_set.add(deal_url)
                newly_found_urls.append(deal_url)
        if fresh_items:
            grouped_new_deals[source_title] = fresh_items

    if not newly_found_urls:
        print("[INFO] Không có deal nào mới trong lần quét này. Bỏ qua gửi tin nhắn.")
        return

    message = build_telegram_message(grouped_new_deals)

    if not token or not chat_id:
        print("[WARN] Thiếu TELEGRAM_TOKEN hoặc TELEGRAM_CHAT_ID trong biến môi trường.")
        print("--- XEM TRƯỚC BẢN TIN ---")
        print(message)
        return

    if send_telegram_message(token, chat_id, message):
        save_sent_deals(sent_list + newly_found_urls)


if __name__ == "__main__":
    main()
