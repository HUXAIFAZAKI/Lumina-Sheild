import sqlite3
import hashlib
from datetime import datetime
import os

DB_NAME = os.path.join(os.path.dirname(__file__), "sachai.db")

# ---- Global city coordinates (100+ cities) ----
GLOBAL_CITY_COORDS = {
    # Pakistan
    "Karachi": [24.8607, 67.0011], "Lahore": [31.5497, 74.3436],
    "Islamabad": [33.6844, 73.0479], "Peshawar": [34.0151, 71.5249],
    "Quetta": [30.1798, 66.9750], "Faisalabad": [31.4504, 73.1350],
    "Multan": [30.1575, 71.5249], "Gujranwala": [32.1877, 74.1945],
    "Hyderabad": [25.3960, 68.3578], "Rawalpindi": [33.5651, 73.0169],
    "Sialkot": [32.4945, 74.5229], "Bahawalpur": [29.3956, 71.6836],
    "Sukkur": [27.7052, 68.8574], "Mardan": [34.1980, 72.0459],
    "Abbottabad": [34.1688, 73.2215], "Muzaffarabad": [34.3700, 73.4711],
    # South Asia
    "Mumbai": [19.0760, 72.8777], "Delhi": [28.7041, 77.1025],
    "Bangalore": [12.9716, 77.5946], "Chennai": [13.0827, 80.2707],
    "Kolkata": [22.5726, 88.3639], "Dhaka": [23.8103, 90.4125],
    "Colombo": [6.9271, 79.8612], "Kathmandu": [27.7172, 85.3240],
    # Middle East
    "Dubai": [25.2048, 55.2708], "Abu Dhabi": [24.4539, 54.3773],
    "Riyadh": [24.7136, 46.6753], "Jeddah": [21.4858, 39.1925],
    "Doha": [25.2854, 51.5310], "Kuwait City": [29.3759, 47.9774],
    "Muscat": [23.5880, 58.3829], "Tehran": [35.6892, 51.3890],
    "Baghdad": [33.3152, 44.3661], "Istanbul": [41.0082, 28.9784],
    "Ankara": [39.9334, 32.8597],
    # Europe
    "London": [51.5074, -0.1278], "Paris": [48.8566, 2.3522],
    "Berlin": [52.5200, 13.4050], "Rome": [41.9028, 12.4964],
    "Madrid": [40.4168, -3.7038], "Amsterdam": [52.3676, 4.9041],
    "Brussels": [50.8503, 4.3517], "Vienna": [48.2082, 16.3738],
    "Zurich": [47.3769, 8.5417], "Stockholm": [59.3293, 18.0686],
    "Oslo": [59.9139, 10.7522], "Copenhagen": [55.6761, 12.5683],
    "Helsinki": [60.1699, 24.9384], "Warsaw": [52.2297, 21.0122],
    "Prague": [50.0755, 14.4378], "Budapest": [47.4979, 19.0402],
    "Dublin": [53.3498, -6.2603], "Lisbon": [38.7223, -9.1393],
    "Athens": [37.9838, 23.7275], "Moscow": [55.7558, 37.6173],
    # North America
    "New York": [40.7128, -74.0060], "Los Angeles": [34.0522, -118.2437],
    "Chicago": [41.8781, -87.6298], "Houston": [29.7604, -95.3698],
    "Toronto": [43.6510, -79.3470], "Vancouver": [49.2827, -123.1207],
    "Montreal": [45.5017, -73.5673], "Mexico City": [19.4326, -99.1332],
    "San Francisco": [37.7749, -122.4194], "Washington DC": [38.9072, -77.0369],
    "Miami": [25.7617, -80.1918], "Boston": [42.3601, -71.0589],
    "Seattle": [47.6062, -122.3321], "Dallas": [32.7767, -96.7970],
    # South America
    "São Paulo": [-23.5505, -46.6333], "Buenos Aires": [-34.6037, -58.3816],
    "Bogotá": [4.7110, -74.0721], "Lima": [-12.0464, -77.0428],
    "Santiago": [-33.4489, -70.6693],
    # Africa
    "Cairo": [30.0444, 31.2357], "Lagos": [6.5244, 3.3792],
    "Nairobi": [-1.2921, 36.8219], "Cape Town": [-33.9249, 18.4241],
    "Casablanca": [33.5731, -7.5898], "Addis Ababa": [9.0250, 38.7469],
    "Accra": [5.6037, -0.1870], "Dar es Salaam": [-6.7924, 39.2083],
    # East Asia & Pacific
    "Tokyo": [35.6762, 139.6503], "Seoul": [37.5665, 126.9780],
    "Beijing": [39.9042, 116.4074], "Shanghai": [31.2304, 121.4737],
    "Hong Kong": [22.3193, 114.1694], "Taipei": [25.0330, 121.5654],
    "Singapore": [1.3521, 103.8198], "Bangkok": [13.7563, 100.5018],
    "Jakarta": [-6.2088, 106.8456], "Manila": [14.5995, 120.9842],
    "Kuala Lumpur": [3.1390, 101.6869], "Hanoi": [21.0285, 105.8542],
    "Ho Chi Minh City": [10.8231, 106.6297],
    # Oceania
    "Sydney": [-33.8688, 151.2093], "Melbourne": [-37.8136, 144.9631],
    "Auckland": [-36.8509, 174.7645], "Brisbane": [-27.4698, 153.0251],
    "Perth": [-31.9505, 115.8605],
}

def get_city_coords(city: str) -> list:
    """Get coordinates for a city. Returns [lat, lon] or None."""
    return GLOBAL_CITY_COORDS.get(city)

def get_all_city_names() -> list:
    """Get sorted list of all available city names."""
    return sorted(GLOBAL_CITY_COORDS.keys())


def _ensure_initialized(conn):
    """Create tables if they don't exist."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            raw_text TEXT,
            language TEXT,
            persona TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS verdicts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            submission_id INTEGER,
            claim_id INTEGER,
            verdict TEXT,
            confidence REAL,
            evidence TEXT,
            tactic_flags TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            submission_id INTEGER,
            type TEXT,
            value TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS heatmap_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            city TEXT,
            category TEXT,
            verdict TEXT,
            date TEXT DEFAULT (date('now'))
        );
        CREATE TABLE IF NOT EXISTS community_feed (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            submission_id INTEGER,
            verdict TEXT,
            snippet TEXT,
            content_hash TEXT,
            upvotes INTEGER DEFAULT 0,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS annotations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            note TEXT,
            tags TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()

def init_db():
    """Explicitly create tables if they don't exist (safe to call multiple times)."""
    conn = sqlite3.connect(DB_NAME)
    _ensure_initialized(conn)
    
    # Seed community_feed data for hackathon demo if empty
    count = conn.execute("SELECT COUNT(*) FROM community_feed").fetchone()[0]
    if count == 0:
        import datetime as dt
        import random
        base_date = dt.datetime.now()
        verdicts_list = ["FAKE", "SCAM", "MANIPULATED", "FALSE", "MIXTURE"]
        snippets = [
            "BISP mein 25000 milenge, is link par register karein — FAKE link detected",
            "Government ne naya laptop scheme announce kiya — Official source mismatch",
            "Breaking: Schools will remain closed nationwide for 2 weeks — No official confirmation",
            "Forward this message to 10 people to get free mobile balance — Classic scam pattern",
            "NASA ne confirm kiya ke kal raat 3 chaand nazar aayenge — Fabricated claim",
            "Petrol prices will increase by 50 rupees from tomorrow — Unverified, no gazette notification",
            "This WhatsApp update will turn your chat blue if you don't forward — Hoax chain message",
            "NADRA is giving free SIM cards — check at this link — Phishing attempt",
            "Earthquake warning for next 48 hours in Islamabad — Not from PMD official",
            "Free COVID booster available at this number — Unofficial helpline",
            "PM announces Rs 100,000 for every family via Ehsaas — Misquoted amount",
            "Water in plastic bottles causes cancer says Harvard — Debunked study",
            "Bank is freezing accounts — call this number immediately — Social engineering scam",
            "New traffic challan system: pay via this app — Fake app redirect",
            "Army chief replaced — breaking news from ARY — Manipulated screenshot",
        ]
        for i in range(15):
            date = base_date - dt.timedelta(days=random.randint(0, 10), hours=random.randint(0, 23))
            v = random.choice(verdicts_list)
            snippet = snippets[i % len(snippets)]
            content_hash = hashlib.md5(snippet.encode()).hexdigest()
            conn.execute(
                "INSERT INTO community_feed (submission_id, verdict, snippet, content_hash, upvotes, timestamp) VALUES (?,?,?,?,?,?)",
                (i, v, snippet, content_hash, random.randint(1, 50), date.strftime("%Y-%m-%d %H:%M:%S"))
            )
        conn.commit()

    # Seed heatmap_log data for demo if empty
    heatmap_count = conn.execute("SELECT COUNT(*) FROM heatmap_log").fetchone()[0]
    if heatmap_count == 0:
        import datetime as dt
        import random
        base_date = dt.datetime.now()
        cities = ["Karachi", "Lahore", "Islamabad", "Peshawar", "Faisalabad",
                  "New York", "London", "Dubai", "Mumbai", "Toronto", "Singapore",
                  "Sydney", "Berlin", "Tokyo", "Cairo"]
        categories = ["political", "financial", "health", "scheme", "cyber", "general"]
        verdicts_list = ["FAKE", "SCAM", "FALSE", "MANIPULATED", "MIXTURE", "TRUE"]
        for i in range(30):
            date = base_date - dt.timedelta(days=random.randint(0, 14))
            city = random.choice(cities)
            cat = random.choice(categories)
            v = random.choice(verdicts_list)
            conn.execute(
                "INSERT INTO heatmap_log (city, category, verdict, date) VALUES (?,?,?,?)",
                (city, cat, v, date.strftime("%Y-%m-%d"))
            )
        conn.commit()
    
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    _ensure_initialized(conn)          # ensures tables exist on every connect
    return conn

def log_submission(raw_text, language, persona):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO submissions (raw_text, language, persona) VALUES (?,?,?)",
                (raw_text, language, persona))
    conn.commit()
    sub_id = cur.lastrowid
    conn.close()
    return sub_id

def log_verdict(submission_id, claim_id, verdict, confidence, evidence, tactic_flags):
    conn = get_db()
    conn.execute("INSERT INTO verdicts (submission_id, claim_id, verdict, confidence, evidence, tactic_flags) VALUES (?,?,?,?,?,?)",
                 (submission_id, claim_id, verdict, confidence, evidence, str(tactic_flags)))
    conn.commit()
    conn.close()

def log_ioc(submission_id, ioc_type, value):
    conn = get_db()
    conn.execute("INSERT INTO iocs (submission_id, type, value) VALUES (?,?,?)",
                 (submission_id, ioc_type, value))
    conn.commit()
    conn.close()

def log_heatmap(city, category, verdict):
    conn = get_db()
    conn.execute("INSERT INTO heatmap_log (city, category, verdict) VALUES (?,?,?)",
                 (city, category, verdict))
    conn.commit()
    conn.close()

def _content_hash(text: str) -> str:
    """Generate a hash for content deduplication."""
    normalized = text.strip().lower()[:200]
    return hashlib.md5(normalized.encode()).hexdigest()

def check_feed_duplicate(snippet: str) -> bool:
    """Check if similar content already exists in the feed."""
    conn = get_db()
    h = _content_hash(snippet)
    row = conn.execute("SELECT COUNT(*) FROM community_feed WHERE content_hash = ?", (h,)).fetchone()
    conn.close()
    return row[0] > 0

def log_to_feed(submission_id, verdict, snippet):
    """Add to feed only if not duplicate."""
    if check_feed_duplicate(snippet):
        return False
    conn = get_db()
    h = _content_hash(snippet)
    conn.execute("INSERT INTO community_feed (submission_id, verdict, snippet, content_hash) VALUES (?,?,?,?)",
                 (submission_id, verdict, snippet, h))
    conn.commit()
    conn.close()
    return True

def get_heatmap_data():
    conn = get_db()
    rows = conn.execute("SELECT city, category, verdict, date FROM heatmap_log").fetchall()
    conn.close()
    return rows

def get_community_feed(limit=50):
    conn = get_db()
    rows = conn.execute("SELECT id, verdict, snippet, upvotes, timestamp FROM community_feed ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return rows

def get_community_feed_filtered(verdict_filter=None, sort_by="latest", limit=50):
    """Get filtered and sorted community feed."""
    conn = get_db()
    query = "SELECT id, verdict, snippet, upvotes, timestamp FROM community_feed"
    params = []
    if verdict_filter and verdict_filter != "ALL":
        query += " WHERE verdict = ?"
        params.append(verdict_filter)
    if sort_by == "upvotes":
        query += " ORDER BY upvotes DESC"
    else:
        query += " ORDER BY timestamp DESC"
    query += " LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, tuple(params)).fetchall()
    conn.close()
    return rows

def upvote_feed_item(item_id):
    conn = get_db()
    conn.execute("UPDATE community_feed SET upvotes = upvotes + 1 WHERE id = ?", (item_id,))
    conn.commit()
    conn.close()

def add_annotation(target, note, tags):
    conn = get_db()
    conn.execute("INSERT INTO annotations (target, note, tags) VALUES (?,?,?)",
                 (target, note, tags))
    conn.commit()
    conn.close()

def get_annotations(target):
    conn = get_db()
    rows = conn.execute("SELECT id, note, tags, timestamp FROM annotations WHERE target = ? ORDER BY timestamp DESC", (target,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]