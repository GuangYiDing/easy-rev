from __future__ import annotations

import secrets
import string
import uuid

from easy_rev.core.types import AccountProfile

# Alphabetic-only name pools — many signup forms reject digits / symbols in names.
_FIRST_NAMES = (
    "James",
    "Mary",
    "John",
    "Patricia",
    "Robert",
    "Jennifer",
    "Michael",
    "Linda",
    "William",
    "Elizabeth",
    "David",
    "Barbara",
    "Richard",
    "Susan",
    "Joseph",
    "Jessica",
    "Thomas",
    "Sarah",
    "Charles",
    "Karen",
    "Christopher",
    "Lisa",
    "Daniel",
    "Nancy",
    "Matthew",
    "Betty",
    "Anthony",
    "Margaret",
    "Mark",
    "Sandra",
    "Donald",
    "Ashley",
    "Steven",
    "Kimberly",
    "Paul",
    "Emily",
    "Andrew",
    "Donna",
    "Joshua",
    "Michelle",
    "Kenneth",
    "Dorothy",
    "Kevin",
    "Carol",
    "Brian",
    "Amanda",
    "George",
    "Melissa",
    "Timothy",
    "Deborah",
    "Oliver",
    "Emma",
    "Noah",
    "Olivia",
    "Liam",
    "Ava",
    "Sophia",
    "Isabella",
    "Mia",
    "Charlotte",
)

_LAST_NAMES = (
    "Smith",
    "Johnson",
    "Williams",
    "Brown",
    "Jones",
    "Garcia",
    "Miller",
    "Davis",
    "Rodriguez",
    "Martinez",
    "Hernandez",
    "Lopez",
    "Gonzalez",
    "Wilson",
    "Anderson",
    "Thomas",
    "Taylor",
    "Moore",
    "Jackson",
    "Martin",
    "Lee",
    "Perez",
    "Thompson",
    "White",
    "Harris",
    "Sanchez",
    "Clark",
    "Ramirez",
    "Lewis",
    "Robinson",
    "Walker",
    "Young",
    "Allen",
    "King",
    "Wright",
    "Scott",
    "Torres",
    "Nguyen",
    "Hill",
    "Flores",
    "Green",
    "Adams",
    "Nelson",
    "Baker",
    "Hall",
    "Rivera",
    "Campbell",
    "Mitchell",
    "Carter",
    "Roberts",
)


def _rand_token(n: int = 8) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _pick_name(pool: tuple[str, ...]) -> str:
    return pool[secrets.randbelow(len(pool))]


def generate_password(length: int = 16) -> str:
    """Mixed-case + digit + symbol password suitable for most signup rules."""
    length = max(10, length)
    # urlsafe can include '-' '_' ; ensure trailing complexity markers.
    base = secrets.token_urlsafe(length)[: max(1, length - 4)]
    password = (base + "Aa1!")[:length]
    if len(password) < length:
        password = (password + "x" * length)[:length]
    return password


def generate_account(
    *,
    email_domain: str = "example.test",
    password_length: int = 16,
    first_name: str | None = None,
    last_name: str | None = None,
) -> AccountProfile:
    """Build a registration identity with alphabetic human names by default."""
    token = _rand_token(10)
    username = f"user_{token}"
    email = f"{username}@{email_domain}"
    password = generate_password(password_length)
    fn = first_name if first_name else _pick_name(_FIRST_NAMES)
    ln = last_name if last_name else _pick_name(_LAST_NAMES)
    # Guard: names must stay letter-only for strict forms (e.g. mail.com).
    if not fn.isalpha() or not ln.isalpha():
        fn, ln = "James", "Wilson"
    return AccountProfile(
        email=email,
        password=password,
        username=username,
        first_name=fn,
        last_name=ln,
        extra={"uuid": str(uuid.uuid4())},
    )
