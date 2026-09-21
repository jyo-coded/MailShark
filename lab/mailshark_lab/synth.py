"""Synthetic campaign generator for validation.

Public corpora do not say which emails belong to the same operation, so ground truth is produced
here: realistic phishing campaigns whose indicators are rotated at controlled levels, mixed with
unrelated background mail. Rotation levels follow the research design:

    0 none · 1 domain · 2 sender · 3 url · 4 attachment · 5 multiple · 6 almost everything
    7 everything: also rotates the HTML template, mailer software and kit path, the honest limit
      of any correlation approach (see the research paper, section 27).
"""

from __future__ import annotations

import io
import random
import zipfile
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import format_datetime
from datetime import datetime, timedelta, timezone

LEVELS = ["none", "domain", "sender", "url", "attachment", "multiple", "almost-everything", "everything"]

THEMES = [
    ("Microsoft 365", "Your mailbox storage is full", "Your mailbox has exceeded its storage limit. Messages are on hold. Verify your account within 24 hours to release them.", "/owa/{tok}/verify"),
    ("DocuSign", "Please review and sign: {doc}", "You have received a document to review and sign. Access the document with your corporate credentials before it expires.", "/sign/{tok}/view"),
    ("DHL Express", "Delivery failed: customs fee due for {ref}", "Your parcel is on hold. Pay the customs fee to reschedule delivery. Confirm your address today.", "/track/{tok}/pay"),
    ("Accounts Payable", "Overdue invoice {ref}", "Please find the outstanding invoice attached. Kindly settle the payment immediately to avoid late fees.", "/inv/{tok}/download"),
    ("PayPal", "Your account has been limited", "We noticed unusual activity. Your account has been limited until you confirm your identity.", "/webscr/{tok}/signin"),
    ("HR Department", "Salary adjustment {q} {year}", "Please review your updated salary adjustment letter. Sign in to view the confidential document.", "/hr/{tok}/letter"),
    ("IT Help Desk", "Password expiry notice for {user}", "Your password expires today. Keep the same password by validating your account now.", "/pw/{tok}/keep"),
    ("Netflix", "Your membership is on hold", "We were unable to process your payment. Update your billing information to continue watching.", "/billing/{tok}/update"),
    ("WeTransfer", "{user} sent you files", "You received files via WeTransfer. Download them before the link expires in 7 days.", "/dl/{tok}/files"),
    ("Coinbase", "Security alert: new device", "A new device signed in to your wallet. If this wasn't you, secure your wallet now.", "/wallet/{tok}/secure"),
    ("Amazon", "Your order {ref} could not be shipped", "There is a problem with your order. Update your payment method to avoid cancellation.", "/order/{tok}/update"),
    ("Zoom", "Missed meeting recording", "A meeting recording has been shared with you. View the recording with your work account.", "/rec/{tok}/play"),
]

BACKGROUND = [
    ("Weekly digest", "Here are this week's top stories about science and design."),
    ("Lunch friday?", "Want to grab ramen near the office on Friday around one?"),
    ("Build failed on main", "The CI pipeline failed on the lint step. See the logs for details."),
    ("Your receipt", "Thanks for your purchase. Your receipt is attached for your records."),
    ("Meeting notes", "Attached are the notes from today's planning meeting."),
    ("Trip photos", "Finally uploaded the pictures from the trip, let me know which ones you like."),
]

FILLER = (
    "project timeline budget review design team client launch schedule update draft proposal agenda notes feedback results quarter "
    "report dataset model server deploy release branch merge ticket sprint roadmap vendor contract invoice travel booking hotel flight "
    "garden recipe weekend concert movie family birthday photos hiking beach library course lecture exam thesis research paper"
).split()

TLDS = ["com", "net", "org", "info", "top", "xyz", "online", "site"]
WORDS = ["secure", "portal", "account", "verify", "center", "access", "cloud", "docs", "mail", "support", "service", "online", "update", "review"]


@dataclass
class Sample:
    raw: bytes
    campaign: int  # -1 = background
    level: str


def _tok(rng: random.Random, n: int = 18) -> str:
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))


def _domain(rng: random.Random) -> str:
    return f"{rng.choice(WORDS)}-{rng.choice(WORDS)}{rng.randint(1, 99)}.{rng.choice(TLDS)}"


def _ip(rng: random.Random) -> str:
    return f"{rng.randint(20, 220)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _attachment(rng: random.Random, theme: int, repack: bool) -> tuple[str, bytes]:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types/>')
        z.writestr("word/document.xml", f"<w:document>Invoice {theme}{' ' + _tok(rng) if repack else ''}</w:document>")
        z.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0VBA" + (_tok(rng).encode() if repack else b"macro"))
    return f"Invoice_{rng.randint(1000, 9999) if repack else 2031}.docm", buf.getvalue()


def _paraphrase(rng: random.Random, text: str) -> str:
    swaps = {"Verify": "Confirm", "verify": "confirm", "immediately": "right away", "within 24 hours": "today", "Please": "Kindly", "account": "profile"}
    out = text
    for a, b in swaps.items():
        if rng.random() < 0.5:
            out = out.replace(a, b)
    return out


def generate(level: str = "multiple", campaigns: int = 8, per_campaign: int = 12, background: int = 40, seed: int = 7) -> list[Sample]:
    rng = random.Random(seed * 1000 + LEVELS.index(level))
    samples: list[Sample] = []
    start = datetime(2026, 9, 1, 8, 0, tzinfo=timezone.utc)
    for c in range(campaigns):
        brand, subj, body, path = THEMES[c % len(THEMES)]
        base_domain, base_ip, base_sender = _domain(rng), _ip(rng), f"noreply{c}"
        mailer = rng.choice(["PHPMailer 6.8.1", "Microsoft Outlook 16.0", "Mailer v3.2", "Leaf PHPMailer 2.8"])
        attach = c % 3 == 0
        for i in range(per_campaign):
            rot = {
                "none": set(),
                "domain": {"domain"},
                "sender": {"sender"},
                "url": {"url"},
                "attachment": {"attachment"},
                "multiple": {"domain", "sender", "url", "ip"},
                "almost-everything": {"domain", "sender", "url", "ip", "attachment", "subject", "body"},
                "everything": {"domain", "sender", "url", "ip", "attachment", "subject", "body", "template", "tooling", "kit"},
            }[level]
            dom = _domain(rng) if "domain" in rot else base_domain
            sender = f"{rng.choice(['alert', 'support', 'notice', 'service'])}{rng.randint(1, 999)}" if "sender" in rot else base_sender
            url_dom = _domain(rng) if "url" in rot else f"login.{base_domain}"
            ip = _ip(rng) if "ip" in rot else base_ip
            ref = f"INV-{rng.randint(10000, 99999)}"
            subject = subj.format(doc=f"Agreement_{rng.randint(100, 999)}.pdf", ref=ref, q=f"Q{rng.randint(1, 4)}", year=2026, user=f"user{rng.randint(1, 500)}")
            if "subject" in rot and rng.random() < 0.5:
                subject = "Action required: " + subject.lower()
            text = _paraphrase(rng, body) if "body" in rot else body
            kit_path = f"/{rng.choice(WORDS)}/{{tok}}/{rng.choice(WORDS)}" if "kit" in rot else path
            link = f"https://{url_dom}{kit_path.format(tok=_tok(rng))}"
            m = EmailMessage()
            m["Received"] = f"from mail.{dom} (mail.{dom} [{ip}]) by mx.victim.example with ESMTPS id {_tok(rng, 10)}; {format_datetime(start + timedelta(hours=i * 3 + c))}"
            m["From"] = f"{brand} <{sender}@{dom}>"
            m["To"] = f"employee{rng.randint(1, 300)}@victim.example"
            m["Subject"] = subject
            m["Date"] = format_datetime(start + timedelta(hours=i * 3 + c))
            m["Message-ID"] = f"<{rng.randint(10**9, 10**10)}.{rng.randint(1000, 9999)}@{dom}>"
            m["X-Mailer"] = rng.choice(["PHPMailer 6.8.1", "Microsoft Outlook 16.0", "Mailer v3.2", "Leaf PHPMailer 2.8", "Thunderbird 115"]) if "tooling" in rot else mailer
            layout = rng.randrange(3) if "template" in rot else 0
            if layout == 0:
                html = (
                    f'<table class="c{c}-card"><tr><td class="hdr"><b>{brand}</b></td></tr><tr><td class="body"><p>Dear user,</p>'
                    f"<p>{text}</p><p><a class='btn' href='{link}'>Open now</a></p><p class='ft'>{brand} Security</p></td></tr></table>"
                )
            elif layout == 1:
                html = f"<div><h2>{brand}</h2><div><span>Hello,</span><br><span>{text}</span></div><div><a href='{link}'>Continue</a></div></div>"
            else:
                html = f"<p>{text}</p><ul><li><a href='{link}'>{link}</a></li></ul><center>{brand}</center>"
            m.set_content(f"Dear user,\n\n{text}\n\n{link}\n")
            m.add_alternative(html, subtype="html")
            if attach:
                name, data = _attachment(rng, c, "attachment" in rot)
                m.add_attachment(data, maintype="application", subtype="vnd.ms-word.document.macroEnabled.12", filename=name)
            samples.append(Sample(m.as_bytes(), c, level))
    for i in range(background):
        subj, text = BACKGROUND[i % len(BACKGROUND)]
        m = EmailMessage()
        dom = f"{rng.choice(['acme', 'globex', 'initech', 'umbrella', 'hooli', 'wayne'])}{rng.randint(1, 50)}.com"
        m["Received"] = f"from smtp.{dom} (smtp.{dom} [{_ip(rng)}]) by mx.victim.example with ESMTPS id {_tok(rng, 10)}; {format_datetime(start + timedelta(hours=i))}"
        m["From"] = f"{rng.choice(['Asha', 'Ravi', 'Mei', 'Tom', 'Lena'])} <{rng.choice(['asha', 'ravi', 'mei', 'tom', 'lena'])}{i}@{dom}>"
        m["To"] = "employee@victim.example"
        m["Subject"] = f"{subj}: {' '.join(rng.sample(FILLER, 2))}"
        m["Date"] = format_datetime(start + timedelta(hours=i))
        m["Message-ID"] = f"<{_tok(rng, 24)}@{dom}>"
        m.set_content(text + "\n\n" + " ".join(rng.sample(FILLER, 24)) + "\n")
        samples.append(Sample(m.as_bytes(), -1, level))
    rng.shuffle(samples)
    return samples
