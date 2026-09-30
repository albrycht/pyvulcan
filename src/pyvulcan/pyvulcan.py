import abc
import argparse
import base64
import configparser
import dataclasses
import datetime
import hashlib
import html
import json
import logging
import mimetypes
import os
import re
import smtplib
import sys
import time
from configparser import ConfigParser
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from http import client as http_client
from pathlib import Path
from textwrap import dedent
from urllib.parse import quote, urljoin

import boto3
import requests
from bs4 import BeautifulSoup
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, LargeBinary, String
from sqlalchemy.engine import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()

FAILED_TO_DOWNLOAD_ATTACHMENT_DATA = "Failed to download attachment data!"
TRUE_VALUES = ("yes", "on", "true", "1")
FALSE_VALUES = ("no", "off", "false", "0")
LINK_EXPIRE_DURATION = 604800  # 7 days is maximum possible for S3 pre-signed URLs
DEFAULT_WEBHOOK_ATTACHMENTS_SOURCE = "vulcan_link"
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"

logger = logging.getLogger(__name__)


def str_to_bool(s: str):
    if s is None:
        return None
    s = s.lower()
    if s in TRUE_VALUES:
        return True
    elif s in FALSE_VALUES:
        return False
    else:
        raise ValueError(f"Invalid boolean value: {s}. Should be one of: {list(TRUE_VALUES) + list(FALSE_VALUES)} ")


def str_to_int(s: str):
    if s is None:
        return None
    return int(s)


@dataclasses.dataclass(slots=True)
class PyVulcanConfig:
    workdir: str
    send_message: str = "unread"
    fetch_attachments: bool = True
    max_age_of_sending_msg_days: int = 4
    debug: bool = False
    sleep_between_users: int = 10
    cookie_file: str = "pyvulcan_cookies.json"

    def __post_init__(self):
        for field in dataclasses.fields(self):
            if not isinstance(field.default, dataclasses._MISSING_TYPE) and getattr(self, field.name) is None:
                setattr(self, field.name, field.default)
        if self.send_message not in ("unread", "unsent"):
            raise ValueError("SEND_MESSAGE should be 'unread' or 'unsent'")

    @classmethod
    def from_config(cls, workdir: str, config: ConfigParser) -> "PyVulcanConfig":
        global_config = config["global"]
        return cls(
            send_message=global_config.get("send_message", None),
            fetch_attachments=global_config.getboolean("fetch_attachments", None),
            max_age_of_sending_msg_days=global_config.getint("max_age_of_sending_msg_days", None),
            debug=global_config.getboolean("debug", None),
            sleep_between_users=global_config.getint("sleep_between_users", None),
            cookie_file=global_config.get("cookie_file", None),
            workdir=workdir,
        )

    @classmethod
    def from_env(cls, workdir: str) -> "PyVulcanConfig":
        return cls(
            send_message=os.environ.get("SEND_MESSAGE"),
            fetch_attachments=str_to_bool(os.environ.get("FETCH_ATTACHMENTS")),
            max_age_of_sending_msg_days=str_to_int(os.environ.get("MAX_AGE_OF_SENDING_MSG_DAYS")),
            debug=str_to_bool(os.environ.get("VULCAN_DEBUG")),
            workdir=workdir,
        )


def validate_fields(instance):
    for field in dataclasses.fields(instance):
        value = getattr(instance, field.name)
        if value is None or value == "":
            raise ValueError(f"The field '{field.name}' cannot be None.")


class Notify(abc.ABC):
    @staticmethod
    def is_email() -> bool:
        return False

    @staticmethod
    def is_webhook() -> bool:
        return False


@dataclasses.dataclass(slots=True)
class EmailNotify(Notify):
    smtp_user: str
    smtp_pass: str = dataclasses.field(repr=False)
    smtp_server: str
    email_dest: list[str] | str
    smtp_port: int = 587

    @staticmethod
    def is_email() -> bool:
        return True

    def __post_init__(self):
        if isinstance(self.email_dest, str):
            self.email_dest = [email.strip() for email in self.email_dest.split(",")]
        for field in dataclasses.fields(self):
            if not isinstance(field.default, dataclasses._MISSING_TYPE) and getattr(self, field.name) is None:
                setattr(self, field.name, field.default)
        validate_fields(self)

    @classmethod
    def from_env(cls) -> "EmailNotify":
        return cls(
            smtp_user=os.environ.get("SMTP_USER", "Default user"),
            smtp_pass=os.environ.get("SMTP_PASS"),
            smtp_server=os.environ.get("SMTP_SERVER"),
            smtp_port=int(os.environ.get("SMTP_PORT", "587")),
            email_dest=os.environ.get("EMAIL_DEST"),
        )

    @classmethod
    def from_config(cls, config, section) -> "EmailNotify":
        return cls(
            smtp_user=config[section]["smtp_user"],
            smtp_pass=config[section]["smtp_pass"],
            smtp_server=config[section]["smtp_server"],
            smtp_port=int(config[section].get("smtp_port", "587")),
            email_dest=config[section]["email_dest"],
        )


@dataclasses.dataclass(slots=True)
class WebhookNotify(Notify):
    webhook: str = dataclasses.field(repr=False)
    webhook_attachments_source: str = DEFAULT_WEBHOOK_ATTACHMENTS_SOURCE
    s3_region: str | None = None
    s3_access_key_id: str | None = dataclasses.field(default=None, repr=False)
    s3_secret_access_key: str | None = dataclasses.field(default=None, repr=False)
    s3_session_token: str | None = dataclasses.field(default=None, repr=False)
    s3_endpoint_url: str | None = None

    @staticmethod
    def is_webhook() -> bool:
        return True

    def __post_init__(self):
        if not self.webhook:
            raise ValueError("The field 'webhook' cannot be None.")
        if (
            self.webhook_attachments_source != DEFAULT_WEBHOOK_ATTACHMENTS_SOURCE
            and not self.webhook_attachments_source.startswith("s3://")
        ):
            raise ValueError(
                f"webhook_attachments_source should be '{DEFAULT_WEBHOOK_ATTACHMENTS_SOURCE}' or start with 's3://'"
            )
        if self.webhook_attachments_source.startswith("s3://"):
            bucket_name, _ = parse_s3_source(self.webhook_attachments_source)
            if not bucket_name:
                raise ValueError("Invalid webhook_attachments_source. Expected: s3://<bucket>/<optional-prefix>")
            if not self.s3_region:
                raise ValueError("s3_region is required when webhook_attachments_source uses s3://")
            if not self.s3_access_key_id:
                raise ValueError("s3_access_key_id is required when webhook_attachments_source uses s3://")
            if not self.s3_secret_access_key:
                raise ValueError("s3_secret_access_key is required when webhook_attachments_source uses s3://")

    @classmethod
    def from_env(cls) -> "WebhookNotify":
        return cls(
            webhook=os.environ.get("WEBHOOK"),
            webhook_attachments_source=os.environ.get("WEBHOOK_ATTACHMENTS_SOURCE")
            or DEFAULT_WEBHOOK_ATTACHMENTS_SOURCE,
            s3_region=os.environ.get("S3_REGION"),
            s3_access_key_id=os.environ.get("S3_ACCESS_KEY_ID"),
            s3_secret_access_key=os.environ.get("S3_SECRET_ACCESS_KEY"),
            s3_session_token=os.environ.get("S3_SESSION_TOKEN"),
            s3_endpoint_url=os.environ.get("S3_ENDPOINT_URL"),
        )

    @classmethod
    def from_config(cls, config, section):
        return cls(
            webhook=config[section]["webhook"],
            webhook_attachments_source=config[section].get(
                "webhook_attachments_source",
                DEFAULT_WEBHOOK_ATTACHMENTS_SOURCE,
            ),
            s3_region=config[section].get("s3_region"),
            s3_access_key_id=config[section].get("s3_access_key_id"),
            s3_secret_access_key=config[section].get("s3_secret_access_key"),
            s3_session_token=config[section].get("s3_session_token"),
            s3_endpoint_url=config[section].get("s3_endpoint_url"),
        )


@dataclasses.dataclass(slots=True)
class VulcanUser:
    login: str
    password: str = dataclasses.field(repr=False)
    name: str
    notify: EmailNotify | WebhookNotify
    db_name: str
    # Substring of the mailbox name (e.g. child's first name) - selects the mailbox when one
    # eduVulcan login has access to more than one child. Empty = all mailboxes.
    student: str = ""

    @classmethod
    def from_config(cls, config, section) -> "VulcanUser":
        name = section.split(":", 1)[1]
        # Determine whether the user uses email or webhook notification
        if "email_dest" in config[section]:
            notify = EmailNotify.from_config(config, section)
        elif "webhook" in config[section]:
            notify = WebhookNotify.from_config(config, section)
        else:
            raise ValueError(f"No valid notification method for {section}")
        db_name = config[section].get("db_name")
        if not db_name:
            db_name = config["global"].get("db_name", "pyvulcan.sqlite")
        return cls(
            name=name,
            login=config[section]["vulcan_user"],
            password=config[section]["vulcan_pass"],
            student=config[section].get("student", ""),
            notify=notify,
            db_name=db_name,
        )

    @classmethod
    def from_env(cls) -> "VulcanUser":
        return cls(
            login=os.environ.get("VULCAN_USER"),
            password=os.environ.get("VULCAN_PASS"),
            name=os.environ.get("VULCAN_NAME"),
            student=os.environ.get("VULCAN_STUDENT", ""),
            notify=WebhookNotify.from_env() if os.environ.get("WEBHOOK") else EmailNotify.from_env(),
            db_name=os.environ.get("DB_NAME", "pyvulcan.sqlite"),
        )

    @classmethod
    def load_vulcan_users_from_config(cls, config: ConfigParser) -> list["VulcanUser"]:
        return [cls.from_config(config, section) for section in config.sections() if section.startswith("user:")]


class Msg(Base):
    __tablename__ = "messages"

    key = Column(String, primary_key=True)  # apiGlobalKey (GUID) of the message
    id = Column(Integer)
    tenant = Column(String)
    mailbox = Column(String)
    sender = Column(String)
    subject = Column(String)
    date = Column(DateTime)
    contents_html = Column(String)
    contents_text = Column(String)
    email_sent = Column(Boolean, default=False)


class Attachment(Base):
    __tablename__ = "attachments"

    link_id = Column(String, primary_key=True)
    msg_key = Column(String, ForeignKey(Msg.key))
    name = Column(String)
    url = Column(String)
    data = Column(LargeBinary)
    s3_key = Column(String, nullable=True)
    s3_upload_date = Column(DateTime, nullable=True)
    s3_etag = Column(String, nullable=True)


def parse_s3_source(webhook_attachments_source: str) -> tuple[str | None, str]:
    if not webhook_attachments_source or not webhook_attachments_source.startswith("s3://"):
        return None, ""
    source_without_scheme = webhook_attachments_source[len("s3://") :]
    if not source_without_scheme:
        return None, ""
    bucket_name, _, raw_prefix = source_without_scheme.partition("/")
    if not bucket_name:
        return None, ""
    return bucket_name, raw_prefix.strip("/")


def is_s3_webhook_source(webhook_attachments_source: str) -> bool:
    return bool(webhook_attachments_source and webhook_attachments_source.startswith("s3://"))


def sanitize_s3_segment(segment: str, fallback: str = "item") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", (segment or "").strip())
    return cleaned or fallback


def build_download_content_disposition(file_name: str) -> str:
    safe_ascii_name = file_name.encode("ascii", "ignore").decode() or "attachment"
    encoded_file_name = quote(file_name, safe="")
    return f"attachment; filename=\"{safe_ascii_name}\"; filename*=UTF-8''{encoded_file_name}"


class S3AttachmentStorage:
    def __init__(self, webhook_notify: WebhookNotify):
        bucket_name, key_prefix = parse_s3_source(webhook_notify.webhook_attachments_source)
        if not bucket_name:
            raise ValueError("Missing bucket name in webhook_attachments_source")
        self._bucket_name = bucket_name
        self._key_prefix = key_prefix
        self._client = boto3.client(
            "s3",
            region_name=webhook_notify.s3_region,
            aws_access_key_id=webhook_notify.s3_access_key_id,
            aws_secret_access_key=webhook_notify.s3_secret_access_key,
            aws_session_token=webhook_notify.s3_session_token or None,
            endpoint_url=webhook_notify.s3_endpoint_url or None,
        )

    def build_object_key(self, user_name: str, msg_key: str, attachment: Attachment) -> str:
        user_segment = sanitize_s3_segment(user_name, fallback="user")
        msg_segment = hashlib.sha1(msg_key.encode("utf-8"), usedforsecurity=False).hexdigest()[:12]
        attachment_segment = sanitize_s3_segment(attachment.link_id, fallback="attachment")
        name_segment = sanitize_s3_segment(attachment.name, fallback="file")
        parts = [p for p in (self._key_prefix, user_segment, msg_segment, f"{attachment_segment}_{name_segment}") if p]
        return "/".join(parts)

    def upload_attachment(self, user_name: str, msg_key: str, attachment: Attachment) -> tuple[str, str]:
        object_key = attachment.s3_key or self.build_object_key(user_name, msg_key, attachment)
        content_type = mimetypes.guess_type(attachment.name)[0] or "application/octet-stream"
        response = self._client.put_object(
            Bucket=self._bucket_name,
            Key=object_key,
            Body=attachment.data,
            ContentType=content_type,
            ContentDisposition=build_download_content_disposition(attachment.name),
        )
        return object_key, str(response.get("ETag", "")).strip('"')

    def generate_download_link(self, attachment: Attachment) -> str:
        if not attachment.s3_key:
            raise ValueError("Missing s3_key for pre-signed URL generation")
        return self._client.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": self._bucket_name,
                "Key": attachment.s3_key,
                "ResponseContentDisposition": build_download_content_disposition(attachment.name),
            },
            ExpiresIn=LINK_EXPIRE_DURATION,
        )


class SessionExpired(Exception):
    pass


def solve_pow_captcha(challenge: str, difficulty: int, rounds: int) -> str:
    """Proof-of-work captcha used by eduvulcan.pl login form (see README - API notes).

    For every round find the smallest nonce such that the first 4 bytes (big-endian) of
    sha256(buffer + str(nonce)) are below `difficulty`. The buffer accumulates the nonces.
    """
    buffer = challenge
    nonces = []
    for _ in range(rounds):
        nonce = 1
        while int.from_bytes(hashlib.sha256(f"{buffer}{nonce}".encode()).digest()[:4], "big") >= difficulty:
            nonce += 1
        nonces.append(str(nonce))
        buffer += str(nonce)
    return ";".join(nonces)


class VulcanClient:
    """Client for eduVULCAN web messages module (wiadomosci.eduvulcan.pl).

    Flow:
      1. eduvulcan.pl/logowanie - login form (+ optional proof-of-work captcha)
      2. eduvulcan.pl/api/ap - JSON with one JWT per student; `tenant` claim is the school symbol
      3. wiadomosci.eduvulcan.pl/<tenant>/App - WS-Federation SSO via auto-submitted forms,
         final page contains antiForgeryToken used as X-V-RequestVerificationToken header
      4. wiadomosci.eduvulcan.pl/<tenant>/api/... - JSON API

    All cookies are persisted per login, so a run every few minutes keeps the session alive and a
    password login happens only after the server-side session expires.
    """

    EDUVULCAN_URL = "https://eduvulcan.pl"
    MESSAGES_URL = "https://wiadomosci.eduvulcan.pl"
    MAX_SSO_HOPS = 8

    def __init__(self, login: str, passwd: str, pyvulcan_config: PyVulcanConfig):
        self._login = login
        self._passwd = passwd
        self._config = pyvulcan_config
        self._session = requests.session()
        self._session.headers.update({"User-Agent": USER_AGENT, "Accept-Language": "pl"})
        self._state_path = Path(self._config.workdir) / self._config.cookie_file
        self._tenants: list[str] = []
        self._anti_forgery: dict[str, str] = {}  # tenant -> antiForgeryToken
        self._logged_in_this_run = False
        self.load_state()

    # --- state persistence -------------------------------------------------

    def _load_state_per_login(self) -> dict:
        try:
            return json.loads(self._state_path.read_text())
        except FileNotFoundError:
            return {}
        except Exception as e:
            logger.info(f"Could not load {self._state_path}: {e}")
            return {}

    def load_state(self) -> None:
        state = self._load_state_per_login().get(self._login) or {}
        self._tenants = state.get("tenants", [])
        for entry in state.get("cookies", []):
            cookie = requests.cookies.create_cookie(
                name=entry["name"],
                value=entry["value"],
                domain=entry.get("domain", ""),
                path=entry.get("path", "/"),
            )
            self._session.cookies.set_cookie(cookie)

    def store_state(self) -> None:
        state_per_login = self._load_state_per_login()
        state_per_login[self._login] = {
            "tenants": self._tenants,
            "cookies": [
                {"name": c.name, "value": c.value, "domain": c.domain, "path": c.path} for c in self._session.cookies
            ],
        }
        self._state_path.write_text(json.dumps(state_per_login))
        self._state_path.chmod(0o600)

    # --- login -------------------------------------------------------------

    def _password_login(self) -> None:
        logger.info(f"Logging in to eduVULCAN as {self._login}")
        self._session.cookies.clear()
        self._session.post(f"{self.EDUVULCAN_URL}/Account/QueryUserInfo", data={"UserName": self._login})
        login_url = f"{self.EDUVULCAN_URL}/logowanie"
        soup = BeautifulSoup(self._session.get(login_url).text, "html.parser")
        token_input = soup.find("input", {"name": "__RequestVerificationToken"})
        if token_input is None:
            raise RuntimeError("Login page has no __RequestVerificationToken")
        form = {
            "UserName": self._login,
            "Password": self._passwd,
            "captcha-response": "",
            "__RequestVerificationToken": token_input["value"],
        }
        resp = self._session.post(login_url, data=form, allow_redirects=False)
        captcha = soup.find("div", class_="captcha-wrapper")
        if resp.status_code != 302 and captcha is not None and captcha.get("data-challenge"):
            # Plain login was rejected - retry with solved proof-of-work captcha
            logger.info("Solving login captcha")
            form["captcha-response"] = solve_pow_captcha(
                captcha["data-challenge"],
                int(captcha["data-difficulty"]),
                int(captcha["data-rounds"]),
            )
            resp = self._session.post(login_url, data=form, allow_redirects=False)
        if resp.status_code != 302:
            raise RuntimeError(f"eduVULCAN login failed (HTTP {resp.status_code}) - check vulcan_user/vulcan_pass")
        self._session.get(urljoin(login_url, resp.headers.get("Location", "/")))
        self._logged_in_this_run = True

    def _discover_tenants(self) -> list[str]:
        resp = self._session.get(f"{self.EDUVULCAN_URL}/api/ap")
        ap_input = BeautifulSoup(resp.text, "html.parser").find("input", id="ap")
        if ap_input is None:
            raise SessionExpired("eduvulcan.pl/api/ap - not logged in")
        ap = json.loads(html.unescape(ap_input["value"]))
        if not ap.get("Success"):
            raise RuntimeError(f"eduvulcan.pl/api/ap failed: {ap.get('ErrorMessage')}")
        tenants = []
        for token in ap.get("Tokens") or []:
            payload = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
            logger.info(f"Found student {payload.get('name')} in {payload.get('tenant')}")
            if payload.get("tenant") and payload["tenant"] not in tenants:
                tenants.append(payload["tenant"])
        if not tenants:
            raise RuntimeError("No students assigned to this eduVULCAN account")
        return tenants

    def _follow_sso_forms(self, resp: requests.Response) -> requests.Response:
        """Submits WS-Federation "Working..." auto-post forms (wa/wresult/wctx) until the final page."""
        for _ in range(self.MAX_SSO_HOPS):
            form = BeautifulSoup(resp.text, "html.parser").find("form")
            if form is None or form.find("input", {"name": "wresult"}) is None:
                return resp
            data = {i["name"]: i.get("value", "") for i in form.find_all("input") if i.get("name")}
            resp = self._session.post(urljoin(resp.url, form["action"]), data=data)
        raise RuntimeError("Too many SSO redirects")

    def _open_messages_app(self, tenant: str) -> bool:
        resp = self._follow_sso_forms(self._session.get(f"{self.MESSAGES_URL}/{tenant}/App"))
        match = re.search(r"antiForgeryToken\s*:\s*'([^']*)'", resp.text)
        if not resp.url.startswith(self.MESSAGES_URL) or match is None:
            logger.debug(f"Messages app not available, ended at {resp.url}")
            return False
        self._anti_forgery[tenant] = match.group(1)
        return True

    def __enter__(self):
        if not self._tenants:
            try:
                self._tenants = self._discover_tenants()
            except SessionExpired:
                self._password_login()
                self._tenants = self._discover_tenants()
        for tenant in self._tenants:
            if self._open_messages_app(tenant):
                continue
            if self._logged_in_this_run:
                raise RuntimeError(f"Could not open messages module for {tenant} right after login")
            logger.info("Session expired, logging in again")
            self._password_login()
            self._tenants = self._discover_tenants()
            return self.__enter__()
        logger.info(f"Session ready for {self._login} (fresh login: {self._logged_in_this_run})")
        self.store_state()
        return self

    def __exit__(self, exc_type=None, exc_val=None, exc_tb=None):
        # Cookies may be refreshed by the server on every call - always persist them
        self.store_state()

    # --- messages API ------------------------------------------------------

    @property
    def tenants(self) -> list[str]:
        return list(self._tenants)

    def _api_get(self, tenant: str, path: str, **params):
        resp = self._session.get(
            f"{self.MESSAGES_URL}/{tenant}/api/{path}",
            params=params,
            headers={
                "Accept": "application/json",
                "X-Requested-With": "XMLHttpRequest",
                "X-V-RequestVerificationToken": self._anti_forgery.get(tenant, ""),
                "Referer": f"{self.MESSAGES_URL}/{tenant}/App/odebrane",
            },
            allow_redirects=False,
        )
        if resp.status_code != 200:
            # 409 is returned when the session is gone
            raise SessionExpired(f"GET api/{path} returned HTTP {resp.status_code}")
        return resp.json()

    def mailboxes(self, tenant: str) -> list[dict]:
        """[{"globalKey": GUID, "nazwa": "Parent - R - Child - (unit)", "typUzytkownika": 2}]"""
        return self._api_get(tenant, "Skrzynki")

    def received(self, tenant: str, mailbox_key: str, page_size: int = 50) -> list[dict]:
        """Newest first. Items: apiGlobalKey, id, data, temat, korespondenci, hasZalaczniki, przeczytana, ..."""
        return self._api_get(
            tenant,
            "OdebraneSkrzynka",
            globalKeySkrzynka=mailbox_key,
            idLastWiadomosc=0,
            pageSize=page_size,
        )

    def message_details(self, tenant: str, api_global_key: str) -> dict:
        """Does NOT mark the message as read. Keys: nadawca, odbiorcy, temat, tresc (HTML), data, zalaczniki."""
        return self._api_get(tenant, "WiadomoscSzczegoly", apiGlobalKey=api_global_key)

    def download_attachment(self, url: str) -> bytes:
        resp = self._session.get(url, headers={"Referer": f"{self.MESSAGES_URL}/"})
        resp.raise_for_status()
        if "text/html" in resp.headers.get("content-type", ""):
            raise RuntimeError(f"Expected file, got HTML page from {resp.url}")
        return resp.content


def parse_vulcan_date(s: str) -> datetime.datetime:
    """'2026-09-17T12:50:20.877+02:00' -> naive local (Europe/Warsaw) datetime"""
    return datetime.datetime.fromisoformat(s).replace(tzinfo=None)


def html_to_text(contents_html: str) -> str:
    soup = BeautifulSoup(contents_html or "", "html.parser")
    for br in soup.find_all("br"):
        br.replace_with("\n")
    for p in soup.find_all(["p", "div", "li"]):
        p.insert_after("\n")
    return re.sub(r"\n{3,}", "\n\n", soup.get_text()).strip()


class VulcanNotifier:
    def __init__(self, pyvulcan_config: PyVulcanConfig, vulcan_user: VulcanUser):
        self._config = pyvulcan_config
        self._vulcan_user = vulcan_user
        self._engine = None
        self._session = None

    def _create_db(self):
        workdir_path = Path(self._config.workdir)
        if not workdir_path.exists():
            raise RuntimeError(f"Workdir {workdir_path} does not exist")
        self._engine = create_engine(f"sqlite:///{workdir_path / self._vulcan_user.db_name}")
        Base.metadata.create_all(self._engine)
        self._session = sessionmaker(bind=self._engine)()

    def __enter__(self):
        self._create_db()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self._session.commit()
        else:
            self._session.rollback()

    def commit(self):
        self._session.commit()

    def get_msg(self, key):
        return self._session.get(Msg, key)

    def add_msg(self, msg: Msg, attachments: list[Attachment]) -> Msg:
        existing = self.get_msg(msg.key)
        if existing:
            return existing
        self._session.add(msg)
        for attachment in attachments:
            self._session.add(attachment)
        return msg

    def notify(self, msg_from_db):
        if self._vulcan_user.notify.is_webhook():
            logger.info(f"Sending '{msg_from_db.subject}' to webhook from {msg_from_db.sender} ({msg_from_db.date})")
            self.send_via_webhook(msg_from_db)
        else:
            logger.info(
                f"Sending '{msg_from_db.subject}' to {self._vulcan_user.notify.email_dest} from {msg_from_db.sender}"
            )
            self.send_email(msg_from_db)

    def _get_attachments(self, msg_from_db) -> list[Attachment]:
        if not self._session:
            return []
        return self._session.query(Attachment).filter(Attachment.msg_key == msg_from_db.key).all()

    @staticmethod
    def _vulcan_attachment_links(attachments: list[Attachment]) -> list[tuple[str, str]]:
        return [(a.name, a.url) for a in attachments]

    def _s3_attachment_links(self, msg_from_db, attachments: list[Attachment]) -> list[tuple[str, str]]:
        links: list[tuple[str, str]] = []
        storage = S3AttachmentStorage(self._vulcan_user.notify)
        for attach in attachments:
            if attach.data is None:
                logger.warning(f"Attachment '{attach.name}' has no data in DB, fallback to Vulcan link")
                links.append((attach.name, attach.url))
                continue
            try:
                if not attach.s3_key:
                    attach.s3_key, attach.s3_etag = storage.upload_attachment(
                        user_name=self._vulcan_user.name,
                        msg_key=msg_from_db.key,
                        attachment=attach,
                    )
                    attach.s3_upload_date = datetime.datetime.now()
                    logger.info(f"Uploaded attachment '{attach.name}' to S3 key '{attach.s3_key}'")
                else:
                    logger.info(f"Reusing uploaded S3 key for attachment '{attach.name}': {attach.s3_key}")
                links.append((attach.name, storage.generate_download_link(attach)))
            except Exception as ex:
                logger.warning(f"Failed to upload/presign attachment '{attach.name}' ({ex}), fallback to Vulcan link")
                links.append((attach.name, attach.url))
        return links

    def _build_webhook_attachment_links(self, msg_from_db) -> list[tuple[str, str]]:
        attachments = self._get_attachments(msg_from_db)
        if not attachments:
            return []
        if not is_s3_webhook_source(self._vulcan_user.notify.webhook_attachments_source):
            return self._vulcan_attachment_links(attachments)
        try:
            return self._s3_attachment_links(msg_from_db, attachments)
        except Exception as ex:
            logger.warning(f"Failed to initialize S3 attachment storage ({ex}), fallback to Vulcan links")
            return self._vulcan_attachment_links(attachments)

    def send_via_webhook(self, msg_from_db):
        attachment_links = self._build_webhook_attachment_links(msg_from_db)

        msg = (
            dedent(f"""
        *VULCAN {self._vulcan_user.name} - {msg_from_db.date}*
        *Od: {msg_from_db.sender}*
        *Temat: {msg_from_db.subject}*
        """)
            + f"\n{msg_from_db.contents_text}"
        )
        if attachment_links:
            msg += "\n\nZałączniki:\n"
            for attachment_name, link in attachment_links:
                msg += f"- <{link}|{attachment_name}>\n"

        response = requests.post(
            self._vulcan_user.notify.webhook,
            data=json.dumps({"text": msg}),
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        if response.status_code != 200:
            raise RuntimeError(f"Failed to send message to webhook. Status code: {response.status_code}")

    @staticmethod
    def format_sender(sender_info, sender_email):
        sender_b64 = base64.b64encode(sender_info.encode())
        sender_info_encoded = "=?utf-8?B?" + sender_b64.decode() + "?="
        return f'"{sender_info_encoded}" <{sender_email}>'

    def send_email(self, msg_from_db):
        msg = MIMEMultipart("alternative")
        msg.set_charset("utf-8")

        msg["Subject"] = msg_from_db.subject
        msg["From"] = self.format_sender(msg_from_db.sender, self._vulcan_user.notify.smtp_user)
        msg["To"] = ", ".join(self._vulcan_user.notify.email_dest)

        attachments = self._get_attachments(msg_from_db)
        attachments_only_with_link = [a for a in attachments if a.data is None]
        attachments_with_data = [a for a in attachments if a.data is not None]
        attachments_as_text_msg = (
            ""
            if not attachments_only_with_link
            else "\n\nZałączniki:\n - " + "\n - ".join(f"{a.name}: {a.url}" for a in attachments_only_with_link)
        )
        attachments_as_html_msg = (
            ""
            if not attachments_only_with_link
            else "<br/><br/><p>Załączniki:<p><ul>"
            + "".join(f"<li><a href='{a.url}'>{a.name}</a></li>" for a in attachments_only_with_link)
            + "</ul>"
        )

        msg.attach(MIMEText(msg_from_db.contents_html + attachments_as_html_msg, "html"))
        msg.attach(MIMEText(msg_from_db.contents_text + attachments_as_text_msg, "plain"))
        for attach in attachments_with_data:
            part = MIMEApplication(attach.data, Name=attach.name)
            part["Content-Disposition"] = f'attachment; filename="{attach.name}"'
            msg.attach(part)

        server = smtplib.SMTP(self._vulcan_user.notify.smtp_server, self._vulcan_user.notify.smtp_port)
        server.ehlo()
        server.starttls()
        server.login(self._vulcan_user.notify.smtp_user, self._vulcan_user.notify.smtp_pass)
        server.sendmail(self._vulcan_user.notify.smtp_user, self._vulcan_user.notify.email_dest, msg.as_string())
        server.close()


def read_pyvulcan_config(workdir: str, config_file: str) -> tuple[PyVulcanConfig, list[VulcanUser]]:
    config_path = Path(workdir) / config_file
    if config_path.exists():
        logger.info(f"Read config from file: {config_path}")
        config = configparser.ConfigParser()
        config.read(config_path)
        return PyVulcanConfig.from_config(workdir, config), VulcanUser.load_vulcan_users_from_config(config)
    logger.info(f"Could not find config file: {config_path}, read config from env variables")
    return PyVulcanConfig.from_env(workdir), [VulcanUser.from_env()]


def send_test_notification(pyvulcan_config: PyVulcanConfig, vulcan_user: VulcanUser):
    notifier = VulcanNotifier(pyvulcan_config, vulcan_user)
    msg = Msg(
        key="fake-message",
        sender="Testing sender Żółta Jaźń [ŻJ] - P - (000000)",
        date=datetime.datetime.now(),
        subject="Testing subject with żółta jaźń",
        contents_html="<h2>html content with żółta jaźń</h2>",
        contents_text="text content with żółta jaźń",
    )
    logger.info("Sending testing notify")
    notifier.notify(msg)
    return 2


def should_fetch_attachment_content(pyvulcan_config: PyVulcanConfig, vulcan_user: VulcanUser) -> bool:
    return pyvulcan_config.fetch_attachments and (
        vulcan_user.notify.is_email()
        or (vulcan_user.notify.is_webhook() and is_s3_webhook_source(vulcan_user.notify.webhook_attachments_source))
    )


def fetch_msg(client: VulcanClient, tenant: str, mailbox: dict, item: dict, fetch_content: bool):
    details = client.message_details(tenant, item["apiGlobalKey"])
    msg = Msg(
        key=item["apiGlobalKey"],
        id=item.get("id"),
        tenant=tenant,
        mailbox=mailbox["nazwa"],
        sender=details.get("nadawca") or item.get("korespondenci"),
        subject=details.get("temat") or item.get("temat"),
        date=parse_vulcan_date(details.get("data") or item["data"]),
        contents_html=details.get("tresc") or "",
        contents_text=html_to_text(details.get("tresc")),
    )
    attachments = []
    for zal in details.get("zalaczniki") or []:
        name = zal.get("nazwaPliku") or "attachment"
        url = zal.get("url") or ""
        attachment = Attachment(
            link_id=f"{msg.key}:{zal.get('idZalacznik') or url}",
            msg_key=msg.key,
            name=name,
            url=url,
            data=None,
        )
        if fetch_content and url:
            logger.info(f"Download attachment {name}")
            try:
                attachment.data = client.download_attachment(url)
            except Exception as ex:
                reason = f"Failed to download attachment: {ex}"
                logger.warning(reason)
                attachment.data = reason.encode()
            logger.info(f"{attachment.name=} {len(attachment.data)=}")
        attachments.append(attachment)
    return msg, attachments


def handle_user(pyvulcan_config: PyVulcanConfig, vulcan_user: VulcanUser):
    fetch_content = should_fetch_attachment_content(pyvulcan_config, vulcan_user)
    max_age = datetime.timedelta(days=pyvulcan_config.max_age_of_sending_msg_days)
    with VulcanClient(vulcan_user.login, vulcan_user.password, pyvulcan_config) as client:
        with VulcanNotifier(pyvulcan_config, vulcan_user) as notifier:
            for tenant in client.tenants:
                mailboxes = [m for m in client.mailboxes(tenant) if vulcan_user.student.lower() in m["nazwa"].lower()]
                if not mailboxes:
                    logger.info(f"No mailbox matching student='{vulcan_user.student}' in {tenant}")
                for mailbox in mailboxes:
                    # API returns newest first - process oldest first, like pylibrus
                    for item in reversed(client.received(tenant, mailbox["globalKey"])):
                        msg = notifier.get_msg(item["apiGlobalKey"])
                        if not msg:
                            if datetime.datetime.now() - parse_vulcan_date(item["data"]) > max_age:
                                logger.debug(f"Skip '{item['temat']}' (message too old, {item['data']})")
                                continue
                            logger.debug(f"Fetch {item['apiGlobalKey']}")
                            msg, attachments = fetch_msg(client, tenant, mailbox, item, fetch_content)
                            msg = notifier.add_msg(msg, attachments)

                        if pyvulcan_config.send_message == "unsent" and msg.email_sent:
                            logger.debug(f"Do not send '{msg.subject}' (message already sent)")
                        elif pyvulcan_config.send_message == "unread" and item.get("przeczytana"):
                            logger.debug(f"Do not send '{msg.subject}' (message already read)")
                        else:
                            notifier.notify(msg)
                            msg.email_sent = True
                        notifier.commit()


def parse_args():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument("--debug", action="store_true", help="enable debug")

    paths = parser.add_argument_group("Paths")
    paths.add_argument(
        "--config", metavar="PATH", help="config file, can be absolute or relative to workdir", default="pyvulcan.ini"
    )
    paths.add_argument(
        "--cookies",
        metavar="PATH",
        help="cookie/session file, can be absolute or relative to workdir",
        default="pyvulcan_cookies.json",
    )
    paths.add_argument("--workdir", metavar="PATH", help="working directory with config and DBs", default=Path.cwd())

    tests = parser.add_argument_group("Test notifications")
    tests.add_argument("--test-notify", action="store_true", default=False, help="send a test notification")

    return parser.parse_args()


def setup_logging(debug: bool):
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    if debug:
        http_client.HTTPConnection.debuglevel = 1


def main():
    args = parse_args()
    setup_logging(args.debug)

    pyvulcan_config, vulcan_users = read_pyvulcan_config(args.workdir, args.config)
    pyvulcan_config.debug |= args.debug
    pyvulcan_config.cookie_file = args.cookies
    if pyvulcan_config.debug:
        setup_logging(True)
        logging.getLogger().setLevel(logging.DEBUG)
    logger.info(f"Config: {pyvulcan_config}")
    for user in vulcan_users:
        logger.info(f"User: {user}")

    if args.test_notify:
        return send_test_notification(pyvulcan_config, vulcan_users[0])

    failed_users = []
    for i, vulcan_user in enumerate(vulcan_users):
        try:
            handle_user(pyvulcan_config, vulcan_user)
        except Exception:
            # One user failing must not stop the remaining users from being processed.
            failed_users.append(vulcan_user.name)
            logger.exception(f"Failed to handle user {vulcan_user.name}, continuing with remaining users")
        if i != len(vulcan_users) - 1:
            time.sleep(pyvulcan_config.sleep_between_users)

    if failed_users:
        logger.error(f"Failed users: {', '.join(failed_users)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
