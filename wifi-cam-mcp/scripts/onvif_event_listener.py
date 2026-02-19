#!/usr/bin/env python3
"""ONVIF event listener daemon for Tapo C220 person detection.

Subscribes to ONVIF PullPoint events and writes detections to /tmp/ayumu_inbox.

Usage:
    uv run python scripts/onvif_event_listener.py

Environment variables:
    TAPO_CAMERA_HOST    Camera IP (default: 192.168.68.72)
    TAPO_USERNAME       ONVIF username
    TAPO_PASSWORD       ONVIF password
    TAPO_ONVIF_PORT     ONVIF port (default: 2020)
    AYUMU_INBOX         Inbox file path (default: /tmp/ayumu_inbox)
    EVENT_COOLDOWN      Seconds between duplicate events (default: 30)
"""

import asyncio
import hashlib
import logging
import os
import re
import secrets
import signal
import sys
from base64 import b64encode
from datetime import datetime, timezone

import httpx
import onvif
from onvif import ONVIFCamera

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("onvif-listener")

# Config from environment
HOST = os.getenv("TAPO_CAMERA_HOST", "192.168.68.72")
PORT = int(os.getenv("TAPO_ONVIF_PORT", "2020"))
USERNAME = os.getenv("TAPO_USERNAME", "")
PASSWORD = os.getenv("TAPO_PASSWORD", "")
INBOX = os.getenv("AYUMU_INBOX", "/tmp/ayumu_inbox")
COOLDOWN = int(os.getenv("EVENT_COOLDOWN", "30"))

# Track state for edge detection (only notify on changes)
_current_state: dict[str, bool] = {}
_last_change_time: dict[str, float] = {}


def _wsse_header(user: str, password: str) -> str:
    """Generate WS-Security UsernameToken header."""
    nonce = secrets.token_bytes(16)
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    digest_input = nonce + created.encode() + password.encode()
    digest = b64encode(hashlib.sha1(digest_input).digest()).decode()
    nonce_b64 = b64encode(nonce).decode()
    return (
        '<wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/'
        'oasis-200401-wss-wssecurity-secext-1.0.xsd" '
        'xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/'
        'oasis-200401-wss-wssecurity-utility-1.0.xsd">'
        "<wsse:UsernameToken>"
        f"<wsse:Username>{user}</wsse:Username>"
        '<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/'
        'oasis-200401-wss-username-token-profile-1.0#PasswordDigest">'
        f"{digest}</wsse:Password>"
        '<wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/'
        'oasis-200401-wss-soap-message-security-1.0#Base64Binary">'
        f"{nonce_b64}</wsse:Nonce>"
        f"<wsu:Created>{created}</wsu:Created>"
        "</wsse:UsernameToken>"
        "</wsse:Security>"
    )


def _pull_messages_soap(user: str, password: str, timeout_s: int = 10) -> str:
    """Build SOAP envelope for PullMessages."""
    wsse = _wsse_header(user, password)
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:tev="http://www.onvif.org/ver10/events/wsdl">'
        f"<s:Header>{wsse}</s:Header>"
        "<s:Body>"
        "<tev:PullMessages>"
        f"<tev:Timeout>PT{timeout_s}S</tev:Timeout>"
        "<tev:MessageLimit>10</tev:MessageLimit>"
        "</tev:PullMessages>"
        "</s:Body>"
        "</s:Envelope>"
    )


def _parse_events(xml_body: str) -> list[dict[str, str]]:
    """Parse SimpleItem events from SOAP response XML."""
    events = []
    # Find all NotificationMessage blocks
    messages = re.findall(
        r"<wsnt:NotificationMessage>(.*?)</wsnt:NotificationMessage>",
        xml_body,
        re.DOTALL,
    )
    if not messages:
        # Try without namespace prefix
        messages = re.findall(
            r"<NotificationMessage>(.*?)</NotificationMessage>",
            xml_body,
            re.DOTALL,
        )

    for msg in messages:
        topic_match = re.search(r"Topic[^>]*>([^<]+)<", msg)
        topic = topic_match.group(1).strip() if topic_match else "unknown"

        items = re.findall(
            r'SimpleItem\s+Name="([^"]+)"\s+Value="([^"]+)"', msg
        )
        event = {"topic": topic}
        for name, value in items:
            event[name] = value
        events.append(event)

    return events


def _on_state_change(event_type: str, is_active: bool) -> None:
    """Write to inbox only on state transitions (edge detection)."""
    prev = _current_state.get(event_type)
    _current_state[event_type] = is_active

    # Only notify on change (None→True counts as change)
    if prev == is_active:
        return

    # Cooldown: ignore rapid toggling
    now = datetime.now().timestamp()
    last = _last_change_time.get(event_type, 0)
    if now - last < COOLDOWN:
        logger.debug("Cooldown: skipping %s state change", event_type)
        return
    _last_change_time[event_type] = now

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if event_type == "person":
        detail = "人物を検知しました（誰か来た）" if is_active else "人物がいなくなりました"
    elif event_type == "pet":
        detail = "ペットを検知しました" if is_active else "ペットがいなくなりました"
    elif event_type == "tamper":
        detail = "カメラへのタンパーを検知" if is_active else "タンパー解除"
    else:
        detail = f"{event_type} {'ON' if is_active else 'OFF'}"

    line = f"SENSOR: {timestamp} {detail}\n"
    with open(INBOX, "a") as f:
        f.write(line)

    logger.info("State change → inbox: %s", line.strip())


async def _create_subscription(cam: ONVIFCamera) -> str:
    """Create PullPoint subscription and return the subscription address."""
    event_service = await cam.create_events_service()
    sub = await event_service.CreatePullPointSubscription({
        "InitialTerminationTime": "PT600S",  # 10 minutes
    })
    addr = sub.SubscriptionReference.Address._value_1
    logger.info("Subscription created: %s", addr)
    return addr


async def _listen_loop(sub_addr: str) -> None:
    """Pull events in a loop."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        while True:
            try:
                soap = _pull_messages_soap(USERNAME, PASSWORD, timeout_s=10)
                resp = await client.post(
                    sub_addr,
                    content=soap,
                    headers={"Content-Type": "application/soap+xml; charset=utf-8"},
                )

                if resp.status_code != 200:
                    logger.warning("HTTP %d: %s", resp.status_code, resp.text[:200])
                    await asyncio.sleep(5)
                    continue

                events = _parse_events(resp.text)
                for event in events:
                    topic = event.get("topic", "")
                    logger.debug("Event: %s %s", topic, event)

                    # Person detection (edge: notify on appear/disappear)
                    if "IsPeople" in event:
                        _on_state_change("person", event["IsPeople"].lower() == "true")

                    # Motion detection (logged only, too noisy for inbox)
                    if "IsMotion" in event:
                        is_motion = event["IsMotion"].lower() == "true"
                        if is_motion:
                            logger.debug("Motion detected")

                    # Pet detection
                    if "IsPet" in event:
                        _on_state_change("pet", event["IsPet"].lower() == "true")

                    # Tamper detection
                    if "IsTamper" in event:
                        _on_state_change("tamper", event["IsTamper"].lower() == "true")

            except httpx.TimeoutException:
                continue  # Normal timeout, just retry
            except Exception as e:
                logger.error("Pull error: %s", e)
                await asyncio.sleep(5)


async def main() -> None:
    if not USERNAME or not PASSWORD:
        logger.error("TAPO_USERNAME and TAPO_PASSWORD must be set")
        sys.exit(1)

    logger.info("Starting ONVIF event listener for %s:%d", HOST, PORT)

    # Fix WSDL path
    onvif_dir = os.path.dirname(onvif.__file__)
    wsdl_dir = os.path.join(onvif_dir, "wsdl")
    if not os.path.isdir(wsdl_dir):
        wsdl_dir = os.path.join(os.path.dirname(onvif_dir), "wsdl")

    while True:
        try:
            cam = ONVIFCamera(HOST, PORT, USERNAME, PASSWORD,
                              wsdl_dir=wsdl_dir, adjust_time=True)
            await cam.update_xaddrs()
            logger.info("Connected to camera")

            sub_addr = await _create_subscription(cam)
            await _listen_loop(sub_addr)

        except KeyboardInterrupt:
            logger.info("Shutting down")
            break
        except Exception as e:
            logger.error("Connection error: %s. Retrying in 30s...", e)
            await asyncio.sleep(30)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutting down")
    except SystemExit:
        pass
