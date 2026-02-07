# ============================================================================
# notify_manager.py - Email notifications for responder actions
# ============================================================================

import json
import logging
import os
import ssl
import subprocess
from email.message import EmailMessage
import smtplib

import config

logger = logging.getLogger(__name__)


def _parse_recipients(raw: str):
    if not raw:
        return []
    return [addr.strip() for addr in raw.replace(',', ';').split(';') if addr.strip()]


def _build_message(subject: str, body: str) -> EmailMessage:
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = config.NOTIFY_FROM
    msg['To'] = ', '.join(_parse_recipients(config.NOTIFY_TO))
    msg.set_content(body)
    return msg


def _send_via_sendmail(message: EmailMessage) -> None:
    sendmail_path = config.NOTIFY_SENDMAIL_PATH or '/usr/sbin/sendmail'
    if not os.path.exists(sendmail_path):
        raise FileNotFoundError(f"Sendmail not found at {sendmail_path}")

    logger.info("Sending notification via sendmail: %s", sendmail_path)
    proc = subprocess.run(
        [sendmail_path, '-t', '-i'],
        input=message.as_bytes(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode(errors='ignore') or 'sendmail failed')


def _send_via_smtp(message: EmailMessage) -> None:
    host = config.NOTIFY_SMTP_HOST
    port = config.NOTIFY_SMTP_PORT
    user = config.NOTIFY_AUTH_USER
    password = config.NOTIFY_AUTH_PASS
    use_tls = config.NOTIFY_USE_TLS
    use_ssl = config.NOTIFY_USE_SSL

    if not host or not port:
        raise ValueError("SMTP host/port not configured")

    if use_ssl:
        context = _build_ssl_context()
        server = smtplib.SMTP_SSL(host, port, timeout=config.NOTIFY_SMTP_TIMEOUT, context=context)
    else:
        server = smtplib.SMTP(host, port, timeout=config.NOTIFY_SMTP_TIMEOUT)

    try:
        if use_tls:
            context = _build_ssl_context()
            server.starttls(context=context)
        if user and password:
            server.login(user, password)
        server.send_message(message)
    finally:
        server.quit()


def _build_ssl_context() -> ssl.SSLContext:
    if config.NOTIFY_ALLOW_SELF_SIGNED:
        return ssl._create_unverified_context()
    return ssl.create_default_context()


def send_notification(subject: str, body: str) -> None:
    if not getattr(config, 'NOTIFY_ENABLED', False):
        return

    recipients = _parse_recipients(config.NOTIFY_TO)
    if not recipients:
        logger.warning("Notification enabled but NOTIFY_TO is empty")
        return

    message = _build_message(subject, body)

    method = getattr(config, 'NOTIFY_METHOD', 'auto')
    if method == 'auto':
        if not config.IS_WINDOWS:
            try:
                _send_via_sendmail(message)
                return
            except Exception as e:
                logger.warning("Sendmail not available: %s", e)
        _send_via_smtp(message)
    elif method == 'sendmail':
        _send_via_sendmail(message)
    elif method == 'smtp':
        _send_via_smtp(message)
    else:
        raise ValueError(f"Unknown NOTIFY_METHOD: {method}")


def notify_responder_action(action, executed_by: str) -> None:
    """Send notification for a single responder action."""
    try:
        if getattr(action, 'status', None) not in {"Success", "Completed"}:
            return
        payload = {
            'dataType': action.payload_data_type,
            'data': action.payload_data
        }
        subject = f"FUCO Responder: {action.responder_name}"
        body = (
            f"Responder action requested\n\n"
            f"Responder: {action.responder_name}\n"
            f"Executed by: {executed_by}\n"
            f"Observable: {action.observable}\n"
            f"Original DataType: {action.data_type}\n\n"
            f"Payload (sent to Cortex):\n"
            f"{json.dumps(payload, ensure_ascii=False, indent=2)}\n"
        )
        send_notification(subject, body)
    except Exception as e:
        logger.error("Notification error: %s", e)


def notify_responder_bulk(actions, executed_by: str, statuses: dict) -> None:
    """Send a single summary notification for bulk responder actions."""
    try:
        if not actions:
            return

        status_counts = {}
        lines = []
        has_success = False
        for action in actions:
            key = action.job_id or f"{action.observable}:{action.responder_name}"
            status = statuses.get(key) or getattr(action, 'status', 'Unknown')
            if status in {"Success", "Completed"}:
                has_success = True
            status_counts[status] = status_counts.get(status, 0) + 1

            lines.append(
                "\n".join([
                    f"Responder: {action.responder_name}",
                    f"Observable: {action.observable}",
                    f"DataType: {action.data_type}",
                    f"Job ID: {action.job_id or 'N/A'}",
                    f"Status: {status}",
                ])
            )

        if not has_success:
            return

        subject = f"FUCO Bulk Responder Summary ({len(actions)} actions)"
        summary = "\n".join([f"{k}: {v}" for k, v in sorted(status_counts.items())])
        body = (
            "Bulk responder actions completed\n\n"
            f"Executed by: {executed_by}\n"
            f"Total actions: {len(actions)}\n"
            f"Status summary:\n{summary}\n\n"
            "Details:\n\n" + "\n\n".join(lines)
        )

        send_notification(subject, body)
    except Exception as e:
        logger.error("Bulk notification error: %s", e)
