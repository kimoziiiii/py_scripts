import time
import os
import hmac
import hashlib
import base64
import requests
import urllib.parse

import syslog
import argparse
from dotenv import load_dotenv

"""
Usage: 
    文本消息
    send_msg(
        'message content',
    )

    卡片消息
    send_msg(
        'message content',
        msg_type="actionCard",
        preview_title="aaaa",
        btn_title="",
        action_url=""
    )

"""

load_dotenv()

TRIGGER_STATUS_PIC = {
    "OK": "http://tva1.sinaimg.cn/large/88128a35gy1hi33jrvh5oj26qo21udxg.jpg",
    "PROBLEM": "http://tva1.sinaimg.cn/large/88128a35gy1hi33isgfiuj24mp1jsatr.jpg",
}


def get_sign(ts: int) -> str:
    """
    ts: round(time.time() * 1000)
    sk: secret key
    """

    sk = os.getenv("dign_secret_key")
    if not sk:
        raise RuntimeError("Miss secret key.")
    string_to_sign = "{}\n{}".format(ts, sk)
    sk_encoded = sk.encode("utf-8")
    hmac_code = hmac.new(
        sk_encoded, string_to_sign.encode("utf-8"), digestmod=hashlib.sha256
    ).digest()
    return urllib.parse.quote_plus(base64.b64encode(hmac_code))


def send_msg(msg: str, *, msg_type="text", **kwargs):
    base_url = f"https://oapi.dingtalk.com/robot/send"

    ts = round(time.time() * 1000)
    request_sign = get_sign(ts)

    msg_content = _msg_format(msg, msg_type, **kwargs)
    resp = requests.post(
        base_url,
        params={
            "timestamp": ts,
            "sign": request_sign,
            "access_token": os.getenv("ding_access_token"),
        },
        json=msg_content,
    )
    if resp.status_code == 200:
        resp_dict = resp.json()
        if resp_dict.get("errcode") != 0:
            raise RuntimeError(f"Message have sent fail, {resp_dict.get('errmsg')}")
        return resp_dict
    raise RuntimeError(f"Request fail, {resp.text}")


def _msg_format(msg_content, msg_type, **kwargs):
    trigger_status = kwargs.get("trigger_status")

    if msg_type == "text":
        return {"msgtype": msg_type, "text": {"content": msg_content}}

    if msg_type == "actionCard":
        preview_title = kwargs.get("preview_title", "TEST MSG")
        # btn_title = kwargs.get("btn_title", "I'm a button")
        # action_url = kwargs.get("action_url", "https://www.baidu.com")

        trigger_status = None

        if preview_title.startswith("OK"):
            trigger_status = "OK"

        if preview_title.startswith("PROBLEM"):
            trigger_status = "PROBLEM"

        if trigger_status is None:
            raise RuntimeError(f"Trigger status unknow.")

        msg_content_prefix = (
            f"![screenshot]({TRIGGER_STATUS_PIC.get(trigger_status)})\n\n"
        )

        msg_content = f"{msg_content_prefix}{msg_content}"
        return {
            "msgtype": msg_type,
            "actionCard": {
                "title": f"{preview_title}",
                "text": f"{msg_content}",
                "btnOrientation": "0",
                # "btns": [
                #     {"title": f"{btn_title}", "actionURL": f"{action_url}"},
                # ],
            },
        }

    raise RuntimeError(f"Not support message type: {msg_type}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Dingding webhook for zabbix")
    parser.add_argument("subject", type=str, help="message sujbect")
    parser.add_argument("message", type=str, help="message content")

    args = parser.parse_args()
    syslog.syslog(f"[DingBot] Args: {args}")
    try:
        r = send_msg(
            args.message,
            msg_type="actionCard",
            preview_title=args.subject,
        )
    except RuntimeError as exc:
        syslog.syslog(syslog.LOG_ERR, f"[DingBot] {exc}")
    else:
        syslog.syslog(f"[DingBot] {r}")
