#!/usr/bin/env python3
"""
MQTT activity watcher for honeypot session analysis.
Subscribes to all topics and logs every message and event as structured JSON.
Runs inside the Docker network so it sees all broker traffic.
"""

import json
import os
import time
from datetime import datetime, timezone

import paho.mqtt.client as mqtt

MQTT_HOST = os.environ.get("MQTT_HOST", "mosquitto")
MQTT_PORT = int(os.environ.get("MQTT_PORT", 1883))

# Our own telemetry client ID — flag messages from ourselves
OWN_CLIENT_ID = "heliocontrol-gateway"


def log(event: dict):
    print(json.dumps(event), flush=True)


def on_connect(client, userdata, flags, rc):
    log({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "watcher_connected",
        "broker": f"{MQTT_HOST}:{MQTT_PORT}"
    })
    client.subscribe("#")       # all application topics
    client.subscribe("$SYS/#")  # broker statistics and connection events


def on_disconnect(client, userdata, rc):
    log({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "watcher_disconnected",
        "rc": rc
    })


def on_message(client, userdata, msg):
    # Decode payload — attackers may send binary or text
    payload_encoding = "binary"
    try:
        decoded = msg.payload.decode("utf-8")
        payload_encoding = "utf8"
        try:
            payload = json.loads(decoded)
            payload_encoding = "json"
        except (json.JSONDecodeError, ValueError):
            payload = decoded
    except UnicodeDecodeError:
        payload = msg.payload.hex()

    topic = msg.topic
    is_sys = topic.startswith("$SYS/")
    is_own = topic.startswith("solar/") or topic.startswith("grid/")

    log({
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "event":            "mqtt_message",
        "topic":            topic,
        "payload":          payload,
        "payload_size":     len(msg.payload),
        "payload_encoding": payload_encoding,
        "qos":              msg.qos,
        "retain":           msg.retain,
        "msg_id":           msg.mid,
        "source":           "broker_stats" if is_sys else ("own_telemetry" if is_own else "external"),
    })


def on_subscribe(client, userdata, mid, granted_qos):
    log({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "watcher_subscribed",
        "mid": mid
    })


def main():
    client = mqtt.Client(client_id="honeypot-watcher", clean_session=True)
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message
    client.on_subscribe = on_subscribe

    log({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "watcher_starting",
        "broker": f"{MQTT_HOST}:{MQTT_PORT}"
    })

    connected = False
    while not connected:
        try:
            client.connect(MQTT_HOST, MQTT_PORT, keepalive=60)
            connected = True
        except Exception as e:
            log({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": "connection_failed",
                "error": str(e)
            })
            time.sleep(5)

    client.loop_forever()


if __name__ == "__main__":
    main()
