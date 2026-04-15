#!/usr/bin/env python3
"""
Fake solar inverter telemetry generator.
Publishes realistic energy data to MQTT to make the honeypot convincing.
"""

import json
import math
import os
import random
import time
from datetime import datetime, timezone

import paho.mqtt.client as mqtt

MQTT_HOST = os.environ.get("MQTT_HOST", "localhost")
MQTT_PORT = int(os.environ.get("MQTT_PORT", 1883))

# Simulated device identity (fictional brand)
DEVICE_INFO = {
    "manufacturer": "HelioControl",
    "model": "HC-5000",
    "firmware": "2.1.4",
    "serial": "HC5K-2024-00847",
    "install_date": "2023-06-15",
    "rated_power_w": 5000,
    "location": "Residential - Roof Mount"
}


def solar_curve(hour: float) -> float:
    """Simulate solar output based on time of day. Returns 0-1 factor."""
    if hour < 6 or hour > 20:
        return 0.0
    # Bell curve centered at solar noon (13:00)
    return max(0, math.exp(-0.5 * ((hour - 13) / 3) ** 2))


def get_power_output() -> float:
    """Get simulated power output in watts."""
    now = datetime.now()
    hour = now.hour + now.minute / 60.0
    base = solar_curve(hour) * DEVICE_INFO["rated_power_w"]
    # Add weather variation (clouds)
    cloud_factor = random.uniform(0.7, 1.0)
    # Add small noise
    noise = random.uniform(-50, 50)
    return max(0, round(base * cloud_factor + noise, 1))


def get_device_status(power_w: float) -> dict:
    """Get device status JSON."""
    return {
        "device_id": DEVICE_INFO["serial"],
        "manufacturer": DEVICE_INFO["manufacturer"],
        "model": DEVICE_INFO["model"],
        "firmware_version": DEVICE_INFO["firmware"],
        "status": "producing" if power_w > 0 else "standby",
        "power_output_w": power_w,
        "temperature_c": round(random.uniform(25, 55) if power_w > 0 else random.uniform(15, 25), 1),
        "voltage_dc": round(random.uniform(300, 400) if power_w > 0 else 0, 1),
        "frequency_hz": round(random.uniform(49.95, 50.05), 2),
        "energy_today_kwh": round(random.uniform(5, 25), 2),
        "energy_total_kwh": round(random.uniform(8500, 9500), 1),
        "uptime_hours": random.randint(4000, 5000),
        "error_code": 0,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


def get_consumption() -> float:
    """Simulate household consumption in watts."""
    now = datetime.now()
    hour = now.hour
    # Base load + time-of-day variation
    base = 400
    if 7 <= hour <= 9:
        base = 1200   # Morning
    elif 12 <= hour <= 14:
        base = 800    # Midday
    elif 17 <= hour <= 21:
        base = 1800   # Evening peak
    elif 22 <= hour or hour <= 6:
        base = 300    # Night
    return round(base + random.uniform(-100, 200), 1)


def main():
    client = mqtt.Client(client_id="heliocontrol-gateway")
    print(f"Connecting to MQTT broker at {MQTT_HOST}:{MQTT_PORT}")

    connected = False
    while not connected:
        try:
            client.connect(MQTT_HOST, MQTT_PORT, 60)
            connected = True
            print("Connected to MQTT broker")
        except Exception as e:
            print(f"Connection failed: {e}. Retrying in 5s...")
            time.sleep(5)

    client.loop_start()

    while True:
        try:
            power = get_power_output()
            consumption = get_consumption()
            export = max(0, power - consumption)

            # Publish power output
            client.publish(
                "solar/inverter/01/power_output",
                json.dumps({"watts": power, "timestamp": datetime.now(timezone.utc).isoformat()}),
                qos=0
            )

            # Publish device status
            status = get_device_status(power)
            client.publish(
                "solar/inverter/01/status",
                json.dumps(status),
                qos=0
            )

            # Publish consumption
            client.publish(
                "grid/meter/01/consumption",
                json.dumps({"watts": consumption, "timestamp": datetime.now(timezone.utc).isoformat()}),
                qos=0
            )

            # Publish grid export
            client.publish(
                "grid/meter/01/export",
                json.dumps({"watts": export, "timestamp": datetime.now(timezone.utc).isoformat()}),
                qos=0
            )

            time.sleep(30)

        except Exception as e:
            print(f"Error publishing: {e}")
            time.sleep(10)


if __name__ == "__main__":
    main()
