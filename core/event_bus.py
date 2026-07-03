"""
SentinelForge Event Bus
=======================
Thread-safe pub/sub for pipeline decoupling.

Usage:
    from core.event_bus import bus, ALERT_NEW, BLOCK_TRIGGERED

    # Subscribe (call before bus.start())
    bus.subscribe(ALERT_NEW, my_callback)    # fn(event_type, data, ts)
    bus.subscribe('*', catch_all_callback)   # wildcard subscriber

    # Start dispatch thread (once, at app startup)
    bus.start()

    # Publish from anywhere (non-blocking)
    bus.publish(ALERT_NEW, {'src_ip': '10.0.0.1', 'sig': 'SSH Brute Force'})
"""

import threading
import queue
import logging
from collections import defaultdict
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class EventBus:
    def __init__(self):
        self._queue       = queue.Queue()
        self._subscribers = defaultdict(list)
        self._lock        = threading.Lock()
        self._running     = False
        self._thread      = None

    def subscribe(self, event_type: str, callback):
        """Register a callback for an event_type (or '*' for all events).
        callback signature: fn(event_type: str, data: dict, timestamp: str)
        """
        with self._lock:
            self._subscribers[event_type].append(callback)

    def publish(self, event_type: str, data: dict):
        """Non-blocking publish. Event is dispatched in the background thread."""
        ts = datetime.now(timezone.utc).isoformat()
        self._queue.put((event_type, data, ts))

    def _dispatch_loop(self):
        while self._running:
            try:
                event_type, data, ts = self._queue.get(timeout=1.0)
                with self._lock:
                    callbacks = (
                        list(self._subscribers.get(event_type, []))
                        + list(self._subscribers.get('*', []))
                    )
                for cb in callbacks:
                    try:
                        cb(event_type, data, ts)
                    except Exception as e:
                        logger.error(f"[EventBus] {event_type} callback error: {e}")
            except queue.Empty:
                continue

    def start(self):
        """Start the background dispatch thread (daemon, auto-stops with process)."""
        if self._running:
            return
        self._running = True
        self._thread  = threading.Thread(target=self._dispatch_loop, daemon=True, name="EventBus")
        self._thread.start()
        logger.info("[EventBus] started")

    def stop(self):
        """Gracefully stop the dispatch thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)
        logger.info("[EventBus] stopped")

    @property
    def queue_depth(self) -> int:
        return self._queue.qsize()


# ── Singleton ─────────────────────────────────────────────────────────────────
bus = EventBus()

# ── Event type constants ──────────────────────────────────────────────────────
ALERT_NEW        = 'alert.new'        # new alert written to DB
ALERT_ENRICHED   = 'alert.enriched'   # AbuseIPDB enrichment completed
BLOCK_TRIGGERED  = 'block.triggered'  # iptables DROP executed
INCIDENT_OPENED  = 'incident.opened'  # new incident created
ANALYST_READY    = 'analyst.ready'    # AI analysis available for an alert batch
SCAN_DETECTED    = 'scan.detected'    # port scan / probe detected


# ── Self-test ─────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    import time
    logging.basicConfig(level=logging.DEBUG, format='%(message)s')

    results = []
    bus.subscribe(ALERT_NEW,       lambda t, d, ts: results.append(f"ALERT: {d['sig']}"))
    bus.subscribe(BLOCK_TRIGGERED, lambda t, d, ts: results.append(f"BLOCK: {d['ip']}"))
    bus.subscribe('*',             lambda t, d, ts: results.append(f"WILDCARD: {t}"))
    bus.start()

    bus.publish(ALERT_NEW,       {'src_ip': '10.0.0.1', 'sig': 'SSH Brute Force'})
    bus.publish(BLOCK_TRIGGERED, {'ip': '10.0.0.1'})
    time.sleep(0.3)
    bus.stop()

    print("Events dispatched:")
    for r in results:
        print(" ", r)
    assert len(results) == 4, f"Expected 4 (2 typed + 2 wildcard), got {len(results)}"
    print("Self-test PASSED")
