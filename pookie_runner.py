"""pookie_runner.py - one thread per WhatsApp agent, supervised.

Design:
  * exactly one poller thread per token (specs are de-duplicated before this)
  * a *fatal* error (revoked token, another poller on the same token) stops
    only that agent and marks it "failed"; the other agents keep running
  * any other error restarts that agent with exponential backoff (5s -> 300s),
    never a tight loop
  * shutdown uses the `stop` callback accepted by Agent.run(); a poll lasts at
    most ~25 s so a clean stop can take that long
This module does not import whagent: the agent factory and the list of fatal
exception classes are injected (assistant.py provides them), which keeps it
testable with fakes.
"""

import logging
import threading
import time

log = logging.getLogger("pookie.runner")


class AgentRunner(threading.Thread):
    def __init__(self, spec, agent_factory, fatal_exceptions=(), initial_backoff=5.0,
                 max_backoff=300.0):
        super().__init__(name=f"agent-{spec.label}", daemon=True)
        self.spec = spec
        self._factory = agent_factory
        self._fatal = tuple(fatal_exceptions)
        self._initial_backoff = initial_backoff
        self._max_backoff = max_backoff
        self._stop_event = threading.Event()
        self.status = "starting"   # starting | running | retrying | failed | stopped
        self.last_error = None     # exception CLASS NAME only, never the message
        self.restarts = 0

    def request_stop(self):
        self._stop_event.set()

    def run(self):
        backoff = self._initial_backoff
        while not self._stop_event.is_set():
            agent = None
            started = time.monotonic()
            try:
                self.status = "starting"
                agent = self._factory(self.spec)
                self.status = "running"
                log.info("Agent '%s' polling", self.spec.label)
                agent.run(stop=self._stop_event.is_set)
                break  # returned normally (stop requested)
            except self._fatal as exc:
                self.status, self.last_error = "failed", type(exc).__name__
                log.error("Agent '%s' stopped permanently: %s (other agents keep running)",
                          self.spec.label, type(exc).__name__)
                break
            except Exception as exc:  # noqa: BLE001 - supervised, logged by class name only
                self.last_error = type(exc).__name__
                self.restarts += 1
                self.status = "retrying"
                if time.monotonic() - started > 60:
                    backoff = self._initial_backoff  # it ran for a while: reset backoff
                log.warning("Agent '%s' error %s; restarting in %.0fs",
                            self.spec.label, type(exc).__name__, backoff)
                if self._stop_event.wait(backoff):
                    break
                backoff = min(backoff * 2, self._max_backoff)
            finally:
                if agent is not None:
                    try:
                        agent.close()
                    except Exception:  # noqa: BLE001
                        pass
        if self.status != "failed":
            self.status = "stopped"


class Supervisor:
    def __init__(self, runners):
        self.runners = list(runners)

    def start(self):
        for runner in self.runners:
            runner.start()

    def stop(self, timeout=30.0):
        for runner in self.runners:
            runner.request_stop()
        deadline = time.monotonic() + timeout
        for runner in self.runners:
            runner.join(max(0.0, deadline - time.monotonic()))

    def any_alive(self):
        return any(r.is_alive() for r in self.runners)

    def statuses(self):
        return {
            r.spec.label: {"status": r.status, "last_error": r.last_error, "restarts": r.restarts}
            for r in self.runners
        }
