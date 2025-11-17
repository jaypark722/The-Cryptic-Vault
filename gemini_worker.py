"""
Gemini worker that runs a single asyncio event loop in a background thread.
Connection threads can submit commands to this worker which will execute them
via the async GeminiTerminal in a single event loop to avoid thread-safety issues.
"""

import threading
import asyncio
import logging
from typing import Dict, Tuple

from ssh_config import COMMAND_TIMEOUT
from gemini_terminal import GeminiTerminal

logger = logging.getLogger(__name__)


class GeminiWorker:
    def __init__(self):
        self.loop = None
        self.thread = None
        self._started = threading.Event()
        self.sessions: Dict[str, GeminiTerminal] = {}

    def start(self):
        if self.thread and self.thread.is_alive():
            return

        def _run():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self._started.set()
            try:
                self.loop.run_forever()
            finally:
                # Close any remaining tasks
                pending = asyncio.all_tasks(loop=self.loop)
                for task in pending:
                    task.cancel()
                try:
                    self.loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                except Exception:
                    pass
                self.loop.close()

        self.thread = threading.Thread(target=_run, name="gemini-worker", daemon=True)
        self.thread.start()
        # Wait until loop is ready
        self._started.wait()
        logger.info("Gemini worker started")

    def stop(self):
        if not self.loop:
            return
        self.loop.call_soon_threadsafe(self.loop.stop)
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("Gemini worker stopped")

    def submit(self, session_id: str, command: str, timeout: int = COMMAND_TIMEOUT + 5) -> Tuple[str, bool]:
        """
        Submit a command to the worker and wait for the result synchronously.
        Returns (output, success)
        """
        if not self.loop:
            raise RuntimeError("Gemini worker loop is not running")

        coro = self._handle(session_id, command)
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)
        try:
            return future.result(timeout=timeout)
        except Exception as e:
            try:
                future.cancel()
            except Exception:
                pass
            logger.exception("Gemini worker submit failed")
            return (f"Command failed or timed out: {e}", False)

    async def _handle(self, session_id: str, command: str) -> Tuple[str, bool]:
        """Coroutine that runs in the worker loop to handle a command."""
        # Get or create session terminal inside the worker loop/thread
        term = self.sessions.get(session_id)
        if term is None:
            # Instantiate GeminiTerminal in the worker's thread / loop
            # GeminiTerminal.__init__ is synchronous but safe to run here since
            # we're already in the dedicated worker thread.
            term = GeminiTerminal(session_id)
            self.sessions[session_id] = term

        # GeminiTerminal.execute_command is async; await it
        try:
            out, success = await term.execute_command(command)
            return out, success
        except Exception as e:
            logger.exception("Error in Gemini command execution")
            return (f"Command execution error: {e}", False)
