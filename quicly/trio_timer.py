#  Copyright ©  2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/

import trio
from typing import *

class TrioTimer:

    def __init__(self, callback_fn: Callable[[], None] | None = None) -> None:
        self._callback_fn = callback_fn
        self._deadline: None | float = None
        self._timer_armed = trio.Event()

    async def timer_loop(self) -> None:
        while True:
            if self._deadline is None:
                await self._timer_armed.wait()  # wait until deadline is set
                self._timer_armed = trio.Event()  # create new event after the other was consumed
                continue
            with trio.move_on_at(self._deadline) as cancel_scope:
                await self._timer_armed.wait()  # wait if deadline is modified while being armed
                self._timer_armed = trio.Event()
            if cancel_scope.cancelled_caught:  # timer went off
                self._deadline = None
                if self._callback_fn is not None:
                    self._callback_fn()  # not async since it must not be interrupted by setting this Timer anew
            else:
                pass

    def set_timer_at(self, deadline: float | None) -> None:
        self._deadline = None if deadline is None else deadline
        self._timer_armed.set()

    def set_timer_after(self, delay: float | None) -> None:
        self.set_timer_at(None if delay is None else trio.current_time() + delay)

    def cancel(self) -> None:
        self.set_timer_at(None)
