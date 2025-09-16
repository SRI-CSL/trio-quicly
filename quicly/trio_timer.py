#  Copyright ©  2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/
from functools import partial

import trio
from typing import *

from .logger import init_logging

# Note from FRC 9002 (Section 6.2.1):

# When a PTO timer expires, the PTO backoff MUST be increased, resulting in the PTO period being set to twice its
# current value. The PTO backoff factor is reset when an acknowledgment is received, except in the following case. A
# server might take longer to respond to packets during the handshake than otherwise. To protect such a server from
# repeated client probes, the PTO backoff is not reset at a client that is not yet certain that the server has
# finished validating the client's address. That is, a client does not reset the PTO backoff factor on receiving
# acknowledgments in Initial packets.
#
# This exponential reduction in the sender's rate is important because consecutive PTOs might be caused by loss of
# packets or acknowledgments due to severe congestion. Even when there are ack-eliciting packets in flight in
# multiple packet number spaces, the exponential increase in PTO occurs across all spaces to prevent excess load on
# the network. For example, a timeout in the Initial packet number space doubles the length of the timeout in the
# Handshake packet number space.
#
# The total length of time over which consecutive PTOs expire is limited by the idle timeout.

class TrioTimer:

    def __init__(self, callback_fn: Callable[..., None] | None = None, *cb_args: Any, **cb_kwargs: Any) -> None:
        self._callback = None if callback_fn is None else partial(callback_fn, *cb_args, **cb_kwargs)
        self._deadline: None | float = None
        self._timer_armed = trio.Event()
        self._qlog, _ = init_logging()

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
                if self._callback is not None:
                    self._callback() # not async since it must not be interrupted by setting this Timer anew
            else:
                pass

    def set_timer_at(self, deadline: float | None) -> None:
        self._deadline = None if deadline is None else deadline
        self._timer_armed.set()  # triggers timer loop to advance from `wait()`
        if self._deadline is None:
            self._qlog.debug(f'Timer disarmed at {trio.current_time():.3f}')
        else:
            self._qlog.debug(f'Timer armed at {trio.current_time():.3f}', deadline=f'{deadline:.3f}')

    def set_timer_after(self, delay: float | None) -> None:
        self.set_timer_at(None if delay is None else trio.current_time() + delay)

    def cancel(self) -> None:
        self.set_timer_at(None)
