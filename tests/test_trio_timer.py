import trio
from trio.testing import MockClock

# Flexible import so it works whether the module is top-level or package-scoped
try:
    from trio_timer import TrioTimer  # local module
except Exception:  # pragma: no cover
    from quicly.trio_timer import TrioTimer  # package module

# --- global time the callback will check ---
alarm: float = 0.0

def approx(a, b, tol=0.01):
    return abs(a - b) <= tol

def cb():
    global alarm
    assert alarm <= trio.current_time()
    alarm = 0.0  # reset

async def _run_timer_with(callback, async_test):
    timer = TrioTimer(callback_fn=callback)
    async with trio.open_nursery() as nursery:
        nursery.start_soon(timer.timer_loop)
        nursery.start_soon(async_test, timer, nursery)

def test_timer_fires_at_deadline():
    async def main():
        async def scenario(timer, nursery):
            global alarm
            alarm = trio.current_time() + 2.0
            timer.set_timer_at(alarm)
            # cross the deadline and give the callback a chance to run
            await trio.sleep(3)
            assert alarm == 0.0  # timer fired and executed callback
            alarm = trio.current_time() + 2.0
            timer.set_timer_after(2.0)
            await trio.sleep(3)
            assert alarm == 0.0  # timer fired and executed callback

            # stop the timer loop so the test completes
            nursery.cancel_scope.cancel()

        await _run_timer_with(cb, scenario)

    # real_start = time.perf_counter()
    trio.run(main, clock=MockClock(autojump_threshold=0))
    # real_duration = time.perf_counter() - real_start
    # print(f"\nTotal real time elapsed: {real_duration} seconds")

def test_timer_cancel_prevents_fire():
    async def main():
        async def scenario(timer, nursery):
            global alarm
            alarm = trio.current_time() + 3.0
            timer.set_timer_at(alarm)
            await trio.sleep(1)
            timer.cancel()
            # cross the prior deadline and give the callback a chance to run
            await trio.sleep(2)
            assert alarm > 0.0  # timer got canceled in time before firing

            # stop the timer loop so the test completes
            nursery.cancel_scope.cancel()

        await _run_timer_with(cb, scenario)

    trio.run(main, clock=MockClock(autojump_threshold=0))

def test_timer_reset_to_later_delays_fire():
    async def main():
        async def scenario(timer, nursery):
            global alarm
            alarm = trio.current_time() + 2.0
            timer.set_timer_at(alarm)
            await trio.sleep(1)
            assert alarm > 0.0  # timer hasn't fired yet
            alarm = trio.current_time() + 2.0
            timer.set_timer_after(2.0)  # add 1 second
            await trio.sleep(1.2)
            assert alarm > 0.0  # timer hasn't fired yet
            # cross the prior deadline and give the callback a chance to run
            await trio.sleep(2)
            assert alarm == 0.0  # timer fired

            # stop the timer loop so the test completes
            nursery.cancel_scope.cancel()

        await _run_timer_with(cb, scenario)

    trio.run(main, clock=MockClock(autojump_threshold=0))

def test_timer_reset_to_earlier_fires_early():
    async def main():
        async def scenario(timer, nursery):
            global alarm
            alarm = trio.current_time() + 5.0
            timer.set_timer_at(alarm)
            await trio.sleep(1)
            assert alarm > 0.0  # timer hasn't fired yet
            alarm = trio.current_time() + 1.0
            timer.set_timer_at(alarm)
            # cross the new deadline before the old one and give the callback a chance to run
            await trio.sleep(1.2)
            assert alarm == 0.0  # timer fired

            # stop the timer loop so the test completes
            nursery.cancel_scope.cancel()

        await _run_timer_with(cb, scenario)

    trio.run(main, clock=MockClock(autojump_threshold=0))

def test_timer_can_be_reused_after_firing():
    async def main():
        async def scenario(timer, nursery):
            global alarm
            alarm = trio.current_time() + 2.0
            timer.set_timer_at(alarm)
            await trio.sleep(1)
            assert alarm > 0.0  # timer hasn't fired yet
            # cross the new deadline before the old one and give the callback a chance to run
            await trio.sleep(1.2)
            assert alarm == 0.0  # timer fired
            await trio.sleep(1)
            alarm = trio.current_time() + 2.0
            timer.set_timer_at(alarm)
            # cross the new deadline before the old one and give the callback a chance to run
            await trio.sleep(2.2)
            assert alarm == 0.0  # timer fired again

            # stop the timer loop so the test completes
            nursery.cancel_scope.cancel()

        await _run_timer_with(cb, scenario)

    trio.run(main, clock=MockClock(autojump_threshold=0))

def test_timer_fires_if_deadline_is_set_to_past():
    async def main():
        async def scenario(timer, nursery):
            await trio.sleep(2)
            global alarm
            alarm = trio.current_time() - 1
            timer.set_timer_at(alarm)
            await trio.sleep(1)
            assert alarm == 0.0  # timer fired and executed callback

            # stop the timer loop so the test completes
            nursery.cancel_scope.cancel()

        await _run_timer_with(cb, scenario)

    trio.run(main, clock=MockClock(autojump_threshold=0))
