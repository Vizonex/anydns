from collections.abc import Callable
from dataclasses import dataclass, field

from anyio import (
    TaskHandle,
    create_task_group,
    notify_closing,
    sleep,
    wait_readable,
    wait_writable,
)
from anyio.abc import TaskGroup
from anyio.lowlevel import checkpoint


def convert_timeout(delay: float | None = None) -> float:
    timeout = delay
    if timeout is None or timeout < 0 or timeout > 1:
        return 1.0
    elif timeout == 0:
        return 0.1
    else:
        return timeout


class Timer:
    __slots__ = ("_callback", "_group", "_queue_cancellation", "_task", "_timeout")

    def __init__(
        self,
        group: TaskGroup,
        callback: Callable[[], None],
        timeout: float | None = None,
    ):
        self._timeout = convert_timeout(timeout)
        self._task = None
        self._group = group
        self._callback = callback
        self._queue_cancellation = False

    def start(self) -> None:
        if not self._task or self._task.status != TaskHandle.Status.PENDING:
            self._task = self._group.create_task(self.run())

    async def run(self) -> None:
        """Runs timer on repeat forever."""
        self._queue_cancellation = False
        while not self._queue_cancellation:
            # print("WATIING")
            await sleep(self._timeout)
            # print("SENDING")
            self._callback()

    def cancel(self) -> None:
        # if there is no task or inner flag was called there is no need
        # to cancel the main timer task.
        if self._task is not None and not self._queue_cancellation:
            self._task.cancel()

    def cancel_later(self) -> None:
        """Finishes timer off after it's next interval gracefully
        it's cheaper than a forceful cancellation."""
        self._queue_cancellation = True


@dataclass(slots=True)
class Selector:
    timeout: float | None
    on_timeout: Callable[[], None]
    on_read: Callable[[int], None]
    on_write: Callable[[int], None]
    readers: set[int] = field(default_factory=set, init=False)
    writers: set[int] = field(default_factory=set, init=False)
    group: TaskGroup = field(default_factory=create_task_group, init=False)
    closed: bool = field(default=True, init=False)
    timer: None | Timer = field(default=None, init=False)

    def _check_timer_activity(self):
        if not self.timer:
            self.start_timer()

    def _check_closed(self) -> None:
        if self.closed:
            raise RuntimeError("selector is closed")

    def start_timer(self) -> None:
        if not self.timer:
            self.timer = Timer(self.group, self.call_timeout, self.timeout)
        self.timer.start()

    def call_timeout(self):
        if self.writers or self.readers:
            self.on_timeout()
        else:
            self.timer.cancel_later()

    async def open(self) -> None:
        if not self.closed:
            return

        await self.group.__aenter__()
        self.start_timer()
        self.closed = False

    async def __aenter__(self):
        await self.open()
        return self

    async def close(self) -> None:
        if self.closed:
            return
        if self.timer:
            self.timer.cancel()

        # handle checkpoint so that timer cleans up.
        await checkpoint()

        # cleanse selector callbacks.
        for fd in self.readers.copy():
            self.remove_reader(fd)

        for fd in self.writers.copy():
            self.remove_writer(fd)

        self.timer = None
        await self.group.__aexit__(None, None, None)
        self.closed = True

    async def __aexit__(self, *args) -> None:
        await self.close()

    async def reader_task(self, fd: int) -> None:
        while fd in self.readers:
            await wait_readable(fd)
            self.on_read(fd)

    def remove_reader(self, fd: int) -> None:
        self.readers.discard(fd)
        notify_closing(fd)

    def add_reader(self, fd: int) -> None:
        self._check_closed()
        if fd in self.readers:
            self.remove_reader(fd)
        self.readers.add(fd)
        self.group.start_soon(self.reader_task, fd)
        self._check_timer_activity()

    async def writer_task(self, fd: int):
        while fd in self.writers:
            await wait_writable(fd)
            self.on_read(fd)

    def remove_writer(self, fd: int) -> None:
        self.writers.discard(fd)
        notify_closing(fd)

    def add_writer(self, fd: int) -> None:
        self._check_closed()

        # recycle if same fd.
        if fd in self.writers:
            self.remove_writer(fd)
        self.writers.add(fd)
        self.group.start_soon(self.writer_task, fd)
        self._check_timer_activity()
