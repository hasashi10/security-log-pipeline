"""Common interface every platform collector implements."""
from abc import ABC, abstractmethod
from typing import Iterable

from ..models import LogEvent


class Collector(ABC):
    @abstractmethod
    def collect(self) -> Iterable[LogEvent]:
        """Yield normalized LogEvents from this platform's log source."""
