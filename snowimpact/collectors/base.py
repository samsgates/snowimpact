from __future__ import annotations

from abc import ABC, abstractmethod

from snowimpact.core.models import EnvironmentSnapshot


class MetadataCollector(ABC):
    @abstractmethod
    def collect(self, environment: str = "development") -> EnvironmentSnapshot:
        raise NotImplementedError

    @abstractmethod
    def doctor(self) -> list[dict[str, object]]:
        raise NotImplementedError
