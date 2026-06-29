#!/usr/bin/env python3

from abc import ABC, abstractmethod
from typing import Optional, Callable, Dict


class BaseScannerModule(ABC):

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def module_key(self) -> str:
        pass

    @property
    def description(self) -> str:
        return f"{self.name} Scanner"

    @abstractmethod
    def run(self, scan_id: int, db_path: str,
            on_progress: Optional[Callable[[str], None]] = None,
            cookie: Optional[str] = None) -> Dict:
        pass
