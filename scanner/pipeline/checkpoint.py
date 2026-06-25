from __future__ import annotations

from pathlib import Path

from .utils import load_json, save_json


class CheckpointStore:
    def __init__(self, state_file: Path) -> None:
        self.state_file = state_file
        self.data: dict[str, bool] = load_json(state_file, fallback={})

    def is_done(self, stage: str) -> bool:
        return bool(self.data.get(stage))

    def mark_done(self, stage: str) -> None:
        self.data[stage] = True
        save_json(self.state_file, self.data)

    def clear(self) -> None:
        self.data = {}
        save_json(self.state_file, self.data)
