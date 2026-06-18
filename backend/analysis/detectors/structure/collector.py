from collections import Counter
from analysis.utils.models import Threat

class ThreatCollector:

    def __init__(self, category: str):
        self.category = category
        self._map: dict = {}

    def add(self, t_id: str, severity: int, description: str, location: str):
        key = (t_id, severity, description)
        self._map.setdefault(key, []).append(location)

    def render(self) -> list[Threat]:
        threats = []
        for (t_id, severity, desc), locations in self._map.items():
            loc_counts = Counter(locations)
            loc_summary = ", ".join(
                f"{loc}" + (f" (x{count})" if count > 1 else "")
                for loc, count in loc_counts.items()
            )
            threats.append(Threat(
                id=t_id,
                category=self.category,
                severity=severity,
                description=desc,
                location=loc_summary,
            ))
        return threats
