import hashlib

GENERIC_SCRIPT_TYPES = {"", "Unknown", "Binary Discovery"}


class ScriptAggregator:
    def __init__(self):
        self.scripts_map = {}

    def _generate_id(self, code):
        return hashlib.sha256(code.encode("utf-8")).hexdigest()

    def add_script(self, code, location, script_type="JavaScript", source_object=None):
        if not code or not code.strip():
            return

        code_clean = code.strip()
        script_id = self._generate_id(code_clean)

        if script_id not in self.scripts_map:
            self.scripts_map[script_id] = {
                "code": code_clean,
                "script_type": script_type,
                "source_objects": set(),
                "locations": set()
            }

        elif (script_type not in GENERIC_SCRIPT_TYPES
              and self.scripts_map[script_id]["script_type"] in GENERIC_SCRIPT_TYPES):
            self.scripts_map[script_id]["script_type"] = script_type

        self.scripts_map[script_id]["locations"].add(location)

        if source_object:
            self.scripts_map[script_id]["source_objects"].add(source_object)

    def get_all_scripts(self):
        results = []

        for script_id, data in self.scripts_map.items():
            entry = {
                "id": script_id,
                "script_type": data["script_type"],
                "code": data["code"],
                "locations": sorted(data["locations"]),
            }
            
            if data["source_objects"]:
                entry["source_objects"] = sorted(data["source_objects"])
                
            results.append(entry)

        return results