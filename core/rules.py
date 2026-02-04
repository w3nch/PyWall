import json
import os
from json import JSONDecodeError

RULES_FILE = "config/rules.json"


class RuleEngine:
    def __init__(self):
        os.makedirs("config", exist_ok=True)

        if not os.path.exists(RULES_FILE):
            self.rules = []
            self._next_id = 1
            self._save()
        else:
            self._load_safe()

    def _load_safe(self):
        try:
            with open(RULES_FILE, "r") as f:
                data = json.load(f)
                self.rules = data.get("rules", [])
        except (JSONDecodeError, ValueError):
            # corrupted or empty file → recover safely
            print("[!] rules.json corrupted or empty, reinitializing")
            self.rules = []

        self._next_id = self._compute_next_id()
        self._save()

    def _is_duplicate(self, rule):
        for r in self.rules:
            if (
                r["action"] == rule["action"]
                and r["ip"] == rule["ip"]
                and r["port"] == rule["port"]
                and r["protocol"] == rule["protocol"]
            ):
                return r["id"]
        return None

    def _save(self):
        with open(RULES_FILE, "w") as f:
            json.dump({"rules": self.rules}, f, indent=4)

    def _compute_next_id(self):
        if not self.rules:
            return 1
        return max(r["id"] for r in self.rules) + 1

    def add_rule(self, rule):
        existing_id = self._is_duplicate(rule)
        if existing_id is not None:
            return existing_id, False  # rule already exists


        rule["id"] = self._next_id
        self._next_id += 1
        self.rules.append(rule)
        self._save()
        return rule["id"],True

    def delete_rule(self, rule_id):
        for i, r in enumerate(self.rules):
            if r["id"] == rule_id:
                del self.rules[i]
                self._save()
                return True
        return False

    def list_rules(self):
        return list(self.rules)
