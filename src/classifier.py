import logging
logger = logging.getLogger("classifier")

class Classifier:
    def classify(self, result):
        score = result.risk_score
        if score >= 81:
            level = "CRITICAL"
        elif score >= 51:
            level = "HIGH"
        elif score >= 21:
            level = "MEDIUM"
        else:
            level = "LOW"
        result.risk_level = level
        return level

    def classify_all(self, results):
        for r in results:
            self.classify(r)
        return results
