import logging
logger = logging.getLogger("risk_scorer")

class RiskScorer:
    def score(self, result):
        score = 0
        for f in result.vulnerabilities_found:
            score += f.score_contribution
        score = min(100, score)
        result.risk_score = score
        return score

    def score_all(self, results):
        for r in results:
            self.score(r)
        return results
