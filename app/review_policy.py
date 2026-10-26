"""Explicit review metadata; legacy omissions remain visible rather than upgraded."""
CONFIDENCE = ('low', 'medium', 'high')
BASES = ('victim_report', 'research_report', 'vendor_advisory', 'government_advisory',
         'legal_allegation', 'attacker_claim')


def missing_metadata(attributes):
    return [key for key, allowed in (('confidence', CONFIDENCE), ('basis', BASES))
            if attributes.get(key) not in allowed]
