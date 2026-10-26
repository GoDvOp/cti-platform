"""An isolated teaching reconstruction; never a point-in-time backtest."""
from copy import deepcopy
import json

from .graph_scoring import calculate_graph

AS_OF = '2017-09-15T23:59:59+00:00'
CASE_ID = 'equifax-2017'


class _HistoricalView:
    """Supply copied case records to the unchanged scoring model.

    Sources were actually collected/reviewed later. Availability timestamps in
    this in-memory view are explicitly assumed for the teaching scenario. The
    underlying records, observed event dates, statuses and weights stay intact.
    """
    def __init__(self, store):
        self.store = store
        self.pubs = {}
        for pub in store.publications(False):
            content = json.loads(pub['data'])
            meta = content.get('metadata', {})
            known_day = meta.get('publication_day') or meta.get('source_updated_day')
            if meta.get('case_id') != CASE_ID or not known_day or known_day > AS_OF[:10]:
                continue
            copied = deepcopy(pub)
            copied['collected_at'] = AS_OF
            self.pubs[pub['id']] = copied

    def companies(self):
        return [c for c in self.store.companies() if c['id'] == 'equifax']

    def entities(self, demo=False):
        return self.store.entities(demo)

    def publications(self, demo=False):
        return list(self.pubs.values()) if not demo else []

    def signals(self, demo=False):
        return []

    def assertions(self, demo=False):
        result = []
        if demo:
            return result
        for record in self.store.assertions(False):
            if record['publication_id'] not in self.pubs:
                continue
            if record['kind'] not in {'incident_affects', 'incident_product', 'incident_exploited',
                                      'uses_product', 'affects_product'}:
                continue
            copied = deepcopy(record)
            copied['publication'] = self.pubs[record['publication_id']]
            copied['reviewed_at'] = AS_OF
            result.append(copied)
        return result


def calculate_example(store):
    view = _HistoricalView(store)
    result = calculate_graph(view, as_of=AS_OF, include_historical=True)
    row = next((c for c in result['companies'] if c['company_id'] == 'equifax'), None)
    if row is None:
        return None
    return {'as_of': AS_OF, 'publication_ids': sorted(view.pubs),
            'mode': 'teaching_reconstruction', 'is_backtest': False,
            'is_probability': False, 'model': result['model_version'],
            'weights_sha256': result['weights_sha256'], **row}
