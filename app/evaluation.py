"""Small labelled development audit. Never presented as independent prediction validation."""
from collections import Counter
import hashlib
import html
import json
from pathlib import Path
from .extraction import event_type
from .models import Publication


def evaluate(path):
    path = Path(path)
    raw = path.read_bytes()
    data = json.loads(raw)
    labels = ['unknown', 'attack_claim', 'ransomware_claim', 'availability_claim',
              'data_leak_claim', 'access_sale_claim', 'vulnerability_advisory']
    confusion, results = Counter(), []
    for row in data['records']:
        pub = Publication(**row['publication'])
        if pub.content_hash != row['content_hash']:
            raise ValueError('Изменился размеченный текст: ' + str(row['sample_id']))
        gold = row['gold_event_type']
        if gold not in labels:
            raise ValueError('Неизвестный класс в разметке')
        predicted = event_type(pub.title + '. ' + pub.text)
        confusion[gold, predicted] += 1
        results.append({'sample_id': row['sample_id'], 'publication_id': row['publication_id'],
                        'title': pub.title, 'url': pub.url, 'gold': gold, 'predicted': predicted,
                        'correct': gold == predicted, 'note': row['annotation_note']})
    metrics = []
    for label in labels:
        tp = confusion[label, label]
        support = sum(v for (gold, _), v in confusion.items() if gold == label)
        selected = sum(v for (_, predicted), v in confusion.items() if predicted == label)
        precision = tp / selected if selected else None
        recall = tp / support if support else None
        f1 = 2 * tp / (support + selected) if support + selected else None
        metrics.append({'class': label, 'support': support, 'predicted': selected,
                        'precision': precision, 'recall': recall, 'f1': f1})
    return {'corpus_version': data['version'], 'corpus_sha256': hashlib.sha256(raw).hexdigest(),
            'status': data['status'], 'annotator': data['annotator'], 'sampling': data['sampling'],
            'task': data['task'], 'limitations': data['limitations'], 'count': len(results),
            'correct': sum(r['correct'] for r in results),
            'accuracy': sum(r['correct'] for r in results) / len(results) if results else None,
            'macro_f1_supported': sum(m['f1'] or 0 for m in metrics if m['support']) / sum(bool(m['support']) for m in metrics),
            'per_class': metrics, 'confusion': [{'gold': g, 'predicted': p, 'count': n} for (g,p),n in sorted(confusion.items())],
            'records': results}


def export(result, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'evaluation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    esc = lambda v: html.escape(str(v))
    rows = ''.join('<tr>' + ''.join('<td>' + esc(r[k]) + '</td>' for k in ('sample_id','title','gold','predicted','correct','note')) + '</tr>' for r in result['records'])
    metrics = ''.join('<tr>' + ''.join('<td>' + esc('нет оценки' if r[k] is None else round(r[k],4) if isinstance(r[k],float) else r[k]) + '</td>' for k in ('class','support','predicted','precision','recall','f1')) + '</tr>' for r in result['per_class'])
    page = '<!doctype html><html lang="ru"><meta charset="utf-8"><title>Пилотная проверка классификации</title><style>body{font:15px/1.5 system-ui;max-width:1150px;margin:32px auto;padding:20px}table{border-collapse:collapse}td,th{border:1px solid #ccd5df;padding:9px;text-align:left}</style><h1>Пилотная проверка классификации</h1>'
    page += '<p>Разметка ассистентом на данных, доступных при разработке. Это не независимая проверочная выборка и не оценка вероятности атаки.</p>'
    page += f'<p>Правильно: {result["correct"]}/{result["count"]}; accuracy={result["accuracy"]:.3f}; macro F1 по представленным классам={result["macro_f1_supported"]:.3f}.</p>'
    page += '<table><tr><th>Класс</th><th>Поддержка</th><th>Предсказано</th><th>Precision</th><th>Recall</th><th>F1</th></tr>' + metrics + '</table><h2>Разбор каждого текста</h2><table><tr><th>ID</th><th>Заголовок</th><th>Разметка</th><th>Результат</th><th>Совпало</th><th>Комментарий</th></tr>' + rows + '</table></html>'
    (output / 'evaluation.html').write_text(page, encoding='utf-8')
    return {'directory': str(output.resolve()), 'count': result['count'], 'correct': result['correct'],
            'accuracy': result['accuracy'], 'macro_f1_supported': result['macro_f1_supported']}
