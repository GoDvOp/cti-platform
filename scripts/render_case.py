"""Render a local case note to offline HTML and paginated PDF (system Pango/Cairo)."""
from pathlib import Path
import html
import re
import sys
import json

ROOT = Path(__file__).resolve().parents[1]
folder = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / 'docs/cases/novabev-2025'
source = (folder / 'case.md').read_text(encoding='utf-8')
case_title = source.splitlines()[0].lstrip('# ').strip()
case_badge = case_title.split('.')[0] if case_title.startswith('Кейс ') else ('Задание № 1' if folder.name == 'submission' else 'Чувствительность весов')
submission = json.loads((ROOT / 'config/submission.json').read_text())
footer_day = submission.get('release_date', '2026-10-25') if folder.name == 'submission' else submission['frozen_at'][:10]
footer_day = '.'.join(reversed(footer_day.split('-')))


def inline(text):
    value = html.escape(text)
    return re.sub(r'\[([^]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', value)


blocks = re.split(r'\n\s*\n', source.strip())
body = []
for block in blocks:
    if block.startswith('```'):
        body.append('<pre>' + html.escape('\n'.join(block.splitlines()[1:-1])) + '</pre>')
    elif block.startswith('#'):
        level = len(block) - len(block.lstrip('#'))
        body.append(f'<h{level}>' + inline(block[level:].strip()) + f'</h{level}>')
    elif block.startswith('|'):
        rows = block.splitlines()
        cells = lambda row, tag: '<tr>' + ''.join(f'<{tag}>' + inline(c.strip()) + f'</{tag}>' for c in row.strip('|').split('|')) + '</tr>'
        body.append('<div class="table-wrap"><table>' + cells(rows[0], 'th') + ''.join(cells(r, 'td') for r in rows[2:]) + '</table></div>')
    elif block.startswith('- '):
        body.append('<ul>' + ''.join('<li>' + inline(r[2:]) + '</li>' for r in block.splitlines()) + '</ul>')
    elif re.match(r'^\d+\. ', block):
        body.append('<ol>' + ''.join('<li>' + inline(re.sub(r'^\d+\. ', '', r)) + '</li>' for r in block.splitlines()) + '</ol>')
    else:
        body.append('<p>' + inline(block) + '</p>')
        if block.startswith('Схема:'):
            body.append('<figure><img src="graph.svg" alt="Граф связей по доказательствам кейса"></figure>')
page = '''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Кейс 01 · Novabev Group и ВинЛаб</title><style>
body{font:16px/1.6 system-ui,sans-serif;color:#1b2c43;background:#f5f7fb;margin:0}main{max-width:1000px;margin:30px auto;background:white;padding:36px 48px;border-radius:14px}h1{font-size:32px;line-height:1.2}h2{margin-top:2em;color:#23486d}a{color:#165e9e}nav{font-size:14px;border-bottom:1px solid #dae1e9;padding-bottom:16px}nav a{margin-right:18px}table{border-collapse:collapse;width:100%;font-size:14px}td,th{border:1px solid #d5dde7;padding:12px;text-align:left;vertical-align:top}th{background:#edf2f8}pre{white-space:pre-wrap;background:#edf2f8;padding:18px;border-radius:8px}figure{margin:22px 0}img{width:100%;height:auto}.table-wrap{overflow:auto}li{margin:.5em 0}@media(max-width:700px){main{padding:22px;margin:0;border-radius:0}h1{font-size:26px}}@media print{body{background:white}main{margin:0;padding:0}nav{display:none}h2{break-after:avoid}tr,figure,pre{break-inside:avoid}a{color:inherit}}
</style><main><nav><a href="case.pdf">PDF</a><a href="evidence.json">Реестр доказательств</a><a href="score_snapshot.json">Расчёт</a><a href="graph.cypher">Запросы Neo4j</a></nav>'''+ '\n'.join(body) + '</main></html>'
page = page.replace('<title>Кейс 01 · Novabev Group и ВинЛаб</title>', '<title>' + html.escape(case_title) + '</title>')
nav = '<nav>' + ''.join(f'<a href="{name}">{label}</a>' for name, label in (
    ('case.pdf', 'PDF'), ('evidence.json', 'Реестр доказательств'), ('score_snapshot.json', 'Расчёт'),
    ('graph.cypher', 'Запросы Neo4j'), ('sensitivity.html', 'Все сценарии'), ('snapshot.json.gz', 'Отдельный снимок'))
    if name == 'case.pdf' or (folder / name).exists()) + '</nav>'
page = re.sub(r'<nav>.*?</nav>', lambda match: nav, page, count=1)
(folder / 'case.html').write_text(page, encoding='utf-8')

try:
    import cairo
    import gi
    gi.require_version('Pango', '1.0')
    gi.require_version('PangoCairo', '1.0')
    from gi.repository import Pango, PangoCairo
except ImportError:
    raise SystemExit('HTML готов; для PDF нужны системные Pango/Cairo.')

width, height, margin = 595.28, 841.89, 46
pdf = cairo.PDFSurface(str(folder / 'case.pdf'), width, height)
pdf.set_metadata(cairo.PDF_METADATA_TITLE, case_title)
if folder.name == 'submission' and submission.get('author'):
    pdf.set_metadata(cairo.PDF_METADATA_AUTHOR, submission['author'])
pdf_ctx = cairo.Context(pdf)
number, y = 1, margin
recording = cairo.RecordingSurface(cairo.CONTENT_COLOR_ALPHA, (0, 0, width, height))
ctx = cairo.Context(recording)


def layout(text, size, bold=False):
    item = PangoCairo.create_layout(ctx)
    font = Pango.FontDescription('DejaVu Sans' + (' Bold' if bold else ''))
    font.set_absolute_size(size * Pango.SCALE)
    item.set_font_description(font)
    item.set_width(int((width - 2 * margin) * Pango.SCALE))
    item.set_wrap(Pango.WrapMode.WORD_CHAR)
    item.set_text(text, -1)
    return item


def finish_page():
    ctx.set_source_rgb(.4, .45, .52)
    ctx.move_to(margin, height - 28)
    PangoCairo.show_layout(ctx, layout(f'CTI · {case_badge} · {footer_day}                                      {number}', 8))
    pdf_ctx.set_source_surface(recording, 0, 0)
    pdf_ctx.paint()
    pdf_ctx.show_page()
    preview = cairo.ImageSurface(cairo.FORMAT_ARGB32, int(width * 1.5), int(height * 1.5))
    preview_ctx = cairo.Context(preview)
    preview_ctx.set_source_rgb(1, 1, 1)
    preview_ctx.paint()
    preview_ctx.scale(1.5, 1.5)
    preview_ctx.set_source_surface(recording, 0, 0)
    preview_ctx.paint()
    preview.write_to_png(f'/tmp/cti-case-{folder.name}-page{number}.png')


def new_page():
    global ctx, recording, y, number
    finish_page()
    number += 1
    y = margin
    recording = cairo.RecordingSurface(cairo.CONTENT_COLOR_ALPHA, (0, 0, width, height))
    ctx = cairo.Context(recording)


def draw(text, size=10.2, bold=False, gap=9):
    global y
    item = layout(text, size, bold)
    lines = item.get_lines_readonly()
    for line in lines:
        _, bounds = line.get_extents()
        line_height = bounds.height / Pango.SCALE + 3
        if y + line_height > height - margin:
            new_page()
        ctx.set_source_rgb(*((.12, .27, .42) if bold else (.10, .15, .21)))
        ctx.move_to(margin, y - bounds.y / Pango.SCALE)
        PangoCairo.show_layout_line(ctx, line)
        y += line_height
    y += gap


def architecture_diagram():
    global y
    if y + 90 > height - margin:
        new_page()
    labels = [('Источники', 'RSS · HTML · JSON'), ('Публикации', 'версии · хеши'), ('Проверка', 'текст · статус'), ('Граф', 'пути · веса'), ('Отчёт', 'вывод · пределы')]
    for index, (title, subtitle) in enumerate(labels):
        x = margin + index * 102
        ctx.set_source_rgb(.92, .95, .98)
        ctx.rectangle(x, y, 94, 61)
        ctx.fill_preserve()
        ctx.set_source_rgb(.65, .74, .83)
        ctx.set_line_width(.7)
        ctx.stroke()
        for offset, text, size in [(12, title, 9), (34, subtitle, 7)]:
            item = layout(text, size)
            item.set_width(int(90 * Pango.SCALE))
            item.set_alignment(Pango.Alignment.CENTER)
            ctx.set_source_rgb(.12, .27, .42)
            ctx.move_to(x + 2, y + offset)
            PangoCairo.show_layout(ctx, item)
        if index < 4:
            ctx.set_source_rgb(.3, .45, .6)
            ctx.move_to(x + 95, y + 30)
            ctx.line_to(x + 101, y + 30)
            ctx.stroke()
    y += 82


links = {}
for block in blocks:
    for label, url in re.findall(r'\[([^]]+)\]\(([^)]+)\)', block):
        if url.startswith('https://'):
            links[label.split(' — ')[0]] = url
    clean = re.sub(r'\[([^]]+)\]\(([^)]+)\)', r'\1', block).replace('`', '')
    if block.startswith('#'):
        level = len(block) - len(block.lstrip('#'))
        if y > height - margin - 75:
            new_page()
        draw(clean.lstrip('#').strip(), 20 if level == 1 else 13, True, 12)
    elif block.startswith('|'):
        rows = block.splitlines()
        headers = [c.strip() for c in rows[0].strip('|').split('|')]
        for row in rows[2:]:
            cells = [re.sub(r'\[([^]]+)\]\(([^)]+)\)', r'\1', c.strip()) for c in row.strip('|').split('|')]
            draw(' · '.join(f'{key}: {value}' for key, value in zip(headers, cells)), 9.8)
    elif block.startswith('```'):
        draw('\n'.join(block.splitlines()[1:-1]), 10)
    elif block.startswith('- ') or re.match(r'^\d+\. ', block):
        for line in clean.splitlines():
            draw(line, gap=6)
        y += 4
    else:
        draw(clean)
        if folder.name == "submission" and block.startswith("Схема:"):
            architecture_diagram()
if y > height - margin - 80:
    new_page()
draw('Ссылки на первоисточники', 13, True) if links else None
for label, url in links.items():
    draw(label + ': ' + url, 8.3)
finish_page()
pdf.finish()
print(f'Готово: {folder / "case.html"}; {folder / "case.pdf"} ({number} стр.)')
