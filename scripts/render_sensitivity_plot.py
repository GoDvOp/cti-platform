"""Optional Matplotlib figure from a saved sensitivity experiment."""
import json
import sys
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
ROOT=Path(__file__).resolve().parents[1]
root=Path(sys.argv[1]) if len(sys.argv)>1 else ROOT/'data/processed/sensitivity'
d=json.loads((root/'sensitivity.json').read_text())
labels={'half_life_days.interest':'Период затухания интереса','half_life_days.technical':'Период затухания тех. оснований',
 'confidence.high':'Уверенность high','confidence.medium':'Уверенность medium','basis.victim_report':'Основание: сообщение компании',
 'basis.unspecified':'Основание без заданного типа','interest_caps.incident_history':'Бюджет истории инцидентов',
 'interest_caps.direct_signal':'Бюджет адресных сигналов','interest_caps.sector_activity':'Бюджет отраслевого контекста',
 'unknown_version_multiplier':'Штраф неизвестной версии','technical_base_multiplier':'Базовый технический множитель',
 'exploitation_bonus_multiplier':'Бонус эксплуатации'}
fig,axes=plt.subplots(1,3,figsize=(17,6.5),layout='constrained')
for ax,(cid,dim,title) in zip(axes,[('novabev','interest','Novabev · интерес'),('equifax','interest','Equifax · интерес'),('equifax','technical','Equifax · технический индекс')]):
 base=next(c for c in d['companies'] if c['company_id']==cid)[dim]['baseline']
 grouped={}
 for s in d['scenarios']:
  if s['kind']!='one_at_a_time':continue
  score=next(c for c in s['companies'] if c['company_id']==cid)[dim]['score']
  if score is not None:grouped.setdefault(s['parameter'],[]).append(score)
 ranked=sorted(grouped.items(),key=lambda x:max(abs(v-base) for v in x[1]),reverse=True)[:5]
 for y,(param,values) in enumerate(reversed(ranked)):
  low,high=min(values+[base]),max(values+[base])
  ax.barh(y,high-low,left=low,height=.55,color='#5B86B2',alpha=.85)
  ax.plot(values,[y]*len(values),'o',markersize=4,color='#23486d')
 ax.axvline(base,color='#bd6947',linestyle='--',linewidth=1.4,label='Исходный балл')
 ax.set_yticks(range(len(ranked)),[labels.get(k,k) for k,_ in reversed(ranked)],fontsize=9)
 ax.set_title(title,fontsize=12,fontweight='bold');ax.set_xlabel('Баллы / 100',fontsize=10)
 ax.grid(axis='x',alpha=.18);ax.set_axisbelow(True);ax.spines[['top','right']].set_visible(False)
 ax.ticklabel_format(style='sci',axis='x',scilimits=(-3,3))
 ax.legend(fontsize=8,loc='upper right')
fig.suptitle('Чувствительность к изменению одного коэффициента на ±20%',fontsize=16,fontweight='bold')
fig.supxlabel('Шкалы панелей различаются · один текущий снимок · диапазоны не являются вероятностями или доверительными интервалами',fontsize=10)
fig.savefig(root/'graph.svg',bbox_inches='tight')
fig.savefig(root/'graph.png',dpi=120,bbox_inches='tight')
print('Sensitivity figure saved')
