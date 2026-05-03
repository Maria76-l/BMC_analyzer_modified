from sympy import symbols
import pandas as pd
import matplotlib.pyplot as plt
import io
import base64

def calculate_risks(commands_qs):
    C, F = symbols('C F')
    risk_formula = C * F
    commands, freq, crit = [], [], []
    for item in commands_qs:
        commands.append(item.command)
        freq.append(item.frequency)
        crit.append(item.criticality)
    risk_original = [float(risk_formula.subs({C: c, F: f})) for f, c in zip(freq, crit)]
    crit_enh = [c * 1.2 if c > 0.5 else c for c in crit]
    risk_enhanced = [float(risk_formula.subs({C: c, F: f})) for f, c in zip(freq, crit_enh)]
    df_orig = pd.DataFrame({
        '№': range(1, len(commands)+1),
        'Команда': commands,
        'Частота (F)': freq,
        'Критичность (C)': crit,
        'Индекс угрозы (R=C×F)': risk_original
    })
    df_enh = pd.DataFrame({
        '№': range(1, len(commands)+1),
        'Команда': commands,
        'Частота (F)': freq,
        'Критичность (усиленная)': crit_enh,
        'Индекс угрозы (усиленный)': risk_enhanced
    })
    return risk_original, risk_enhanced, df_orig, df_enh

def generate_bar_chart(data, title="Индекс угрозы по командам"):
    plt.figure(figsize=(12, 6))
    colors = ['#28a745' if x <= 1.0 else '#ffc107' if x <= 2.0 else '#dc3545' for x in data]
    bars = plt.bar(range(1, len(data)+1), data, color=colors, edgecolor='black', linewidth=0.8)
    for bar, val in zip(bars, data):
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.05,
                 f'{val:.2f}', ha='center', va='bottom', fontsize=9, fontweight='bold')
    plt.xlabel('Номер команды', fontsize=11)
    plt.ylabel('Индекс угрозы (R = C × F)', fontsize=11)
    plt.title(title, fontsize=14, fontweight='bold')
    plt.xticks(range(1, len(data)+1))
    plt.grid(axis='y', linestyle='--', alpha=0.6)
    plt.ylim(0, max(data) * 1.15 if data else 1)
    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=100)
    buf.seek(0)
    img = base64.b64encode(buf.read()).decode('utf-8')
    plt.close()
    return img

def generate_pie_chart(data, title="Вклад команд в общий индекс угрозы"):
    filtered = [(val, idx) for idx, val in enumerate(data) if val > 0]
    if not filtered:
        plt.figure(figsize=(8,8))
        plt.pie([1], labels=['Нет данных'], autopct='%1.1f%%')
        plt.title(title)
        buf = io.BytesIO()
        plt.savefig(buf, format='png')
        buf.seek(0)
        img = base64.b64encode(buf.read()).decode('utf-8')
        plt.close()
        return img
    values, indices = zip(*filtered)
    labels = [str(i+1) for i in indices]
    if len(values) > 5:
        sorted_data = sorted(zip(values, labels), reverse=True)
        top5 = sorted_data[:5]
        others_val = sum(v for v, _ in sorted_data[5:])
        others_label = f'Остальные ({len(sorted_data)-5})'
        values = [v for v, _ in top5] + [others_val]
        labels = [l for _, l in top5] + [others_label]
    def autopct_format(pct):
        return f'{pct:.1f}%' if pct > 3 else ''
    plt.figure(figsize=(8,8))
    wedges, texts, autotexts = plt.pie(values, labels=labels, autopct=autopct_format,
                                        startangle=90, wedgeprops={'edgecolor': 'white', 'linewidth': 1.5})
    for autotext in autotexts:
        autotext.set_fontsize(9)
        autotext.set_weight('bold')
    plt.title(title, fontsize=14, fontweight='bold')
    plt.axis('equal')
    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=100)
    buf.seek(0)
    img = base64.b64encode(buf.read()).decode('utf-8')
    plt.close()
    return img

def generate_line_chart(risk_orig, risk_enh):
    plt.figure(figsize=(12,6))
    x = range(1, len(risk_orig)+1)
    plt.plot(x, risk_orig, label='Исходный индекс угрозы', marker='o', linestyle='-', color='#007bff', linewidth=2, markersize=8)
    plt.plot(x, risk_enh, label='Усиленный индекс угрозы', marker='s', linestyle='--', color='#fd7e14', linewidth=2, markersize=8)
    plt.xlabel('Номер команды', fontsize=11)
    plt.ylabel('Индекс угрозы', fontsize=11)
    plt.title('Сравнение исходного и усиленного индекса угрозы', fontsize=14, fontweight='bold')
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.xticks(x)
    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=100)
    buf.seek(0)
    img = base64.b64encode(buf.read()).decode('utf-8')
    plt.close()
    return img