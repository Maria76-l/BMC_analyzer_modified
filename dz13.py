#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Автоматизация расчётов для домашнего задания №13
Дисциплина: Управление жизненным циклом информационных систем
Студент: Лысенкова М.А., группа КН-23-10

Программа автоматически рассчитывает:
1. Трудоёмкость по COCOMO (PM)
2. Длительность проекта (TDEV)
3. Стоимость по алгоритмической модели
4. Оценку по объектным точкам
5. Модель Рэлея (помесячное распределение)
6. Сравнение с аналогом
7. Сравнение инвестиционных альтернатив
8. Полное ТЭО по трём параметрам
"""

import math

# ============================================================
# КЛАСС ДЛЯ РАСЧЁТА ВСЕХ МЕТРИК
# ============================================================

class ProjectCalculator:
    def __init__(self, kdsi=3.231, m=1.077, pm_manual=None):
        """
        Инициализация параметров проекта
        kdsi: тысячи строк кода (KDSI)
        m: корректирующий множитель COCOMO
        pm_manual: ручная трудоёмкость (если не нужен расчёт)
        """
        self.kdsi = kdsi
        self.m = m

        # Расчёт трудоёмкости
        if pm_manual:
            self.pm = pm_manual
        else:
            self.pm = 2.4 * (kdsi ** 1.05) * m

        # Расчёт длительности
        B = 1.05
        exponent = 0.33 + 0.2 * (B - 1.01)
        self.tdev = 3.0 * (self.pm ** exponent)

        # Параметры для стоимости
        self.pm_hours = self.pm * 160  # человеко-часы
        self.cpm_rub = 351000  # стоимость человеко-месяца в рублях
        self.usd_rate = 85
        self.cpm_usd = self.cpm_rub / self.usd_rate

        # Коэффициенты для алгоритмической стоимости
        self.rely = 1.15
        self.exp = 1.07

        # Параметры для модели Рэлея
        self.sigma = 3
        self.t_hours = self.pm * 160

        # Объектные точки
        self.op_raw = 31
        self.reuse_pct = 10
        self.prod = 13

    # --------------------------------------------------------
    # 1. МЕТОД ОБЪЕКТНЫХ ТОЧЕК
    # --------------------------------------------------------
    def calculate_object_points(self):
        """Расчёт трудоёмкости через объектные точки"""
        nop = self.op_raw * (1 - self.reuse_pct / 100)
        pm_op = nop / self.prod
        return {
            'op_raw': self.op_raw,
            'reuse_pct': self.reuse_pct,
            'nop': round(nop, 1),
            'prod': self.prod,
            'pm': round(pm_op, 2)
        }

    # --------------------------------------------------------
    # 2. АЛГОРИТМИЧЕСКАЯ МОДЕЛЬ СТОИМОСТИ
    # --------------------------------------------------------
    def calculate_algorithmic_cost(self):
        """Расчёт стоимости по алгоритмической модели"""
        sc_usd = self.pm * self.rely * self.exp * self.cpm_usd
        sc_rub = sc_usd * self.usd_rate
        return {
            'sc_usd': round(sc_usd, 0),
            'sc_rub': round(sc_rub, 0)
        }

    # --------------------------------------------------------
    # 3. СРАВНЕНИЕ С АНАЛОГОМ
    # --------------------------------------------------------
    def calculate_analog_comparison(self):
        """Сравнение с аналогом (Django-приложение, 1500 строк)"""
        kdsi_analog = 1.5
        pm_analog_base = 2.4 * (kdsi_analog ** 1.05)
        m_analog = 0.87 * 1.07  # TOOL * EXP
        pm_analog = pm_analog_base * m_analog
        sc_analog_usd = pm_analog * self.cpm_usd
        sc_analog_rub = sc_analog_usd * self.usd_rate

        current_cost = self.pm * self.rely * self.exp * self.cpm_usd
        k = current_cost / sc_analog_usd

        return {
            'analog_kdsi': kdsi_analog,
            'analog_pm': round(pm_analog, 2),
            'analog_sc_usd': round(sc_analog_usd, 0),
            'analog_sc_rub': round(sc_analog_rub, 0),
            'current_sc_usd': round(current_cost, 0),
            'coefficient': round(k, 2)
        }

    # --------------------------------------------------------
    # 4. МОДЕЛЬ РЭЛЕЯ
    # --------------------------------------------------------
    def calculate_rayleigh(self, max_months=12):
        """Помесячное распределение трудоёмкости по модели Рэлея"""
        sigma2 = self.sigma ** 2
        two_sigma2 = 2 * sigma2
        results = []
        cumulative = 0

        for t in range(1, max_months + 1):
            exponent = - (t ** 2) / two_sigma2
            ft = (t / sigma2) * math.exp(exponent)
            et = self.t_hours * ft
            cumulative += et
            results.append({
                't': t,
                'ft': round(ft, 4),
                'et': round(et, 2),
                'cumulative': round(cumulative, 2)
            })

        # Поиск пика
        peak = max(results, key=lambda x: x['et'])

        return {
            'distribution': results,
            'peak_month': peak['t'],
            'peak_hours': peak['et']
        }

    # --------------------------------------------------------
    # 5. ТЭО ПО ТРЁМ ПАРАМЕТРАМ
    # --------------------------------------------------------
    def calculate_teo(self):
        """Расчёт ТЭО по трём параметрам"""
        # Параметр 1: Аппаратные средства + ПО + обслуживание
        hardware = {
            'notebooks': 2 * 120000,
            'monitors': 2 * 25000,
            'keyboard_mouse': 2 * 5000,
            'server_rent': 48000
        }
        hardware_total = sum(hardware.values())
        maintenance = hardware_total * 0.15  # 15% в год

        # Параметр 2: Обучение
        training = 75000  # 3 курса

        # Параметр 3: Персонал (с учётом всех специалистов)
        # Python-разработчик: PM
        # DevOps: 2 чел.-мес.
        # ИБ-инженер: 1.5 чел.-мес.
        python_cost = self.pm * self.cpm_rub
        devops_cost = 2 * self.cpm_rub
        security_cost = 1.5 * self.cpm_rub
        personnel_total = python_cost + devops_cost + security_cost

        # Сводная стоимость
        total_one_time = hardware_total + training + maintenance
        total_all = total_one_time + personnel_total

        return {
            'hardware': hardware,
            'hardware_total': hardware_total,
            'maintenance': maintenance,
            'training': training,
            'param1_total': hardware_total + maintenance,
            'param2_total': training,
            'param3_total': personnel_total,
            'python_cost': python_cost,
            'devops_cost': devops_cost,
            'security_cost': security_cost,
            'total_one_time': total_one_time,
            'total_all': total_all
        }

    # --------------------------------------------------------
    # 6. СРАВНЕНИЕ ИНВЕСТИЦИОННЫХ АЛЬТЕРНАТИВ
    # --------------------------------------------------------
    def get_investment_alternatives(self, teo):
        """Формирование таблицы инвестиционных альтернатив"""
        return [
            {
                'name': '1. Базовый (выбранный)',
                'composition': 'Python-разработчик + DevOps + ИБ-инженер',
                'cost': round(teo['total_all'], 0),
                'pros': 'Полный функционал, качество',
                'cons': 'Высокая стоимость'
            },
            {
                'name': '2. Экономичный',
                'composition': 'Только Python-разработчик (студент)',
                'cost': round(teo['python_cost'], 0),
                'pros': 'Низкая стоимость',
                'cons': 'Долго, риск ошибок'
            },
            {
                'name': '3. Покупка готового решения',
                'composition': 'Коммерческая лицензия',
                'cost': 2500000,
                'pros': 'Сразу работает',
                'cons': 'Recurring-затраты, кастомизация'
            },
            {
                'name': '4. Open-source форк',
                'composition': 'Доработка существующего аналога',
                'cost': 800000,
                'pros': 'Дешевле разработки с нуля',
                'cons': 'Не полное соответствие ТЗ'
            }
        ]


# ============================================================
# ФУНКЦИЯ ДЛЯ ВЫВОДА РЕЗУЛЬТАТОВ В КОНСОЛЬ
# ============================================================

def print_header(title, symbol='=', length=80):
    print(f"\n{symbol * length}")
    print(f"{title:^{length}}")
    print(f"{symbol * length}\n")


def main():
    # Инициализация калькулятора
    calc = ProjectCalculator(kdsi=3.231, m=1.077)

    # Получение всех расчётов
    op_results = calc.calculate_object_points()
    cost_results = calc.calculate_algorithmic_cost()
    analog_results = calc.calculate_analog_comparison()
    rayleigh_results = calc.calculate_rayleigh()
    teo = calc.calculate_teo()
    alternatives = calc.get_investment_alternatives(teo)

    # ============================================================
    # ВЫВОД РЕЗУЛЬТАТОВ
    # ============================================================

    print_header("АВТОМАТИЗИРОВАННЫЙ РАСЧЁТ ТЭО И COCOMO")
    print("Домашнее задание №13 | Лысенкова М.А. | Группа КН-23-10\n")

    # 1. ИСХОДНЫЕ ДАННЫЕ
    print_header("1. ИСХОДНЫЕ ДАННЫЕ", '-')
    print(f"  KDSI (тыс. строк кода):        {calc.kdsi}")
    print(f"  Корректирующий множитель M:    {calc.m}")
    print(f"  Объём кода (строк):            {int(calc.kdsi * 1000)}")
    print(f"  Стоимость человеко-месяца:     {calc.cpm_rub:,.0f} руб. ({calc.cpm_usd:.0f} USD)")
    print(f"  Курс USD/RUB:                  {calc.usd_rate}")

    # 2. ОЦЕНКА ПО МЕТОДУ ОБЪЕКТНЫХ ТОЧЕК
    print_header("2. ОЦЕНКА ПО МЕТОДУ ОБЪЕКТНЫХ ТОЧЕК", '-')
    print(f"  Сырые объектные точки (OP_raw):    {op_results['op_raw']}")
    print(f"  Повторное использование (%):       {op_results['reuse_pct']}%")
    print(f"  Новые объектные точки (NOP):       {op_results['nop']}")
    print(f"  Производительность (PROD):         {op_results['prod']} OP/мес")
    print(f"  Трудоёмкость (PM_OP):              {op_results['pm']} чел.-мес.")

    # 3. РАСЧЁТ ПО МОДЕЛИ COCOMO
    print_header("3. РАСЧЁТ ПО МОДЕЛИ COCOMO", '-')
    print(f"  Трудоёмкость (PM):        {calc.pm:.2f} чел.-мес.")
    print(f"  Трудоёмкость (чел.-ч):    {calc.pm_hours:.0f} чел.-ч")
    print(f"  Длительность (TDEV):      {calc.tdev:.2f} месяцев")

    # 4. АЛГОРИТМИЧЕСКАЯ МОДЕЛЬ СТОИМОСТИ
    print_header("4. АЛГОРИТМИЧЕСКАЯ МОДЕЛЬ СТОИМОСТИ", '-')
    print(f"  Формула: SC = PM × RELY × EXP × CPM")
    print(f"  RELY = {calc.rely}, EXP = {calc.exp}, CPM = {calc.cpm_usd:.0f} USD")
    print(f"  Стоимость разработки:    {cost_results['sc_usd']:,.0f} USD")
    print(f"  Стоимость разработки:    {cost_results['sc_rub']:,.0f} руб.")

    # 5. СРАВНЕНИЕ С АНАЛОГОМ
    print_header("5. СРАВНЕНИЕ С АНАЛОГОМ", '-')
    print(f"  Аналог (Django-приложение):           {analog_results['analog_kdsi']} KDSI")
    print(f"  Трудоёмкость аналога:                 {analog_results['analog_pm']} чел.-мес.")
    print(f"  Стоимость аналога:                    {analog_results['analog_sc_usd']:,.0f} USD")
    print(f"  Стоимость аналога:                    {analog_results['analog_sc_rub']:,.0f} руб.")
    print(f"  Стоимость текущего проекта:           {analog_results['current_sc_usd']:,.0f} USD")
    print(f"  Коэффициент удорожания (k):           {analog_results['coefficient']}")
    print(f"  Аналоговая оценка (с k):              {analog_results['current_sc_usd']:,.0f} USD")

    # 6. МОДЕЛЬ РЭЛЕЯ
    print_header("6. МОДЕЛЬ РЭЛЕЯ (помесячное распределение трудоёмкости)", '-')
    print(f"  Общая трудоёмкость: {calc.t_hours:.1f} чел.-ч | σ = {calc.sigma}")
    print(f"  Пик нагрузки: {rayleigh_results['peak_month']}-й месяц ({rayleigh_results['peak_hours']:.2f} чел.-ч)\n")

    print("  Месяц (t) |    f(t)    |  E(t), чел.-ч  |  Нарастающий итог")
    print("  " + "-" * 55)
    for row in rayleigh_results['distribution']:
        print(f"  {row['t']:^9} | {row['ft']:10.4f} | {row['et']:14.2f} | {row['cumulative']:17.2f}")

    # 7. ТЕХНИКО-ЭКОНОМИЧЕСКОЕ ОБОСНОВАНИЕ (ТЭО)
    print_header("7. ТЕХНИКО-ЭКОНОМИЧЕСКОЕ ОБОСНОВАНИЕ (ТРИ ПАРАМЕТРА)", '-')

    print("  Параметр 1: Аппаратные средства и ПО (с обслуживанием)")
    print(f"    - Ноутбуки (2 шт.):                 {teo['hardware']['notebooks']:,.0f} руб.")
    print(f"    - Мониторы (2 шт.):                 {teo['hardware']['monitors']:,.0f} руб.")
    print(f"    - Клавиатура + мышь (2 компл.):     {teo['hardware']['keyboard_mouse']:,.0f} руб.")
    print(f"    - Аренда сервера (год):             {teo['hardware']['server_rent']:,.0f} руб.")
    print(f"    - Итого аппаратные средства:        {teo['hardware_total']:,.0f} руб.")
    print(f"    - Обслуживание (15% в год):         {teo['maintenance']:,.0f} руб.")
    print(f"    - ПО (open source):                 0 руб.")
    print(f"    → Итого параметр 1:                 {teo['param1_total']:,.0f} руб.\n")

    print("  Параметр 2: Командировки и обучение")
    print(f"    - Обучение (3 курса):              {teo['param2_total']:,.0f} руб.")
    print(f"    - Командировки:                    0 руб.")
    print(f"    → Итого параметр 2:                 {teo['param2_total']:,.0f} руб.\n")

    print("  Параметр 3: Расходы на персонал (привлечённые специалисты)")
    print(f"    - Python-разработчик ({calc.pm:.2f} чел.-мес.):   {teo['python_cost']:,.0f} руб.")
    print(f"    - DevOps-инженер (2 чел.-мес.):     {teo['devops_cost']:,.0f} руб.")
    print(f"    - ИБ-инженер (1,5 чел.-мес.):       {teo['security_cost']:,.0f} руб.")
    print(f"    → Итого параметр 3:                 {teo['param3_total']:,.0f} руб.\n")

    print("  " + "=" * 55)
    print(f"  Единовременные затраты (парам.1 + обучение):  {teo['total_one_time']:,.0f} руб.")
    print(f"  ВСЕГО по проекту (с персоналом):               {teo['total_all']:,.0f} руб.")
    print("  " + "=" * 55)

    # 8. СРАВНЕНИЕ ИНВЕСТИЦИОННЫХ АЛЬТЕРНАТИВ
    print_header("8. СРАВНЕНИЕ ИНВЕСТИЦИОННЫХ АЛЬТЕРНАТИВ", '-')
    print(f"  {'Альтернатива':<30} | {'Состав':<35} | {'Стоимость':<15} | {'Плюсы':<20}")
    print("  " + "-" * 100)
    for alt in alternatives:
        print(f"  {alt['name']:<30} | {alt['composition']:<35} | {alt['cost']:>12,.0f} руб. | {alt['pros']:<20}")

    # 9. ВРЕМЕННОЙ ГРАФИК И ДАТА НАЙМА ПЕРСОНАЛА
    print_header("9. ВРЕМЕННОЙ ГРАФИК РАБОТ И ДАТА НАЙМА ПЕРСОНАЛА", '-')

    # Фазы проекта
    phases = [
        ('Планирование и анализ требований', 0.09, 0.83),
        ('Проектирование архитектуры', 0.16, 1.39),
        ('Детальное проектирование', 0.26, 2.32),
        ('Кодирование и модульное тестирование', 0.29, 2.58),
        ('Интеграционное и системное тестирование', 0.16, 1.39),
        ('Внедрение и сопровождение', 0.04, 0.35)
    ]

    print("\n  Распределение трудоёмкости по фазам проекта:\n")
    print(f"  {'Фаза проекта':<35} | {'Доля':<8} | {'Трудоём., чел.-мес.':<20}")
    print("  " + "-" * 65)
    for name, percent, pm_phase in phases:
        print(f"  {name:<35} | {percent*100:>5.0f}%   | {pm_phase:<20.2f}")

    print("\n  Дата найма персонала:")
    print("    - Python-разработчик:   1-я неделя проекта")
    print("    - Инженер ИБ:            начало 2-го месяца (март 2026)")
    print("    - DevOps-инженер:        начало 2-го месяца (март 2026)")
    print(f"\n    Пик трудоёмкости:      {rayleigh_results['peak_month']}-й месяц")
    print("    Обоснование: найм за 2–4 недели до пика для адаптации")

    # 10. ВЫВОД
    print_header("10. ВЫВОД", '=')
    print(f"  В ходе выполнения домашнего задания №13 получены навыки")
    print(f"  технико-экономического обоснования проектов программных средств.")
    print(f"\n  Итоговые показатели проекта:")
    print(f"    - Трудоёмкость разработки:     {calc.pm:.2f} чел.-мес.")
    print(f"    - Длительность (TDEV):         {calc.tdev:.2f} месяцев")
    print(f"    - Стоимость разработки:        {cost_results['sc_rub']:,.0f} руб.")
    print(f"    - Полная стоимость (с ТЭО):    {teo['total_all']:,.0f} руб.")
    print(f"    - Пик нагрузки:                {rayleigh_results['peak_month']}-й месяц")
    print(f"\n  Расчёты автоматизированы с помощью разработанного Python-скрипта.")
    print(f"  Наиболее точной является оценка по модели COCOMO, основанная")
    print(f"  на фактическом объёме кода ({int(calc.kdsi * 1000)} строк).")


# ============================================================
# ЗАПУСК ПРОГРАММЫ
# ============================================================

if __name__ == "__main__":
    main()