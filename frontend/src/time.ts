/* Время показываем в зоне, которую задала панель.
 *
 * Не в зоне браузера: панель и её журнал должны читаться одинаково у всех, кто
 * в них смотрит. Расследование по журналу сводится к вопросу "а что было в
 * 19:40", и ответ со сдвигом на три часа выглядит достоверно ровно до того
 * момента, когда по нему делают вывод.
 *
 * По умолчанию UTC: панель ставят где угодно, и "время сервера" без явной зоны
 * - это спор, а не факт. Свою зону задают переменной SEKVYR_TIMEZONE.
 */

let panelZone = 'UTC'

/** Панель сообщает свою зону при загрузке (см. /api/health). */
export function setTimeZone(zone: string): void {
  if (!zone) return
  try {
    new Intl.DateTimeFormat('ru-RU', { timeZone: zone })
    panelZone = zone
  } catch {
    // Неизвестное имя (MSK, Europe/Moskow): время шло бы в зоне каждого
    // браузера под подписью "время MSK" и у разных людей расходилось бы.
    // Остаемся в UTC, и подпись говорит правду.
    panelZone = 'UTC'
  }
}

export function timeZone(): string {
  return panelZone
}

function parse(iso: string): Date | null {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? null : d
}

function options(extra: Intl.DateTimeFormatOptions): Intl.DateTimeFormatOptions {
  try {
    // Проверяем зону: неизвестное имя роняет форматирование, а время должно
    // показаться в любом случае - пусть и в UTC.
    new Intl.DateTimeFormat('ru-RU', { timeZone: panelZone })
    return { ...extra, timeZone: panelZone }
  } catch {
    return extra
  }
}

/** 07.09.2026, 20:15:53 - для журнала */
export function formatDateTime(iso: string): string {
  const d = parse(iso)
  return d ? d.toLocaleString('ru-RU', options({ hour12: false })) : iso
}

/** 20:15:53 - когда дата уже сказана заголовком дня */
export function formatTime(iso: string): string {
  const d = parse(iso)
  return d
    ? d.toLocaleTimeString('ru-RU', options({ hour12: false }))
    : iso
}

/** 07.09.2026 - там, где время не нужно */
export function formatDate(iso: string): string {
  const d = parse(iso)
  return d ? d.toLocaleDateString('ru-RU', options({})) : iso
}

/** 01.03.2027 - день, который человек выбрал сам (срок ключа). Сервер хранит
 *  его полночью UTC, и в зоне западнее Гринвича он показывался бы предыдущим
 *  днем: выбрали 1 марта, а в списке "до 28.02". */
export function formatDay(iso: string): string {
  const d = parse(iso)
  return d ? d.toLocaleDateString('ru-RU', { timeZone: 'UTC' }) : iso
}

/** На сколько миллисекунд часы зоны панели впереди UTC в этот момент. */
function zoneShift(at: number): number {
  const parts = new Intl.DateTimeFormat(
    'en-US',
    options({
      hourCycle: 'h23',
      year: 'numeric',
      month: 'numeric',
      day: 'numeric',
      hour: 'numeric',
      minute: 'numeric',
      second: 'numeric',
    }),
  ).formatToParts(new Date(at))
  const part = (type: string) => Number(parts.find((p) => p.type === type)?.value ?? 0)
  const wall = Date.UTC(
    part('year'),
    part('month') - 1,
    part('day'),
    part('hour') % 24,
    part('minute'),
    part('second'),
  )
  return wall - Math.floor(at / 1000) * 1000
}

/** Конец дня "2026-09-30" в зоне панели, строкой ISO. "До 30 сентября" в
 *  панели с московским временем значит до полуночи по Москве; 23:59 UTC там
 *  уже 1 октября, и список показывал "до 01.10". */
export function endOfDay(date: string): string {
  const [y, m, d] = date.split('-').map(Number)
  const wall = Date.UTC(y, m - 1, d, 23, 59, 59)
  // Второй шаг - на случай перевода часов в этот день: сдвиг берется в
  // найденный момент, а не в "наивный".
  const first = wall - zoneShift(wall)
  return new Date(wall - zoneShift(first)).toISOString()
}

/** "2 дня назад" - когда важна не дата, а свежесть.
 *
 * Точную дату при этом не теряем: она уходит в подсказку рядом. В списке из
 * сотни ключей "06.09.2026, 14:12" читается как шум, а "3 дня назад" отвечает
 * на вопрос сразу.
 */
export function formatAgo(iso: string, lang: string): string {
  const d = parse(iso)
  if (!d) return ''
  const seconds = (Date.now() - d.getTime()) / 1000
  const steps: [Intl.RelativeTimeFormatUnit, number][] = [
    ['second', 60],
    ['minute', 60],
    ['hour', 24],
    ['day', 30],
    ['month', 12],
    ['year', Infinity],
  ]
  let value = seconds
  for (const [unit, size] of steps) {
    if (Math.abs(value) < size) {
      const rtf = new Intl.RelativeTimeFormat(lang === 'en' ? 'en' : 'ru', { numeric: 'auto' })
      return rtf.format(-Math.round(value), unit)
    }
    value /= size
  }
  return formatDate(iso)
}

/** Насколько давно это было, в часах. Пусто - "никогда". */
export function hoursSince(iso: string): number | null {
  const d = parse(iso)
  if (!d) return null
  return (Date.now() - d.getTime()) / 3_600_000
}

/* Когда отметка сервера считается старой.
 *
 * Агент ходит раз в минуту, поэтому час молчания - это уже не "задержка", а
 * повод посмотреть, жив ли он. Сутки - почти наверняка забытый сервер, который
 * до сих пор числится с доступом к прод-секретам. */
export function staleClass(iso: string): string {
  const hours = hoursSince(iso)
  if (hours === null) return ''
  if (hours >= 24) return 'stale-old'
  if (hours >= 1) return 'stale-warn'
  return ''
}
