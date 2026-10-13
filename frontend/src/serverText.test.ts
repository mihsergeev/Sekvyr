/* Тексты сервера в английском интерфейсе.
 *
 * Сервер отвечает по-русски, и без перевода англоязычный человек видел бы
 * русскую строку в каждом отказе и в каждой подробности журнала.
 */

import { beforeAll, describe, expect, it, vi } from 'vitest'

let serverText: (text: string) => string

beforeAll(async () => {
  // Язык i18n читает при первом импорте, а общая подготовка тестов ставит
  // русский: модули грузим заново уже с английским выбором.
  vi.resetModules()
  localStorage.setItem('sekvyr_lang', 'en')
  serverText = (await import('./serverText')).serverText
  localStorage.setItem('sekvyr_lang', 'ru')
})

describe('serverText по-английски', () => {
  it('переводит точную строку', () => {
    expect(serverText('Такого ключа здесь нет')).toBe('There is no such key here')
  })

  it('переводит подстановку, если там русское слово', () => {
    expect(serverText('Нет права «читать значения» в этом месте')).toBe(
      'No "read values" right in this place',
    )
    expect(serverText('Имя окружения: строчные латинские буквы, цифры и дефис')).toBe(
      'The name of the environment: lowercase Latin letters, digits and hyphens',
    )
  })

  it('переводит вложенную ошибку разбора файла', () => {
    expect(serverText('Файл не разобрался: строка без «=»: FOO')).toBe(
      'The file could not be parsed: a line without "=": FOO',
    )
  })

  it('переводит отказ проверки адреса с названием канала', () => {
    expect(
      serverText('Вебхук: адрес должен начинаться с https:// — иначе оповещения уйдут открытым текстом'),
    ).toBe('Webhook: the address must start with https://, otherwise alerts would travel in plain text')
  })

  it('переводит каждый пункт журнала, сколько бы их ни было', () => {
    expect(
      serverText('название; группа; в архив; порог согласования: 0 → 30; обязательные ключи: 3 шт.'),
    ).toBe('title; group; archived; approval threshold: 0 -> 30; required keys: 3')
  })

  it('комментарий человека не переводится кусками', async () => {
    const { versionComment } = await import('./serverText')
    expect(versionComment('роль: старый ключ')).toBe('роль: старый ключ')
    expect(versionComment('было 5 стало 6')).toBe('было 5 стало 6')
    expect(versionComment('переименован из закрытой папки')).toBe('renamed from a closed folder')
    expect(versionComment('снимок «перед релизом», версия 4')).toBe('snapshot "перед релизом", version 4')
    expect(versionComment('откат к версии 2')).toBe('rollback to version 2')
  })

  it('переводит скрытое прежнее место ключа', () => {
    expect(serverText('было в закрытой папке · вслед за prod')).toBe('was in a closed folder · following prod')
    expect(serverText('было в закрытой папке')).toBe('was in a closed folder')
    expect(serverText('переименован из закрытой папки')).toBe('renamed from a closed folder')
  })

  it('переводит подробности выдачи права, оповещений и логотипа', () => {
    expect(serverText('allow list,read все проекты/')).toBe('allow list,read all projects/')
    expect(serverText('telegram; вебхук; копия журнала')).toBe('telegram; webhook; audit log copy')
    expect(serverText('выключено')).toBe('off')
    expect(serverText('image/png, 1234 байт; тёмная тема: image/svg+xml, 99 байт')).toBe(
      'image/png, 1234 bytes; dark theme: image/svg+xml, 99 bytes',
    )
  })

  it('переводит подробности журнала с подстановками', () => {
    expect(serverText('версия 3, повторных чтений с прошлой записи: 2')).toBe(
      'version 3, repeated reads since the last entry: 2',
    )
    expect(serverText('долями: 3 из 5')).toBe('with shares: 3 of 5')
    expect(serverText('система')).toBe('system')
  })

  it('переводит отказ источника переноса', () => {
    expect(serverText('вход в Infisical не удался: HTTP 401 — bad token')).toBe(
      'the Infisical login failed: HTTP 401, bad token',
    )
    expect(serverText('Vault не отдал секрет shop/db: HTTP 403')).toBe(
      'Vault did not return the secret shop/db: HTTP 403',
    )
  })

  it('незнакомую строку и данные оставляет как есть', () => {
    expect(serverText('совсем новая ошибка')).toBe('совсем новая ошибка')
    expect(serverText('machine:skv-0123')).toBe('machine:skv-0123')
  })
})

describe('serverText по-русски', () => {
  it('ничего не трогает', async () => {
    vi.resetModules()
    localStorage.setItem('sekvyr_lang', 'ru')
    const ru = (await import('./serverText')).serverText
    expect(ru('Такого ключа здесь нет')).toBe('Такого ключа здесь нет')
  })
})
