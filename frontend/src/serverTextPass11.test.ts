/* Новые тексты переноса в английском интерфейсе. */

import { beforeAll, describe, expect, it, vi } from 'vitest'

let serverText: (text: string) => string

beforeAll(async () => {
  vi.resetModules()
  localStorage.setItem('sekvyr_lang', 'en')
  serverText = (await import('./serverText')).serverText
  localStorage.setItem('sekvyr_lang', 'ru')
})

describe('serverText: перенос, одиннадцатый проход', () => {
  it('ответ источника не того формата и не того размера', () => {
    expect(serverText('Infisical не отдал секреты: ответ не в том формате, что описан в API источника')).toBe(
      'Infisical did not return the secrets: the answer is not in the format described by the source API',
    )
    expect(serverText('Vault не отдал секрет shop/db: ответ больше 20 МБ, сузьте путь')).toBe(
      'Vault did not return the secret shop/db: the answer is larger than 20 MB, narrow the path',
    )
    expect(serverText('на той стороне больше 5000 ключей, сузьте путь')).toBe(
      'the source has more than 5000 keys, narrow the path',
    )
  })

  it('импорты, скрытые значения и пропуски', () => {
    expect(
      serverText(
        'ключей из импортов Infisical: 2. Они переносятся как обычные ключи и ссылками больше не будут, а ключ самого окружения важнее импортированного с тем же именем',
      ),
    ).toMatch(/^keys from Infisical imports: 2\. /)
    expect(serverText('Infisical не отдал значение: у машинной личности нет права его читать')).toBe(
      'Infisical did not return the value: the machine identity may not read it',
    )
    expect(serverText('недопустимое имя')).toBe('invalid name')
    expect(serverText('недопустимая папка')).toBe('invalid folder')
  })
})
