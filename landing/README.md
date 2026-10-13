# Лендинг sekvyr.ru

Статический сайт на двух языках: русская страница в корне (`site/index.html`),
английская в `site/en/index.html`. Общие `style.css` и `lb.js` (лайтбокс для
кадров и кнопка "копировать"). Ни сборки, ни зависимостей.

Кадры в `site/shots/` - те же, что в README, перегнанные в webp: полный размер
для героя и лайтбокса, 960 по ширине для галереи и `og.png` для превью ссылки.

```sh
python docs/make-shots.py          # переснять кадры панели
python landing/build-shots.py      # перегнать их для сайта
```

## Посмотреть локально

```sh
python -m http.server -d landing/site 8090
```

## Как развернут

Сайт раздает nginx хостинга под HestiaCP из
`/home/<user>/web/sekvyr.ru/public_html`. Домен, сертификат, переход на https и
HSTS заводятся ее средствами. Записи `www` в DNS нет, поэтому домен заведен без
алиаса (`none`), иначе Let's Encrypt не выдаст сертификат:

```sh
v-add-web-domain <user> sekvyr.ru <ip> yes none
v-add-letsencrypt-domain <user> sekvyr.ru
v-add-web-domain-ssl-force <user> sekvyr.ru yes
v-add-web-domain-ssl-hsts <user> sekvyr.ru
```

Заголовки безопасности (CSP, запрет фрейма и прочие) лежат в
`nginx.ssl.conf_security`: Hestia подключает такие файлы в блок домена и не
затирает при пересборке.

```sh
scp landing/nginx.ssl.conf_security <host>:/tmp/
ssh <host> 'sudo cp /tmp/nginx.ssl.conf_security /home/<user>/conf/web/sekvyr.ru/ && sudo nginx -t && sudo systemctl reload nginx'
```

Выкладка - tar по ssh. Распаковка от имени пользователя сайта, иначе файлы
достанутся владельцу с рабочей машины:

```sh
cd landing/site && tar -czf - . | ssh <host> 'sudo -u <user> tar -xzf - -C /home/<user>/web/sekvyr.ru/public_html'
```

`robots.txt` создает сама панель хостинга, поэтому в репозитории его нет. Панель
Sekvyr живет на своем сервере и поддомене, отдельно от сайта: сайт и продукт не
должны падать вместе.

## Что править

- `site/index.html` и `site/en/index.html` - тексты. Держите их согласованными:
  расходятся они незаметно, а читают их разные люди.
- `site/style.css` - палитра взята из панели (`frontend/src/index.css`), чтобы
  сайт и продукт выглядели одним целым. Зеленый здесь - состояние, а не фон.
- `site/logo.svg`, `site/mark.svg`, `site/favicon.svg` - из бренд-кита, новые не
  рисуйте.
- После правки `style.css` или `lb.js` поднимите `?v=` в ссылках на них в обеих
  страницах, иначе браузеры еще долго будут держать старую версию.
