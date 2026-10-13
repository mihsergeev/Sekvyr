// Лайтбокс для кадров и кнопка "копировать": ради двух действий незачем тянуть
// библиотеку.
(function () {
  var lb = document.getElementById('lb');
  var img = lb && lb.querySelector('img');
  var copied = document.documentElement.lang === 'ru' ? 'скопировано' : 'copied';

  document.querySelectorAll('[data-lb]').forEach(function (a) {
    a.addEventListener('click', function (e) {
      if (!lb) return;
      e.preventDefault();
      var thumb = a.querySelector('img');
      img.alt = thumb ? thumb.alt : '';
      img.src = a.getAttribute('href');
      lb.classList.add('on');
      document.body.style.overflow = 'hidden';
    });
  });

  function close() {
    lb.classList.remove('on');
    document.body.style.overflow = '';
    // картинку убираем с задержкой, иначе на закрытии мелькает пустая рамка
    setTimeout(function () {
      if (!lb.classList.contains('on')) img.removeAttribute('src');
    }, 200);
  }
  if (lb) lb.addEventListener('click', close);
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && lb && lb.classList.contains('on')) close();
  });

  // Буфер обмена бывает недоступен: страница без https, запрет в настройках
  // браузера, встроенный просмотр. Тогда команда просто выделяется, и Ctrl+C
  // сделает остальное.
  function select(code) {
    var range = document.createRange();
    range.selectNodeContents(code);
    var sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }

  document.querySelectorAll('[data-copy]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var code = btn.parentNode.querySelector('code');
      if (!navigator.clipboard) return select(code);
      navigator.clipboard.writeText(code.textContent.trim()).then(function () {
        var was = btn.textContent;
        btn.textContent = copied;
        setTimeout(function () { btn.textContent = was; }, 1600);
      }, function () { select(code); });
    });
  });
})();
