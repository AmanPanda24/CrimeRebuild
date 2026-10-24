// Created by: Aman Kumar Panda
// Small UI helpers (no framework).
document.querySelectorAll('[data-autosubmit]').forEach(function (el) {
  el.addEventListener('change', function () { el.form.submit(); });
});
// Scroll a deep-linked timeline event into view
if (location.hash.startsWith('#ev')) {
  var t = document.querySelector(location.hash);
  if (t) { t.scrollIntoView({ block: 'center' }); }
}
// When an alert is opened in the timeline, bring its first linked event into view
var firstFocus = document.querySelector('.tl-item.focus');
if (firstFocus && !location.hash) { firstFocus.scrollIntoView({ block: 'center' }); }
