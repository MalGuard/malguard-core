'use strict';
self.postMessage({ type: 'ready' });
self.addEventListener('message', function (event) {
  if (!event.data || event.data.type !== 'hang') return;
  // Deliberately keep the worker alive without returning a result.
  setInterval(function () {}, 1000);
});
