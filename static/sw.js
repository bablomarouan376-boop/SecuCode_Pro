// static/sw.js
self.addEventListener('install', (e) => {
  console.log('SecuCode Service Worker Installed');
});

self.addEventListener('fetch', (e) => {
  // هذا الكود ضروري ليعمل الموقع بدون إنترنت ولتفعيل خاصية التثبيت
  e.respondWith(fetch(e.request));
});
