importScripts('/workbox-sw.js')

if (workbox) {
	  console.log(`Yay! Workbox is loaded 🎉`);
} else {
	  console.log(`Boo! Workbox didn't load 😬`);
}

import {registerRoute} from 'workbox-routing';
import {CacheFirst} from 'workbox-strategies';

registerRoute(new CacheFirst());
