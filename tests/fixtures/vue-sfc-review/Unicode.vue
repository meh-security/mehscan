<template>éλ<p v-html="markup"></p></template><script setup>const markup = window.location.hash; document.body.innerHTML = markup;</script>
