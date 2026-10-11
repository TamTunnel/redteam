// Vulnerable: server fetches a caller-supplied URL.
const axios = require("axios");

async function fetchProfile(userUrl) {
  const res = await fetch(userUrl);
  return res.json();
}

function fetchAvatar(userId) {
  return axios.get("https://cdn.example.com/avatars/" + userId);
}

module.exports = { fetchProfile, fetchAvatar };
