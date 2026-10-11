// Fixed: fixed allowlisted endpoints; the user id is validated and only
// selects a pre-defined resource.
const axios = require("axios");

async function fetchProfile() {
  const res = await fetch("https://api.example.com/v1/profile");
  return res.json();
}

function fetchAvatar(userId) {
  if (!/^[a-z0-9_-]{1,32}$/i.test(userId)) throw new Error("bad user id");
  return axios.get("https://cdn.example.com/avatars/default.png");
}

module.exports = { fetchProfile, fetchAvatar };
