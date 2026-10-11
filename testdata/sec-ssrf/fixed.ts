// Fixed: fixed allowlisted endpoint only.
import axios from "axios";

export async function fetchProfile(): Promise<unknown> {
  const res = await fetch("https://api.example.com/v1/profile");
  return res.json();
}

export function fetchAvatar(): Promise<unknown> {
  return axios.get("https://cdn.example.com/avatars/default.png");
}
