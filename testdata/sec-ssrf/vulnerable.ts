// Vulnerable: server fetches a caller-supplied URL.
import axios from "axios";

export async function fetchProfile(userUrl: string): Promise<unknown> {
  const res = await fetch(userUrl);
  return res.json();
}

export function fetchAvatar(userId: string): Promise<unknown> {
  return axios.get("https://cdn.example.com/avatars/" + userId);
}
