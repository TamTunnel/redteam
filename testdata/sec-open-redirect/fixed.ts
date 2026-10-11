// Fixed: fixed destinations only.
interface Req {
  query: { next?: string };
}
interface Res {
  redirect(url: string): void;
}

export function login(req: Req, res: Res): void {
  res.redirect("/dashboard");
}

export function goHome(): void {
  window.location = "/home";
}
