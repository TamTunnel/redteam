// Vulnerable: redirect target comes from the request.
interface Req {
  query: { next?: string };
}
interface Res {
  redirect(url: string): void;
}

export function login(req: Req, res: Res): void {
  const next = req.query.next ?? "/";
  res.redirect(next);
}

export function go(dest: string): void {
  window.location = dest;
}
