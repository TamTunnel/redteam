// Vulnerable: unescaped HTML sink.
export function renderComment(el: HTMLElement, comment: string): void {
  el.innerHTML = comment;
}

export function replaceBody(html: string): void {
  document.body.outerHTML = html;
}
