// Vulnerable: unescaped HTML sinks.
function renderComment(el, comment) {
  el.innerHTML = comment;
}

function replaceBody(html) {
  document.body.outerHTML = html;
}

function Bio({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

module.exports = { renderComment, replaceBody, Bio };
