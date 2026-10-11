// Fixed: text sinks and escaped output only.
function renderComment(el, comment) {
  el.textContent = comment;
}

function Bio({ text }) {
  const el = document.createElement("div");
  el.textContent = text;
  return el;
}

module.exports = { renderComment, Bio };
