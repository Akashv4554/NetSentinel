document.addEventListener('DOMContentLoaded', function () {
  const overlay = document.getElementById('loadingOverlay');

  document.querySelectorAll('form[data-show-loading="true"]').forEach(function (form) {
    form.addEventListener('submit', function () {
      const button = form.querySelector('button[type="submit"]');
      if (button) {
        button.disabled = true;
        button.dataset.originalText = button.innerHTML;
        button.innerHTML = '<span class="spinner-border spinner-border-sm me-2" aria-hidden="true"></span>Working';
      }
      if (overlay) {
        overlay.classList.add('show');
        overlay.setAttribute('aria-hidden', 'false');
      }
    });
  });

  document.querySelectorAll('[data-table-search]').forEach(function (input) {
    const table = document.querySelector(input.dataset.tableSearch);
    if (!table) {
      return;
    }
    input.addEventListener('input', function () {
      const term = input.value.trim().toLowerCase();
      table.querySelectorAll('tbody tr').forEach(function (row) {
        row.hidden = term.length > 0 && !row.textContent.toLowerCase().includes(term);
      });
    });
  });

  document.querySelectorAll('th[data-sort-key]').forEach(function (header) {
    header.addEventListener('click', function () {
      const table = header.closest('table');
      const tbody = table ? table.querySelector('tbody') : null;
      if (!tbody) {
        return;
      }
      const index = Array.prototype.indexOf.call(header.parentElement.children, header);
      const direction = header.dataset.sortDirection === 'asc' ? 'desc' : 'asc';
      header.dataset.sortDirection = direction;
      Array.from(tbody.querySelectorAll('tr'))
        .sort(function (a, b) {
          const aText = a.children[index].textContent.trim();
          const bText = b.children[index].textContent.trim();
          return direction === 'asc' ? aText.localeCompare(bText, undefined, { numeric: true }) : bText.localeCompare(aText, undefined, { numeric: true });
        })
        .forEach(function (row) {
          tbody.appendChild(row);
        });
    });
  });
});
