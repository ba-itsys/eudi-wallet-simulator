// Shows only the credential queries and claims of the currently selected alternatives. Every
// value is still submitted with the form, so the page works without this script as well.
function applyAlternatives() {
    const selects = document.querySelectorAll('select[data-alternatives-select]');
    const controlled = new Set();
    const selected = new Set();
    selects.forEach(select => {
        Array.from(select.options).forEach(option => {
            (option.dataset.queryIds || '').split(',').filter(Boolean).forEach(id => controlled.add(id));
        });
        const chosen = select.options[select.selectedIndex];
        (chosen.dataset.queryIds || '').split(',').filter(Boolean).forEach(id => selected.add(id));
    });
    document.querySelectorAll('[data-query-slot]').forEach(slot => {
        const queryId = slot.dataset.querySlot;
        slot.hidden = controlled.has(queryId) && !selected.has(queryId);
    });
}

function applyClaimSets() {
    document.querySelectorAll('select[data-claim-set-select]').forEach(select => {
        const queryId = select.dataset.queryId;
        const chosen = select.value;
        document.querySelectorAll('[data-claim-set-query="' + queryId + '"]').forEach(entry => {
            entry.hidden = entry.dataset.claimSetOption !== chosen;
        });
    });
}

// The show all toggle reveals the credentials that do not match the verifier's query. Turning it
// off hides only the unpicked ones: a picked non matching card stays visible, so what the wallet
// presents is always on screen. Picking another card afterwards hides the invalid card. Turning
// the toggle on re-picks the first card of a slot that has none checked. A picker that is
// unsatisfiable with matches alone enables the present button while the toggle is on.
function applyShowAll() {
    const toggle = document.getElementById('show-all-credentials');
    if (!toggle) {
        return;
    }
    document.querySelectorAll('[data-non-matching]').forEach(card => {
        const picked = card.querySelector('input[type="radio"]:checked');
        card.hidden = !toggle.checked && !picked;
    });
    if (toggle.checked) {
        document.querySelectorAll('[data-query-slot]').forEach(slot => {
            if (!slot.querySelector('input[type="radio"]:checked')) {
                const first = slot.querySelector('input[type="radio"]');
                if (first) {
                    first.checked = true;
                }
            }
        });
    }
    const present = document.getElementById('present-credential');
    if (present && present.hasAttribute('data-unsatisfiable')) {
        present.disabled = !toggle.checked;
    }
}

function applyAll() {
    applyAlternatives();
    applyClaimSets();
    applyShowAll();
}

document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('select[data-alternatives-select], select[data-claim-set-select]')
        .forEach(select => select.addEventListener('change', applyAll));
    const showAll = document.getElementById('show-all-credentials');
    if (showAll) {
        showAll.addEventListener('change', applyShowAll);
    }
    document.querySelectorAll('[data-query-slot] input[type="radio"]')
        .forEach(radio => radio.addEventListener('change', applyShowAll));
    applyAll();
});
