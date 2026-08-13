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

function applyAll() {
    applyAlternatives();
    applyClaimSets();
}

document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('select[data-alternatives-select], select[data-claim-set-select]')
        .forEach(select => select.addEventListener('change', applyAll));
    applyAll();
});
