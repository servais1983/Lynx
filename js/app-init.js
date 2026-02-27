// Lynx — App initialisation
// Wires all UI event listeners after DOM is ready.
// Kept in a separate file so the strict CSP (no 'unsafe-inline') is honoured.

document.addEventListener('DOMContentLoaded', function () {
    'use strict';

    /* ── Drop zone ─────────────────────────── */
    const dropZone = document.getElementById('dropZone');
    if (dropZone) {
        dropZone.addEventListener('dragover',  dragOverHandler);
        dropZone.addEventListener('dragleave', dragLeaveHandler);
        dropZone.addEventListener('drop',      dropHandler);
        dropZone.addEventListener('click', function (e) {
            if (e.target === dropZone || (e.target.closest('.upload-content') && !e.target.closest('button'))) {
                document.getElementById('fileInput').click();
            }
        });
        dropZone.addEventListener('keydown', function (e) {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                document.getElementById('fileInput').click();
            }
        });
    }

    /* ── File input ─────────────────────────── */
    const fileInput = document.getElementById('fileInput');
    if (fileInput) {
        fileInput.addEventListener('change', function () {
            if (this.files && this.files.length > 0) {
                handleFiles(this.files);
            }
        });
    }

    /* ── Scan buttons ───────────────────────── */
    const quickScanBtn = document.getElementById('quickScanBtn');
    if (quickScanBtn) quickScanBtn.addEventListener('click', quickScan);

    const deepScanBtn = document.getElementById('deepScanBtn');
    if (deepScanBtn) deepScanBtn.addEventListener('click', deepScan);

    const clearFilesBtn = document.getElementById('clearFilesBtn');
    if (clearFilesBtn) clearFilesBtn.addEventListener('click', clearFiles);

    /* ── Toggle chart ───────────────────────── */
    const toggleChartBtn = document.getElementById('toggleChartBtn');
    if (toggleChartBtn) toggleChartBtn.addEventListener('click', toggleChartType);

    /* ── Pattern search ─────────────────────── */
    const searchPatternBtn = document.getElementById('searchPatternBtn');
    if (searchPatternBtn) searchPatternBtn.addEventListener('click', searchPattern);

    const patternInput = document.getElementById('patternInput');
    if (patternInput) {
        patternInput.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') searchPattern();
        });
    }

    /* ── Custom patterns ────────────────────── */
    const addCustomPatternBtn = document.getElementById('addCustomPatternBtn');
    if (addCustomPatternBtn) addCustomPatternBtn.addEventListener('click', addCustomPattern);

    /* ── Triage ─────────────────────────────── */
    const selectSourceDirBtn = document.getElementById('selectSourceDirBtn');
    if (selectSourceDirBtn) {
        selectSourceDirBtn.addEventListener('click', function () {
            const inp = document.getElementById('sourceDirectoryInput');
            if (inp) inp.click();
        });
    }

    const sourceDirectoryInput = document.getElementById('sourceDirectoryInput');
    if (sourceDirectoryInput) {
        sourceDirectoryInput.addEventListener('change', function () {
            if (this.files && this.files.length > 0) {
                const path = this.files[0].webkitRelativePath.split('/')[0] || 'Dossier sélectionné';
                const display = document.getElementById('sourceDirectory');
                if (display) display.textContent = path;
                if (typeof configureTriage === 'function') configureTriage(this.files);
            }
        });
    }

    const startTriageAutomationBtn = document.getElementById('startTriageAutomationBtn');
    if (startTriageAutomationBtn) startTriageAutomationBtn.addEventListener('click', startTriageAutomation);

    const stopTriageAutomationBtn = document.getElementById('stopTriageAutomationBtn');
    if (stopTriageAutomationBtn) stopTriageAutomationBtn.addEventListener('click', stopTriageAutomation);

    const showTriageReportBtn = document.getElementById('showTriageReportBtn');
    if (showTriageReportBtn) showTriageReportBtn.addEventListener('click', showTriageReport);

    const showTriageHelpBtn = document.getElementById('showTriageHelpBtn');
    if (showTriageHelpBtn) showTriageHelpBtn.addEventListener('click', showTriageHelp);

    /* ── Detail modal backdrop close ────────── */
    const detailModal = document.getElementById('detailModal');
    if (detailModal) {
        detailModal.addEventListener('click', function (e) {
            if (e.target === detailModal) closeModal();
        });
    }
});
