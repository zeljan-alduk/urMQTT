// "Try in the emulator" (C1g). Nothing of the emulator is fetched, parsed or
// started before the user clicks the button; the dialog below is all the page
// itself carries. (Filled in after the spike, ADR-223.)

function openEmulatorDialog() {
  openDialog({
    title: t('emulator.title'),
    body: [h('p', { text: t('emulator.not-ready') })],
    actions: [dialogButton(t('common.close'), 'close')],
  });
}
