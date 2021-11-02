# Steam Manifest Patcher

Supported platform: Windows.

This is a short application which patches Steam so that you use `depot_download` again after it was disabled by Valve.

Patching is done by finding the failure string in memory `Depot download failed : Manifest not available.` and then
finding the `push` instruction using its offset. This differs from other patching methods in that it doesn't need to be
updated after a Steam client update.
