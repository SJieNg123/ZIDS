# Public suffix snapshot

`public_suffixes.json` is the canonical JSON form of `data/publicSuffixList.js`
from Adblock Plus core commit `5073eaf111cc3c46343046e6371371a9d0e8b9df`.
It is used to reproduce that reference engine's first/third-party calculation.
Copyright eyeo GmbH and contributors. The upstream GPL-3.0 license is retained
in `ABP-LICENSE.txt`. Source: https://github.com/adblockplus/adblockpluscore

The independent matcher is installed only for offline validation by
`tools/setup_reference.py`. No runtime rule download or browser is involved.
