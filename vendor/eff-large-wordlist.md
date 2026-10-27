# Vendored EFF large wordlist

`vendor/eff-large-wordlist/eff_large_wordlist.txt` is the EFF large wordlist for passphrases by
Joseph Bonneau and the Electronic Frontier Foundation. `build.rs` writes its words, in the order of
its lines, as `password_check::EFF_WORDS`, the list of the password check word profile
(MHFE-PASSWORD-CHECK-1); a test rebuilds the file from them and compares its SHA-256.

| Item      | Value                                                                             |
| --------- | --------------------------------------------------------------------------------- |
| Source    | https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt                       |
| Described | https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases            |
| Retrieved | 2026-09-29                                                                        |
| SHA-256   | `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`                |
| Format    | 7,776 lines, each five dice digits (1 to 6), a tab and a word; no duplicate words |
| Changes   | none; the file is byte for byte the one published by EFF                          |

## Licence

EFF's copyright policy (https://www.eff.org/copyright, read on 2026-09-29) states that original
material on the EFF website may be freely distributed under the Creative Commons Attribution 4.0
International licence (CC BY 4.0) unless otherwise noted. The wordlist and the article that
publishes it carry no other notice, so the list is used under CC BY 4.0:
https://creativecommons.org/licenses/by/4.0/.

Attribution: "EFF large wordlist" by the Electronic Frontier Foundation (Joseph Bonneau),
https://www.eff.org/dice, licensed under CC BY 4.0, unchanged.
