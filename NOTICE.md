# Licences of kode-app-template

This file says which licence applies to this repository, and to an app that starts from it.

## The code of Kode

Copyright (C) 2026 Kode.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

The file `LICENSE` holds the full text of the GNU General Public License, version 3.

### Additional permission under GNU GPL version 3 section 7

If you modify this Program, or any covered work, by linking or combining it with the RF Abstraction Layer (RFAL) and the ST25R3916 driver of STMicroelectronics (or a modified version of those libraries), containing parts covered by the terms of the STMicroelectronics SLA0051 licence, the licensors of this Program grant you additional permission to convey the resulting work. Corresponding Source for a non-source form of such a combination shall include the source code for the parts of RFAL and of the ST25R3916 driver used as well as that of the covered work.

If you change the code of Kode, you can remove this permission from your version. Section 7 of the GNU General Public License allows this.

### Trademarks, under GNU GPL version 3 section 7(e)

This licence gives no right to use the names Kode, Kode Dot, kodeOS and Kody, or the character Kody, as trademarks. `TRADEMARKS.md` in the repository `kodediy/.github` says how you can use them.

## An app that starts from this template

Your app is your code. The SDK that it links is GPL-3.0-or-later, so your app is too. The SDK's NFC is built on RFAL: give your own code the same additional permission, as this file does, so that your app can be shared with RFAL in it.

## The SDK

The SDK is not in this repository: the ESP-IDF component manager downloads it when you build. Its `NOTICE.md` says which licence applies to each of its parts.
