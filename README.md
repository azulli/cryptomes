# cryptomes

An implementation of the [Cryptographic Message Syntax][rfc5652] for Dart.

Code distributed under [MPL-2.0 license](https://github.com/azulli/crypto_ms/blob/main/LICENSE).

[rfc5652]: https://https://tools.ietf.org/html/rfc5652

## Limitations

This library is only capable to parse a CaDES structure with RSA signed content (p7m digital signature).

## Usage

A simple usage example:

```dart
import 'package:cryptomes/cryptomes.dart';

main() {
  final cms = CMS.fromASN1(asn1Data);
}
```

## Features and bugs

Please file feature requests and bugs at the [issue tracker][tracker].

[tracker]: https://github.com/azulli/crypto_ms/issues
