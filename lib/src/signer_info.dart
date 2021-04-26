// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
import 'dart:typed_data';

import 'package:asn1dart/asn1dart.dart';

/// Signer information.
class SignerInfo {
  late Uint8List? _bytes;

  int? version;
  dynamic? sid;
  String? digestAlgorithm;
  Uint8List? rawSignedAttrs; // Leave as Uint8List?
  late Map<String, dynamic>? signedAttrs;
  String? signatureAlgorithm;
  dynamic? signature;
  List<dynamic>? unsignedAttrs;

  SignerInfo._();

  /// Decodes a signer information structure
  SignerInfo.fromASN1(ASN1Collection asn1root) {
    _bytes = asn1root.data!;
    version = asn1root[0].value.toInt();
    sid = asn1root[1].value;
    digestAlgorithm = OIDTable[asn1root[2][0].value]!.description;
    rawSignedAttrs = asn1root[3].data;
    if (rawSignedAttrs != null) {
      signedAttrs = <String, dynamic>{};
      for (var el in asn1root[3].childs!) {
        signedAttrs![OIDTable[el[0].value]!.description] =
            el[1].childs!.first.value;
      }
    }
    signatureAlgorithm = OIDTable[asn1root[4][0].value]!.description;
    // Leave as Uint8List?
    signature = asn1root[5].content;
  }

  Uint8List signedAttrsToDer() {
    var result = Uint8List.fromList(rawSignedAttrs!.toList());
    result[0] = 0x31;
    return result;
  }
}

class CertShim {
  late String? keyAlgorithm;
  late String? signatureAlgorithm;
  late Uint8List? signature;
  // Utilizing package:crypton
  late BigInt? keyModulus;
  late BigInt? keyExponent;

  CertShim._();

  CertShim.fromASN1(ASN1Collection asn1root) {
    keyAlgorithm = OIDTable[asn1root[0][6][0][0].value]!.description;
    final pk = asn1root[0][6][1][0];
    keyModulus = pk[0].value;
    keyExponent = pk[1].value;
    signatureAlgorithm = OIDTable[asn1root[1][0].value]!.description;
    signature = asn1root[2].data!;
  }
}
