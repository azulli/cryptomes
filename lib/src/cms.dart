// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
import 'dart:typed_data';

import 'package:asn1dart/asn1dart.dart';
import 'package:cryptomes/src/exceptions.dart';

import 'signer_info.dart';

/// Cryptographic Message Structure object.
class CMS {
  /// CMS version
  late final int version;

  /// Digest algorithms.
  final List<String> digestAlgorithms;

  /// Encapsulated content.
  final Uint8List? content;

  /// Signing certificates
  final List<CertShim>? certificates;

  /// Certificate revocations list.
  final List<Uint8List>? clrs;

  /// Signre infos.
  final List<SignerInfo>? signerInfos;

  static const _SIGNED_DATA_OID = '1.2.840.113549.1.7.2';
  static const _DATA_OID = '1.2.840.113549.1.7.1';

  CMS(this.version, this.digestAlgorithms, this.content, this.certificates,
      this.clrs, this.signerInfos);

  /// Static constructor from ASN.1 encoded data.
  static CMS fromASN1(Uint8List asn1data) {
    if (asn1data.isEmpty) throw NullDataException('No ASN.1 data to parse');
    final decoder = ASN1Decoder();
    final asn1 = decoder.convert(asn1data);
    if (asn1 == null) throw NullDataException('Invalid ASN.1 structure');
    if (asn1.tag?.tagNumber != TagNumber.SEQUENCE) {
      throw InvalidASN1Object('Container ASN.1 Object must be a SEQUENCE, '
          'found: ${asn1.tag?.tagNumber ?? 'null'}');
    }
    // Checks the correct OID of the envelope
    final envelopeOid = (asn1.childs!.first as ASN1ObjectIdentifier).value;
    if (envelopeOid != _SIGNED_DATA_OID) {
      throw CMSException(
          'Invalid envelope identifier $envelopeOid, it should have been $_SIGNED_DATA_OID');
    }
    // Isolates the signedData content tree
    // SEQUENCE → [0] → SEQUENCE
    final signedData = asn1.childs!.last.childs!.first as ASN1Collection;
    // Extracts the parts to be feed to the constructor.
    if (signedData.childs != null) {
      // SEQUENCE → OBJECT IDENTIFIER
      final contentOid = (signedData[2][0] as ASN1ObjectIdentifier).value;
      // Checks for valid OID
      if (contentOid != _DATA_OID) {
        throw CMSException(
            'Invalid encapContentInfo $contentOid, it should have been $_DATA_OID');
      }
      // INTEGER
      final version = (signedData[0] as ASN1Integer).value.toInt();
      // SET → SEQUENCE → OBJECT IDENTIFIER…
      final digests = signedData.childs![1].childs!
          .map((element) {
            final oid = (element[0] as ASN1ObjectIdentifier).value;
            return OIDTable[oid]?.description;
          })
          .whereType<String>()
          .toList(growable: false);
      // SEQUENCE → [0] → OCTET STRING
      final content = (signedData[2][1][0] as ASN1DataString).value;
      // [0] → SEQUENCE…
      final certificates = signedData[3]
          .childs
          ?.map((element) => CertShim.fromASN1(element as ASN1Collection))
          .whereType<CertShim>()
          .toList(growable: false);
      // SET → SEQUENCE…
      final signerInfos = signedData[4]
          .childs
          ?.map((element) => SignerInfo.fromASN1(element as ASN1Collection))
          .whereType<SignerInfo>()
          .toList(growable: false);
      return CMS(version, digests, Uint8List.fromList(content.codeUnits),
          certificates, null, signerInfos);
    }
    throw CMSException(
        'The ASN.1 data could not be converted to a valid CMS object');
  }
}
