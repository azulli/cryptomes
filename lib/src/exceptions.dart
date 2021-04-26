// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

class NullDataException implements Exception {
  final String message;

  NullDataException([this.message = '']);
}

class InvalidASN1Object implements Exception {
  final String message;

  InvalidASN1Object([this.message = '']);
}

class CMSException implements Exception {
  final String message;

  CMSException([this.message = '']);
}
