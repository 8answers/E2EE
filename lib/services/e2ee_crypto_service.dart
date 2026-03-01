import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';

class EncryptionKeyUnavailableException implements Exception {
  final String message;
  EncryptionKeyUnavailableException(this.message);

  @override
  String toString() => message;
}

class E2EECryptoService {
  static const _storage = FlutterSecureStorage();
  static const _masterKeyPrefix = 'landman_e2ee_master_key_v1_';
  static const _masterKeyBackupPrefix = 'landman_e2ee_master_key_backup_v1_';
  static const _aad = 'landman-project-payload-v1';
  static final Cipher _cipher = AesGcm.with256bits();
  static final Hkdf _hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);

  static Future<Map<String, dynamic>> encryptProjectPayload({
    required String userId,
    required String projectId,
    required Map<String, dynamic> payload,
  }) async {
    final projectKey =
        await _deriveProjectKey(userId: userId, projectId: projectId);
    final nonce = _randomBytes(12);
    final cleartext = Uint8List.fromList(utf8.encode(jsonEncode(payload)));
    final secretBox = await _cipher.encrypt(
      cleartext,
      secretKey: projectKey,
      nonce: nonce,
      aad: Uint8List.fromList(utf8.encode(_aad)),
    );

    return {
      'algorithm': 'AES-256-GCM',
      'key_version': 1,
      'nonce_b64': base64Encode(secretBox.nonce),
      'ciphertext_b64': base64Encode(secretBox.cipherText),
      'mac_b64': base64Encode(secretBox.mac.bytes),
    };
  }

  static Future<Map<String, dynamic>?> decryptProjectPayload({
    required String userId,
    required String projectId,
    required Map<String, dynamic> encryptedPayload,
  }) async {
    final nonceB64 = (encryptedPayload['nonce_b64'] ?? '').toString();
    final ciphertextB64 = (encryptedPayload['ciphertext_b64'] ?? '').toString();
    final macB64 = (encryptedPayload['mac_b64'] ?? '').toString();
    if (nonceB64.isEmpty || ciphertextB64.isEmpty || macB64.isEmpty) {
      return null;
    }

    final existingMasterKey = await _getExistingMasterKeyBytes(userId);
    if (existingMasterKey == null) {
      throw EncryptionKeyUnavailableException(
        'Encryption key is missing for this browser origin. '
        'Use the same app URL/port where this project was encrypted.',
      );
    }
    final projectKey = await _deriveProjectKeyFromMaster(
      masterKeyBytes: existingMasterKey,
      projectId: projectId,
    );
    final secretBox = SecretBox(
      base64Decode(ciphertextB64),
      nonce: base64Decode(nonceB64),
      mac: Mac(base64Decode(macB64)),
    );
    final cleartext = await _cipher.decrypt(
      secretBox,
      secretKey: projectKey,
      aad: Uint8List.fromList(utf8.encode(_aad)),
    );
    final decoded = jsonDecode(utf8.decode(cleartext));
    if (decoded is Map<String, dynamic>) {
      return decoded;
    }
    if (decoded is Map) {
      return decoded.cast<String, dynamic>();
    }
    return null;
  }

  static Future<SecretKey> _deriveProjectKey({
    required String userId,
    required String projectId,
  }) async {
    final masterKeyBytes = await _getOrCreateMasterKeyBytes(userId);
    return _deriveProjectKeyFromMaster(
      masterKeyBytes: masterKeyBytes,
      projectId: projectId,
    );
  }

  static Future<SecretKey> _deriveProjectKeyFromMaster({
    required List<int> masterKeyBytes,
    required String projectId,
  }) async {
    final key = await _hkdf.deriveKey(
      secretKey: SecretKey(masterKeyBytes),
      nonce: Uint8List.fromList(utf8.encode(projectId)),
      info: Uint8List.fromList(utf8.encode('landman-e2ee-project-key-v1')),
    );
    return key;
  }

  static Future<List<int>> _getOrCreateMasterKeyBytes(String userId) async {
    final storageKey = '$_masterKeyPrefix$userId';
    final existingB64 = await _storage.read(key: storageKey);
    if (existingB64 != null && existingB64.isNotEmpty) {
      if (kIsWeb) {
        await _writeBackupMasterKey(userId, existingB64);
      }
      return base64Decode(existingB64);
    }

    if (kIsWeb) {
      final backupB64 = await _readBackupMasterKey(userId);
      if (backupB64 != null && backupB64.isNotEmpty) {
        await _storage.write(key: storageKey, value: backupB64);
        return base64Decode(backupB64);
      }
    }

    final bytes = _randomBytes(32);
    final encoded = base64Encode(bytes);
    await _storage.write(key: storageKey, value: encoded);
    if (kIsWeb) {
      await _writeBackupMasterKey(userId, encoded);
    }
    return bytes;
  }

  static Future<List<int>?> _getExistingMasterKeyBytes(String userId) async {
    final storageKey = '$_masterKeyPrefix$userId';
    final existingB64 = await _storage.read(key: storageKey);
    if (existingB64 == null || existingB64.isEmpty) {
      if (!kIsWeb) return null;
      final backupB64 = await _readBackupMasterKey(userId);
      if (backupB64 == null || backupB64.isEmpty) return null;
      await _storage.write(key: storageKey, value: backupB64);
      return base64Decode(backupB64);
    }
    if (kIsWeb) {
      await _writeBackupMasterKey(userId, existingB64);
    }
    return base64Decode(existingB64);
  }

  static Future<String?> _readBackupMasterKey(String userId) async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString('$_masterKeyBackupPrefix$userId');
  }

  static Future<void> _writeBackupMasterKey(
      String userId, String encodedKey) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('$_masterKeyBackupPrefix$userId', encodedKey);
  }

  static List<int> _randomBytes(int length) {
    return SecretKeyData.random(length: length).bytes;
  }
}
