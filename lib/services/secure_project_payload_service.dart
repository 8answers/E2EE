import 'package:supabase_flutter/supabase_flutter.dart';

class SecureProjectPayloadService {
  static final SupabaseClient _supabase = Supabase.instance.client;
  static bool? _supportsSecurePayloadTable;

  static Future<bool> _supportsTable() async {
    if (_supportsSecurePayloadTable == true) return true;
    try {
      await _supabase
          .from('project_secure_payloads')
          .select('project_id')
          .limit(1);
      _supportsSecurePayloadTable = true;
    } catch (_) {
      _supportsSecurePayloadTable = false;
    }
    return _supportsSecurePayloadTable!;
  }

  static Future<bool> isSecurePayloadTableAvailable() async {
    return _supportsTable();
  }

  static Future<Map<String, dynamic>?> fetchPayload({
    required String projectId,
    required String userId,
  }) async {
    if (!await _supportsTable()) return null;
    try {
      final row = await _supabase
          .from('project_secure_payloads')
          .select()
          .eq('project_id', projectId)
          .eq('user_id', userId)
          .maybeSingle();
      if (row == null) return null;
      return Map<String, dynamic>.from(row);
    } catch (_) {
      return null;
    }
  }

  static Future<void> upsertPayload({
    required String projectId,
    required String userId,
    required Map<String, dynamic> encryptedPayload,
  }) async {
    if (!await _supportsTable()) return;
    await _supabase.from('project_secure_payloads').upsert(
      {
        'project_id': projectId,
        'user_id': userId,
        ...encryptedPayload,
        'updated_at': DateTime.now().toIso8601String(),
      },
      onConflict: 'project_id',
    );
  }
}
