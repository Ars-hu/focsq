// SPDX-FileCopyrightText: 2026 luminescq
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:math';

import 'package:ffi/ffi.dart';
import 'package:flutter/services.dart';

import '../modals/profile_form_components.dart';
import '../models/server_profile.dart';
import 'db.dart';
import 'vk/token.dart';

enum ImportProblem {
  emptyClipboard,
  readError,
  invalidFormat,
  saveFailed,
}

class ImportResult {
  const ImportResult({
    this.imported = 0,
    this.duplicates = 0,
    this.invalid = 0,
    this.problem,
  });

  final int imported;
  final int duplicates;
  final int invalid;
  final ImportProblem? problem;

  bool get hasError => problem != null;
}

class ParsedLinkResult {
  final ServerProfile profile;
  final List<String> hashes;
  final String? token;
  final int? workers;

  const ParsedLinkResult({
    required this.profile,
    this.hashes = const [],
    this.token,
    this.workers,
  });
}

typedef _NativeDecrypt = ffi.Int32 Function(
  ffi.Pointer<Utf8> input,
  ffi.Pointer<ffi.Uint8> outBuf,
  ffi.IntPtr outCap,
);
typedef _DartDecrypt = int Function(
  ffi.Pointer<Utf8> input,
  ffi.Pointer<ffi.Uint8> outBuf,
  int outCap,
);

typedef _NativeEncrypt = ffi.Int32 Function(
  ffi.Pointer<Utf8> input,
  ffi.Pointer<ffi.Uint8> outBuf,
  ffi.IntPtr outCap,
);
typedef _DartEncrypt = int Function(
  ffi.Pointer<Utf8> input,
  ffi.Pointer<ffi.Uint8> outBuf,
  int outCap,
);

class CsqttNativeCrypto {
  static ffi.DynamicLibrary? _lib;

  static ffi.DynamicLibrary? _getDynamicLib() {
    if (_lib != null) return _lib;
    try {
      if (Platform.isWindows) {
        _lib = ffi.DynamicLibrary.open('rust_lib_frontend.dll');
      } else if (Platform.isLinux) {
        _lib = ffi.DynamicLibrary.open('librust_lib_frontend.so');
      } else if (Platform.isMacOS) {
        _lib = ffi.DynamicLibrary.open('librust_lib_frontend.dylib');
      } else {
        _lib = ffi.DynamicLibrary.process();
      }
    } catch (_) {
      try {
        _lib = ffi.DynamicLibrary.process();
      } catch (_) {}
    }
    return _lib;
  }

  static String? decrypt(String rawLink) {
    final lib = _getDynamicLib();
    if (lib == null) return null;

    try {
      final decryptFn = lib.lookupFunction<_NativeDecrypt, _DartDecrypt>(
        'focsq_decrypt_csqtt_link',
      );

      final inputPtr = rawLink.toNativeUtf8();
      const outCap = 32768;
      final outBuf = calloc<ffi.Uint8>(outCap);

      try {
        final resultLen = decryptFn(inputPtr, outBuf, outCap);
        if (resultLen > 0) {
          final bytes = outBuf.asTypedList(resultLen);
          return utf8.decode(bytes);
        }
      } finally {
        calloc.free(inputPtr);
        calloc.free(outBuf);
      }
    } catch (_) {}
    return null;
  }

  static String? encrypt(String payload) {
    final lib = _getDynamicLib();
    if (lib == null) return null;

    try {
      final encryptFn = lib.lookupFunction<_NativeEncrypt, _DartEncrypt>(
        'focsq_encrypt_csqtt_link',
      );

      final inputPtr = payload.toNativeUtf8();
      const outCap = 32768;
      final outBuf = calloc<ffi.Uint8>(outCap);

      try {
        final resultLen = encryptFn(inputPtr, outBuf, outCap);
        if (resultLen > 0) {
          final bytes = outBuf.asTypedList(resultLen);
          return utf8.decode(bytes);
        }
      } finally {
        calloc.free(inputPtr);
        calloc.free(outBuf);
      }
    } catch (_) {}
    return null;
  }
}

class LinkParser {
  LinkParser({Random? random}) : _random = random ?? Random();

  static const String scheme = 'csqtt://';
  static const String _connectPrefix = '${scheme}connect?';
  static const Set<String> _knownKeys = {
    'host',
    'peer',
    'password',
    'hashes',
    'token',
    'workers',
    'client',
  };

  final Random _random;

  ParsedLinkResult? parseLinkFull(String link) {
    final trimmed = link.trim();
    if (!trimmed.startsWith(scheme)) return null;

    try {
      if (trimmed.startsWith(_connectPrefix)) {
        return _parseV2(trimmed);
      }

      if (trimmed.contains('@')) {
        final legacy = _parseLegacy(trimmed);
        return legacy != null ? ParsedLinkResult(profile: legacy) : null;
      }

      // Если ссылка зашифрована (csqtt://<base64>)
      final decrypted = CsqttNativeCrypto.decrypt(trimmed);
      if (decrypted != null && decrypted.isNotEmpty) {
        final candidate = decrypted.startsWith('csqtt://connect?')
            ? decrypted
            : decrypted.startsWith('connect?')
                ? '$scheme$decrypted'
                : decrypted.startsWith('csqtt://')
                    ? '${scheme}connect?${decrypted.substring(scheme.length)}'
                    : '${scheme}connect?$decrypted';
        final v2 = _parseV2(candidate);
        if (v2 != null) return v2;
      }

      // Legacy csqtt://password@host:port (fallback)
      final legacy = _parseLegacy(trimmed);
      return legacy != null ? ParsedLinkResult(profile: legacy) : null;
    } on FormatException {
      return null;
    } on ArgumentError {
      return null;
    }
  }

  ServerProfile? parse(String link) => parseLinkFull(link)?.profile;

  ParsedLinkResult? _parseV2(String link) {
    final fixedLink = _separateParams(link);
    final uri = Uri.tryParse(fixedLink);
    if (uri == null) return null;

    final query = uri.queryParameters;
    if (query['v'] != '2') return null;

    final host = query['host']?.trim();
    final peer = query['peer']?.trim();
    final password = query['password'];
    if (host == null || host.isEmpty) return null;
    if (password == null || password.isEmpty) return null;

    final port = int.tryParse(peer ?? '');
    if (!ImportService.isValidPort(port)) return null;

    // Hashes
    final rawHashes = query['hashes'];
    final hashes = <String>[];
    if (rawHashes != null && rawHashes.isNotEmpty) {
      for (final part in rawHashes.split(RegExp(r'[+,]'))) {
        final stripped = stripVkCallUrl(part.trim());
        if (stripped.length >= 16 && !stripped.contains(RegExp(r'\s'))) {
          if (!hashes.contains(stripped)) {
            hashes.add(stripped);
          }
        }
      }
    }

    // Token
    final rawToken = query['token']?.trim();
    final token = (rawToken != null && rawToken.isNotEmpty) ? rawToken : null;

    // Workers
    final rawWorkers = query['workers']?.trim();
    final workers = int.tryParse(rawWorkers ?? '');
    final power = workers != null ? closestWorkerStep(workers) : null;

    // Client name
    final rawClient = query['client']?.trim();
    final clientName = (rawClient != null && rawClient.isNotEmpty) ? rawClient : null;

    final profile = ServerProfile(
      name: clientName ?? _generateName(),
      ip: host,
      port: port,
      password: password,
      power: power ?? 10,
    );

    return ParsedLinkResult(
      profile: profile,
      hashes: hashes,
      token: token,
      workers: power,
    );
  }

  String _separateParams(String link) {
    var result = link;
    for (final key in _knownKeys) {
      result = result.replaceFirst('$key=', '&$key=');
    }
    return result;
  }

  ServerProfile? _parseLegacy(String link) {
    final withoutScheme = link.substring(scheme.length);
    final at = withoutScheme.lastIndexOf('@');
    if (at <= 0 || at == withoutScheme.length - 1) return null;

    final password = Uri.decodeComponent(withoutScheme.substring(0, at));
    final address = withoutScheme.substring(at + 1);

    String host;
    int? port;

    if (address.startsWith('[')) {
      final closeBracket = address.indexOf(']');
      if (closeBracket == -1) return null;
      host = address.substring(1, closeBracket);
      if (host.isEmpty) return null;
      final rest = address.substring(closeBracket + 1);
      if (!rest.startsWith(':')) return null;
      port = int.tryParse(rest.substring(1));
    } else {
      final parts = address.split(':');
      if (parts.length != 2 || parts[0].isEmpty) return null;
      host = parts[0];
      port = int.tryParse(parts[1]);
    }

    if (!ImportService.isValidPort(port)) return null;

    return ServerProfile(
      name: _generateName(),
      ip: host,
      port: port,
      password: password,
      power: 10,
    );
  }

  String _generateName() => 'Сервер #${_random.nextInt(9000) + 1000}';
}

String stripVkCallUrl(String input) {
  var s = input.trim();
  final lower = s.toLowerCase();
  const prefixes = [
    'https://vk.com/call/join/',
    'http://vk.com/call/join/',
    'https://m.vk.com/call/join/',
    'http://m.vk.com/call/join/',
    'm.vk.com/call/join/',
    'vk.com/call/join/',
    'https://vk.ru/call/join/',
    'http://vk.ru/call/join/',
    'https://m.vk.ru/call/join/',
    'http://m.vk.ru/call/join/',
    'm.vk.ru/call/join/',
    'vk.ru/call/join/',
  ];
  for (final prefix in prefixes) {
    if (lower.startsWith(prefix)) {
      s = s.substring(prefix.length);
      break;
    }
  }
  final qIdx = s.indexOf('?');
  if (qIdx != -1) s = s.substring(0, qIdx);
  final hIdx = s.indexOf('#');
  if (hIdx != -1) s = s.substring(0, hIdx);
  return s.replaceAll(RegExp(r'/+$'), '');
}

class ImportService {
  ImportService._();

  static final LinkParser _parser = LinkParser();

  static final RegExp _linkPattern = RegExp(
    r'csqtt://\S+',
    caseSensitive: false,
  );

  static Future<ImportResult> importFromClipboard() async {
    final String? text;
    try {
      final data = await Clipboard.getData(Clipboard.kTextPlain);
      text = data?.text?.trim();
    } catch (_) {
      return const ImportResult(problem: ImportProblem.readError);
    }

    if (text == null || text.isEmpty) {
      return const ImportResult(problem: ImportProblem.emptyClipboard);
    }
    return importText(text);
  }

  static List<ServerProfile> extractProfiles(String text) =>
      [for (final c in _extractCandidates(text)) if (_parser.parse(c) case final ServerProfile p) p];

  static ServerProfile? parseLink(String link) => _parser.parse(link);

  static ParsedLinkResult? parseCsqttLink(String link) => _parser.parseLinkFull(link);

  static bool isValidPort(int? port) => port != null && port > 0 && port <= 65535;

  static List<String> _extractCandidates(String text) =>
      _linkPattern.allMatches(text).map((m) => m.group(0)!).toList();

  static Future<ImportResult> importText(String text) async {
    final candidates = _extractCandidates(text);
    final results = <ParsedLinkResult>[];

    for (final c in candidates) {
      final parsed = _parser.parseLinkFull(c);
      if (parsed != null) {
        results.add(parsed);
      }
    }

    final invalid = candidates.length - results.length;

    if (results.isEmpty) {
      return const ImportResult(problem: ImportProblem.invalidFormat);
    }

    final allHashes = <String>[];
    String? latestToken;
    for (final res in results) {
      for (final h in res.hashes) {
        if (!allHashes.contains(h)) allHashes.add(h);
      }
      if (res.token != null && res.token!.isNotEmpty) {
        latestToken = res.token;
      }
    }

    if (allHashes.isNotEmpty) {
      try {
        await DbService.updateSettings((s) {
          s.customHashes = allHashes.join(',');
          s.hashes = 'Ручной';
          return s;
        });
      } catch (_) {}
    }

    if (latestToken != null) {
      try {
        await VkToken.save(latestToken);
      } catch (_) {}
    }

    final profiles = results.map((r) => r.profile).toList();

    List<ServerProfile> existing;
    try {
      existing = await DbService.getProfiles();
    } catch (_) {
      return const ImportResult(problem: ImportProblem.saveFailed);
    }

    final fresh = <ServerProfile>[];
    var duplicates = 0;
    for (final profile in profiles) {
      final duplicate = existing.any(
        (e) => e.ip == profile.ip && e.port == profile.port,
      );
      if (duplicate) {
        duplicates++;
      } else {
        fresh.add(profile);
      }
    }

    if (fresh.isEmpty) {
      return ImportResult(duplicates: duplicates, invalid: invalid);
    }

    try {
      for (final profile in fresh) {
        await DbService.saveProfile(profile);
      }
    } catch (_) {
      return ImportResult(
        problem: ImportProblem.saveFailed,
        duplicates: duplicates,
        invalid: invalid,
      );
    }
    return ImportResult(
      imported: fresh.length,
      duplicates: duplicates,
      invalid: invalid,
    );
  }

  static String? formatLink({
    required String host,
    required int port,
    required String password,
    List<String> hashes = const [],
    String? token,
    int? workers,
    String? client,
  }) {
    final query = <String>['v=2', 'host=${Uri.encodeQueryComponent(host)}', 'peer=$port'];
    if (password.isNotEmpty) {
      query.add('password=${Uri.encodeQueryComponent(password)}');
    }
    if (hashes.isNotEmpty) {
      query.add('hashes=${hashes.map(Uri.encodeQueryComponent).join("+")}');
    } else if (token != null && token.isNotEmpty) {
      query.add('token=${Uri.encodeQueryComponent(token)}');
    }
    if (workers != null && workers > 0) {
      query.add('workers=$workers');
    }
    if (client != null && client.isNotEmpty) {
      query.add('client=${Uri.encodeQueryComponent(client)}');
    }

    final plain = 'connect?${query.join("&")}';
    return CsqttNativeCrypto.encrypt(plain);
  }
}
