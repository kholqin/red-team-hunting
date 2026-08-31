# Matriks Language-Aware Analyzer

Modul ini melakukan analisis statis terhadap source code dan artefak konfigurasi. Ia tidak menjalankan source, tidak mengompilasi project secara otomatis, tidak mengirim payload ke aplikasi, dan tidak membaca file di luar path yang diberikan pengguna.

| Keluarga | Bahasa/teknologi | Ekstensi utama | Analisis |
|---|---|---|---|
| JVM | Java, Kotlin, Scala, Clojure, Groovy-compatible files | `.java`, `.kt`, `.kts`, `.scala`, `.clj` | package/import, class/function, dependency file, crypto/API-risk pattern |
| Web | JavaScript, TypeScript, HTML | `.js`, `.jsx`, `.mjs`, `.ts`, `.tsx`, `.html`, `.htm` | import, route/API string, DOM sink/source, secret indicator, unsafe browser API |
| PHP | PHP, Laravel | `.php`, `composer.json`, `.env.example` | namespace/use, Laravel routes/config, dependency, dangerous function and secret pattern |
| Native | C, C++, C#, Objective-C, Swift, Rust, Zig, D, Ada, Nim | `.c`, `.h`, `.cpp`, `.cc`, `.hpp`, `.cs`, `.m`, `.mm`, `.swift`, `.rs`, `.zig`, `.d`, `.ada`, `.adb`, `.nim` | include/import/use, function/struct/class, unsafe memory/process/crypto pattern |
| Scripting | Python, Ruby, Lua, Perl, Visual Basic, F# | `.py`, `.pyi`, `.rb`, `.lua`, `.pl`, `.pm`, `.vb`, `.fs`, `.fsx` | import/require, function/class, subprocess/eval/deserialization pattern, dependency |
| Go | Go | `.go`, `go.mod`, `go.sum` | package/import, exported symbol, HTTP/SQL/crypto pattern, dependency |
| Functional/concurrent | Elixir, Erlang, Haskell, Julia, R | `.ex`, `.exs`, `.erl`, `.hrl`, `.hs`, `.lhs`, `.jl`, `.r`, `.R` | module/import, function, shell/eval/crypto/API-risk pattern |
| Scientific | R, MATLAB, Julia, Fortran | `.r`, `.R`, `.m`, `.jl`, `.f`, `.f90`, `.for` | function/import, external process/eval, embedded URL/secret |
| Database | SQL, PL/SQL, T-SQL, PL/pgSQL | `.sql`, `.pls`, `.pkb`, `.pks`, `.pgsql` | statement classification, dynamic SQL, credential/secret indicator; no execution |
| Smart contract | Solidity, Vyper, Cairo, Move | `.sol`, `.vy`, `.cairo`, `.move` | contract/function, external call, auth modifier, reentrancy-risk indicators |
| Legacy/low-level | COBOL, Assembly | `.cob`, `.cbl`, `.asm`, `.s`, `.S` | paragraph/label/function, syscall/exec/embedded secret indicators |
| Dart | Dart, Flutter source | `.dart`, `pubspec.yaml` | import, class/function, HTTP/storage/secret pattern |

## Output nyata

Setiap finding menyertakan path, nomor baris, rule ID, severity, confidence, snippet yang sudah disanitasi, dan remediation. Jika parser khusus tidak tersedia, engine tetap memberikan statistik lexical yang dapat diverifikasi dan menandainya sebagai `ANALYSIS`, bukan vulnerability. Pola hanya dilaporkan sebagai indikasi; validasi manual tetap diperlukan.
