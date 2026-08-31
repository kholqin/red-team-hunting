# DISCLAIMER

RED TEAM HUNTING adalah perangkat lunak riset keamanan yang dirancang untuk pemeriksaan non-destruktif terhadap aset yang pengguna miliki atau telah diberi izin tertulis untuk diuji. Perangkat lunak ini tidak memberikan hak akses, izin, atau pembenaran untuk menguji sistem pihak lain.

Pengguna bertanggung jawab atas otorisasi, penetapan scope, rate limit, perlindungan data pribadi, kepatuhan kontrak, serta seluruh hukum dan kebijakan yang berlaku. Jangan menjalankan tool terhadap target yang tidak berada dalam scope. Jangan memasukkan kredensial, token, password, private key, cookie aktif, atau data rahasia ke issue, log, laporan publik, atau konfigurasi yang tidak terlindungi.

Fitur deteksi bersifat indikator dan dapat menghasilkan false positive maupun false negative. Hasil tidak boleh diperlakukan sebagai bukti final tanpa verifikasi manual yang berwenang. `DETECTED` harus didukung evidence aktual; `NOT DETECTED` bukan jaminan aman; `SKIPPED`, `NOT TESTED`, dan `INCONCLUSIVE` menunjukkan prasyarat atau evidence belum cukup. Tool tidak boleh membuat finding, confidence, CVSS, endpoint, IP, subdomain, atau evidence palsu.

Profile yang lebih agresif hanya memperluas discovery secara bounded. Rilis ini tetap menolak perilaku destruktif, brute force, credential attack, credential stuffing, password spraying, database modification, persistence, malware execution, dan denial-of-service behavior.

Dependency eksternal, provider API, parser binary, dan layanan pihak ketiga harus diverifikasi oleh `redhunt doctor` serta digunakan sesuai rate limit dan terms of service. Jika dependency tidak tersedia, hasil yang benar adalah `SKIPPED` atau `INCONCLUSIVE`, bukan sukses palsu.

Penulis dan pemegang hak cipta menyediakan perangkat lunak ini tanpa jaminan dan tidak bertanggung jawab atas kerusakan, kehilangan data, pelanggaran, atau konsekuensi apa pun yang timbul dari penggunaan maupun penyalahgunaan perangkat lunak. Pengguna wajib melakukan review manual, validasi scope, dan koordinasi dengan pemilik sistem sebelum serta sesudah pemeriksaan.

Dengan menggunakan software ini, pengguna menyatakan memahami dan menerima batasan di atas serta bertanggung jawab atas seluruh aktivitas yang dilakukan menggunakan software ini.
