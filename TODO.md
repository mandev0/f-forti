# TODO

## Kod imzalama / EDR izin listesi

Plan: repo public olduktan sonra derleme GitHub Actions'a taşınacak ve
ücretsiz açık kaynak imzalama için SignPath Foundation'a başvurulacak.

İmzasız Go binary'leri (özellikle servis kuran, sürücü yükleyen ve ağ trafiğini
tünelleyen `fvpn-svc.exe`) Defender/EDR sezgisel kurallarına takılabilir.
SmartScreen de imzasız exe'lerde uyarı gösterir.

- [ ] Kod imzalama sertifikası edin (tercihen EV veya HSM'de saklanan OV
      sertifikası).
- [ ] Varsa: `fvpn-svc.exe`, `fvpn-gui.exe`, `fvpn-ctl.exe` dosyalarını
      `signtool sign /fd sha256 /tr <RFC3161 timestamp URL> /td sha256` ile imzala;
      `build.sh` sonrasına bir imzalama adımı ekle (imzalama Windows'ta ya da
      `osslsigncode` ile yapılabilir).
- [ ] Yoksa: EDR'da izin listesi kuralı tanımla. Tercih sırası:
      1. Yayıncı/sertifika bazlı kural (imza varsa).
      2. SHA-256 bazlı kural: her sürümde `bin/windows/SHA256SUMS` içindeki
         hash'ler güncellenmeli.
      3. Yol bazlı kural (`C:\Program Files\FVPN\*`) — en zayıfı; yalnızca
         dizin yazma izni Administrators/SYSTEM ile sınırlı olduğu için kabul
         edilebilir.
- [ ] `wintun.dll` zaten WireGuard LLC tarafından imzalı; ek işlem gerekmiyor
      (kurulumda SHA-256 doğrulanıyor).
- [ ] İmzalı sürümde Defender'a false-positive bildirimi gerekirse:
      https://www.microsoft.com/wdsi/filesubmission

## 1Password

- [ ] `op.exe` imza kontrolü (internal/opcli `SignerOK`): güncel sürümler
      Microsoft Trusted Signing ile imzalı (CN=O=Agilebits, C=CA, veren
      "Microsoft ID Verified CS …"); eski sürümler "AgileBits Inc.". 1Password
      imzalama yöntemini değiştirirse FVPN op'u reddeder; hata mesajı gerçek
      imzalayanı gösterir, kuralı ona göre güncelle.

## Diğer

- [ ] (İleride) FortiOS 7.6.3+ SSL-VPN tunnel mode'u kaldırıyor → IPsec/IKEv2.

## Ertelendi

- [ ] DTLS veya `tun` tünel yöntemi (performans).
