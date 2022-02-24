# イルミパケット

---

以下において、一部を2022年の新しい情報にアップデートしました。

 => (追記)で表記

---

通信パケットを可視化するLANケーブル

[English](https://github.com/souring001/illumi-packet/blob/master/README_EN.md)

![illumi-packet](https://user-images.githubusercontent.com/29009733/70907987-8ab66000-204d-11ea-86e2-09a34d7c557a.jpg)

[動画 (YouTube)](https://youtu.be/5yJyNpHeRzg)

## 概要

イルミパケットは、通信パケットの種類と方向に合わせて、まるでパケットが流れたかのようにケーブルが光ります。

ARPのパケットはオレンジ色、DHCPのパケットは水色のように光ります。

通常のパケット解析に使われるツールはリアルタイムで目で追うことが難しいのに対し、これはパソコンを操作しながらパケットを観察できるので、「どういう操作」をした時に「どういうパケット」が発生するのかを体感することができます。

例えば、ウェブサイトにアクセスした時は、緑(DNS)と青(TCP)の光が複数個流れます。

![color](https://user-images.githubusercontent.com/29009733/71455676-786cbc80-27d9-11ea-980c-99a22d31696f.png)

## 準備

### 必要なもの
|材料|量|諸注意|
|:-|-:|:-|
|LEDテープ(WS281B)|1m|個別アドレス可能・フルカラーのもの．144LEDs/m 推奨．|
|Raspberry Pi|1台|動作確認: Raspberry Pi 2, 3, 4|
|LANケーブル|1m||
|ジャンパ線 オス-メス|3本||
|結束バンド|4本||

そのほかに，キーボード，ディスプレイ，HDMIケーブル，ルータ等はご用意ください．

### 環境設定
動作には以下の環境が必要です．
* golang
* libpcap
* SCons
* rpi_ws281x
* illumi-packet



## ビルド方法
#### golangのインストール

実行するプログラムはgo言語で記述されています．

https://golang.org/doc/install#install に従ってインストールします．

以下のようにターミナルで実行し，最後にバージョンが表示されることを確認してください．

```sh
$ version=1.13.4
$ wget https://storage.googleapis.com/golang/go${version}.linux-armv6l.tar.gz
$ sudo tar -C /usr/local -xzf go${version}.linux-armv6l.tar.gz

$ echo "export PATH=\$PATH:/usr/local/go/bin" >> ~/.profile
$ . ~/.profile

$ go version
go version go1.13.4 linux/arm
```

--- 

(追記)

更新したライブラリで現在利用しているgoのバージョンは go version go1.17.6 linux/arm です。

(追記ここまで)

--- 
#### libpcapのインストール
プログラムからパケットキャプチャを行うためにlibpcapをインストールします．

```sh
$ sudo apt-get install libpcap-dev
```

#### SConsのインストール
rpi_ws281xをビルドするためにSConsをインストールします．

```sh
$ sudo apt-get install scons
```

#### rpi_ws281xのインストール
LEDテープはrpi_ws281xというライブラリで操作します．

https://github.com/jgarff/rpi_ws281x に従ってインストールします．

```sh
$ git clone https://github.com/jgarff/rpi_ws281x.git
$ cd rpi_ws281x
$ scons

$ sudo cp -ai ./ws2811.h ./rpihw.h ./pwm.h /usr/local/include/
$ sudo cp -ai ./libws2811.a /usr/local/lib/
```

---
(追記)

ビルドがうまくいかず、何度も行う場合は`-ai`のオプションを`-af`にしておくと、いちいち確認が出ずに強制的に上書きしてくれます。


### testの実行

ビルド完了したディレクトリで
```sh
$ sudo ./test
```
を実行

虹色にぎらぎら動いたらビルド成功です！

(追記ここまで)

--- 


#### イルミパケットのソースコード
このリポジトリのソースコードを適当なディレクトリにダウンロードします．

```sh
$ git clone https://github.com/souring001/illumi-packet.git
$ cd illumi-packet
```

---
(追記)

現在ご覧のこのリポジトリは

```sh
$ git clone https://github.com/yuukami256/illumi-packet.git
$ cd illumi-packet
```

で取得できます。

### 必要パッケージなどのインストール
とりあえず `$ go build illumi-packet.go` を実行してみて、〜が足りませんみたいなお知らせが出た場合は

```sh
$ go mod download github.com/rpi-ws281x/rpi-ws281x-go
```
などを実行して必要なものをインストールしてください。

(追記ここまで)

--- 

LEDの個数によって`illumi-packet.go`の以下の変数を適宜変更してください．

| LEDの個数 | count | speed | series |
| --------:| -----:| -----:| ------:|
|60 個/m   |    60 |      1 |     6 |
|144 個/m  |   144 |      4 |    12 |
|144 個/m (50cm)  |   72 |      1 |    12 |

## LANケーブルの作り方

1. LANケーブルにLEDテープを乗せて，結束バンドで固定する．
2. ジャンパワイヤ(オス側)を挿し込む
3. メス側を Raspberry Pi のGPIOの2(5V), 6(GND), 12(信号) に挿し込む
4. Raspberry Piとルータに接続する

![GPIO_Outline](https://user-images.githubusercontent.com/29009733/71317350-aba20980-24c2-11ea-8a59-47388f5b2d73.png)

![GPIO](https://user-images.githubusercontent.com/29009733/70908199-f7315f00-204d-11ea-9cb0-256967c7ca5e.png)


## ビルド方法
ソースコードを変更するたびにビルドをする必要があります．

```sh
$ go build illumi-packet.go
```

--- 
(追記)
うまくいかない場合はsudoをつけるとうまくいくこともあるようです。

```sh
$ sudo go build illumi-packet.go
```
を実行して実行ファイルが完成します。

(追記ここまで)

---


## 起動

```sh
$ sudo ./illumi-packet
```

Ctrl+Cで終了します．

### オプション

|オプション|内容|
|:-|:-|
|-h|オプションの説明|
|-debug |パケット情報等の詳細を出力する(デフォルトは`true`)|
|-device [string]|ネットワークインターフェースを設定(デフォルトは`eth0`)|
|-speed [int]|パケットの流れる速度を設定(デフォルトは`1`)|
|-narp|ARPを表示しない|
|-ntcp|TCPを表示しない|
|-nudp|UDPを表示しない|
|-reset|点灯中のLEDの表示を消す|
|-ipaddr|IPアドレスをLEDに表示する|

#### 例

TCP, UDPのパケットを表示しない．
```sh
$ sudo ./illumi-packet -nudp -ntcp
```

<br>

パケット情報等の詳細を出力しない．

```sh
$ sudo ./illumi-packet -debug=false
```

<br>

Wi-Fiの通信を可視化する．
```sh
$ sudo ./illumi-packet -device wlan0
```

<br>

IPアドレスをLEDに表示する．
```sh
$ sudo ./illumi-packet -ipaddr
```
![showipaddress](https://user-images.githubusercontent.com/29009733/70908359-5e4f1380-204e-11ea-9187-a2d385c9f300.JPG)

LEDの表示を消す．
```sh
$ sudo ./illumi-packet -reset
```

## LICENSE, CONTACT

[本家様のREADME](https://github.com/souring001/illumi-packet/blob/master/README.md) をご参照ください。