# ecc_secp256k1_crypto

基于secp256k1椭圆曲线的ecc加密解密(iOS)

## using
1. `git clone`
2. `pod install`
3. `单独在gitHub上下载CryptoppECC并且pod安装，将pod中的CryptoppECC文件夹拖出来替换本项目的libc/CryptoppECC`

## 最近在做区块链相关的数字钱包，用到了ecc加密，所以整理记录一下。
便于理解以下几点
1. 理解X.509证书规范，ecc椭圆曲线加密，secp256k1曲线
2. 理解secp256k1曲线用于比特币密钥对和地址的生成
3. 理解ecc加密在API接口的层面的应用

## 资源参考
1. openssl 用于解析X.509规范的ctr证书，并获取公钥
2. BCGenerator 用于生成比特币规则的密钥对(secp256k1)
3. CryptoppECC 用于ecc加密解密

## iOS与服务器端ecc椭圆曲线加密的完整步骤
1. 服务器端生成ctr证书给iOS端，服务器端持有私钥
   证书生成细节
   - 证书符合X.509规范，同时公钥也要符合
   - 采用secp256k1椭圆曲线参数
2. iOS端通过解析证书拿到服务器公钥
3. iOS端用公钥加密字符串，密文传输给服务器端
4. 服务器端用私钥解密，拿到明文
5. iOS端自己生成密钥对，把公钥给到服务器端，iOS持有私钥
6. 服务器端用公钥加密，返回给iOS端后iOS私钥解密

* 关健点:iOS端和服务器持有自己的私钥，彼此的公钥

## 已经实现
1. iOS自身生成secp256k1的密钥对
2. iOS端使用自己生成的密钥对加密解密
3. iOS端使用证书里面的公钥加密字符串
* java端私钥解密可以参照CryptoppECC提供的java示例
