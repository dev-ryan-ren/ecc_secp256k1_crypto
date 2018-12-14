//
//  ViewController.m
//  ecc_secp256k1_crypto
//
//  Created by R on 2018/12/14.
//  Copyright © 2018 R. All rights reserved.
//

#import "ViewController.h"

#import <Security/Security.h>
#import <openssl/x509.h>
#import "BCGenerator.h"
#import "CryptoppECC.h"
#import "GTMBase64.h"

@interface ViewController ()
 
 // iOS生成的密钥对
 @property (nonatomic,strong) NSData * publicData;
 @property (nonatomic,strong) NSData * privateData;
 
 // 证书公钥字符串
 @property (nonatomic,copy) NSString * cer_publicKeyString;
 
@end

@implementation ViewController
    
- (void)viewDidLoad {
    [super viewDidLoad];
    
    /*
     iOS与服务器端ecc椭圆曲线加密的完整步骤
     1.服务器端生成ctr证书给iOS端，服务器端持有私钥
        证书生成细节
        1>证书符合X.509规范，同时公钥也要符合
        2>采用secp256k1椭圆曲线参数
     2.iOS端通过解析证书拿到服务器公钥
     3.iOS端用公钥加密字符串，密文传输给服务器端
     4.服务器端用私钥解密，拿到明文
     5.iOS端自己生成密钥对，把公钥给到服务器端，iOS持有私钥
     6.服务器端用公钥加密，返回给iOS端后iOS私钥解密
     
     * 关健点:iOS端和服务器持有自己的私钥，彼此的公钥
     * 目前已经实现
     iOS自身生成secp256k1的密钥对
     iOS端使用自己生成的密钥对加密解密
     
     iOS端使用证书里面的公钥加密字符串
     java端私钥解密可以参照CryptoppECC提供的java示例
     */
    
    // 解析证书并获取证书中的公钥，使用公钥ecc加密
    [self getX509PublicKey];
    
    // 自己生成x509->secp256k1的密钥对
    [self generatorKeyPair];
    
    // ecc加密解密
    [self eccCrypt];
}
    
#pragma mark -
#pragma mark -  ecc加密解密 - CryptoppECC
- (void)eccCrypt{
    
    // 将公钥私钥GTMbase64编码
    NSString *publicKey = [self encodeBase64Data:_publicData];
    NSString *priveKey = [self encodeBase64Data:_privateData];
    
    NSLog(@"\n\n===公钥base64\n\n  %@",publicKey);
    NSLog(@"\n\n===公钥base64\n\n  %@",publicKey);
    
    CryptoppECC* ecc = [[CryptoppECC alloc] init];
    
    // 待加密的字符串
    NSString *str = @"hello world!!";
    NSLog(@"\n\n===待加密的字符串\n\n  %@",str);
    
    // ecc公钥加密
    NSString*enStr = [ecc encrypt:str :publicKey curve:CurveType_secp256k1];
    NSLog(@"\n\n===ecc公钥加密后的密文\n\n %@",enStr);
    
    
    // ecc私钥解密
    NSString*deStr = [ecc decrypt:enStr :priveKey curve:CurveType_secp256k1];
    if (deStr.length == 0) {
        NSLog(@"\n\n===解密后的字符串 解密失败");
    }else{
        NSLog(@"\n\n===ecc私钥解密后的字符串\n\n %@",deStr);
    }
}
    
#pragma mark -
#pragma mark -  生成密钥对 - BCGenerator
- (void) generatorKeyPair{
    NSLog(@"\n\n iOS端自身生成密钥对ecc加解密数据 \n\n");
    // 生成公钥私钥
    BCGenerator * generator = [[BCGenerator alloc]initWithWith:@"pseudorandom sequence"];
    NSData *publicData = generator.rootPublickey;
    NSData *privateData = generator.rootPrivatekey;
    
    _publicData = publicData;
    _privateData = privateData;
    
    NSLog(@"\n\n===16进制公钥 \n\n%@",[self convertDataToHexStr:publicData]);
    NSLog(@"\n\n===16进制私钥 \n\n%@",[self convertDataToHexStr:privateData]);
}
    
    
#pragma mark -
#pragma mark -  获取证书公钥 - openssl
- (void) getX509PublicKey{
    NSLog(@"\n\n 通过读取证书获得公钥ecc加密数据 \n\n");
    NSString *file = [[NSBundle mainBundle] pathForResource:@"secp256k1_sha256withECDSA" ofType:@"crt"];
    NSData *serverCertificateData = [NSData dataWithContentsOfFile:file];
    NSLog(@"\n\nctr证书：===\n\n %@",serverCertificateData);
    
    const unsigned char *certificateDataBytes = (const unsigned char *)[serverCertificateData bytes];
    X509 *certificateX509 = d2i_X509(NULL, &certificateDataBytes, [serverCertificateData length]);
    ASN1_BIT_STRING *pubKey2 = X509_get0_pubkey_bitstr(certificateX509);
    unsigned char *data = pubKey2->data;
    printf("\n\n证书公钥data:===\n\n %s",data);
    
    NSString *cer_publicKeyString = [[NSString alloc] init];
    
    for (int i = 0; i < pubKey2->length; i++){
        NSString *aString = [NSString stringWithFormat:@"%02x", pubKey2->data[i]];
        cer_publicKeyString = [cer_publicKeyString stringByAppendingString:aString];
    }
    // 0487b95112d380272828e54172ef37bad1f1d82e28a4d78440816fe77b7003426459ddfbacec5cb9c081fc56a5f9fd7e7139d1547f6cbd7b3bc7d3e7025ee1b00a
    
    _cer_publicKeyString = cer_publicKeyString;
    NSLog(@"\n\n证书公钥16进制:===\n\n %@", cer_publicKeyString);
    
    _publicData = [self convertHexStrToData:_cer_publicKeyString];
    NSLog(@"\n\n证书公钥data:===\n\n %@", _publicData);
    
    // 用证书公钥加密
    [self eccCrypt];
}
    
    
#pragma mark -
#pragma mark -
#pragma mark - GTMBase64编码解码
// 编码
- (NSString*)encodeBase64Data:(NSData *)data {
    data = [GTMBase64 encodeData:data];
    NSString *base64String = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return base64String;
}
    
// 解码
- (NSData*)decodeBase64Data:(NSData *)data {
    data = [GTMBase64 decodeData:data];
    return data;
}
    
#pragma mark - 16进制与NSData相互转换
// 16进制转NSData
- (NSData *)convertHexStrToData:(NSString *)str
    {
        if (!str || [str length] == 0) {
            return nil;
        }
        
        NSMutableData *hexData = [[NSMutableData alloc] initWithCapacity:20];
        NSRange range;
        if ([str length] % 2 == 0) {
            range = NSMakeRange(0, 2);
        } else {
            range = NSMakeRange(0, 1);
        }
        for (NSInteger i = range.location; i < [str length]; i += 2) {
            unsigned int anInt;
            NSString *hexCharStr = [str substringWithRange:range];
            NSScanner *scanner = [[NSScanner alloc] initWithString:hexCharStr];
            
            [scanner scanHexInt:&anInt];
            NSData *entity = [[NSData alloc] initWithBytes:&anInt length:1];
            [hexData appendData:entity];
            
            range.location += range.length;
            range.length = 2;
        }
        return hexData;
    }
    
// NSData转16进制
- (NSString *)convertDataToHexStr:(NSData *)data
    {
        if (!data || [data length] == 0) {
            return @"";
        }
        NSMutableString *string = [[NSMutableString alloc] initWithCapacity:[data length]];
        
        [data enumerateByteRangesUsingBlock:^(const void *bytes, NSRange byteRange, BOOL *stop) {
            unsigned char *dataBytes = (unsigned char*)bytes;
            for (NSInteger i = 0; i < byteRange.length; i++) {
                NSString *hexStr = [NSString stringWithFormat:@"%x", (dataBytes[i]) & 0xff];
                if ([hexStr length] == 2) {
                    [string appendString:hexStr];
                } else {
                    [string appendFormat:@"0%@", hexStr];
                }
            }
        }];
        return string;
    }
    
@end
