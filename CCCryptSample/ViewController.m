//
//  ViewController.m
//  CCCryptSample
//
//  Created by HankTseng on 2018/7/4.
//  Copyright © 2018年 HyerTech. All rights reserved.
//

#import "ViewController.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    [self encryptDES];
    [self decryptDES];
    
    [self tripleDesEncryptString:@"another new saodfijcowmiecrowiteqcihasdifjkfgnc29 3][12040pafsdjiu48c09x209daokfpsmguh93cowkspdokfpoirjtmvwemrfj,xpojgicuo,ai,iwuehx.c,sm::sdjoi[]'a/s;x.`012`23456789jskiec" key:@"123456789123456789123456"];
    NSData *cipherData = [[NSUserDefaults standardUserDefaults] objectForKey:@"new123"];
    [self tripleDesDecryptData:cipherData key:@"123456789123456789123456"];
    [[NSUserDefaults standardUserDefaults] setObject:@"1" forKey:@"encryptedKey"];
    
}

- (void)encryptDES {
    
    NSString *stringToEncrypt = @"123123123123123123123123123123123asd asd";
    NSString *encryptedString = nil;
    const void *textBytes = [stringToEncrypt UTF8String];
    NSUInteger dataLength = [stringToEncrypt length];
    //key轉成 c 的 char，c 不吃 NSString
    const void *key = [@"@23another new saodfijcowmiecrowiteqcihasdifjkfgnc29 3][12040pafsdjiu48c09x209daokfpsmguh93cowkspdokfpoirjtmvwemrfj,xpojgicuo,ai,iwuehx.c,sm::sdjoi[]'a/s;x.`012`23456789jskiec中文" UTF8String];
    unsigned char buffer[1024];
    memset(buffer, 0, sizeof(char));
    size_t numBytesEncrypted = 0;
    NSString *nsstringKey = @"123";
    
    
    CCCryptorStatus ccStatus = CCCrypt(kCCEncrypt,
                                       kCCAlgorithmDES,
                                       kCCOptionPKCS7Padding,
                                       key,
                                       kCCKeySizeDES,
                                       nil,
                                       textBytes,
                                       dataLength,
                                       buffer,
                                       1024,
                                       &numBytesEncrypted);
    
    if (ccStatus == kCCSuccess) {
        NSLog(@"encrypt buffer: %s",buffer);
        NSData *data = [NSData dataWithBytes:buffer length:(NSUInteger)numBytesEncrypted];
        
        //把上次做的data存起來，給下次用
        [[NSUserDefaults standardUserDefaults] setObject:data forKey:@"123"];
    } else if (ccStatus == kCCParamError) {
        NSLog(@"kCCParamError");
    } else if (ccStatus == kCCBufferTooSmall) {
        NSLog(@"kCCBufferTooSmall");
    } else if (ccStatus == kCCMemoryFailure) {
        NSLog(@"kCCMemoryFailure");
    } else if (ccStatus == kCCAlignmentError) {
        NSLog(@"kCCAlignmentError");
    } else if (ccStatus == kCCDecodeError) {
        NSLog(@"kCCDecodeError");
    } else if (ccStatus == kCCUnimplemented) {
        NSLog(@"kCCUnimplemented");
    } else {
        NSLog(@"on non fail");
    }

    
   
    
}

- (void)decryptDES {
    NSData *cipherData = [[NSUserDefaults standardUserDefaults] objectForKey:@"123"];
    unsigned char buffer[1024];
    const void *key = [@"@23another new saodfijcowmiecrowiteqcihasdifjkfgnc29 3][12040pafsdjiu48c09x209daokfpsmguh93cowkspdokfpoirjtmvwemrfj,xpojgicuo,ai,iwuehx.c,sm::sdjoi[]'a/s;x.`012`23456789jskiec中文" UTF8String];
    memset(buffer, 0, sizeof(char));
    size_t numBytesDecrypted = 0;
    CCCryptorStatus ccStatus = CCCrypt(kCCDecrypt,
                                       kCCAlgorithmDES,
                                       kCCOptionPKCS7Padding,
                                       key,
                                       kCCKeySizeDES,
                                       nil,
                                       [cipherData bytes],
                                       [cipherData length],
                                       buffer,
                                       1024,
                                       &numBytesDecrypted);
   
    
    NSString* plainText = nil;
    if (ccStatus == kCCSuccess) {
        NSData* data = [NSData dataWithBytes:buffer length:(NSUInteger)numBytesDecrypted];
        plainText = [[NSString alloc] initWithData:data encoding:NSNonLossyASCIIStringEncoding] ;
        NSLog(@"decrypt buffer: %s", buffer);
        NSLog(@"decrypt plainText: %@",plainText);
    } else if (ccStatus == kCCParamError) {
        NSLog(@"kCCParamError");
    } else if (ccStatus == kCCBufferTooSmall) {
        NSLog(@"kCCBufferTooSmall");
    } else if (ccStatus == kCCMemoryFailure) {
        NSLog(@"kCCMemoryFailure");
    } else if (ccStatus == kCCAlignmentError) {
        NSLog(@"kCCAlignmentError");
    } else if (ccStatus == kCCDecodeError) {
        NSLog(@"kCCDecodeError");
    } else if (ccStatus == kCCUnimplemented) {
        NSLog(@"kCCUnimplemented");
    }else {
        NSLog(@"on non fail");
    }
}


- (NSData *)tripleDesEncryptString:(NSString *)input
                               key:(NSString *)key
{
    NSParameterAssert(input);
    NSParameterAssert(key);
    
    NSData *inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    
    size_t outLength;
    
    NSAssert(keyData.length == kCCKeySize3DES, @"the keyData is an invalid size");
    
    NSMutableData *outputData = [NSMutableData dataWithLength:(inputData.length  +  kCCBlockSize3DES)];
    
    CCCryptorStatus
    result = CCCrypt(kCCEncrypt, // operation
                     kCCAlgorithm3DES, // Algorithm
                     kCCOptionPKCS7Padding | kCCOptionECBMode, // options
                     keyData.bytes, // key
                     keyData.length, // keylength
                     nil,// iv
                     inputData.bytes, // dataIn
                     inputData.length, // dataInLength,
                     outputData.mutableBytes, // dataOut
                     outputData.length, // dataOutAvailable
                     &outLength); // dataOutMoved
    
    if (result != kCCSuccess) {
        NSLog(@"error....tripleDesEncryptString");
    }
    [outputData setLength:outLength];
    [[NSUserDefaults standardUserDefaults] setObject:outputData forKey:@"new123"];
    return outputData;
}



- (NSString *)tripleDesDecryptData:(NSData *)input
                               key:(NSString *)key
{
    NSParameterAssert(input);
    NSParameterAssert(key);
    
    NSData *inputData = input;
    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    
    size_t outLength;
    
    NSAssert(keyData.length == kCCKeySize3DES, @"the keyData is an invalid size");
    
    NSMutableData *outputData = [NSMutableData dataWithLength:(inputData.length  +  kCCBlockSize3DES)];
    
    CCCryptorStatus
    result = CCCrypt(kCCDecrypt, // operation
                     kCCAlgorithm3DES, // Algorithm
                     kCCOptionPKCS7Padding | kCCOptionECBMode, // options
                     keyData.bytes, // key
                     keyData.length, // keylength
                     nil,// iv
                     inputData.bytes, // dataIn
                     inputData.length, // dataInLength,
                     outputData.mutableBytes, // dataOut
                     outputData.length, // dataOutAvailable
                     &outLength); // dataOutMoved
    
    if (result != kCCSuccess) {
        NSLog(@"error tripleDesDecryptData");
    }
    [outputData setLength:outLength];
    NSLog(@"tripleDesDecryptData return: %@",[[NSString alloc] initWithData:outputData encoding:NSUTF8StringEncoding]);
    return [[NSString alloc] initWithData:outputData encoding:NSUTF8StringEncoding];
}

@end
