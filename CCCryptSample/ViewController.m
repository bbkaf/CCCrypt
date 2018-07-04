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
    
    //[self encryptDES];
    [self decryptDES];
    
    
}

- (void)encryptDES {
    
    NSString *stringToEncrypt = @"1";
    NSString *encryptedString = nil;
    const char *textBytes = [stringToEncrypt UTF8String];
    NSUInteger dataLength = [stringToEncrypt length];
    unsigned char buffer[1024];
    
    memset(buffer, 0, sizeof(char));
    size_t numBytesEncrypted = 0;
    
    
    
    CCCryptorStatus ccStatus = CCCrypt(kCCEncrypt,
                                       kCCAlgorithmDES,
                                       kCCOptionPKCS7Padding,
                                       @"1",
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
        
        //把上次做的data存起來，給下次用，也就是每次做出的data不同
        [[NSUserDefaults standardUserDefaults] setObject:data forKey:@"123"];
        [self decryptDES];
    }
    
}

- (void)decryptDES {
    NSData *cipherData = [[NSUserDefaults standardUserDefaults] objectForKey:@"123"];
    unsigned char buffer[1024];
    memset(buffer, 0, sizeof(char));
    size_t numBytesDecrypted = 0;
    CCCryptorStatus ccStatus = CCCrypt(kCCDecrypt,
                                       kCCAlgorithmDES,
                                       kCCOptionPKCS7Padding,
                                       @"1",
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
    }
}



@end
