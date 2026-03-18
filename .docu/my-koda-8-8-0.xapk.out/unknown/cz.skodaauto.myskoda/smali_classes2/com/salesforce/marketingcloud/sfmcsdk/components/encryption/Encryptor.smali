.class Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final AES_CBC_CIPHER:Ljava/lang/String; = "AES/CBC/PKCS5Padding"

.field private static final AES_GCM_CIPHER:Ljava/lang/String; = "AES/GCM/NoPadding"

.field private static final BOUNCY_CASTLE:Ljava/lang/String; = "BC"

.field private static final MAC_TRANSFORMATION:Ljava/lang/String; = "HmacSHA256"

.field private static final RSA_PKCS1:Ljava/lang/String; = "RSA/ECB/PKCS1Padding"

.field private static final SHA1PRNG:Ljava/lang/String; = "SHA1PRNG"

.field private static final TAG:Ljava/lang/String; = "Encryptor"


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static decrypt(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    const/16 v0, 0xc

    .line 1
    new-array v0, v0, [B

    invoke-static {p0, p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->decrypt(Ljava/lang/String;Ljava/lang/String;[B)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static decrypt(Ljava/lang/String;Ljava/lang/String;[B)Ljava/lang/String;
    .locals 1

    .line 3
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v0

    if-nez v0, :cond_1

    if-nez p0, :cond_0

    goto :goto_0

    .line 4
    :cond_0
    invoke-virtual {p0}, Ljava/lang/String;->getBytes()[B

    move-result-object p0

    invoke-static {p0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->decrypt([BLjava/lang/String;[B)Ljava/lang/String;

    move-result-object p0

    :cond_1
    :goto_0
    return-object p0
.end method

.method public static decrypt([BLjava/lang/String;)Ljava/lang/String;
    .locals 1

    const/16 v0, 0xc

    .line 2
    new-array v0, v0, [B

    invoke-static {p0, p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->decrypt([BLjava/lang/String;[B)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static decrypt([BLjava/lang/String;[B)Ljava/lang/String;
    .locals 3

    .line 5
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_1

    if-eqz p0, :cond_0

    .line 6
    new-instance p1, Ljava/lang/String;

    sget-object p2, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    invoke-direct {p1, p0, p2}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    return-object p1

    :cond_0
    return-object v1

    :cond_1
    const/4 v0, 0x2

    .line 7
    :try_start_0
    invoke-static {p1, v0}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    move-result-object p1

    .line 8
    invoke-static {p0, v0}, Landroid/util/Base64;->decode([BI)[B

    move-result-object p0

    .line 9
    array-length v0, p0

    invoke-static {p0, v0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->decrypt([BI[B[B)[B

    move-result-object p0

    .line 10
    new-instance p1, Ljava/lang/String;

    array-length p2, p0

    sget-object v0, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    const/4 v2, 0x0

    invoke-direct {p1, p0, v2, p2, v0}, Ljava/lang/String;-><init>([BIILjava/nio/charset/Charset;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object p1

    :catch_0
    move-exception p0

    .line 11
    const-string p1, "Encryptor"

    const-string p2, "Error during decryption"

    invoke-static {p1, p2, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    return-object v1
.end method

.method private static decrypt([BI[B[B)[B
    .locals 3

    .line 12
    array-length v0, p3

    const/4 v1, 0x0

    invoke-static {p0, v1, p3, v1, v0}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 13
    array-length v0, p3

    sub-int/2addr p1, v0

    .line 14
    array-length v0, p3

    .line 15
    new-array v2, p1, [B

    .line 16
    invoke-static {p0, v0, v2, v1, p1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 17
    array-length p0, p3

    const/16 v0, 0xc

    if-ne p0, v0, :cond_0

    .line 18
    invoke-static {p2, p3}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->getDecryptingCipher([B[B)Ljavax/crypto/Cipher;

    move-result-object p0

    goto :goto_0

    .line 19
    :cond_0
    invoke-static {p2, p3}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->getLegacyDecryptingCipher([B[B)Ljavax/crypto/Cipher;

    move-result-object p0

    .line 20
    :goto_0
    invoke-virtual {p0, v2, v1, p1}, Ljavax/crypto/Cipher;->doFinal([BII)[B

    move-result-object p0

    return-object p0
.end method

.method public static decryptBytes([B[B[B)Ljava/lang/String;
    .locals 2

    .line 1
    :try_start_0
    invoke-static {p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->getLegacyDecryptingCipher([B[B)Ljavax/crypto/Cipher;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    array-length p2, p0

    .line 6
    const/4 v0, 0x0

    .line 7
    invoke-virtual {p1, p0, v0, p2}, Ljavax/crypto/Cipher;->doFinal([BII)[B

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    new-instance p1, Ljava/lang/String;

    .line 12
    .line 13
    array-length p2, p0

    .line 14
    sget-object v1, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 15
    .line 16
    invoke-direct {p1, p0, v0, p2, v1}, Ljava/lang/String;-><init>([BIILjava/nio/charset/Charset;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 17
    .line 18
    .line 19
    return-object p1

    .line 20
    :catch_0
    move-exception p0

    .line 21
    const-string p1, "Encryptor"

    .line 22
    .line 23
    const-string p2, "Error during symmetric decryption using AES"

    .line 24
    .line 25
    invoke-static {p1, p2, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 26
    .line 27
    .line 28
    const/4 p0, 0x0

    .line 29
    return-object p0
.end method

.method private static decryptWithPrivateKey(Ljava/security/PrivateKey;Ljava/lang/String;Ljava/lang/String;)[B
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p0, :cond_1

    .line 3
    .line 4
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    :try_start_0
    invoke-static {p2}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;

    .line 12
    .line 13
    .line 14
    move-result-object p2

    .line 15
    const/4 v1, 0x2

    .line 16
    invoke-virtual {p2, v1, p0}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p1}, Ljava/lang/String;->getBytes()[B

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    const/4 p1, 0x3

    .line 24
    invoke-static {p0, p1}, Landroid/util/Base64;->decode([BI)[B

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-virtual {p2, p0}, Ljavax/crypto/Cipher;->doFinal([B)[B

    .line 29
    .line 30
    .line 31
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 32
    return-object p0

    .line 33
    :catch_0
    move-exception p0

    .line 34
    const-string p1, "Encryptor"

    .line 35
    .line 36
    const-string p2, "Error during asymmetric decryption"

    .line 37
    .line 38
    invoke-static {p1, p2, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 39
    .line 40
    .line 41
    :cond_1
    :goto_0
    return-object v0
.end method

.method public static decryptWithRSA(Ljava/security/PrivateKey;Ljava/lang/String;)Ljava/lang/String;
    .locals 3

    .line 1
    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->decryptWithRSABytes(Ljava/security/PrivateKey;Ljava/lang/String;)[B

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    :try_start_0
    new-instance p1, Ljava/lang/String;

    .line 8
    .line 9
    array-length v0, p0

    .line 10
    sget-object v1, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    invoke-direct {p1, p0, v2, v0, v1}, Ljava/lang/String;-><init>([BIILjava/nio/charset/Charset;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :catch_0
    move-exception p0

    .line 18
    const-string p1, "Encryptor"

    .line 19
    .line 20
    const-string v0, "Error during asymmetric decryption using RSA"

    .line 21
    .line 22
    invoke-static {p1, v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 23
    .line 24
    .line 25
    :cond_0
    const/4 p0, 0x0

    .line 26
    return-object p0
.end method

.method public static decryptWithRSABytes(Ljava/security/PrivateKey;Ljava/lang/String;)[B
    .locals 1

    .line 1
    const-string v0, "RSA/ECB/PKCS1Padding"

    .line 2
    .line 3
    invoke-static {p0, p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->decryptWithPrivateKey(Ljava/security/PrivateKey;Ljava/lang/String;Ljava/lang/String;)[B

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public static encrypt(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    :try_start_0
    invoke-static {}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->generateInitVector()[B

    move-result-object v0

    invoke-static {p0, p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->encrypt(Ljava/lang/String;Ljava/lang/String;[B)Ljava/lang/String;

    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    :catch_0
    move-exception p0

    .line 2
    const-string p1, "Encryptor"

    const-string v0, "Error during encryption"

    invoke-static {p1, v0, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    const/4 p0, 0x0

    return-object p0
.end method

.method public static encrypt(Ljava/lang/String;Ljava/lang/String;[B)Ljava/lang/String;
    .locals 1

    .line 3
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v0

    if-nez v0, :cond_2

    if-nez p0, :cond_0

    goto :goto_0

    .line 4
    :cond_0
    invoke-static {p0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->encryptBytes(Ljava/lang/String;Ljava/lang/String;[B)[B

    move-result-object p0

    const/4 p1, 0x0

    if-nez p0, :cond_1

    return-object p1

    .line 5
    :cond_1
    :try_start_0
    new-instance p2, Ljava/lang/String;

    sget-object v0, Ljava/nio/charset/StandardCharsets;->US_ASCII:Ljava/nio/charset/Charset;

    invoke-direct {p2, p0, v0}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object p2

    :catch_0
    move-exception p0

    .line 6
    const-string p2, "Encryptor"

    const-string v0, "Error during encryption"

    invoke-static {p2, v0, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    return-object p1

    :cond_2
    :goto_0
    return-object p0
.end method

.method private static encrypt([B[B[B)[B
    .locals 2

    .line 7
    invoke-static {p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->getEncryptingCipher([B[B)Ljavax/crypto/Cipher;

    move-result-object p1

    .line 8
    invoke-virtual {p1, p0}, Ljavax/crypto/Cipher;->doFinal([B)[B

    move-result-object p0

    .line 9
    array-length p1, p2

    array-length v0, p0

    add-int/2addr p1, v0

    new-array p1, p1, [B

    .line 10
    array-length v0, p2

    const/4 v1, 0x0

    invoke-static {p2, v1, p1, v1, v0}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 11
    array-length p2, p2

    array-length v0, p0

    invoke-static {p0, v1, p1, p2, v0}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    return-object p1
.end method

.method public static encryptBytes(Ljava/lang/String;Ljava/lang/String;)[B
    .locals 1

    .line 1
    :try_start_0
    invoke-static {}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->generateInitVector()[B

    move-result-object v0

    invoke-static {p0, p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->encryptBytes(Ljava/lang/String;Ljava/lang/String;[B)[B

    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    :catch_0
    move-exception p0

    .line 2
    const-string p1, "Encryptor"

    const-string v0, "Error during encryption"

    invoke-static {p1, v0, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    const/4 p0, 0x0

    return-object p0
.end method

.method public static encryptBytes(Ljava/lang/String;Ljava/lang/String;[B)[B
    .locals 3

    .line 3
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_1

    if-nez p0, :cond_0

    return-object v1

    .line 4
    :cond_0
    invoke-virtual {p0}, Ljava/lang/String;->getBytes()[B

    move-result-object p0

    return-object p0

    :cond_1
    const/4 v0, 0x2

    .line 5
    :try_start_0
    invoke-static {p1, v0}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    move-result-object p1

    .line 6
    sget-object v2, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    invoke-virtual {p0, v2}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    move-result-object p0

    .line 7
    invoke-static {p0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->encrypt([B[B[B)[B

    move-result-object p0

    invoke-static {p0, v0}, Landroid/util/Base64;->encode([BI)[B

    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    :catch_0
    move-exception p0

    .line 8
    const-string p1, "Encryptor"

    const-string p2, "Error during encryption"

    invoke-static {p1, p2, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    return-object v1
.end method

.method private static encryptWithPublicKey(Ljava/security/PublicKey;Ljava/lang/String;Ljava/lang/String;)[B
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p0, :cond_1

    .line 3
    .line 4
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    :try_start_0
    invoke-static {p2}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;

    .line 12
    .line 13
    .line 14
    move-result-object p2

    .line 15
    const/4 v1, 0x1

    .line 16
    invoke-virtual {p2, v1, p0}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p1}, Ljava/lang/String;->getBytes()[B

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    invoke-virtual {p2, p0}, Ljavax/crypto/Cipher;->doFinal([B)[B

    .line 24
    .line 25
    .line 26
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 27
    return-object p0

    .line 28
    :catch_0
    move-exception p0

    .line 29
    const-string p1, "Encryptor"

    .line 30
    .line 31
    const-string p2, "Error during asymmetric encryption"

    .line 32
    .line 33
    invoke-static {p1, p2, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 34
    .line 35
    .line 36
    :cond_1
    :goto_0
    return-object v0
.end method

.method public static encryptWithRSA(Ljava/security/PublicKey;Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->encryptWithRSABytes(Ljava/security/PublicKey;Ljava/lang/String;)[B

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    const/4 p1, 0x3

    .line 8
    invoke-static {p0, p1}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return-object p0
.end method

.method public static encryptWithRSABytes(Ljava/security/PublicKey;Ljava/lang/String;)[B
    .locals 1

    .line 1
    const-string v0, "RSA/ECB/PKCS1Padding"

    .line 2
    .line 3
    invoke-static {p0, p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->encryptWithPublicKey(Ljava/security/PublicKey;Ljava/lang/String;Ljava/lang/String;)[B

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public static generateInitVector()[B
    .locals 2

    .line 1
    const-string v0, "SHA1PRNG"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/security/SecureRandom;->getInstance(Ljava/lang/String;)Ljava/security/SecureRandom;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/16 v1, 0xc

    .line 8
    .line 9
    new-array v1, v1, [B

    .line 10
    .line 11
    invoke-virtual {v0, v1}, Ljava/security/SecureRandom;->nextBytes([B)V

    .line 12
    .line 13
    .line 14
    return-object v1
.end method

.method private static getBestCipher(Ljava/lang/String;)Ljavax/crypto/Cipher;
    .locals 2

    .line 1
    :try_start_0
    const-string v0, "AES/GCM/NoPadding"

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-static {p0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0

    .line 14
    :cond_0
    invoke-static {}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->getLegacyEncryptionProvider()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-static {p0, v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/Cipher;

    .line 19
    .line 20
    .line 21
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 22
    return-object p0

    .line 23
    :catch_0
    move-exception p0

    .line 24
    const-string v0, "Encryptor"

    .line 25
    .line 26
    const-string v1, "No cipher transformation available"

    .line 27
    .line 28
    invoke-static {v0, v1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 29
    .line 30
    .line 31
    const/4 p0, 0x0

    .line 32
    return-object p0
.end method

.method private static getDecryptingCipher([B[B)Ljavax/crypto/Cipher;
    .locals 3

    .line 1
    const-string v0, "AES/GCM/NoPadding"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->getBestCipher(Ljava/lang/String;)Ljavax/crypto/Cipher;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Ljavax/crypto/spec/SecretKeySpec;

    .line 8
    .line 9
    invoke-virtual {v0}, Ljavax/crypto/Cipher;->getAlgorithm()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    invoke-direct {v1, p0, v2}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V

    .line 14
    .line 15
    .line 16
    new-instance p0, Ljavax/crypto/spec/IvParameterSpec;

    .line 17
    .line 18
    invoke-direct {p0, p1}, Ljavax/crypto/spec/IvParameterSpec;-><init>([B)V

    .line 19
    .line 20
    .line 21
    const/4 p1, 0x2

    .line 22
    invoke-virtual {v0, p1, v1, p0}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0}, Ljavax/crypto/spec/IvParameterSpec;->getIV()[B

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-virtual {v0, p0}, Ljavax/crypto/Cipher;->updateAAD([B)V

    .line 30
    .line 31
    .line 32
    return-object v0
.end method

.method private static getEncryptingCipher([B[B)Ljavax/crypto/Cipher;
    .locals 3

    .line 1
    const-string v0, "AES/GCM/NoPadding"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->getBestCipher(Ljava/lang/String;)Ljavax/crypto/Cipher;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Ljavax/crypto/spec/SecretKeySpec;

    .line 8
    .line 9
    invoke-virtual {v0}, Ljavax/crypto/Cipher;->getAlgorithm()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    invoke-direct {v1, p0, v2}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V

    .line 14
    .line 15
    .line 16
    new-instance p0, Ljavax/crypto/spec/IvParameterSpec;

    .line 17
    .line 18
    invoke-direct {p0, p1}, Ljavax/crypto/spec/IvParameterSpec;-><init>([B)V

    .line 19
    .line 20
    .line 21
    const/4 p1, 0x1

    .line 22
    invoke-virtual {v0, p1, v1, p0}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0}, Ljavax/crypto/spec/IvParameterSpec;->getIV()[B

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-virtual {v0, p0}, Ljavax/crypto/Cipher;->updateAAD([B)V

    .line 30
    .line 31
    .line 32
    return-object v0
.end method

.method private static getLegacyDecryptingCipher([B[B)Ljavax/crypto/Cipher;
    .locals 3

    .line 1
    const-string v0, "AES/CBC/PKCS5Padding"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->getBestCipher(Ljava/lang/String;)Ljavax/crypto/Cipher;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Ljavax/crypto/spec/SecretKeySpec;

    .line 8
    .line 9
    invoke-virtual {v0}, Ljavax/crypto/Cipher;->getAlgorithm()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    invoke-direct {v1, p0, v2}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V

    .line 14
    .line 15
    .line 16
    new-instance p0, Ljavax/crypto/spec/IvParameterSpec;

    .line 17
    .line 18
    invoke-direct {p0, p1}, Ljavax/crypto/spec/IvParameterSpec;-><init>([B)V

    .line 19
    .line 20
    .line 21
    const/4 p1, 0x2

    .line 22
    invoke-virtual {v0, p1, v1, p0}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V

    .line 23
    .line 24
    .line 25
    return-object v0
.end method

.method private static getLegacyEncryptionProvider()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "BC"

    .line 2
    .line 3
    return-object v0
.end method

.method public static legacyDecrypt(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .locals 1
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    const/16 v0, 0x10

    .line 1
    new-array v0, v0, [B

    invoke-static {p0, p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->decrypt(Ljava/lang/String;Ljava/lang/String;[B)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static legacyDecrypt([BLjava/lang/String;)Ljava/lang/String;
    .locals 1
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    const/16 v0, 0x10

    .line 2
    new-array v0, v0, [B

    invoke-static {p0, p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->decrypt([BLjava/lang/String;[B)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method
