.class public Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$CipherTextIvMac;,
        Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;
    }
.end annotation


# static fields
.field private static final AES_KEY_LENGTH_BITS:I = 0x80

.field private static final ALLOW_BROKEN_PRNG:Z = false

.field public static final BASE64_FLAGS:I = 0x2

.field private static final CIPHER:Ljava/lang/String; = "AES"

.field private static final CIPHER_TRANSFORMATION:Ljava/lang/String; = "AES/CBC/PKCS5Padding"

.field private static final HMAC_ALGORITHM:Ljava/lang/String; = "HmacSHA256"

.field private static final HMAC_KEY_LENGTH_BITS:I = 0x100

.field private static final IV_LENGTH_BYTES:I = 0x10

.field private static final PBE_ALGORITHM:Ljava/lang/String; = "PBKDF2WithHmacSHA1"

.field private static final PBE_SALT_LENGTH_BITS:I = 0x80

.field static final prngFixed:Ljava/util/concurrent/atomic/AtomicBoolean;


# direct methods
.method public static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity;->prngFixed:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static constantTimeEq([B[B)Z
    .locals 5

    .line 1
    array-length v0, p0

    .line 2
    array-length v1, p1

    .line 3
    const/4 v2, 0x0

    .line 4
    if-eq v0, v1, :cond_0

    .line 5
    .line 6
    return v2

    .line 7
    :cond_0
    move v0, v2

    .line 8
    move v1, v0

    .line 9
    :goto_0
    array-length v3, p0

    .line 10
    if-ge v0, v3, :cond_1

    .line 11
    .line 12
    aget-byte v3, p0, v0

    .line 13
    .line 14
    aget-byte v4, p1, v0

    .line 15
    .line 16
    xor-int/2addr v3, v4

    .line 17
    or-int/2addr v1, v3

    .line 18
    add-int/lit8 v0, v0, 0x1

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_1
    if-nez v1, :cond_2

    .line 22
    .line 23
    const/4 p0, 0x1

    .line 24
    return p0

    .line 25
    :cond_2
    return v2
.end method

.method private static copyOfRange([BII)[B
    .locals 2

    .line 1
    sub-int/2addr p2, p1

    .line 2
    new-array v0, p2, [B

    .line 3
    .line 4
    const/4 v1, 0x0

    .line 5
    invoke-static {p0, p1, v0, v1, p2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method

.method public static decrypt(Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$CipherTextIvMac;Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;)[B
    .locals 3

    .line 1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$CipherTextIvMac;->getIv()[B

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$CipherTextIvMac;->getCipherText()[B

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$CipherTextIvMac;->ivCipherConcat([B[B)[B

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;->getIntegrityKey()Ljavax/crypto/SecretKey;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity;->generateMac([BLjavax/crypto/SecretKey;)[B

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$CipherTextIvMac;->getMac()[B

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity;->constantTimeEq([B[B)Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_0

    .line 30
    .line 31
    const-string v0, "AES/CBC/PKCS5Padding"

    .line 32
    .line 33
    invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;->getConfidentialityKey()Ljavax/crypto/SecretKey;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    new-instance v1, Ljavax/crypto/spec/IvParameterSpec;

    .line 42
    .line 43
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$CipherTextIvMac;->getIv()[B

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    invoke-direct {v1, v2}, Ljavax/crypto/spec/IvParameterSpec;-><init>([B)V

    .line 48
    .line 49
    .line 50
    const/4 v2, 0x2

    .line 51
    invoke-virtual {v0, v2, p1, v1}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$CipherTextIvMac;->getCipherText()[B

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    invoke-virtual {v0, p0}, Ljavax/crypto/Cipher;->doFinal([B)[B

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    return-object p0

    .line 63
    :cond_0
    new-instance p0, Ljava/security/GeneralSecurityException;

    .line 64
    .line 65
    const-string p1, "MAC stored in civ does not match computed MAC."

    .line 66
    .line 67
    invoke-direct {p0, p1}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    throw p0
.end method

.method public static decryptString(Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$CipherTextIvMac;Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "UTF-8"

    invoke-static {p0, p1, v0}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity;->decryptString(Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$CipherTextIvMac;Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static decryptString(Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$CipherTextIvMac;Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 2
    new-instance v0, Ljava/lang/String;

    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity;->decrypt(Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$CipherTextIvMac;Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;)[B

    move-result-object p0

    invoke-direct {v0, p0, p2}, Ljava/lang/String;-><init>([BLjava/lang/String;)V

    return-object v0
.end method

.method public static encrypt(Ljava/lang/String;Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;)Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$CipherTextIvMac;
    .locals 1

    .line 1
    const-string v0, "UTF-8"

    invoke-static {p0, p1, v0}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity;->encrypt(Ljava/lang/String;Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;Ljava/lang/String;)Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$CipherTextIvMac;

    move-result-object p0

    return-object p0
.end method

.method public static encrypt(Ljava/lang/String;Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;Ljava/lang/String;)Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$CipherTextIvMac;
    .locals 0

    .line 2
    invoke-virtual {p0, p2}, Ljava/lang/String;->getBytes(Ljava/lang/String;)[B

    move-result-object p0

    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity;->encrypt([BLcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;)Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$CipherTextIvMac;

    move-result-object p0

    return-object p0
.end method

.method public static encrypt([BLcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;)Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$CipherTextIvMac;
    .locals 4

    .line 3
    invoke-static {}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity;->generateIv()[B

    move-result-object v0

    const-string v1, "AES/CBC/PKCS5Padding"

    invoke-static {v1}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;

    move-result-object v1

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;->getConfidentialityKey()Ljavax/crypto/SecretKey;

    move-result-object v2

    new-instance v3, Ljavax/crypto/spec/IvParameterSpec;

    invoke-direct {v3, v0}, Ljavax/crypto/spec/IvParameterSpec;-><init>([B)V

    const/4 v0, 0x1

    invoke-virtual {v1, v0, v2, v3}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V

    invoke-virtual {v1}, Ljavax/crypto/Cipher;->getIV()[B

    move-result-object v0

    invoke-virtual {v1, p0}, Ljavax/crypto/Cipher;->doFinal([B)[B

    move-result-object p0

    invoke-static {v0, p0}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$CipherTextIvMac;->ivCipherConcat([B[B)[B

    move-result-object v1

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;->getIntegrityKey()Ljavax/crypto/SecretKey;

    move-result-object p1

    invoke-static {v1, p1}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity;->generateMac([BLjavax/crypto/SecretKey;)[B

    move-result-object p1

    new-instance v1, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$CipherTextIvMac;

    invoke-direct {v1, p0, v0, p1}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$CipherTextIvMac;-><init>([B[B[B)V

    return-object v1
.end method

.method private static fixPrng()V
    .locals 3

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity;->prngFixed:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-nez v1, :cond_1

    .line 8
    .line 9
    const-class v1, Lcom/salesforce/marketingcloud/tozny/a;

    .line 10
    .line 11
    monitor-enter v1

    .line 12
    :try_start_0
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    if-nez v2, :cond_0

    .line 17
    .line 18
    invoke-static {}, Lcom/salesforce/marketingcloud/tozny/a;->a()V

    .line 19
    .line 20
    .line 21
    const/4 v2, 0x1

    .line 22
    invoke-virtual {v0, v2}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :catchall_0
    move-exception v0

    .line 27
    goto :goto_1

    .line 28
    :cond_0
    :goto_0
    monitor-exit v1

    .line 29
    return-void

    .line 30
    :goto_1
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 31
    throw v0

    .line 32
    :cond_1
    return-void
.end method

.method public static generateIv()[B
    .locals 1

    .line 1
    const/16 v0, 0x10

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity;->randomBytes(I)[B

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    return-object v0
.end method

.method public static generateKey()Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;
    .locals 4

    .line 1
    invoke-static {}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity;->fixPrng()V

    .line 2
    .line 3
    .line 4
    const-string v0, "AES"

    .line 5
    .line 6
    invoke-static {v0}, Ljavax/crypto/KeyGenerator;->getInstance(Ljava/lang/String;)Ljavax/crypto/KeyGenerator;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    const/16 v1, 0x80

    .line 11
    .line 12
    invoke-virtual {v0, v1}, Ljavax/crypto/KeyGenerator;->init(I)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0}, Ljavax/crypto/KeyGenerator;->generateKey()Ljavax/crypto/SecretKey;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    const/16 v1, 0x20

    .line 20
    .line 21
    invoke-static {v1}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity;->randomBytes(I)[B

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    new-instance v2, Ljavax/crypto/spec/SecretKeySpec;

    .line 26
    .line 27
    const-string v3, "HmacSHA256"

    .line 28
    .line 29
    invoke-direct {v2, v1, v3}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V

    .line 30
    .line 31
    .line 32
    new-instance v1, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;

    .line 33
    .line 34
    invoke-direct {v1, v0, v2}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;-><init>(Ljavax/crypto/SecretKey;Ljavax/crypto/SecretKey;)V

    .line 35
    .line 36
    .line 37
    return-object v1
.end method

.method public static generateKeyFromPassword(Ljava/lang/String;Ljava/lang/String;I)Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;
    .locals 1

    const/4 v0, 0x2

    .line 1
    invoke-static {p1, v0}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    move-result-object p1

    invoke-static {p0, p1, p2}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity;->generateKeyFromPassword(Ljava/lang/String;[BI)Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;

    move-result-object p0

    return-object p0
.end method

.method public static generateKeyFromPassword(Ljava/lang/String;[BI)Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;
    .locals 2

    .line 2
    invoke-static {}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity;->fixPrng()V

    new-instance v0, Ljavax/crypto/spec/PBEKeySpec;

    invoke-virtual {p0}, Ljava/lang/String;->toCharArray()[C

    move-result-object p0

    const/16 v1, 0x180

    invoke-direct {v0, p0, p1, p2, v1}, Ljavax/crypto/spec/PBEKeySpec;-><init>([C[BII)V

    const-string p0, "PBKDF2WithHmacSHA1"

    invoke-static {p0}, Ljavax/crypto/SecretKeyFactory;->getInstance(Ljava/lang/String;)Ljavax/crypto/SecretKeyFactory;

    move-result-object p0

    invoke-virtual {p0, v0}, Ljavax/crypto/SecretKeyFactory;->generateSecret(Ljava/security/spec/KeySpec;)Ljavax/crypto/SecretKey;

    move-result-object p0

    invoke-interface {p0}, Ljava/security/Key;->getEncoded()[B

    move-result-object p0

    const/4 p1, 0x0

    const/16 p2, 0x10

    invoke-static {p0, p1, p2}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity;->copyOfRange([BII)[B

    move-result-object p1

    const/16 v0, 0x30

    invoke-static {p0, p2, v0}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity;->copyOfRange([BII)[B

    move-result-object p0

    new-instance p2, Ljavax/crypto/spec/SecretKeySpec;

    const-string v0, "AES"

    invoke-direct {p2, p1, v0}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V

    new-instance p1, Ljavax/crypto/spec/SecretKeySpec;

    const-string v0, "HmacSHA256"

    invoke-direct {p1, p0, v0}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V

    new-instance p0, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;

    invoke-direct {p0, p2, p1}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;-><init>(Ljavax/crypto/SecretKey;Ljavax/crypto/SecretKey;)V

    return-object p0
.end method

.method public static generateMac([BLjavax/crypto/SecretKey;)[B
    .locals 1

    .line 1
    const-string v0, "HmacSHA256"

    .line 2
    .line 3
    invoke-static {v0}, Ljavax/crypto/Mac;->getInstance(Ljava/lang/String;)Ljavax/crypto/Mac;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {v0, p1}, Ljavax/crypto/Mac;->init(Ljava/security/Key;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljavax/crypto/Mac;->doFinal([B)[B

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public static generateSalt()[B
    .locals 1

    .line 1
    const/16 v0, 0x80

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity;->randomBytes(I)[B

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    return-object v0
.end method

.method public static keyString(Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;->toString()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static keys(Ljava/lang/String;)Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;
    .locals 6

    .line 1
    const-string v0, ":"

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    array-length v0, p0

    .line 8
    const/4 v1, 0x2

    .line 9
    if-ne v0, v1, :cond_2

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    aget-object v2, p0, v0

    .line 13
    .line 14
    invoke-static {v2, v1}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    array-length v3, v2

    .line 19
    const/16 v4, 0x10

    .line 20
    .line 21
    if-ne v3, v4, :cond_1

    .line 22
    .line 23
    const/4 v3, 0x1

    .line 24
    aget-object p0, p0, v3

    .line 25
    .line 26
    invoke-static {p0, v1}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    array-length v1, p0

    .line 31
    const/16 v3, 0x20

    .line 32
    .line 33
    if-ne v1, v3, :cond_0

    .line 34
    .line 35
    new-instance v1, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;

    .line 36
    .line 37
    new-instance v3, Ljavax/crypto/spec/SecretKeySpec;

    .line 38
    .line 39
    array-length v4, v2

    .line 40
    const-string v5, "AES"

    .line 41
    .line 42
    invoke-direct {v3, v2, v0, v4, v5}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BIILjava/lang/String;)V

    .line 43
    .line 44
    .line 45
    new-instance v0, Ljavax/crypto/spec/SecretKeySpec;

    .line 46
    .line 47
    const-string v2, "HmacSHA256"

    .line 48
    .line 49
    invoke-direct {v0, p0, v2}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V

    .line 50
    .line 51
    .line 52
    invoke-direct {v1, v3, v0}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;-><init>(Ljavax/crypto/SecretKey;Ljavax/crypto/SecretKey;)V

    .line 53
    .line 54
    .line 55
    return-object v1

    .line 56
    :cond_0
    new-instance p0, Ljava/security/InvalidKeyException;

    .line 57
    .line 58
    const-string v0, "Base64 decoded key is not 256 bytes"

    .line 59
    .line 60
    invoke-direct {p0, v0}, Ljava/security/InvalidKeyException;-><init>(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    throw p0

    .line 64
    :cond_1
    new-instance p0, Ljava/security/InvalidKeyException;

    .line 65
    .line 66
    const-string v0, "Base64 decoded key is not 128 bytes"

    .line 67
    .line 68
    invoke-direct {p0, v0}, Ljava/security/InvalidKeyException;-><init>(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    throw p0

    .line 72
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 73
    .line 74
    const-string v0, "Cannot parse aesKey:hmacKey"

    .line 75
    .line 76
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    throw p0
.end method

.method private static randomBytes(I)[B
    .locals 1

    .line 1
    invoke-static {}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity;->fixPrng()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/security/SecureRandom;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/security/SecureRandom;-><init>()V

    .line 7
    .line 8
    .line 9
    new-array p0, p0, [B

    .line 10
    .line 11
    invoke-virtual {v0, p0}, Ljava/security/SecureRandom;->nextBytes([B)V

    .line 12
    .line 13
    .line 14
    return-object p0
.end method

.method public static saltString([B)Ljava/lang/String;
    .locals 1

    .line 1
    const/4 v0, 0x2

    .line 2
    invoke-static {p0, v0}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    return-object p0
.end method
