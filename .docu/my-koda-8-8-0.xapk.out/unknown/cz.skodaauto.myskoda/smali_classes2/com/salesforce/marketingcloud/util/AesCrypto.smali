.class public Lcom/salesforce/marketingcloud/util/AesCrypto;
.super Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/util/Crypto;


# static fields
.field private static final AES_CRYPTO_PREFS:Ljava/lang/String; = "com.salesforce.marketingcloud.storagePrefs"

.field private static final ENC_TEST_STRING:Ljava/lang/String; = "F6389234-1024-481F-9173-37D9D7F5051F"

.field private static final INSTALL_DATE_ENC:Ljava/lang/String; = "install_date_enc"

.field private static final PBE_ITERATIONS:I = 0x1f4


# instance fields
.field private final aesKey:Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;


# direct methods
.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILcom/salesforce/marketingcloud/legacycrypto/OldSdkHash;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity;-><init>()V

    invoke-direct {p0, p2, p3, p4, p6}, Lcom/salesforce/marketingcloud/util/AesCrypto;->generateEncPp(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/legacycrypto/SdkHash;)Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/util/AesCrypto;->getSalt(Landroid/content/Context;)Ljava/lang/String;

    move-result-object p1

    invoke-static {p2, p1, p5}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity;->generateKeyFromPassword(Ljava/lang/String;Ljava/lang/String;I)Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;

    move-result-object p1

    iput-object p1, p0, Lcom/salesforce/marketingcloud/util/AesCrypto;->aesKey:Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;

    invoke-direct {p0}, Lcom/salesforce/marketingcloud/util/AesCrypto;->verifyEncryption()V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/legacycrypto/OldSdkHash;)V
    .locals 7

    const/16 v5, 0x1f4

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    move-object v4, p4

    move-object v6, p5

    .line 2
    invoke-direct/range {v0 .. v6}, Lcom/salesforce/marketingcloud/util/AesCrypto;-><init>(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILcom/salesforce/marketingcloud/legacycrypto/OldSdkHash;)V

    return-void
.end method

.method private generateEncPp(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/legacycrypto/SdkHash;)Ljava/lang/String;
    .locals 2

    .line 1
    const/4 p0, 0x2

    .line 2
    const-string v0, "__"

    .line 3
    .line 4
    const-string v1, "--"

    .line 5
    .line 6
    if-nez p4, :cond_0

    .line 7
    .line 8
    new-instance p4, Ljava/lang/StringBuilder;

    .line 9
    .line 10
    invoke-direct {p4}, Ljava/lang/StringBuilder;-><init>()V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p4, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {p4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    invoke-virtual {p4, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {p4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {p4, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {p4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    sget-object p2, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 33
    .line 34
    invoke-virtual {p1, p2}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    invoke-static {p1, p0}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0

    .line 43
    :cond_0
    invoke-static {p1, v1}, Lp3/m;->q(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    invoke-interface {p4, p2}, Lcom/salesforce/marketingcloud/legacycrypto/SdkHash;->generateHash(Ljava/lang/String;)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p2

    .line 51
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    invoke-interface {p4, p3}, Lcom/salesforce/marketingcloud/legacycrypto/SdkHash;->generateHash(Ljava/lang/String;)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p2

    .line 61
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    invoke-interface {p4, p1}, Lcom/salesforce/marketingcloud/legacycrypto/SdkHash;->generateHash(Ljava/lang/String;)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p1

    .line 72
    sget-object p2, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 73
    .line 74
    invoke-virtual {p1, p2}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    invoke-static {p1, p0}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    return-object p0
.end method

.method private verifyEncryption()V
    .locals 2

    .line 1
    const-string v0, "F6389234-1024-481F-9173-37D9D7F5051F"

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/util/AesCrypto;->encString(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-virtual {p0, v1}, Lcom/salesforce/marketingcloud/util/AesCrypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-virtual {v0, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    new-instance p0, Ljava/security/GeneralSecurityException;

    .line 19
    .line 20
    const-string v0, "Encryption/decryption test failed"

    .line 21
    .line 22
    invoke-direct {p0, v0}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    throw p0
.end method


# virtual methods
.method public decString(Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return-object p0

    .line 5
    :cond_0
    :try_start_0
    new-instance v0, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$CipherTextIvMac;

    .line 6
    .line 7
    invoke-direct {v0, p1}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$CipherTextIvMac;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lcom/salesforce/marketingcloud/util/AesCrypto;->aesKey:Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;

    .line 11
    .line 12
    invoke-static {v0, p0}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity;->decryptString(Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$CipherTextIvMac;Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0
    :try_end_0
    .catch Ljava/io/UnsupportedEncodingException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/security/GeneralSecurityException; {:try_start_0 .. :try_end_0} :catch_0

    .line 16
    return-object p0

    .line 17
    :catch_0
    move-exception p0

    .line 18
    new-instance p1, Ljava/lang/RuntimeException;

    .line 19
    .line 20
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 21
    .line 22
    .line 23
    throw p1

    .line 24
    :catch_1
    move-exception p0

    .line 25
    new-instance p1, Ljava/lang/RuntimeException;

    .line 26
    .line 27
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 28
    .line 29
    .line 30
    throw p1
.end method

.method public encString(Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return-object p0

    .line 5
    :cond_0
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/util/AesCrypto;->aesKey:Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;

    .line 6
    .line 7
    invoke-static {p1, p0}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity;->encrypt(Ljava/lang/String;Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$SecretKeys;)Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$CipherTextIvMac;

    .line 8
    .line 9
    .line 10
    move-result-object p0
    :try_end_0
    .catch Ljava/io/UnsupportedEncodingException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/security/GeneralSecurityException; {:try_start_0 .. :try_end_0} :catch_0

    .line 11
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$CipherTextIvMac;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :catch_0
    move-exception p0

    .line 17
    new-instance p1, Ljava/lang/RuntimeException;

    .line 18
    .line 19
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 20
    .line 21
    .line 22
    throw p1

    .line 23
    :catch_1
    move-exception p0

    .line 24
    new-instance p1, Ljava/lang/RuntimeException;

    .line 25
    .line 26
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 27
    .line 28
    .line 29
    throw p1
.end method

.method public getSalt(Landroid/content/Context;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string p0, "com.salesforce.marketingcloud.storagePrefs"

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-virtual {p1, p0, v0}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    const/4 p1, 0x0

    .line 9
    const-string v0, "install_date_enc"

    .line 10
    .line 11
    invoke-interface {p0, v0, p1}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    if-nez p1, :cond_0

    .line 16
    .line 17
    invoke-static {}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity;->generateSalt()[B

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    invoke-static {p1}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity;->saltString([B)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    invoke-interface {p0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-interface {p0, v0, p1}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-interface {p0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 34
    .line 35
    .line 36
    :cond_0
    return-object p1
.end method
