.class Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/SalesforceKeyGenerator;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final AES:Ljava/lang/String; = "AES"

.field private static final KEYSTORE_ALIAS:Ljava/lang/String; = "com.salesforce.androidsdk.security.KEYPAIR"

.field private static final SHA1PRNG:Ljava/lang/String; = "SHA1PRNG"

.field private static final SHA256:Ljava/lang/String; = "SHA-256"

.field private static final TAG:Ljava/lang/String; = "SalesforceKeyGenerator"


# instance fields
.field private final CACHED_ENCRYPTION_KEYS:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private final context:Landroid/content/Context;

.field private final keyStoreWrapper:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/KeyStoreWrapper;


# direct methods
.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/KeyStoreWrapper;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/SalesforceKeyGenerator;->CACHED_ENCRYPTION_KEYS:Ljava/util/Map;

    .line 10
    .line 11
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/SalesforceKeyGenerator;->context:Landroid/content/Context;

    .line 16
    .line 17
    iput-object p2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/SalesforceKeyGenerator;->keyStoreWrapper:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/KeyStoreWrapper;

    .line 18
    .line 19
    return-void
.end method

.method private declared-synchronized generateEncryptionKey(Ljava/lang/String;)Ljava/lang/String;
    .locals 3

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/SalesforceKeyGenerator;->getUniqueId(Ljava/lang/String;)Ljava/lang/String;

    .line 3
    .line 4
    .line 5
    move-result-object p1

    .line 6
    sget-object v0, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    const-string v0, "SHA-256"

    .line 13
    .line 14
    invoke-static {v0}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-virtual {v0, p1}, Ljava/security/MessageDigest;->digest([B)[B

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    const/16 v0, 0x20

    .line 23
    .line 24
    new-array v1, v0, [B

    .line 25
    .line 26
    const/4 v2, 0x0

    .line 27
    invoke-static {p1, v2, v1, v2, v0}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 28
    .line 29
    .line 30
    const/4 p1, 0x2

    .line 31
    invoke-static {v1, p1}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p1
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 35
    goto :goto_0

    .line 36
    :catchall_0
    move-exception p1

    .line 37
    goto :goto_1

    .line 38
    :catch_0
    move-exception p1

    .line 39
    :try_start_1
    const-string v0, "SalesforceKeyGenerator"

    .line 40
    .line 41
    const-string v1, "Exception thrown while getting encryption key"

    .line 42
    .line 43
    invoke-static {v0, v1, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 44
    .line 45
    .line 46
    const/4 p1, 0x0

    .line 47
    :goto_0
    monitor-exit p0

    .line 48
    return-object p1

    .line 49
    :goto_1
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 50
    throw p1
.end method

.method private declared-synchronized generateUniqueId(Ljava/lang/String;I)Ljava/lang/String;
    .locals 2

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/SalesforceKeyGenerator;->readFromNoBackupFile(Ljava/lang/String;)Ljava/lang/String;

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    iget-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/SalesforceKeyGenerator;->keyStoreWrapper:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/KeyStoreWrapper;

    .line 9
    .line 10
    const-string p2, "com.salesforce.androidsdk.security.KEYPAIR"

    .line 11
    .line 12
    invoke-virtual {p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/KeyStoreWrapper;->getRSAPrivateKey(Ljava/lang/String;)Ljava/security/PrivateKey;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->decryptWithRSA(Ljava/security/PrivateKey;Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 20
    monitor-exit p0

    .line 21
    return-object p1

    .line 22
    :catchall_0
    move-exception p1

    .line 23
    goto :goto_1

    .line 24
    :cond_0
    :try_start_1
    const-string v0, "SHA1PRNG"

    .line 25
    .line 26
    invoke-static {v0}, Ljava/security/SecureRandom;->getInstance(Ljava/lang/String;)Ljava/security/SecureRandom;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    const-string v1, "AES"

    .line 31
    .line 32
    invoke-static {v1}, Ljavax/crypto/KeyGenerator;->getInstance(Ljava/lang/String;)Ljavax/crypto/KeyGenerator;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    invoke-virtual {v1, p2, v0}, Ljavax/crypto/KeyGenerator;->init(ILjava/security/SecureRandom;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {v1}, Ljavax/crypto/KeyGenerator;->generateKey()Ljavax/crypto/SecretKey;

    .line 40
    .line 41
    .line 42
    move-result-object p2

    .line 43
    invoke-interface {p2}, Ljava/security/Key;->getEncoded()[B

    .line 44
    .line 45
    .line 46
    move-result-object p2

    .line 47
    const/4 v0, 0x2

    .line 48
    invoke-static {p2, v0}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p2
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 52
    goto :goto_0

    .line 53
    :catch_0
    move-exception p2

    .line 54
    :try_start_2
    const-string v0, "SalesforceKeyGenerator"

    .line 55
    .line 56
    const-string v1, "Security exception thrown"

    .line 57
    .line 58
    invoke-static {v0, v1, p2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 59
    .line 60
    .line 61
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 62
    .line 63
    .line 64
    move-result-object p2

    .line 65
    invoke-virtual {p2}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object p2

    .line 69
    :goto_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/SalesforceKeyGenerator;->keyStoreWrapper:Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/KeyStoreWrapper;

    .line 70
    .line 71
    const-string v1, "com.salesforce.androidsdk.security.KEYPAIR"

    .line 72
    .line 73
    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/KeyStoreWrapper;->getRSAPublicKey(Ljava/lang/String;)Ljava/security/PublicKey;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    invoke-static {v0, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/Encryptor;->encryptWithRSA(Ljava/security/PublicKey;Ljava/lang/String;)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    invoke-direct {p0, p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/SalesforceKeyGenerator;->storeInNoBackupFile(Ljava/lang/String;Ljava/lang/String;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 82
    .line 83
    .line 84
    monitor-exit p0

    .line 85
    return-object p2

    .line 86
    :goto_1
    :try_start_3
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 87
    throw p1
.end method

.method private readFromNoBackupFile(Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/SalesforceKeyGenerator;->context:Landroid/content/Context;

    .line 2
    .line 3
    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/util/FileUtilsKt;->retrieveModuleKey(Landroid/content/Context;Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method private declared-synchronized storeInNoBackupFile(Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/SalesforceKeyGenerator;->context:Landroid/content/Context;

    .line 3
    .line 4
    invoke-static {v0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/util/FileUtilsKt;->storeModuleKey(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 5
    .line 6
    .line 7
    monitor-exit p0

    .line 8
    return-void

    .line 9
    :catchall_0
    move-exception p1

    .line 10
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 11
    throw p1
.end method


# virtual methods
.method public getEncryptionKey(Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return-object p0

    .line 9
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/SalesforceKeyGenerator;->CACHED_ENCRYPTION_KEYS:Ljava/util/Map;

    .line 10
    .line 11
    invoke-interface {v0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    check-cast v0, Ljava/lang/String;

    .line 16
    .line 17
    if-nez v0, :cond_1

    .line 18
    .line 19
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/SalesforceKeyGenerator;->generateEncryptionKey(Ljava/lang/String;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    if-eqz v0, :cond_1

    .line 24
    .line 25
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/SalesforceKeyGenerator;->CACHED_ENCRYPTION_KEYS:Ljava/util/Map;

    .line 26
    .line 27
    invoke-interface {p0, p1, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    :cond_1
    return-object v0
.end method

.method public getRandom128ByteKey()Ljava/lang/String;
    .locals 1

    .line 1
    new-instance p0, Ljava/security/SecureRandom;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/security/SecureRandom;-><init>()V

    .line 4
    .line 5
    .line 6
    const/16 v0, 0x80

    .line 7
    .line 8
    new-array v0, v0, [B

    .line 9
    .line 10
    invoke-virtual {p0, v0}, Ljava/security/SecureRandom;->nextBytes([B)V

    .line 11
    .line 12
    .line 13
    const/16 p0, 0xb

    .line 14
    .line 15
    invoke-static {v0, p0}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method public getSHA256Hash(Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    sget-object p0, Ljava/nio/charset/StandardCharsets;->US_ASCII:Ljava/nio/charset/Charset;

    .line 2
    .line 3
    invoke-virtual {p1, p0}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    :try_start_0
    const-string p1, "SHA-256"

    .line 8
    .line 9
    invoke-static {p1}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    invoke-virtual {p1, p0}, Ljava/security/MessageDigest;->digest([B)[B

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    const/16 p1, 0xb

    .line 18
    .line 19
    invoke-static {p0, p1}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 23
    return-object p0

    .line 24
    :catch_0
    move-exception p0

    .line 25
    const-string p1, "SalesforceKeyGenerator"

    .line 26
    .line 27
    const-string v0, "Exception thrown while generating SHA-256 hash"

    .line 28
    .line 29
    invoke-static {p1, v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 30
    .line 31
    .line 32
    const/4 p0, 0x0

    .line 33
    return-object p0
.end method

.method public getUniqueId(Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    const/16 v0, 0x100

    .line 1
    invoke-virtual {p0, p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/SalesforceKeyGenerator;->getUniqueId(Ljava/lang/String;I)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public getUniqueId(Ljava/lang/String;I)Ljava/lang/String;
    .locals 0

    .line 2
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/SalesforceKeyGenerator;->generateUniqueId(Ljava/lang/String;I)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method
