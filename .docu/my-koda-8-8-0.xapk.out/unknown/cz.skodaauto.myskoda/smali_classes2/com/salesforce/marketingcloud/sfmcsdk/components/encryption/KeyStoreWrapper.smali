.class Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/KeyStoreWrapper;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final ANDROID_KEYSTORE:Ljava/lang/String; = "AndroidKeyStore"

.field private static final EC:Ljava/lang/String; = "EC"

.field private static final EC_KEY_LENGTH:I = 0x100

.field private static final RSA:Ljava/lang/String; = "RSA"

.field private static final RSA_KEY_LENGTH:I = 0x800

.field private static final TAG:Ljava/lang/String; = "KeyStoreWrapper"


# instance fields
.field private final context:Landroid/content/Context;

.field private final keyStore:Ljava/security/KeyStore;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/KeyStoreWrapper;->context:Landroid/content/Context;

    .line 9
    .line 10
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/KeyStoreWrapper;->loadKeyStore()Ljava/security/KeyStore;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/KeyStoreWrapper;->keyStore:Ljava/security/KeyStore;

    .line 15
    .line 16
    return-void
.end method

.method private declared-synchronized createKeysIfNecessary(Ljava/lang/String;Ljava/lang/String;I)V
    .locals 2

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/KeyStoreWrapper;->keyStore:Ljava/security/KeyStore;

    .line 3
    .line 4
    invoke-virtual {v0, p2}, Ljava/security/KeyStore;->containsAlias(Ljava/lang/String;)Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    const-string v0, "AndroidKeyStore"

    .line 11
    .line 12
    invoke-static {p1, v0}, Ljava/security/KeyPairGenerator;->getInstance(Ljava/lang/String;Ljava/lang/String;)Ljava/security/KeyPairGenerator;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    new-instance v0, Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 17
    .line 18
    const/4 v1, 0x3

    .line 19
    invoke-direct {v0, p2, v1}, Landroid/security/keystore/KeyGenParameterSpec$Builder;-><init>(Ljava/lang/String;I)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0, p3}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->setKeySize(I)Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 23
    .line 24
    .line 25
    move-result-object p2

    .line 26
    const-string p3, "PKCS1Padding"

    .line 27
    .line 28
    filled-new-array {p3}, [Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p3

    .line 32
    invoke-virtual {p2, p3}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->setEncryptionPaddings([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 33
    .line 34
    .line 35
    move-result-object p2

    .line 36
    const/4 p3, 0x0

    .line 37
    invoke-virtual {p2, p3}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->setIsStrongBoxBacked(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {p2}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->build()Landroid/security/keystore/KeyGenParameterSpec;

    .line 41
    .line 42
    .line 43
    move-result-object p2

    .line 44
    invoke-virtual {p1, p2}, Ljava/security/KeyPairGenerator;->initialize(Ljava/security/spec/AlgorithmParameterSpec;)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {p1}, Ljava/security/KeyPairGenerator;->generateKeyPair()Ljava/security/KeyPair;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 48
    .line 49
    .line 50
    goto :goto_0

    .line 51
    :catchall_0
    move-exception p1

    .line 52
    goto :goto_1

    .line 53
    :catch_0
    move-exception p1

    .line 54
    :try_start_1
    const-string p2, "KeyStoreWrapper"

    .line 55
    .line 56
    const-string p3, "Could not generate key pair"

    .line 57
    .line 58
    invoke-static {p2, p3, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 59
    .line 60
    .line 61
    :cond_0
    :goto_0
    monitor-exit p0

    .line 62
    return-void

    .line 63
    :goto_1
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 64
    throw p1
.end method

.method private getPrivateKey(Ljava/lang/String;Ljava/lang/String;I)Ljava/security/PrivateKey;
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/KeyStoreWrapper;->createKeysIfNecessary(Ljava/lang/String;Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    const/4 p1, 0x0

    .line 5
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/KeyStoreWrapper;->keyStore:Ljava/security/KeyStore;

    .line 6
    .line 7
    invoke-virtual {p0, p2, p1}, Ljava/security/KeyStore;->getKey(Ljava/lang/String;[C)Ljava/security/Key;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    check-cast p0, Ljava/security/PrivateKey;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 12
    .line 13
    return-object p0

    .line 14
    :catch_0
    move-exception p0

    .line 15
    const-string p2, "KeyStoreWrapper"

    .line 16
    .line 17
    const-string p3, "Could not retrieve private key"

    .line 18
    .line 19
    invoke-static {p2, p3, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 20
    .line 21
    .line 22
    return-object p1
.end method

.method private getPublicKey(Ljava/lang/String;Ljava/lang/String;I)Ljava/security/PublicKey;
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/KeyStoreWrapper;->createKeysIfNecessary(Ljava/lang/String;Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/KeyStoreWrapper;->keyStore:Ljava/security/KeyStore;

    .line 5
    .line 6
    invoke-virtual {p0, p2}, Ljava/security/KeyStore;->getCertificate(Ljava/lang/String;)Ljava/security/cert/Certificate;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0}, Ljava/security/cert/Certificate;->getPublicKey()Ljava/security/PublicKey;

    .line 11
    .line 12
    .line 13
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 14
    return-object p0

    .line 15
    :catch_0
    move-exception p0

    .line 16
    const-string p1, "KeyStoreWrapper"

    .line 17
    .line 18
    const-string p2, "Could not retrieve public key"

    .line 19
    .line 20
    invoke-static {p1, p2, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 21
    .line 22
    .line 23
    const/4 p0, 0x0

    .line 24
    return-object p0
.end method

.method private getPublicKeyString(Ljava/lang/String;Ljava/lang/String;I)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/KeyStoreWrapper;->getPublicKey(Ljava/lang/String;Ljava/lang/String;I)Ljava/security/PublicKey;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    invoke-interface {p0}, Ljava/security/Key;->getEncoded()[B

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    const/4 p1, 0x3

    .line 12
    invoke-static {p0, p1}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0

    .line 17
    :cond_0
    const/4 p0, 0x0

    .line 18
    return-object p0
.end method

.method private loadKeyStore()Ljava/security/KeyStore;
    .locals 1

    .line 1
    const-string p0, "AndroidKeyStore"

    .line 2
    .line 3
    invoke-static {p0}, Ljava/security/KeyStore;->getInstance(Ljava/lang/String;)Ljava/security/KeyStore;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const/4 v0, 0x0

    .line 8
    invoke-virtual {p0, v0}, Ljava/security/KeyStore;->load(Ljava/security/KeyStore$LoadStoreParameter;)V

    .line 9
    .line 10
    .line 11
    return-object p0
.end method


# virtual methods
.method public getECPrivateKey(Ljava/lang/String;)Ljava/security/PrivateKey;
    .locals 2

    .line 1
    const-string v0, "EC"

    .line 2
    .line 3
    const/16 v1, 0x100

    .line 4
    .line 5
    invoke-direct {p0, v0, p1, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/KeyStoreWrapper;->getPrivateKey(Ljava/lang/String;Ljava/lang/String;I)Ljava/security/PrivateKey;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public getECPublicKey(Ljava/lang/String;)Ljava/security/PublicKey;
    .locals 2

    .line 1
    const-string v0, "EC"

    .line 2
    .line 3
    const/16 v1, 0x100

    .line 4
    .line 5
    invoke-direct {p0, v0, p1, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/KeyStoreWrapper;->getPublicKey(Ljava/lang/String;Ljava/lang/String;I)Ljava/security/PublicKey;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public getECPublicString(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "EC"

    .line 2
    .line 3
    const/16 v1, 0x100

    .line 4
    .line 5
    invoke-direct {p0, v0, p1, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/KeyStoreWrapper;->getPublicKeyString(Ljava/lang/String;Ljava/lang/String;I)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public getRSAPrivateKey(Ljava/lang/String;)Ljava/security/PrivateKey;
    .locals 1

    const/16 v0, 0x800

    .line 1
    invoke-virtual {p0, p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/KeyStoreWrapper;->getRSAPrivateKey(Ljava/lang/String;I)Ljava/security/PrivateKey;

    move-result-object p0

    return-object p0
.end method

.method public getRSAPrivateKey(Ljava/lang/String;I)Ljava/security/PrivateKey;
    .locals 1

    .line 2
    const-string v0, "RSA"

    invoke-direct {p0, v0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/KeyStoreWrapper;->getPrivateKey(Ljava/lang/String;Ljava/lang/String;I)Ljava/security/PrivateKey;

    move-result-object p0

    return-object p0
.end method

.method public getRSAPublicKey(Ljava/lang/String;)Ljava/security/PublicKey;
    .locals 1

    const/16 v0, 0x800

    .line 1
    invoke-virtual {p0, p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/KeyStoreWrapper;->getRSAPublicKey(Ljava/lang/String;I)Ljava/security/PublicKey;

    move-result-object p0

    return-object p0
.end method

.method public getRSAPublicKey(Ljava/lang/String;I)Ljava/security/PublicKey;
    .locals 1

    .line 2
    const-string v0, "RSA"

    invoke-direct {p0, v0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/KeyStoreWrapper;->getPublicKey(Ljava/lang/String;Ljava/lang/String;I)Ljava/security/PublicKey;

    move-result-object p0

    return-object p0
.end method

.method public getRSAPublicString(Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    const/16 v0, 0x800

    .line 1
    invoke-virtual {p0, p1, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/KeyStoreWrapper;->getRSAPublicString(Ljava/lang/String;I)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public getRSAPublicString(Ljava/lang/String;I)Ljava/lang/String;
    .locals 1

    .line 2
    const-string v0, "RSA"

    invoke-direct {p0, v0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/KeyStoreWrapper;->getPublicKeyString(Ljava/lang/String;Ljava/lang/String;I)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method
