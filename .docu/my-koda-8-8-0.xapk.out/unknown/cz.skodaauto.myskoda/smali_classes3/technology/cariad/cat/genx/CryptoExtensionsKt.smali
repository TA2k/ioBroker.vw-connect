.class public final Ltechnology/cariad/cat/genx/CryptoExtensionsKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0016\n\u0000\n\u0002\u0010\u0012\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0002\u0008\t\"\u001e\u0010\u0000\u001a\u00020\u0001*\u00020\u00028@X\u0080\u0004\u00a2\u0006\u000c\u0012\u0004\u0008\u0003\u0010\u0004\u001a\u0004\u0008\u0005\u0010\u0006\"\u001e\u0010\u0007\u001a\u00020\u0001*\u00020\u00028@X\u0080\u0004\u00a2\u0006\u000c\u0012\u0004\u0008\u0008\u0010\u0004\u001a\u0004\u0008\t\u0010\u0006\"\u001e\u0010\u0000\u001a\u00020\u0001*\u00020\n8@X\u0080\u0004\u00a2\u0006\u000c\u0012\u0004\u0008\u0003\u0010\u000b\u001a\u0004\u0008\u0005\u0010\u000c\"\u001e\u0010\r\u001a\u00020\u0001*\u00020\n8@X\u0080\u0004\u00a2\u0006\u000c\u0012\u0004\u0008\u000e\u0010\u000b\u001a\u0004\u0008\u000f\u0010\u000c\"\u001e\u0010\u0010\u001a\u00020\u0001*\u00020\n8@X\u0080\u0004\u00a2\u0006\u000c\u0012\u0004\u0008\u0011\u0010\u000b\u001a\u0004\u0008\u0012\u0010\u000c\u00a8\u0006\u0013"
    }
    d2 = {
        "publicKeyBytes",
        "",
        "Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;",
        "getPublicKeyBytes$annotations",
        "(Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)V",
        "getPublicKeyBytes",
        "(Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)[B",
        "privateKeyBytes",
        "getPrivateKeyBytes$annotations",
        "getPrivateKeyBytes",
        "Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;",
        "(Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;)V",
        "(Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;)[B",
        "advertisementSecretBytes",
        "getAdvertisementSecretBytes$annotations",
        "getAdvertisementSecretBytes",
        "lamSecretBytes",
        "getLamSecretBytes$annotations",
        "getLamSecretBytes",
        "genx_release"
    }
    k = 0x2
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method public static final getAdvertisementSecretBytes(Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;)[B
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;->getAdvertisementSecret()[B

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method

.method public static synthetic getAdvertisementSecretBytes$annotations(Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;)V
    .locals 0

    .line 1
    return-void
.end method

.method public static final getLamSecretBytes(Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;)[B
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;->getLamSecret()[B

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method

.method public static synthetic getLamSecretBytes$annotations(Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;)V
    .locals 0

    .line 1
    return-void
.end method

.method public static final getPrivateKeyBytes(Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)[B
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;->getPrivateKey()Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;->getRawValue()[B

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public static synthetic getPrivateKeyBytes$annotations(Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)V
    .locals 0

    .line 1
    return-void
.end method

.method public static final getPublicKeyBytes(Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)[B
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;->getPublicKey()Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;

    move-result-object p0

    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;->getRawValue()[B

    move-result-object p0

    return-object p0
.end method

.method public static final getPublicKeyBytes(Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;)[B
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;->getPublicKey()Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;

    move-result-object p0

    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;->getRawValue()[B

    move-result-object p0

    return-object p0
.end method

.method public static synthetic getPublicKeyBytes$annotations(Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)V
    .locals 0

    .line 1
    return-void
.end method

.method public static synthetic getPublicKeyBytes$annotations(Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;)V
    .locals 0

    .line 2
    return-void
.end method
