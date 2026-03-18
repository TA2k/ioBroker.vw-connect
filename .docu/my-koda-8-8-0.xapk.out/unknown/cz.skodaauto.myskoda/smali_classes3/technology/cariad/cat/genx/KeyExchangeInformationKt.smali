.class public final Ltechnology/cariad/cat/genx/KeyExchangeInformationKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000&\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u001a%\u0010\u0000\u001a\u00020\u0001*\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\u0008H\u0080\u0002\"\u0015\u0010\t\u001a\u00020\n*\u00020\u00018F\u00a2\u0006\u0006\u001a\u0004\u0008\u000b\u0010\u000c\u00a8\u0006\r"
    }
    d2 = {
        "invoke",
        "Ltechnology/cariad/cat/genx/KeyExchangeInformation;",
        "Ltechnology/cariad/cat/genx/KeyExchangeInformation$Companion;",
        "qrCode",
        "Ltechnology/cariad/cat/genx/QRCode;",
        "antenna",
        "Ltechnology/cariad/cat/genx/Antenna;",
        "keyPair",
        "Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;",
        "remoteCredentials",
        "Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;",
        "getRemoteCredentials",
        "(Ltechnology/cariad/cat/genx/KeyExchangeInformation;)Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;",
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
.method public static final getRemoteCredentials(Ltechnology/cariad/cat/genx/KeyExchangeInformation;)Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 7
    .line 8
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/KeyExchangeInformation;->getRemotePublicSigningKey()Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/KeyExchangeInformation;->getAdvertisementSecret()[B

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/KeyExchangeInformation;->getLamSecret()[B

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-direct {v0, v1, v2, p0}, Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;-><init>(Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;[B[B)V

    .line 21
    .line 22
    .line 23
    return-object v0
.end method

.method public static final invoke(Ltechnology/cariad/cat/genx/KeyExchangeInformation$Companion;Ltechnology/cariad/cat/genx/QRCode;Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)Ltechnology/cariad/cat/genx/KeyExchangeInformation;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "qrCode"

    .line 7
    .line 8
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p0, "antenna"

    .line 12
    .line 13
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string p0, "keyPair"

    .line 17
    .line 18
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    new-instance p0, Ltechnology/cariad/cat/genx/keyexchange/InternalKeyExchangeInformation;

    .line 22
    .line 23
    invoke-direct {p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/keyexchange/InternalKeyExchangeInformation;-><init>(Ltechnology/cariad/cat/genx/QRCode;Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)V

    .line 24
    .line 25
    .line 26
    return-object p0
.end method
