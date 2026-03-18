.class public final Ltechnology/cariad/cat/genx/protocol/data/ProtocolDataExtensionKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u001a\u0013\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\u0000\u00a2\u0006\u0004\u0008\u0002\u0010\u0003\u001a\u0013\u0010\u0006\u001a\u00020\u0005*\u00020\u0004H\u0000\u00a2\u0006\u0004\u0008\u0006\u0010\u0007\u00a8\u0006\u0008"
    }
    d2 = {
        "Lt41/b;",
        "Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;",
        "toBeaconInformation",
        "(Lt41/b;)Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;",
        "Ltechnology/cariad/cat/genx/DeviceInformation;",
        "Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;",
        "toSmartphoneInformationResponse",
        "(Ltechnology/cariad/cat/genx/DeviceInformation;)Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;",
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
.method public static final toBeaconInformation(Lt41/b;)Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;

    .line 7
    .line 8
    iget-short v1, p0, Lt41/b;->e:S

    .line 9
    .line 10
    iget-short p0, p0, Lt41/b;->f:S

    .line 11
    .line 12
    sget-object v2, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;->OFFLINE:Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;

    .line 13
    .line 14
    const/4 v3, 0x0

    .line 15
    invoke-direct {v0, v1, p0, v2, v3}, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;-><init>(SSLtechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;Lkotlin/jvm/internal/g;)V

    .line 16
    .line 17
    .line 18
    return-object v0
.end method

.method public static final toSmartphoneInformationResponse(Ltechnology/cariad/cat/genx/DeviceInformation;)Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;
    .locals 8

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v1, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;

    .line 7
    .line 8
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/DeviceInformation;->getPhoneName()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/DeviceInformation;->getAppName()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v3

    .line 16
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/DeviceInformation;->getManufacturerName()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v4

    .line 20
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/DeviceInformation;->getModelName()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v5

    .line 24
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/DeviceInformation;->getSwVersion()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v6

    .line 28
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/DeviceInformation;->getAppVersion()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v7

    .line 32
    invoke-direct/range {v1 .. v7}, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponse;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    return-object v1
.end method
