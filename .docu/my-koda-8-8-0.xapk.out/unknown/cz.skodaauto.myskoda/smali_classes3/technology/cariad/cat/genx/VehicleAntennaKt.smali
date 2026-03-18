.class public final Ltechnology/cariad/cat/genx/VehicleAntennaKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000,\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0011\"\u0019\u0010\u0005\u001a\u00060\u0001j\u0002`\u0002*\u00020\u00008F\u00a2\u0006\u0006\u001a\u0004\u0008\u0003\u0010\u0004\"\u0015\u0010\t\u001a\u00020\u0006*\u00020\u00008F\u00a2\u0006\u0006\u001a\u0004\u0008\u0007\u0010\u0008\"\u0015\u0010\r\u001a\u00020\n*\u00020\u00008F\u00a2\u0006\u0006\u001a\u0004\u0008\u000b\u0010\u000c\"\u001d\u0010\u0012\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u000f0\u000e*\u00020\u00008F\u00a2\u0006\u0006\u001a\u0004\u0008\u0010\u0010\u0011\"#\u0010\u0016\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u000f0\u000e*\u00020\u00008F\u00a2\u0006\u000c\u0012\u0004\u0008\u0014\u0010\u0015\u001a\u0004\u0008\u0013\u0010\u0011\"#\u0010\u0019\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u000f0\u000e*\u00020\u00008F\u00a2\u0006\u000c\u0012\u0004\u0008\u0018\u0010\u0015\u001a\u0004\u0008\u0017\u0010\u0011\"#\u0010\u001c\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u000f0\u000e*\u00020\u00008F\u00a2\u0006\u000c\u0012\u0004\u0008\u001b\u0010\u0015\u001a\u0004\u0008\u001a\u0010\u0011\"#\u0010\u001f\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u000f0\u000e*\u00020\u00008F\u00a2\u0006\u000c\u0012\u0004\u0008\u001e\u0010\u0015\u001a\u0004\u0008\u001d\u0010\u0011\u00a8\u0006 "
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/VehicleAntenna;",
        "",
        "Ltechnology/cariad/cat/genx/VIN;",
        "getVin",
        "(Ltechnology/cariad/cat/genx/VehicleAntenna;)Ljava/lang/String;",
        "vin",
        "Ltechnology/cariad/cat/genx/Antenna;",
        "getAntenna",
        "(Ltechnology/cariad/cat/genx/VehicleAntenna;)Ltechnology/cariad/cat/genx/Antenna;",
        "antenna",
        "Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;",
        "getIdentifier",
        "(Ltechnology/cariad/cat/genx/VehicleAntenna;)Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;",
        "identifier",
        "Lyy0/i;",
        "Lt41/g;",
        "getFoundStandardOrLegacyBeacon",
        "(Ltechnology/cariad/cat/genx/VehicleAntenna;)Lyy0/i;",
        "foundStandardOrLegacyBeacon",
        "getFoundLegacyBeacon",
        "getFoundLegacyBeacon$annotations",
        "(Ltechnology/cariad/cat/genx/VehicleAntenna;)V",
        "foundLegacyBeacon",
        "getFoundStandardBeacon",
        "getFoundStandardBeacon$annotations",
        "foundStandardBeacon",
        "getFoundPairingBeacon",
        "getFoundPairingBeacon$annotations",
        "foundPairingBeacon",
        "getFoundAlertBeacon",
        "getFoundAlertBeacon$annotations",
        "foundAlertBeacon",
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
.method public static final getAntenna(Ltechnology/cariad/cat/genx/VehicleAntenna;)Ltechnology/cariad/cat/genx/Antenna;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/VehicleAntenna;->getInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getIdentifier()Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;->getAntenna()Ltechnology/cariad/cat/genx/Antenna;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0
.end method

.method public static final getFoundAlertBeacon(Ltechnology/cariad/cat/genx/VehicleAntenna;)Lyy0/i;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/VehicleAntenna;",
            ")",
            "Lyy0/i;"
        }
    .end annotation

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/VehicleAntenna;->getFoundBeacons()Lyy0/a2;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    new-instance v0, Ltechnology/cariad/cat/genx/VehicleAntennaKt$foundAlertBeacon$1;

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/VehicleAntennaKt$foundAlertBeacon$1;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 14
    .line 15
    .line 16
    invoke-static {v0, p0}, Lyy0/u;->C(Lay0/n;Lyy0/i;)Lzy0/j;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method public static synthetic getFoundAlertBeacon$annotations(Ltechnology/cariad/cat/genx/VehicleAntenna;)V
    .locals 0

    .line 1
    return-void
.end method

.method public static final getFoundLegacyBeacon(Ltechnology/cariad/cat/genx/VehicleAntenna;)Lyy0/i;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/VehicleAntenna;",
            ")",
            "Lyy0/i;"
        }
    .end annotation

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/VehicleAntenna;->getFoundBeacons()Lyy0/a2;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    new-instance v0, Ltechnology/cariad/cat/genx/VehicleAntennaKt$foundLegacyBeacon$1;

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/VehicleAntennaKt$foundLegacyBeacon$1;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 14
    .line 15
    .line 16
    invoke-static {v0, p0}, Lyy0/u;->C(Lay0/n;Lyy0/i;)Lzy0/j;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method public static synthetic getFoundLegacyBeacon$annotations(Ltechnology/cariad/cat/genx/VehicleAntenna;)V
    .locals 0

    .line 1
    return-void
.end method

.method public static final getFoundPairingBeacon(Ltechnology/cariad/cat/genx/VehicleAntenna;)Lyy0/i;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/VehicleAntenna;",
            ")",
            "Lyy0/i;"
        }
    .end annotation

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/VehicleAntenna;->getFoundBeacons()Lyy0/a2;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    new-instance v0, Ltechnology/cariad/cat/genx/VehicleAntennaKt$foundPairingBeacon$1;

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/VehicleAntennaKt$foundPairingBeacon$1;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 14
    .line 15
    .line 16
    invoke-static {v0, p0}, Lyy0/u;->C(Lay0/n;Lyy0/i;)Lzy0/j;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method public static synthetic getFoundPairingBeacon$annotations(Ltechnology/cariad/cat/genx/VehicleAntenna;)V
    .locals 0

    .line 1
    return-void
.end method

.method public static final getFoundStandardBeacon(Ltechnology/cariad/cat/genx/VehicleAntenna;)Lyy0/i;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/VehicleAntenna;",
            ")",
            "Lyy0/i;"
        }
    .end annotation

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/VehicleAntenna;->getFoundBeacons()Lyy0/a2;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    new-instance v0, Ltechnology/cariad/cat/genx/VehicleAntennaKt$foundStandardBeacon$1;

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/VehicleAntennaKt$foundStandardBeacon$1;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 14
    .line 15
    .line 16
    invoke-static {v0, p0}, Lyy0/u;->C(Lay0/n;Lyy0/i;)Lzy0/j;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method public static synthetic getFoundStandardBeacon$annotations(Ltechnology/cariad/cat/genx/VehicleAntenna;)V
    .locals 0

    .line 1
    return-void
.end method

.method public static final getFoundStandardOrLegacyBeacon(Ltechnology/cariad/cat/genx/VehicleAntenna;)Lyy0/i;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/VehicleAntenna;",
            ")",
            "Lyy0/i;"
        }
    .end annotation

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaKt;->getFoundLegacyBeacon(Ltechnology/cariad/cat/genx/VehicleAntenna;)Lyy0/i;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaKt;->getFoundStandardBeacon(Ltechnology/cariad/cat/genx/VehicleAntenna;)Lyy0/i;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    new-instance v1, Ltechnology/cariad/cat/genx/VehicleAntennaKt$foundStandardOrLegacyBeacon$1;

    .line 15
    .line 16
    const/4 v2, 0x0

    .line 17
    invoke-direct {v1, v2}, Ltechnology/cariad/cat/genx/VehicleAntennaKt$foundStandardOrLegacyBeacon$1;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 18
    .line 19
    .line 20
    new-instance v2, Lbn0/f;

    .line 21
    .line 22
    const/4 v3, 0x5

    .line 23
    invoke-direct {v2, v0, p0, v1, v3}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 24
    .line 25
    .line 26
    return-object v2
.end method

.method public static final getIdentifier(Ltechnology/cariad/cat/genx/VehicleAntenna;)Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/VehicleAntenna;->getInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getIdentifier()Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public static final getVin(Ltechnology/cariad/cat/genx/VehicleAntenna;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/VehicleAntenna;->getInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getIdentifier()Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;->getVin()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0
.end method
