.class public final Ltechnology/cariad/cat/genx/VehicleAntennaTransportKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000:\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0008\n\u0002\u0010\u0005\n\u0000\u001a\u000c\u0010\u0014\u001a\u00020\u0015*\u00020\u0016H\u0000\"\u0015\u0010\u0000\u001a\u00020\u0001*\u00020\u00028F\u00a2\u0006\u0006\u001a\u0004\u0008\u0003\u0010\u0004\"\u0015\u0010\u0005\u001a\u00020\u0006*\u00020\u00028F\u00a2\u0006\u0006\u001a\u0004\u0008\u0007\u0010\u0008\"\u0019\u0010\t\u001a\u00060\nj\u0002`\u000b*\u00020\u00028F\u00a2\u0006\u0006\u001a\u0004\u0008\u000c\u0010\r\"\u0015\u0010\u000e\u001a\u00020\u000f*\u00020\u00028F\u00a2\u0006\u0006\u001a\u0004\u0008\u000e\u0010\u0010\"\u0015\u0010\u0005\u001a\u00020\u0006*\u00020\u00118F\u00a2\u0006\u0006\u001a\u0004\u0008\u0007\u0010\u0012\"\u0019\u0010\t\u001a\u00060\nj\u0002`\u000b*\u00020\u00118F\u00a2\u0006\u0006\u001a\u0004\u0008\u000c\u0010\u0013\u00a8\u0006\u0017"
    }
    d2 = {
        "transportType",
        "Ltechnology/cariad/cat/genx/TransportType;",
        "Ltechnology/cariad/cat/genx/VehicleAntennaTransport;",
        "getTransportType",
        "(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;)Ltechnology/cariad/cat/genx/TransportType;",
        "antenna",
        "Ltechnology/cariad/cat/genx/Antenna;",
        "getAntenna",
        "(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;)Ltechnology/cariad/cat/genx/Antenna;",
        "vin",
        "",
        "Ltechnology/cariad/cat/genx/VIN;",
        "getVin",
        "(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;)Ljava/lang/String;",
        "isConnectAllowed",
        "",
        "(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;)Z",
        "Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;",
        "(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;)Ltechnology/cariad/cat/genx/Antenna;",
        "(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;)Ljava/lang/String;",
        "toUnsignedInt",
        "",
        "",
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
.method public static final getAntenna(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;)Ltechnology/cariad/cat/genx/Antenna;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;->getIdentifier()Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    move-result-object p0

    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->getAntenna()Ltechnology/cariad/cat/genx/Antenna;

    move-result-object p0

    return-object p0
.end method

.method public static final getAntenna(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;)Ltechnology/cariad/cat/genx/Antenna;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;->getIdentifier()Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    move-result-object p0

    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->getAntenna()Ltechnology/cariad/cat/genx/Antenna;

    move-result-object p0

    return-object p0
.end method

.method public static final getTransportType(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;)Ltechnology/cariad/cat/genx/TransportType;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;->getIdentifier()Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->getAntennaTransportType()Ltechnology/cariad/cat/genx/TransportType;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public static final getVin(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;)Ljava/lang/String;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;->getIdentifier()Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    move-result-object p0

    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->getVin()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static final getVin(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;)Ljava/lang/String;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;->getIdentifier()Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    move-result-object p0

    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->getVin()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static final isConnectAllowed(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;)Z
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;->isConnectable()Lyy0/a2;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-interface {p0}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ljava/lang/Boolean;

    .line 15
    .line 16
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    return p0
.end method

.method public static final toUnsignedInt(B)I
    .locals 0

    .line 1
    if-gez p0, :cond_0

    .line 2
    .line 3
    add-int/lit16 p0, p0, 0x100

    .line 4
    .line 5
    :cond_0
    return p0
.end method
