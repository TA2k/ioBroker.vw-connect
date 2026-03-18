.class public final Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/VehicleAntennaTransport;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Identifier"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\r\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u00002\u00020\u0001B#\u0012\n\u0010\u0002\u001a\u00060\u0003j\u0002`\u0004\u0012\u0006\u0010\u0005\u001a\u00020\u0006\u0012\u0006\u0010\u0007\u001a\u00020\u0008\u00a2\u0006\u0004\u0008\t\u0010\nJ\r\u0010\u0011\u001a\u00060\u0003j\u0002`\u0004H\u00c6\u0003J\t\u0010\u0012\u001a\u00020\u0006H\u00c6\u0003J\t\u0010\u0013\u001a\u00020\u0008H\u00c6\u0003J+\u0010\u0014\u001a\u00020\u00002\u000c\u0008\u0002\u0010\u0002\u001a\u00060\u0003j\u0002`\u00042\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u00062\u0008\u0008\u0002\u0010\u0007\u001a\u00020\u0008H\u00c6\u0001J\u0013\u0010\u0015\u001a\u00020\u00162\u0008\u0010\u0017\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u0018\u001a\u00020\u0019H\u00d6\u0001J\t\u0010\u001a\u001a\u00020\u0003H\u00d6\u0001R\u0015\u0010\u0002\u001a\u00060\u0003j\u0002`\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000b\u0010\u000cR\u0011\u0010\u0005\u001a\u00020\u0006\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\r\u0010\u000eR\u0011\u0010\u0007\u001a\u00020\u0008\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000f\u0010\u0010\u00a8\u0006\u001b"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;",
        "",
        "vin",
        "",
        "Ltechnology/cariad/cat/genx/VIN;",
        "antenna",
        "Ltechnology/cariad/cat/genx/Antenna;",
        "antennaTransportType",
        "Ltechnology/cariad/cat/genx/TransportType;",
        "<init>",
        "(Ljava/lang/String;Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/TransportType;)V",
        "getVin",
        "()Ljava/lang/String;",
        "getAntenna",
        "()Ltechnology/cariad/cat/genx/Antenna;",
        "getAntennaTransportType",
        "()Ltechnology/cariad/cat/genx/TransportType;",
        "component1",
        "component2",
        "component3",
        "copy",
        "equals",
        "",
        "other",
        "hashCode",
        "",
        "toString",
        "genx_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field private final antenna:Ltechnology/cariad/cat/genx/Antenna;

.field private final antennaTransportType:Ltechnology/cariad/cat/genx/TransportType;

.field private final vin:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/TransportType;)V
    .locals 1

    .line 1
    const-string v0, "vin"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "antenna"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "antennaTransportType"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->vin:Ljava/lang/String;

    .line 20
    .line 21
    iput-object p2, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->antenna:Ltechnology/cariad/cat/genx/Antenna;

    .line 22
    .line 23
    iput-object p3, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->antennaTransportType:Ltechnology/cariad/cat/genx/TransportType;

    .line 24
    .line 25
    return-void
.end method

.method public static synthetic copy$default(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;Ljava/lang/String;Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/TransportType;ILjava/lang/Object;)Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;
    .locals 0

    .line 1
    and-int/lit8 p5, p4, 0x1

    .line 2
    .line 3
    if-eqz p5, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->vin:Ljava/lang/String;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p5, p4, 0x2

    .line 8
    .line 9
    if-eqz p5, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->antenna:Ltechnology/cariad/cat/genx/Antenna;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p4, p4, 0x4

    .line 14
    .line 15
    if-eqz p4, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->antennaTransportType:Ltechnology/cariad/cat/genx/TransportType;

    .line 18
    .line 19
    :cond_2
    invoke-virtual {p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->copy(Ljava/lang/String;Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/TransportType;)Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method


# virtual methods
.method public final component1()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->vin:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Ltechnology/cariad/cat/genx/Antenna;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->antenna:Ltechnology/cariad/cat/genx/Antenna;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Ltechnology/cariad/cat/genx/TransportType;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->antennaTransportType:Ltechnology/cariad/cat/genx/TransportType;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/lang/String;Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/TransportType;)Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;
    .locals 0

    .line 1
    const-string p0, "vin"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "antenna"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p0, "antennaTransportType"

    .line 12
    .line 13
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    new-instance p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 17
    .line 18
    invoke-direct {p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;-><init>(Ljava/lang/String;Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/TransportType;)V

    .line 19
    .line 20
    .line 21
    return-object p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 12
    .line 13
    iget-object v1, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->vin:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->vin:Ljava/lang/String;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object v1, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->antenna:Ltechnology/cariad/cat/genx/Antenna;

    .line 25
    .line 26
    iget-object v3, p1, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->antenna:Ltechnology/cariad/cat/genx/Antenna;

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->antennaTransportType:Ltechnology/cariad/cat/genx/TransportType;

    .line 32
    .line 33
    iget-object p1, p1, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->antennaTransportType:Ltechnology/cariad/cat/genx/TransportType;

    .line 34
    .line 35
    if-eq p0, p1, :cond_4

    .line 36
    .line 37
    return v2

    .line 38
    :cond_4
    return v0
.end method

.method public final getAntenna()Ltechnology/cariad/cat/genx/Antenna;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->antenna:Ltechnology/cariad/cat/genx/Antenna;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getAntennaTransportType()Ltechnology/cariad/cat/genx/TransportType;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->antennaTransportType:Ltechnology/cariad/cat/genx/TransportType;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getVin()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->vin:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->vin:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object v1, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->antenna:Ltechnology/cariad/cat/genx/Antenna;

    .line 10
    .line 11
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    add-int/2addr v1, v0

    .line 16
    mul-int/lit8 v1, v1, 0x1f

    .line 17
    .line 18
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->antennaTransportType:Ltechnology/cariad/cat/genx/TransportType;

    .line 19
    .line 20
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    add-int/2addr p0, v1

    .line 25
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 4

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->vin:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->antenna:Ltechnology/cariad/cat/genx/Antenna;

    .line 4
    .line 5
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;->antennaTransportType:Ltechnology/cariad/cat/genx/TransportType;

    .line 6
    .line 7
    new-instance v2, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v3, "Identifier(vin="

    .line 10
    .line 11
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string v0, ", antenna="

    .line 18
    .line 19
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string v0, ", antennaTransportType="

    .line 26
    .line 27
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string p0, ")"

    .line 34
    .line 35
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0
.end method
