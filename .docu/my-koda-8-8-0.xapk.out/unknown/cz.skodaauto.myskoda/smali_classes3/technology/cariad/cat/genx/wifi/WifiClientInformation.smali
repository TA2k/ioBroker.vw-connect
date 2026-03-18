.class public final Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00000\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0012\n\u0002\u0008\u000b\n\u0002\u0010\u000b\n\u0002\u0008\t\u0008\u0080\u0008\u0018\u00002\u00020\u0001B+\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\n\u0010\u0006\u001a\u00060\u0007j\u0002`\u0008\u0012\u0006\u0010\t\u001a\u00020\n\u00a2\u0006\u0004\u0008\u000b\u0010\u000cJ\u0013\u0010\u0015\u001a\u00020\u00162\u0008\u0010\u0017\u001a\u0004\u0018\u00010\u0001H\u0096\u0002J\u0008\u0010\u0018\u001a\u00020\u0005H\u0016J\t\u0010\u0019\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u001a\u001a\u00020\u0005H\u00c6\u0003J\r\u0010\u001b\u001a\u00060\u0007j\u0002`\u0008H\u00c6\u0003J\t\u0010\u001c\u001a\u00020\nH\u00c6\u0003J5\u0010\u001d\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u00052\u000c\u0008\u0002\u0010\u0006\u001a\u00060\u0007j\u0002`\u00082\u0008\u0008\u0002\u0010\t\u001a\u00020\nH\u00c6\u0001J\t\u0010\u001e\u001a\u00020\u0007H\u00d6\u0001R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\r\u0010\u000eR\u0011\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000f\u0010\u0010R\u0015\u0010\u0006\u001a\u00060\u0007j\u0002`\u0008\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0011\u0010\u0012R\u0011\u0010\t\u001a\u00020\n\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0013\u0010\u0014\u00a8\u0006\u001f"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;",
        "",
        "address",
        "Ljava/net/InetAddress;",
        "port",
        "",
        "vin",
        "",
        "Ltechnology/cariad/cat/genx/VIN;",
        "advertisement",
        "",
        "<init>",
        "(Ljava/net/InetAddress;ILjava/lang/String;[B)V",
        "getAddress",
        "()Ljava/net/InetAddress;",
        "getPort",
        "()I",
        "getVin",
        "()Ljava/lang/String;",
        "getAdvertisement",
        "()[B",
        "equals",
        "",
        "other",
        "hashCode",
        "component1",
        "component2",
        "component3",
        "component4",
        "copy",
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
.field private final address:Ljava/net/InetAddress;

.field private final advertisement:[B

.field private final port:I

.field private final vin:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/net/InetAddress;ILjava/lang/String;[B)V
    .locals 1

    .line 1
    const-string v0, "address"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "vin"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "advertisement"

    .line 12
    .line 13
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->address:Ljava/net/InetAddress;

    .line 20
    .line 21
    iput p2, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->port:I

    .line 22
    .line 23
    iput-object p3, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->vin:Ljava/lang/String;

    .line 24
    .line 25
    iput-object p4, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->advertisement:[B

    .line 26
    .line 27
    return-void
.end method

.method public static synthetic copy$default(Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;Ljava/net/InetAddress;ILjava/lang/String;[BILjava/lang/Object;)Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;
    .locals 0

    .line 1
    and-int/lit8 p6, p5, 0x1

    .line 2
    .line 3
    if-eqz p6, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->address:Ljava/net/InetAddress;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p6, p5, 0x2

    .line 8
    .line 9
    if-eqz p6, :cond_1

    .line 10
    .line 11
    iget p2, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->port:I

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p6, p5, 0x4

    .line 14
    .line 15
    if-eqz p6, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->vin:Ljava/lang/String;

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p5, p5, 0x8

    .line 20
    .line 21
    if-eqz p5, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->advertisement:[B

    .line 24
    .line 25
    :cond_3
    invoke-virtual {p0, p1, p2, p3, p4}, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->copy(Ljava/net/InetAddress;ILjava/lang/String;[B)Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method


# virtual methods
.method public final component1()Ljava/net/InetAddress;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->address:Ljava/net/InetAddress;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->port:I

    .line 2
    .line 3
    return p0
.end method

.method public final component3()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->vin:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()[B
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->advertisement:[B

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/net/InetAddress;ILjava/lang/String;[B)Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;
    .locals 0

    .line 1
    const-string p0, "address"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "vin"

    .line 7
    .line 8
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p0, "advertisement"

    .line 12
    .line 13
    invoke-static {p4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    new-instance p0, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;

    .line 17
    .line 18
    invoke-direct {p0, p1, p2, p3, p4}, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;-><init>(Ljava/net/InetAddress;ILjava/lang/String;[B)V

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
    if-eqz p1, :cond_1

    .line 6
    .line 7
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    goto :goto_0

    .line 12
    :cond_1
    const/4 v1, 0x0

    .line 13
    :goto_0
    const-class v2, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;

    .line 14
    .line 15
    invoke-virtual {v2, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    const/4 v2, 0x0

    .line 20
    if-nez v1, :cond_2

    .line 21
    .line 22
    return v2

    .line 23
    :cond_2
    const-string v1, "null cannot be cast to non-null type technology.cariad.cat.genx.wifi.WifiClientInformation"

    .line 24
    .line 25
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    check-cast p1, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;

    .line 29
    .line 30
    iget v1, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->port:I

    .line 31
    .line 32
    iget v3, p1, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->port:I

    .line 33
    .line 34
    if-eq v1, v3, :cond_3

    .line 35
    .line 36
    return v2

    .line 37
    :cond_3
    iget-object v1, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->address:Ljava/net/InetAddress;

    .line 38
    .line 39
    iget-object v3, p1, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->address:Ljava/net/InetAddress;

    .line 40
    .line 41
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    if-nez v1, :cond_4

    .line 46
    .line 47
    return v2

    .line 48
    :cond_4
    iget-object v1, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->vin:Ljava/lang/String;

    .line 49
    .line 50
    iget-object v3, p1, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->vin:Ljava/lang/String;

    .line 51
    .line 52
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-nez v1, :cond_5

    .line 57
    .line 58
    return v2

    .line 59
    :cond_5
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->advertisement:[B

    .line 60
    .line 61
    iget-object p1, p1, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->advertisement:[B

    .line 62
    .line 63
    invoke-static {p0, p1}, Ljava/util/Arrays;->equals([B[B)Z

    .line 64
    .line 65
    .line 66
    move-result p0

    .line 67
    if-nez p0, :cond_6

    .line 68
    .line 69
    return v2

    .line 70
    :cond_6
    return v0
.end method

.method public final getAddress()Ljava/net/InetAddress;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->address:Ljava/net/InetAddress;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getAdvertisement()[B
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->advertisement:[B

    .line 2
    .line 3
    return-object p0
.end method

.method public final getPort()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->port:I

    .line 2
    .line 3
    return p0
.end method

.method public final getVin()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->vin:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->port:I

    .line 2
    .line 3
    const/16 v1, 0x1f

    .line 4
    .line 5
    mul-int/2addr v0, v1

    .line 6
    iget-object v2, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->address:Ljava/net/InetAddress;

    .line 7
    .line 8
    invoke-virtual {v2}, Ljava/net/InetAddress;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    add-int/2addr v2, v0

    .line 13
    mul-int/2addr v2, v1

    .line 14
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->vin:Ljava/lang/String;

    .line 15
    .line 16
    invoke-static {v2, v1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->advertisement:[B

    .line 21
    .line 22
    invoke-static {p0}, Ljava/util/Arrays;->hashCode([B)I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    add-int/2addr p0, v0

    .line 27
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->address:Ljava/net/InetAddress;

    .line 2
    .line 3
    iget v1, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->port:I

    .line 4
    .line 5
    iget-object v2, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->vin:Ljava/lang/String;

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->advertisement:[B

    .line 8
    .line 9
    invoke-static {p0}, Ljava/util/Arrays;->toString([B)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    new-instance v3, Ljava/lang/StringBuilder;

    .line 14
    .line 15
    const-string v4, "WifiClientInformation(address="

    .line 16
    .line 17
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v0, ", port="

    .line 24
    .line 25
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v0, ", vin="

    .line 32
    .line 33
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    const-string v0, ", advertisement="

    .line 37
    .line 38
    const-string v1, ")"

    .line 39
    .line 40
    invoke-static {v3, v2, v0, p0, v1}, Lvj/b;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    return-object p0
.end method
