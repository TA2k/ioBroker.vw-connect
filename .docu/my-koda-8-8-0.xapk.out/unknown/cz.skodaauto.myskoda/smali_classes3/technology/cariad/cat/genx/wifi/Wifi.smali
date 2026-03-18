.class public final Ltechnology/cariad/cat/genx/wifi/Wifi;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000*\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\n\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0007\u0008\u0086\u0008\u0018\u00002\u00020\u0001B)\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u0012\u0006\u0010\u0005\u001a\u00020\u0006\u0012\u0008\u0010\u0007\u001a\u0004\u0018\u00010\u0003\u00a2\u0006\u0004\u0008\u0008\u0010\tJ\u0013\u0010\u0010\u001a\u00020\u00112\u0008\u0010\u0012\u001a\u0004\u0018\u00010\u0001H\u0096\u0002J\u0008\u0010\u0013\u001a\u00020\u0014H\u0016J\u0008\u0010\u0015\u001a\u00020\u0003H\u0016J\t\u0010\u0016\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0017\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0018\u001a\u00020\u0006H\u00c6\u0003J\u000b\u0010\u0019\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J3\u0010\u001a\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u00062\n\u0008\u0002\u0010\u0007\u001a\u0004\u0018\u00010\u0003H\u00c6\u0001R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\n\u0010\u000bR\u0011\u0010\u0004\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000c\u0010\u000bR\u0011\u0010\u0005\u001a\u00020\u0006\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\r\u0010\u000eR\u0013\u0010\u0007\u001a\u0004\u0018\u00010\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000f\u0010\u000b\u00a8\u0006\u001b"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/wifi/Wifi;",
        "",
        "ssid",
        "",
        "bssid",
        "ipAddress",
        "Ljava/net/Inet4Address;",
        "dnsSearchDomain",
        "<init>",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/net/Inet4Address;Ljava/lang/String;)V",
        "getSsid",
        "()Ljava/lang/String;",
        "getBssid",
        "getIpAddress",
        "()Ljava/net/Inet4Address;",
        "getDnsSearchDomain",
        "equals",
        "",
        "other",
        "hashCode",
        "",
        "toString",
        "component1",
        "component2",
        "component3",
        "component4",
        "copy",
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
.field private final bssid:Ljava/lang/String;

.field private final dnsSearchDomain:Ljava/lang/String;

.field private final ipAddress:Ljava/net/Inet4Address;

.field private final ssid:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/net/Inet4Address;Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "ssid"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "bssid"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "ipAddress"

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
    iput-object p1, p0, Ltechnology/cariad/cat/genx/wifi/Wifi;->ssid:Ljava/lang/String;

    .line 20
    .line 21
    iput-object p2, p0, Ltechnology/cariad/cat/genx/wifi/Wifi;->bssid:Ljava/lang/String;

    .line 22
    .line 23
    iput-object p3, p0, Ltechnology/cariad/cat/genx/wifi/Wifi;->ipAddress:Ljava/net/Inet4Address;

    .line 24
    .line 25
    iput-object p4, p0, Ltechnology/cariad/cat/genx/wifi/Wifi;->dnsSearchDomain:Ljava/lang/String;

    .line 26
    .line 27
    return-void
.end method

.method public static synthetic copy$default(Ltechnology/cariad/cat/genx/wifi/Wifi;Ljava/lang/String;Ljava/lang/String;Ljava/net/Inet4Address;Ljava/lang/String;ILjava/lang/Object;)Ltechnology/cariad/cat/genx/wifi/Wifi;
    .locals 0

    .line 1
    and-int/lit8 p6, p5, 0x1

    .line 2
    .line 3
    if-eqz p6, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Ltechnology/cariad/cat/genx/wifi/Wifi;->ssid:Ljava/lang/String;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p6, p5, 0x2

    .line 8
    .line 9
    if-eqz p6, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Ltechnology/cariad/cat/genx/wifi/Wifi;->bssid:Ljava/lang/String;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p6, p5, 0x4

    .line 14
    .line 15
    if-eqz p6, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Ltechnology/cariad/cat/genx/wifi/Wifi;->ipAddress:Ljava/net/Inet4Address;

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p5, p5, 0x8

    .line 20
    .line 21
    if-eqz p5, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Ltechnology/cariad/cat/genx/wifi/Wifi;->dnsSearchDomain:Ljava/lang/String;

    .line 24
    .line 25
    :cond_3
    invoke-virtual {p0, p1, p2, p3, p4}, Ltechnology/cariad/cat/genx/wifi/Wifi;->copy(Ljava/lang/String;Ljava/lang/String;Ljava/net/Inet4Address;Ljava/lang/String;)Ltechnology/cariad/cat/genx/wifi/Wifi;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method


# virtual methods
.method public final component1()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/Wifi;->ssid:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/Wifi;->bssid:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Ljava/net/Inet4Address;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/Wifi;->ipAddress:Ljava/net/Inet4Address;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/Wifi;->dnsSearchDomain:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/lang/String;Ljava/lang/String;Ljava/net/Inet4Address;Ljava/lang/String;)Ltechnology/cariad/cat/genx/wifi/Wifi;
    .locals 0

    .line 1
    const-string p0, "ssid"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "bssid"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p0, "ipAddress"

    .line 12
    .line 13
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    new-instance p0, Ltechnology/cariad/cat/genx/wifi/Wifi;

    .line 17
    .line 18
    invoke-direct {p0, p1, p2, p3, p4}, Ltechnology/cariad/cat/genx/wifi/Wifi;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/net/Inet4Address;Ljava/lang/String;)V

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
    const-class v2, Ltechnology/cariad/cat/genx/wifi/Wifi;

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
    const-string v1, "null cannot be cast to non-null type technology.cariad.cat.genx.wifi.Wifi"

    .line 24
    .line 25
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    check-cast p1, Ltechnology/cariad/cat/genx/wifi/Wifi;

    .line 29
    .line 30
    iget-object v1, p0, Ltechnology/cariad/cat/genx/wifi/Wifi;->ssid:Ljava/lang/String;

    .line 31
    .line 32
    iget-object v3, p1, Ltechnology/cariad/cat/genx/wifi/Wifi;->ssid:Ljava/lang/String;

    .line 33
    .line 34
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-nez v1, :cond_3

    .line 39
    .line 40
    return v2

    .line 41
    :cond_3
    iget-object v1, p0, Ltechnology/cariad/cat/genx/wifi/Wifi;->ipAddress:Ljava/net/Inet4Address;

    .line 42
    .line 43
    iget-object v3, p1, Ltechnology/cariad/cat/genx/wifi/Wifi;->ipAddress:Ljava/net/Inet4Address;

    .line 44
    .line 45
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    if-nez v1, :cond_4

    .line 50
    .line 51
    return v2

    .line 52
    :cond_4
    iget-object v1, p0, Ltechnology/cariad/cat/genx/wifi/Wifi;->dnsSearchDomain:Ljava/lang/String;

    .line 53
    .line 54
    iget-object v3, p1, Ltechnology/cariad/cat/genx/wifi/Wifi;->dnsSearchDomain:Ljava/lang/String;

    .line 55
    .line 56
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    if-nez v1, :cond_5

    .line 61
    .line 62
    return v2

    .line 63
    :cond_5
    iget-object v1, p0, Ltechnology/cariad/cat/genx/wifi/Wifi;->bssid:Ljava/lang/String;

    .line 64
    .line 65
    iget-object v3, p1, Ltechnology/cariad/cat/genx/wifi/Wifi;->bssid:Ljava/lang/String;

    .line 66
    .line 67
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-nez v1, :cond_6

    .line 72
    .line 73
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/Wifi;->bssid:Ljava/lang/String;

    .line 74
    .line 75
    const-string v1, "02:00:00:00:00:00"

    .line 76
    .line 77
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result p0

    .line 81
    if-nez p0, :cond_6

    .line 82
    .line 83
    iget-object p0, p1, Ltechnology/cariad/cat/genx/wifi/Wifi;->bssid:Ljava/lang/String;

    .line 84
    .line 85
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result p0

    .line 89
    if-nez p0, :cond_6

    .line 90
    .line 91
    return v2

    .line 92
    :cond_6
    return v0
.end method

.method public final getBssid()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/Wifi;->bssid:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getDnsSearchDomain()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/Wifi;->dnsSearchDomain:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getIpAddress()Ljava/net/Inet4Address;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/Wifi;->ipAddress:Ljava/net/Inet4Address;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getSsid()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/Wifi;->ssid:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/Wifi;->ssid:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-object v2, p0, Ltechnology/cariad/cat/genx/wifi/Wifi;->bssid:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Ltechnology/cariad/cat/genx/wifi/Wifi;->ipAddress:Ljava/net/Inet4Address;

    .line 17
    .line 18
    invoke-virtual {v2}, Ljava/net/Inet4Address;->hashCode()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v0

    .line 23
    mul-int/2addr v2, v1

    .line 24
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/Wifi;->dnsSearchDomain:Ljava/lang/String;

    .line 25
    .line 26
    if-eqz p0, :cond_0

    .line 27
    .line 28
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    goto :goto_0

    .line 33
    :cond_0
    const/4 p0, 0x0

    .line 34
    :goto_0
    add-int/2addr v2, p0

    .line 35
    return v2
.end method

.method public toString()Ljava/lang/String;
    .locals 6

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/Wifi;->ssid:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p0, Ltechnology/cariad/cat/genx/wifi/Wifi;->bssid:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, p0, Ltechnology/cariad/cat/genx/wifi/Wifi;->ipAddress:Ljava/net/Inet4Address;

    .line 6
    .line 7
    invoke-virtual {v2}, Ljava/net/Inet4Address;->getHostAddress()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/Wifi;->dnsSearchDomain:Ljava/lang/String;

    .line 12
    .line 13
    const-string v3, "\', bssid=\'"

    .line 14
    .line 15
    const-string v4, "\', ipAddress="

    .line 16
    .line 17
    const-string v5, "Wifi(ssid=\'"

    .line 18
    .line 19
    invoke-static {v5, v0, v3, v1, v4}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    const-string v1, ", dnsSearchDomain="

    .line 24
    .line 25
    const-string v3, ")"

    .line 26
    .line 27
    invoke-static {v0, v2, v1, p0, v3}, Lvj/b;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0
.end method
