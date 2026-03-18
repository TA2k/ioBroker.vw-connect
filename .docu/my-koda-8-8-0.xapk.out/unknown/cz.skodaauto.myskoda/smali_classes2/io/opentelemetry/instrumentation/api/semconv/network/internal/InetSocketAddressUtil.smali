.class public final Lio/opentelemetry/instrumentation/api/semconv/network/internal/InetSocketAddressUtil;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static getIpAddress(Ljava/net/InetSocketAddress;)Ljava/lang/String;
    .locals 1
    .param p0    # Ljava/net/InetSocketAddress;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    const/4 v0, 0x0

    .line 2
    if-nez p0, :cond_0

    .line 3
    .line 4
    return-object v0

    .line 5
    :cond_0
    invoke-virtual {p0}, Ljava/net/InetSocketAddress;->getAddress()Ljava/net/InetAddress;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    if-nez p0, :cond_1

    .line 10
    .line 11
    return-object v0

    .line 12
    :cond_1
    invoke-virtual {p0}, Ljava/net/InetAddress;->getHostAddress()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method

.method public static getNetworkType(Ljava/net/InetSocketAddress;Ljava/net/InetSocketAddress;)Ljava/lang/String;
    .locals 1
    .param p0    # Ljava/net/InetSocketAddress;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p1    # Ljava/net/InetSocketAddress;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    move-object p0, p1

    .line 4
    :cond_0
    const/4 p1, 0x0

    .line 5
    if-nez p0, :cond_1

    .line 6
    .line 7
    return-object p1

    .line 8
    :cond_1
    invoke-virtual {p0}, Ljava/net/InetSocketAddress;->getAddress()Ljava/net/InetAddress;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    instance-of v0, p0, Ljava/net/Inet4Address;

    .line 13
    .line 14
    if-eqz v0, :cond_2

    .line 15
    .line 16
    const-string p0, "ipv4"

    .line 17
    .line 18
    return-object p0

    .line 19
    :cond_2
    instance-of p0, p0, Ljava/net/Inet6Address;

    .line 20
    .line 21
    if-eqz p0, :cond_3

    .line 22
    .line 23
    const-string p0, "ipv6"

    .line 24
    .line 25
    return-object p0

    .line 26
    :cond_3
    return-object p1
.end method

.method public static getPort(Ljava/net/InetSocketAddress;)Ljava/lang/Integer;
    .locals 0
    .param p0    # Ljava/net/InetSocketAddress;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return-object p0

    .line 5
    :cond_0
    invoke-virtual {p0}, Ljava/net/InetSocketAddress;->getPort()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method
