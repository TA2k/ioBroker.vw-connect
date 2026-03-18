.class public final Lio/opentelemetry/sdk/common/export/ProxyOptions;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/sdk/common/export/ProxyOptions$SimpleProxySelector;
    }
.end annotation


# instance fields
.field private final proxySelector:Ljava/net/ProxySelector;


# direct methods
.method private constructor <init>(Ljava/net/ProxySelector;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/sdk/common/export/ProxyOptions;->proxySelector:Ljava/net/ProxySelector;

    .line 5
    .line 6
    return-void
.end method

.method public static create(Ljava/net/InetSocketAddress;)Lio/opentelemetry/sdk/common/export/ProxyOptions;
    .locals 4

    .line 2
    new-instance v0, Lio/opentelemetry/sdk/common/export/ProxyOptions;

    new-instance v1, Lio/opentelemetry/sdk/common/export/ProxyOptions$SimpleProxySelector;

    new-instance v2, Ljava/net/Proxy;

    sget-object v3, Ljava/net/Proxy$Type;->HTTP:Ljava/net/Proxy$Type;

    invoke-direct {v2, v3, p0}, Ljava/net/Proxy;-><init>(Ljava/net/Proxy$Type;Ljava/net/SocketAddress;)V

    const/4 p0, 0x0

    invoke-direct {v1, v2, p0}, Lio/opentelemetry/sdk/common/export/ProxyOptions$SimpleProxySelector;-><init>(Ljava/net/Proxy;Lio/opentelemetry/sdk/common/export/ProxyOptions$1;)V

    invoke-direct {v0, v1}, Lio/opentelemetry/sdk/common/export/ProxyOptions;-><init>(Ljava/net/ProxySelector;)V

    return-object v0
.end method

.method public static create(Ljava/net/ProxySelector;)Lio/opentelemetry/sdk/common/export/ProxyOptions;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/common/export/ProxyOptions;

    invoke-direct {v0, p0}, Lio/opentelemetry/sdk/common/export/ProxyOptions;-><init>(Ljava/net/ProxySelector;)V

    return-object v0
.end method


# virtual methods
.method public getProxySelector()Ljava/net/ProxySelector;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/common/export/ProxyOptions;->proxySelector:Ljava/net/ProxySelector;

    .line 2
    .line 3
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "ProxyOptions{proxySelector="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lio/opentelemetry/sdk/common/export/ProxyOptions;->proxySelector:Ljava/net/ProxySelector;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string p0, "}"

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method
