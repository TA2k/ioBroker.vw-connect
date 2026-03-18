.class abstract Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl$ServiceMatcher;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x409
    name = "ServiceMatcher"
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static create(Ljava/lang/Integer;Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl$ServiceMatcher;
    .locals 1
    .param p0    # Ljava/lang/Integer;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p1    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/AutoValue_PeerServiceResolverImpl_ServiceMatcher;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/AutoValue_PeerServiceResolverImpl_ServiceMatcher;-><init>(Ljava/lang/Integer;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method


# virtual methods
.method public abstract getPath()Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method

.method public abstract getPort()Ljava/lang/Integer;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method

.method public matches(Ljava/lang/Integer;Ljava/util/function/Supplier;)Z
    .locals 2
    .param p1    # Ljava/lang/Integer;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Integer;",
            "Ljava/util/function/Supplier<",
            "Ljava/lang/String;",
            ">;)Z"
        }
    .end annotation

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl$ServiceMatcher;->getPort()Ljava/lang/Integer;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl$ServiceMatcher;->getPort()Ljava/lang/Integer;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-virtual {v0, p1}, Ljava/lang/Integer;->equals(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-nez v0, :cond_0

    .line 17
    .line 18
    return v1

    .line 19
    :cond_0
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl$ServiceMatcher;->getPath()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    if-eqz v0, :cond_3

    .line 24
    .line 25
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl$ServiceMatcher;->getPath()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-lez v0, :cond_3

    .line 34
    .line 35
    invoke-interface {p2}, Ljava/util/function/Supplier;->get()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p2

    .line 39
    check-cast p2, Ljava/lang/String;

    .line 40
    .line 41
    if-nez p2, :cond_1

    .line 42
    .line 43
    return v1

    .line 44
    :cond_1
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl$ServiceMatcher;->getPath()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    invoke-virtual {p2, v0}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 49
    .line 50
    .line 51
    move-result p2

    .line 52
    if-nez p2, :cond_2

    .line 53
    .line 54
    return v1

    .line 55
    :cond_2
    if-eqz p1, :cond_3

    .line 56
    .line 57
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl$ServiceMatcher;->getPort()Ljava/lang/Integer;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    invoke-virtual {p1, p0}, Ljava/lang/Integer;->equals(Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    return p0

    .line 66
    :cond_3
    const/4 p0, 0x1

    .line 67
    return p0
.end method
