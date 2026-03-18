.class public interface abstract Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolver;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static create(Ljava/util/Map;)Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolver;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolver;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl;-><init>(Ljava/util/Map;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method


# virtual methods
.method public abstract isEmpty()Z
.end method

.method public abstract resolveService(Ljava/lang/String;Ljava/lang/Integer;Ljava/util/function/Supplier;)Ljava/lang/String;
    .param p2    # Ljava/lang/Integer;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/Integer;",
            "Ljava/util/function/Supplier<",
            "Ljava/lang/String;",
            ">;)",
            "Ljava/lang/String;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method
