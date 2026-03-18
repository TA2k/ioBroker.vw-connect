.class public final synthetic Lio/opentelemetry/instrumentation/api/incubator/semconv/net/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Comparator;


# virtual methods
.method public final compare(Ljava/lang/Object;Ljava/lang/Object;)I
    .locals 0

    .line 1
    check-cast p1, Ljava/util/Map$Entry;

    .line 2
    .line 3
    check-cast p2, Ljava/util/Map$Entry;

    .line 4
    .line 5
    invoke-static {p1, p2}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl;->d(Ljava/util/Map$Entry;Ljava/util/Map$Entry;)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method
