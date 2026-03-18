.class public final synthetic Lio/opentelemetry/instrumentation/api/semconv/http/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/ToIntFunction;


# virtual methods
.method public final applyAsInt(Ljava/lang/Object;)I
    .locals 0

    .line 1
    check-cast p1, Lio/opentelemetry/context/Context;

    .line 2
    .line 3
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientRequestResendCount;->getAndIncrement(Lio/opentelemetry/context/Context;)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
