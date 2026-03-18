.class public final synthetic Lio/opentelemetry/exporter/otlp/logs/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/BiFunction;


# virtual methods
.method public final apply(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lio/grpc/Channel;

    .line 2
    .line 3
    check-cast p2, Ljava/lang/String;

    .line 4
    .line 5
    invoke-static {p1, p2}, Lio/opentelemetry/exporter/otlp/logs/MarshalerLogsServiceGrpc;->newFutureStub(Lio/grpc/Channel;Ljava/lang/String;)Lio/opentelemetry/exporter/otlp/logs/MarshalerLogsServiceGrpc$LogsServiceFutureStub;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
