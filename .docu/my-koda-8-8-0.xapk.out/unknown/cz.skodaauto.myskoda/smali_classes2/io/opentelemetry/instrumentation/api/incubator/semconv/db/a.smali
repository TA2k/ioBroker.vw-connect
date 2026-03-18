.class public final synthetic Lio/opentelemetry/instrumentation/api/incubator/semconv/db/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;


# virtual methods
.method public final create(Lio/opentelemetry/api/metrics/Meter;)Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;
    .locals 0

    .line 1
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientMetrics;->a(Lio/opentelemetry/api/metrics/Meter;)Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
