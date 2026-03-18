.class public final synthetic Lio/opentelemetry/instrumentation/api/instrumenter/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/BiConsumer;


# virtual methods
.method public final accept(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p1, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 2
    .line 3
    check-cast p2, Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;

    .line 4
    .line 5
    invoke-static {p1, p2}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->a(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
