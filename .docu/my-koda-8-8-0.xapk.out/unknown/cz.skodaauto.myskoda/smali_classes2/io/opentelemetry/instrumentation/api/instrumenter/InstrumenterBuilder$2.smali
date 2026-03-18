.class Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/internal/InstrumenterBuilderAccess;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
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


# virtual methods
.method public buildDownstreamInstrumenter(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;Lio/opentelemetry/context/propagation/TextMapSetter;Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<RQ:",
            "Ljava/lang/Object;",
            "RS:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TRQ;TRS;>;",
            "Lio/opentelemetry/context/propagation/TextMapSetter<",
            "TRQ;>;",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor<",
            "TRQ;>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter<",
            "TRQ;TRS;>;"
        }
    .end annotation

    .line 1
    invoke-virtual {p1, p2, p3}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->buildDownstreamInstrumenter(Lio/opentelemetry/context/propagation/TextMapSetter;Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public buildUpstreamInstrumenter(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;Lio/opentelemetry/context/propagation/TextMapGetter;Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<RQ:",
            "Ljava/lang/Object;",
            "RS:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TRQ;TRS;>;",
            "Lio/opentelemetry/context/propagation/TextMapGetter<",
            "TRQ;>;",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor<",
            "TRQ;>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter<",
            "TRQ;TRS;>;"
        }
    .end annotation

    .line 1
    invoke-virtual {p1, p2, p3}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->buildUpstreamInstrumenter(Lio/opentelemetry/context/propagation/TextMapGetter;Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public propagateOperationListenersToOnEnd(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<RQ:",
            "Ljava/lang/Object;",
            "RS:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TRQ;TRS;>;)V"
        }
    .end annotation

    .line 1
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->access$000(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method
