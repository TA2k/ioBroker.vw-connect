.class final Lio/opentelemetry/instrumentation/api/instrumenter/PropagatingFromUpstreamInstrumenter;
.super Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<REQUEST:",
        "Ljava/lang/Object;",
        "RESPONSE:",
        "Ljava/lang/Object;",
        ">",
        "Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter<",
        "TREQUEST;TRESPONSE;>;"
    }
.end annotation


# instance fields
.field private final getter:Lio/opentelemetry/context/propagation/TextMapGetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/context/propagation/TextMapGetter<",
            "TREQUEST;>;"
        }
    .end annotation
.end field

.field private final propagators:Lio/opentelemetry/context/propagation/ContextPropagators;


# direct methods
.method public constructor <init>(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;Lio/opentelemetry/context/propagation/TextMapGetter;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;",
            "Lio/opentelemetry/context/propagation/TextMapGetter<",
            "TREQUEST;>;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1}, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;-><init>(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;)V

    .line 2
    .line 3
    .line 4
    iget-object p1, p1, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->openTelemetry:Lio/opentelemetry/api/OpenTelemetry;

    .line 5
    .line 6
    invoke-interface {p1}, Lio/opentelemetry/api/OpenTelemetry;->getPropagators()Lio/opentelemetry/context/propagation/ContextPropagators;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/instrumenter/PropagatingFromUpstreamInstrumenter;->propagators:Lio/opentelemetry/context/propagation/ContextPropagators;

    .line 11
    .line 12
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/instrumenter/PropagatingFromUpstreamInstrumenter;->getter:Lio/opentelemetry/context/propagation/TextMapGetter;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public start(Lio/opentelemetry/context/Context;Ljava/lang/Object;)Lio/opentelemetry/context/Context;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/context/Context;",
            "TREQUEST;)",
            "Lio/opentelemetry/context/Context;"
        }
    .end annotation

    .line 1
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;->debugContextLeakIfEnabled()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/PropagatingFromUpstreamInstrumenter;->propagators:Lio/opentelemetry/context/propagation/ContextPropagators;

    .line 5
    .line 6
    invoke-interface {v0}, Lio/opentelemetry/context/propagation/ContextPropagators;->getTextMapPropagator()Lio/opentelemetry/context/propagation/TextMapPropagator;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/instrumenter/PropagatingFromUpstreamInstrumenter;->getter:Lio/opentelemetry/context/propagation/TextMapGetter;

    .line 11
    .line 12
    invoke-interface {v0, p1, p2, v1}, Lio/opentelemetry/context/propagation/TextMapPropagator;->extract(Lio/opentelemetry/context/Context;Ljava/lang/Object;Lio/opentelemetry/context/propagation/TextMapGetter;)Lio/opentelemetry/context/Context;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    invoke-super {p0, p1, p2}, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->start(Lio/opentelemetry/context/Context;Ljava/lang/Object;)Lio/opentelemetry/context/Context;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method
