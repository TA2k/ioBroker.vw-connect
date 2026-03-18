.class final Lio/opentelemetry/instrumentation/api/instrumenter/PropagatingToDownstreamInstrumenter;
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
.field private final propagators:Lio/opentelemetry/context/propagation/ContextPropagators;

.field private final setter:Lio/opentelemetry/context/propagation/TextMapSetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/context/propagation/TextMapSetter<",
            "TREQUEST;>;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;Lio/opentelemetry/context/propagation/TextMapSetter;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;",
            "Lio/opentelemetry/context/propagation/TextMapSetter<",
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
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/instrumenter/PropagatingToDownstreamInstrumenter;->propagators:Lio/opentelemetry/context/propagation/ContextPropagators;

    .line 11
    .line 12
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/instrumenter/PropagatingToDownstreamInstrumenter;->setter:Lio/opentelemetry/context/propagation/TextMapSetter;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public start(Lio/opentelemetry/context/Context;Ljava/lang/Object;)Lio/opentelemetry/context/Context;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/context/Context;",
            "TREQUEST;)",
            "Lio/opentelemetry/context/Context;"
        }
    .end annotation

    .line 1
    invoke-super {p0, p1, p2}, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->start(Lio/opentelemetry/context/Context;Ljava/lang/Object;)Lio/opentelemetry/context/Context;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/PropagatingToDownstreamInstrumenter;->propagators:Lio/opentelemetry/context/propagation/ContextPropagators;

    .line 6
    .line 7
    invoke-interface {v0}, Lio/opentelemetry/context/propagation/ContextPropagators;->getTextMapPropagator()Lio/opentelemetry/context/propagation/TextMapPropagator;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/PropagatingToDownstreamInstrumenter;->setter:Lio/opentelemetry/context/propagation/TextMapSetter;

    .line 12
    .line 13
    invoke-interface {v0, p1, p2, p0}, Lio/opentelemetry/context/propagation/TextMapPropagator;->inject(Lio/opentelemetry/context/Context;Ljava/lang/Object;Lio/opentelemetry/context/propagation/TextMapSetter;)V

    .line 14
    .line 15
    .line 16
    return-object p1
.end method
