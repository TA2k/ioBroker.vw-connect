.class public final Lio/opentelemetry/instrumentation/api/incubator/instrumenter/internal/InstrumenterCustomizerImpl;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/incubator/instrumenter/InstrumenterCustomizer;


# instance fields
.field private final customizer:Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizer;


# direct methods
.method public constructor <init>(Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizer;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/instrumenter/internal/InstrumenterCustomizerImpl;->customizer:Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizer;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public addAttributesExtractor(Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;)Lio/opentelemetry/instrumentation/api/incubator/instrumenter/InstrumenterCustomizer;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "**>;)",
            "Lio/opentelemetry/instrumentation/api/incubator/instrumenter/InstrumenterCustomizer;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/instrumenter/internal/InstrumenterCustomizerImpl;->customizer:Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizer;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizer;->addAttributesExtractor(Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public addAttributesExtractors(Ljava/lang/Iterable;)Lio/opentelemetry/instrumentation/api/incubator/instrumenter/InstrumenterCustomizer;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Iterable<",
            "+",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "**>;>;)",
            "Lio/opentelemetry/instrumentation/api/incubator/instrumenter/InstrumenterCustomizer;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/instrumenter/internal/InstrumenterCustomizerImpl;->customizer:Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizer;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizer;->addAttributesExtractors(Ljava/lang/Iterable;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public addContextCustomizer(Lio/opentelemetry/instrumentation/api/instrumenter/ContextCustomizer;)Lio/opentelemetry/instrumentation/api/incubator/instrumenter/InstrumenterCustomizer;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/ContextCustomizer<",
            "*>;)",
            "Lio/opentelemetry/instrumentation/api/incubator/instrumenter/InstrumenterCustomizer;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/instrumenter/internal/InstrumenterCustomizerImpl;->customizer:Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizer;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizer;->addContextCustomizer(Lio/opentelemetry/instrumentation/api/instrumenter/ContextCustomizer;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public addOperationMetrics(Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;)Lio/opentelemetry/instrumentation/api/incubator/instrumenter/InstrumenterCustomizer;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/instrumenter/internal/InstrumenterCustomizerImpl;->customizer:Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizer;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizer;->addOperationMetrics(Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public getInstrumentationName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/instrumenter/internal/InstrumenterCustomizerImpl;->customizer:Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizer;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizer;->getInstrumentationName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public setSpanNameExtractor(Ljava/util/function/Function;)Lio/opentelemetry/instrumentation/api/incubator/instrumenter/InstrumenterCustomizer;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Function<",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor<",
            "*>;",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor<",
            "*>;>;)",
            "Lio/opentelemetry/instrumentation/api/incubator/instrumenter/InstrumenterCustomizer;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/instrumenter/internal/InstrumenterCustomizerImpl;->customizer:Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizer;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizer;->setSpanNameExtractor(Ljava/util/function/Function;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method
