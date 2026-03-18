.class public interface abstract Lio/opentelemetry/instrumentation/api/incubator/instrumenter/InstrumenterCustomizer;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public abstract addAttributesExtractor(Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;)Lio/opentelemetry/instrumentation/api/incubator/instrumenter/InstrumenterCustomizer;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "**>;)",
            "Lio/opentelemetry/instrumentation/api/incubator/instrumenter/InstrumenterCustomizer;"
        }
    .end annotation
.end method

.method public abstract addAttributesExtractors(Ljava/lang/Iterable;)Lio/opentelemetry/instrumentation/api/incubator/instrumenter/InstrumenterCustomizer;
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
.end method

.method public abstract addContextCustomizer(Lio/opentelemetry/instrumentation/api/instrumenter/ContextCustomizer;)Lio/opentelemetry/instrumentation/api/incubator/instrumenter/InstrumenterCustomizer;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/ContextCustomizer<",
            "*>;)",
            "Lio/opentelemetry/instrumentation/api/incubator/instrumenter/InstrumenterCustomizer;"
        }
    .end annotation
.end method

.method public abstract addOperationMetrics(Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;)Lio/opentelemetry/instrumentation/api/incubator/instrumenter/InstrumenterCustomizer;
.end method

.method public abstract getInstrumentationName()Ljava/lang/String;
.end method

.method public abstract setSpanNameExtractor(Ljava/util/function/Function;)Lio/opentelemetry/instrumentation/api/incubator/instrumenter/InstrumenterCustomizer;
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
.end method
