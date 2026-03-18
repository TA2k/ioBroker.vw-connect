.class public interface abstract Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizer;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<REQUEST:",
        "Ljava/lang/Object;",
        "RESPONSE:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation


# virtual methods
.method public abstract addAttributesExtractor(Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;)V
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "TREQUEST;TRESPONSE;>;)V"
        }
    .end annotation
.end method

.method public abstract addAttributesExtractors(Ljava/lang/Iterable;)V
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Iterable<",
            "+",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "TREQUEST;TRESPONSE;>;>;)V"
        }
    .end annotation
.end method

.method public abstract addContextCustomizer(Lio/opentelemetry/instrumentation/api/instrumenter/ContextCustomizer;)V
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/ContextCustomizer<",
            "TREQUEST;>;)V"
        }
    .end annotation
.end method

.method public abstract addOperationMetrics(Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;)V
.end method

.method public abstract getInstrumentationName()Ljava/lang/String;
.end method

.method public abstract setSpanNameExtractor(Ljava/util/function/Function;)V
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Function<",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor<",
            "-TREQUEST;>;",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor<",
            "-TREQUEST;>;>;)V"
        }
    .end annotation
.end method
