.class Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizer;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->applyCustomizers(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizer<",
        "TREQUEST;TRESPONSE;>;"
    }
.end annotation


# instance fields
.field final synthetic val$builder:Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;


# direct methods
.method public constructor <init>(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$1;->val$builder:Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public addAttributesExtractor(Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "TREQUEST;TRESPONSE;>;)V"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$1;->val$builder:Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->addAttributesExtractor(Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public addAttributesExtractors(Ljava/lang/Iterable;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Iterable<",
            "+",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "TREQUEST;TRESPONSE;>;>;)V"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$1;->val$builder:Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->addAttributesExtractors(Ljava/lang/Iterable;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public addContextCustomizer(Lio/opentelemetry/instrumentation/api/instrumenter/ContextCustomizer;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/ContextCustomizer<",
            "TREQUEST;>;)V"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$1;->val$builder:Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->addContextCustomizer(Lio/opentelemetry/instrumentation/api/instrumenter/ContextCustomizer;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public addOperationMetrics(Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$1;->val$builder:Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->addOperationMetrics(Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public getInstrumentationName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$1;->val$builder:Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 2
    .line 3
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->instrumentationName:Ljava/lang/String;

    .line 4
    .line 5
    return-object p0
.end method

.method public setSpanNameExtractor(Ljava/util/function/Function;)V
    .locals 1
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

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$1;->val$builder:Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 2
    .line 3
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->spanNameExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;

    .line 4
    .line 5
    invoke-interface {p1, v0}, Ljava/util/function/Function;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    check-cast p1, Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;

    .line 10
    .line 11
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->spanNameExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;

    .line 12
    .line 13
    return-void
.end method
