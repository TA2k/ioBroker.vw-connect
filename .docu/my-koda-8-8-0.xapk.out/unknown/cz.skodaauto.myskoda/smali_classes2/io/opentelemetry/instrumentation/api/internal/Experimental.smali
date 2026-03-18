.class public final Lio/opentelemetry/instrumentation/api/internal/Experimental;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static volatile operationListenerAttributesExtractorAdder:Ljava/util/function/BiConsumer;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/BiConsumer<",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "**>;",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "**>;>;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private static volatile redactHttpClientQueryParameters:Ljava/util/function/BiConsumer;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/BiConsumer<",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder<",
            "**>;",
            "Ljava/lang/Boolean;",
            ">;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private static volatile urlTemplateExtractorSetter:Ljava/util/function/BiConsumer;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/BiConsumer<",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder<",
            "*>;",
            "Ljava/util/function/Function<",
            "*",
            "Ljava/lang/String;",
            ">;>;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static addOperationListenerAttributesExtractor(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            "RESPONSE:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "-TREQUEST;-TRESPONSE;>;)V"
        }
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/Experimental;->operationListenerAttributesExtractorAdder:Ljava/util/function/BiConsumer;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/Experimental;->operationListenerAttributesExtractorAdder:Ljava/util/function/BiConsumer;

    .line 6
    .line 7
    invoke-interface {v0, p0, p1}, Ljava/util/function/BiConsumer;->accept(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    return-void
.end method

.method public static internalAddOperationListenerAttributesExtractor(Ljava/util/function/BiConsumer;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            "RESPONSE:",
            "Ljava/lang/Object;",
            ">(",
            "Ljava/util/function/BiConsumer<",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "-TREQUEST;-TRESPONSE;>;>;)V"
        }
    .end annotation

    .line 1
    sput-object p0, Lio/opentelemetry/instrumentation/api/internal/Experimental;->operationListenerAttributesExtractorAdder:Ljava/util/function/BiConsumer;

    .line 2
    .line 3
    return-void
.end method

.method public static internalSetRedactHttpClientQueryParameters(Ljava/util/function/BiConsumer;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/BiConsumer<",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder<",
            "**>;",
            "Ljava/lang/Boolean;",
            ">;)V"
        }
    .end annotation

    .line 1
    sput-object p0, Lio/opentelemetry/instrumentation/api/internal/Experimental;->redactHttpClientQueryParameters:Ljava/util/function/BiConsumer;

    .line 2
    .line 3
    return-void
.end method

.method public static internalSetUrlTemplateExtractor(Ljava/util/function/BiConsumer;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            ">(",
            "Ljava/util/function/BiConsumer<",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder<",
            "TREQUEST;>;",
            "Ljava/util/function/Function<",
            "TREQUEST;",
            "Ljava/lang/String;",
            ">;>;)V"
        }
    .end annotation

    .line 1
    sput-object p0, Lio/opentelemetry/instrumentation/api/internal/Experimental;->urlTemplateExtractorSetter:Ljava/util/function/BiConsumer;

    .line 2
    .line 3
    return-void
.end method

.method public static setRedactQueryParameters(Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;Z)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder<",
            "**>;Z)V"
        }
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/Experimental;->redactHttpClientQueryParameters:Ljava/util/function/BiConsumer;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/Experimental;->redactHttpClientQueryParameters:Ljava/util/function/BiConsumer;

    .line 6
    .line 7
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    invoke-interface {v0, p0, p1}, Ljava/util/function/BiConsumer;->accept(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    return-void
.end method

.method public static setUrlTemplateExtractor(Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;Ljava/util/function/Function;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder<",
            "TREQUEST;>;",
            "Ljava/util/function/Function<",
            "TREQUEST;",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/Experimental;->urlTemplateExtractorSetter:Ljava/util/function/BiConsumer;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/Experimental;->urlTemplateExtractorSetter:Ljava/util/function/BiConsumer;

    .line 6
    .line 7
    invoke-interface {v0, p0, p1}, Ljava/util/function/BiConsumer;->accept(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    return-void
.end method
