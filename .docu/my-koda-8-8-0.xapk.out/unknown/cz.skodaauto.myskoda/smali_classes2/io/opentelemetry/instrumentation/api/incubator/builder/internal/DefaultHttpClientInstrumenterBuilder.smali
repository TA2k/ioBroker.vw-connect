.class public final Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;
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


# static fields
.field private static final PEER_SERVICE:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private final additionalExtractors:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "-TREQUEST;-TRESPONSE;>;>;"
        }
    .end annotation
.end field

.field private final attributesGetter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation
.end field

.field private builderCustomizer:Ljava/util/function/Consumer;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Consumer<",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;>;"
        }
    .end annotation
.end field

.field private emitExperimentalHttpClientTelemetry:Z

.field private final headerSetter:Lio/opentelemetry/context/propagation/TextMapSetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/context/propagation/TextMapSetter<",
            "TREQUEST;>;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final httpAttributesExtractorBuilder:Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation
.end field

.field private final httpSpanNameExtractorBuilder:Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder<",
            "TREQUEST;>;"
        }
    .end annotation
.end field

.field private final instrumentationName:Ljava/lang/String;

.field private final openTelemetry:Lio/opentelemetry/api/OpenTelemetry;

.field private spanNameExtractorTransformer:Ljava/util/function/Function;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Function<",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor<",
            "TREQUEST;>;+",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor<",
            "TREQUEST;>;>;"
        }
    .end annotation
.end field

.field private statusExtractorTransformer:Ljava/util/function/Function;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Function<",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor<",
            "TREQUEST;TRESPONSE;>;",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor<",
            "TREQUEST;TRESPONSE;>;>;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "peer.service"

    .line 2
    .line 3
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->PEER_SERVICE:Lio/opentelemetry/api/common/AttributeKey;

    .line 8
    .line 9
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;Lio/opentelemetry/api/OpenTelemetry;Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;Lio/opentelemetry/context/propagation/TextMapSetter;)V
    .locals 2
    .param p4    # Lio/opentelemetry/context/propagation/TextMapSetter;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lio/opentelemetry/api/OpenTelemetry;",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter<",
            "TREQUEST;TRESPONSE;>;",
            "Lio/opentelemetry/context/propagation/TextMapSetter<",
            "TREQUEST;>;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->additionalExtractors:Ljava/util/List;

    .line 10
    .line 11
    invoke-static {}, Ljava/util/function/Function;->identity()Ljava/util/function/Function;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->statusExtractorTransformer:Ljava/util/function/Function;

    .line 16
    .line 17
    invoke-static {}, Ljava/util/function/Function;->identity()Ljava/util/function/Function;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->spanNameExtractorTransformer:Ljava/util/function/Function;

    .line 22
    .line 23
    const/4 v0, 0x0

    .line 24
    iput-boolean v0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->emitExperimentalHttpClientTelemetry:Z

    .line 25
    .line 26
    new-instance v0, Lfx0/a;

    .line 27
    .line 28
    const/4 v1, 0x0

    .line 29
    invoke-direct {v0, v1}, Lfx0/a;-><init>(I)V

    .line 30
    .line 31
    .line 32
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->builderCustomizer:Ljava/util/function/Consumer;

    .line 33
    .line 34
    const-string v0, "instrumentationName"

    .line 35
    .line 36
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->instrumentationName:Ljava/lang/String;

    .line 40
    .line 41
    const-string p1, "openTelemetry"

    .line 42
    .line 43
    invoke-static {p2, p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    check-cast p2, Lio/opentelemetry/api/OpenTelemetry;

    .line 47
    .line 48
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->openTelemetry:Lio/opentelemetry/api/OpenTelemetry;

    .line 49
    .line 50
    const-string p1, "attributesGetter"

    .line 51
    .line 52
    invoke-static {p3, p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-object p1, p3

    .line 56
    check-cast p1, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;

    .line 57
    .line 58
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->attributesGetter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;

    .line 59
    .line 60
    invoke-static {p3}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractor;->builder(Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->httpSpanNameExtractorBuilder:Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;

    .line 65
    .line 66
    invoke-static {p3}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractor;->builder(Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->httpAttributesExtractorBuilder:Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;

    .line 71
    .line 72
    iput-object p4, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->headerSetter:Lio/opentelemetry/context/propagation/TextMapSetter;

    .line 73
    .line 74
    return-void
.end method

.method public static synthetic a(Ljava/util/function/Function;Ljava/lang/Object;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->lambda$build$2(Ljava/util/function/Function;Ljava/lang/Object;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic b(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;)V
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->lambda$new$0(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic c(Ljava/lang/Object;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->lambda$build$1(Ljava/lang/Object;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static create(Ljava/lang/String;Lio/opentelemetry/api/OpenTelemetry;Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            "RESPONSE:",
            "Ljava/lang/Object;",
            ">(",
            "Ljava/lang/String;",
            "Lio/opentelemetry/api/OpenTelemetry;",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter<",
            "TREQUEST;TRESPONSE;>;)",
            "Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;

    const/4 v1, 0x0

    invoke-direct {v0, p0, p1, p2, v1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;-><init>(Ljava/lang/String;Lio/opentelemetry/api/OpenTelemetry;Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;Lio/opentelemetry/context/propagation/TextMapSetter;)V

    return-object v0
.end method

.method public static create(Ljava/lang/String;Lio/opentelemetry/api/OpenTelemetry;Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;Lio/opentelemetry/context/propagation/TextMapSetter;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            "RESPONSE:",
            "Ljava/lang/Object;",
            ">(",
            "Ljava/lang/String;",
            "Lio/opentelemetry/api/OpenTelemetry;",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter<",
            "TREQUEST;TRESPONSE;>;",
            "Lio/opentelemetry/context/propagation/TextMapSetter<",
            "TREQUEST;>;)",
            "Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 2
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;

    const-string v1, "headerSetter"

    .line 3
    invoke-static {p3, v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    check-cast p3, Lio/opentelemetry/context/propagation/TextMapSetter;

    invoke-direct {v0, p0, p1, p2, p3}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;-><init>(Ljava/lang/String;Lio/opentelemetry/api/OpenTelemetry;Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;Lio/opentelemetry/context/propagation/TextMapSetter;)V

    return-object v0
.end method

.method private static synthetic lambda$build$1(Ljava/lang/Object;)Ljava/lang/String;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method private static synthetic lambda$build$2(Ljava/util/function/Function;Ljava/lang/Object;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/context/Context;->current()Lio/opentelemetry/context/Context;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientUrlTemplate;->get(Lio/opentelemetry/context/Context;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    return-object v0

    .line 12
    :cond_0
    invoke-interface {p0, p1}, Ljava/util/function/Function;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    check-cast p0, Ljava/lang/String;

    .line 17
    .line 18
    return-object p0
.end method

.method private static synthetic lambda$new$0(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;)V
    .locals 0

    .line 1
    return-void
.end method

.method private static set(Ljava/util/function/Supplier;Ljava/util/function/Consumer;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Ljava/util/function/Supplier<",
            "TT;>;",
            "Ljava/util/function/Consumer<",
            "TT;>;)V"
        }
    .end annotation

    .line 1
    invoke-interface {p0}, Ljava/util/function/Supplier;->get()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    invoke-interface {p1, p0}, Ljava/util/function/Consumer;->accept(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    return-void
.end method


# virtual methods
.method public addAttributesExtractor(Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "-TREQUEST;-TRESPONSE;>;)",
            "Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->additionalExtractors:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public build()Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iget-boolean v0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->emitExperimentalHttpClientTelemetry:Z

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    new-instance v0, Lfx0/d;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    invoke-direct {v0, v1}, Lfx0/d;-><init>(I)V

    .line 9
    .line 10
    .line 11
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->attributesGetter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;

    .line 12
    .line 13
    instance-of v2, v1, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientExperimentalAttributesGetter;

    .line 14
    .line 15
    if-eqz v2, :cond_0

    .line 16
    .line 17
    check-cast v1, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientExperimentalAttributesGetter;

    .line 18
    .line 19
    new-instance v0, Lfx0/e;

    .line 20
    .line 21
    const/4 v2, 0x0

    .line 22
    invoke-direct {v0, v1, v2}, Lfx0/e;-><init>(Ljava/lang/Object;I)V

    .line 23
    .line 24
    .line 25
    :cond_0
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->httpSpanNameExtractorBuilder:Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;

    .line 26
    .line 27
    new-instance v2, Lfx0/e;

    .line 28
    .line 29
    const/4 v3, 0x1

    .line 30
    invoke-direct {v2, v0, v3}, Lfx0/e;-><init>(Ljava/lang/Object;I)V

    .line 31
    .line 32
    .line 33
    invoke-static {v1, v2}, Lio/opentelemetry/instrumentation/api/internal/Experimental;->setUrlTemplateExtractor(Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;Ljava/util/function/Function;)V

    .line 34
    .line 35
    .line 36
    :cond_1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->spanNameExtractorTransformer:Ljava/util/function/Function;

    .line 37
    .line 38
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->httpSpanNameExtractorBuilder:Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;

    .line 39
    .line 40
    invoke-virtual {v1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;->build()Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    invoke-interface {v0, v1}, Ljava/util/function/Function;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    check-cast v0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;

    .line 49
    .line 50
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->openTelemetry:Lio/opentelemetry/api/OpenTelemetry;

    .line 51
    .line 52
    iget-object v2, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->instrumentationName:Ljava/lang/String;

    .line 53
    .line 54
    invoke-static {v1, v2, v0}, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->builder(Lio/opentelemetry/api/OpenTelemetry;Ljava/lang/String;Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->statusExtractorTransformer:Ljava/util/function/Function;

    .line 59
    .line 60
    iget-object v2, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->attributesGetter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;

    .line 61
    .line 62
    invoke-static {v2}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanStatusExtractor;->create(Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;)Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor;

    .line 63
    .line 64
    .line 65
    move-result-object v2

    .line 66
    invoke-interface {v1, v2}, Ljava/util/function/Function;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    check-cast v1, Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor;

    .line 71
    .line 72
    invoke-virtual {v0, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->setSpanStatusExtractor(Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->httpAttributesExtractorBuilder:Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;

    .line 77
    .line 78
    invoke-virtual {v1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->build()Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;

    .line 79
    .line 80
    .line 81
    move-result-object v1

    .line 82
    invoke-virtual {v0, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->addAttributesExtractor(Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->additionalExtractors:Ljava/util/List;

    .line 87
    .line 88
    invoke-virtual {v0, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->addAttributesExtractors(Ljava/lang/Iterable;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    invoke-static {}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientMetrics;->get()Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;

    .line 93
    .line 94
    .line 95
    move-result-object v1

    .line 96
    invoke-virtual {v0, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->addOperationMetrics(Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    iget-boolean v1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->emitExperimentalHttpClientTelemetry:Z

    .line 101
    .line 102
    if-eqz v1, :cond_2

    .line 103
    .line 104
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->attributesGetter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;

    .line 105
    .line 106
    invoke-static {v1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpExperimentalAttributesExtractor;->create(Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;)Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;

    .line 107
    .line 108
    .line 109
    move-result-object v1

    .line 110
    invoke-virtual {v0, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->addAttributesExtractor(Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 111
    .line 112
    .line 113
    move-result-object v1

    .line 114
    invoke-static {}, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientExperimentalMetrics;->get()Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;

    .line 115
    .line 116
    .line 117
    move-result-object v2

    .line 118
    invoke-virtual {v1, v2}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->addOperationMetrics(Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 119
    .line 120
    .line 121
    :cond_2
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->builderCustomizer:Ljava/util/function/Consumer;

    .line 122
    .line 123
    invoke-interface {v1, v0}, Ljava/util/function/Consumer;->accept(Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->headerSetter:Lio/opentelemetry/context/propagation/TextMapSetter;

    .line 127
    .line 128
    if-eqz p0, :cond_3

    .line 129
    .line 130
    invoke-virtual {v0, p0}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->buildClientInstrumenter(Lio/opentelemetry/context/propagation/TextMapSetter;)Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    return-object p0

    .line 135
    :cond_3
    invoke-static {}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;->alwaysClient()Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    invoke-virtual {v0, p0}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->buildInstrumenter(Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    return-object p0
.end method

.method public configure(Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;",
            ")",
            "Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    new-instance v0, Lfx0/c;

    .line 5
    .line 6
    const/4 v1, 0x1

    .line 7
    invoke-direct {v0, p1, v1}, Lfx0/c;-><init>(Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;I)V

    .line 8
    .line 9
    .line 10
    new-instance v1, Lfx0/b;

    .line 11
    .line 12
    const/4 v2, 0x3

    .line 13
    invoke-direct {v1, p0, v2}, Lfx0/b;-><init>(Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;I)V

    .line 14
    .line 15
    .line 16
    invoke-static {v0, v1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->set(Ljava/util/function/Supplier;Ljava/util/function/Consumer;)V

    .line 17
    .line 18
    .line 19
    new-instance v0, Lfx0/c;

    .line 20
    .line 21
    const/4 v1, 0x3

    .line 22
    invoke-direct {v0, p1, v1}, Lfx0/c;-><init>(Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;I)V

    .line 23
    .line 24
    .line 25
    new-instance v1, Lfx0/b;

    .line 26
    .line 27
    const/4 v2, 0x4

    .line 28
    invoke-direct {v1, p0, v2}, Lfx0/b;-><init>(Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;I)V

    .line 29
    .line 30
    .line 31
    invoke-static {v0, v1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->set(Ljava/util/function/Supplier;Ljava/util/function/Consumer;)V

    .line 32
    .line 33
    .line 34
    new-instance v0, Lfx0/c;

    .line 35
    .line 36
    const/4 v1, 0x4

    .line 37
    invoke-direct {v0, p1, v1}, Lfx0/c;-><init>(Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;I)V

    .line 38
    .line 39
    .line 40
    new-instance v1, Lfx0/b;

    .line 41
    .line 42
    const/4 v2, 0x5

    .line 43
    invoke-direct {v1, p0, v2}, Lfx0/b;-><init>(Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;I)V

    .line 44
    .line 45
    .line 46
    invoke-static {v0, v1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->set(Ljava/util/function/Supplier;Ljava/util/function/Consumer;)V

    .line 47
    .line 48
    .line 49
    new-instance v0, Lfx0/c;

    .line 50
    .line 51
    const/4 v1, 0x5

    .line 52
    invoke-direct {v0, p1, v1}, Lfx0/c;-><init>(Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;I)V

    .line 53
    .line 54
    .line 55
    new-instance v1, Lfx0/b;

    .line 56
    .line 57
    const/4 v2, 0x0

    .line 58
    invoke-direct {v1, p0, v2}, Lfx0/b;-><init>(Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;I)V

    .line 59
    .line 60
    .line 61
    invoke-static {v0, v1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->set(Ljava/util/function/Supplier;Ljava/util/function/Consumer;)V

    .line 62
    .line 63
    .line 64
    new-instance v0, Lfx0/c;

    .line 65
    .line 66
    const/4 v1, 0x0

    .line 67
    invoke-direct {v0, p1, v1}, Lfx0/c;-><init>(Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;I)V

    .line 68
    .line 69
    .line 70
    new-instance v1, Lfx0/b;

    .line 71
    .line 72
    const/4 v2, 0x1

    .line 73
    invoke-direct {v1, p0, v2}, Lfx0/b;-><init>(Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;I)V

    .line 74
    .line 75
    .line 76
    invoke-static {v0, v1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->set(Ljava/util/function/Supplier;Ljava/util/function/Consumer;)V

    .line 77
    .line 78
    .line 79
    new-instance v0, Lfx0/c;

    .line 80
    .line 81
    const/4 v1, 0x2

    .line 82
    invoke-direct {v0, p1, v1}, Lfx0/c;-><init>(Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;I)V

    .line 83
    .line 84
    .line 85
    new-instance p1, Lfx0/b;

    .line 86
    .line 87
    invoke-direct {p1, p0, v1}, Lfx0/b;-><init>(Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;I)V

    .line 88
    .line 89
    .line 90
    invoke-static {v0, p1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->set(Ljava/util/function/Supplier;Ljava/util/function/Consumer;)V

    .line 91
    .line 92
    .line 93
    return-object p0
.end method

.method public instrumenterBuilder(Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<BUI",
            "LDERREQUEST:Ljava/lang/Object;",
            "BUI",
            "LDERRESPONSE:Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor<",
            "-TBUI",
            "LDERREQUEST;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TBUI",
            "LDERREQUEST;",
            "TBUI",
            "LDERRESPONSE;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->openTelemetry:Lio/opentelemetry/api/OpenTelemetry;

    .line 2
    .line 3
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->instrumentationName:Ljava/lang/String;

    .line 4
    .line 5
    invoke-static {v0, p0, p1}, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->builder(Lio/opentelemetry/api/OpenTelemetry;Ljava/lang/String;Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public setBuilderCustomizer(Ljava/util/function/Consumer;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Consumer<",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;>;)",
            "Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->builderCustomizer:Ljava/util/function/Consumer;

    .line 2
    .line 3
    return-object p0
.end method

.method public setCapturedRequestHeaders(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->httpAttributesExtractorBuilder:Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->setCapturedRequestHeaders(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public setCapturedResponseHeaders(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->httpAttributesExtractorBuilder:Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->setCapturedResponseHeaders(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public setEmitExperimentalHttpClientTelemetry(Z)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(Z)",
            "Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iput-boolean p1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->emitExperimentalHttpClientTelemetry:Z

    .line 2
    .line 3
    return-object p0
.end method

.method public setKnownMethods(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->httpAttributesExtractorBuilder:Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->setKnownMethods(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->httpSpanNameExtractorBuilder:Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;->setKnownMethods(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;

    .line 9
    .line 10
    .line 11
    return-object p0
.end method

.method public setPeerService(Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->PEER_SERVICE:Lio/opentelemetry/api/common/AttributeKey;

    .line 2
    .line 3
    invoke-static {v0, p1}, Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;->constant(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->addAttributesExtractor(Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public setPeerServiceResolver(Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolver;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolver;",
            ")",
            "Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->attributesGetter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;

    .line 2
    .line 3
    invoke-static {v0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientPeerServiceAttributesExtractor;->create(Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolver;)Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientPeerServiceAttributesExtractor;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->addAttributesExtractor(Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public setRedactQueryParameters(Z)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(Z)",
            "Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->httpAttributesExtractorBuilder:Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;

    .line 2
    .line 3
    invoke-static {v0, p1}, Lio/opentelemetry/instrumentation/api/internal/Experimental;->setRedactQueryParameters(Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;Z)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public setSpanNameExtractor(Ljava/util/function/Function;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Function<",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor<",
            "TREQUEST;>;",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor<",
            "TREQUEST;>;>;)",
            "Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->spanNameExtractorTransformer:Ljava/util/function/Function;

    .line 2
    .line 3
    return-object p0
.end method

.method public setStatusExtractor(Ljava/util/function/Function;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Function<",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor<",
            "TREQUEST;TRESPONSE;>;",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor<",
            "TREQUEST;TRESPONSE;>;>;)",
            "Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpClientInstrumenterBuilder;->statusExtractorTransformer:Ljava/util/function/Function;

    .line 2
    .line 3
    return-object p0
.end method
