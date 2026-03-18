.class public final Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;
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

.field private final attributesGetter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter<",
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

.field private emitExperimentalHttpServerTelemetry:Z

.field private final headerGetter:Lio/opentelemetry/context/propagation/TextMapGetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/context/propagation/TextMapGetter<",
            "TREQUEST;>;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final httpAttributesExtractorBuilder:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation
.end field

.field private final httpServerRouteBuilder:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder<",
            "TREQUEST;>;"
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
            "TREQUEST;>;",
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
.method private constructor <init>(Ljava/lang/String;Lio/opentelemetry/api/OpenTelemetry;Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;Lio/opentelemetry/context/propagation/TextMapGetter;)V
    .locals 2
    .param p4    # Lio/opentelemetry/context/propagation/TextMapGetter;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lio/opentelemetry/api/OpenTelemetry;",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter<",
            "TREQUEST;TRESPONSE;>;",
            "Lio/opentelemetry/context/propagation/TextMapGetter<",
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
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->additionalExtractors:Ljava/util/List;

    .line 10
    .line 11
    invoke-static {}, Ljava/util/function/Function;->identity()Ljava/util/function/Function;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->statusExtractorTransformer:Ljava/util/function/Function;

    .line 16
    .line 17
    invoke-static {}, Ljava/util/function/Function;->identity()Ljava/util/function/Function;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->spanNameExtractorTransformer:Ljava/util/function/Function;

    .line 22
    .line 23
    const/4 v0, 0x0

    .line 24
    iput-boolean v0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->emitExperimentalHttpServerTelemetry:Z

    .line 25
    .line 26
    new-instance v0, Lfx0/a;

    .line 27
    .line 28
    const/4 v1, 0x1

    .line 29
    invoke-direct {v0, v1}, Lfx0/a;-><init>(I)V

    .line 30
    .line 31
    .line 32
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->builderCustomizer:Ljava/util/function/Consumer;

    .line 33
    .line 34
    const-string v0, "instrumentationName"

    .line 35
    .line 36
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->instrumentationName:Ljava/lang/String;

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
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->openTelemetry:Lio/opentelemetry/api/OpenTelemetry;

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
    check-cast p1, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;

    .line 57
    .line 58
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->attributesGetter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;

    .line 59
    .line 60
    invoke-static {p3}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractor;->builder(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->httpAttributesExtractorBuilder:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;

    .line 65
    .line 66
    invoke-static {p3}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractor;->builder(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->httpSpanNameExtractorBuilder:Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;

    .line 71
    .line 72
    invoke-static {p3}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRoute;->builder(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->httpServerRouteBuilder:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;

    .line 77
    .line 78
    iput-object p4, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->headerGetter:Lio/opentelemetry/context/propagation/TextMapGetter;

    .line 79
    .line 80
    return-void
.end method

.method public static synthetic a(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;)V
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->lambda$new$0(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static create(Ljava/lang/String;Lio/opentelemetry/api/OpenTelemetry;Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;
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
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter<",
            "TREQUEST;TRESPONSE;>;)",
            "Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;

    const/4 v1, 0x0

    invoke-direct {v0, p0, p1, p2, v1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;-><init>(Ljava/lang/String;Lio/opentelemetry/api/OpenTelemetry;Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;Lio/opentelemetry/context/propagation/TextMapGetter;)V

    return-object v0
.end method

.method public static create(Ljava/lang/String;Lio/opentelemetry/api/OpenTelemetry;Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;Lio/opentelemetry/context/propagation/TextMapGetter;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;
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
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter<",
            "TREQUEST;TRESPONSE;>;",
            "Lio/opentelemetry/context/propagation/TextMapGetter<",
            "TREQUEST;>;)",
            "Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 2
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;

    const-string v1, "headerGetter"

    .line 3
    invoke-static {p3, v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    check-cast p3, Lio/opentelemetry/context/propagation/TextMapGetter;

    invoke-direct {v0, p0, p1, p2, p3}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;-><init>(Ljava/lang/String;Lio/opentelemetry/api/OpenTelemetry;Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;Lio/opentelemetry/context/propagation/TextMapGetter;)V

    return-object v0
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
.method public addAttributesExtractor(Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "-TREQUEST;-TRESPONSE;>;)",
            "Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->additionalExtractors:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public build()Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->instrumenterBuilder()Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->headerGetter:Lio/opentelemetry/context/propagation/TextMapGetter;

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    invoke-virtual {v0, p0}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->buildServerInstrumenter(Lio/opentelemetry/context/propagation/TextMapGetter;)Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0

    .line 14
    :cond_0
    invoke-static {}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;->alwaysServer()Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-virtual {v0, p0}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->buildInstrumenter(Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method

.method public configure(Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;",
            ")",
            "Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder<",
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
    new-instance v1, Lfx0/f;

    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    invoke-direct {v1, p0, v2}, Lfx0/f;-><init>(Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;I)V

    .line 14
    .line 15
    .line 16
    invoke-static {v0, v1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->set(Ljava/util/function/Supplier;Ljava/util/function/Consumer;)V

    .line 17
    .line 18
    .line 19
    new-instance v0, Lfx0/c;

    .line 20
    .line 21
    const/4 v1, 0x6

    .line 22
    invoke-direct {v0, p1, v1}, Lfx0/c;-><init>(Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;I)V

    .line 23
    .line 24
    .line 25
    new-instance v1, Lfx0/f;

    .line 26
    .line 27
    const/4 v2, 0x1

    .line 28
    invoke-direct {v1, p0, v2}, Lfx0/f;-><init>(Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;I)V

    .line 29
    .line 30
    .line 31
    invoke-static {v0, v1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->set(Ljava/util/function/Supplier;Ljava/util/function/Consumer;)V

    .line 32
    .line 33
    .line 34
    new-instance v0, Lfx0/c;

    .line 35
    .line 36
    const/4 v1, 0x7

    .line 37
    invoke-direct {v0, p1, v1}, Lfx0/c;-><init>(Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;I)V

    .line 38
    .line 39
    .line 40
    new-instance v1, Lfx0/f;

    .line 41
    .line 42
    const/4 v2, 0x2

    .line 43
    invoke-direct {v1, p0, v2}, Lfx0/f;-><init>(Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;I)V

    .line 44
    .line 45
    .line 46
    invoke-static {v0, v1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->set(Ljava/util/function/Supplier;Ljava/util/function/Consumer;)V

    .line 47
    .line 48
    .line 49
    new-instance v0, Lfx0/c;

    .line 50
    .line 51
    const/16 v1, 0x8

    .line 52
    .line 53
    invoke-direct {v0, p1, v1}, Lfx0/c;-><init>(Lio/opentelemetry/instrumentation/api/incubator/config/internal/CommonConfig;I)V

    .line 54
    .line 55
    .line 56
    new-instance p1, Lfx0/f;

    .line 57
    .line 58
    const/4 v1, 0x3

    .line 59
    invoke-direct {p1, p0, v1}, Lfx0/f;-><init>(Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;I)V

    .line 60
    .line 61
    .line 62
    invoke-static {v0, p1}, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->set(Ljava/util/function/Supplier;Ljava/util/function/Consumer;)V

    .line 63
    .line 64
    .line 65
    return-object p0
.end method

.method public instrumenterBuilder()Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->spanNameExtractorTransformer:Ljava/util/function/Function;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->httpSpanNameExtractorBuilder:Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;

    .line 4
    .line 5
    invoke-virtual {v1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;->build()Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-interface {v0, v1}, Ljava/util/function/Function;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    check-cast v0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;

    .line 14
    .line 15
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->openTelemetry:Lio/opentelemetry/api/OpenTelemetry;

    .line 16
    .line 17
    iget-object v2, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->instrumentationName:Ljava/lang/String;

    .line 18
    .line 19
    invoke-static {v1, v2, v0}, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->builder(Lio/opentelemetry/api/OpenTelemetry;Ljava/lang/String;Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->statusExtractorTransformer:Ljava/util/function/Function;

    .line 24
    .line 25
    iget-object v2, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->attributesGetter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;

    .line 26
    .line 27
    invoke-static {v2}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanStatusExtractor;->create(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;)Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    invoke-interface {v1, v2}, Ljava/util/function/Function;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    check-cast v1, Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor;

    .line 36
    .line 37
    invoke-virtual {v0, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->setSpanStatusExtractor(Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->httpAttributesExtractorBuilder:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;

    .line 42
    .line 43
    invoke-virtual {v1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->build()Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    invoke-virtual {v0, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->addAttributesExtractor(Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->additionalExtractors:Ljava/util/List;

    .line 52
    .line 53
    invoke-virtual {v0, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->addAttributesExtractors(Ljava/lang/Iterable;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->httpServerRouteBuilder:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;

    .line 58
    .line 59
    invoke-virtual {v1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;->build()Lio/opentelemetry/instrumentation/api/instrumenter/ContextCustomizer;

    .line 60
    .line 61
    .line 62
    move-result-object v1

    .line 63
    invoke-virtual {v0, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->addContextCustomizer(Lio/opentelemetry/instrumentation/api/instrumenter/ContextCustomizer;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    invoke-static {}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerMetrics;->get()Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    invoke-virtual {v0, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->addOperationMetrics(Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    iget-boolean v1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->emitExperimentalHttpServerTelemetry:Z

    .line 76
    .line 77
    if-eqz v1, :cond_0

    .line 78
    .line 79
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->attributesGetter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;

    .line 80
    .line 81
    invoke-static {v1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpExperimentalAttributesExtractor;->create(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;)Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;

    .line 82
    .line 83
    .line 84
    move-result-object v1

    .line 85
    invoke-virtual {v0, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->addAttributesExtractor(Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    invoke-static {}, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpServerExperimentalMetrics;->get()Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;

    .line 90
    .line 91
    .line 92
    move-result-object v2

    .line 93
    invoke-virtual {v1, v2}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->addOperationMetrics(Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 94
    .line 95
    .line 96
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->builderCustomizer:Ljava/util/function/Consumer;

    .line 97
    .line 98
    invoke-interface {p0, v0}, Ljava/util/function/Consumer;->accept(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    return-object v0
.end method

.method public setBuilderCustomizer(Ljava/util/function/Consumer;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Consumer<",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;>;)",
            "Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->builderCustomizer:Ljava/util/function/Consumer;

    .line 2
    .line 3
    return-object p0
.end method

.method public setCapturedRequestHeaders(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->httpAttributesExtractorBuilder:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->setCapturedRequestHeaders(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public setCapturedResponseHeaders(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->httpAttributesExtractorBuilder:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->setCapturedResponseHeaders(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public setEmitExperimentalHttpServerTelemetry(Z)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(Z)",
            "Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iput-boolean p1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->emitExperimentalHttpServerTelemetry:Z

    .line 2
    .line 3
    return-object p0
.end method

.method public setKnownMethods(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->httpAttributesExtractorBuilder:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;->setKnownMethods(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesExtractorBuilder;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->httpSpanNameExtractorBuilder:Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;->setKnownMethods(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpSpanNameExtractorBuilder;

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->httpServerRouteBuilder:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;

    .line 12
    .line 13
    invoke-virtual {v0, p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;->setKnownMethods(Ljava/util/Collection;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteBuilder;

    .line 14
    .line 15
    .line 16
    return-object p0
.end method

.method public setSpanNameExtractor(Ljava/util/function/Function;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Function<",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor<",
            "TREQUEST;>;",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor<",
            "TREQUEST;>;>;)",
            "Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->spanNameExtractorTransformer:Ljava/util/function/Function;

    .line 2
    .line 3
    return-object p0
.end method

.method public setStatusExtractor(Ljava/util/function/Function;)Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Function<",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor<",
            "TREQUEST;TRESPONSE;>;",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor<",
            "TREQUEST;TRESPONSE;>;>;)",
            "Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/builder/internal/DefaultHttpServerInstrumenterBuilder;->statusExtractorTransformer:Ljava/util/function/Function;

    .line 2
    .line 3
    return-object p0
.end method
