.class public final Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$InstrumenterConstructor;
    }
.end annotation

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
.field private static final logger:Ljava/util/logging/Logger;

.field private static final spanSuppressionStrategy:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;


# instance fields
.field final attributesExtractors:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "-TREQUEST;-TRESPONSE;>;>;"
        }
    .end annotation
.end field

.field final contextCustomizers:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/instrumentation/api/instrumenter/ContextCustomizer<",
            "-TREQUEST;>;>;"
        }
    .end annotation
.end field

.field enabled:Z

.field errorCauseExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/ErrorCauseExtractor;

.field final instrumentationName:Ljava/lang/String;

.field private instrumentationVersion:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field final openTelemetry:Lio/opentelemetry/api/OpenTelemetry;

.field final operationListenerAttributesExtractors:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "-TREQUEST;-TRESPONSE;>;>;"
        }
    .end annotation
.end field

.field private final operationListeners:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;",
            ">;"
        }
    .end annotation
.end field

.field private final operationMetrics:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;",
            ">;"
        }
    .end annotation
.end field

.field propagateOperationListenersToOnEnd:Z

.field private schemaUrl:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field spanKindExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor<",
            "-TREQUEST;>;"
        }
    .end annotation
.end field

.field final spanLinksExtractors:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanLinksExtractor<",
            "-TREQUEST;>;>;"
        }
    .end annotation
.end field

.field spanNameExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor<",
            "-TREQUEST;>;"
        }
    .end annotation
.end field

.field spanStatusExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor<",
            "-TREQUEST;-TRESPONSE;>;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0}, Ljava/util/logging/Logger;->getLogger(Ljava/lang/String;)Ljava/util/logging/Logger;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->logger:Ljava/util/logging/Logger;

    .line 12
    .line 13
    const-string v0, "otel.instrumentation.experimental.span-suppression-strategy"

    .line 14
    .line 15
    invoke-static {v0}, Lio/opentelemetry/instrumentation/api/internal/ConfigPropertiesUtil;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-static {v0}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;->fromConfig(Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    sput-object v0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->spanSuppressionStrategy:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;

    .line 24
    .line 25
    new-instance v0, Lio/opentelemetry/instrumentation/api/instrumenter/c;

    .line 26
    .line 27
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 28
    .line 29
    .line 30
    invoke-static {v0}, Lio/opentelemetry/instrumentation/api/internal/Experimental;->internalAddOperationListenerAttributesExtractor(Ljava/util/function/BiConsumer;)V

    .line 31
    .line 32
    .line 33
    new-instance v0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$2;

    .line 34
    .line 35
    invoke-direct {v0}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$2;-><init>()V

    .line 36
    .line 37
    .line 38
    invoke-static {v0}, Lio/opentelemetry/instrumentation/api/internal/InstrumenterUtil;->setInstrumenterBuilderAccess(Lio/opentelemetry/instrumentation/api/internal/InstrumenterBuilderAccess;)V

    .line 39
    .line 40
    .line 41
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/api/OpenTelemetry;Ljava/lang/String;Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/OpenTelemetry;",
            "Ljava/lang/String;",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor<",
            "-TREQUEST;>;)V"
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
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->spanLinksExtractors:Ljava/util/List;

    .line 10
    .line 11
    new-instance v0, Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->attributesExtractors:Ljava/util/List;

    .line 17
    .line 18
    new-instance v0, Ljava/util/ArrayList;

    .line 19
    .line 20
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->operationListenerAttributesExtractors:Ljava/util/List;

    .line 24
    .line 25
    new-instance v0, Ljava/util/ArrayList;

    .line 26
    .line 27
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 28
    .line 29
    .line 30
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->contextCustomizers:Ljava/util/List;

    .line 31
    .line 32
    new-instance v0, Ljava/util/ArrayList;

    .line 33
    .line 34
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 35
    .line 36
    .line 37
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->operationListeners:Ljava/util/List;

    .line 38
    .line 39
    new-instance v0, Ljava/util/ArrayList;

    .line 40
    .line 41
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 42
    .line 43
    .line 44
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->operationMetrics:Ljava/util/List;

    .line 45
    .line 46
    const/4 v0, 0x0

    .line 47
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->schemaUrl:Ljava/lang/String;

    .line 48
    .line 49
    invoke-static {}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;->alwaysInternal()Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->spanKindExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;

    .line 54
    .line 55
    invoke-static {}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor;->getDefault()Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->spanStatusExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor;

    .line 60
    .line 61
    invoke-static {}, Lio/opentelemetry/instrumentation/api/instrumenter/ErrorCauseExtractor;->getDefault()Lio/opentelemetry/instrumentation/api/instrumenter/ErrorCauseExtractor;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->errorCauseExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/ErrorCauseExtractor;

    .line 66
    .line 67
    const/4 v0, 0x0

    .line 68
    iput-boolean v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->propagateOperationListenersToOnEnd:Z

    .line 69
    .line 70
    const/4 v0, 0x1

    .line 71
    iput-boolean v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->enabled:Z

    .line 72
    .line 73
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->openTelemetry:Lio/opentelemetry/api/OpenTelemetry;

    .line 74
    .line 75
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->instrumentationName:Ljava/lang/String;

    .line 76
    .line 77
    iput-object p3, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->spanNameExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;

    .line 78
    .line 79
    invoke-static {p2}, Lio/opentelemetry/instrumentation/api/internal/EmbeddedInstrumentationProperties;->findVersion(Ljava/lang/String;)Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->instrumentationVersion:Ljava/lang/String;

    .line 84
    .line 85
    return-void
.end method

.method public static synthetic a(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->lambda$static$0(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic access$000(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->propagateOperationListenersToOnEnd()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static applyCustomizers(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            "RESPONSE:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;)V"
        }
    .end annotation

    .line 1
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizerUtil;->getInstrumenterCustomizerProviders()Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    check-cast v1, Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizerProvider;

    .line 20
    .line 21
    new-instance v2, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$1;

    .line 22
    .line 23
    invoke-direct {v2, p0}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$1;-><init>(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;)V

    .line 24
    .line 25
    .line 26
    invoke-interface {v1, v2}, Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizerProvider;->customize(Lio/opentelemetry/instrumentation/api/internal/InternalInstrumenterCustomizer;)V

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    return-void
.end method

.method public static synthetic b(Lio/opentelemetry/instrumentation/api/internal/SchemaUrlProvider;)Ljava/util/stream/Stream;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->lambda$getSchemaUrl$1(Lio/opentelemetry/instrumentation/api/internal/SchemaUrlProvider;)Ljava/util/stream/Stream;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private buildInstrumenter(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$InstrumenterConstructor;Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$InstrumenterConstructor<",
            "TREQUEST;TRESPONSE;>;",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor<",
            "-TREQUEST;>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 5
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->applyCustomizers(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;)V

    .line 6
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->spanKindExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;

    .line 7
    invoke-interface {p1, p0}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$InstrumenterConstructor;->create(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;)Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    move-result-object p0

    return-object p0
.end method

.method public static synthetic c(Lio/opentelemetry/instrumentation/api/internal/SpanKeyProvider;)Ljava/util/stream/Stream;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->lambda$getSpanKeysFromAttributesExtractors$2(Lio/opentelemetry/instrumentation/api/internal/SpanKeyProvider;)Ljava/util/stream/Stream;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private getSchemaUrl()Ljava/lang/String;
    .locals 4
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->schemaUrl:Ljava/lang/String;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-object v0

    .line 6
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->attributesExtractors:Ljava/util/List;

    .line 7
    .line 8
    invoke-interface {p0}, Ljava/util/Collection;->stream()Ljava/util/stream/Stream;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    new-instance v0, Lio/opentelemetry/instrumentation/api/instrumenter/a;

    .line 13
    .line 14
    const/4 v1, 0x1

    .line 15
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/a;-><init>(I)V

    .line 16
    .line 17
    .line 18
    invoke-interface {p0, v0}, Ljava/util/stream/Stream;->filter(Ljava/util/function/Predicate;)Ljava/util/stream/Stream;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    new-instance v0, Lio/opentelemetry/instrumentation/api/instrumenter/b;

    .line 23
    .line 24
    const/4 v1, 0x2

    .line 25
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/b;-><init>(I)V

    .line 26
    .line 27
    .line 28
    invoke-interface {p0, v0}, Ljava/util/stream/Stream;->map(Ljava/util/function/Function;)Ljava/util/stream/Stream;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    new-instance v0, Lio/opentelemetry/instrumentation/api/instrumenter/b;

    .line 33
    .line 34
    const/4 v1, 0x3

    .line 35
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/b;-><init>(I)V

    .line 36
    .line 37
    .line 38
    invoke-interface {p0, v0}, Ljava/util/stream/Stream;->flatMap(Ljava/util/function/Function;)Ljava/util/stream/Stream;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    invoke-static {}, Ljava/util/stream/Collectors;->toSet()Ljava/util/stream/Collector;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    invoke-interface {p0, v0}, Ljava/util/stream/Stream;->collect(Ljava/util/stream/Collector;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    check-cast p0, Ljava/util/Set;

    .line 51
    .line 52
    invoke-interface {p0}, Ljava/util/Set;->size()I

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    const/4 v1, 0x0

    .line 57
    if-eqz v0, :cond_2

    .line 58
    .line 59
    const/4 v2, 0x1

    .line 60
    if-eq v0, v2, :cond_1

    .line 61
    .line 62
    sget-object v0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->logger:Ljava/util/logging/Logger;

    .line 63
    .line 64
    sget-object v2, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    .line 65
    .line 66
    const-string v3, "Multiple schemaUrls were detected: {0}. The built Instrumenter will have no schemaUrl assigned."

    .line 67
    .line 68
    invoke-virtual {v0, v2, v3, p0}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    return-object v1

    .line 72
    :cond_1
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    check-cast p0, Ljava/lang/String;

    .line 81
    .line 82
    return-object p0

    .line 83
    :cond_2
    return-object v1
.end method

.method private getSpanKeysFromAttributesExtractors()Ljava/util/Set;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Lio/opentelemetry/instrumentation/api/internal/SpanKey;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->attributesExtractors:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/util/Collection;->stream()Ljava/util/stream/Stream;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    new-instance v0, Lio/opentelemetry/instrumentation/api/instrumenter/a;

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/a;-><init>(I)V

    .line 11
    .line 12
    .line 13
    invoke-interface {p0, v0}, Ljava/util/stream/Stream;->filter(Ljava/util/function/Predicate;)Ljava/util/stream/Stream;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    new-instance v0, Lio/opentelemetry/instrumentation/api/instrumenter/b;

    .line 18
    .line 19
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/b;-><init>(I)V

    .line 20
    .line 21
    .line 22
    invoke-interface {p0, v0}, Ljava/util/stream/Stream;->map(Ljava/util/function/Function;)Ljava/util/stream/Stream;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    new-instance v0, Lio/opentelemetry/instrumentation/api/instrumenter/b;

    .line 27
    .line 28
    const/4 v1, 0x1

    .line 29
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/b;-><init>(I)V

    .line 30
    .line 31
    .line 32
    invoke-interface {p0, v0}, Ljava/util/stream/Stream;->flatMap(Ljava/util/function/Function;)Ljava/util/stream/Stream;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-static {}, Ljava/util/stream/Collectors;->toSet()Ljava/util/stream/Collector;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    invoke-interface {p0, v0}, Ljava/util/stream/Stream;->collect(Ljava/util/stream/Collector;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    check-cast p0, Ljava/util/Set;

    .line 45
    .line 46
    return-object p0
.end method

.method private static synthetic lambda$getSchemaUrl$1(Lio/opentelemetry/instrumentation/api/internal/SchemaUrlProvider;)Ljava/util/stream/Stream;
    .locals 0

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/instrumentation/api/internal/SchemaUrlProvider;->internalGetSchemaUrl()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    new-array p0, p0, [Ljava/lang/String;

    .line 9
    .line 10
    invoke-static {p0}, Ljava/util/stream/Stream;->of([Ljava/lang/Object;)Ljava/util/stream/Stream;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :cond_0
    invoke-static {p0}, Ljava/util/stream/Stream;->of(Ljava/lang/Object;)Ljava/util/stream/Stream;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method private static synthetic lambda$getSpanKeysFromAttributesExtractors$2(Lio/opentelemetry/instrumentation/api/internal/SpanKeyProvider;)Ljava/util/stream/Stream;
    .locals 0

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/instrumentation/api/internal/SpanKeyProvider;->internalGetSpanKey()Lio/opentelemetry/instrumentation/api/internal/SpanKey;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    new-array p0, p0, [Lio/opentelemetry/instrumentation/api/internal/SpanKey;

    .line 9
    .line 10
    invoke-static {p0}, Ljava/util/stream/Stream;->of([Ljava/lang/Object;)Ljava/util/stream/Stream;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :cond_0
    invoke-static {p0}, Ljava/util/stream/Stream;->of(Ljava/lang/Object;)Ljava/util/stream/Stream;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method private static synthetic lambda$static$0(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->operationListenerAttributesExtractors:Ljava/util/List;

    .line 2
    .line 3
    const-string v0, "operationListenerAttributesExtractor"

    .line 4
    .line 5
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    check-cast p1, Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;

    .line 9
    .line 10
    invoke-interface {p0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method private propagateOperationListenersToOnEnd()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->propagateOperationListenersToOnEnd:Z

    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public addAttributesExtractor(Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "-TREQUEST;-TRESPONSE;>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->attributesExtractors:Ljava/util/List;

    .line 2
    .line 3
    const-string v1, "attributesExtractor"

    .line 4
    .line 5
    invoke-static {p1, v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    check-cast p1, Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;

    .line 9
    .line 10
    invoke-interface {v0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    return-object p0
.end method

.method public addAttributesExtractors(Ljava/lang/Iterable;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Iterable<",
            "+",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "-TREQUEST;-TRESPONSE;>;>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/instrumenter/d;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/api/instrumenter/d;-><init>(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, v0}, Ljava/lang/Iterable;->forEach(Ljava/util/function/Consumer;)V

    .line 7
    .line 8
    .line 9
    return-object p0
.end method

.method public addContextCustomizer(Lio/opentelemetry/instrumentation/api/instrumenter/ContextCustomizer;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/ContextCustomizer<",
            "-TREQUEST;>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->contextCustomizers:Ljava/util/List;

    .line 2
    .line 3
    const-string v1, "contextCustomizer"

    .line 4
    .line 5
    invoke-static {p1, v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    check-cast p1, Lio/opentelemetry/instrumentation/api/instrumenter/ContextCustomizer;

    .line 9
    .line 10
    invoke-interface {v0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    return-object p0
.end method

.method public addOperationListener(Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;",
            ")",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->operationListeners:Ljava/util/List;

    .line 2
    .line 3
    const-string v1, "operationListener"

    .line 4
    .line 5
    invoke-static {p1, v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    check-cast p1, Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;

    .line 9
    .line 10
    invoke-interface {v0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    return-object p0
.end method

.method public addOperationMetrics(Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;",
            ")",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->operationMetrics:Ljava/util/List;

    .line 2
    .line 3
    const-string v1, "operationMetrics"

    .line 4
    .line 5
    invoke-static {p1, v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    check-cast p1, Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;

    .line 9
    .line 10
    invoke-interface {v0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    return-object p0
.end method

.method public addSpanLinksExtractor(Lio/opentelemetry/instrumentation/api/instrumenter/SpanLinksExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanLinksExtractor<",
            "TREQUEST;>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->spanLinksExtractors:Ljava/util/List;

    .line 2
    .line 3
    const-string v1, "spanLinksExtractor"

    .line 4
    .line 5
    invoke-static {p1, v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    check-cast p1, Lio/opentelemetry/instrumentation/api/instrumenter/SpanLinksExtractor;

    .line 9
    .line 10
    invoke-interface {v0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    return-object p0
.end method

.method public buildClientInstrumenter(Lio/opentelemetry/context/propagation/TextMapSetter;)Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/context/propagation/TextMapSetter<",
            "TREQUEST;>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    const-string v0, "setter"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    check-cast p1, Lio/opentelemetry/context/propagation/TextMapSetter;

    .line 7
    .line 8
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$InstrumenterConstructor;->propagatingToDownstream(Lio/opentelemetry/context/propagation/TextMapSetter;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$InstrumenterConstructor;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    invoke-static {}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;->alwaysClient()Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-direct {p0, p1, v0}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->buildInstrumenter(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$InstrumenterConstructor;Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method public buildConsumerInstrumenter(Lio/opentelemetry/context/propagation/TextMapGetter;)Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/context/propagation/TextMapGetter<",
            "TREQUEST;>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    const-string v0, "getter"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    check-cast p1, Lio/opentelemetry/context/propagation/TextMapGetter;

    .line 7
    .line 8
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$InstrumenterConstructor;->propagatingFromUpstream(Lio/opentelemetry/context/propagation/TextMapGetter;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$InstrumenterConstructor;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    invoke-static {}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;->alwaysConsumer()Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-direct {p0, p1, v0}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->buildInstrumenter(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$InstrumenterConstructor;Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method public buildDownstreamInstrumenter(Lio/opentelemetry/context/propagation/TextMapSetter;Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/context/propagation/TextMapSetter<",
            "TREQUEST;>;",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor<",
            "TREQUEST;>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    const-string v0, "setter"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    check-cast p1, Lio/opentelemetry/context/propagation/TextMapSetter;

    .line 7
    .line 8
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$InstrumenterConstructor;->propagatingToDownstream(Lio/opentelemetry/context/propagation/TextMapSetter;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$InstrumenterConstructor;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->buildInstrumenter(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$InstrumenterConstructor;Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method

.method public buildInstrumenter()Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    invoke-static {}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$InstrumenterConstructor;->internal()Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$InstrumenterConstructor;

    move-result-object v0

    invoke-static {}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;->alwaysInternal()Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;

    move-result-object v1

    .line 2
    invoke-direct {p0, v0, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->buildInstrumenter(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$InstrumenterConstructor;Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    move-result-object p0

    return-object p0
.end method

.method public buildInstrumenter(Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor<",
            "-TREQUEST;>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 3
    invoke-static {}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$InstrumenterConstructor;->internal()Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$InstrumenterConstructor;

    move-result-object v0

    const-string v1, "spanKindExtractor"

    invoke-static {p1, v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    check-cast p1, Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;

    .line 4
    invoke-direct {p0, v0, p1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->buildInstrumenter(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$InstrumenterConstructor;Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    move-result-object p0

    return-object p0
.end method

.method public buildOperationListeners()Ljava/util/List;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->operationMetrics:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    new-instance v0, Ljava/util/ArrayList;

    .line 10
    .line 11
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->operationListeners:Ljava/util/List;

    .line 12
    .line 13
    invoke-direct {v0, p0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 14
    .line 15
    .line 16
    return-object v0

    .line 17
    :cond_0
    new-instance v0, Ljava/util/ArrayList;

    .line 18
    .line 19
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->operationListeners:Ljava/util/List;

    .line 20
    .line 21
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    iget-object v2, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->operationMetrics:Ljava/util/List;

    .line 26
    .line 27
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    add-int/2addr v2, v1

    .line 32
    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 33
    .line 34
    .line 35
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->operationListeners:Ljava/util/List;

    .line 36
    .line 37
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 38
    .line 39
    .line 40
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->openTelemetry:Lio/opentelemetry/api/OpenTelemetry;

    .line 41
    .line 42
    invoke-interface {v1}, Lio/opentelemetry/api/OpenTelemetry;->getMeterProvider()Lio/opentelemetry/api/metrics/MeterProvider;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    iget-object v2, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->instrumentationName:Ljava/lang/String;

    .line 47
    .line 48
    invoke-interface {v1, v2}, Lio/opentelemetry/api/metrics/MeterProvider;->meterBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/MeterBuilder;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    iget-object v2, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->instrumentationVersion:Ljava/lang/String;

    .line 53
    .line 54
    if-eqz v2, :cond_1

    .line 55
    .line 56
    invoke-interface {v1, v2}, Lio/opentelemetry/api/metrics/MeterBuilder;->setInstrumentationVersion(Ljava/lang/String;)Lio/opentelemetry/api/metrics/MeterBuilder;

    .line 57
    .line 58
    .line 59
    :cond_1
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->getSchemaUrl()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    if-eqz v2, :cond_2

    .line 64
    .line 65
    invoke-interface {v1, v2}, Lio/opentelemetry/api/metrics/MeterBuilder;->setSchemaUrl(Ljava/lang/String;)Lio/opentelemetry/api/metrics/MeterBuilder;

    .line 66
    .line 67
    .line 68
    :cond_2
    invoke-interface {v1}, Lio/opentelemetry/api/metrics/MeterBuilder;->build()Lio/opentelemetry/api/metrics/Meter;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->operationMetrics:Ljava/util/List;

    .line 73
    .line 74
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 79
    .line 80
    .line 81
    move-result v2

    .line 82
    if-eqz v2, :cond_3

    .line 83
    .line 84
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v2

    .line 88
    check-cast v2, Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;

    .line 89
    .line 90
    invoke-interface {v2, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;->create(Lio/opentelemetry/api/metrics/Meter;)Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;

    .line 91
    .line 92
    .line 93
    move-result-object v2

    .line 94
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    goto :goto_0

    .line 98
    :cond_3
    return-object v0
.end method

.method public buildProducerInstrumenter(Lio/opentelemetry/context/propagation/TextMapSetter;)Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/context/propagation/TextMapSetter<",
            "TREQUEST;>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    const-string v0, "setter"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    check-cast p1, Lio/opentelemetry/context/propagation/TextMapSetter;

    .line 7
    .line 8
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$InstrumenterConstructor;->propagatingToDownstream(Lio/opentelemetry/context/propagation/TextMapSetter;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$InstrumenterConstructor;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    invoke-static {}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;->alwaysProducer()Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-direct {p0, p1, v0}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->buildInstrumenter(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$InstrumenterConstructor;Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method public buildServerInstrumenter(Lio/opentelemetry/context/propagation/TextMapGetter;)Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/context/propagation/TextMapGetter<",
            "TREQUEST;>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    const-string v0, "getter"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    check-cast p1, Lio/opentelemetry/context/propagation/TextMapGetter;

    .line 7
    .line 8
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$InstrumenterConstructor;->propagatingFromUpstream(Lio/opentelemetry/context/propagation/TextMapGetter;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$InstrumenterConstructor;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    invoke-static {}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;->alwaysServer()Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-direct {p0, p1, v0}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->buildInstrumenter(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$InstrumenterConstructor;Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method public buildSpanSuppressor()Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$ByContextKey;

    .line 2
    .line 3
    sget-object v1, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->spanSuppressionStrategy:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;

    .line 4
    .line 5
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->getSpanKeysFromAttributesExtractors()Ljava/util/Set;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-virtual {v1, p0}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;->create(Ljava/util/Set;)Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$ByContextKey;-><init>(Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;)V

    .line 14
    .line 15
    .line 16
    return-object v0
.end method

.method public buildTracer()Lio/opentelemetry/api/trace/Tracer;
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->openTelemetry:Lio/opentelemetry/api/OpenTelemetry;

    .line 2
    .line 3
    invoke-interface {v0}, Lio/opentelemetry/api/OpenTelemetry;->getTracerProvider()Lio/opentelemetry/api/trace/TracerProvider;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->instrumentationName:Ljava/lang/String;

    .line 8
    .line 9
    invoke-interface {v0, v1}, Lio/opentelemetry/api/trace/TracerProvider;->tracerBuilder(Ljava/lang/String;)Lio/opentelemetry/api/trace/TracerBuilder;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->instrumentationVersion:Ljava/lang/String;

    .line 14
    .line 15
    if-eqz v1, :cond_0

    .line 16
    .line 17
    invoke-interface {v0, v1}, Lio/opentelemetry/api/trace/TracerBuilder;->setInstrumentationVersion(Ljava/lang/String;)Lio/opentelemetry/api/trace/TracerBuilder;

    .line 18
    .line 19
    .line 20
    :cond_0
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->getSchemaUrl()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    if-eqz p0, :cond_1

    .line 25
    .line 26
    invoke-interface {v0, p0}, Lio/opentelemetry/api/trace/TracerBuilder;->setSchemaUrl(Ljava/lang/String;)Lio/opentelemetry/api/trace/TracerBuilder;

    .line 27
    .line 28
    .line 29
    :cond_1
    invoke-interface {v0}, Lio/opentelemetry/api/trace/TracerBuilder;->build()Lio/opentelemetry/api/trace/Tracer;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0
.end method

.method public buildUpstreamInstrumenter(Lio/opentelemetry/context/propagation/TextMapGetter;Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/context/propagation/TextMapGetter<",
            "TREQUEST;>;",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor<",
            "TREQUEST;>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    const-string v0, "getter"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    check-cast p1, Lio/opentelemetry/context/propagation/TextMapGetter;

    .line 7
    .line 8
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$InstrumenterConstructor;->propagatingFromUpstream(Lio/opentelemetry/context/propagation/TextMapGetter;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$InstrumenterConstructor;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->buildInstrumenter(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder$InstrumenterConstructor;Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method

.method public setEnabled(Z)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(Z)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iput-boolean p1, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->enabled:Z

    .line 2
    .line 3
    return-object p0
.end method

.method public setErrorCauseExtractor(Lio/opentelemetry/instrumentation/api/instrumenter/ErrorCauseExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/ErrorCauseExtractor;",
            ")",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    const-string v0, "errorCauseExtractor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    check-cast p1, Lio/opentelemetry/instrumentation/api/instrumenter/ErrorCauseExtractor;

    .line 7
    .line 8
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->errorCauseExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/ErrorCauseExtractor;

    .line 9
    .line 10
    return-object p0
.end method

.method public setInstrumentationVersion(Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    const-string v0, "instrumentationVersion"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->instrumentationVersion:Ljava/lang/String;

    .line 7
    .line 8
    return-object p0
.end method

.method public setSchemaUrl(Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    const-string v0, "schemaUrl"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->schemaUrl:Ljava/lang/String;

    .line 7
    .line 8
    return-object p0
.end method

.method public setSpanStatusExtractor(Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor<",
            "-TREQUEST;-TRESPONSE;>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    const-string v0, "spanStatusExtractor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    check-cast p1, Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor;

    .line 7
    .line 8
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->spanStatusExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor;

    .line 9
    .line 10
    return-object p0
.end method
