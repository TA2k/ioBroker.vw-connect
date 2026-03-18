.class public Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;
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
.field private static final START_OPERATION_LISTENERS:Lio/opentelemetry/context/ContextKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/context/ContextKey<",
            "[",
            "Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;",
            ">;"
        }
    .end annotation
.end field

.field private static final supportability:Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;


# instance fields
.field private final attributesExtractors:[Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "[",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "-TREQUEST;-TRESPONSE;>;"
        }
    .end annotation
.end field

.field private final contextCustomizers:[Lio/opentelemetry/instrumentation/api/instrumenter/ContextCustomizer;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "[",
            "Lio/opentelemetry/instrumentation/api/instrumenter/ContextCustomizer<",
            "-TREQUEST;>;"
        }
    .end annotation
.end field

.field private final enabled:Z

.field private final errorCauseExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/ErrorCauseExtractor;

.field private final instrumentationName:Ljava/lang/String;

.field private final operationListenerAttributesExtractors:[Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "[",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "-TREQUEST;-TRESPONSE;>;"
        }
    .end annotation
.end field

.field private final operationListeners:[Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;

.field private final propagateOperationListenersToOnEnd:Z

.field private final spanKindExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor<",
            "-TREQUEST;>;"
        }
    .end annotation
.end field

.field private final spanLinksExtractors:[Lio/opentelemetry/instrumentation/api/instrumenter/SpanLinksExtractor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "[",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanLinksExtractor<",
            "-TREQUEST;>;"
        }
    .end annotation
.end field

.field private final spanNameExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor<",
            "-TREQUEST;>;"
        }
    .end annotation
.end field

.field private final spanStatusExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor<",
            "-TREQUEST;-TRESPONSE;>;"
        }
    .end annotation
.end field

.field private final spanSuppressor:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;

.field private final tracer:Lio/opentelemetry/api/trace/Tracer;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "instrumenter-start-operation-listeners"

    .line 2
    .line 3
    invoke-static {v0}, Lio/opentelemetry/context/ContextKey;->named(Ljava/lang/String;)Lio/opentelemetry/context/ContextKey;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->START_OPERATION_LISTENERS:Lio/opentelemetry/context/ContextKey;

    .line 8
    .line 9
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->instance()Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    sput-object v0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->supportability:Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;

    .line 14
    .line 15
    new-instance v0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter$1;

    .line 16
    .line 17
    invoke-direct {v0}, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter$1;-><init>()V

    .line 18
    .line 19
    .line 20
    invoke-static {v0}, Lio/opentelemetry/instrumentation/api/internal/InstrumenterUtil;->setInstrumenterAccess(Lio/opentelemetry/instrumentation/api/internal/InstrumenterAccess;)V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p1, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->instrumentationName:Ljava/lang/String;

    .line 5
    .line 6
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->instrumentationName:Ljava/lang/String;

    .line 7
    .line 8
    invoke-virtual {p1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->buildTracer()Lio/opentelemetry/api/trace/Tracer;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->tracer:Lio/opentelemetry/api/trace/Tracer;

    .line 13
    .line 14
    iget-object v0, p1, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->spanNameExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;

    .line 15
    .line 16
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->spanNameExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;

    .line 17
    .line 18
    iget-object v0, p1, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->spanKindExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;

    .line 19
    .line 20
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->spanKindExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;

    .line 21
    .line 22
    iget-object v0, p1, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->spanStatusExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor;

    .line 23
    .line 24
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->spanStatusExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor;

    .line 25
    .line 26
    iget-object v0, p1, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->spanLinksExtractors:Ljava/util/List;

    .line 27
    .line 28
    const/4 v1, 0x0

    .line 29
    new-array v2, v1, [Lio/opentelemetry/instrumentation/api/instrumenter/SpanLinksExtractor;

    .line 30
    .line 31
    invoke-interface {v0, v2}, Ljava/util/List;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    check-cast v0, [Lio/opentelemetry/instrumentation/api/instrumenter/SpanLinksExtractor;

    .line 36
    .line 37
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->spanLinksExtractors:[Lio/opentelemetry/instrumentation/api/instrumenter/SpanLinksExtractor;

    .line 38
    .line 39
    iget-object v0, p1, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->attributesExtractors:Ljava/util/List;

    .line 40
    .line 41
    new-array v2, v1, [Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;

    .line 42
    .line 43
    invoke-interface {v0, v2}, Ljava/util/List;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    check-cast v0, [Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;

    .line 48
    .line 49
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->attributesExtractors:[Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;

    .line 50
    .line 51
    iget-object v0, p1, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->contextCustomizers:Ljava/util/List;

    .line 52
    .line 53
    new-array v2, v1, [Lio/opentelemetry/instrumentation/api/instrumenter/ContextCustomizer;

    .line 54
    .line 55
    invoke-interface {v0, v2}, Ljava/util/List;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    check-cast v0, [Lio/opentelemetry/instrumentation/api/instrumenter/ContextCustomizer;

    .line 60
    .line 61
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->contextCustomizers:[Lio/opentelemetry/instrumentation/api/instrumenter/ContextCustomizer;

    .line 62
    .line 63
    invoke-virtual {p1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->buildOperationListeners()Ljava/util/List;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    new-array v2, v1, [Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;

    .line 68
    .line 69
    invoke-interface {v0, v2}, Ljava/util/List;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    check-cast v0, [Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;

    .line 74
    .line 75
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->operationListeners:[Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;

    .line 76
    .line 77
    iget-object v0, p1, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->operationListenerAttributesExtractors:Ljava/util/List;

    .line 78
    .line 79
    new-array v1, v1, [Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;

    .line 80
    .line 81
    invoke-interface {v0, v1}, Ljava/util/List;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    check-cast v0, [Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;

    .line 86
    .line 87
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->operationListenerAttributesExtractors:[Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;

    .line 88
    .line 89
    iget-object v0, p1, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->errorCauseExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/ErrorCauseExtractor;

    .line 90
    .line 91
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->errorCauseExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/ErrorCauseExtractor;

    .line 92
    .line 93
    iget-boolean v0, p1, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->propagateOperationListenersToOnEnd:Z

    .line 94
    .line 95
    iput-boolean v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->propagateOperationListenersToOnEnd:Z

    .line 96
    .line 97
    iget-boolean v0, p1, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->enabled:Z

    .line 98
    .line 99
    iput-boolean v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->enabled:Z

    .line 100
    .line 101
    invoke-virtual {p1}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;->buildSpanSuppressor()Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;

    .line 102
    .line 103
    .line 104
    move-result-object p1

    .line 105
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->spanSuppressor:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;

    .line 106
    .line 107
    return-void
.end method

.method public static synthetic access$000(Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;)Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->spanKindExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;

    .line 2
    .line 3
    return-object p0
.end method

.method public static synthetic access$100(Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;)Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->spanSuppressor:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;

    .line 2
    .line 3
    return-object p0
.end method

.method public static builder(Lio/opentelemetry/api/OpenTelemetry;Ljava/lang/String;Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;)Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            "RESPONSE:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/OpenTelemetry;",
            "Ljava/lang/String;",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor<",
            "-TREQUEST;>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1, p2}, Lio/opentelemetry/instrumentation/api/instrumenter/InstrumenterBuilder;-><init>(Lio/opentelemetry/api/OpenTelemetry;Ljava/lang/String;Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method private doEnd(Lio/opentelemetry/context/Context;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;Ljava/time/Instant;)V
    .locals 10
    .param p3    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p4    # Ljava/lang/Throwable;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p5    # Ljava/time/Instant;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/context/Context;",
            "TREQUEST;TRESPONSE;",
            "Ljava/lang/Throwable;",
            "Ljava/time/Instant;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-static {p1}, Lio/opentelemetry/api/trace/Span;->fromContext(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/trace/Span;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz p4, :cond_0

    .line 6
    .line 7
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->errorCauseExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/ErrorCauseExtractor;

    .line 8
    .line 9
    invoke-interface {v1, p4}, Lio/opentelemetry/instrumentation/api/instrumenter/ErrorCauseExtractor;->extract(Ljava/lang/Throwable;)Ljava/lang/Throwable;

    .line 10
    .line 11
    .line 12
    move-result-object p4

    .line 13
    invoke-interface {v0, p4}, Lio/opentelemetry/api/trace/Span;->recordException(Ljava/lang/Throwable;)Lio/opentelemetry/api/trace/Span;

    .line 14
    .line 15
    .line 16
    :cond_0
    move-object v6, p4

    .line 17
    new-instance v2, Lio/opentelemetry/instrumentation/api/instrumenter/UnsafeAttributes;

    .line 18
    .line 19
    invoke-direct {v2}, Lio/opentelemetry/instrumentation/api/instrumenter/UnsafeAttributes;-><init>()V

    .line 20
    .line 21
    .line 22
    iget-object p4, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->attributesExtractors:[Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;

    .line 23
    .line 24
    array-length v7, p4

    .line 25
    const/4 v8, 0x0

    .line 26
    move v9, v8

    .line 27
    :goto_0
    if-ge v9, v7, :cond_1

    .line 28
    .line 29
    aget-object v1, p4, v9

    .line 30
    .line 31
    move-object v3, p1

    .line 32
    move-object v4, p2

    .line 33
    move-object v5, p3

    .line 34
    invoke-interface/range {v1 .. v6}, Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;->onEnd(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/context/Context;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 35
    .line 36
    .line 37
    add-int/lit8 v9, v9, 0x1

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_1
    move-object v3, p1

    .line 41
    move-object v4, p2

    .line 42
    move-object v5, p3

    .line 43
    invoke-interface {v0, v2}, Lio/opentelemetry/api/trace/Span;->setAllAttributes(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/trace/Span;

    .line 44
    .line 45
    .line 46
    sget-object p1, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->START_OPERATION_LISTENERS:Lio/opentelemetry/context/ContextKey;

    .line 47
    .line 48
    invoke-interface {v3, p1}, Lio/opentelemetry/context/Context;->get(Lio/opentelemetry/context/ContextKey;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    check-cast p1, [Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;

    .line 53
    .line 54
    if-nez p1, :cond_2

    .line 55
    .line 56
    iget-object p1, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->operationListeners:[Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;

    .line 57
    .line 58
    :cond_2
    array-length p2, p1

    .line 59
    if-eqz p2, :cond_5

    .line 60
    .line 61
    iget-object p2, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->operationListenerAttributesExtractors:[Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;

    .line 62
    .line 63
    array-length p2, p2

    .line 64
    if-eqz p2, :cond_3

    .line 65
    .line 66
    move-object p2, v2

    .line 67
    new-instance v2, Lio/opentelemetry/instrumentation/api/instrumenter/UnsafeAttributes;

    .line 68
    .line 69
    invoke-direct {v2}, Lio/opentelemetry/instrumentation/api/instrumenter/UnsafeAttributes;-><init>()V

    .line 70
    .line 71
    .line 72
    invoke-virtual {p2}, Lio/opentelemetry/instrumentation/api/instrumenter/UnsafeAttributes;->asMap()Ljava/util/Map;

    .line 73
    .line 74
    .line 75
    move-result-object p2

    .line 76
    invoke-virtual {v2, p2}, Ljava/util/AbstractMap;->putAll(Ljava/util/Map;)V

    .line 77
    .line 78
    .line 79
    iget-object p2, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->operationListenerAttributesExtractors:[Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;

    .line 80
    .line 81
    array-length p3, p2

    .line 82
    :goto_1
    if-ge v8, p3, :cond_4

    .line 83
    .line 84
    aget-object v1, p2, v8

    .line 85
    .line 86
    invoke-interface/range {v1 .. v6}, Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;->onEnd(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/context/Context;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 87
    .line 88
    .line 89
    add-int/lit8 v8, v8, 0x1

    .line 90
    .line 91
    goto :goto_1

    .line 92
    :cond_3
    move-object p2, v2

    .line 93
    :cond_4
    invoke-static {p5}, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->getNanos(Ljava/time/Instant;)J

    .line 94
    .line 95
    .line 96
    move-result-wide p2

    .line 97
    array-length p4, p1

    .line 98
    add-int/lit8 p4, p4, -0x1

    .line 99
    .line 100
    :goto_2
    if-ltz p4, :cond_5

    .line 101
    .line 102
    aget-object v1, p1, p4

    .line 103
    .line 104
    invoke-interface {v1, v3, v2, p2, p3}, Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;->onEnd(Lio/opentelemetry/context/Context;Lio/opentelemetry/api/common/Attributes;J)V

    .line 105
    .line 106
    .line 107
    add-int/lit8 p4, p4, -0x1

    .line 108
    .line 109
    goto :goto_2

    .line 110
    :cond_5
    new-instance p1, Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusBuilderImpl;

    .line 111
    .line 112
    invoke-direct {p1, v0}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusBuilderImpl;-><init>(Lio/opentelemetry/api/trace/Span;)V

    .line 113
    .line 114
    .line 115
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->spanStatusExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor;

    .line 116
    .line 117
    invoke-interface {p0, p1, v4, v5, v6}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusExtractor;->extract(Lio/opentelemetry/instrumentation/api/instrumenter/SpanStatusBuilder;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 118
    .line 119
    .line 120
    if-eqz p5, :cond_6

    .line 121
    .line 122
    invoke-interface {v0, p5}, Lio/opentelemetry/api/trace/Span;->end(Ljava/time/Instant;)V

    .line 123
    .line 124
    .line 125
    return-void

    .line 126
    :cond_6
    invoke-interface {v0}, Lio/opentelemetry/api/trace/Span;->end()V

    .line 127
    .line 128
    .line 129
    return-void
.end method

.method private doStart(Lio/opentelemetry/context/Context;Ljava/lang/Object;Ljava/time/Instant;)Lio/opentelemetry/context/Context;
    .locals 0
    .param p3    # Ljava/time/Instant;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/context/Context;",
            "TREQUEST;",
            "Ljava/time/Instant;",
            ")",
            "Lio/opentelemetry/context/Context;"
        }
    .end annotation

    .line 1
    :try_start_0
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->doStartImpl(Lio/opentelemetry/context/Context;Ljava/lang/Object;Ljava/time/Instant;)Lio/opentelemetry/context/Context;

    .line 2
    .line 3
    .line 4
    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 5
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/InstrumenterContext;->reset()V

    .line 6
    .line 7
    .line 8
    return-object p0

    .line 9
    :catchall_0
    move-exception p0

    .line 10
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/InstrumenterContext;->reset()V

    .line 11
    .line 12
    .line 13
    throw p0
.end method

.method private doStartImpl(Lio/opentelemetry/context/Context;Ljava/lang/Object;Ljava/time/Instant;)Lio/opentelemetry/context/Context;
    .locals 11
    .param p3    # Ljava/time/Instant;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/context/Context;",
            "TREQUEST;",
            "Ljava/time/Instant;",
            ")",
            "Lio/opentelemetry/context/Context;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->spanKindExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;

    .line 2
    .line 3
    invoke-interface {v0, p2}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;->extract(Ljava/lang/Object;)Lio/opentelemetry/api/trace/SpanKind;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->tracer:Lio/opentelemetry/api/trace/Tracer;

    .line 8
    .line 9
    iget-object v2, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->spanNameExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;

    .line 10
    .line 11
    invoke-interface {v2, p2}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;->extract(Ljava/lang/Object;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    invoke-interface {v1, v2}, Lio/opentelemetry/api/trace/Tracer;->spanBuilder(Ljava/lang/String;)Lio/opentelemetry/api/trace/SpanBuilder;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    invoke-interface {v1, v0}, Lio/opentelemetry/api/trace/SpanBuilder;->setSpanKind(Lio/opentelemetry/api/trace/SpanKind;)Lio/opentelemetry/api/trace/SpanBuilder;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    if-eqz p3, :cond_0

    .line 24
    .line 25
    invoke-interface {v1, p3}, Lio/opentelemetry/api/trace/SpanBuilder;->setStartTimestamp(Ljava/time/Instant;)Lio/opentelemetry/api/trace/SpanBuilder;

    .line 26
    .line 27
    .line 28
    :cond_0
    new-instance v2, Lio/opentelemetry/instrumentation/api/instrumenter/SpanLinksBuilderImpl;

    .line 29
    .line 30
    invoke-direct {v2, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanLinksBuilderImpl;-><init>(Lio/opentelemetry/api/trace/SpanBuilder;)V

    .line 31
    .line 32
    .line 33
    iget-object v3, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->spanLinksExtractors:[Lio/opentelemetry/instrumentation/api/instrumenter/SpanLinksExtractor;

    .line 34
    .line 35
    array-length v4, v3

    .line 36
    const/4 v5, 0x0

    .line 37
    move v6, v5

    .line 38
    :goto_0
    if-ge v6, v4, :cond_1

    .line 39
    .line 40
    aget-object v7, v3, v6

    .line 41
    .line 42
    invoke-interface {v7, v2, p1, p2}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanLinksExtractor;->extract(Lio/opentelemetry/instrumentation/api/instrumenter/SpanLinksBuilder;Lio/opentelemetry/context/Context;Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    add-int/lit8 v6, v6, 0x1

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_1
    new-instance v2, Lio/opentelemetry/instrumentation/api/instrumenter/UnsafeAttributes;

    .line 49
    .line 50
    invoke-direct {v2}, Lio/opentelemetry/instrumentation/api/instrumenter/UnsafeAttributes;-><init>()V

    .line 51
    .line 52
    .line 53
    iget-object v3, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->attributesExtractors:[Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;

    .line 54
    .line 55
    array-length v4, v3

    .line 56
    move v6, v5

    .line 57
    :goto_1
    if-ge v6, v4, :cond_2

    .line 58
    .line 59
    aget-object v7, v3, v6

    .line 60
    .line 61
    invoke-interface {v7, v2, p1, p2}, Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;->onStart(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/context/Context;Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    add-int/lit8 v6, v6, 0x1

    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_2
    iget-object v3, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->contextCustomizers:[Lio/opentelemetry/instrumentation/api/instrumenter/ContextCustomizer;

    .line 68
    .line 69
    array-length v4, v3

    .line 70
    move-object v7, p1

    .line 71
    move v6, v5

    .line 72
    :goto_2
    if-ge v6, v4, :cond_3

    .line 73
    .line 74
    aget-object v8, v3, v6

    .line 75
    .line 76
    invoke-interface {v8, v7, p2, v2}, Lio/opentelemetry/instrumentation/api/instrumenter/ContextCustomizer;->onStart(Lio/opentelemetry/context/Context;Ljava/lang/Object;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/context/Context;

    .line 77
    .line 78
    .line 79
    move-result-object v7

    .line 80
    add-int/lit8 v6, v6, 0x1

    .line 81
    .line 82
    goto :goto_2

    .line 83
    :cond_3
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/instrumenter/LocalRootSpan;->isLocalRoot(Lio/opentelemetry/context/Context;)Z

    .line 84
    .line 85
    .line 86
    move-result v3

    .line 87
    invoke-static {v7}, Lio/opentelemetry/instrumentation/api/instrumenter/LocalRootSpan;->fromContextOrNull(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/trace/Span;

    .line 88
    .line 89
    .line 90
    move-result-object v4

    .line 91
    if-eqz v4, :cond_4

    .line 92
    .line 93
    const/4 v4, 0x1

    .line 94
    goto :goto_3

    .line 95
    :cond_4
    move v4, v5

    .line 96
    :goto_3
    invoke-interface {v1, v2}, Lio/opentelemetry/api/trace/SpanBuilder;->setAllAttributes(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/trace/SpanBuilder;

    .line 97
    .line 98
    .line 99
    invoke-interface {v1, v7}, Lio/opentelemetry/api/trace/SpanBuilder;->setParent(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/trace/SpanBuilder;

    .line 100
    .line 101
    .line 102
    move-result-object v1

    .line 103
    invoke-interface {v1}, Lio/opentelemetry/api/trace/SpanBuilder;->startSpan()Lio/opentelemetry/api/trace/Span;

    .line 104
    .line 105
    .line 106
    move-result-object v1

    .line 107
    invoke-interface {v7, v1}, Lio/opentelemetry/context/Context;->with(Lio/opentelemetry/context/ImplicitContextKeyed;)Lio/opentelemetry/context/Context;

    .line 108
    .line 109
    .line 110
    move-result-object v6

    .line 111
    iget-object v7, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->operationListeners:[Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;

    .line 112
    .line 113
    array-length v7, v7

    .line 114
    if-eqz v7, :cond_7

    .line 115
    .line 116
    iget-object v7, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->operationListenerAttributesExtractors:[Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;

    .line 117
    .line 118
    array-length v7, v7

    .line 119
    if-eqz v7, :cond_6

    .line 120
    .line 121
    new-instance v7, Lio/opentelemetry/instrumentation/api/instrumenter/UnsafeAttributes;

    .line 122
    .line 123
    invoke-direct {v7}, Lio/opentelemetry/instrumentation/api/instrumenter/UnsafeAttributes;-><init>()V

    .line 124
    .line 125
    .line 126
    invoke-virtual {v2}, Lio/opentelemetry/instrumentation/api/instrumenter/UnsafeAttributes;->asMap()Ljava/util/Map;

    .line 127
    .line 128
    .line 129
    move-result-object v2

    .line 130
    invoke-virtual {v7, v2}, Ljava/util/AbstractMap;->putAll(Ljava/util/Map;)V

    .line 131
    .line 132
    .line 133
    iget-object v2, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->operationListenerAttributesExtractors:[Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;

    .line 134
    .line 135
    array-length v8, v2

    .line 136
    move v9, v5

    .line 137
    :goto_4
    if-ge v9, v8, :cond_5

    .line 138
    .line 139
    aget-object v10, v2, v9

    .line 140
    .line 141
    invoke-interface {v10, v7, p1, p2}, Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;->onStart(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/context/Context;Ljava/lang/Object;)V

    .line 142
    .line 143
    .line 144
    add-int/lit8 v9, v9, 0x1

    .line 145
    .line 146
    goto :goto_4

    .line 147
    :cond_5
    move-object v2, v7

    .line 148
    :cond_6
    invoke-static {p3}, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->getNanos(Ljava/time/Instant;)J

    .line 149
    .line 150
    .line 151
    move-result-wide p1

    .line 152
    iget-object p3, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->operationListeners:[Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;

    .line 153
    .line 154
    array-length v7, p3

    .line 155
    :goto_5
    if-ge v5, v7, :cond_7

    .line 156
    .line 157
    aget-object v8, p3, v5

    .line 158
    .line 159
    invoke-interface {v8, v6, v2, p1, p2}, Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;->onStart(Lio/opentelemetry/context/Context;Lio/opentelemetry/api/common/Attributes;J)Lio/opentelemetry/context/Context;

    .line 160
    .line 161
    .line 162
    move-result-object v6

    .line 163
    add-int/lit8 v5, v5, 0x1

    .line 164
    .line 165
    goto :goto_5

    .line 166
    :cond_7
    iget-boolean p1, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->propagateOperationListenersToOnEnd:Z

    .line 167
    .line 168
    if-nez p1, :cond_8

    .line 169
    .line 170
    sget-object p1, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->START_OPERATION_LISTENERS:Lio/opentelemetry/context/ContextKey;

    .line 171
    .line 172
    invoke-interface {v6, p1}, Lio/opentelemetry/context/Context;->get(Lio/opentelemetry/context/ContextKey;)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object p1

    .line 176
    if-eqz p1, :cond_9

    .line 177
    .line 178
    :cond_8
    sget-object p1, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->START_OPERATION_LISTENERS:Lio/opentelemetry/context/ContextKey;

    .line 179
    .line 180
    iget-object p2, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->operationListeners:[Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;

    .line 181
    .line 182
    invoke-interface {v6, p1, p2}, Lio/opentelemetry/context/Context;->with(Lio/opentelemetry/context/ContextKey;Ljava/lang/Object;)Lio/opentelemetry/context/Context;

    .line 183
    .line 184
    .line 185
    move-result-object v6

    .line 186
    :cond_9
    if-eqz v3, :cond_a

    .line 187
    .line 188
    invoke-static {v6, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/LocalRootSpan;->store(Lio/opentelemetry/context/Context;Lio/opentelemetry/api/trace/Span;)Lio/opentelemetry/context/Context;

    .line 189
    .line 190
    .line 191
    move-result-object v6

    .line 192
    :cond_a
    if-nez v4, :cond_b

    .line 193
    .line 194
    sget-object p1, Lio/opentelemetry/api/trace/SpanKind;->SERVER:Lio/opentelemetry/api/trace/SpanKind;

    .line 195
    .line 196
    if-ne v0, p1, :cond_b

    .line 197
    .line 198
    invoke-static {v6, v1}, Lio/opentelemetry/instrumentation/api/internal/HttpRouteState;->updateSpan(Lio/opentelemetry/context/Context;Lio/opentelemetry/api/trace/Span;)V

    .line 199
    .line 200
    .line 201
    :cond_b
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->spanSuppressor:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;

    .line 202
    .line 203
    invoke-interface {p0, v6, v0, v1}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;->storeInContext(Lio/opentelemetry/context/Context;Lio/opentelemetry/api/trace/SpanKind;Lio/opentelemetry/api/trace/Span;)Lio/opentelemetry/context/Context;

    .line 204
    .line 205
    .line 206
    move-result-object p0

    .line 207
    return-object p0
.end method

.method private static getNanos(Ljava/time/Instant;)J
    .locals 4
    .param p0    # Ljava/time/Instant;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    return-wide v0

    .line 8
    :cond_0
    sget-object v0, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 9
    .line 10
    invoke-virtual {p0}, Ljava/time/Instant;->getEpochSecond()J

    .line 11
    .line 12
    .line 13
    move-result-wide v1

    .line 14
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    .line 15
    .line 16
    .line 17
    move-result-wide v0

    .line 18
    invoke-virtual {p0}, Ljava/time/Instant;->getNano()I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    int-to-long v2, p0

    .line 23
    add-long/2addr v0, v2

    .line 24
    return-wide v0
.end method


# virtual methods
.method public end(Lio/opentelemetry/context/Context;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;)V
    .locals 6
    .param p3    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p4    # Ljava/lang/Throwable;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/context/Context;",
            "TREQUEST;TRESPONSE;",
            "Ljava/lang/Throwable;",
            ")V"
        }
    .end annotation

    .line 1
    const/4 v5, 0x0

    .line 2
    move-object v0, p0

    .line 3
    move-object v1, p1

    .line 4
    move-object v2, p2

    .line 5
    move-object v3, p3

    .line 6
    move-object v4, p4

    .line 7
    invoke-direct/range {v0 .. v5}, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->doEnd(Lio/opentelemetry/context/Context;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;Ljava/time/Instant;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public shouldStart(Lio/opentelemetry/context/Context;Ljava/lang/Object;)Z
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/context/Context;",
            "TREQUEST;)Z"
        }
    .end annotation

    .line 1
    iget-boolean v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->enabled:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return p0

    .line 7
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->spanKindExtractor:Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;

    .line 8
    .line 9
    invoke-interface {v0, p2}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanKindExtractor;->extract(Ljava/lang/Object;)Lio/opentelemetry/api/trace/SpanKind;

    .line 10
    .line 11
    .line 12
    move-result-object p2

    .line 13
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->spanSuppressor:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;

    .line 14
    .line 15
    invoke-interface {v0, p1, p2}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;->shouldSuppress(Lio/opentelemetry/context/Context;Lio/opentelemetry/api/trace/SpanKind;)Z

    .line 16
    .line 17
    .line 18
    move-result p1

    .line 19
    if-eqz p1, :cond_1

    .line 20
    .line 21
    sget-object v0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->supportability:Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;

    .line 22
    .line 23
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->instrumentationName:Ljava/lang/String;

    .line 24
    .line 25
    invoke-virtual {v0, p2, p0}, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->recordSuppressedSpan(Lio/opentelemetry/api/trace/SpanKind;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    :cond_1
    xor-int/lit8 p0, p1, 0x1

    .line 29
    .line 30
    return p0
.end method

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
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, p1, p2, v0}, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->doStart(Lio/opentelemetry/context/Context;Ljava/lang/Object;Ljava/time/Instant;)Lio/opentelemetry/context/Context;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    return-object p0
.end method

.method public startAndEnd(Lio/opentelemetry/context/Context;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;Ljava/time/Instant;Ljava/time/Instant;)Lio/opentelemetry/context/Context;
    .locals 0
    .param p3    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p4    # Ljava/lang/Throwable;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/context/Context;",
            "TREQUEST;TRESPONSE;",
            "Ljava/lang/Throwable;",
            "Ljava/time/Instant;",
            "Ljava/time/Instant;",
            ")",
            "Lio/opentelemetry/context/Context;"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2, p5}, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->doStart(Lio/opentelemetry/context/Context;Ljava/lang/Object;Ljava/time/Instant;)Lio/opentelemetry/context/Context;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    move-object p5, p6

    .line 6
    invoke-direct/range {p0 .. p5}, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->doEnd(Lio/opentelemetry/context/Context;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;Ljava/time/Instant;)V

    .line 7
    .line 8
    .line 9
    return-object p1
.end method
