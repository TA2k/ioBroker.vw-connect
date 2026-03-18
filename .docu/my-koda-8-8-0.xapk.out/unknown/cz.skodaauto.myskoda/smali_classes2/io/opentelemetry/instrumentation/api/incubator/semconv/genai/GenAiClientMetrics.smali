.class public final Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiClientMetrics;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiClientMetrics$State;
    }
.end annotation


# static fields
.field private static final GEN_AI_CLIENT_METRICS_STATE:Lio/opentelemetry/context/ContextKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/context/ContextKey<",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiClientMetrics$State;",
            ">;"
        }
    .end annotation
.end field

.field static final GEN_AI_TOKEN_TYPE:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private static final NANOS_PER_S:D

.field private static final logger:Ljava/util/logging/Logger;


# instance fields
.field private final operationDuration:Lio/opentelemetry/api/metrics/DoubleHistogram;

.field private final tokenUsage:Lio/opentelemetry/api/metrics/LongHistogram;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    sget-object v0, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 2
    .line 3
    const-wide/16 v1, 0x1

    .line 4
    .line 5
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    long-to-double v0, v0

    .line 10
    sput-wide v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiClientMetrics;->NANOS_PER_S:D

    .line 11
    .line 12
    const-string v0, "gen-ai-client-metrics-state"

    .line 13
    .line 14
    invoke-static {v0}, Lio/opentelemetry/context/ContextKey;->named(Ljava/lang/String;)Lio/opentelemetry/context/ContextKey;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiClientMetrics;->GEN_AI_CLIENT_METRICS_STATE:Lio/opentelemetry/context/ContextKey;

    .line 19
    .line 20
    const-class v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientMetrics;

    .line 21
    .line 22
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-static {v0}, Ljava/util/logging/Logger;->getLogger(Ljava/lang/String;)Ljava/util/logging/Logger;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiClientMetrics;->logger:Ljava/util/logging/Logger;

    .line 31
    .line 32
    const-string v0, "gen_ai.token.type"

    .line 33
    .line 34
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiClientMetrics;->GEN_AI_TOKEN_TYPE:Lio/opentelemetry/api/common/AttributeKey;

    .line 39
    .line 40
    return-void
.end method

.method private constructor <init>(Lio/opentelemetry/api/metrics/Meter;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "gen_ai.client.token.usage"

    .line 5
    .line 6
    invoke-interface {p1, v0}, Lio/opentelemetry/api/metrics/Meter;->histogramBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-interface {v0}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->ofLongs()Lio/opentelemetry/api/metrics/LongHistogramBuilder;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    const-string v1, "{token}"

    .line 15
    .line 16
    invoke-interface {v0, v1}, Lio/opentelemetry/api/metrics/LongHistogramBuilder;->setUnit(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongHistogramBuilder;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    const-string v1, "Measures number of input and output tokens used."

    .line 21
    .line 22
    invoke-interface {v0, v1}, Lio/opentelemetry/api/metrics/LongHistogramBuilder;->setDescription(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongHistogramBuilder;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    sget-object v1, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiMetricsAdvice;->CLIENT_TOKEN_USAGE_BUCKETS:Ljava/util/List;

    .line 27
    .line 28
    invoke-interface {v0, v1}, Lio/opentelemetry/api/metrics/LongHistogramBuilder;->setExplicitBucketBoundariesAdvice(Ljava/util/List;)Lio/opentelemetry/api/metrics/LongHistogramBuilder;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    invoke-static {v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiMetricsAdvice;->applyClientTokenUsageAdvice(Lio/opentelemetry/api/metrics/LongHistogramBuilder;)V

    .line 33
    .line 34
    .line 35
    invoke-interface {v0}, Lio/opentelemetry/api/metrics/LongHistogramBuilder;->build()Lio/opentelemetry/api/metrics/LongHistogram;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiClientMetrics;->tokenUsage:Lio/opentelemetry/api/metrics/LongHistogram;

    .line 40
    .line 41
    const-string v0, "gen_ai.client.operation.duration"

    .line 42
    .line 43
    invoke-interface {p1, v0}, Lio/opentelemetry/api/metrics/Meter;->histogramBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    const-string v0, "s"

    .line 48
    .line 49
    invoke-interface {p1, v0}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->setUnit(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    const-string v0, "GenAI operation duration."

    .line 54
    .line 55
    invoke-interface {p1, v0}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->setDescription(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiMetricsAdvice;->CLIENT_OPERATION_DURATION_BUCKETS:Ljava/util/List;

    .line 60
    .line 61
    invoke-interface {p1, v0}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->setExplicitBucketBoundariesAdvice(Ljava/util/List;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiMetricsAdvice;->applyClientOperationDurationAdvice(Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;)V

    .line 66
    .line 67
    .line 68
    invoke-interface {p1}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->build()Lio/opentelemetry/api/metrics/DoubleHistogram;

    .line 69
    .line 70
    .line 71
    move-result-object p1

    .line 72
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiClientMetrics;->operationDuration:Lio/opentelemetry/api/metrics/DoubleHistogram;

    .line 73
    .line 74
    return-void
.end method

.method public static synthetic a(Lio/opentelemetry/api/metrics/Meter;)Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiClientMetrics;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiClientMetrics;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiClientMetrics;-><init>(Lio/opentelemetry/api/metrics/Meter;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static get()Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;
    .locals 2

    .line 1
    new-instance v0, Lfx0/d;

    .line 2
    .line 3
    const/16 v1, 0xa

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lfx0/d;-><init>(I)V

    .line 6
    .line 7
    .line 8
    const-string v1, "gen_ai client"

    .line 9
    .line 10
    invoke-static {v1, v0}, Lio/opentelemetry/instrumentation/api/internal/OperationMetricsUtil;->create(Ljava/lang/String;Ljava/util/function/Function;)Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    return-object v0
.end method


# virtual methods
.method public onEnd(Lio/opentelemetry/context/Context;Lio/opentelemetry/api/common/Attributes;J)V
    .locals 5

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiClientMetrics;->GEN_AI_CLIENT_METRICS_STATE:Lio/opentelemetry/context/ContextKey;

    .line 2
    .line 3
    invoke-interface {p1, v0}, Lio/opentelemetry/context/Context;->get(Lio/opentelemetry/context/ContextKey;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiClientMetrics$State;

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    sget-object p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiClientMetrics;->logger:Ljava/util/logging/Logger;

    .line 12
    .line 13
    sget-object p2, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    .line 14
    .line 15
    const-string p3, "No state present when ending context {0}. Cannot record gen_ai operation metrics."

    .line 16
    .line 17
    invoke-virtual {p0, p2, p3, p1}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    invoke-virtual {v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiClientMetrics$State;->startAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    invoke-interface {v1}, Lio/opentelemetry/api/common/Attributes;->toBuilder()Lio/opentelemetry/api/common/AttributesBuilder;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    invoke-interface {v1, p2}, Lio/opentelemetry/api/common/AttributesBuilder;->putAll(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    iget-object v2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiClientMetrics;->operationDuration:Lio/opentelemetry/api/metrics/DoubleHistogram;

    .line 34
    .line 35
    invoke-virtual {v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiClientMetrics$State;->startTimeNanos()J

    .line 36
    .line 37
    .line 38
    move-result-wide v3

    .line 39
    sub-long/2addr p3, v3

    .line 40
    long-to-double p3, p3

    .line 41
    sget-wide v3, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiClientMetrics;->NANOS_PER_S:D

    .line 42
    .line 43
    div-double/2addr p3, v3

    .line 44
    invoke-interface {v1}, Lio/opentelemetry/api/common/AttributesBuilder;->build()Lio/opentelemetry/api/common/Attributes;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    invoke-interface {v2, p3, p4, v0, p1}, Lio/opentelemetry/api/metrics/DoubleHistogram;->record(DLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V

    .line 49
    .line 50
    .line 51
    sget-object p3, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_USAGE_INPUT_TOKENS:Lio/opentelemetry/api/common/AttributeKey;

    .line 52
    .line 53
    invoke-interface {p2, p3}, Lio/opentelemetry/api/common/Attributes;->get(Lio/opentelemetry/api/common/AttributeKey;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object p3

    .line 57
    check-cast p3, Ljava/lang/Long;

    .line 58
    .line 59
    if-eqz p3, :cond_1

    .line 60
    .line 61
    iget-object p4, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiClientMetrics;->tokenUsage:Lio/opentelemetry/api/metrics/LongHistogram;

    .line 62
    .line 63
    invoke-virtual {p3}, Ljava/lang/Long;->longValue()J

    .line 64
    .line 65
    .line 66
    move-result-wide v2

    .line 67
    sget-object p3, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiClientMetrics;->GEN_AI_TOKEN_TYPE:Lio/opentelemetry/api/common/AttributeKey;

    .line 68
    .line 69
    const-string v0, "input"

    .line 70
    .line 71
    invoke-interface {v1, p3, v0}, Lio/opentelemetry/api/common/AttributesBuilder;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 72
    .line 73
    .line 74
    move-result-object p3

    .line 75
    invoke-interface {p3}, Lio/opentelemetry/api/common/AttributesBuilder;->build()Lio/opentelemetry/api/common/Attributes;

    .line 76
    .line 77
    .line 78
    move-result-object p3

    .line 79
    invoke-interface {p4, v2, v3, p3, p1}, Lio/opentelemetry/api/metrics/LongHistogram;->record(JLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V

    .line 80
    .line 81
    .line 82
    :cond_1
    sget-object p3, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiAttributesExtractor;->GEN_AI_USAGE_OUTPUT_TOKENS:Lio/opentelemetry/api/common/AttributeKey;

    .line 83
    .line 84
    invoke-interface {p2, p3}, Lio/opentelemetry/api/common/Attributes;->get(Lio/opentelemetry/api/common/AttributeKey;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p2

    .line 88
    check-cast p2, Ljava/lang/Long;

    .line 89
    .line 90
    if-eqz p2, :cond_2

    .line 91
    .line 92
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiClientMetrics;->tokenUsage:Lio/opentelemetry/api/metrics/LongHistogram;

    .line 93
    .line 94
    invoke-virtual {p2}, Ljava/lang/Long;->longValue()J

    .line 95
    .line 96
    .line 97
    move-result-wide p2

    .line 98
    sget-object p4, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiClientMetrics;->GEN_AI_TOKEN_TYPE:Lio/opentelemetry/api/common/AttributeKey;

    .line 99
    .line 100
    const-string v0, "output"

    .line 101
    .line 102
    invoke-interface {v1, p4, v0}, Lio/opentelemetry/api/common/AttributesBuilder;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 103
    .line 104
    .line 105
    move-result-object p4

    .line 106
    invoke-interface {p4}, Lio/opentelemetry/api/common/AttributesBuilder;->build()Lio/opentelemetry/api/common/Attributes;

    .line 107
    .line 108
    .line 109
    move-result-object p4

    .line 110
    invoke-interface {p0, p2, p3, p4, p1}, Lio/opentelemetry/api/metrics/LongHistogram;->record(JLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V

    .line 111
    .line 112
    .line 113
    :cond_2
    return-void
.end method

.method public onStart(Lio/opentelemetry/context/Context;Lio/opentelemetry/api/common/Attributes;J)Lio/opentelemetry/context/Context;
    .locals 1

    .line 1
    sget-object p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/GenAiClientMetrics;->GEN_AI_CLIENT_METRICS_STATE:Lio/opentelemetry/context/ContextKey;

    .line 2
    .line 3
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/AutoValue_GenAiClientMetrics_State;

    .line 4
    .line 5
    invoke-direct {v0, p2, p3, p4}, Lio/opentelemetry/instrumentation/api/incubator/semconv/genai/AutoValue_GenAiClientMetrics_State;-><init>(Lio/opentelemetry/api/common/Attributes;J)V

    .line 6
    .line 7
    .line 8
    invoke-interface {p1, p0, v0}, Lio/opentelemetry/context/Context;->with(Lio/opentelemetry/context/ContextKey;Ljava/lang/Object;)Lio/opentelemetry/context/Context;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0
.end method
