.class public final Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingProducerMetrics;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingProducerMetrics$State;
    }
.end annotation


# static fields
.field private static final MESSAGING_PRODUCER_METRICS_STATE:Lio/opentelemetry/context/ContextKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/context/ContextKey<",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingProducerMetrics$State;",
            ">;"
        }
    .end annotation
.end field

.field private static final NANOS_PER_S:D

.field private static final logger:Ljava/util/logging/Logger;


# instance fields
.field private final publishDurationHistogram:Lio/opentelemetry/api/metrics/DoubleHistogram;


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
    sput-wide v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingProducerMetrics;->NANOS_PER_S:D

    .line 11
    .line 12
    const-string v0, "messaging-producer-metrics-state"

    .line 13
    .line 14
    invoke-static {v0}, Lio/opentelemetry/context/ContextKey;->named(Ljava/lang/String;)Lio/opentelemetry/context/ContextKey;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingProducerMetrics;->MESSAGING_PRODUCER_METRICS_STATE:Lio/opentelemetry/context/ContextKey;

    .line 19
    .line 20
    const-class v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingProducerMetrics;

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
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingProducerMetrics;->logger:Ljava/util/logging/Logger;

    .line 31
    .line 32
    return-void
.end method

.method private constructor <init>(Lio/opentelemetry/api/metrics/Meter;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "messaging.publish.duration"

    .line 5
    .line 6
    invoke-interface {p1, v0}, Lio/opentelemetry/api/metrics/Meter;->histogramBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    const-string v0, "Measures the duration of publish operation."

    .line 11
    .line 12
    invoke-interface {p1, v0}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->setDescription(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingMetricsAdvice;->DURATION_SECONDS_BUCKETS:Ljava/util/List;

    .line 17
    .line 18
    invoke-interface {p1, v0}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->setExplicitBucketBoundariesAdvice(Ljava/util/List;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    const-string v0, "s"

    .line 23
    .line 24
    invoke-interface {p1, v0}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->setUnit(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingMetricsAdvice;->applyPublishDurationAdvice(Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;)V

    .line 29
    .line 30
    .line 31
    invoke-interface {p1}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->build()Lio/opentelemetry/api/metrics/DoubleHistogram;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingProducerMetrics;->publishDurationHistogram:Lio/opentelemetry/api/metrics/DoubleHistogram;

    .line 36
    .line 37
    return-void
.end method

.method public static synthetic a(Lio/opentelemetry/api/metrics/Meter;)Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingProducerMetrics;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingProducerMetrics;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingProducerMetrics;-><init>(Lio/opentelemetry/api/metrics/Meter;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static get()Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/a;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/a;-><init>(I)V

    .line 5
    .line 6
    .line 7
    const-string v1, "messaging producer"

    .line 8
    .line 9
    invoke-static {v1, v0}, Lio/opentelemetry/instrumentation/api/internal/OperationMetricsUtil;->create(Ljava/lang/String;Ljava/util/function/Function;)Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    return-object v0
.end method


# virtual methods
.method public onEnd(Lio/opentelemetry/context/Context;Lio/opentelemetry/api/common/Attributes;J)V
    .locals 2

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingProducerMetrics;->MESSAGING_PRODUCER_METRICS_STATE:Lio/opentelemetry/context/ContextKey;

    .line 2
    .line 3
    invoke-interface {p1, v0}, Lio/opentelemetry/context/Context;->get(Lio/opentelemetry/context/ContextKey;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingProducerMetrics$State;

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    sget-object p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingProducerMetrics;->logger:Ljava/util/logging/Logger;

    .line 12
    .line 13
    sget-object p2, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    .line 14
    .line 15
    const-string p3, "No state present when ending context {0}. Cannot record produce publish metrics."

    .line 16
    .line 17
    invoke-virtual {p0, p2, p3, p1}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    invoke-virtual {v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingProducerMetrics$State;->startAttributes()Lio/opentelemetry/api/common/Attributes;

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
    move-result-object p2

    .line 33
    invoke-interface {p2}, Lio/opentelemetry/api/common/AttributesBuilder;->build()Lio/opentelemetry/api/common/Attributes;

    .line 34
    .line 35
    .line 36
    move-result-object p2

    .line 37
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingProducerMetrics;->publishDurationHistogram:Lio/opentelemetry/api/metrics/DoubleHistogram;

    .line 38
    .line 39
    invoke-virtual {v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingProducerMetrics$State;->startTimeNanos()J

    .line 40
    .line 41
    .line 42
    move-result-wide v0

    .line 43
    sub-long/2addr p3, v0

    .line 44
    long-to-double p3, p3

    .line 45
    sget-wide v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingProducerMetrics;->NANOS_PER_S:D

    .line 46
    .line 47
    div-double/2addr p3, v0

    .line 48
    invoke-interface {p0, p3, p4, p2, p1}, Lio/opentelemetry/api/metrics/DoubleHistogram;->record(DLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V

    .line 49
    .line 50
    .line 51
    return-void
.end method

.method public onStart(Lio/opentelemetry/context/Context;Lio/opentelemetry/api/common/Attributes;J)Lio/opentelemetry/context/Context;
    .locals 1

    .line 1
    sget-object p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/MessagingProducerMetrics;->MESSAGING_PRODUCER_METRICS_STATE:Lio/opentelemetry/context/ContextKey;

    .line 2
    .line 3
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/AutoValue_MessagingProducerMetrics_State;

    .line 4
    .line 5
    invoke-direct {v0, p2, p3, p4}, Lio/opentelemetry/instrumentation/api/incubator/semconv/messaging/AutoValue_MessagingProducerMetrics_State;-><init>(Lio/opentelemetry/api/common/Attributes;J)V

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
