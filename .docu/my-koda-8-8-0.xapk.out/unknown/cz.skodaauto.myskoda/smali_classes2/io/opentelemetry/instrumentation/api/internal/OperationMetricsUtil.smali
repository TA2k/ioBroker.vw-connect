.class public Lio/opentelemetry/instrumentation/api/internal/OperationMetricsUtil;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final NOOP_OPERATION_LISTENER:Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;

.field private static final logger:Ljava/util/logging/Logger;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/instrumentation/api/internal/OperationMetricsUtil;

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
    sput-object v0, Lio/opentelemetry/instrumentation/api/internal/OperationMetricsUtil;->logger:Ljava/util/logging/Logger;

    .line 12
    .line 13
    new-instance v0, Lio/opentelemetry/instrumentation/api/internal/OperationMetricsUtil$1;

    .line 14
    .line 15
    invoke-direct {v0}, Lio/opentelemetry/instrumentation/api/internal/OperationMetricsUtil$1;-><init>()V

    .line 16
    .line 17
    .line 18
    sput-object v0, Lio/opentelemetry/instrumentation/api/internal/OperationMetricsUtil;->NOOP_OPERATION_LISTENER:Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;

    .line 19
    .line 20
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic a(Ljava/util/function/BiConsumer;Ljava/lang/String;Ljava/util/function/Function;Lio/opentelemetry/api/metrics/Meter;)Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lio/opentelemetry/instrumentation/api/internal/OperationMetricsUtil;->lambda$create$1(Ljava/util/function/BiConsumer;Ljava/lang/String;Ljava/util/function/Function;Lio/opentelemetry/api/metrics/Meter;)Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic b(Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lio/opentelemetry/instrumentation/api/internal/OperationMetricsUtil;->lambda$create$0(Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static create(Ljava/lang/String;Ljava/util/function/Function;)Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/util/function/Function<",
            "Lio/opentelemetry/api/metrics/Meter;",
            "Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/internal/f;

    const/4 v1, 0x2

    invoke-direct {v0, p0, v1}, Lio/opentelemetry/instrumentation/api/internal/f;-><init>(Ljava/lang/Object;I)V

    invoke-static {p0, p1, v0}, Lio/opentelemetry/instrumentation/api/internal/OperationMetricsUtil;->create(Ljava/lang/String;Ljava/util/function/Function;Ljava/util/function/BiConsumer;)Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;

    move-result-object p0

    return-object p0
.end method

.method public static create(Ljava/lang/String;Ljava/util/function/Function;Ljava/util/function/BiConsumer;)Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/util/function/Function<",
            "Lio/opentelemetry/api/metrics/Meter;",
            "Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;",
            ">;",
            "Ljava/util/function/BiConsumer<",
            "Ljava/lang/String;",
            "Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/OperationMetrics;"
        }
    .end annotation

    .line 2
    new-instance v0, Lio/opentelemetry/instrumentation/api/internal/b;

    invoke-direct {v0, p0, p1, p2}, Lio/opentelemetry/instrumentation/api/internal/b;-><init>(Ljava/lang/String;Ljava/util/function/Function;Ljava/util/function/BiConsumer;)V

    return-object v0
.end method

.method private static synthetic lambda$create$0(Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;)V
    .locals 2

    .line 1
    sget-object p1, Lio/opentelemetry/instrumentation/api/internal/OperationMetricsUtil;->logger:Ljava/util/logging/Logger;

    .line 2
    .line 3
    sget-object v0, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    .line 4
    .line 5
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    move-result-object p2

    .line 9
    invoke-virtual {p2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p2

    .line 13
    const-class v1, Lio/opentelemetry/api/incubator/metrics/ExtendedDoubleHistogramBuilder;

    .line 14
    .line 15
    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    filled-new-array {p0, p2, v1}, [Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    const-string p2, "Disabling {0} metrics because {1} does not implement {2}. This prevents using metrics advice, which could result in {0} metrics having high cardinality attributes."

    .line 24
    .line 25
    invoke-virtual {p1, v0, p2, p0}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method private static synthetic lambda$create$1(Ljava/util/function/BiConsumer;Ljava/lang/String;Ljava/util/function/Function;Lio/opentelemetry/api/metrics/Meter;)Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;
    .locals 3

    .line 1
    const-string v0, "compatibility-test"

    .line 2
    .line 3
    invoke-interface {p3, v0}, Lio/opentelemetry/api/metrics/Meter;->histogramBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    instance-of v1, v0, Lio/opentelemetry/api/incubator/metrics/ExtendedDoubleHistogramBuilder;

    .line 8
    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    const-string v2, "NoopDoubleHistogram"

    .line 20
    .line 21
    invoke-virtual {v1, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-nez v1, :cond_0

    .line 26
    .line 27
    invoke-interface {p0, p1, v0}, Ljava/util/function/BiConsumer;->accept(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    sget-object p0, Lio/opentelemetry/instrumentation/api/internal/OperationMetricsUtil;->NOOP_OPERATION_LISTENER:Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;

    .line 31
    .line 32
    return-object p0

    .line 33
    :cond_0
    invoke-interface {p2, p3}, Ljava/util/function/Function;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    check-cast p0, Lio/opentelemetry/instrumentation/api/instrumenter/OperationListener;

    .line 38
    .line 39
    return-object p0
.end method
