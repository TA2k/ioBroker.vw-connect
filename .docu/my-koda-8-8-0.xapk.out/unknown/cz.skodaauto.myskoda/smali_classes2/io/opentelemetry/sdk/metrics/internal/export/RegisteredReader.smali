.class public Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final ID_COUNTER:Ljava/util/concurrent/atomic/AtomicInteger;


# instance fields
.field private final id:I

.field private volatile lastCollectEpochNanos:J

.field private final metricReader:Lio/opentelemetry/sdk/metrics/export/MetricReader;

.field private final viewRegistry:Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->ID_COUNTER:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 8
    .line 9
    return-void
.end method

.method private constructor <init>(Lio/opentelemetry/sdk/metrics/export/MetricReader;Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->ID_COUNTER:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 5
    .line 6
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicInteger;->incrementAndGet()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    iput v0, p0, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->id:I

    .line 11
    .line 12
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->metricReader:Lio/opentelemetry/sdk/metrics/export/MetricReader;

    .line 13
    .line 14
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->viewRegistry:Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;

    .line 15
    .line 16
    return-void
.end method

.method public static create(Lio/opentelemetry/sdk/metrics/export/MetricReader;Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;)Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;-><init>(Lio/opentelemetry/sdk/metrics/export/MetricReader;Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method


# virtual methods
.method public equals(Ljava/lang/Object;)Z
    .locals 3
    .param p1    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    iget p0, p0, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->id:I

    .line 12
    .line 13
    check-cast p1, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;

    .line 14
    .line 15
    iget p1, p1, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->id:I

    .line 16
    .line 17
    if-ne p0, p1, :cond_2

    .line 18
    .line 19
    return v0

    .line 20
    :cond_2
    return v2
.end method

.method public getLastCollectEpochNanos()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->lastCollectEpochNanos:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getReader()Lio/opentelemetry/sdk/metrics/export/MetricReader;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->metricReader:Lio/opentelemetry/sdk/metrics/export/MetricReader;

    .line 2
    .line 3
    return-object p0
.end method

.method public getViewRegistry()Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->viewRegistry:Lio/opentelemetry/sdk/metrics/internal/view/ViewRegistry;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->id:I

    .line 2
    .line 3
    return p0
.end method

.method public setLastCollectEpochNanos(J)V
    .locals 0

    .line 1
    iput-wide p1, p0, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->lastCollectEpochNanos:J

    .line 2
    .line 3
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "RegisteredReader{"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget p0, p0, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->id:I

    .line 9
    .line 10
    const-string v1, "}"

    .line 11
    .line 12
    invoke-static {p0, v1, v0}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method
