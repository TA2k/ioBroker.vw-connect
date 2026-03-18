.class public final Lio/opentelemetry/sdk/metrics/export/PeriodicMetricReaderBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field static final DEFAULT_SCHEDULE_DELAY_MINUTES:J = 0x1L


# instance fields
.field private executor:Ljava/util/concurrent/ScheduledExecutorService;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private intervalNanos:J

.field private final metricExporter:Lio/opentelemetry/sdk/metrics/export/MetricExporter;


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/metrics/export/MetricExporter;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Ljava/util/concurrent/TimeUnit;->MINUTES:Ljava/util/concurrent/TimeUnit;

    .line 5
    .line 6
    const-wide/16 v1, 0x1

    .line 7
    .line 8
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    .line 9
    .line 10
    .line 11
    move-result-wide v0

    .line 12
    iput-wide v0, p0, Lio/opentelemetry/sdk/metrics/export/PeriodicMetricReaderBuilder;->intervalNanos:J

    .line 13
    .line 14
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/export/PeriodicMetricReaderBuilder;->metricExporter:Lio/opentelemetry/sdk/metrics/export/MetricExporter;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public build()Lio/opentelemetry/sdk/metrics/export/PeriodicMetricReader;
    .locals 5

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/export/PeriodicMetricReaderBuilder;->executor:Ljava/util/concurrent/ScheduledExecutorService;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lio/opentelemetry/sdk/internal/DaemonThreadFactory;

    .line 6
    .line 7
    const-string v1, "PeriodicMetricReader"

    .line 8
    .line 9
    invoke-direct {v0, v1}, Lio/opentelemetry/sdk/internal/DaemonThreadFactory;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const/4 v1, 0x1

    .line 13
    invoke-static {v1, v0}, Ljava/util/concurrent/Executors;->newScheduledThreadPool(ILjava/util/concurrent/ThreadFactory;)Ljava/util/concurrent/ScheduledExecutorService;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    :cond_0
    new-instance v1, Lio/opentelemetry/sdk/metrics/export/PeriodicMetricReader;

    .line 18
    .line 19
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/export/PeriodicMetricReaderBuilder;->metricExporter:Lio/opentelemetry/sdk/metrics/export/MetricExporter;

    .line 20
    .line 21
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/export/PeriodicMetricReaderBuilder;->intervalNanos:J

    .line 22
    .line 23
    invoke-direct {v1, v2, v3, v4, v0}, Lio/opentelemetry/sdk/metrics/export/PeriodicMetricReader;-><init>(Lio/opentelemetry/sdk/metrics/export/MetricExporter;JLjava/util/concurrent/ScheduledExecutorService;)V

    .line 24
    .line 25
    .line 26
    return-object v1
.end method

.method public setExecutor(Ljava/util/concurrent/ScheduledExecutorService;)Lio/opentelemetry/sdk/metrics/export/PeriodicMetricReaderBuilder;
    .locals 1

    .line 1
    const-string v0, "executor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/export/PeriodicMetricReaderBuilder;->executor:Ljava/util/concurrent/ScheduledExecutorService;

    .line 7
    .line 8
    return-object p0
.end method

.method public setInterval(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/sdk/metrics/export/PeriodicMetricReaderBuilder;
    .locals 2

    .line 1
    const-string v0, "unit"

    invoke-static {p3, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    const-wide/16 v0, 0x0

    cmp-long v0, p1, v0

    if-lez v0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    .line 2
    :goto_0
    const-string v1, "interval must be positive"

    invoke-static {v0, v1}, Lio/opentelemetry/api/internal/Utils;->checkArgument(ZLjava/lang/String;)V

    .line 3
    invoke-virtual {p3, p1, p2}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    move-result-wide p1

    iput-wide p1, p0, Lio/opentelemetry/sdk/metrics/export/PeriodicMetricReaderBuilder;->intervalNanos:J

    return-object p0
.end method

.method public setInterval(Ljava/time/Duration;)Lio/opentelemetry/sdk/metrics/export/PeriodicMetricReaderBuilder;
    .locals 2

    .line 4
    const-string v0, "interval"

    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 5
    invoke-virtual {p1}, Ljava/time/Duration;->toNanos()J

    move-result-wide v0

    sget-object p1, Ljava/util/concurrent/TimeUnit;->NANOSECONDS:Ljava/util/concurrent/TimeUnit;

    invoke-virtual {p0, v0, v1, p1}, Lio/opentelemetry/sdk/metrics/export/PeriodicMetricReaderBuilder;->setInterval(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/sdk/metrics/export/PeriodicMetricReaderBuilder;

    move-result-object p0

    return-object p0
.end method
