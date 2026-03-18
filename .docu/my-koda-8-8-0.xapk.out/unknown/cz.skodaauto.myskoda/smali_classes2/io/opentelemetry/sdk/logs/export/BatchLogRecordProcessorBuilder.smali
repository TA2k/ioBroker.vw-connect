.class public final Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field static final DEFAULT_EXPORT_TIMEOUT_MILLIS:I = 0x7530

.field static final DEFAULT_MAX_EXPORT_BATCH_SIZE:I = 0x200

.field static final DEFAULT_MAX_QUEUE_SIZE:I = 0x800

.field static final DEFAULT_SCHEDULE_DELAY_MILLIS:J = 0x3e8L

.field private static final logger:Ljava/util/logging/Logger;


# instance fields
.field private exporterTimeoutNanos:J

.field private final logRecordExporter:Lio/opentelemetry/sdk/logs/export/LogRecordExporter;

.field private maxExportBatchSize:I

.field private maxQueueSize:I

.field private meterProvider:Lio/opentelemetry/api/metrics/MeterProvider;

.field private scheduleDelayNanos:J


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;

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
    sput-object v0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->logger:Ljava/util/logging/Logger;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/sdk/logs/export/LogRecordExporter;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 5
    .line 6
    const-wide/16 v1, 0x3e8

    .line 7
    .line 8
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    .line 9
    .line 10
    .line 11
    move-result-wide v1

    .line 12
    iput-wide v1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->scheduleDelayNanos:J

    .line 13
    .line 14
    const/16 v1, 0x800

    .line 15
    .line 16
    iput v1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->maxQueueSize:I

    .line 17
    .line 18
    const/16 v1, 0x200

    .line 19
    .line 20
    iput v1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->maxExportBatchSize:I

    .line 21
    .line 22
    const-wide/16 v1, 0x7530

    .line 23
    .line 24
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    .line 25
    .line 26
    .line 27
    move-result-wide v0

    .line 28
    iput-wide v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->exporterTimeoutNanos:J

    .line 29
    .line 30
    invoke-static {}, Lio/opentelemetry/api/metrics/MeterProvider;->noop()Lio/opentelemetry/api/metrics/MeterProvider;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    iput-object v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->meterProvider:Lio/opentelemetry/api/metrics/MeterProvider;

    .line 35
    .line 36
    const-string v0, "logRecordExporter"

    .line 37
    .line 38
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    check-cast p1, Lio/opentelemetry/sdk/logs/export/LogRecordExporter;

    .line 42
    .line 43
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->logRecordExporter:Lio/opentelemetry/sdk/logs/export/LogRecordExporter;

    .line 44
    .line 45
    return-void
.end method


# virtual methods
.method public build()Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;
    .locals 10

    .line 1
    iget v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->maxExportBatchSize:I

    .line 2
    .line 3
    iget v1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->maxQueueSize:I

    .line 4
    .line 5
    if-le v0, v1, :cond_0

    .line 6
    .line 7
    sget-object v0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->logger:Ljava/util/logging/Logger;

    .line 8
    .line 9
    sget-object v2, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    .line 10
    .line 11
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    iget v3, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->maxExportBatchSize:I

    .line 16
    .line 17
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 18
    .line 19
    .line 20
    move-result-object v3

    .line 21
    filled-new-array {v1, v3}, [Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    const-string v3, "maxExportBatchSize should not exceed maxQueueSize. Setting maxExportBatchSize to {0} instead of {1}"

    .line 26
    .line 27
    invoke-virtual {v0, v2, v3, v1}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    iget v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->maxQueueSize:I

    .line 31
    .line 32
    iput v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->maxExportBatchSize:I

    .line 33
    .line 34
    :cond_0
    new-instance v1, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;

    .line 35
    .line 36
    iget-object v2, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->logRecordExporter:Lio/opentelemetry/sdk/logs/export/LogRecordExporter;

    .line 37
    .line 38
    iget-object v3, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->meterProvider:Lio/opentelemetry/api/metrics/MeterProvider;

    .line 39
    .line 40
    iget-wide v4, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->scheduleDelayNanos:J

    .line 41
    .line 42
    iget v6, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->maxQueueSize:I

    .line 43
    .line 44
    iget v7, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->maxExportBatchSize:I

    .line 45
    .line 46
    iget-wide v8, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->exporterTimeoutNanos:J

    .line 47
    .line 48
    invoke-direct/range {v1 .. v9}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;-><init>(Lio/opentelemetry/sdk/logs/export/LogRecordExporter;Lio/opentelemetry/api/metrics/MeterProvider;JIIJ)V

    .line 49
    .line 50
    .line 51
    return-object v1
.end method

.method public getExporterTimeoutNanos()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->exporterTimeoutNanos:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getMaxExportBatchSize()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->maxExportBatchSize:I

    .line 2
    .line 3
    return p0
.end method

.method public getMaxQueueSize()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->maxQueueSize:I

    .line 2
    .line 3
    return p0
.end method

.method public getScheduleDelayNanos()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->scheduleDelayNanos:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public setExporterTimeout(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;
    .locals 3

    .line 1
    const-string v0, "unit"

    invoke-static {p3, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    const-wide/16 v0, 0x0

    cmp-long v0, p1, v0

    if-ltz v0, :cond_0

    const/4 v1, 0x1

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    .line 2
    :goto_0
    const-string v2, "timeout must be non-negative"

    invoke-static {v1, v2}, Lio/opentelemetry/api/internal/Utils;->checkArgument(ZLjava/lang/String;)V

    if-nez v0, :cond_1

    const-wide p1, 0x7fffffffffffffffL

    goto :goto_1

    .line 3
    :cond_1
    invoke-virtual {p3, p1, p2}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    move-result-wide p1

    :goto_1
    iput-wide p1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->exporterTimeoutNanos:J

    return-object p0
.end method

.method public setExporterTimeout(Ljava/time/Duration;)Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;
    .locals 2

    .line 4
    const-string v0, "timeout"

    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 5
    invoke-virtual {p1}, Ljava/time/Duration;->toNanos()J

    move-result-wide v0

    sget-object p1, Ljava/util/concurrent/TimeUnit;->NANOSECONDS:Ljava/util/concurrent/TimeUnit;

    invoke-virtual {p0, v0, v1, p1}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->setExporterTimeout(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setMaxExportBatchSize(I)Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;
    .locals 2

    .line 1
    if-lez p1, :cond_0

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    goto :goto_0

    .line 5
    :cond_0
    const/4 v0, 0x0

    .line 6
    :goto_0
    const-string v1, "maxExportBatchSize must be positive."

    .line 7
    .line 8
    invoke-static {v0, v1}, Lio/opentelemetry/api/internal/Utils;->checkArgument(ZLjava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iput p1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->maxExportBatchSize:I

    .line 12
    .line 13
    return-object p0
.end method

.method public setMaxQueueSize(I)Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;
    .locals 2

    .line 1
    if-lez p1, :cond_0

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    goto :goto_0

    .line 5
    :cond_0
    const/4 v0, 0x0

    .line 6
    :goto_0
    const-string v1, "maxQueueSize must be positive."

    .line 7
    .line 8
    invoke-static {v0, v1}, Lio/opentelemetry/api/internal/Utils;->checkArgument(ZLjava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iput p1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->maxQueueSize:I

    .line 12
    .line 13
    return-object p0
.end method

.method public setMeterProvider(Lio/opentelemetry/api/metrics/MeterProvider;)Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;
    .locals 1

    .line 1
    const-string v0, "meterProvider"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->meterProvider:Lio/opentelemetry/api/metrics/MeterProvider;

    .line 7
    .line 8
    return-object p0
.end method

.method public setScheduleDelay(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;
    .locals 2

    .line 1
    const-string v0, "unit"

    invoke-static {p3, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    const-wide/16 v0, 0x0

    cmp-long v0, p1, v0

    if-ltz v0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    .line 2
    :goto_0
    const-string v1, "delay must be non-negative"

    invoke-static {v0, v1}, Lio/opentelemetry/api/internal/Utils;->checkArgument(ZLjava/lang/String;)V

    .line 3
    invoke-virtual {p3, p1, p2}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    move-result-wide p1

    iput-wide p1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->scheduleDelayNanos:J

    return-object p0
.end method

.method public setScheduleDelay(Ljava/time/Duration;)Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;
    .locals 2

    .line 4
    const-string v0, "delay"

    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 5
    invoke-virtual {p1}, Ljava/time/Duration;->toNanos()J

    move-result-wide v0

    sget-object p1, Ljava/util/concurrent/TimeUnit;->NANOSECONDS:Ljava/util/concurrent/TimeUnit;

    invoke-virtual {p0, v0, v1, p1}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;->setScheduleDelay(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;

    move-result-object p0

    return-object p0
.end method
