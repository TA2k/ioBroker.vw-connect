.class final Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Worker"
.end annotation


# static fields
.field static final synthetic $assertionsDisabled:Z

.field private static final logger:Ljava/util/logging/Logger;


# instance fields
.field private final batch:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "Lio/opentelemetry/sdk/logs/data/LogRecordData;",
            ">;"
        }
    .end annotation
.end field

.field private volatile continueWork:Z

.field private final droppedAttrs:Lio/opentelemetry/api/common/Attributes;

.field private final exportedAttrs:Lio/opentelemetry/api/common/Attributes;

.field private final exporterTimeoutNanos:J

.field private final flushRequested:Ljava/util/concurrent/atomic/AtomicReference;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/atomic/AtomicReference<",
            "Lio/opentelemetry/sdk/common/CompletableResultCode;",
            ">;"
        }
    .end annotation
.end field

.field private final logRecordExporter:Lio/opentelemetry/sdk/logs/export/LogRecordExporter;

.field private final logsNeeded:Ljava/util/concurrent/atomic/AtomicInteger;

.field private final maxExportBatchSize:I

.field private nextExportTime:J

.field private final processedLogsCounter:Lio/opentelemetry/api/metrics/LongCounter;

.field private final queue:Ljava/util/Queue;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Queue<",
            "Lio/opentelemetry/sdk/logs/ReadWriteLogRecord;",
            ">;"
        }
    .end annotation
.end field

.field private final scheduleDelayNanos:J

.field private final signal:Ljava/util/concurrent/BlockingQueue;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/BlockingQueue<",
            "Ljava/lang/Boolean;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;

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
    sput-object v0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->logger:Ljava/util/logging/Logger;

    .line 12
    .line 13
    return-void
.end method

.method private constructor <init>(Lio/opentelemetry/sdk/logs/export/LogRecordExporter;Lio/opentelemetry/api/metrics/MeterProvider;JIJLjava/util/Queue;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/logs/export/LogRecordExporter;",
            "Lio/opentelemetry/api/metrics/MeterProvider;",
            "JIJ",
            "Ljava/util/Queue<",
            "Lio/opentelemetry/sdk/logs/ReadWriteLogRecord;",
            ">;)V"
        }
    .end annotation

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    new-instance v0, Ljava/util/concurrent/atomic/AtomicInteger;

    const v1, 0x7fffffff

    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    iput-object v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->logsNeeded:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 4
    new-instance v0, Ljava/util/concurrent/atomic/AtomicReference;

    invoke-direct {v0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    iput-object v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->flushRequested:Ljava/util/concurrent/atomic/AtomicReference;

    const/4 v0, 0x1

    .line 5
    iput-boolean v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->continueWork:Z

    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->logRecordExporter:Lio/opentelemetry/sdk/logs/export/LogRecordExporter;

    .line 7
    iput-wide p3, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->scheduleDelayNanos:J

    .line 8
    iput p5, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->maxExportBatchSize:I

    .line 9
    iput-wide p6, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->exporterTimeoutNanos:J

    .line 10
    iput-object p8, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->queue:Ljava/util/Queue;

    .line 11
    new-instance p1, Ljava/util/concurrent/ArrayBlockingQueue;

    invoke-direct {p1, v0}, Ljava/util/concurrent/ArrayBlockingQueue;-><init>(I)V

    iput-object p1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->signal:Ljava/util/concurrent/BlockingQueue;

    .line 12
    const-string p1, "io.opentelemetry.sdk.logs"

    invoke-interface {p2, p1}, Lio/opentelemetry/api/metrics/MeterProvider;->meterBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/MeterBuilder;

    move-result-object p1

    invoke-interface {p1}, Lio/opentelemetry/api/metrics/MeterBuilder;->build()Lio/opentelemetry/api/metrics/Meter;

    move-result-object p1

    .line 13
    const-string p2, "queueSize"

    .line 14
    invoke-interface {p1, p2}, Lio/opentelemetry/api/metrics/Meter;->gaugeBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleGaugeBuilder;

    move-result-object p2

    .line 15
    invoke-interface {p2}, Lio/opentelemetry/api/metrics/DoubleGaugeBuilder;->ofLongs()Lio/opentelemetry/api/metrics/LongGaugeBuilder;

    move-result-object p2

    const-string p3, "The number of items queued"

    .line 16
    invoke-interface {p2, p3}, Lio/opentelemetry/api/metrics/LongGaugeBuilder;->setDescription(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongGaugeBuilder;

    move-result-object p2

    .line 17
    const-string p3, "1"

    invoke-interface {p2, p3}, Lio/opentelemetry/api/metrics/LongGaugeBuilder;->setUnit(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongGaugeBuilder;

    move-result-object p2

    new-instance p4, Lio/opentelemetry/sdk/logs/export/a;

    invoke-direct {p4, p8}, Lio/opentelemetry/sdk/logs/export/a;-><init>(Ljava/util/Queue;)V

    .line 18
    invoke-interface {p2, p4}, Lio/opentelemetry/api/metrics/LongGaugeBuilder;->buildWithCallback(Ljava/util/function/Consumer;)Lio/opentelemetry/api/metrics/ObservableLongGauge;

    .line 19
    const-string p2, "processedLogs"

    .line 20
    invoke-interface {p1, p2}, Lio/opentelemetry/api/metrics/Meter;->counterBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongCounterBuilder;

    move-result-object p1

    .line 21
    invoke-interface {p1, p3}, Lio/opentelemetry/api/metrics/LongCounterBuilder;->setUnit(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongCounterBuilder;

    move-result-object p1

    const-string p2, "The number of logs processed by the BatchLogRecordProcessor. [dropped=true if they were dropped due to high throughput]"

    .line 22
    invoke-interface {p1, p2}, Lio/opentelemetry/api/metrics/LongCounterBuilder;->setDescription(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongCounterBuilder;

    move-result-object p1

    .line 23
    invoke-interface {p1}, Lio/opentelemetry/api/metrics/LongCounterBuilder;->build()Lio/opentelemetry/api/metrics/LongCounter;

    move-result-object p1

    iput-object p1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->processedLogsCounter:Lio/opentelemetry/api/metrics/LongCounter;

    .line 24
    invoke-static {}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;->access$900()Lio/opentelemetry/api/common/AttributeKey;

    move-result-object p1

    .line 25
    invoke-static {}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;->access$1000()Ljava/lang/String;

    move-result-object p2

    .line 26
    invoke-static {}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;->access$1100()Lio/opentelemetry/api/common/AttributeKey;

    move-result-object p3

    .line 27
    sget-object p4, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 28
    invoke-static {p1, p2, p3, p4}, Lio/opentelemetry/api/common/Attributes;->of(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/Attributes;

    move-result-object p1

    iput-object p1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->droppedAttrs:Lio/opentelemetry/api/common/Attributes;

    .line 29
    invoke-static {}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;->access$900()Lio/opentelemetry/api/common/AttributeKey;

    move-result-object p1

    .line 30
    invoke-static {}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;->access$1000()Ljava/lang/String;

    move-result-object p2

    .line 31
    invoke-static {}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;->access$1100()Lio/opentelemetry/api/common/AttributeKey;

    move-result-object p3

    .line 32
    sget-object p4, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 33
    invoke-static {p1, p2, p3, p4}, Lio/opentelemetry/api/common/Attributes;->of(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/Attributes;

    move-result-object p1

    iput-object p1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->exportedAttrs:Lio/opentelemetry/api/common/Attributes;

    .line 34
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1, p5}, Ljava/util/ArrayList;-><init>(I)V

    iput-object p1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->batch:Ljava/util/ArrayList;

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/sdk/logs/export/LogRecordExporter;Lio/opentelemetry/api/metrics/MeterProvider;JIJLjava/util/Queue;Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$1;)V
    .locals 0

    .line 1
    invoke-direct/range {p0 .. p8}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;-><init>(Lio/opentelemetry/sdk/logs/export/LogRecordExporter;Lio/opentelemetry/api/metrics/MeterProvider;JIJLjava/util/Queue;)V

    return-void
.end method

.method public static synthetic a(Ljava/util/Queue;Lio/opentelemetry/api/metrics/ObservableLongMeasurement;)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->lambda$new$0(Ljava/util/Queue;Lio/opentelemetry/api/metrics/ObservableLongMeasurement;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic access$100(Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;Lio/opentelemetry/sdk/logs/ReadWriteLogRecord;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->addLog(Lio/opentelemetry/sdk/logs/ReadWriteLogRecord;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic access$200(Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;)Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 0

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic access$300(Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;)Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 0

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->forceFlush()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic access$400(Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;)Lio/opentelemetry/sdk/logs/export/LogRecordExporter;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->logRecordExporter:Lio/opentelemetry/sdk/logs/export/LogRecordExporter;

    .line 2
    .line 3
    return-object p0
.end method

.method public static synthetic access$500(Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;)Ljava/util/ArrayList;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->batch:Ljava/util/ArrayList;

    .line 2
    .line 3
    return-object p0
.end method

.method public static synthetic access$600(Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;)J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->scheduleDelayNanos:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public static synthetic access$700(Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;)I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->maxExportBatchSize:I

    .line 2
    .line 3
    return p0
.end method

.method public static synthetic access$800(Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;)J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->exporterTimeoutNanos:J

    .line 2
    .line 3
    return-wide v0
.end method

.method private addLog(Lio/opentelemetry/sdk/logs/ReadWriteLogRecord;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->queue:Ljava/util/Queue;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Ljava/util/Queue;->offer(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    if-nez p1, :cond_0

    .line 8
    .line 9
    iget-object p1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->processedLogsCounter:Lio/opentelemetry/api/metrics/LongCounter;

    .line 10
    .line 11
    const-wide/16 v0, 0x1

    .line 12
    .line 13
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->droppedAttrs:Lio/opentelemetry/api/common/Attributes;

    .line 14
    .line 15
    invoke-interface {p1, v0, v1, p0}, Lio/opentelemetry/api/metrics/LongCounter;->add(JLio/opentelemetry/api/common/Attributes;)V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    iget-object p1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->queue:Ljava/util/Queue;

    .line 20
    .line 21
    invoke-interface {p1}, Ljava/util/Collection;->size()I

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->logsNeeded:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 26
    .line 27
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicInteger;->get()I

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-lt p1, v0, :cond_1

    .line 32
    .line 33
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->signal:Ljava/util/concurrent/BlockingQueue;

    .line 34
    .line 35
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 36
    .line 37
    invoke-interface {p0, p1}, Ljava/util/concurrent/BlockingQueue;->offer(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    :cond_1
    return-void
.end method

.method public static synthetic b(Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/sdk/common/CompletableResultCode;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->lambda$shutdown$2(Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/sdk/common/CompletableResultCode;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic c(Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/sdk/common/CompletableResultCode;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->lambda$shutdown$1(Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/sdk/common/CompletableResultCode;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private exportCurrentBatch()V
    .locals 4

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->batch:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    :try_start_0
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->logRecordExporter:Lio/opentelemetry/sdk/logs/export/LogRecordExporter;

    .line 11
    .line 12
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->batch:Ljava/util/ArrayList;

    .line 13
    .line 14
    invoke-static {v1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    invoke-interface {v0, v1}, Lio/opentelemetry/sdk/logs/export/LogRecordExporter;->export(Ljava/util/Collection;)Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    iget-wide v1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->exporterTimeoutNanos:J

    .line 23
    .line 24
    sget-object v3, Ljava/util/concurrent/TimeUnit;->NANOSECONDS:Ljava/util/concurrent/TimeUnit;

    .line 25
    .line 26
    invoke-virtual {v0, v1, v2, v3}, Lio/opentelemetry/sdk/common/CompletableResultCode;->join(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0}, Lio/opentelemetry/sdk/common/CompletableResultCode;->isSuccess()Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-eqz v0, :cond_1

    .line 34
    .line 35
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->processedLogsCounter:Lio/opentelemetry/api/metrics/LongCounter;

    .line 36
    .line 37
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->batch:Ljava/util/ArrayList;

    .line 38
    .line 39
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    int-to-long v1, v1

    .line 44
    iget-object v3, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->exportedAttrs:Lio/opentelemetry/api/common/Attributes;

    .line 45
    .line 46
    invoke-interface {v0, v1, v2, v3}, Lio/opentelemetry/api/metrics/LongCounter;->add(JLio/opentelemetry/api/common/Attributes;)V

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    :catchall_0
    move-exception v0

    .line 51
    goto :goto_2

    .line 52
    :catch_0
    move-exception v0

    .line 53
    goto :goto_1

    .line 54
    :cond_1
    sget-object v0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->logger:Ljava/util/logging/Logger;

    .line 55
    .line 56
    sget-object v1, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    .line 57
    .line 58
    const-string v2, "Exporter failed"

    .line 59
    .line 60
    invoke-virtual {v0, v1, v2}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 61
    .line 62
    .line 63
    :goto_0
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->batch:Ljava/util/ArrayList;

    .line 64
    .line 65
    invoke-virtual {p0}, Ljava/util/ArrayList;->clear()V

    .line 66
    .line 67
    .line 68
    return-void

    .line 69
    :goto_1
    :try_start_1
    sget-object v1, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->logger:Ljava/util/logging/Logger;

    .line 70
    .line 71
    sget-object v2, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    .line 72
    .line 73
    const-string v3, "Exporter threw an Exception"

    .line 74
    .line 75
    invoke-virtual {v1, v2, v3, v0}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Throwable;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 76
    .line 77
    .line 78
    goto :goto_0

    .line 79
    :goto_2
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->batch:Ljava/util/ArrayList;

    .line 80
    .line 81
    invoke-virtual {p0}, Ljava/util/ArrayList;->clear()V

    .line 82
    .line 83
    .line 84
    throw v0
.end method

.method private flush()V
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->queue:Ljava/util/Queue;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    :cond_0
    :goto_0
    if-lez v0, :cond_1

    .line 8
    .line 9
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->queue:Ljava/util/Queue;

    .line 10
    .line 11
    invoke-interface {v1}, Ljava/util/Queue;->poll()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    check-cast v1, Lio/opentelemetry/sdk/logs/ReadWriteLogRecord;

    .line 16
    .line 17
    iget-object v2, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->batch:Ljava/util/ArrayList;

    .line 18
    .line 19
    invoke-interface {v1}, Lio/opentelemetry/sdk/logs/ReadWriteLogRecord;->toLogRecordData()Lio/opentelemetry/sdk/logs/data/LogRecordData;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    add-int/lit8 v0, v0, -0x1

    .line 27
    .line 28
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->batch:Ljava/util/ArrayList;

    .line 29
    .line 30
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    iget v2, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->maxExportBatchSize:I

    .line 35
    .line 36
    if-lt v1, v2, :cond_0

    .line 37
    .line 38
    invoke-direct {p0}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->exportCurrentBatch()V

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_1
    invoke-direct {p0}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->exportCurrentBatch()V

    .line 43
    .line 44
    .line 45
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->flushRequested:Ljava/util/concurrent/atomic/AtomicReference;

    .line 46
    .line 47
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    check-cast v0, Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 52
    .line 53
    if-eqz v0, :cond_2

    .line 54
    .line 55
    invoke-virtual {v0}, Lio/opentelemetry/sdk/common/CompletableResultCode;->succeed()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 56
    .line 57
    .line 58
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->flushRequested:Ljava/util/concurrent/atomic/AtomicReference;

    .line 59
    .line 60
    const/4 v0, 0x0

    .line 61
    invoke-virtual {p0, v0}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    :cond_2
    return-void
.end method

.method private forceFlush()Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 3

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/sdk/common/CompletableResultCode;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->flushRequested:Ljava/util/concurrent/atomic/AtomicReference;

    .line 7
    .line 8
    :cond_0
    const/4 v2, 0x0

    .line 9
    invoke-virtual {v1, v2, v0}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    if-eqz v2, :cond_1

    .line 14
    .line 15
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->signal:Ljava/util/concurrent/BlockingQueue;

    .line 16
    .line 17
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 18
    .line 19
    invoke-interface {v0, v1}, Ljava/util/concurrent/BlockingQueue;->offer(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_1
    invoke-virtual {v1}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    if-eqz v2, :cond_0

    .line 28
    .line 29
    :goto_0
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->flushRequested:Ljava/util/concurrent/atomic/AtomicReference;

    .line 30
    .line 31
    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    check-cast p0, Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 36
    .line 37
    if-nez p0, :cond_2

    .line 38
    .line 39
    invoke-static {}, Lio/opentelemetry/sdk/common/CompletableResultCode;->ofSuccess()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    :cond_2
    return-object p0
.end method

.method private static synthetic lambda$new$0(Ljava/util/Queue;Lio/opentelemetry/api/metrics/ObservableLongMeasurement;)V
    .locals 3

    .line 1
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    int-to-long v0, p0

    .line 6
    invoke-static {}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;->access$900()Lio/opentelemetry/api/common/AttributeKey;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-static {}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;->access$1000()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    invoke-static {p0, v2}, Lio/opentelemetry/api/common/Attributes;->of(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/Attributes;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-interface {p1, v0, v1, p0}, Lio/opentelemetry/api/metrics/ObservableLongMeasurement;->record(JLio/opentelemetry/api/common/Attributes;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method private static synthetic lambda$shutdown$1(Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/sdk/common/CompletableResultCode;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/common/CompletableResultCode;->isSuccess()Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-eqz p0, :cond_1

    .line 6
    .line 7
    invoke-virtual {p1}, Lio/opentelemetry/sdk/common/CompletableResultCode;->isSuccess()Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    if-nez p0, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    invoke-virtual {p2}, Lio/opentelemetry/sdk/common/CompletableResultCode;->succeed()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :cond_1
    :goto_0
    invoke-virtual {p2}, Lio/opentelemetry/sdk/common/CompletableResultCode;->fail()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method private synthetic lambda$shutdown$2(Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/sdk/common/CompletableResultCode;)V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->continueWork:Z

    .line 3
    .line 4
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->logRecordExporter:Lio/opentelemetry/sdk/logs/export/LogRecordExporter;

    .line 5
    .line 6
    invoke-interface {p0}, Lio/opentelemetry/sdk/logs/export/LogRecordExporter;->shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    new-instance v0, Lio/opentelemetry/sdk/logs/export/c;

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    invoke-direct {v0, p1, p0, p2, v1}, Lio/opentelemetry/sdk/logs/export/c;-><init>(Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/sdk/common/CompletableResultCode;I)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0, v0}, Lio/opentelemetry/sdk/common/CompletableResultCode;->whenComplete(Ljava/lang/Runnable;)Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method private shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 4

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/sdk/common/CompletableResultCode;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->forceFlush()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    new-instance v2, Lio/opentelemetry/sdk/logs/export/b;

    .line 11
    .line 12
    const/4 v3, 0x0

    .line 13
    invoke-direct {v2, p0, v1, v0, v3}, Lio/opentelemetry/sdk/logs/export/b;-><init>(Ljava/lang/Object;Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/sdk/common/CompletableResultCode;I)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v1, v2}, Lio/opentelemetry/sdk/common/CompletableResultCode;->whenComplete(Ljava/lang/Runnable;)Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 17
    .line 18
    .line 19
    return-object v0
.end method

.method private updateNextExportTime()V
    .locals 4

    .line 1
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    iget-wide v2, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->scheduleDelayNanos:J

    .line 6
    .line 7
    add-long/2addr v0, v2

    .line 8
    iput-wide v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->nextExportTime:J

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public run()V
    .locals 5

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->updateNextExportTime()V

    .line 2
    .line 3
    .line 4
    :cond_0
    :goto_0
    iget-boolean v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->continueWork:Z

    .line 5
    .line 6
    if-eqz v0, :cond_5

    .line 7
    .line 8
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->flushRequested:Ljava/util/concurrent/atomic/AtomicReference;

    .line 9
    .line 10
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    if-eqz v0, :cond_1

    .line 15
    .line 16
    invoke-direct {p0}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->flush()V

    .line 17
    .line 18
    .line 19
    :cond_1
    :goto_1
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->queue:Ljava/util/Queue;

    .line 20
    .line 21
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-nez v0, :cond_2

    .line 26
    .line 27
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->batch:Ljava/util/ArrayList;

    .line 28
    .line 29
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    iget v1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->maxExportBatchSize:I

    .line 34
    .line 35
    if-ge v0, v1, :cond_2

    .line 36
    .line 37
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->batch:Ljava/util/ArrayList;

    .line 38
    .line 39
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->queue:Ljava/util/Queue;

    .line 40
    .line 41
    invoke-interface {v1}, Ljava/util/Queue;->poll()Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    check-cast v1, Lio/opentelemetry/sdk/logs/ReadWriteLogRecord;

    .line 46
    .line 47
    invoke-interface {v1}, Lio/opentelemetry/sdk/logs/ReadWriteLogRecord;->toLogRecordData()Lio/opentelemetry/sdk/logs/data/LogRecordData;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_2
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->batch:Ljava/util/ArrayList;

    .line 56
    .line 57
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    iget v1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->maxExportBatchSize:I

    .line 62
    .line 63
    if-ge v0, v1, :cond_3

    .line 64
    .line 65
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 66
    .line 67
    .line 68
    move-result-wide v0

    .line 69
    iget-wide v2, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->nextExportTime:J

    .line 70
    .line 71
    cmp-long v0, v0, v2

    .line 72
    .line 73
    if-ltz v0, :cond_4

    .line 74
    .line 75
    :cond_3
    invoke-direct {p0}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->exportCurrentBatch()V

    .line 76
    .line 77
    .line 78
    invoke-direct {p0}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->updateNextExportTime()V

    .line 79
    .line 80
    .line 81
    :cond_4
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->queue:Ljava/util/Queue;

    .line 82
    .line 83
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 84
    .line 85
    .line 86
    move-result v0

    .line 87
    if-eqz v0, :cond_0

    .line 88
    .line 89
    :try_start_0
    iget-wide v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->nextExportTime:J

    .line 90
    .line 91
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 92
    .line 93
    .line 94
    move-result-wide v2

    .line 95
    sub-long/2addr v0, v2

    .line 96
    const-wide/16 v2, 0x0

    .line 97
    .line 98
    cmp-long v2, v0, v2

    .line 99
    .line 100
    if-lez v2, :cond_0

    .line 101
    .line 102
    iget-object v2, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->logsNeeded:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 103
    .line 104
    iget v3, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->maxExportBatchSize:I

    .line 105
    .line 106
    iget-object v4, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->batch:Ljava/util/ArrayList;

    .line 107
    .line 108
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 109
    .line 110
    .line 111
    move-result v4

    .line 112
    sub-int/2addr v3, v4

    .line 113
    invoke-virtual {v2, v3}, Ljava/util/concurrent/atomic/AtomicInteger;->set(I)V

    .line 114
    .line 115
    .line 116
    iget-object v2, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->signal:Ljava/util/concurrent/BlockingQueue;

    .line 117
    .line 118
    sget-object v3, Ljava/util/concurrent/TimeUnit;->NANOSECONDS:Ljava/util/concurrent/TimeUnit;

    .line 119
    .line 120
    invoke-interface {v2, v0, v1, v3}, Ljava/util/concurrent/BlockingQueue;->poll(JLjava/util/concurrent/TimeUnit;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->logsNeeded:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 124
    .line 125
    const v1, 0x7fffffff

    .line 126
    .line 127
    .line 128
    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicInteger;->set(I)V
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0

    .line 129
    .line 130
    .line 131
    goto :goto_0

    .line 132
    :catch_0
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    invoke-virtual {p0}, Ljava/lang/Thread;->interrupt()V

    .line 137
    .line 138
    .line 139
    :cond_5
    return-void
.end method
