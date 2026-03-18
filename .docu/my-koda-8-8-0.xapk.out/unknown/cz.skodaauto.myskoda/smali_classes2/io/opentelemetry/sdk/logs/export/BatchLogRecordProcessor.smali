.class public final Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/logs/LogRecordProcessor;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;
    }
.end annotation


# static fields
.field private static final LOG_RECORD_PROCESSOR_DROPPED_LABEL:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/Boolean;",
            ">;"
        }
    .end annotation
.end field

.field private static final LOG_RECORD_PROCESSOR_TYPE_LABEL:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private static final LOG_RECORD_PROCESSOR_TYPE_VALUE:Ljava/lang/String;

.field private static final WORKER_THREAD_NAME:Ljava/lang/String; = "BatchLogRecordProcessor_WorkerThread"


# instance fields
.field private final isShutdown:Ljava/util/concurrent/atomic/AtomicBoolean;

.field private final worker:Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "processorType"

    .line 2
    .line 3
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;->LOG_RECORD_PROCESSOR_TYPE_LABEL:Lio/opentelemetry/api/common/AttributeKey;

    .line 8
    .line 9
    const-string v0, "dropped"

    .line 10
    .line 11
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->booleanKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;->LOG_RECORD_PROCESSOR_DROPPED_LABEL:Lio/opentelemetry/api/common/AttributeKey;

    .line 16
    .line 17
    const-string v0, "BatchLogRecordProcessor"

    .line 18
    .line 19
    sput-object v0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;->LOG_RECORD_PROCESSOR_TYPE_VALUE:Ljava/lang/String;

    .line 20
    .line 21
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/sdk/logs/export/LogRecordExporter;Lio/opentelemetry/api/metrics/MeterProvider;JIIJ)V
    .locals 12

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;->isShutdown:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 11
    .line 12
    new-instance v2, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;

    .line 13
    .line 14
    new-instance v10, Ljava/util/concurrent/ArrayBlockingQueue;

    .line 15
    .line 16
    move/from16 v0, p5

    .line 17
    .line 18
    invoke-direct {v10, v0}, Ljava/util/concurrent/ArrayBlockingQueue;-><init>(I)V

    .line 19
    .line 20
    .line 21
    const/4 v11, 0x0

    .line 22
    move-object v3, p1

    .line 23
    move-object v4, p2

    .line 24
    move-wide v5, p3

    .line 25
    move/from16 v7, p6

    .line 26
    .line 27
    move-wide/from16 v8, p7

    .line 28
    .line 29
    invoke-direct/range {v2 .. v11}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;-><init>(Lio/opentelemetry/sdk/logs/export/LogRecordExporter;Lio/opentelemetry/api/metrics/MeterProvider;JIJLjava/util/Queue;Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$1;)V

    .line 30
    .line 31
    .line 32
    iput-object v2, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;->worker:Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;

    .line 33
    .line 34
    new-instance p0, Lio/opentelemetry/sdk/internal/DaemonThreadFactory;

    .line 35
    .line 36
    sget-object p1, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;->WORKER_THREAD_NAME:Ljava/lang/String;

    .line 37
    .line 38
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/internal/DaemonThreadFactory;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p0, v2}, Lio/opentelemetry/sdk/internal/DaemonThreadFactory;->newThread(Ljava/lang/Runnable;)Ljava/lang/Thread;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-virtual {p0}, Ljava/lang/Thread;->start()V

    .line 46
    .line 47
    .line 48
    return-void
.end method

.method public static synthetic access$1000()Ljava/lang/String;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;->LOG_RECORD_PROCESSOR_TYPE_VALUE:Ljava/lang/String;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic access$1100()Lio/opentelemetry/api/common/AttributeKey;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;->LOG_RECORD_PROCESSOR_DROPPED_LABEL:Lio/opentelemetry/api/common/AttributeKey;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic access$900()Lio/opentelemetry/api/common/AttributeKey;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;->LOG_RECORD_PROCESSOR_TYPE_LABEL:Lio/opentelemetry/api/common/AttributeKey;

    .line 2
    .line 3
    return-object v0
.end method

.method public static builder(Lio/opentelemetry/sdk/logs/export/LogRecordExporter;)Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessorBuilder;-><init>(Lio/opentelemetry/sdk/logs/export/LogRecordExporter;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method


# virtual methods
.method public forceFlush()Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;->worker:Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;

    .line 2
    .line 3
    invoke-static {p0}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->access$300(Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;)Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getBatch()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/logs/data/LogRecordData;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;->worker:Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;

    .line 2
    .line 3
    invoke-static {p0}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->access$500(Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;)Ljava/util/ArrayList;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getLogRecordExporter()Lio/opentelemetry/sdk/logs/export/LogRecordExporter;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;->worker:Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;

    .line 2
    .line 3
    invoke-static {p0}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->access$400(Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;)Lio/opentelemetry/sdk/logs/export/LogRecordExporter;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public onEmit(Lio/opentelemetry/context/Context;Lio/opentelemetry/sdk/logs/ReadWriteLogRecord;)V
    .locals 0

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;->worker:Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;

    .line 5
    .line 6
    invoke-static {p0, p2}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->access$100(Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;Lio/opentelemetry/sdk/logs/ReadWriteLogRecord;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;->isShutdown:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;->getAndSet(Z)Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    invoke-static {}, Lio/opentelemetry/sdk/common/CompletableResultCode;->ofSuccess()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;->worker:Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;

    .line 16
    .line 17
    invoke-static {p0}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->access$200(Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;)Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "BatchLogRecordProcessor{logRecordExporter="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;->worker:Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;

    .line 9
    .line 10
    invoke-static {v1}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->access$400(Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;)Lio/opentelemetry/sdk/logs/export/LogRecordExporter;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string v1, ", scheduleDelayNanos="

    .line 18
    .line 19
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;->worker:Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;

    .line 23
    .line 24
    invoke-static {v1}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->access$600(Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;)J

    .line 25
    .line 26
    .line 27
    move-result-wide v1

    .line 28
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v1, ", maxExportBatchSize="

    .line 32
    .line 33
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;->worker:Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;

    .line 37
    .line 38
    invoke-static {v1}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->access$700(Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;)I

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    const-string v1, ", exporterTimeoutNanos="

    .line 46
    .line 47
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor;->worker:Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;

    .line 51
    .line 52
    invoke-static {p0}, Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;->access$800(Lio/opentelemetry/sdk/logs/export/BatchLogRecordProcessor$Worker;)J

    .line 53
    .line 54
    .line 55
    move-result-wide v1

    .line 56
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    const/16 p0, 0x7d

    .line 60
    .line 61
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    return-object p0
.end method
