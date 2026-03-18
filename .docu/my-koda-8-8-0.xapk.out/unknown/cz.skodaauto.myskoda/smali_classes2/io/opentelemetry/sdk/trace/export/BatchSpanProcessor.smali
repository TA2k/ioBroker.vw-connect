.class public final Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/trace/SpanProcessor;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;
    }
.end annotation


# static fields
.field private static final SPAN_PROCESSOR_DROPPED_LABEL:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/Boolean;",
            ">;"
        }
    .end annotation
.end field

.field private static final SPAN_PROCESSOR_TYPE_LABEL:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private static final SPAN_PROCESSOR_TYPE_VALUE:Ljava/lang/String;

.field private static final WORKER_THREAD_NAME:Ljava/lang/String;

.field private static final logger:Ljava/util/logging/Logger;


# instance fields
.field private final exportUnsampledSpans:Z

.field private final isShutdown:Ljava/util/concurrent/atomic/AtomicBoolean;

.field private final worker:Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor;

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
    sput-object v0, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor;->logger:Ljava/util/logging/Logger;

    .line 12
    .line 13
    const-string v0, "BatchSpanProcessor_WorkerThread"

    .line 14
    .line 15
    sput-object v0, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor;->WORKER_THREAD_NAME:Ljava/lang/String;

    .line 16
    .line 17
    const-string v0, "processorType"

    .line 18
    .line 19
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    sput-object v0, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor;->SPAN_PROCESSOR_TYPE_LABEL:Lio/opentelemetry/api/common/AttributeKey;

    .line 24
    .line 25
    const-string v0, "dropped"

    .line 26
    .line 27
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->booleanKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    sput-object v0, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor;->SPAN_PROCESSOR_DROPPED_LABEL:Lio/opentelemetry/api/common/AttributeKey;

    .line 32
    .line 33
    const-string v0, "BatchSpanProcessor"

    .line 34
    .line 35
    sput-object v0, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor;->SPAN_PROCESSOR_TYPE_VALUE:Ljava/lang/String;

    .line 36
    .line 37
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/sdk/trace/export/SpanExporter;ZLio/opentelemetry/api/metrics/MeterProvider;JIIJ)V
    .locals 11

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v1, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 5
    .line 6
    const/4 v2, 0x0

    .line 7
    invoke-direct {v1, v2}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 8
    .line 9
    .line 10
    iput-object v1, p0, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor;->isShutdown:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 11
    .line 12
    iput-boolean p2, p0, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor;->exportUnsampledSpans:Z

    .line 13
    .line 14
    new-instance v1, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;

    .line 15
    .line 16
    invoke-static/range {p6 .. p6}, Lio/opentelemetry/sdk/trace/internal/JcTools;->newFixedSizeQueue(I)Ljava/util/Queue;

    .line 17
    .line 18
    .line 19
    move-result-object v9

    .line 20
    const/4 v10, 0x0

    .line 21
    move-object v2, p1

    .line 22
    move-object v3, p3

    .line 23
    move-wide v4, p4

    .line 24
    move/from16 v6, p7

    .line 25
    .line 26
    move-wide/from16 v7, p8

    .line 27
    .line 28
    invoke-direct/range {v1 .. v10}, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;-><init>(Lio/opentelemetry/sdk/trace/export/SpanExporter;Lio/opentelemetry/api/metrics/MeterProvider;JIJLjava/util/Queue;Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$1;)V

    .line 29
    .line 30
    .line 31
    iput-object v1, p0, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor;->worker:Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;

    .line 32
    .line 33
    new-instance v0, Lio/opentelemetry/sdk/internal/DaemonThreadFactory;

    .line 34
    .line 35
    sget-object v2, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor;->WORKER_THREAD_NAME:Ljava/lang/String;

    .line 36
    .line 37
    invoke-direct {v0, v2}, Lio/opentelemetry/sdk/internal/DaemonThreadFactory;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {v0, v1}, Lio/opentelemetry/sdk/internal/DaemonThreadFactory;->newThread(Ljava/lang/Runnable;)Ljava/lang/Thread;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    invoke-virtual {v0}, Ljava/lang/Thread;->start()V

    .line 45
    .line 46
    .line 47
    return-void
.end method

.method public static synthetic access$1000()Lio/opentelemetry/api/common/AttributeKey;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor;->SPAN_PROCESSOR_TYPE_LABEL:Lio/opentelemetry/api/common/AttributeKey;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic access$1100()Ljava/lang/String;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor;->SPAN_PROCESSOR_TYPE_VALUE:Ljava/lang/String;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic access$1200()Lio/opentelemetry/api/common/AttributeKey;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor;->SPAN_PROCESSOR_DROPPED_LABEL:Lio/opentelemetry/api/common/AttributeKey;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic access$1300()Ljava/util/logging/Logger;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor;->logger:Ljava/util/logging/Logger;

    .line 2
    .line 3
    return-object v0
.end method

.method public static builder(Lio/opentelemetry/sdk/trace/export/SpanExporter;)Lio/opentelemetry/sdk/trace/export/BatchSpanProcessorBuilder;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessorBuilder;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessorBuilder;-><init>(Lio/opentelemetry/sdk/trace/export/SpanExporter;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method


# virtual methods
.method public forceFlush()Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor;->worker:Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;

    .line 2
    .line 3
    invoke-static {p0}, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;->access$300(Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;)Lio/opentelemetry/sdk/common/CompletableResultCode;

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
            "Lio/opentelemetry/sdk/trace/data/SpanData;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor;->worker:Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;

    .line 2
    .line 3
    invoke-static {p0}, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;->access$500(Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;)Ljava/util/ArrayList;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getQueue()Ljava/util/Queue;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Queue<",
            "Lio/opentelemetry/sdk/trace/ReadableSpan;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor;->worker:Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;

    .line 2
    .line 3
    invoke-static {p0}, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;->access$600(Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;)Ljava/util/Queue;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getSpanExporter()Lio/opentelemetry/sdk/trace/export/SpanExporter;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor;->worker:Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;

    .line 2
    .line 3
    invoke-static {p0}, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;->access$400(Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;)Lio/opentelemetry/sdk/trace/export/SpanExporter;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public isEndRequired()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public isStartRequired()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public onEnd(Lio/opentelemetry/sdk/trace/ReadableSpan;)V
    .locals 1

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    iget-boolean v0, p0, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor;->exportUnsampledSpans:Z

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/ReadableSpan;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-interface {v0}, Lio/opentelemetry/api/trace/SpanContext;->isSampled()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor;->worker:Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;

    .line 18
    .line 19
    invoke-static {p0, p1}, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;->access$100(Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;Lio/opentelemetry/sdk/trace/ReadableSpan;)V

    .line 20
    .line 21
    .line 22
    :cond_1
    return-void
.end method

.method public onStart(Lio/opentelemetry/context/Context;Lio/opentelemetry/sdk/trace/ReadWriteSpan;)V
    .locals 0

    .line 1
    return-void
.end method

.method public shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor;->isShutdown:Ljava/util/concurrent/atomic/AtomicBoolean;

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
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor;->worker:Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;

    .line 16
    .line 17
    invoke-static {p0}, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;->access$200(Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;)Lio/opentelemetry/sdk/common/CompletableResultCode;

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
    const-string v1, "BatchSpanProcessor{spanExporter="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor;->worker:Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;

    .line 9
    .line 10
    invoke-static {v1}, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;->access$400(Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;)Lio/opentelemetry/sdk/trace/export/SpanExporter;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string v1, ", exportUnsampledSpans="

    .line 18
    .line 19
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    iget-boolean v1, p0, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor;->exportUnsampledSpans:Z

    .line 23
    .line 24
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const-string v1, ", scheduleDelayNanos="

    .line 28
    .line 29
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor;->worker:Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;

    .line 33
    .line 34
    invoke-static {v1}, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;->access$700(Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;)J

    .line 35
    .line 36
    .line 37
    move-result-wide v1

    .line 38
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v1, ", maxExportBatchSize="

    .line 42
    .line 43
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor;->worker:Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;

    .line 47
    .line 48
    invoke-static {v1}, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;->access$800(Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;)I

    .line 49
    .line 50
    .line 51
    move-result v1

    .line 52
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    const-string v1, ", exporterTimeoutNanos="

    .line 56
    .line 57
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor;->worker:Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;

    .line 61
    .line 62
    invoke-static {p0}, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;->access$900(Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;)J

    .line 63
    .line 64
    .line 65
    move-result-wide v1

    .line 66
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    const/16 p0, 0x7d

    .line 70
    .line 71
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    return-object p0
.end method
