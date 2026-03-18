.class public final Lio/opentelemetry/exporter/internal/http/HttpExporter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation


# static fields
.field private static final internalLogger:Ljava/util/logging/Logger;


# instance fields
.field private final exporterMetrics:Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation;

.field private final httpSender:Lio/opentelemetry/exporter/internal/http/HttpSender;

.field private final isShutdown:Ljava/util/concurrent/atomic/AtomicBoolean;

.field private final logger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;

.field private final type:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/exporter/internal/http/HttpExporter;

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
    sput-object v0, Lio/opentelemetry/exporter/internal/http/HttpExporter;->internalLogger:Ljava/util/logging/Logger;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/sdk/internal/StandardComponentId;Lio/opentelemetry/exporter/internal/http/HttpSender;Ljava/util/function/Supplier;Lio/opentelemetry/sdk/common/InternalTelemetryVersion;Ljava/lang/String;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/internal/StandardComponentId;",
            "Lio/opentelemetry/exporter/internal/http/HttpSender;",
            "Ljava/util/function/Supplier<",
            "Lio/opentelemetry/api/metrics/MeterProvider;",
            ">;",
            "Lio/opentelemetry/sdk/common/InternalTelemetryVersion;",
            "Ljava/lang/String;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lio/opentelemetry/sdk/internal/ThrottlingLogger;

    .line 5
    .line 6
    sget-object v1, Lio/opentelemetry/exporter/internal/http/HttpExporter;->internalLogger:Ljava/util/logging/Logger;

    .line 7
    .line 8
    invoke-direct {v0, v1}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;-><init>(Ljava/util/logging/Logger;)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporter;->logger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;

    .line 12
    .line 13
    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 14
    .line 15
    invoke-direct {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>()V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporter;->isShutdown:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 19
    .line 20
    invoke-virtual {p1}, Lio/opentelemetry/sdk/internal/StandardComponentId;->getStandardType()Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    invoke-virtual {v0}, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->signal()Lio/opentelemetry/sdk/internal/Signal;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    invoke-virtual {v0}, Lio/opentelemetry/sdk/internal/Signal;->logFriendlyName()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporter;->type:Ljava/lang/String;

    .line 33
    .line 34
    iput-object p2, p0, Lio/opentelemetry/exporter/internal/http/HttpExporter;->httpSender:Lio/opentelemetry/exporter/internal/http/HttpSender;

    .line 35
    .line 36
    new-instance p2, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation;

    .line 37
    .line 38
    invoke-direct {p2, p4, p3, p1, p5}, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation;-><init>(Lio/opentelemetry/sdk/common/InternalTelemetryVersion;Ljava/util/function/Supplier;Lio/opentelemetry/sdk/internal/StandardComponentId;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    iput-object p2, p0, Lio/opentelemetry/exporter/internal/http/HttpExporter;->exporterMetrics:Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation;

    .line 42
    .line 43
    return-void
.end method

.method public static synthetic a(Lio/opentelemetry/exporter/internal/http/HttpExporter;Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;Ljava/lang/Throwable;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/http/HttpExporter;->lambda$export$1(Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;Ljava/lang/Throwable;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic b(Lio/opentelemetry/exporter/internal/http/HttpExporter;Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;Lio/opentelemetry/exporter/internal/http/HttpSender$Response;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/http/HttpExporter;->lambda$export$0(Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;Lio/opentelemetry/exporter/internal/http/HttpSender$Response;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static extractErrorStatus(Ljava/lang/String;[B)Ljava/lang/String;
    .locals 0
    .param p1    # [B
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const-string p1, "Response body missing, HTTP status message: "

    .line 4
    .line 5
    invoke-static {p1, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0

    .line 10
    :cond_0
    :try_start_0
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/grpc/GrpcExporterUtil;->getStatusMessage([B)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 14
    return-object p0

    .line 15
    :catch_0
    const-string p1, "Unable to parse response body, HTTP status message: "

    .line 16
    .line 17
    invoke-static {p1, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method

.method private synthetic lambda$export$0(Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;Lio/opentelemetry/exporter/internal/http/HttpSender$Response;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/http/HttpExporter;->onResponse(Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;Lio/opentelemetry/exporter/internal/http/HttpSender$Response;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private synthetic lambda$export$1(Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;Ljava/lang/Throwable;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/http/HttpExporter;->onError(Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;Ljava/lang/Throwable;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private onError(Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;Ljava/lang/Throwable;)V
    .locals 3

    .line 1
    invoke-virtual {p2, p3}, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;->finishFailed(Ljava/lang/Throwable;)V

    .line 2
    .line 3
    .line 4
    iget-object p2, p0, Lio/opentelemetry/exporter/internal/http/HttpExporter;->logger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;

    .line 5
    .line 6
    sget-object v0, Ljava/util/logging/Level;->SEVERE:Ljava/util/logging/Level;

    .line 7
    .line 8
    new-instance v1, Ljava/lang/StringBuilder;

    .line 9
    .line 10
    const-string v2, "Failed to export "

    .line 11
    .line 12
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporter;->type:Ljava/lang/String;

    .line 16
    .line 17
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    const-string p0, "s. The request could not be executed. Full error message: "

    .line 21
    .line 22
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {p3}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-virtual {p2, v0, p0, p3}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->log(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 37
    .line 38
    .line 39
    invoke-static {p3}, Lio/opentelemetry/exporter/internal/FailedExportException;->httpFailedExceptionally(Ljava/lang/Throwable;)Lio/opentelemetry/exporter/internal/FailedExportException$HttpExportException;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    invoke-virtual {p1, p0}, Lio/opentelemetry/sdk/common/CompletableResultCode;->failExceptionally(Ljava/lang/Throwable;)Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 44
    .line 45
    .line 46
    return-void
.end method

.method private onResponse(Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;Lio/opentelemetry/exporter/internal/http/HttpSender$Response;)V
    .locals 6

    .line 1
    invoke-interface {p3}, Lio/opentelemetry/exporter/internal/http/HttpSender$Response;->statusCode()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    int-to-long v1, v0

    .line 6
    invoke-virtual {p2, v1, v2}, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;->setHttpStatusCode(J)V

    .line 7
    .line 8
    .line 9
    const/16 v1, 0xc8

    .line 10
    .line 11
    if-lt v0, v1, :cond_0

    .line 12
    .line 13
    const/16 v1, 0x12c

    .line 14
    .line 15
    if-ge v0, v1, :cond_0

    .line 16
    .line 17
    invoke-virtual {p2}, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;->finishSuccessful()V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p1}, Lio/opentelemetry/sdk/common/CompletableResultCode;->succeed()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :cond_0
    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    invoke-virtual {p2, v1}, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;->finishFailed(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    :try_start_0
    invoke-interface {p3}, Lio/opentelemetry/exporter/internal/http/HttpSender$Response;->responseBody()[B

    .line 32
    .line 33
    .line 34
    move-result-object p2
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 35
    goto :goto_0

    .line 36
    :catch_0
    move-exception p2

    .line 37
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporter;->logger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;

    .line 38
    .line 39
    sget-object v2, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    .line 40
    .line 41
    const-string v3, "Unable to obtain response body"

    .line 42
    .line 43
    invoke-virtual {v1, v2, v3, p2}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->log(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 44
    .line 45
    .line 46
    const/4 p2, 0x0

    .line 47
    :goto_0
    invoke-interface {p3}, Lio/opentelemetry/exporter/internal/http/HttpSender$Response;->statusMessage()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    invoke-static {v1, p2}, Lio/opentelemetry/exporter/internal/http/HttpExporter;->extractErrorStatus(Ljava/lang/String;[B)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p2

    .line 55
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporter;->logger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;

    .line 56
    .line 57
    sget-object v2, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    .line 58
    .line 59
    new-instance v3, Ljava/lang/StringBuilder;

    .line 60
    .line 61
    const-string v4, "Failed to export "

    .line 62
    .line 63
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporter;->type:Ljava/lang/String;

    .line 67
    .line 68
    const-string v4, "s. Server responded with HTTP status code "

    .line 69
    .line 70
    const-string v5, ". Error message: "

    .line 71
    .line 72
    invoke-static {v3, p0, v4, v0, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->z(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {v3, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    invoke-virtual {v1, v2, p0}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    invoke-static {p3}, Lio/opentelemetry/exporter/internal/FailedExportException;->httpFailedWithResponse(Lio/opentelemetry/exporter/internal/http/HttpSender$Response;)Lio/opentelemetry/exporter/internal/FailedExportException$HttpExportException;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    invoke-virtual {p1, p0}, Lio/opentelemetry/sdk/common/CompletableResultCode;->failExceptionally(Ljava/lang/Throwable;)Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 90
    .line 91
    .line 92
    return-void
.end method


# virtual methods
.method public export(Lio/opentelemetry/exporter/internal/marshal/Marshaler;I)Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TT;I)",
            "Lio/opentelemetry/sdk/common/CompletableResultCode;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporter;->isShutdown:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-static {}, Lio/opentelemetry/sdk/common/CompletableResultCode;->ofFailure()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0

    .line 14
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporter;->exporterMetrics:Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation;

    .line 15
    .line 16
    invoke-virtual {v0, p2}, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation;->startRecordingExport(I)Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;

    .line 17
    .line 18
    .line 19
    move-result-object p2

    .line 20
    new-instance v0, Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 21
    .line 22
    invoke-direct {v0}, Lio/opentelemetry/sdk/common/CompletableResultCode;-><init>()V

    .line 23
    .line 24
    .line 25
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/http/HttpExporter;->httpSender:Lio/opentelemetry/exporter/internal/http/HttpSender;

    .line 26
    .line 27
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/Marshaler;->getBinarySerializedSize()I

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    new-instance v3, Lio/opentelemetry/exporter/internal/http/a;

    .line 32
    .line 33
    const/4 v4, 0x0

    .line 34
    invoke-direct {v3, p0, v0, p2, v4}, Lio/opentelemetry/exporter/internal/http/a;-><init>(Lio/opentelemetry/exporter/internal/http/HttpExporter;Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;I)V

    .line 35
    .line 36
    .line 37
    new-instance v4, Lio/opentelemetry/exporter/internal/http/a;

    .line 38
    .line 39
    const/4 v5, 0x1

    .line 40
    invoke-direct {v4, p0, v0, p2, v5}, Lio/opentelemetry/exporter/internal/http/a;-><init>(Lio/opentelemetry/exporter/internal/http/HttpExporter;Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;I)V

    .line 41
    .line 42
    .line 43
    invoke-interface {v1, p1, v2, v3, v4}, Lio/opentelemetry/exporter/internal/http/HttpSender;->send(Lio/opentelemetry/exporter/internal/marshal/Marshaler;ILjava/util/function/Consumer;Ljava/util/function/Consumer;)V

    .line 44
    .line 45
    .line 46
    return-object v0
.end method

.method public shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporter;->isShutdown:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporter;->logger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;

    .line 12
    .line 13
    sget-object v0, Ljava/util/logging/Level;->INFO:Ljava/util/logging/Level;

    .line 14
    .line 15
    const-string v1, "Calling shutdown() multiple times."

    .line 16
    .line 17
    invoke-virtual {p0, v0, v1}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-static {}, Lio/opentelemetry/sdk/common/CompletableResultCode;->ofSuccess()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0

    .line 25
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/http/HttpExporter;->httpSender:Lio/opentelemetry/exporter/internal/http/HttpSender;

    .line 26
    .line 27
    invoke-interface {p0}, Lio/opentelemetry/exporter/internal/http/HttpSender;->shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0
.end method
