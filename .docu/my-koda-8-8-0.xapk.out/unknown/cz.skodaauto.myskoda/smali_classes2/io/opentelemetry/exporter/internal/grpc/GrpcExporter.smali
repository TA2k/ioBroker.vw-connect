.class public final Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;
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

.field private final grpcSender:Lio/opentelemetry/exporter/internal/grpc/GrpcSender;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/exporter/internal/grpc/GrpcSender<",
            "TT;>;"
        }
    .end annotation
.end field

.field private final isShutdown:Ljava/util/concurrent/atomic/AtomicBoolean;

.field private final loggedUnimplemented:Ljava/util/concurrent/atomic/AtomicBoolean;

.field private final logger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;

.field private final type:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;

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
    sput-object v0, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->internalLogger:Ljava/util/logging/Logger;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/exporter/internal/grpc/GrpcSender;Lio/opentelemetry/sdk/common/InternalTelemetryVersion;Lio/opentelemetry/sdk/internal/StandardComponentId;Ljava/util/function/Supplier;Ljava/lang/String;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/exporter/internal/grpc/GrpcSender<",
            "TT;>;",
            "Lio/opentelemetry/sdk/common/InternalTelemetryVersion;",
            "Lio/opentelemetry/sdk/internal/StandardComponentId;",
            "Ljava/util/function/Supplier<",
            "Lio/opentelemetry/api/metrics/MeterProvider;",
            ">;",
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
    sget-object v1, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->internalLogger:Ljava/util/logging/Logger;

    .line 7
    .line 8
    invoke-direct {v0, v1}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;-><init>(Ljava/util/logging/Logger;)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->logger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;

    .line 12
    .line 13
    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 14
    .line 15
    invoke-direct {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>()V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->loggedUnimplemented:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 19
    .line 20
    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 21
    .line 22
    invoke-direct {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>()V

    .line 23
    .line 24
    .line 25
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->isShutdown:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 26
    .line 27
    invoke-virtual {p3}, Lio/opentelemetry/sdk/internal/StandardComponentId;->getStandardType()Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    invoke-virtual {v0}, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->signal()Lio/opentelemetry/sdk/internal/Signal;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    invoke-virtual {v0}, Lio/opentelemetry/sdk/internal/Signal;->logFriendlyName()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->type:Ljava/lang/String;

    .line 40
    .line 41
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->grpcSender:Lio/opentelemetry/exporter/internal/grpc/GrpcSender;

    .line 42
    .line 43
    new-instance p1, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation;

    .line 44
    .line 45
    invoke-direct {p1, p2, p4, p3, p5}, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation;-><init>(Lio/opentelemetry/sdk/common/InternalTelemetryVersion;Ljava/util/function/Supplier;Lio/opentelemetry/sdk/internal/StandardComponentId;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->exporterMetrics:Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation;

    .line 49
    .line 50
    return-void
.end method

.method public static synthetic a(Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;Ljava/lang/Throwable;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->lambda$export$1(Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;Ljava/lang/Throwable;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic b(Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;Lio/opentelemetry/exporter/internal/grpc/GrpcResponse;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->lambda$export$0(Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;Lio/opentelemetry/exporter/internal/grpc/GrpcResponse;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private synthetic lambda$export$0(Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;Lio/opentelemetry/exporter/internal/grpc/GrpcResponse;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->onResponse(Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;Lio/opentelemetry/exporter/internal/grpc/GrpcResponse;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private synthetic lambda$export$1(Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;Ljava/lang/Throwable;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->onError(Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;Ljava/lang/Throwable;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private onError(Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;Ljava/lang/Throwable;)V
    .locals 4

    .line 1
    invoke-virtual {p2, p3}, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;->finishFailed(Ljava/lang/Throwable;)V

    .line 2
    .line 3
    .line 4
    iget-object p2, p0, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->logger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;

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
    iget-object v3, p0, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->type:Ljava/lang/String;

    .line 16
    .line 17
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    const-string v3, "s. The request could not be executed. Error message: "

    .line 21
    .line 22
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {p3}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    invoke-virtual {p2, v0, v1, p3}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->log(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 37
    .line 38
    .line 39
    iget-object p2, p0, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->logger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;

    .line 40
    .line 41
    sget-object v0, Ljava/util/logging/Level;->FINEST:Ljava/util/logging/Level;

    .line 42
    .line 43
    invoke-virtual {p2, v0}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->isLoggable(Ljava/util/logging/Level;)Z

    .line 44
    .line 45
    .line 46
    move-result p2

    .line 47
    if-eqz p2, :cond_0

    .line 48
    .line 49
    iget-object p2, p0, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->logger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;

    .line 50
    .line 51
    new-instance v1, Ljava/lang/StringBuilder;

    .line 52
    .line 53
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->type:Ljava/lang/String;

    .line 57
    .line 58
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    const-string p0, "s. Details follow: "

    .line 62
    .line 63
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    invoke-virtual {v1, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    invoke-virtual {p2, v0, p0}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    :cond_0
    invoke-static {p3}, Lio/opentelemetry/exporter/internal/FailedExportException;->grpcFailedExceptionally(Ljava/lang/Throwable;)Lio/opentelemetry/exporter/internal/FailedExportException$GrpcExportException;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    invoke-virtual {p1, p0}, Lio/opentelemetry/sdk/common/CompletableResultCode;->failExceptionally(Ljava/lang/Throwable;)Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 81
    .line 82
    .line 83
    return-void
.end method

.method private onResponse(Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;Lio/opentelemetry/exporter/internal/grpc/GrpcResponse;)V
    .locals 5

    .line 1
    invoke-virtual {p3}, Lio/opentelemetry/exporter/internal/grpc/GrpcResponse;->grpcStatusValue()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    int-to-long v1, v0

    .line 6
    invoke-virtual {p2, v1, v2}, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;->setGrpcStatusCode(J)V

    .line 7
    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    invoke-virtual {p2}, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;->finishSuccessful()V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p1}, Lio/opentelemetry/sdk/common/CompletableResultCode;->succeed()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    invoke-virtual {p2, v1}, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;->finishFailed(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    const/16 p2, 0xc

    .line 26
    .line 27
    if-eq v0, p2, :cond_2

    .line 28
    .line 29
    const/16 p2, 0xe

    .line 30
    .line 31
    const-string v1, "Failed to export "

    .line 32
    .line 33
    if-eq v0, p2, :cond_1

    .line 34
    .line 35
    iget-object p2, p0, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->logger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;

    .line 36
    .line 37
    sget-object v2, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    .line 38
    .line 39
    new-instance v3, Ljava/lang/StringBuilder;

    .line 40
    .line 41
    invoke-direct {v3, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->type:Ljava/lang/String;

    .line 45
    .line 46
    const-string v1, "s. Server responded with gRPC status code "

    .line 47
    .line 48
    const-string v4, ". Error message: "

    .line 49
    .line 50
    invoke-static {v3, p0, v1, v0, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->z(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {p3}, Lio/opentelemetry/exporter/internal/grpc/GrpcResponse;->grpcStatusDescription()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    invoke-virtual {p2, v2, p0}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_1
    iget-object p2, p0, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->logger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;

    .line 69
    .line 70
    sget-object v0, Ljava/util/logging/Level;->SEVERE:Ljava/util/logging/Level;

    .line 71
    .line 72
    new-instance v2, Ljava/lang/StringBuilder;

    .line 73
    .line 74
    invoke-direct {v2, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->type:Ljava/lang/String;

    .line 78
    .line 79
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    const-string p0, "s. Server is UNAVAILABLE. Make sure your collector is running and reachable from this network. Full error message:"

    .line 83
    .line 84
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    invoke-virtual {p3}, Lio/opentelemetry/exporter/internal/grpc/GrpcResponse;->grpcStatusDescription()Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    invoke-virtual {p2, v0, p0}, Lio/opentelemetry/sdk/internal/ThrottlingLogger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    goto :goto_0

    .line 102
    :cond_2
    iget-object p2, p0, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->loggedUnimplemented:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 103
    .line 104
    const/4 v0, 0x0

    .line 105
    const/4 v1, 0x1

    .line 106
    invoke-virtual {p2, v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    .line 107
    .line 108
    .line 109
    move-result p2

    .line 110
    if-eqz p2, :cond_3

    .line 111
    .line 112
    sget-object p2, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->internalLogger:Ljava/util/logging/Logger;

    .line 113
    .line 114
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->type:Ljava/lang/String;

    .line 115
    .line 116
    invoke-virtual {p3}, Lio/opentelemetry/exporter/internal/grpc/GrpcResponse;->grpcStatusDescription()Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object v0

    .line 120
    invoke-static {p2, p0, v0}, Lio/opentelemetry/exporter/internal/grpc/GrpcExporterUtil;->logUnimplemented(Ljava/util/logging/Logger;Ljava/lang/String;Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    :cond_3
    :goto_0
    invoke-static {p3}, Lio/opentelemetry/exporter/internal/FailedExportException;->grpcFailedWithResponse(Lio/opentelemetry/exporter/internal/grpc/GrpcResponse;)Lio/opentelemetry/exporter/internal/FailedExportException$GrpcExportException;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    invoke-virtual {p1, p0}, Lio/opentelemetry/sdk/common/CompletableResultCode;->failExceptionally(Ljava/lang/Throwable;)Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 128
    .line 129
    .line 130
    return-void
.end method


# virtual methods
.method public export(Lio/opentelemetry/exporter/internal/marshal/Marshaler;I)Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TT;I)",
            "Lio/opentelemetry/sdk/common/CompletableResultCode;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->isShutdown:Ljava/util/concurrent/atomic/AtomicBoolean;

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
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->exporterMetrics:Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation;

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
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->grpcSender:Lio/opentelemetry/exporter/internal/grpc/GrpcSender;

    .line 26
    .line 27
    new-instance v2, Lio/opentelemetry/exporter/internal/grpc/a;

    .line 28
    .line 29
    const/4 v3, 0x0

    .line 30
    invoke-direct {v2, p0, v0, p2, v3}, Lio/opentelemetry/exporter/internal/grpc/a;-><init>(Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;I)V

    .line 31
    .line 32
    .line 33
    new-instance v3, Lio/opentelemetry/exporter/internal/grpc/a;

    .line 34
    .line 35
    const/4 v4, 0x1

    .line 36
    invoke-direct {v3, p0, v0, p2, v4}, Lio/opentelemetry/exporter/internal/grpc/a;-><init>(Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;I)V

    .line 37
    .line 38
    .line 39
    invoke-interface {v1, p1, v2, v3}, Lio/opentelemetry/exporter/internal/grpc/GrpcSender;->send(Lio/opentelemetry/exporter/internal/marshal/Marshaler;Ljava/util/function/Consumer;Ljava/util/function/Consumer;)V

    .line 40
    .line 41
    .line 42
    return-object v0
.end method

.method public shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->isShutdown:Ljava/util/concurrent/atomic/AtomicBoolean;

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
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->logger:Lio/opentelemetry/sdk/internal/ThrottlingLogger;

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
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->grpcSender:Lio/opentelemetry/exporter/internal/grpc/GrpcSender;

    .line 26
    .line 27
    invoke-interface {p0}, Lio/opentelemetry/exporter/internal/grpc/GrpcSender;->shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0
.end method
