.class public abstract Lio/opentelemetry/exporter/internal/FailedExportException;
.super Ljava/lang/Exception;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/exporter/internal/FailedExportException$HttpExportException;,
        Lio/opentelemetry/exporter/internal/FailedExportException$GrpcExportException;
    }
.end annotation


# static fields
.field private static final serialVersionUID:J = 0x60fda62078875b65L


# direct methods
.method private constructor <init>(Ljava/lang/Throwable;)V
    .locals 0
    .param p1    # Ljava/lang/Throwable;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 2
    invoke-direct {p0, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/Throwable;)V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Throwable;Lio/opentelemetry/exporter/internal/FailedExportException$1;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lio/opentelemetry/exporter/internal/FailedExportException;-><init>(Ljava/lang/Throwable;)V

    return-void
.end method

.method public static grpcFailedExceptionally(Ljava/lang/Throwable;)Lio/opentelemetry/exporter/internal/FailedExportException$GrpcExportException;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/FailedExportException$GrpcExportException;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1, p0, v1}, Lio/opentelemetry/exporter/internal/FailedExportException$GrpcExportException;-><init>(Lio/opentelemetry/exporter/internal/grpc/GrpcResponse;Ljava/lang/Throwable;Lio/opentelemetry/exporter/internal/FailedExportException$1;)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method public static grpcFailedWithResponse(Lio/opentelemetry/exporter/internal/grpc/GrpcResponse;)Lio/opentelemetry/exporter/internal/FailedExportException$GrpcExportException;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/FailedExportException$GrpcExportException;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, v1, v1}, Lio/opentelemetry/exporter/internal/FailedExportException$GrpcExportException;-><init>(Lio/opentelemetry/exporter/internal/grpc/GrpcResponse;Ljava/lang/Throwable;Lio/opentelemetry/exporter/internal/FailedExportException$1;)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method public static httpFailedExceptionally(Ljava/lang/Throwable;)Lio/opentelemetry/exporter/internal/FailedExportException$HttpExportException;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/FailedExportException$HttpExportException;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1, p0, v1}, Lio/opentelemetry/exporter/internal/FailedExportException$HttpExportException;-><init>(Lio/opentelemetry/exporter/internal/http/HttpSender$Response;Ljava/lang/Throwable;Lio/opentelemetry/exporter/internal/FailedExportException$1;)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method public static httpFailedWithResponse(Lio/opentelemetry/exporter/internal/http/HttpSender$Response;)Lio/opentelemetry/exporter/internal/FailedExportException$HttpExportException;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/FailedExportException$HttpExportException;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, v1, v1}, Lio/opentelemetry/exporter/internal/FailedExportException$HttpExportException;-><init>(Lio/opentelemetry/exporter/internal/http/HttpSender$Response;Ljava/lang/Throwable;Lio/opentelemetry/exporter/internal/FailedExportException$1;)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method


# virtual methods
.method public abstract failedWithResponse()Z
.end method
