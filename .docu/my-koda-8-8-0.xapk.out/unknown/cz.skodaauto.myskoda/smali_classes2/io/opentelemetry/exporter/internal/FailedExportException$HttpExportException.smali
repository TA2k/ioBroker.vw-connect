.class public final Lio/opentelemetry/exporter/internal/FailedExportException$HttpExportException;
.super Lio/opentelemetry/exporter/internal/FailedExportException;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/exporter/internal/FailedExportException;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "HttpExportException"
.end annotation


# static fields
.field private static final serialVersionUID:J = -0x5e31a7690ab67e07L


# instance fields
.field private final cause:Ljava/lang/Throwable;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final response:Lio/opentelemetry/exporter/internal/http/HttpSender$Response;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field


# direct methods
.method private constructor <init>(Lio/opentelemetry/exporter/internal/http/HttpSender$Response;Ljava/lang/Throwable;)V
    .locals 1
    .param p1    # Lio/opentelemetry/exporter/internal/http/HttpSender$Response;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p2    # Ljava/lang/Throwable;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, p2, v0}, Lio/opentelemetry/exporter/internal/FailedExportException;-><init>(Ljava/lang/Throwable;Lio/opentelemetry/exporter/internal/FailedExportException$1;)V

    .line 3
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/FailedExportException$HttpExportException;->response:Lio/opentelemetry/exporter/internal/http/HttpSender$Response;

    .line 4
    iput-object p2, p0, Lio/opentelemetry/exporter/internal/FailedExportException$HttpExportException;->cause:Ljava/lang/Throwable;

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/exporter/internal/http/HttpSender$Response;Ljava/lang/Throwable;Lio/opentelemetry/exporter/internal/FailedExportException$1;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/exporter/internal/FailedExportException$HttpExportException;-><init>(Lio/opentelemetry/exporter/internal/http/HttpSender$Response;Ljava/lang/Throwable;)V

    return-void
.end method


# virtual methods
.method public failedWithResponse()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/FailedExportException$HttpExportException;->response:Lio/opentelemetry/exporter/internal/http/HttpSender$Response;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public getCause()Ljava/lang/Throwable;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/FailedExportException$HttpExportException;->cause:Ljava/lang/Throwable;

    .line 2
    .line 3
    return-object p0
.end method

.method public getResponse()Lio/opentelemetry/exporter/internal/http/HttpSender$Response;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/FailedExportException$HttpExportException;->response:Lio/opentelemetry/exporter/internal/http/HttpSender$Response;

    .line 2
    .line 3
    return-object p0
.end method
