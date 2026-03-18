.class public Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "Recording"
.end annotation


# instance fields
.field private final delegate:Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics$Recording;

.field private grpcStatusCode:Ljava/lang/Long;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private httpStatusCode:Ljava/lang/Long;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field


# direct methods
.method private constructor <init>(Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics$Recording;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;->delegate:Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics$Recording;

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics$Recording;Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$1;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;-><init>(Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics$Recording;)V

    return-void
.end method

.method private buildRequestAttributes()Lio/opentelemetry/api/common/Attributes;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;->httpStatusCode:Ljava/lang/Long;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget-object p0, Lio/opentelemetry/sdk/internal/SemConvAttributes;->HTTP_RESPONSE_STATUS_CODE:Lio/opentelemetry/api/common/AttributeKey;

    .line 6
    .line 7
    invoke-static {p0, v0}, Lio/opentelemetry/api/common/Attributes;->of(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/Attributes;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;->grpcStatusCode:Ljava/lang/Long;

    .line 13
    .line 14
    if-eqz p0, :cond_1

    .line 15
    .line 16
    sget-object v0, Lio/opentelemetry/sdk/internal/SemConvAttributes;->RPC_GRPC_STATUS_CODE:Lio/opentelemetry/api/common/AttributeKey;

    .line 17
    .line 18
    invoke-static {v0, p0}, Lio/opentelemetry/api/common/Attributes;->of(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/Attributes;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :cond_1
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0
.end method


# virtual methods
.method public finishFailed(Ljava/lang/String;)V
    .locals 1

    .line 2
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;->delegate:Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics$Recording;

    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;->buildRequestAttributes()Lio/opentelemetry/api/common/Attributes;

    move-result-object p0

    invoke-virtual {v0, p1, p0}, Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics$Recording;->finishFailed(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;)V

    return-void
.end method

.method public finishFailed(Ljava/lang/Throwable;)V
    .locals 0

    .line 1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, p1}, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;->finishFailed(Ljava/lang/String;)V

    return-void
.end method

.method public finishSuccessful()V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;->delegate:Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics$Recording;

    .line 2
    .line 3
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;->buildRequestAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {v0, p0}, Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics$Recording;->finishSuccessful(Lio/opentelemetry/api/common/Attributes;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public setGrpcStatusCode(J)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;->httpStatusCode:Ljava/lang/Long;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-static {p1, p2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;->grpcStatusCode:Ljava/lang/Long;

    .line 10
    .line 11
    return-void

    .line 12
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 13
    .line 14
    const-string p1, "HTTP status code already set, can only set either gRPC or HTTP"

    .line 15
    .line 16
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    throw p0
.end method

.method public setHttpStatusCode(J)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;->grpcStatusCode:Ljava/lang/Long;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-static {p1, p2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;->httpStatusCode:Ljava/lang/Long;

    .line 10
    .line 11
    return-void

    .line 12
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 13
    .line 14
    const-string p1, "gRPC status code already set, can only set either gRPC or HTTP"

    .line 15
    .line 16
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    throw p0
.end method
