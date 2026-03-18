.class public abstract Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics$Recording;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x409
    name = "Recording"
.end annotation


# instance fields
.field private alreadyEnded:Z


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-boolean v0, p0, Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics$Recording;->alreadyEnded:Z

    .line 6
    .line 7
    return-void
.end method

.method private ensureEndedOnce()V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics$Recording;->alreadyEnded:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    iput-boolean v0, p0, Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics$Recording;->alreadyEnded:Z

    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 10
    .line 11
    const-string v0, "Recording already ended"

    .line 12
    .line 13
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    throw p0
.end method


# virtual methods
.method public abstract doFinish(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;)V
    .param p1    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
.end method

.method public final finishFailed(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics$Recording;->ensureEndedOnce()V

    .line 2
    .line 3
    .line 4
    if-eqz p1, :cond_0

    .line 5
    .line 6
    invoke-virtual {p1}, Ljava/lang/String;->isEmpty()Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics$Recording;->doFinish(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;)V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 17
    .line 18
    const-string p1, "The export failed but no failure reason was provided"

    .line 19
    .line 20
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    throw p0
.end method

.method public final finishSuccessful(Lio/opentelemetry/api/common/Attributes;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics$Recording;->ensureEndedOnce()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    invoke-virtual {p0, v0, p1}, Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics$Recording;->doFinish(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
