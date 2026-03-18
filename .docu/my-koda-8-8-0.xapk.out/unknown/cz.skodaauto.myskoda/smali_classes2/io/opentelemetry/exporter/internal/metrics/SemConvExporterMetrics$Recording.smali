.class Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics$Recording;
.super Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics$Recording;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "Recording"
.end annotation


# instance fields
.field private final itemCount:I

.field private final startNanoTime:J

.field final synthetic this$0:Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;


# direct methods
.method private constructor <init>(Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;I)V
    .locals 2

    .line 2
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics$Recording;->this$0:Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;

    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics$Recording;-><init>()V

    .line 3
    iput p2, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics$Recording;->itemCount:I

    .line 4
    invoke-static {}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->access$100()Lio/opentelemetry/sdk/common/Clock;

    move-result-object v0

    invoke-interface {v0}, Lio/opentelemetry/sdk/common/Clock;->nanoTime()J

    move-result-wide v0

    iput-wide v0, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics$Recording;->startNanoTime:J

    int-to-long v0, p2

    .line 5
    invoke-static {p1, v0, v1}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->access$200(Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;J)V

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;ILio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics$1;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics$Recording;-><init>(Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;I)V

    return-void
.end method


# virtual methods
.method public doFinish(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;)V
    .locals 4
    .param p1    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics$Recording;->this$0:Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;

    .line 2
    .line 3
    iget v1, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics$Recording;->itemCount:I

    .line 4
    .line 5
    int-to-long v1, v1

    .line 6
    invoke-static {v0, v1, v2}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->access$300(Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;J)V

    .line 7
    .line 8
    .line 9
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics$Recording;->this$0:Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;

    .line 10
    .line 11
    iget v1, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics$Recording;->itemCount:I

    .line 12
    .line 13
    int-to-long v1, v1

    .line 14
    invoke-static {v0, v1, v2, p1}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->access$400(Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;JLjava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-static {}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->access$100()Lio/opentelemetry/sdk/common/Clock;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    invoke-interface {v0}, Lio/opentelemetry/sdk/common/Clock;->nanoTime()J

    .line 22
    .line 23
    .line 24
    move-result-wide v0

    .line 25
    iget-wide v2, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics$Recording;->startNanoTime:J

    .line 26
    .line 27
    sub-long/2addr v0, v2

    .line 28
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics$Recording;->this$0:Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;

    .line 29
    .line 30
    long-to-double v0, v0

    .line 31
    const-wide v2, 0x41cdcd6500000000L    # 1.0E9

    .line 32
    .line 33
    .line 34
    .line 35
    .line 36
    div-double/2addr v0, v2

    .line 37
    invoke-static {p0, v0, v1, p1, p2}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->access$500(Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;DLjava/lang/String;Lio/opentelemetry/api/common/Attributes;)V

    .line 38
    .line 39
    .line 40
    return-void
.end method
