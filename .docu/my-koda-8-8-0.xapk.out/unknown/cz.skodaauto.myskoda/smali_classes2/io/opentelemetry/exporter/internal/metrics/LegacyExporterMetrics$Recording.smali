.class Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$Recording;
.super Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics$Recording;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "Recording"
.end annotation


# instance fields
.field private final itemCount:I

.field final synthetic this$0:Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;


# direct methods
.method private constructor <init>(Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;I)V
    .locals 2

    .line 2
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$Recording;->this$0:Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;

    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics$Recording;-><init>()V

    .line 3
    iput p2, p0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$Recording;->itemCount:I

    int-to-long v0, p2

    .line 4
    invoke-static {p1, v0, v1}, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->access$100(Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;J)V

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;ILio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$1;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$Recording;-><init>(Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;I)V

    return-void
.end method


# virtual methods
.method public doFinish(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;)V
    .locals 2
    .param p1    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iget-object p1, p0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$Recording;->this$0:Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;

    .line 4
    .line 5
    iget p0, p0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$Recording;->itemCount:I

    .line 6
    .line 7
    int-to-long v0, p0

    .line 8
    invoke-static {p1, v0, v1}, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->access$200(Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;J)V

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :cond_0
    iget-object p1, p0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$Recording;->this$0:Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;

    .line 13
    .line 14
    iget p0, p0, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics$Recording;->itemCount:I

    .line 15
    .line 16
    int-to-long v0, p0

    .line 17
    invoke-static {p1, v0, v1}, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->access$300(Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;J)V

    .line 18
    .line 19
    .line 20
    return-void
.end method
