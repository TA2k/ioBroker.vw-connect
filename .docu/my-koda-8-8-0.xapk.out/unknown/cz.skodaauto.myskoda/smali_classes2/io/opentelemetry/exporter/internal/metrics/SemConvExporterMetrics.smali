.class public Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics$Recording;
    }
.end annotation


# static fields
.field private static final CLOCK:Lio/opentelemetry/sdk/common/Clock;


# instance fields
.field private final additionalAttributes:Lio/opentelemetry/api/common/Attributes;

.field private volatile allAttributes:Lio/opentelemetry/api/common/Attributes;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final componentId:Lio/opentelemetry/sdk/internal/ComponentId;

.field private volatile duration:Lio/opentelemetry/api/metrics/DoubleHistogram;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private volatile exported:Lio/opentelemetry/api/metrics/LongCounter;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private volatile inflight:Lio/opentelemetry/api/metrics/LongUpDownCounter;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final meterProviderSupplier:Ljava/util/function/Supplier;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Supplier<",
            "Lio/opentelemetry/api/metrics/MeterProvider;",
            ">;"
        }
    .end annotation
.end field

.field private final signal:Lio/opentelemetry/sdk/internal/Signal;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/sdk/common/Clock;->getDefault()Lio/opentelemetry/sdk/common/Clock;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->CLOCK:Lio/opentelemetry/sdk/common/Clock;

    .line 6
    .line 7
    return-void
.end method

.method public constructor <init>(Ljava/util/function/Supplier;Lio/opentelemetry/sdk/internal/Signal;Lio/opentelemetry/sdk/internal/ComponentId;Lio/opentelemetry/api/common/Attributes;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Supplier<",
            "Lio/opentelemetry/api/metrics/MeterProvider;",
            ">;",
            "Lio/opentelemetry/sdk/internal/Signal;",
            "Lio/opentelemetry/sdk/internal/ComponentId;",
            "Lio/opentelemetry/api/common/Attributes;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->inflight:Lio/opentelemetry/api/metrics/LongUpDownCounter;

    .line 6
    .line 7
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->exported:Lio/opentelemetry/api/metrics/LongCounter;

    .line 8
    .line 9
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->duration:Lio/opentelemetry/api/metrics/DoubleHistogram;

    .line 10
    .line 11
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->allAttributes:Lio/opentelemetry/api/common/Attributes;

    .line 12
    .line 13
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->meterProviderSupplier:Ljava/util/function/Supplier;

    .line 14
    .line 15
    iput-object p3, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->componentId:Lio/opentelemetry/sdk/internal/ComponentId;

    .line 16
    .line 17
    iput-object p2, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->signal:Lio/opentelemetry/sdk/internal/Signal;

    .line 18
    .line 19
    iput-object p4, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->additionalAttributes:Lio/opentelemetry/api/common/Attributes;

    .line 20
    .line 21
    return-void
.end method

.method public static synthetic access$100()Lio/opentelemetry/sdk/common/Clock;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->CLOCK:Lio/opentelemetry/sdk/common/Clock;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic access$200(Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;J)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->incrementInflight(J)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic access$300(Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;J)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->decrementInflight(J)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic access$400(Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;JLjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->incrementExported(JLjava/lang/String;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic access$500(Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;DLjava/lang/String;Lio/opentelemetry/api/common/Attributes;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3, p4}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->recordDuration(DLjava/lang/String;Lio/opentelemetry/api/common/Attributes;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private allAttributes()Lio/opentelemetry/api/common/Attributes;
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->allAttributes:Lio/opentelemetry/api/common/Attributes;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->builder()Lio/opentelemetry/api/common/AttributesBuilder;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sget-object v1, Lio/opentelemetry/sdk/internal/SemConvAttributes;->OTEL_COMPONENT_TYPE:Lio/opentelemetry/api/common/AttributeKey;

    .line 10
    .line 11
    iget-object v2, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->componentId:Lio/opentelemetry/sdk/internal/ComponentId;

    .line 12
    .line 13
    invoke-virtual {v2}, Lio/opentelemetry/sdk/internal/ComponentId;->getTypeName()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    invoke-interface {v0, v1, v2}, Lio/opentelemetry/api/common/AttributesBuilder;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 18
    .line 19
    .line 20
    sget-object v1, Lio/opentelemetry/sdk/internal/SemConvAttributes;->OTEL_COMPONENT_NAME:Lio/opentelemetry/api/common/AttributeKey;

    .line 21
    .line 22
    iget-object v2, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->componentId:Lio/opentelemetry/sdk/internal/ComponentId;

    .line 23
    .line 24
    invoke-virtual {v2}, Lio/opentelemetry/sdk/internal/ComponentId;->getComponentName()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    invoke-interface {v0, v1, v2}, Lio/opentelemetry/api/common/AttributesBuilder;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 29
    .line 30
    .line 31
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->additionalAttributes:Lio/opentelemetry/api/common/Attributes;

    .line 32
    .line 33
    invoke-interface {v0, v1}, Lio/opentelemetry/api/common/AttributesBuilder;->putAll(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 34
    .line 35
    .line 36
    invoke-interface {v0}, Lio/opentelemetry/api/common/AttributesBuilder;->build()Lio/opentelemetry/api/common/Attributes;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->allAttributes:Lio/opentelemetry/api/common/Attributes;

    .line 41
    .line 42
    :cond_0
    return-object v0
.end method

.method private decrementInflight(J)V
    .locals 1

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->inflight()Lio/opentelemetry/api/metrics/LongUpDownCounter;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    neg-long p1, p1

    .line 6
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->allAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-interface {v0, p1, p2, p0}, Lio/opentelemetry/api/metrics/LongUpDownCounter;->add(JLio/opentelemetry/api/common/Attributes;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method private duration()Lio/opentelemetry/api/metrics/DoubleHistogram;
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->duration:Lio/opentelemetry/api/metrics/DoubleHistogram;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    invoke-static {v0}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->isNoop(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    return-object v0

    .line 13
    :cond_1
    :goto_0
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->meter()Lio/opentelemetry/api/metrics/Meter;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    const-string v1, "otel.sdk.exporter.operation.duration"

    .line 18
    .line 19
    invoke-interface {v0, v1}, Lio/opentelemetry/api/metrics/Meter;->histogramBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    const-string v1, "s"

    .line 24
    .line 25
    invoke-interface {v0, v1}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->setUnit(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    const-string v1, "The duration of exporting a batch of telemetry records"

    .line 30
    .line 31
    invoke-interface {v0, v1}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->setDescription(Ljava/lang/String;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    sget-object v1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 36
    .line 37
    invoke-interface {v0, v1}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->setExplicitBucketBoundariesAdvice(Ljava/util/List;)Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    invoke-interface {v0}, Lio/opentelemetry/api/metrics/DoubleHistogramBuilder;->build()Lio/opentelemetry/api/metrics/DoubleHistogram;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->duration:Lio/opentelemetry/api/metrics/DoubleHistogram;

    .line 46
    .line 47
    return-object v0
.end method

.method private exported()Lio/opentelemetry/api/metrics/LongCounter;
    .locals 4

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->exported:Lio/opentelemetry/api/metrics/LongCounter;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    invoke-static {v0}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->isNoop(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    return-object v0

    .line 13
    :cond_1
    :goto_0
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->signal:Lio/opentelemetry/sdk/internal/Signal;

    .line 14
    .line 15
    invoke-virtual {v0}, Lio/opentelemetry/sdk/internal/Signal;->getMetricUnit()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->meter()Lio/opentelemetry/api/metrics/Meter;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    new-instance v2, Ljava/lang/StringBuilder;

    .line 24
    .line 25
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 26
    .line 27
    .line 28
    iget-object v3, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->signal:Lio/opentelemetry/sdk/internal/Signal;

    .line 29
    .line 30
    invoke-virtual {v3}, Lio/opentelemetry/sdk/internal/Signal;->getExporterMetricNamespace()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    const-string v3, ".exported"

    .line 38
    .line 39
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v2

    .line 46
    invoke-interface {v1, v2}, Lio/opentelemetry/api/metrics/Meter;->counterBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongCounterBuilder;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    new-instance v2, Ljava/lang/StringBuilder;

    .line 51
    .line 52
    const-string v3, "{"

    .line 53
    .line 54
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    const-string v3, "}"

    .line 61
    .line 62
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v2

    .line 69
    invoke-interface {v1, v2}, Lio/opentelemetry/api/metrics/LongCounterBuilder;->setUnit(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongCounterBuilder;

    .line 70
    .line 71
    .line 72
    move-result-object v1

    .line 73
    new-instance v2, Ljava/lang/StringBuilder;

    .line 74
    .line 75
    const-string v3, "The number of "

    .line 76
    .line 77
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string v0, "s for which the export has finished, either successful or failed"

    .line 84
    .line 85
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    invoke-interface {v1, v0}, Lio/opentelemetry/api/metrics/LongCounterBuilder;->setDescription(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongCounterBuilder;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    invoke-interface {v0}, Lio/opentelemetry/api/metrics/LongCounterBuilder;->build()Lio/opentelemetry/api/metrics/LongCounter;

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->exported:Lio/opentelemetry/api/metrics/LongCounter;

    .line 101
    .line 102
    return-object v0
.end method

.method private getAttributesWithPotentialError(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/common/Attributes;
    .locals 2
    .param p1    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->allAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    invoke-virtual {p1}, Ljava/lang/String;->isEmpty()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    const/4 v0, 0x1

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    const/4 v0, 0x0

    .line 16
    :goto_0
    if-nez v0, :cond_2

    .line 17
    .line 18
    invoke-interface {p2}, Lio/opentelemetry/api/common/Attributes;->isEmpty()Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-nez v1, :cond_1

    .line 23
    .line 24
    goto :goto_1

    .line 25
    :cond_1
    return-object p0

    .line 26
    :cond_2
    :goto_1
    invoke-interface {p0}, Lio/opentelemetry/api/common/Attributes;->toBuilder()Lio/opentelemetry/api/common/AttributesBuilder;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    if-eqz v0, :cond_3

    .line 31
    .line 32
    sget-object v0, Lio/opentelemetry/sdk/internal/SemConvAttributes;->ERROR_TYPE:Lio/opentelemetry/api/common/AttributeKey;

    .line 33
    .line 34
    invoke-interface {p0, v0, p1}, Lio/opentelemetry/api/common/AttributesBuilder;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 35
    .line 36
    .line 37
    :cond_3
    invoke-interface {p0, p2}, Lio/opentelemetry/api/common/AttributesBuilder;->putAll(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-interface {p0}, Lio/opentelemetry/api/common/AttributesBuilder;->build()Lio/opentelemetry/api/common/Attributes;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0
.end method

.method private incrementExported(JLjava/lang/String;)V
    .locals 2
    .param p3    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->exported()Lio/opentelemetry/api/metrics/LongCounter;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-direct {p0, p3, v1}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->getAttributesWithPotentialError(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/common/Attributes;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-interface {v0, p1, p2, p0}, Lio/opentelemetry/api/metrics/LongCounter;->add(JLio/opentelemetry/api/common/Attributes;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method private incrementInflight(J)V
    .locals 1

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->inflight()Lio/opentelemetry/api/metrics/LongUpDownCounter;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->allAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-interface {v0, p1, p2, p0}, Lio/opentelemetry/api/metrics/LongUpDownCounter;->add(JLio/opentelemetry/api/common/Attributes;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method private inflight()Lio/opentelemetry/api/metrics/LongUpDownCounter;
    .locals 4

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->inflight:Lio/opentelemetry/api/metrics/LongUpDownCounter;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    invoke-static {v0}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->isNoop(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    return-object v0

    .line 13
    :cond_1
    :goto_0
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->signal:Lio/opentelemetry/sdk/internal/Signal;

    .line 14
    .line 15
    invoke-virtual {v0}, Lio/opentelemetry/sdk/internal/Signal;->getMetricUnit()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->meter()Lio/opentelemetry/api/metrics/Meter;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    new-instance v2, Ljava/lang/StringBuilder;

    .line 24
    .line 25
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 26
    .line 27
    .line 28
    iget-object v3, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->signal:Lio/opentelemetry/sdk/internal/Signal;

    .line 29
    .line 30
    invoke-virtual {v3}, Lio/opentelemetry/sdk/internal/Signal;->getExporterMetricNamespace()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    const-string v3, ".inflight"

    .line 38
    .line 39
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v2

    .line 46
    invoke-interface {v1, v2}, Lio/opentelemetry/api/metrics/Meter;->upDownCounterBuilder(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    new-instance v2, Ljava/lang/StringBuilder;

    .line 51
    .line 52
    const-string v3, "{"

    .line 53
    .line 54
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    const-string v3, "}"

    .line 61
    .line 62
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v2

    .line 69
    invoke-interface {v1, v2}, Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;->setUnit(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;

    .line 70
    .line 71
    .line 72
    move-result-object v1

    .line 73
    new-instance v2, Ljava/lang/StringBuilder;

    .line 74
    .line 75
    const-string v3, "The number of "

    .line 76
    .line 77
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string v0, "s which were passed to the exporter, but that have not been exported yet (neither successful, nor failed)"

    .line 84
    .line 85
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    invoke-interface {v1, v0}, Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;->setDescription(Ljava/lang/String;)Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    invoke-interface {v0}, Lio/opentelemetry/api/metrics/LongUpDownCounterBuilder;->build()Lio/opentelemetry/api/metrics/LongUpDownCounter;

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    iput-object v0, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->inflight:Lio/opentelemetry/api/metrics/LongUpDownCounter;

    .line 101
    .line 102
    return-object v0
.end method

.method public static isNoop(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const-string v0, "Noop"

    .line 10
    .line 11
    invoke-virtual {p0, v0}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0
.end method

.method private meter()Lio/opentelemetry/api/metrics/Meter;
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->meterProviderSupplier:Ljava/util/function/Supplier;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/function/Supplier;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lio/opentelemetry/api/metrics/MeterProvider;

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    invoke-static {}, Lio/opentelemetry/api/metrics/MeterProvider;->noop()Lio/opentelemetry/api/metrics/MeterProvider;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    :cond_0
    new-instance v1, Ljava/lang/StringBuilder;

    .line 16
    .line 17
    const-string v2, "io.opentelemetry.exporters."

    .line 18
    .line 19
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->componentId:Lio/opentelemetry/sdk/internal/ComponentId;

    .line 23
    .line 24
    invoke-virtual {p0}, Lio/opentelemetry/sdk/internal/ComponentId;->getTypeName()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-interface {v0, p0}, Lio/opentelemetry/api/metrics/MeterProvider;->get(Ljava/lang/String;)Lio/opentelemetry/api/metrics/Meter;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0
.end method

.method private recordDuration(DLjava/lang/String;Lio/opentelemetry/api/common/Attributes;)V
    .locals 1
    .param p3    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->duration()Lio/opentelemetry/api/metrics/DoubleHistogram;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-direct {p0, p3, p4}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;->getAttributesWithPotentialError(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/common/Attributes;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-interface {v0, p1, p2, p0}, Lio/opentelemetry/api/metrics/DoubleHistogram;->record(DLio/opentelemetry/api/common/Attributes;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public startRecordingExport(I)Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics$Recording;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics$Recording;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, p1, v1}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics$Recording;-><init>(Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;ILio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics$1;)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method
