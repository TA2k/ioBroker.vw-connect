.class public Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;
    }
.end annotation


# instance fields
.field private final implementation:Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics;


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/common/InternalTelemetryVersion;Ljava/util/function/Supplier;Lio/opentelemetry/sdk/internal/StandardComponentId;Ljava/lang/String;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/common/InternalTelemetryVersion;",
            "Ljava/util/function/Supplier<",
            "Lio/opentelemetry/api/metrics/MeterProvider;",
            ">;",
            "Lio/opentelemetry/sdk/internal/StandardComponentId;",
            "Ljava/lang/String;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p3}, Lio/opentelemetry/sdk/internal/StandardComponentId;->getStandardType()Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    invoke-virtual {v0}, Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;->signal()Lio/opentelemetry/sdk/internal/Signal;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    sget-object v1, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$1;->$SwitchMap$io$opentelemetry$sdk$common$InternalTelemetryVersion:[I

    .line 13
    .line 14
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    aget v1, v1, v2

    .line 19
    .line 20
    const/4 v2, 0x1

    .line 21
    if-eq v1, v2, :cond_2

    .line 22
    .line 23
    const/4 v2, 0x2

    .line 24
    if-ne v1, v2, :cond_1

    .line 25
    .line 26
    sget-object p1, Lio/opentelemetry/sdk/internal/Signal;->PROFILE:Lio/opentelemetry/sdk/internal/Signal;

    .line 27
    .line 28
    if-ne v0, p1, :cond_0

    .line 29
    .line 30
    sget-object p1, Lio/opentelemetry/exporter/internal/metrics/NoopExporterMetrics;->INSTANCE:Lio/opentelemetry/exporter/internal/metrics/NoopExporterMetrics;

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    new-instance p1, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;

    .line 34
    .line 35
    invoke-static {p4}, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation;->extractServerAttributes(Ljava/lang/String;)Lio/opentelemetry/api/common/Attributes;

    .line 36
    .line 37
    .line 38
    move-result-object p4

    .line 39
    invoke-direct {p1, p2, v0, p3, p4}, Lio/opentelemetry/exporter/internal/metrics/SemConvExporterMetrics;-><init>(Ljava/util/function/Supplier;Lio/opentelemetry/sdk/internal/Signal;Lio/opentelemetry/sdk/internal/ComponentId;Lio/opentelemetry/api/common/Attributes;)V

    .line 40
    .line 41
    .line 42
    :goto_0
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation;->implementation:Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics;

    .line 43
    .line 44
    return-void

    .line 45
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    new-instance p2, Ljava/lang/StringBuilder;

    .line 48
    .line 49
    const-string p3, "Unhandled case: "

    .line 50
    .line 51
    invoke-direct {p2, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw p0

    .line 65
    :cond_2
    invoke-virtual {p3}, Lio/opentelemetry/sdk/internal/StandardComponentId;->getStandardType()Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;->isSupportedType(Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;)Z

    .line 70
    .line 71
    .line 72
    move-result p1

    .line 73
    if-eqz p1, :cond_3

    .line 74
    .line 75
    new-instance p1, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;

    .line 76
    .line 77
    invoke-virtual {p3}, Lio/opentelemetry/sdk/internal/StandardComponentId;->getStandardType()Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;

    .line 78
    .line 79
    .line 80
    move-result-object p3

    .line 81
    invoke-direct {p1, p2, p3}, Lio/opentelemetry/exporter/internal/metrics/LegacyExporterMetrics;-><init>(Ljava/util/function/Supplier;Lio/opentelemetry/sdk/internal/StandardComponentId$ExporterType;)V

    .line 82
    .line 83
    .line 84
    goto :goto_1

    .line 85
    :cond_3
    sget-object p1, Lio/opentelemetry/exporter/internal/metrics/NoopExporterMetrics;->INSTANCE:Lio/opentelemetry/exporter/internal/metrics/NoopExporterMetrics;

    .line 86
    .line 87
    :goto_1
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation;->implementation:Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics;

    .line 88
    .line 89
    return-void
.end method

.method public static extractServerAttributes(Ljava/lang/String;)Lio/opentelemetry/api/common/Attributes;
    .locals 4

    .line 1
    :try_start_0
    new-instance v0, Ljava/net/URI;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Ljava/net/URI;-><init>(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->builder()Lio/opentelemetry/api/common/AttributesBuilder;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {v0}, Ljava/net/URI;->getHost()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    if-eqz v1, :cond_0

    .line 15
    .line 16
    sget-object v2, Lio/opentelemetry/sdk/internal/SemConvAttributes;->SERVER_ADDRESS:Lio/opentelemetry/api/common/AttributeKey;

    .line 17
    .line 18
    invoke-interface {p0, v2, v1}, Lio/opentelemetry/api/common/AttributesBuilder;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 19
    .line 20
    .line 21
    :cond_0
    invoke-virtual {v0}, Ljava/net/URI;->getPort()I

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    const/4 v2, -0x1

    .line 26
    if-ne v1, v2, :cond_2

    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/net/URI;->getScheme()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    const-string v3, "https"

    .line 33
    .line 34
    invoke-virtual {v3, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v3

    .line 38
    if-eqz v3, :cond_1

    .line 39
    .line 40
    const/16 v1, 0x1bb

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_1
    const-string v3, "http"

    .line 44
    .line 45
    invoke-virtual {v3, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    if-eqz v0, :cond_2

    .line 50
    .line 51
    const/16 v1, 0x50

    .line 52
    .line 53
    :cond_2
    :goto_0
    if-eq v1, v2, :cond_3

    .line 54
    .line 55
    sget-object v0, Lio/opentelemetry/sdk/internal/SemConvAttributes;->SERVER_PORT:Lio/opentelemetry/api/common/AttributeKey;

    .line 56
    .line 57
    invoke-interface {p0, v0, v1}, Lio/opentelemetry/api/common/AttributesBuilder;->put(Lio/opentelemetry/api/common/AttributeKey;I)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 58
    .line 59
    .line 60
    :cond_3
    invoke-interface {p0}, Lio/opentelemetry/api/common/AttributesBuilder;->build()Lio/opentelemetry/api/common/Attributes;

    .line 61
    .line 62
    .line 63
    move-result-object p0
    :try_end_0
    .catch Ljava/net/URISyntaxException; {:try_start_0 .. :try_end_0} :catch_0

    .line 64
    return-object p0

    .line 65
    :catch_0
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    return-object p0
.end method


# virtual methods
.method public startRecordingExport(I)Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;

    .line 2
    .line 3
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation;->implementation:Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics;

    .line 4
    .line 5
    invoke-interface {p0, p1}, Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics;->startRecordingExport(I)Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics$Recording;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const/4 p1, 0x0

    .line 10
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$Recording;-><init>(Lio/opentelemetry/exporter/internal/metrics/ExporterMetrics$Recording;Lio/opentelemetry/exporter/internal/metrics/ExporterInstrumentation$1;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method
