.class public final Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/export/MetricExporter;


# annotations
.annotation build Ljavax/annotation/concurrent/ThreadSafe;
.end annotation


# instance fields
.field final aggregationTemporalitySelector:Lio/opentelemetry/sdk/metrics/export/AggregationTemporalitySelector;

.field private final builder:Lio/opentelemetry/exporter/internal/grpc/GrpcExporterBuilder;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/exporter/internal/grpc/GrpcExporterBuilder<",
            "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
            ">;"
        }
    .end annotation
.end field

.field final defaultAggregationSelector:Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;

.field private final delegate:Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/exporter/internal/grpc/GrpcExporter<",
            "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
            ">;"
        }
    .end annotation
.end field

.field private final marshaler:Lio/opentelemetry/exporter/internal/otlp/metrics/MetricReusableDataMarshaler;


# direct methods
.method public constructor <init>(Lio/opentelemetry/exporter/internal/grpc/GrpcExporterBuilder;Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;Lio/opentelemetry/sdk/metrics/export/AggregationTemporalitySelector;Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;Lio/opentelemetry/sdk/common/export/MemoryMode;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/exporter/internal/grpc/GrpcExporterBuilder<",
            "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
            ">;",
            "Lio/opentelemetry/exporter/internal/grpc/GrpcExporter<",
            "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
            ">;",
            "Lio/opentelemetry/sdk/metrics/export/AggregationTemporalitySelector;",
            "Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;",
            "Lio/opentelemetry/sdk/common/export/MemoryMode;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporter;->builder:Lio/opentelemetry/exporter/internal/grpc/GrpcExporterBuilder;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporter;->delegate:Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;

    .line 7
    .line 8
    iput-object p3, p0, Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporter;->aggregationTemporalitySelector:Lio/opentelemetry/sdk/metrics/export/AggregationTemporalitySelector;

    .line 9
    .line 10
    iput-object p4, p0, Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporter;->defaultAggregationSelector:Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;

    .line 11
    .line 12
    new-instance p1, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricReusableDataMarshaler;

    .line 13
    .line 14
    invoke-static {p2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    new-instance p3, Lio/opentelemetry/exporter/otlp/http/logs/a;

    .line 18
    .line 19
    const/4 p4, 0x1

    .line 20
    invoke-direct {p3, p2, p4}, Lio/opentelemetry/exporter/otlp/http/logs/a;-><init>(Ljava/lang/Object;I)V

    .line 21
    .line 22
    .line 23
    invoke-direct {p1, p5, p3}, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricReusableDataMarshaler;-><init>(Lio/opentelemetry/sdk/common/export/MemoryMode;Ljava/util/function/BiFunction;)V

    .line 24
    .line 25
    .line 26
    iput-object p1, p0, Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporter;->marshaler:Lio/opentelemetry/exporter/internal/otlp/metrics/MetricReusableDataMarshaler;

    .line 27
    .line 28
    return-void
.end method

.method public static builder()Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporterBuilder;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporterBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporterBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static getDefault()Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporter;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporter;->builder()Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporterBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporterBuilder;->build()Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporter;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    return-object v0
.end method


# virtual methods
.method public export(Ljava/util/Collection;)Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Lio/opentelemetry/sdk/metrics/data/MetricData;",
            ">;)",
            "Lio/opentelemetry/sdk/common/CompletableResultCode;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporter;->marshaler:Lio/opentelemetry/exporter/internal/otlp/metrics/MetricReusableDataMarshaler;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricReusableDataMarshaler;->export(Ljava/util/Collection;)Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public flush()Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 0

    .line 1
    invoke-static {}, Lio/opentelemetry/sdk/common/CompletableResultCode;->ofSuccess()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public getAggregationTemporality(Lio/opentelemetry/sdk/metrics/InstrumentType;)Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporter;->aggregationTemporalitySelector:Lio/opentelemetry/sdk/metrics/export/AggregationTemporalitySelector;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lio/opentelemetry/sdk/metrics/export/AggregationTemporalitySelector;->getAggregationTemporality(Lio/opentelemetry/sdk/metrics/InstrumentType;)Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getDefaultAggregation(Lio/opentelemetry/sdk/metrics/InstrumentType;)Lio/opentelemetry/sdk/metrics/Aggregation;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporter;->defaultAggregationSelector:Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;->getDefaultAggregation(Lio/opentelemetry/sdk/metrics/InstrumentType;)Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getMemoryMode()Lio/opentelemetry/sdk/common/export/MemoryMode;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporter;->marshaler:Lio/opentelemetry/exporter/internal/otlp/metrics/MetricReusableDataMarshaler;

    .line 2
    .line 3
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricReusableDataMarshaler;->getMemoryMode()Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporter;->delegate:Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;

    .line 2
    .line 3
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/grpc/GrpcExporter;->shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public toBuilder()Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporterBuilder;
    .locals 4

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporterBuilder;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporter;->builder:Lio/opentelemetry/exporter/internal/grpc/GrpcExporterBuilder;

    .line 4
    .line 5
    invoke-virtual {v1}, Lio/opentelemetry/exporter/internal/grpc/GrpcExporterBuilder;->copy()Lio/opentelemetry/exporter/internal/grpc/GrpcExporterBuilder;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    iget-object v2, p0, Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporter;->aggregationTemporalitySelector:Lio/opentelemetry/sdk/metrics/export/AggregationTemporalitySelector;

    .line 10
    .line 11
    iget-object v3, p0, Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporter;->defaultAggregationSelector:Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;

    .line 12
    .line 13
    iget-object p0, p0, Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporter;->marshaler:Lio/opentelemetry/exporter/internal/otlp/metrics/MetricReusableDataMarshaler;

    .line 14
    .line 15
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricReusableDataMarshaler;->getMemoryMode()Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-direct {v0, v1, v2, v3, p0}, Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporterBuilder;-><init>(Lio/opentelemetry/exporter/internal/grpc/GrpcExporterBuilder;Lio/opentelemetry/sdk/metrics/export/AggregationTemporalitySelector;Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;Lio/opentelemetry/sdk/common/export/MemoryMode;)V

    .line 20
    .line 21
    .line 22
    return-object v0
.end method

.method public toString()Ljava/lang/String;
    .locals 4

    .line 1
    new-instance v0, Ljava/util/StringJoiner;

    .line 2
    .line 3
    const-string v1, "OtlpGrpcMetricExporter{"

    .line 4
    .line 5
    const-string v2, "}"

    .line 6
    .line 7
    const-string v3, ", "

    .line 8
    .line 9
    invoke-direct {v0, v3, v1, v2}, Ljava/util/StringJoiner;-><init>(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Ljava/lang/CharSequence;)V

    .line 10
    .line 11
    .line 12
    iget-object v1, p0, Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporter;->builder:Lio/opentelemetry/exporter/internal/grpc/GrpcExporterBuilder;

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    invoke-virtual {v1, v2}, Lio/opentelemetry/exporter/internal/grpc/GrpcExporterBuilder;->toString(Z)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    invoke-virtual {v0, v1}, Ljava/util/StringJoiner;->add(Ljava/lang/CharSequence;)Ljava/util/StringJoiner;

    .line 20
    .line 21
    .line 22
    new-instance v1, Ljava/lang/StringBuilder;

    .line 23
    .line 24
    const-string v2, "aggregationTemporalitySelector="

    .line 25
    .line 26
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    iget-object v2, p0, Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporter;->aggregationTemporalitySelector:Lio/opentelemetry/sdk/metrics/export/AggregationTemporalitySelector;

    .line 30
    .line 31
    invoke-static {v2}, Lio/opentelemetry/sdk/metrics/export/AggregationTemporalitySelector;->asString(Lio/opentelemetry/sdk/metrics/export/AggregationTemporalitySelector;)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    invoke-virtual {v0, v1}, Ljava/util/StringJoiner;->add(Ljava/lang/CharSequence;)Ljava/util/StringJoiner;

    .line 43
    .line 44
    .line 45
    new-instance v1, Ljava/lang/StringBuilder;

    .line 46
    .line 47
    const-string v2, "defaultAggregationSelector="

    .line 48
    .line 49
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    iget-object v2, p0, Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporter;->defaultAggregationSelector:Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;

    .line 53
    .line 54
    invoke-static {v2}, Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;->asString(Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    invoke-virtual {v0, v1}, Ljava/util/StringJoiner;->add(Ljava/lang/CharSequence;)Ljava/util/StringJoiner;

    .line 66
    .line 67
    .line 68
    new-instance v1, Ljava/lang/StringBuilder;

    .line 69
    .line 70
    const-string v2, "memoryMode="

    .line 71
    .line 72
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    iget-object p0, p0, Lio/opentelemetry/exporter/otlp/metrics/OtlpGrpcMetricExporter;->marshaler:Lio/opentelemetry/exporter/internal/otlp/metrics/MetricReusableDataMarshaler;

    .line 76
    .line 77
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricReusableDataMarshaler;->getMemoryMode()Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    invoke-virtual {v0, p0}, Ljava/util/StringJoiner;->add(Ljava/lang/CharSequence;)Ljava/util/StringJoiner;

    .line 89
    .line 90
    .line 91
    invoke-virtual {v0}, Ljava/util/StringJoiner;->toString()Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    return-object p0
.end method
