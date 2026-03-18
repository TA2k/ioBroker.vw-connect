.class public abstract Lz81/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lio/opentelemetry/api/common/AttributeKey;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "service.name"

    .line 2
    .line 3
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lz81/h;->a:Lio/opentelemetry/api/common/AttributeKey;

    .line 8
    .line 9
    return-void
.end method

.method public static final a(Lh/w;)Lio/opentelemetry/sdk/logs/export/LogRecordExporter;
    .locals 4

    .line 1
    iget-object v0, p0, Lh/w;->b:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lz81/s;

    .line 4
    .line 5
    instance-of v1, v0, Lz81/r;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    invoke-static {}, Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporter;->builder()Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    check-cast v0, Lz81/r;

    .line 14
    .line 15
    const-string v0, "https://otlp.eu01.nr-data.net"

    .line 16
    .line 17
    invoke-virtual {v1, v0}, Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;->setEndpoint(Ljava/lang/String;)Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    const-string v1, "gzip"

    .line 22
    .line 23
    invoke-virtual {v0, v1}, Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;->setCompression(Ljava/lang/String;)Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    sget-object v1, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 28
    .line 29
    const-wide/16 v2, 0x3c

    .line 30
    .line 31
    invoke-virtual {v0, v2, v3, v1}, Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;->setTimeout(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    invoke-virtual {v0, v2, v3, v1}, Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;->setConnectTimeout(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    invoke-static {}, Lio/opentelemetry/sdk/common/export/RetryPolicy;->getDefault()Lio/opentelemetry/sdk/common/export/RetryPolicy;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    invoke-virtual {v0, v1}, Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;->setRetryPolicy(Lio/opentelemetry/sdk/common/export/RetryPolicy;)Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    iget-object p0, p0, Lh/w;->c:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast p0, Lz81/c;

    .line 50
    .line 51
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    invoke-interface {p0, v0}, Lz81/c;->a(Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;)Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;

    .line 55
    .line 56
    .line 57
    invoke-virtual {v0}, Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;->build()Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporter;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    const-string v0, "build(...)"

    .line 62
    .line 63
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    return-object p0

    .line 67
    :cond_0
    invoke-static {}, Lio/opentelemetry/exporter/logging/SystemOutLogRecordExporter;->create()Lio/opentelemetry/exporter/logging/SystemOutLogRecordExporter;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    const-string v0, "create(...)"

    .line 72
    .line 73
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    return-object p0
.end method

.method public static final b(Lh/w;)Lio/opentelemetry/sdk/trace/export/SpanExporter;
    .locals 4

    .line 1
    iget-object v0, p0, Lh/w;->b:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lz81/s;

    .line 4
    .line 5
    instance-of v1, v0, Lz81/r;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    invoke-static {}, Lio/opentelemetry/exporter/otlp/trace/OtlpGrpcSpanExporter;->builder()Lio/opentelemetry/exporter/otlp/trace/OtlpGrpcSpanExporterBuilder;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    check-cast v0, Lz81/r;

    .line 14
    .line 15
    const-string v0, "https://otlp.eu01.nr-data.net"

    .line 16
    .line 17
    invoke-virtual {v1, v0}, Lio/opentelemetry/exporter/otlp/trace/OtlpGrpcSpanExporterBuilder;->setEndpoint(Ljava/lang/String;)Lio/opentelemetry/exporter/otlp/trace/OtlpGrpcSpanExporterBuilder;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    const-string v1, "gzip"

    .line 22
    .line 23
    invoke-virtual {v0, v1}, Lio/opentelemetry/exporter/otlp/trace/OtlpGrpcSpanExporterBuilder;->setCompression(Ljava/lang/String;)Lio/opentelemetry/exporter/otlp/trace/OtlpGrpcSpanExporterBuilder;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    sget-object v1, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 28
    .line 29
    const-wide/16 v2, 0x3c

    .line 30
    .line 31
    invoke-virtual {v0, v2, v3, v1}, Lio/opentelemetry/exporter/otlp/trace/OtlpGrpcSpanExporterBuilder;->setTimeout(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/exporter/otlp/trace/OtlpGrpcSpanExporterBuilder;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    invoke-virtual {v0, v2, v3, v1}, Lio/opentelemetry/exporter/otlp/trace/OtlpGrpcSpanExporterBuilder;->setConnectTimeout(JLjava/util/concurrent/TimeUnit;)Lio/opentelemetry/exporter/otlp/trace/OtlpGrpcSpanExporterBuilder;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    invoke-static {}, Lio/opentelemetry/sdk/common/export/RetryPolicy;->getDefault()Lio/opentelemetry/sdk/common/export/RetryPolicy;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    invoke-virtual {v0, v1}, Lio/opentelemetry/exporter/otlp/trace/OtlpGrpcSpanExporterBuilder;->setRetryPolicy(Lio/opentelemetry/sdk/common/export/RetryPolicy;)Lio/opentelemetry/exporter/otlp/trace/OtlpGrpcSpanExporterBuilder;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    iget-object p0, p0, Lh/w;->c:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast p0, Lz81/c;

    .line 50
    .line 51
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    invoke-interface {p0, v0}, Lz81/c;->b(Lio/opentelemetry/exporter/otlp/trace/OtlpGrpcSpanExporterBuilder;)Lio/opentelemetry/exporter/otlp/trace/OtlpGrpcSpanExporterBuilder;

    .line 55
    .line 56
    .line 57
    invoke-virtual {v0}, Lio/opentelemetry/exporter/otlp/trace/OtlpGrpcSpanExporterBuilder;->build()Lio/opentelemetry/exporter/otlp/trace/OtlpGrpcSpanExporter;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    const-string v0, "build(...)"

    .line 62
    .line 63
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    return-object p0

    .line 67
    :cond_0
    invoke-static {}, Lio/opentelemetry/exporter/logging/LoggingSpanExporter;->create()Lio/opentelemetry/exporter/logging/LoggingSpanExporter;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    const-string v0, "create(...)"

    .line 72
    .line 73
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    return-object p0
.end method
