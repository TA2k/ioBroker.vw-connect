.class public final Lz81/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lz81/c;


# virtual methods
.method public final a(Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;)Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;
    .locals 1

    .line 1
    const-string p0, "api-key"

    .line 2
    .line 3
    const-string v0, "eu01xxa3f22b0360f8178638f16b958a0ec0NRAL"

    .line 4
    .line 5
    invoke-virtual {p1, p0, v0}, Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;->addHeader(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/exporter/otlp/logs/OtlpGrpcLogRecordExporterBuilder;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const-string p1, "addHeader(...)"

    .line 10
    .line 11
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    return-object p0
.end method

.method public final b(Lio/opentelemetry/exporter/otlp/trace/OtlpGrpcSpanExporterBuilder;)Lio/opentelemetry/exporter/otlp/trace/OtlpGrpcSpanExporterBuilder;
    .locals 1

    .line 1
    const-string p0, "api-key"

    .line 2
    .line 3
    const-string v0, "eu01xxa3f22b0360f8178638f16b958a0ec0NRAL"

    .line 4
    .line 5
    invoke-virtual {p1, p0, v0}, Lio/opentelemetry/exporter/otlp/trace/OtlpGrpcSpanExporterBuilder;->addHeader(Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/exporter/otlp/trace/OtlpGrpcSpanExporterBuilder;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const-string p1, "addHeader(...)"

    .line 10
    .line 11
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    return-object p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    instance-of p0, p1, Lz81/a;

    .line 5
    .line 6
    if-nez p0, :cond_1

    .line 7
    .line 8
    const/4 p0, 0x0

    .line 9
    return p0

    .line 10
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 11
    return p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    const p0, 0x5d944bc4

    .line 2
    .line 3
    .line 4
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "ApiKey(apiKey=eu01xxa3f22b0360f8178638f16b958a0ec0NRAL)"

    .line 2
    .line 3
    return-object p0
.end method
