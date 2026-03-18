.class public final Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/logs/export/LogRecordExporter;


# annotations
.annotation build Ljavax/annotation/concurrent/ThreadSafe;
.end annotation


# instance fields
.field private final builder:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder<",
            "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
            ">;"
        }
    .end annotation
.end field

.field private final delegate:Lio/opentelemetry/exporter/internal/http/HttpExporter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/exporter/internal/http/HttpExporter<",
            "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
            ">;"
        }
    .end annotation
.end field

.field private final marshaler:Lio/opentelemetry/exporter/internal/otlp/logs/LogReusableDataMarshaler;


# direct methods
.method public constructor <init>(Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;Lio/opentelemetry/exporter/internal/http/HttpExporter;Lio/opentelemetry/sdk/common/export/MemoryMode;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder<",
            "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
            ">;",
            "Lio/opentelemetry/exporter/internal/http/HttpExporter<",
            "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
            ">;",
            "Lio/opentelemetry/sdk/common/export/MemoryMode;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporter;->builder:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporter;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporter;

    .line 7
    .line 8
    new-instance p1, Lio/opentelemetry/exporter/internal/otlp/logs/LogReusableDataMarshaler;

    .line 9
    .line 10
    invoke-static {p2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    new-instance v0, Lio/opentelemetry/exporter/otlp/http/logs/a;

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    invoke-direct {v0, p2, v1}, Lio/opentelemetry/exporter/otlp/http/logs/a;-><init>(Ljava/lang/Object;I)V

    .line 17
    .line 18
    .line 19
    invoke-direct {p1, p3, v0}, Lio/opentelemetry/exporter/internal/otlp/logs/LogReusableDataMarshaler;-><init>(Lio/opentelemetry/sdk/common/export/MemoryMode;Ljava/util/function/BiFunction;)V

    .line 20
    .line 21
    .line 22
    iput-object p1, p0, Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporter;->marshaler:Lio/opentelemetry/exporter/internal/otlp/logs/LogReusableDataMarshaler;

    .line 23
    .line 24
    return-void
.end method

.method public static builder()Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporterBuilder;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporterBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporterBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static getDefault()Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporter;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporter;->builder()Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporterBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporterBuilder;->build()Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporter;

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
            "Lio/opentelemetry/sdk/logs/data/LogRecordData;",
            ">;)",
            "Lio/opentelemetry/sdk/common/CompletableResultCode;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporter;->marshaler:Lio/opentelemetry/exporter/internal/otlp/logs/LogReusableDataMarshaler;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lio/opentelemetry/exporter/internal/otlp/logs/LogReusableDataMarshaler;->export(Ljava/util/Collection;)Lio/opentelemetry/sdk/common/CompletableResultCode;

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

.method public shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporter;->delegate:Lio/opentelemetry/exporter/internal/http/HttpExporter;

    .line 2
    .line 3
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/http/HttpExporter;->shutdown()Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public toBuilder()Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporterBuilder;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporterBuilder;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporter;->builder:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 4
    .line 5
    invoke-virtual {v1}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->copy()Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    iget-object p0, p0, Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporter;->marshaler:Lio/opentelemetry/exporter/internal/otlp/logs/LogReusableDataMarshaler;

    .line 10
    .line 11
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/otlp/logs/LogReusableDataMarshaler;->getMemoryMode()Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-direct {v0, v1, p0}, Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporterBuilder;-><init>(Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;Lio/opentelemetry/sdk/common/export/MemoryMode;)V

    .line 16
    .line 17
    .line 18
    return-object v0
.end method

.method public toString()Ljava/lang/String;
    .locals 4

    .line 1
    new-instance v0, Ljava/util/StringJoiner;

    .line 2
    .line 3
    const-string v1, "OtlpHttpLogRecordExporter{"

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
    iget-object v1, p0, Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporter;->builder:Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    invoke-virtual {v1, v2}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->toString(Z)Ljava/lang/String;

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
    const-string v2, "memoryMode="

    .line 25
    .line 26
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    iget-object p0, p0, Lio/opentelemetry/exporter/otlp/http/logs/OtlpHttpLogRecordExporter;->marshaler:Lio/opentelemetry/exporter/internal/otlp/logs/LogReusableDataMarshaler;

    .line 30
    .line 31
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/otlp/logs/LogReusableDataMarshaler;->getMemoryMode()Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    invoke-virtual {v0, p0}, Ljava/util/StringJoiner;->add(Ljava/lang/CharSequence;)Ljava/util/StringJoiner;

    .line 43
    .line 44
    .line 45
    invoke-virtual {v0}, Ljava/util/StringJoiner;->toString()Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    return-object p0
.end method
