.class public abstract Lio/opentelemetry/exporter/internal/marshal/Marshaler;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public abstract getBinarySerializedSize()I
.end method

.method public final writeBinaryTo(Ljava/io/OutputStream;)V
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;

    .line 2
    .line 3
    invoke-direct {v0, p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;-><init>(Ljava/io/OutputStream;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    invoke-virtual {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/Marshaler;->writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 7
    .line 8
    .line 9
    invoke-virtual {v0}, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->close()V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :catchall_0
    move-exception p0

    .line 14
    :try_start_1
    invoke-virtual {v0}, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->close()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 15
    .line 16
    .line 17
    goto :goto_0

    .line 18
    :catchall_1
    move-exception p1

    .line 19
    invoke-virtual {p0, p1}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 20
    .line 21
    .line 22
    :goto_0
    throw p0
.end method

.method public final writeJsonTo(Ljava/io/OutputStream;)V
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;

    .line 2
    .line 3
    invoke-direct {v0, p1}, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;-><init>(Ljava/io/OutputStream;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    invoke-virtual {v0, p0}, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->writeMessageValue(Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 7
    .line 8
    .line 9
    invoke-virtual {v0}, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->close()V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :catchall_0
    move-exception p0

    .line 14
    :try_start_1
    invoke-virtual {v0}, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->close()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 15
    .line 16
    .line 17
    goto :goto_0

    .line 18
    :catchall_1
    move-exception p1

    .line 19
    invoke-virtual {p0, p1}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 20
    .line 21
    .line 22
    :goto_0
    throw p0
.end method

.method public final writeJsonToGenerator(Lcom/fasterxml/jackson/core/JsonGenerator;)V
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;

    .line 2
    .line 3
    invoke-direct {v0, p1}, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;-><init>(Lcom/fasterxml/jackson/core/JsonGenerator;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    invoke-virtual {v0, p0}, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->writeMessageValue(Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 7
    .line 8
    .line 9
    invoke-virtual {v0}, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->close()V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :catchall_0
    move-exception p0

    .line 14
    :try_start_1
    invoke-virtual {v0}, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->close()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 15
    .line 16
    .line 17
    goto :goto_0

    .line 18
    :catchall_1
    move-exception p1

    .line 19
    invoke-virtual {p0, p1}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 20
    .line 21
    .line 22
    :goto_0
    throw p0
.end method

.method public final writeJsonWithNewline(Lcom/fasterxml/jackson/core/JsonGenerator;)V
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;

    .line 2
    .line 3
    invoke-direct {v0, p1}, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;-><init>(Lcom/fasterxml/jackson/core/JsonGenerator;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    invoke-virtual {v0, p0}, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->writeMessageValue(Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    .line 7
    .line 8
    .line 9
    const/16 p0, 0xa

    .line 10
    .line 11
    invoke-virtual {p1, p0}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeRaw(C)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0}, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->close()V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :catchall_0
    move-exception p0

    .line 19
    :try_start_1
    invoke-virtual {v0}, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->close()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 20
    .line 21
    .line 22
    goto :goto_0

    .line 23
    :catchall_1
    move-exception p1

    .line 24
    invoke-virtual {p0, p1}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    throw p0
.end method

.method public abstract writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;)V
.end method
