.class final Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;
.super Lio/opentelemetry/exporter/internal/marshal/Serializer;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final JSON_FACTORY:Lcom/fasterxml/jackson/core/JsonFactory;


# instance fields
.field private final generator:Lcom/fasterxml/jackson/core/JsonGenerator;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/fasterxml/jackson/core/JsonFactory;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/fasterxml/jackson/core/JsonFactory;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->JSON_FACTORY:Lcom/fasterxml/jackson/core/JsonFactory;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Lcom/fasterxml/jackson/core/JsonGenerator;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;-><init>()V

    .line 3
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    return-void
.end method

.method public constructor <init>(Ljava/io/OutputStream;)V
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->JSON_FACTORY:Lcom/fasterxml/jackson/core/JsonFactory;

    invoke-virtual {v0, p1}, Lcom/fasterxml/jackson/core/JsonFactory;->createGenerator(Ljava/io/OutputStream;)Lcom/fasterxml/jackson/core/JsonGenerator;

    move-result-object p1

    invoke-direct {p0, p1}, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;-><init>(Lcom/fasterxml/jackson/core/JsonGenerator;)V

    return-void
.end method


# virtual methods
.method public close()V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/fasterxml/jackson/core/JsonGenerator;->close()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public serializeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/List;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;",
            "Ljava/util/List<",
            "+",
            "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
            ">;)V"
        }
    .end annotation

    .line 5
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getJsonName()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v0, p1}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeArrayFieldStart(Ljava/lang/String;)V

    .line 6
    invoke-interface {p2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p2

    if-eqz p2, :cond_0

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Lio/opentelemetry/exporter/internal/marshal/Marshaler;

    .line 7
    invoke-virtual {p0, p2}, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->writeMessageValue(Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    goto :goto_0

    .line 8
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    invoke-virtual {p0}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeEndArray()V

    return-void
.end method

.method public serializeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getJsonName()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v0, p1}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeArrayFieldStart(Ljava/lang/String;)V

    .line 2
    array-length p1, p2

    const/4 v0, 0x0

    :goto_0
    if-ge v0, p1, :cond_0

    aget-object v1, p2, v0

    .line 3
    invoke-virtual {p0, v1}, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->writeMessageValue(Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    .line 4
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    invoke-virtual {p0}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeEndArray()V

    return-void
.end method

.method public serializeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/List;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;",
            "Ljava/util/List<",
            "+TT;>;",
            "Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler<",
            "TT;>;",
            "Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;",
            ")V"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getJsonName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {v0, p1}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeArrayFieldStart(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const/4 p1, 0x0

    .line 11
    :goto_0
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-ge p1, v0, :cond_0

    .line 16
    .line 17
    invoke-interface {p2, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 22
    .line 23
    invoke-virtual {v1}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeStartObject()V

    .line 24
    .line 25
    .line 26
    invoke-interface {p3, p0, v0, p4}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;->writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 27
    .line 28
    .line 29
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 30
    .line 31
    invoke-virtual {v0}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeEndObject()V

    .line 32
    .line 33
    .line 34
    add-int/lit8 p1, p1, 0x1

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 38
    .line 39
    invoke-virtual {p0}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeEndArray()V

    .line 40
    .line 41
    .line 42
    return-void
.end method

.method public writeBool(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Z)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getJsonName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1, p2}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeBooleanField(Ljava/lang/String;Z)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public writeByteBuffer(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/nio/ByteBuffer;)V
    .locals 1

    .line 1
    invoke-virtual {p2}, Ljava/nio/Buffer;->capacity()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    new-array v0, v0, [B

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/nio/ByteBuffer;->duplicate()Ljava/nio/ByteBuffer;

    .line 8
    .line 9
    .line 10
    move-result-object p2

    .line 11
    invoke-virtual {p2}, Ljava/nio/ByteBuffer;->clear()Ljava/nio/Buffer;

    .line 12
    .line 13
    .line 14
    move-result-object p2

    .line 15
    check-cast p2, Ljava/nio/ByteBuffer;

    .line 16
    .line 17
    invoke-virtual {p2, v0}, Ljava/nio/ByteBuffer;->get([B)Ljava/nio/ByteBuffer;

    .line 18
    .line 19
    .line 20
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 21
    .line 22
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getJsonName()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    invoke-virtual {p0, p1, v0}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeBinaryField(Ljava/lang/String;[B)V

    .line 27
    .line 28
    .line 29
    return-void
.end method

.method public writeBytes(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getJsonName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1, p2}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeBinaryField(Ljava/lang/String;[B)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public writeDouble(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getJsonName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1, p2, p3}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeNumberField(Ljava/lang/String;D)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public writeDoubleValue(D)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeNumber(D)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public writeEndMessage()V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeEndObject()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public writeEndRepeated()V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeEndArray()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public writeEndRepeatedElement()V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeEndObject()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public writeEndRepeatedPrimitive()V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeEndArray()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public writeEndRepeatedVarint()V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeEndArray()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public writeEnum(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getJsonName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p2}, Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;->getEnumNumber()I

    .line 8
    .line 9
    .line 10
    move-result p2

    .line 11
    invoke-virtual {p0, p1, p2}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeNumberField(Ljava/lang/String;I)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public writeFixed32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getJsonName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1, p2}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeNumberField(Ljava/lang/String;I)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public writeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getJsonName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-static {p2, p3}, Ljava/lang/Long;->toString(J)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p2

    .line 11
    invoke-virtual {p0, p1, p2}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeStringField(Ljava/lang/String;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public writeFixed64Value(J)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-static {p1, p2}, Ljava/lang/Long;->toString(J)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeString(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public writeInt64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getJsonName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-static {p2, p3}, Ljava/lang/Long;->toString(J)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p2

    .line 11
    invoke-virtual {p0, p1, p2}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeStringField(Ljava/lang/String;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public writeMessageValue(Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeStartObject()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1, p0}, Lio/opentelemetry/exporter/internal/marshal/Marshaler;->writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;)V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 10
    .line 11
    invoke-virtual {p0}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeEndObject()V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public writeRepeatedString(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[[B)V
    .locals 5

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getJsonName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {v0, p1}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeArrayFieldStart(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    array-length p1, p2

    .line 11
    const/4 v0, 0x0

    .line 12
    :goto_0
    if-ge v0, p1, :cond_0

    .line 13
    .line 14
    aget-object v1, p2, v0

    .line 15
    .line 16
    iget-object v2, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 17
    .line 18
    new-instance v3, Ljava/lang/String;

    .line 19
    .line 20
    sget-object v4, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 21
    .line 22
    invoke-direct {v3, v1, v4}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v2, v3}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeString(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    add-int/lit8 v0, v0, 0x1

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 32
    .line 33
    invoke-virtual {p0}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeEndArray()V

    .line 34
    .line 35
    .line 36
    return-void
.end method

.method public writeSInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getJsonName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1, p2}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeNumberField(Ljava/lang/String;I)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public writeSerializedMessage([BLjava/lang/String;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeRaw(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public writeSpanId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getJsonName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1, p2}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeStringField(Ljava/lang/String;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public writeStartMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getJsonName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeObjectFieldStart(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public writeStartRepeated(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getJsonName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeArrayFieldStart(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public writeStartRepeatedElement(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeStartObject()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public writeStartRepeatedPrimitive(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;II)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getJsonName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeArrayFieldStart(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public writeStartRepeatedVarint(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getJsonName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeArrayFieldStart(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public writeString(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;ILio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 0

    .line 3
    iget-object p3, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getJsonName()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p3, p1}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeFieldName(Ljava/lang/String;)V

    .line 4
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    invoke-virtual {p0, p2}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeString(Ljava/lang/String;)V

    return-void
.end method

.method public writeString(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getJsonName()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v0, p1}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeFieldName(Ljava/lang/String;)V

    .line 2
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    new-instance p1, Ljava/lang/String;

    sget-object v0, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    invoke-direct {p1, p2, v0}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    invoke-virtual {p0, p1}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeString(Ljava/lang/String;)V

    return-void
.end method

.method public writeTraceId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getJsonName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1, p2}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeStringField(Ljava/lang/String;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public writeUInt64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getJsonName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-static {p2, p3}, Ljava/lang/Long;->toString(J)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p2

    .line 11
    invoke-virtual {p0, p1, p2}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeStringField(Ljava/lang/String;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public writeUInt64Value(J)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-static {p1, p2}, Ljava/lang/Long;->toString(J)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeString(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public writeUint32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getJsonName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1, p2}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeNumberField(Ljava/lang/String;I)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public writeint32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/JsonSerializer;->generator:Lcom/fasterxml/jackson/core/JsonGenerator;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getJsonName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1, p2}, Lcom/fasterxml/jackson/core/JsonGenerator;->writeNumberField(Ljava/lang/String;I)V

    .line 8
    .line 9
    .line 10
    return-void
.end method
