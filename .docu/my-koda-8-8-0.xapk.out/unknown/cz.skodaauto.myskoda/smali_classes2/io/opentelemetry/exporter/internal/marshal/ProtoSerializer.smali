.class final Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;
.super Lio/opentelemetry/exporter/internal/marshal/Serializer;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/AutoCloseable;


# static fields
.field private static final THREAD_LOCAL_ID_CACHE:Ljava/lang/ThreadLocal;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/ThreadLocal<",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "[B>;>;"
        }
    .end annotation
.end field


# instance fields
.field private final idCache:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "[B>;"
        }
    .end annotation
.end field

.field private final output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/lang/ThreadLocal;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/ThreadLocal;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->THREAD_LOCAL_ID_CACHE:Ljava/lang/ThreadLocal;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Ljava/io/OutputStream;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->newInstance(Ljava/io/OutputStream;)Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 9
    .line 10
    invoke-static {}, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->getIdCache()Ljava/util/Map;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->idCache:Ljava/util/Map;

    .line 15
    .line 16
    return-void
.end method

.method public static synthetic f(Ljava/lang/String;)[B
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->lambda$writeTraceId$0(Ljava/lang/String;)[B

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic g(Ljava/lang/String;)[B
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->lambda$writeSpanId$1(Ljava/lang/String;)[B

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static getIdCache()Ljava/util/Map;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "[B>;"
        }
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->THREAD_LOCAL_ID_CACHE:Ljava/lang/ThreadLocal;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Ljava/util/Map;

    .line 8
    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    new-instance v1, Ljava/util/HashMap;

    .line 12
    .line 13
    invoke-direct {v1}, Ljava/util/HashMap;-><init>()V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, v1}, Ljava/lang/ThreadLocal;->set(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    :cond_0
    return-object v1
.end method

.method private static synthetic lambda$writeSpanId$1(Ljava/lang/String;)[B
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/api/trace/SpanId;->getLength()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-static {p0, v0}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->bytesFromBase16(Ljava/lang/CharSequence;I)[B

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method private static synthetic lambda$writeTraceId$0(Ljava/lang/String;)[B
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/api/trace/TraceId;->getLength()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-static {p0, v0}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->bytesFromBase16(Ljava/lang/CharSequence;I)[B

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method


# virtual methods
.method public close()V
    .locals 1

    .line 1
    :try_start_0
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 2
    .line 3
    invoke-virtual {v0}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->flush()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->idCache:Ljava/util/Map;

    .line 7
    .line 8
    invoke-interface {p0}, Ljava/util/Map;->clear()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :catch_0
    move-exception p0

    .line 13
    new-instance v0, Ljava/io/IOException;

    .line 14
    .line 15
    invoke-direct {v0, p0}, Ljava/io/IOException;-><init>(Ljava/lang/Throwable;)V

    .line 16
    .line 17
    .line 18
    throw v0
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

    .line 3
    invoke-interface {p2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p2

    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lio/opentelemetry/exporter/internal/marshal/Marshaler;

    .line 4
    invoke-virtual {p0, p1, v0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    goto :goto_0

    :cond_0
    return-void
.end method

.method public serializeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V
    .locals 3

    .line 1
    array-length v0, p2

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_0

    aget-object v2, p2, v1

    .line 2
    invoke-virtual {p0, p1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/Marshaler;)V

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_0
    return-void
.end method

.method public serializeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/List;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 3
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
    const/4 v0, 0x0

    .line 2
    :goto_0
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 3
    .line 4
    .line 5
    move-result v1

    .line 6
    if-ge v0, v1, :cond_0

    .line 7
    .line 8
    invoke-interface {p2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-virtual {p4}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->getSize()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    invoke-virtual {p0, p1, v2}, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->writeStartMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V

    .line 17
    .line 18
    .line 19
    invoke-interface {p3, p0, v1, p4}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;->writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->writeEndMessage()V

    .line 23
    .line 24
    .line 25
    add-int/lit8 v0, v0, 0x1

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    return-void
.end method

.method public writeBool(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Z)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTag()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeUInt32NoTag(I)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 11
    .line 12
    invoke-virtual {p0, p2}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeBoolNoTag(Z)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public writeByteBuffer(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/nio/ByteBuffer;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTag()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeUInt32NoTag(I)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 11
    .line 12
    invoke-virtual {p0, p2}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeByteBufferNoTag(Ljava/nio/ByteBuffer;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public writeBytes(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTag()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeUInt32NoTag(I)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 11
    .line 12
    invoke-virtual {p0, p2}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeByteArrayNoTag([B)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public writeDouble(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTag()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeUInt32NoTag(I)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 11
    .line 12
    invoke-virtual {p0, p2, p3}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeDoubleNoTag(D)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public writeDoubleValue(D)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeDoubleNoTag(D)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public writeEndMessage()V
    .locals 0

    .line 1
    return-void
.end method

.method public writeEndRepeated()V
    .locals 0

    .line 1
    return-void
.end method

.method public writeEndRepeatedElement()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->writeEndMessage()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public writeEndRepeatedPrimitive()V
    .locals 0

    .line 1
    return-void
.end method

.method public writeEndRepeatedVarint()V
    .locals 0

    .line 1
    return-void
.end method

.method public writeEnum(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTag()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeUInt32NoTag(I)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 11
    .line 12
    invoke-virtual {p2}, Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;->getEnumNumber()I

    .line 13
    .line 14
    .line 15
    move-result p1

    .line 16
    invoke-virtual {p0, p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeEnumNoTag(I)V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public writeFixed32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTag()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeUInt32NoTag(I)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 11
    .line 12
    invoke-virtual {p0, p2}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeFixed32NoTag(I)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public writeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTag()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeUInt32NoTag(I)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 11
    .line 12
    invoke-virtual {p0, p2, p3}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeFixed64NoTag(J)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public writeFixed64Value(J)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeFixed64NoTag(J)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public writeInt64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTag()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeUInt32NoTag(I)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 11
    .line 12
    invoke-virtual {p0, p2, p3}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeInt64NoTag(J)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public writeRepeatedString(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[[B)V
    .locals 3

    .line 1
    array-length v0, p2

    .line 2
    const/4 v1, 0x0

    .line 3
    :goto_0
    if-ge v1, v0, :cond_0

    .line 4
    .line 5
    aget-object v2, p2, v1

    .line 6
    .line 7
    invoke-virtual {p0, p1, v2}, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->writeString(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)V

    .line 8
    .line 9
    .line 10
    add-int/lit8 v1, v1, 0x1

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    return-void
.end method

.method public writeSInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTag()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeUInt32NoTag(I)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 11
    .line 12
    invoke-virtual {p0, p2}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeSInt32NoTag(I)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public writeSerializedMessage([BLjava/lang/String;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeRawBytes([B)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public writeSpanId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->idCache:Ljava/util/Map;

    new-instance v1, Lio/opentelemetry/exporter/internal/marshal/c;

    const/4 v2, 0x1

    invoke-direct {v1, v2}, Lio/opentelemetry/exporter/internal/marshal/c;-><init>(I)V

    .line 2
    invoke-interface {v0, p2, v1}, Ljava/util/Map;->computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, [B

    .line 3
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->writeBytes(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)V

    return-void
.end method

.method public writeSpanId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 1

    .line 4
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->idCache:Ljava/util/Map;

    invoke-interface {v0, p2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [B

    if-nez v0, :cond_0

    .line 5
    invoke-virtual {p3}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->getSpanIdBuffer()[B

    move-result-object v0

    .line 6
    invoke-static {}, Lio/opentelemetry/api/trace/SpanId;->getLength()I

    move-result p3

    invoke-static {p2, p3, v0}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->bytesFromBase16(Ljava/lang/CharSequence;I[B)V

    .line 7
    iget-object p3, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->idCache:Ljava/util/Map;

    invoke-interface {p3, p2, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    :cond_0
    invoke-virtual {p0, p1, v0}, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->writeBytes(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)V

    return-void
.end method

.method public writeStartMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTag()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeUInt32NoTag(I)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 11
    .line 12
    invoke-virtual {p0, p2}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeUInt32NoTag(I)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public writeStartRepeated(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;)V
    .locals 0

    .line 1
    return-void
.end method

.method public writeStartRepeatedElement(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->writeStartMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public writeStartRepeatedPrimitive(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;II)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTag()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeUInt32NoTag(I)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 11
    .line 12
    mul-int/2addr p2, p3

    .line 13
    invoke-virtual {p0, p2}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeUInt32NoTag(I)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public writeStartRepeatedVarint(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTag()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeUInt32NoTag(I)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 11
    .line 12
    invoke-virtual {p0, p2}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeUInt32NoTag(I)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public writeString(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;ILio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 1

    .line 2
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTag()I

    move-result p1

    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeUInt32NoTag(I)V

    .line 3
    iget-object p1, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    invoke-virtual {p1, p3}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeUInt32NoTag(I)V

    .line 4
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    invoke-static {p0, p2, p3, p4}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->writeUtf8(Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;Ljava/lang/String;ILio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void
.end method

.method public writeString(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)V
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->writeBytes(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)V

    return-void
.end method

.method public writeTraceId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->idCache:Ljava/util/Map;

    new-instance v1, Lio/opentelemetry/exporter/internal/marshal/c;

    const/4 v2, 0x0

    invoke-direct {v1, v2}, Lio/opentelemetry/exporter/internal/marshal/c;-><init>(I)V

    .line 2
    invoke-interface {v0, p2, v1}, Ljava/util/Map;->computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, [B

    .line 3
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->writeBytes(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)V

    return-void
.end method

.method public writeTraceId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 1

    .line 4
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->idCache:Ljava/util/Map;

    invoke-interface {v0, p2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [B

    if-nez v0, :cond_0

    .line 5
    invoke-virtual {p3}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->getTraceIdBuffer()[B

    move-result-object v0

    .line 6
    invoke-static {}, Lio/opentelemetry/api/trace/TraceId;->getLength()I

    move-result p3

    invoke-static {p2, p3, v0}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->bytesFromBase16(Ljava/lang/CharSequence;I[B)V

    .line 7
    iget-object p3, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->idCache:Ljava/util/Map;

    invoke-interface {p3, p2, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    :cond_0
    invoke-virtual {p0, p1, v0}, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->writeBytes(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)V

    return-void
.end method

.method public writeUInt64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTag()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeUInt32NoTag(I)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 11
    .line 12
    invoke-virtual {p0, p2, p3}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeUInt64NoTag(J)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public writeUInt64Value(J)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeUInt64NoTag(J)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public writeUint32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTag()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeUInt32NoTag(I)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 11
    .line 12
    invoke-virtual {p0, p2}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeUInt32NoTag(I)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public writeint32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 2
    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTag()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-virtual {v0, p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeUInt32NoTag(I)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/ProtoSerializer;->output:Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;

    .line 11
    .line 12
    invoke-virtual {p0, p2}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->writeInt32NoTag(I)V

    .line 13
    .line 14
    .line 15
    return-void
.end method
