.class public final Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final EMPTY_BYTES:[B

.field private static final JSON_AVAILABLE:Z

.field private static final SPAN_ID_VALUE_SIZE:I

.field private static final TRACE_ID_VALUE_SIZE:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    invoke-static {}, Lio/opentelemetry/api/trace/TraceId;->getLength()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    div-int/lit8 v0, v0, 0x2

    .line 6
    .line 7
    invoke-static {v0}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeLengthDelimitedFieldSize(I)I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    sput v0, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->TRACE_ID_VALUE_SIZE:I

    .line 12
    .line 13
    invoke-static {}, Lio/opentelemetry/api/trace/SpanId;->getLength()I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    div-int/lit8 v0, v0, 0x2

    .line 18
    .line 19
    invoke-static {v0}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeLengthDelimitedFieldSize(I)I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    sput v0, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->SPAN_ID_VALUE_SIZE:I

    .line 24
    .line 25
    const/4 v0, 0x0

    .line 26
    :try_start_0
    const-string v1, "com.fasterxml.jackson.core.JsonFactory"

    .line 27
    .line 28
    invoke-static {v1}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
    :try_end_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 29
    .line 30
    .line 31
    const/4 v1, 0x1

    .line 32
    goto :goto_0

    .line 33
    :catch_0
    move v1, v0

    .line 34
    :goto_0
    sput-boolean v1, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->JSON_AVAILABLE:Z

    .line 35
    .line 36
    new-array v0, v0, [B

    .line 37
    .line 38
    sput-object v0, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->EMPTY_BYTES:[B

    .line 39
    .line 40
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic a(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Ljava/util/List;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->lambda$groupByResourceAndScope$1(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic b(Lio/opentelemetry/sdk/resources/Resource;)Ljava/util/Map;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->lambda$groupByResourceAndScope$0(Lio/opentelemetry/sdk/resources/Resource;)Ljava/util/Map;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static groupByResourceAndScope(Ljava/util/Collection;Ljava/util/function/Function;Ljava/util/function/Function;Ljava/util/function/Function;)Ljava/util/Map;
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            "U:",
            "Ljava/lang/Object;",
            ">(",
            "Ljava/util/Collection<",
            "TT;>;",
            "Ljava/util/function/Function<",
            "TT;",
            "Lio/opentelemetry/sdk/resources/Resource;",
            ">;",
            "Ljava/util/function/Function<",
            "TT;",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            ">;",
            "Ljava/util/function/Function<",
            "TT;TU;>;)",
            "Ljava/util/Map<",
            "Lio/opentelemetry/sdk/resources/Resource;",
            "Ljava/util/Map<",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            "Ljava/util/List<",
            "TU;>;>;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Ljava/util/IdentityHashMap;

    .line 2
    .line 3
    const/16 v1, 0x8

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/util/IdentityHashMap;-><init>(I)V

    .line 6
    .line 7
    .line 8
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    invoke-interface {p1, v1}, Ljava/util/function/Function;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    check-cast v2, Lio/opentelemetry/sdk/resources/Resource;

    .line 27
    .line 28
    new-instance v3, Lio/opentelemetry/exporter/internal/marshal/c;

    .line 29
    .line 30
    const/4 v4, 0x2

    .line 31
    invoke-direct {v3, v4}, Lio/opentelemetry/exporter/internal/marshal/c;-><init>(I)V

    .line 32
    .line 33
    .line 34
    invoke-interface {v0, v2, v3}, Ljava/util/Map;->computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    check-cast v2, Ljava/util/Map;

    .line 39
    .line 40
    invoke-interface {p2, v1}, Ljava/util/function/Function;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v3

    .line 44
    check-cast v3, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 45
    .line 46
    new-instance v4, Lio/opentelemetry/exporter/internal/marshal/c;

    .line 47
    .line 48
    const/4 v5, 0x3

    .line 49
    invoke-direct {v4, v5}, Lio/opentelemetry/exporter/internal/marshal/c;-><init>(I)V

    .line 50
    .line 51
    .line 52
    invoke-interface {v2, v3, v4}, Ljava/util/Map;->computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v2

    .line 56
    check-cast v2, Ljava/util/List;

    .line 57
    .line 58
    invoke-interface {p3, v1}, Ljava/util/function/Function;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    invoke-interface {v2, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_0
    return-object v0
.end method

.method private static synthetic lambda$groupByResourceAndScope$0(Lio/opentelemetry/sdk/resources/Resource;)Ljava/util/Map;
    .locals 1

    .line 1
    new-instance p0, Ljava/util/IdentityHashMap;

    .line 2
    .line 3
    const/16 v0, 0x8

    .line 4
    .line 5
    invoke-direct {p0, v0}, Ljava/util/IdentityHashMap;-><init>(I)V

    .line 6
    .line 7
    .line 8
    return-object p0
.end method

.method private static synthetic lambda$groupByResourceAndScope$1(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Ljava/util/List;
    .locals 0

    .line 1
    new-instance p0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public static preserializeJsonFields(Lio/opentelemetry/exporter/internal/marshal/Marshaler;)Ljava/lang/String;
    .locals 4

    .line 1
    sget-boolean v0, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->JSON_AVAILABLE:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const-string p0, ""

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    new-instance v0, Ljava/io/ByteArrayOutputStream;

    .line 9
    .line 10
    invoke-direct {v0}, Ljava/io/ByteArrayOutputStream;-><init>()V

    .line 11
    .line 12
    .line 13
    :try_start_0
    invoke-virtual {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/Marshaler;->writeJsonTo(Ljava/io/OutputStream;)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    new-instance v0, Ljava/lang/String;

    .line 21
    .line 22
    array-length v1, p0

    .line 23
    add-int/lit8 v1, v1, -0x2

    .line 24
    .line 25
    sget-object v2, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 26
    .line 27
    const/4 v3, 0x1

    .line 28
    invoke-direct {v0, p0, v3, v1, v2}, Ljava/lang/String;-><init>([BIILjava/nio/charset/Charset;)V

    .line 29
    .line 30
    .line 31
    return-object v0

    .line 32
    :catch_0
    move-exception p0

    .line 33
    new-instance v0, Ljava/io/UncheckedIOException;

    .line 34
    .line 35
    const-string v1, "Serialization error, this is likely a bug in OpenTelemetry."

    .line 36
    .line 37
    invoke-direct {v0, v1, p0}, Ljava/io/UncheckedIOException;-><init>(Ljava/lang/String;Ljava/io/IOException;)V

    .line 38
    .line 39
    .line 40
    throw v0
.end method

.method public static sizeBool(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Z)I
    .locals 0

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return p0

    .line 5
    :cond_0
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeBoolSizeNoTag(Z)I

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    add-int/2addr p1, p0

    .line 14
    return p1
.end method

.method public static sizeByteAsFixed32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;B)I
    .locals 0

    .line 1
    and-int/lit16 p1, p1, 0xff

    .line 2
    .line 3
    invoke-static {p0, p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public static sizeByteBuffer(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/nio/ByteBuffer;)I
    .locals 1

    .line 1
    invoke-virtual {p1}, Ljava/nio/Buffer;->capacity()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return p0

    .line 9
    :cond_0
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeByteBufferSizeNoTag(Ljava/nio/ByteBuffer;)I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    add-int/2addr p1, p0

    .line 18
    return p1
.end method

.method public static sizeBytes(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)I
    .locals 1

    .line 1
    array-length v0, p1

    .line 2
    if-nez v0, :cond_0

    .line 3
    .line 4
    const/4 p0, 0x0

    .line 5
    return p0

    .line 6
    :cond_0
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeByteArraySizeNoTag([B)I

    .line 11
    .line 12
    .line 13
    move-result p1

    .line 14
    add-int/2addr p1, p0

    .line 15
    return p1
.end method

.method public static sizeDouble(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)I
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmpl-double v0, p1, v0

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return p0

    .line 9
    :cond_0
    invoke-static {p0, p1, p2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeDoubleOptional(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public static sizeDoubleOptional(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;D)I
    .locals 0

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    invoke-static {p1, p2}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeDoubleSizeNoTag(D)I

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    add-int/2addr p1, p0

    .line 10
    return p1
.end method

.method public static sizeEnum(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;)I
    .locals 0

    .line 1
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoEnumInfo;->getEnumNumber()I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    if-nez p1, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return p0

    .line 9
    :cond_0
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeEnumSizeNoTag(I)I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    add-int/2addr p1, p0

    .line 18
    return p1
.end method

.method public static sizeFixed32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I
    .locals 4

    .line 1
    int-to-long v0, p1

    .line 2
    const-wide/16 v2, 0x0

    .line 3
    .line 4
    cmp-long v0, v0, v2

    .line 5
    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    const/4 p0, 0x0

    .line 9
    return p0

    .line 10
    :cond_0
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeFixed32SizeNoTag(I)I

    .line 15
    .line 16
    .line 17
    move-result p1

    .line 18
    add-int/2addr p1, p0

    .line 19
    return p1
.end method

.method public static sizeFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long v0, p1, v0

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return p0

    .line 9
    :cond_0
    invoke-static {p0, p1, p2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeFixed64Optional(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public static sizeFixed64Optional(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I
    .locals 0

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    invoke-static {p1, p2}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeFixed64SizeNoTag(J)I

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    add-int/2addr p1, p0

    .line 10
    return p1
.end method

.method public static sizeInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I
    .locals 0

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return p0

    .line 5
    :cond_0
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeInt32SizeNoTag(I)I

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    add-int/2addr p1, p0

    .line 14
    return p1
.end method

.method public static sizeInt32Optional(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I
    .locals 0

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    move-result p0

    invoke-static {p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeInt32SizeNoTag(I)I

    move-result p1

    add-int/2addr p1, p0

    return p1
.end method

.method public static sizeInt32Optional(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/Integer;)I
    .locals 0
    .param p1    # Ljava/lang/Integer;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    if-nez p1, :cond_0

    const/4 p0, 0x0

    return p0

    .line 2
    :cond_0
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    move-result p1

    invoke-static {p0, p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeInt32Optional(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I

    move-result p0

    return p0
.end method

.method public static sizeInt64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long v0, p1, v0

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return p0

    .line 9
    :cond_0
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    invoke-static {p1, p2}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeInt64SizeNoTag(J)I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    add-int/2addr p1, p0

    .line 18
    return p1
.end method

.method public static sizeMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I
    .locals 1

    .line 1
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/Marshaler;->getBinarySerializedSize()I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeUInt32SizeNoTag(I)I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    add-int/2addr v0, p0

    .line 14
    add-int/2addr v0, p1

    .line 15
    return v0
.end method

.method public static sizeRepeatedDouble(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/List;)I
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;",
            "Ljava/util/List<",
            "Ljava/lang/Double;",
            ">;)I"
        }
    .end annotation

    .line 1
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    invoke-static {p0, p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeRepeatedFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method private static sizeRepeatedFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I
    .locals 0

    if-nez p1, :cond_0

    const/4 p0, 0x0

    return p0

    :cond_0
    mul-int/lit8 p1, p1, 0x8

    .line 2
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    move-result p0

    .line 3
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeLengthDelimitedFieldSize(I)I

    move-result p1

    add-int/2addr p1, p0

    return p1
.end method

.method public static sizeRepeatedFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/List;)I
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;",
            "Ljava/util/List<",
            "Ljava/lang/Long;",
            ">;)I"
        }
    .end annotation

    .line 1
    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result p1

    invoke-static {p0, p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeRepeatedFixed64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I

    move-result p0

    return p0
.end method

.method public static sizeRepeatedInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/List;)I
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;",
            "Ljava/util/List<",
            "Ljava/lang/Integer;",
            ">;)I"
        }
    .end annotation

    .line 1
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    return v1

    .line 9
    :cond_0
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_1

    .line 18
    .line 19
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    check-cast v0, Ljava/lang/Integer;

    .line 24
    .line 25
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    invoke-static {v0}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeInt32SizeNoTag(I)I

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    add-int/2addr v1, v0

    .line 34
    goto :goto_0

    .line 35
    :cond_1
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    .line 36
    .line 37
    .line 38
    move-result p0

    .line 39
    invoke-static {v1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeUInt32SizeNoTag(I)I

    .line 40
    .line 41
    .line 42
    move-result p1

    .line 43
    add-int/2addr p1, p0

    .line 44
    add-int/2addr p1, v1

    .line 45
    return p1
.end method

.method public static sizeRepeatedInt64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/List;)I
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;",
            "Ljava/util/List<",
            "Ljava/lang/Long;",
            ">;)I"
        }
    .end annotation

    .line 5
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    return v1

    .line 6
    :cond_0
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Long;

    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    move-result-wide v2

    .line 7
    invoke-static {v2, v3}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeInt64SizeNoTag(J)I

    move-result v0

    add-int/2addr v1, v0

    goto :goto_0

    .line 8
    :cond_1
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    move-result p0

    invoke-static {v1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeUInt32SizeNoTag(I)I

    move-result p1

    add-int/2addr p1, p0

    add-int/2addr p1, v1

    return p1
.end method

.method public static sizeRepeatedInt64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[J)I
    .locals 5

    .line 1
    array-length v0, p1

    const/4 v1, 0x0

    if-nez v0, :cond_0

    return v1

    .line 2
    :cond_0
    array-length v0, p1

    move v2, v1

    :goto_0
    if-ge v1, v0, :cond_1

    aget-wide v3, p1, v1

    .line 3
    invoke-static {v3, v4}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeInt64SizeNoTag(J)I

    move-result v3

    add-int/2addr v2, v3

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    .line 4
    :cond_1
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    move-result p0

    invoke-static {v2}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeUInt32SizeNoTag(I)I

    move-result p1

    add-int/2addr p1, p0

    add-int/2addr p1, v2

    return p1
.end method

.method public static sizeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/List;)I
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;",
            "Ljava/util/List<",
            "+",
            "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
            ">;)I"
        }
    .end annotation

    .line 5
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    move-result p0

    .line 6
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p1

    const/4 v0, 0x0

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lio/opentelemetry/exporter/internal/marshal/Marshaler;

    .line 7
    invoke-virtual {v1}, Lio/opentelemetry/exporter/internal/marshal/Marshaler;->getBinarySerializedSize()I

    move-result v1

    .line 8
    invoke-static {v1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeUInt32SizeNoTag(I)I

    move-result v2

    add-int/2addr v2, p0

    add-int/2addr v2, v1

    add-int/2addr v0, v2

    goto :goto_0

    :cond_0
    return v0
.end method

.method public static sizeRepeatedMessage(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[Lio/opentelemetry/exporter/internal/marshal/Marshaler;)I
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
            ">(",
            "Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;",
            "[TT;)I"
        }
    .end annotation

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    move-result p0

    .line 2
    array-length v0, p1

    const/4 v1, 0x0

    move v2, v1

    :goto_0
    if-ge v1, v0, :cond_0

    aget-object v3, p1, v1

    .line 3
    invoke-virtual {v3}, Lio/opentelemetry/exporter/internal/marshal/Marshaler;->getBinarySerializedSize()I

    move-result v3

    .line 4
    invoke-static {v3}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeUInt32SizeNoTag(I)I

    move-result v4

    add-int/2addr v4, p0

    add-int/2addr v4, v3

    add-int/2addr v2, v4

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_0
    return v2
.end method

.method public static sizeRepeatedString(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[[B)I
    .locals 4

    .line 1
    array-length v0, p1

    .line 2
    const/4 v1, 0x0

    .line 3
    move v2, v1

    .line 4
    :goto_0
    if-ge v1, v0, :cond_0

    .line 5
    .line 6
    aget-object v3, p1, v1

    .line 7
    .line 8
    invoke-static {p0, v3}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->sizeBytes(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[B)I

    .line 9
    .line 10
    .line 11
    move-result v3

    .line 12
    add-int/2addr v2, v3

    .line 13
    add-int/lit8 v1, v1, 0x1

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    return v2
.end method

.method public static sizeRepeatedUInt64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;)I
    .locals 4

    .line 9
    invoke-virtual {p1}, Ljava/util/AbstractCollection;->isEmpty()Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    return v1

    :cond_0
    move v0, v1

    .line 10
    :goto_0
    invoke-virtual {p1}, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->size()I

    move-result v2

    if-ge v1, v2, :cond_1

    .line 11
    invoke-virtual {p1, v1}, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->getLong(I)J

    move-result-wide v2

    .line 12
    invoke-static {v2, v3}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeUInt64SizeNoTag(J)I

    move-result v2

    add-int/2addr v0, v2

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    .line 13
    :cond_1
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    move-result p0

    invoke-static {v0}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeUInt32SizeNoTag(I)I

    move-result p1

    add-int/2addr p1, p0

    add-int/2addr p1, v0

    return p1
.end method

.method public static sizeRepeatedUInt64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/List;)I
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;",
            "Ljava/util/List<",
            "Ljava/lang/Long;",
            ">;)I"
        }
    .end annotation

    .line 5
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    return v1

    .line 6
    :cond_0
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Long;

    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    move-result-wide v2

    .line 7
    invoke-static {v2, v3}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeUInt64SizeNoTag(J)I

    move-result v0

    add-int/2addr v1, v0

    goto :goto_0

    .line 8
    :cond_1
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    move-result p0

    invoke-static {v1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeUInt32SizeNoTag(I)I

    move-result p1

    add-int/2addr p1, p0

    add-int/2addr p1, v1

    return p1
.end method

.method public static sizeRepeatedUInt64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;[J)I
    .locals 5

    .line 1
    array-length v0, p1

    const/4 v1, 0x0

    if-nez v0, :cond_0

    return v1

    .line 2
    :cond_0
    array-length v0, p1

    move v2, v1

    :goto_0
    if-ge v1, v0, :cond_1

    aget-wide v3, p1, v1

    .line 3
    invoke-static {v3, v4}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeUInt64SizeNoTag(J)I

    move-result v3

    add-int/2addr v2, v3

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    .line 4
    :cond_1
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    move-result p0

    invoke-static {v2}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeUInt32SizeNoTag(I)I

    move-result p1

    add-int/2addr p1, p0

    add-int/2addr p1, v2

    return p1
.end method

.method public static sizeSInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I
    .locals 0

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return p0

    .line 5
    :cond_0
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeSInt32SizeNoTag(I)I

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    add-int/2addr p1, p0

    .line 14
    return p1
.end method

.method public static sizeSpanId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)I
    .locals 0
    .param p1    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return p0

    .line 5
    :cond_0
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    sget p1, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->SPAN_ID_VALUE_SIZE:I

    .line 10
    .line 11
    add-int/2addr p0, p1

    .line 12
    return p0
.end method

.method public static sizeTraceId(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;)I
    .locals 0
    .param p1    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return p0

    .line 5
    :cond_0
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    sget p1, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->TRACE_ID_VALUE_SIZE:I

    .line 10
    .line 11
    add-int/2addr p0, p1

    .line 12
    return p0
.end method

.method public static sizeUInt32(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I
    .locals 0

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return p0

    .line 5
    :cond_0
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeUInt32SizeNoTag(I)I

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    add-int/2addr p1, p0

    .line 14
    return p1
.end method

.method public static sizeUInt64(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;J)I
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long v0, p1, v0

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return p0

    .line 9
    :cond_0
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    invoke-static {p1, p2}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeUInt64SizeNoTag(J)I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    add-int/2addr p1, p0

    .line 18
    return p1
.end method

.method public static toBytes(Ljava/lang/String;)[B
    .locals 1
    .param p0    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    if-eqz p0, :cond_1

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    sget-object v0, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 11
    .line 12
    invoke-virtual {p0, v0}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0

    .line 17
    :cond_1
    :goto_0
    sget-object p0, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->EMPTY_BYTES:[B

    .line 18
    .line 19
    return-object p0
.end method
