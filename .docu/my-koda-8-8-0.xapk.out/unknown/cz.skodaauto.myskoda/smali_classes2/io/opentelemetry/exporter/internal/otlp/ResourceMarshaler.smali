.class public final Lio/opentelemetry/exporter/internal/otlp/ResourceMarshaler;
.super Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/exporter/internal/otlp/ResourceMarshaler$RealResourceMarshaler;
    }
.end annotation


# static fields
.field private static final RESOURCE_MARSHALER_CACHE:Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap<",
            "Lio/opentelemetry/sdk/resources/Resource;",
            "Lio/opentelemetry/exporter/internal/otlp/ResourceMarshaler;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private final serializedBinary:[B

.field private final serializedJson:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$WithInlinedExpunction;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$WithInlinedExpunction;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/exporter/internal/otlp/ResourceMarshaler;->RESOURCE_MARSHALER_CACHE:Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;

    .line 7
    .line 8
    return-void
.end method

.method private constructor <init>([BLjava/lang/String;)V
    .locals 1

    .line 1
    array-length v0, p1

    .line 2
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;-><init>(I)V

    .line 3
    .line 4
    .line 5
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/otlp/ResourceMarshaler;->serializedBinary:[B

    .line 6
    .line 7
    iput-object p2, p0, Lio/opentelemetry/exporter/internal/otlp/ResourceMarshaler;->serializedJson:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public static create(Lio/opentelemetry/sdk/resources/Resource;)Lio/opentelemetry/exporter/internal/otlp/ResourceMarshaler;
    .locals 4

    .line 1
    sget-object v0, Lio/opentelemetry/exporter/internal/otlp/ResourceMarshaler;->RESOURCE_MARSHALER_CACHE:Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Lio/opentelemetry/exporter/internal/otlp/ResourceMarshaler;

    .line 8
    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    new-instance v1, Lio/opentelemetry/exporter/internal/otlp/ResourceMarshaler$RealResourceMarshaler;

    .line 12
    .line 13
    invoke-virtual {p0}, Lio/opentelemetry/sdk/resources/Resource;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    invoke-static {v2}, Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;->createForAttributes(Lio/opentelemetry/api/common/Attributes;)[Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    const/4 v3, 0x0

    .line 22
    invoke-direct {v1, v2, v3}, Lio/opentelemetry/exporter/internal/otlp/ResourceMarshaler$RealResourceMarshaler;-><init>([Lio/opentelemetry/exporter/internal/otlp/KeyValueMarshaler;Lio/opentelemetry/exporter/internal/otlp/ResourceMarshaler$1;)V

    .line 23
    .line 24
    .line 25
    new-instance v2, Ljava/io/ByteArrayOutputStream;

    .line 26
    .line 27
    invoke-virtual {v1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerWithSize;->getBinarySerializedSize()I

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    invoke-direct {v2, v3}, Ljava/io/ByteArrayOutputStream;-><init>(I)V

    .line 32
    .line 33
    .line 34
    :try_start_0
    invoke-virtual {v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Marshaler;->writeBinaryTo(Ljava/io/OutputStream;)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 35
    .line 36
    .line 37
    invoke-static {v1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->preserializeJsonFields(Lio/opentelemetry/exporter/internal/marshal/Marshaler;)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    new-instance v3, Lio/opentelemetry/exporter/internal/otlp/ResourceMarshaler;

    .line 42
    .line 43
    invoke-virtual {v2}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    invoke-direct {v3, v2, v1}, Lio/opentelemetry/exporter/internal/otlp/ResourceMarshaler;-><init>([BLjava/lang/String;)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {v0, p0, v3}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    return-object v3

    .line 54
    :catch_0
    move-exception p0

    .line 55
    new-instance v0, Ljava/io/UncheckedIOException;

    .line 56
    .line 57
    const-string v1, "Serialization error, this is likely a bug in OpenTelemetry."

    .line 58
    .line 59
    invoke-direct {v0, v1, p0}, Ljava/io/UncheckedIOException;-><init>(Ljava/lang/String;Ljava/io/IOException;)V

    .line 60
    .line 61
    .line 62
    throw v0

    .line 63
    :cond_0
    return-object v1
.end method


# virtual methods
.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/otlp/ResourceMarshaler;->serializedBinary:[B

    .line 2
    .line 3
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/otlp/ResourceMarshaler;->serializedJson:Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {p1, v0, p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->writeSerializedMessage([BLjava/lang/String;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
