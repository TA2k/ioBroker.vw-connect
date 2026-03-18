.class public final Lio/opentelemetry/exporter/sender/okhttp/internal/GrpcRequestBody;
.super Ld01/r0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final COMPRESSED_FLAG:B = 0x1t

.field private static final GRPC_MEDIA_TYPE:Ld01/d0;

.field private static final HEADER_LENGTH:I = 0x5

.field private static final UNCOMPRESSED_FLAG:B


# instance fields
.field private final compressor:Lio/opentelemetry/exporter/internal/compression/Compressor;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final contentLength:I

.field private final marshaler:Lio/opentelemetry/exporter/internal/marshal/Marshaler;

.field private final messageSize:I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Ld01/d0;->e:Lly0/n;

    .line 2
    .line 3
    const-string v0, "application/grpc"

    .line 4
    .line 5
    invoke-static {v0}, Ljp/ue;->e(Ljava/lang/String;)Ld01/d0;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sput-object v0, Lio/opentelemetry/exporter/sender/okhttp/internal/GrpcRequestBody;->GRPC_MEDIA_TYPE:Ld01/d0;

    .line 10
    .line 11
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/exporter/internal/marshal/Marshaler;Lio/opentelemetry/exporter/internal/compression/Compressor;)V
    .locals 0
    .param p2    # Lio/opentelemetry/exporter/internal/compression/Compressor;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/GrpcRequestBody;->marshaler:Lio/opentelemetry/exporter/internal/marshal/Marshaler;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/GrpcRequestBody;->compressor:Lio/opentelemetry/exporter/internal/compression/Compressor;

    .line 7
    .line 8
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/Marshaler;->getBinarySerializedSize()I

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    iput p1, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/GrpcRequestBody;->messageSize:I

    .line 13
    .line 14
    if-eqz p2, :cond_0

    .line 15
    .line 16
    const/4 p1, -0x1

    .line 17
    iput p1, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/GrpcRequestBody;->contentLength:I

    .line 18
    .line 19
    return-void

    .line 20
    :cond_0
    add-int/lit8 p1, p1, 0x5

    .line 21
    .line 22
    iput p1, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/GrpcRequestBody;->contentLength:I

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public contentLength()J
    .locals 2

    .line 1
    iget p0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/GrpcRequestBody;->contentLength:I

    .line 2
    .line 3
    int-to-long v0, p0

    .line 4
    return-wide v0
.end method

.method public contentType()Ld01/d0;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    sget-object p0, Lio/opentelemetry/exporter/sender/okhttp/internal/GrpcRequestBody;->GRPC_MEDIA_TYPE:Ld01/d0;

    .line 2
    .line 3
    return-object p0
.end method

.method public writeTo(Lu01/g;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/GrpcRequestBody;->compressor:Lio/opentelemetry/exporter/internal/compression/Compressor;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    invoke-interface {p1, v0}, Lu01/g;->writeByte(I)Lu01/g;

    .line 7
    .line 8
    .line 9
    iget v0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/GrpcRequestBody;->messageSize:I

    .line 10
    .line 11
    invoke-interface {p1, v0}, Lu01/g;->writeInt(I)Lu01/g;

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/GrpcRequestBody;->marshaler:Lio/opentelemetry/exporter/internal/marshal/Marshaler;

    .line 15
    .line 16
    invoke-interface {p1}, Lu01/g;->t0()Ljava/io/OutputStream;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    invoke-virtual {p0, p1}, Lio/opentelemetry/exporter/internal/marshal/Marshaler;->writeBinaryTo(Ljava/io/OutputStream;)V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :cond_0
    new-instance v1, Lu01/f;

    .line 25
    .line 26
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 27
    .line 28
    .line 29
    new-instance v2, Lm6/b1;

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    invoke-direct {v2, v1, v3}, Lm6/b1;-><init>(Lu01/g;I)V

    .line 33
    .line 34
    .line 35
    invoke-interface {v0, v2}, Lio/opentelemetry/exporter/internal/compression/Compressor;->compress(Ljava/io/OutputStream;)Ljava/io/OutputStream;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    const-string v2, "<this>"

    .line 40
    .line 41
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    new-instance v2, Lu01/x;

    .line 45
    .line 46
    new-instance v3, Lu01/j0;

    .line 47
    .line 48
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 49
    .line 50
    .line 51
    invoke-direct {v2, v0, v3}, Lu01/x;-><init>(Ljava/io/OutputStream;Lu01/j0;)V

    .line 52
    .line 53
    .line 54
    invoke-static {v2}, Lu01/b;->b(Lu01/f0;)Lu01/a0;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    :try_start_0
    iget-object p0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/GrpcRequestBody;->marshaler:Lio/opentelemetry/exporter/internal/marshal/Marshaler;

    .line 59
    .line 60
    new-instance v2, Lm6/b1;

    .line 61
    .line 62
    const/4 v3, 0x2

    .line 63
    invoke-direct {v2, v0, v3}, Lm6/b1;-><init>(Lu01/g;I)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {p0, v2}, Lio/opentelemetry/exporter/internal/marshal/Marshaler;->writeBinaryTo(Ljava/io/OutputStream;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 67
    .line 68
    .line 69
    invoke-virtual {v0}, Lu01/a0;->close()V

    .line 70
    .line 71
    .line 72
    const/4 p0, 0x1

    .line 73
    invoke-interface {p1, p0}, Lu01/g;->writeByte(I)Lu01/g;

    .line 74
    .line 75
    .line 76
    iget-wide v2, v1, Lu01/f;->e:J

    .line 77
    .line 78
    long-to-int p0, v2

    .line 79
    invoke-interface {p1, p0}, Lu01/g;->writeInt(I)Lu01/g;

    .line 80
    .line 81
    .line 82
    int-to-long v2, p0

    .line 83
    invoke-interface {p1, v1, v2, v3}, Lu01/f0;->F(Lu01/f;J)V

    .line 84
    .line 85
    .line 86
    return-void

    .line 87
    :catchall_0
    move-exception p0

    .line 88
    :try_start_1
    invoke-virtual {v0}, Lu01/a0;->close()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 89
    .line 90
    .line 91
    goto :goto_0

    .line 92
    :catchall_1
    move-exception p1

    .line 93
    invoke-virtual {p0, p1}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 94
    .line 95
    .line 96
    :goto_0
    throw p0
.end method
