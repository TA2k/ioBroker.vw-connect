.class Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$CompressedRequestBody;
.super Ld01/r0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "CompressedRequestBody"
.end annotation


# instance fields
.field private final compressor:Lio/opentelemetry/exporter/internal/compression/Compressor;

.field private final requestBody:Ld01/r0;


# direct methods
.method private constructor <init>(Lio/opentelemetry/exporter/internal/compression/Compressor;Ld01/r0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$CompressedRequestBody;->compressor:Lio/opentelemetry/exporter/internal/compression/Compressor;

    .line 3
    iput-object p2, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$CompressedRequestBody;->requestBody:Ld01/r0;

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/exporter/internal/compression/Compressor;Ld01/r0;Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$1;)V
    .locals 0

    .line 4
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$CompressedRequestBody;-><init>(Lio/opentelemetry/exporter/internal/compression/Compressor;Ld01/r0;)V

    return-void
.end method


# virtual methods
.method public contentLength()J
    .locals 2

    .line 1
    const-wide/16 v0, -0x1

    .line 2
    .line 3
    return-wide v0
.end method

.method public contentType()Ld01/d0;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$CompressedRequestBody;->requestBody:Ld01/r0;

    .line 2
    .line 3
    invoke-virtual {p0}, Ld01/r0;->contentType()Ld01/d0;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public writeTo(Lu01/g;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$CompressedRequestBody;->compressor:Lio/opentelemetry/exporter/internal/compression/Compressor;

    .line 2
    .line 3
    invoke-interface {p1}, Lu01/g;->t0()Ljava/io/OutputStream;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-interface {v0, p1}, Lio/opentelemetry/exporter/internal/compression/Compressor;->compress(Ljava/io/OutputStream;)Ljava/io/OutputStream;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    const-string v0, "<this>"

    .line 12
    .line 13
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    new-instance v0, Lu01/x;

    .line 17
    .line 18
    new-instance v1, Lu01/j0;

    .line 19
    .line 20
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 21
    .line 22
    .line 23
    invoke-direct {v0, p1, v1}, Lu01/x;-><init>(Ljava/io/OutputStream;Lu01/j0;)V

    .line 24
    .line 25
    .line 26
    invoke-static {v0}, Lu01/b;->b(Lu01/f0;)Lu01/a0;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    iget-object p0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$CompressedRequestBody;->requestBody:Ld01/r0;

    .line 31
    .line 32
    invoke-virtual {p0, p1}, Ld01/r0;->writeTo(Lu01/g;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p1}, Lu01/a0;->close()V

    .line 36
    .line 37
    .line 38
    return-void
.end method
