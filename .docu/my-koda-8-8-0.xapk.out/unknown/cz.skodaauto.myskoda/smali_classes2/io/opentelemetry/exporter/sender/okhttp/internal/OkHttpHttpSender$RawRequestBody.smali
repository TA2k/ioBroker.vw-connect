.class Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$RawRequestBody;
.super Ld01/r0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "RawRequestBody"
.end annotation


# instance fields
.field private final contentLength:I

.field private final exportAsJson:Z

.field private final marshaler:Lio/opentelemetry/exporter/internal/marshal/Marshaler;

.field private final mediaType:Ld01/d0;


# direct methods
.method private constructor <init>(Lio/opentelemetry/exporter/internal/marshal/Marshaler;ZILd01/d0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$RawRequestBody;->marshaler:Lio/opentelemetry/exporter/internal/marshal/Marshaler;

    .line 3
    iput-boolean p2, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$RawRequestBody;->exportAsJson:Z

    .line 4
    iput p3, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$RawRequestBody;->contentLength:I

    .line 5
    iput-object p4, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$RawRequestBody;->mediaType:Ld01/d0;

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/exporter/internal/marshal/Marshaler;ZILd01/d0;Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$1;)V
    .locals 0

    .line 6
    invoke-direct {p0, p1, p2, p3, p4}, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$RawRequestBody;-><init>(Lio/opentelemetry/exporter/internal/marshal/Marshaler;ZILd01/d0;)V

    return-void
.end method


# virtual methods
.method public contentLength()J
    .locals 2

    .line 1
    iget p0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$RawRequestBody;->contentLength:I

    .line 2
    .line 3
    int-to-long v0, p0

    .line 4
    return-wide v0
.end method

.method public contentType()Ld01/d0;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$RawRequestBody;->mediaType:Ld01/d0;

    .line 2
    .line 3
    return-object p0
.end method

.method public writeTo(Lu01/g;)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$RawRequestBody;->exportAsJson:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$RawRequestBody;->marshaler:Lio/opentelemetry/exporter/internal/marshal/Marshaler;

    .line 6
    .line 7
    invoke-interface {p1}, Lu01/g;->t0()Ljava/io/OutputStream;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    invoke-virtual {p0, p1}, Lio/opentelemetry/exporter/internal/marshal/Marshaler;->writeJsonTo(Ljava/io/OutputStream;)V

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$RawRequestBody;->marshaler:Lio/opentelemetry/exporter/internal/marshal/Marshaler;

    .line 16
    .line 17
    invoke-interface {p1}, Lu01/g;->t0()Ljava/io/OutputStream;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    invoke-virtual {p0, p1}, Lio/opentelemetry/exporter/internal/marshal/Marshaler;->writeBinaryTo(Ljava/io/OutputStream;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method
