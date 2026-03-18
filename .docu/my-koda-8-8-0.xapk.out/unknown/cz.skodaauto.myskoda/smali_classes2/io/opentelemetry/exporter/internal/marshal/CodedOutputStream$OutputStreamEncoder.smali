.class final Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$OutputStreamEncoder;
.super Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "OutputStreamEncoder"
.end annotation


# instance fields
.field private out:Ljava/io/OutputStream;


# direct methods
.method public constructor <init>(Ljava/io/OutputStream;)V
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->access$100()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;-><init>(I)V

    .line 6
    .line 7
    .line 8
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$OutputStreamEncoder;->out:Ljava/io/OutputStream;

    .line 9
    .line 10
    return-void
.end method

.method private doFlush()V
    .locals 4

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$OutputStreamEncoder;->out:Ljava/io/OutputStream;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->buffer:[B

    .line 4
    .line 5
    iget v2, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    invoke-virtual {v0, v1, v3, v2}, Ljava/io/OutputStream;->write([BII)V

    .line 9
    .line 10
    .line 11
    iput v3, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 12
    .line 13
    return-void
.end method

.method private flushIfNotAvailable(I)V
    .locals 2

    .line 1
    iget v0, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->limit:I

    .line 2
    .line 3
    iget v1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 4
    .line 5
    sub-int/2addr v0, v1

    .line 6
    if-ge v0, p1, :cond_0

    .line 7
    .line 8
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$OutputStreamEncoder;->doFlush()V

    .line 9
    .line 10
    .line 11
    :cond_0
    return-void
.end method


# virtual methods
.method public flush()V
    .locals 1

    .line 1
    iget v0, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 2
    .line 3
    if-lez v0, :cond_0

    .line 4
    .line 5
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$OutputStreamEncoder;->doFlush()V

    .line 6
    .line 7
    .line 8
    :cond_0
    return-void
.end method

.method public reset(Ljava/io/OutputStream;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$OutputStreamEncoder;->out:Ljava/io/OutputStream;

    .line 2
    .line 3
    const/4 p1, 0x0

    .line 4
    iput p1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 5
    .line 6
    iput p1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->totalBytesWritten:I

    .line 7
    .line 8
    return-void
.end method

.method public write(B)V
    .locals 2

    .line 18
    iget v0, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    iget v1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->limit:I

    if-ne v0, v1, :cond_0

    .line 19
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$OutputStreamEncoder;->doFlush()V

    .line 20
    :cond_0
    invoke-virtual {p0, p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->buffer(B)V

    return-void
.end method

.method public write(Ljava/nio/ByteBuffer;)V
    .locals 5

    .line 1
    invoke-virtual {p1}, Ljava/nio/Buffer;->remaining()I

    move-result v0

    .line 2
    iget v1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->limit:I

    iget v2, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    sub-int v3, v1, v2

    if-lt v3, v0, :cond_0

    .line 3
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->buffer:[B

    invoke-virtual {p1, v1, v2, v0}, Ljava/nio/ByteBuffer;->get([BII)Ljava/nio/ByteBuffer;

    .line 4
    iget p1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    add-int/2addr p1, v0

    iput p1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 5
    iget p1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->totalBytesWritten:I

    add-int/2addr p1, v0

    iput p1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->totalBytesWritten:I

    return-void

    :cond_0
    sub-int/2addr v1, v2

    .line 6
    iget-object v3, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->buffer:[B

    invoke-virtual {p1, v3, v2, v1}, Ljava/nio/ByteBuffer;->get([BII)Ljava/nio/ByteBuffer;

    sub-int/2addr v0, v1

    .line 7
    iget v2, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->limit:I

    iput v2, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 8
    iget v2, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->totalBytesWritten:I

    add-int/2addr v2, v1

    iput v2, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->totalBytesWritten:I

    .line 9
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$OutputStreamEncoder;->doFlush()V

    .line 10
    :goto_0
    iget v1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->limit:I

    const/4 v2, 0x0

    if-le v0, v1, :cond_1

    .line 11
    iget-object v3, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->buffer:[B

    invoke-virtual {p1, v3, v2, v1}, Ljava/nio/ByteBuffer;->get([BII)Ljava/nio/ByteBuffer;

    .line 12
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$OutputStreamEncoder;->out:Ljava/io/OutputStream;

    iget-object v3, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->buffer:[B

    iget v4, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->limit:I

    invoke-virtual {v1, v3, v2, v4}, Ljava/io/OutputStream;->write([BII)V

    .line 13
    iget v1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->limit:I

    sub-int/2addr v0, v1

    .line 14
    iget v2, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->totalBytesWritten:I

    add-int/2addr v2, v1

    iput v2, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->totalBytesWritten:I

    goto :goto_0

    .line 15
    :cond_1
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->buffer:[B

    invoke-virtual {p1, v1, v2, v0}, Ljava/nio/ByteBuffer;->get([BII)Ljava/nio/ByteBuffer;

    .line 16
    iput v0, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 17
    iget p1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->totalBytesWritten:I

    add-int/2addr p1, v0

    iput p1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->totalBytesWritten:I

    return-void
.end method

.method public write([BII)V
    .locals 3

    .line 21
    iget v0, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->limit:I

    iget v1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    sub-int v2, v0, v1

    if-lt v2, p3, :cond_0

    .line 22
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->buffer:[B

    invoke-static {p1, p2, v0, v1, p3}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 23
    iget p1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    add-int/2addr p1, p3

    iput p1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 24
    iget p1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->totalBytesWritten:I

    add-int/2addr p1, p3

    iput p1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->totalBytesWritten:I

    return-void

    :cond_0
    sub-int/2addr v0, v1

    .line 25
    iget-object v2, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->buffer:[B

    invoke-static {p1, p2, v2, v1, v0}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    add-int/2addr p2, v0

    sub-int/2addr p3, v0

    .line 26
    iget v1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->limit:I

    iput v1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 27
    iget v1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->totalBytesWritten:I

    add-int/2addr v1, v0

    iput v1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->totalBytesWritten:I

    .line 28
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$OutputStreamEncoder;->doFlush()V

    .line 29
    iget v0, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->limit:I

    if-gt p3, v0, :cond_1

    .line 30
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->buffer:[B

    const/4 v1, 0x0

    invoke-static {p1, p2, v0, v1, p3}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 31
    iput p3, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    goto :goto_0

    .line 32
    :cond_1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$OutputStreamEncoder;->out:Ljava/io/OutputStream;

    invoke-virtual {v0, p1, p2, p3}, Ljava/io/OutputStream;->write([BII)V

    .line 33
    :goto_0
    iget p1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->totalBytesWritten:I

    add-int/2addr p1, p3

    iput p1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->totalBytesWritten:I

    return-void
.end method

.method public writeByteArrayNoTag([BII)V
    .locals 0

    .line 1
    invoke-virtual {p0, p3}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$OutputStreamEncoder;->writeUInt32NoTag(I)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$OutputStreamEncoder;->write([BII)V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public writeByteBufferNoTag(Ljava/nio/ByteBuffer;)V
    .locals 2

    .line 1
    invoke-virtual {p1}, Ljava/nio/Buffer;->capacity()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$OutputStreamEncoder;->writeUInt32NoTag(I)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/nio/ByteBuffer;->hasArray()Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    invoke-virtual {p1}, Ljava/nio/ByteBuffer;->array()[B

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-virtual {p1}, Ljava/nio/ByteBuffer;->arrayOffset()I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    invoke-virtual {p1}, Ljava/nio/Buffer;->capacity()I

    .line 23
    .line 24
    .line 25
    move-result p1

    .line 26
    invoke-virtual {p0, v0, v1, p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$OutputStreamEncoder;->write([BII)V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :cond_0
    invoke-virtual {p1}, Ljava/nio/ByteBuffer;->duplicate()Ljava/nio/ByteBuffer;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    invoke-virtual {p1}, Ljava/nio/ByteBuffer;->clear()Ljava/nio/Buffer;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    check-cast p1, Ljava/nio/ByteBuffer;

    .line 39
    .line 40
    invoke-virtual {p0, p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$OutputStreamEncoder;->write(Ljava/nio/ByteBuffer;)V

    .line 41
    .line 42
    .line 43
    return-void
.end method

.method public writeFixed32NoTag(I)V
    .locals 1

    .line 1
    const/4 v0, 0x4

    .line 2
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$OutputStreamEncoder;->flushIfNotAvailable(I)V

    .line 3
    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->bufferFixed32NoTag(I)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public writeFixed64NoTag(J)V
    .locals 1

    .line 1
    const/16 v0, 0x8

    .line 2
    .line 3
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$OutputStreamEncoder;->flushIfNotAvailable(I)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->bufferFixed64NoTag(J)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public writeInt32NoTag(I)V
    .locals 2

    .line 1
    if-ltz p1, :cond_0

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$OutputStreamEncoder;->writeUInt32NoTag(I)V

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :cond_0
    int-to-long v0, p1

    .line 8
    invoke-virtual {p0, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$OutputStreamEncoder;->writeUInt64NoTag(J)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public writeUInt32NoTag(I)V
    .locals 1

    .line 1
    const/4 v0, 0x5

    .line 2
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$OutputStreamEncoder;->flushIfNotAvailable(I)V

    .line 3
    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->bufferUInt32NoTag(I)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public writeUInt64NoTag(J)V
    .locals 1

    .line 1
    const/16 v0, 0xa

    .line 2
    .line 3
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$OutputStreamEncoder;->flushIfNotAvailable(I)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->bufferUInt64NoTag(J)V

    .line 7
    .line 8
    .line 9
    return-void
.end method
