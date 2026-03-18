.class abstract Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;
.super Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x409
    name = "AbstractBufferedEncoder"
.end annotation


# instance fields
.field final buffer:[B

.field final limit:I

.field position:I

.field totalBytesWritten:I


# direct methods
.method public constructor <init>(I)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;-><init>(Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$1;)V

    .line 3
    .line 4
    .line 5
    new-array p1, p1, [B

    .line 6
    .line 7
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->buffer:[B

    .line 8
    .line 9
    array-length p1, p1

    .line 10
    iput p1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->limit:I

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final buffer(B)V
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->buffer:[B

    .line 2
    .line 3
    iget v1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 4
    .line 5
    add-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    iput v2, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 8
    .line 9
    aput-byte p1, v0, v1

    .line 10
    .line 11
    iget p1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->totalBytesWritten:I

    .line 12
    .line 13
    add-int/lit8 p1, p1, 0x1

    .line 14
    .line 15
    iput p1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->totalBytesWritten:I

    .line 16
    .line 17
    return-void
.end method

.method public final bufferFixed32NoTag(I)V
    .locals 5

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->buffer:[B

    .line 2
    .line 3
    iget v1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 4
    .line 5
    add-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    iput v2, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 8
    .line 9
    and-int/lit16 v3, p1, 0xff

    .line 10
    .line 11
    int-to-byte v3, v3

    .line 12
    aput-byte v3, v0, v1

    .line 13
    .line 14
    add-int/lit8 v3, v1, 0x2

    .line 15
    .line 16
    iput v3, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 17
    .line 18
    shr-int/lit8 v4, p1, 0x8

    .line 19
    .line 20
    and-int/lit16 v4, v4, 0xff

    .line 21
    .line 22
    int-to-byte v4, v4

    .line 23
    aput-byte v4, v0, v2

    .line 24
    .line 25
    add-int/lit8 v2, v1, 0x3

    .line 26
    .line 27
    iput v2, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 28
    .line 29
    shr-int/lit8 v4, p1, 0x10

    .line 30
    .line 31
    and-int/lit16 v4, v4, 0xff

    .line 32
    .line 33
    int-to-byte v4, v4

    .line 34
    aput-byte v4, v0, v3

    .line 35
    .line 36
    add-int/lit8 v1, v1, 0x4

    .line 37
    .line 38
    iput v1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 39
    .line 40
    shr-int/lit8 p1, p1, 0x18

    .line 41
    .line 42
    and-int/lit16 p1, p1, 0xff

    .line 43
    .line 44
    int-to-byte p1, p1

    .line 45
    aput-byte p1, v0, v2

    .line 46
    .line 47
    iget p1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->totalBytesWritten:I

    .line 48
    .line 49
    add-int/lit8 p1, p1, 0x4

    .line 50
    .line 51
    iput p1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->totalBytesWritten:I

    .line 52
    .line 53
    return-void
.end method

.method public final bufferFixed64NoTag(J)V
    .locals 9

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->buffer:[B

    .line 2
    .line 3
    iget v1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 4
    .line 5
    add-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    iput v2, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 8
    .line 9
    const-wide/16 v3, 0xff

    .line 10
    .line 11
    and-long v5, p1, v3

    .line 12
    .line 13
    long-to-int v5, v5

    .line 14
    int-to-byte v5, v5

    .line 15
    aput-byte v5, v0, v1

    .line 16
    .line 17
    add-int/lit8 v5, v1, 0x2

    .line 18
    .line 19
    iput v5, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 20
    .line 21
    const/16 v6, 0x8

    .line 22
    .line 23
    shr-long v7, p1, v6

    .line 24
    .line 25
    and-long/2addr v7, v3

    .line 26
    long-to-int v7, v7

    .line 27
    int-to-byte v7, v7

    .line 28
    aput-byte v7, v0, v2

    .line 29
    .line 30
    add-int/lit8 v2, v1, 0x3

    .line 31
    .line 32
    iput v2, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 33
    .line 34
    const/16 v7, 0x10

    .line 35
    .line 36
    shr-long v7, p1, v7

    .line 37
    .line 38
    and-long/2addr v7, v3

    .line 39
    long-to-int v7, v7

    .line 40
    int-to-byte v7, v7

    .line 41
    aput-byte v7, v0, v5

    .line 42
    .line 43
    add-int/lit8 v5, v1, 0x4

    .line 44
    .line 45
    iput v5, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 46
    .line 47
    const/16 v7, 0x18

    .line 48
    .line 49
    shr-long v7, p1, v7

    .line 50
    .line 51
    and-long/2addr v3, v7

    .line 52
    long-to-int v3, v3

    .line 53
    int-to-byte v3, v3

    .line 54
    aput-byte v3, v0, v2

    .line 55
    .line 56
    add-int/lit8 v2, v1, 0x5

    .line 57
    .line 58
    iput v2, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 59
    .line 60
    const/16 v3, 0x20

    .line 61
    .line 62
    shr-long v3, p1, v3

    .line 63
    .line 64
    long-to-int v3, v3

    .line 65
    and-int/lit16 v3, v3, 0xff

    .line 66
    .line 67
    int-to-byte v3, v3

    .line 68
    aput-byte v3, v0, v5

    .line 69
    .line 70
    add-int/lit8 v3, v1, 0x6

    .line 71
    .line 72
    iput v3, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 73
    .line 74
    const/16 v4, 0x28

    .line 75
    .line 76
    shr-long v4, p1, v4

    .line 77
    .line 78
    long-to-int v4, v4

    .line 79
    and-int/lit16 v4, v4, 0xff

    .line 80
    .line 81
    int-to-byte v4, v4

    .line 82
    aput-byte v4, v0, v2

    .line 83
    .line 84
    add-int/lit8 v2, v1, 0x7

    .line 85
    .line 86
    iput v2, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 87
    .line 88
    const/16 v4, 0x30

    .line 89
    .line 90
    shr-long v4, p1, v4

    .line 91
    .line 92
    long-to-int v4, v4

    .line 93
    and-int/lit16 v4, v4, 0xff

    .line 94
    .line 95
    int-to-byte v4, v4

    .line 96
    aput-byte v4, v0, v3

    .line 97
    .line 98
    add-int/2addr v1, v6

    .line 99
    iput v1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 100
    .line 101
    const/16 v1, 0x38

    .line 102
    .line 103
    shr-long/2addr p1, v1

    .line 104
    long-to-int p1, p1

    .line 105
    and-int/lit16 p1, p1, 0xff

    .line 106
    .line 107
    int-to-byte p1, p1

    .line 108
    aput-byte p1, v0, v2

    .line 109
    .line 110
    iget p1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->totalBytesWritten:I

    .line 111
    .line 112
    add-int/2addr p1, v6

    .line 113
    iput p1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->totalBytesWritten:I

    .line 114
    .line 115
    return-void
.end method

.method public final bufferUInt32NoTag(I)V
    .locals 3

    .line 1
    :goto_0
    and-int/lit8 v0, p1, -0x80

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->buffer:[B

    .line 6
    .line 7
    iget v1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 8
    .line 9
    add-int/lit8 v2, v1, 0x1

    .line 10
    .line 11
    iput v2, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 12
    .line 13
    int-to-byte p1, p1

    .line 14
    aput-byte p1, v0, v1

    .line 15
    .line 16
    iget p1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->totalBytesWritten:I

    .line 17
    .line 18
    add-int/lit8 p1, p1, 0x1

    .line 19
    .line 20
    iput p1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->totalBytesWritten:I

    .line 21
    .line 22
    return-void

    .line 23
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->buffer:[B

    .line 24
    .line 25
    iget v1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 26
    .line 27
    add-int/lit8 v2, v1, 0x1

    .line 28
    .line 29
    iput v2, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 30
    .line 31
    and-int/lit8 v2, p1, 0x7f

    .line 32
    .line 33
    or-int/lit16 v2, v2, 0x80

    .line 34
    .line 35
    int-to-byte v2, v2

    .line 36
    aput-byte v2, v0, v1

    .line 37
    .line 38
    iget v0, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->totalBytesWritten:I

    .line 39
    .line 40
    add-int/lit8 v0, v0, 0x1

    .line 41
    .line 42
    iput v0, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->totalBytesWritten:I

    .line 43
    .line 44
    ushr-int/lit8 p1, p1, 0x7

    .line 45
    .line 46
    goto :goto_0
.end method

.method public final bufferUInt64NoTag(J)V
    .locals 4

    .line 1
    :goto_0
    const-wide/16 v0, -0x80

    .line 2
    .line 3
    and-long/2addr v0, p1

    .line 4
    const-wide/16 v2, 0x0

    .line 5
    .line 6
    cmp-long v0, v0, v2

    .line 7
    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->buffer:[B

    .line 11
    .line 12
    iget v1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 13
    .line 14
    add-int/lit8 v2, v1, 0x1

    .line 15
    .line 16
    iput v2, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 17
    .line 18
    long-to-int p1, p1

    .line 19
    int-to-byte p1, p1

    .line 20
    aput-byte p1, v0, v1

    .line 21
    .line 22
    iget p1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->totalBytesWritten:I

    .line 23
    .line 24
    add-int/lit8 p1, p1, 0x1

    .line 25
    .line 26
    iput p1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->totalBytesWritten:I

    .line 27
    .line 28
    return-void

    .line 29
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->buffer:[B

    .line 30
    .line 31
    iget v1, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 32
    .line 33
    add-int/lit8 v2, v1, 0x1

    .line 34
    .line 35
    iput v2, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->position:I

    .line 36
    .line 37
    long-to-int v2, p1

    .line 38
    and-int/lit8 v2, v2, 0x7f

    .line 39
    .line 40
    or-int/lit16 v2, v2, 0x80

    .line 41
    .line 42
    int-to-byte v2, v2

    .line 43
    aput-byte v2, v0, v1

    .line 44
    .line 45
    iget v0, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->totalBytesWritten:I

    .line 46
    .line 47
    add-int/lit8 v0, v0, 0x1

    .line 48
    .line 49
    iput v0, p0, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream$AbstractBufferedEncoder;->totalBytesWritten:I

    .line 50
    .line 51
    const/4 v0, 0x7

    .line 52
    ushr-long/2addr p1, v0

    .line 53
    goto :goto_0
.end method
