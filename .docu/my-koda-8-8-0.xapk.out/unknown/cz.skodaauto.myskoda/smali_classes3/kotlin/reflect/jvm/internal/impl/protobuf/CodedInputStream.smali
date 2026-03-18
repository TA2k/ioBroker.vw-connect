.class public final Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream$RefillCallback;
    }
.end annotation


# instance fields
.field private final buffer:[B

.field private final bufferIsImmutable:Z

.field private bufferPos:I

.field private bufferSize:I

.field private bufferSizeAfterLimit:I

.field private currentLimit:I

.field private enableAliasing:Z

.field private final input:Ljava/io/InputStream;

.field private lastTag:I

.field private recursionDepth:I

.field private recursionLimit:I

.field private refillCallback:Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream$RefillCallback;

.field private sizeLimit:I

.field private totalBytesRetired:I


# direct methods
.method private constructor <init>(Ljava/io/InputStream;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->enableAliasing:Z

    const v1, 0x7fffffff

    .line 3
    iput v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->currentLimit:I

    const/16 v1, 0x40

    .line 4
    iput v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->recursionLimit:I

    const/high16 v1, 0x4000000

    .line 5
    iput v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->sizeLimit:I

    const/4 v1, 0x0

    .line 6
    iput-object v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->refillCallback:Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream$RefillCallback;

    const/16 v1, 0x1000

    .line 7
    new-array v1, v1, [B

    iput-object v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->buffer:[B

    .line 8
    iput v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    .line 9
    iput v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 10
    iput v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->totalBytesRetired:I

    .line 11
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->input:Ljava/io/InputStream;

    .line 12
    iput-boolean v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferIsImmutable:Z

    return-void
.end method

.method private constructor <init>(Lkotlin/reflect/jvm/internal/impl/protobuf/LiteralByteString;)V
    .locals 2

    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 14
    iput-boolean v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->enableAliasing:Z

    const v0, 0x7fffffff

    .line 15
    iput v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->currentLimit:I

    const/16 v0, 0x40

    .line 16
    iput v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->recursionLimit:I

    const/high16 v0, 0x4000000

    .line 17
    iput v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->sizeLimit:I

    const/4 v0, 0x0

    .line 18
    iput-object v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->refillCallback:Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream$RefillCallback;

    .line 19
    iget-object v1, p1, Lkotlin/reflect/jvm/internal/impl/protobuf/LiteralByteString;->bytes:[B

    iput-object v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->buffer:[B

    .line 20
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/protobuf/LiteralByteString;->getOffsetIntoBytes()I

    move-result v1

    iput v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 21
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/protobuf/LiteralByteString;->size()I

    move-result p1

    add-int/2addr v1, p1

    iput v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    .line 22
    iget p1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    neg-int p1, p1

    iput p1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->totalBytesRetired:I

    .line 23
    iput-object v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->input:Ljava/io/InputStream;

    const/4 p1, 0x1

    .line 24
    iput-boolean p1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferIsImmutable:Z

    return-void
.end method

.method public static decodeZigZag32(I)I
    .locals 1

    .line 1
    ushr-int/lit8 v0, p0, 0x1

    .line 2
    .line 3
    and-int/lit8 p0, p0, 0x1

    .line 4
    .line 5
    neg-int p0, p0

    .line 6
    xor-int/2addr p0, v0

    .line 7
    return p0
.end method

.method public static decodeZigZag64(J)J
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    ushr-long v0, p0, v0

    .line 3
    .line 4
    const-wide/16 v2, 0x1

    .line 5
    .line 6
    and-long/2addr p0, v2

    .line 7
    neg-long p0, p0

    .line 8
    xor-long/2addr p0, v0

    .line 9
    return-wide p0
.end method

.method private ensureAvailable(I)V
    .locals 2

    .line 1
    iget v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    .line 2
    .line 3
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 4
    .line 5
    sub-int/2addr v0, v1

    .line 6
    if-ge v0, p1, :cond_0

    .line 7
    .line 8
    invoke-direct {p0, p1}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->refillBuffer(I)V

    .line 9
    .line 10
    .line 11
    :cond_0
    return-void
.end method

.method public static newInstance(Ljava/io/InputStream;)Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;
    .locals 1

    .line 1
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;

    invoke-direct {v0, p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;-><init>(Ljava/io/InputStream;)V

    return-object v0
.end method

.method public static newInstance(Lkotlin/reflect/jvm/internal/impl/protobuf/LiteralByteString;)Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;
    .locals 1

    .line 2
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;

    invoke-direct {v0, p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;-><init>(Lkotlin/reflect/jvm/internal/impl/protobuf/LiteralByteString;)V

    .line 3
    :try_start_0
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/LiteralByteString;->size()I

    move-result p0

    invoke-virtual {v0, p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->pushLimit(I)I
    :try_end_0
    .catch Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException; {:try_start_0 .. :try_end_0} :catch_0

    return-object v0

    :catch_0
    move-exception p0

    .line 4
    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/Throwable;)V

    throw v0
.end method

.method private readRawBytesSlowPath(I)[B
    .locals 12

    .line 1
    if-gtz p1, :cond_1

    .line 2
    .line 3
    if-nez p1, :cond_0

    .line 4
    .line 5
    sget-object p0, Lkotlin/reflect/jvm/internal/impl/protobuf/Internal;->EMPTY_BYTE_ARRAY:[B

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;->negativeSize()Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    throw p0

    .line 13
    :cond_1
    iget v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->totalBytesRetired:I

    .line 14
    .line 15
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 16
    .line 17
    add-int v2, v0, v1

    .line 18
    .line 19
    add-int/2addr v2, p1

    .line 20
    iget v3, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->currentLimit:I

    .line 21
    .line 22
    if-gt v2, v3, :cond_8

    .line 23
    .line 24
    const/16 v2, 0x1000

    .line 25
    .line 26
    const/4 v3, 0x0

    .line 27
    if-ge p1, v2, :cond_2

    .line 28
    .line 29
    new-array v0, p1, [B

    .line 30
    .line 31
    iget v2, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    .line 32
    .line 33
    sub-int/2addr v2, v1

    .line 34
    iget-object v4, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->buffer:[B

    .line 35
    .line 36
    invoke-static {v4, v1, v0, v3, v2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 37
    .line 38
    .line 39
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    .line 40
    .line 41
    iput v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 42
    .line 43
    sub-int/2addr p1, v2

    .line 44
    invoke-direct {p0, p1}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->ensureAvailable(I)V

    .line 45
    .line 46
    .line 47
    iget-object v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->buffer:[B

    .line 48
    .line 49
    invoke-static {v1, v3, v0, v2, p1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 50
    .line 51
    .line 52
    iput p1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 53
    .line 54
    return-object v0

    .line 55
    :cond_2
    iget v4, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    .line 56
    .line 57
    add-int/2addr v0, v4

    .line 58
    iput v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->totalBytesRetired:I

    .line 59
    .line 60
    iput v3, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 61
    .line 62
    iput v3, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    .line 63
    .line 64
    sub-int/2addr v4, v1

    .line 65
    sub-int v0, p1, v4

    .line 66
    .line 67
    new-instance v5, Ljava/util/ArrayList;

    .line 68
    .line 69
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 70
    .line 71
    .line 72
    :goto_0
    if-lez v0, :cond_6

    .line 73
    .line 74
    invoke-static {v0, v2}, Ljava/lang/Math;->min(II)I

    .line 75
    .line 76
    .line 77
    move-result v6

    .line 78
    new-array v7, v6, [B

    .line 79
    .line 80
    move v8, v3

    .line 81
    :goto_1
    if-ge v8, v6, :cond_5

    .line 82
    .line 83
    iget-object v9, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->input:Ljava/io/InputStream;

    .line 84
    .line 85
    const/4 v10, -0x1

    .line 86
    if-nez v9, :cond_3

    .line 87
    .line 88
    move v9, v10

    .line 89
    goto :goto_2

    .line 90
    :cond_3
    sub-int v11, v6, v8

    .line 91
    .line 92
    invoke-virtual {v9, v7, v8, v11}, Ljava/io/InputStream;->read([BII)I

    .line 93
    .line 94
    .line 95
    move-result v9

    .line 96
    :goto_2
    if-eq v9, v10, :cond_4

    .line 97
    .line 98
    iget v10, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->totalBytesRetired:I

    .line 99
    .line 100
    add-int/2addr v10, v9

    .line 101
    iput v10, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->totalBytesRetired:I

    .line 102
    .line 103
    add-int/2addr v8, v9

    .line 104
    goto :goto_1

    .line 105
    :cond_4
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;->truncatedMessage()Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    throw p0

    .line 110
    :cond_5
    sub-int/2addr v0, v6

    .line 111
    invoke-virtual {v5, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    goto :goto_0

    .line 115
    :cond_6
    new-array p1, p1, [B

    .line 116
    .line 117
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->buffer:[B

    .line 118
    .line 119
    invoke-static {p0, v1, p1, v3, v4}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {v5}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    :goto_3
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 127
    .line 128
    .line 129
    move-result v0

    .line 130
    if-eqz v0, :cond_7

    .line 131
    .line 132
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v0

    .line 136
    check-cast v0, [B

    .line 137
    .line 138
    array-length v1, v0

    .line 139
    invoke-static {v0, v3, p1, v4, v1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 140
    .line 141
    .line 142
    array-length v0, v0

    .line 143
    add-int/2addr v4, v0

    .line 144
    goto :goto_3

    .line 145
    :cond_7
    return-object p1

    .line 146
    :cond_8
    sub-int/2addr v3, v0

    .line 147
    sub-int/2addr v3, v1

    .line 148
    invoke-virtual {p0, v3}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->skipRawBytes(I)V

    .line 149
    .line 150
    .line 151
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;->truncatedMessage()Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;

    .line 152
    .line 153
    .line 154
    move-result-object p0

    .line 155
    throw p0
.end method

.method public static readRawVarint32(ILjava/io/InputStream;)I
    .locals 3

    and-int/lit16 v0, p0, 0x80

    if-nez v0, :cond_0

    return p0

    :cond_0
    and-int/lit8 p0, p0, 0x7f

    const/4 v0, 0x7

    :goto_0
    const/16 v1, 0x20

    const/4 v2, -0x1

    if-ge v0, v1, :cond_3

    .line 13
    invoke-virtual {p1}, Ljava/io/InputStream;->read()I

    move-result v1

    if-eq v1, v2, :cond_2

    and-int/lit8 v2, v1, 0x7f

    shl-int/2addr v2, v0

    or-int/2addr p0, v2

    and-int/lit16 v1, v1, 0x80

    if-nez v1, :cond_1

    return p0

    :cond_1
    add-int/lit8 v0, v0, 0x7

    goto :goto_0

    .line 14
    :cond_2
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;->truncatedMessage()Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;

    move-result-object p0

    throw p0

    :cond_3
    :goto_1
    const/16 v1, 0x40

    if-ge v0, v1, :cond_6

    .line 15
    invoke-virtual {p1}, Ljava/io/InputStream;->read()I

    move-result v1

    if-eq v1, v2, :cond_5

    and-int/lit16 v1, v1, 0x80

    if-nez v1, :cond_4

    return p0

    :cond_4
    add-int/lit8 v0, v0, 0x7

    goto :goto_1

    .line 16
    :cond_5
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;->truncatedMessage()Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;

    move-result-object p0

    throw p0

    .line 17
    :cond_6
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;->malformedVarint()Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;

    move-result-object p0

    throw p0
.end method

.method private recomputeBufferSizeAfterLimit()V
    .locals 3

    .line 1
    iget v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    .line 2
    .line 3
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSizeAfterLimit:I

    .line 4
    .line 5
    add-int/2addr v0, v1

    .line 6
    iput v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    .line 7
    .line 8
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->totalBytesRetired:I

    .line 9
    .line 10
    add-int/2addr v1, v0

    .line 11
    iget v2, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->currentLimit:I

    .line 12
    .line 13
    if-le v1, v2, :cond_0

    .line 14
    .line 15
    sub-int/2addr v1, v2

    .line 16
    iput v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSizeAfterLimit:I

    .line 17
    .line 18
    sub-int/2addr v0, v1

    .line 19
    iput v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    .line 20
    .line 21
    return-void

    .line 22
    :cond_0
    const/4 v0, 0x0

    .line 23
    iput v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSizeAfterLimit:I

    .line 24
    .line 25
    return-void
.end method

.method private refillBuffer(I)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->tryRefillBuffer(I)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;->truncatedMessage()Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    throw p0
.end method

.method private skipRawBytesSlowPath(I)V
    .locals 4

    .line 1
    if-ltz p1, :cond_2

    .line 2
    .line 3
    iget v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->totalBytesRetired:I

    .line 4
    .line 5
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 6
    .line 7
    add-int v2, v0, v1

    .line 8
    .line 9
    add-int/2addr v2, p1

    .line 10
    iget v3, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->currentLimit:I

    .line 11
    .line 12
    if-gt v2, v3, :cond_1

    .line 13
    .line 14
    iget v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    .line 15
    .line 16
    sub-int v1, v0, v1

    .line 17
    .line 18
    iput v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 19
    .line 20
    const/4 v0, 0x1

    .line 21
    invoke-direct {p0, v0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->refillBuffer(I)V

    .line 22
    .line 23
    .line 24
    :goto_0
    sub-int v2, p1, v1

    .line 25
    .line 26
    iget v3, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    .line 27
    .line 28
    if-le v2, v3, :cond_0

    .line 29
    .line 30
    add-int/2addr v1, v3

    .line 31
    iput v3, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 32
    .line 33
    invoke-direct {p0, v0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->refillBuffer(I)V

    .line 34
    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    iput v2, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 38
    .line 39
    return-void

    .line 40
    :cond_1
    sub-int/2addr v3, v0

    .line 41
    sub-int/2addr v3, v1

    .line 42
    invoke-virtual {p0, v3}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->skipRawBytes(I)V

    .line 43
    .line 44
    .line 45
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;->truncatedMessage()Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;->negativeSize()Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    throw p0
.end method

.method private tryRefillBuffer(I)Z
    .locals 5

    .line 1
    iget v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 2
    .line 3
    add-int v1, v0, p1

    .line 4
    .line 5
    iget v2, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    .line 6
    .line 7
    if-le v1, v2, :cond_8

    .line 8
    .line 9
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->totalBytesRetired:I

    .line 10
    .line 11
    add-int/2addr v1, v0

    .line 12
    add-int/2addr v1, p1

    .line 13
    iget v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->currentLimit:I

    .line 14
    .line 15
    const/4 v2, 0x0

    .line 16
    if-le v1, v0, :cond_0

    .line 17
    .line 18
    return v2

    .line 19
    :cond_0
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->refillCallback:Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream$RefillCallback;

    .line 20
    .line 21
    if-eqz v0, :cond_1

    .line 22
    .line 23
    invoke-interface {v0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream$RefillCallback;->onRefill()V

    .line 24
    .line 25
    .line 26
    :cond_1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->input:Ljava/io/InputStream;

    .line 27
    .line 28
    if-eqz v0, :cond_7

    .line 29
    .line 30
    iget v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 31
    .line 32
    if-lez v0, :cond_3

    .line 33
    .line 34
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    .line 35
    .line 36
    if-le v1, v0, :cond_2

    .line 37
    .line 38
    iget-object v3, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->buffer:[B

    .line 39
    .line 40
    sub-int/2addr v1, v0

    .line 41
    invoke-static {v3, v0, v3, v2, v1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 42
    .line 43
    .line 44
    :cond_2
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->totalBytesRetired:I

    .line 45
    .line 46
    add-int/2addr v1, v0

    .line 47
    iput v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->totalBytesRetired:I

    .line 48
    .line 49
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    .line 50
    .line 51
    sub-int/2addr v1, v0

    .line 52
    iput v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    .line 53
    .line 54
    iput v2, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 55
    .line 56
    :cond_3
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->input:Ljava/io/InputStream;

    .line 57
    .line 58
    iget-object v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->buffer:[B

    .line 59
    .line 60
    iget v3, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    .line 61
    .line 62
    array-length v4, v1

    .line 63
    sub-int/2addr v4, v3

    .line 64
    invoke-virtual {v0, v1, v3, v4}, Ljava/io/InputStream;->read([BII)I

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    if-eqz v0, :cond_6

    .line 69
    .line 70
    const/4 v1, -0x1

    .line 71
    if-lt v0, v1, :cond_6

    .line 72
    .line 73
    iget-object v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->buffer:[B

    .line 74
    .line 75
    array-length v1, v1

    .line 76
    if-gt v0, v1, :cond_6

    .line 77
    .line 78
    if-lez v0, :cond_7

    .line 79
    .line 80
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    .line 81
    .line 82
    add-int/2addr v1, v0

    .line 83
    iput v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    .line 84
    .line 85
    iget v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->totalBytesRetired:I

    .line 86
    .line 87
    add-int/2addr v0, p1

    .line 88
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->sizeLimit:I

    .line 89
    .line 90
    sub-int/2addr v0, v1

    .line 91
    if-gtz v0, :cond_5

    .line 92
    .line 93
    invoke-direct {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->recomputeBufferSizeAfterLimit()V

    .line 94
    .line 95
    .line 96
    iget v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    .line 97
    .line 98
    if-lt v0, p1, :cond_4

    .line 99
    .line 100
    const/4 p0, 0x1

    .line 101
    return p0

    .line 102
    :cond_4
    invoke-direct {p0, p1}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->tryRefillBuffer(I)Z

    .line 103
    .line 104
    .line 105
    move-result p0

    .line 106
    return p0

    .line 107
    :cond_5
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;->sizeLimitExceeded()Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    throw p0

    .line 112
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 113
    .line 114
    new-instance p1, Ljava/lang/StringBuilder;

    .line 115
    .line 116
    const/16 v1, 0x66

    .line 117
    .line 118
    invoke-direct {p1, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 119
    .line 120
    .line 121
    const-string v1, "InputStream#read(byte[]) returned invalid result: "

    .line 122
    .line 123
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 124
    .line 125
    .line 126
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 127
    .line 128
    .line 129
    const-string v0, "\nThe InputStream implementation is buggy."

    .line 130
    .line 131
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 132
    .line 133
    .line 134
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object p1

    .line 138
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    throw p0

    .line 142
    :cond_7
    return v2

    .line 143
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 144
    .line 145
    new-instance v0, Ljava/lang/StringBuilder;

    .line 146
    .line 147
    const/16 v1, 0x4d

    .line 148
    .line 149
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 150
    .line 151
    .line 152
    const-string v1, "refillBuffer() called when "

    .line 153
    .line 154
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 155
    .line 156
    .line 157
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 158
    .line 159
    .line 160
    const-string p1, " bytes were already available in buffer"

    .line 161
    .line 162
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 163
    .line 164
    .line 165
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 166
    .line 167
    .line 168
    move-result-object p1

    .line 169
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 170
    .line 171
    .line 172
    throw p0
.end method


# virtual methods
.method public checkLastTagWas(I)V
    .locals 0

    .line 1
    iget p0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->lastTag:I

    .line 2
    .line 3
    if-ne p0, p1, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;->invalidEndTag()Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    throw p0
.end method

.method public getBytesUntilLimit()I
    .locals 2

    .line 1
    iget v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->currentLimit:I

    .line 2
    .line 3
    const v1, 0x7fffffff

    .line 4
    .line 5
    .line 6
    if-ne v0, v1, :cond_0

    .line 7
    .line 8
    const/4 p0, -0x1

    .line 9
    return p0

    .line 10
    :cond_0
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->totalBytesRetired:I

    .line 11
    .line 12
    iget p0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 13
    .line 14
    add-int/2addr v1, p0

    .line 15
    sub-int/2addr v0, v1

    .line 16
    return v0
.end method

.method public isAtEnd()Z
    .locals 2

    .line 1
    iget v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 2
    .line 3
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    .line 4
    .line 5
    if-ne v0, v1, :cond_0

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    invoke-direct {p0, v0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->tryRefillBuffer(I)Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    if-nez p0, :cond_0

    .line 13
    .line 14
    return v0

    .line 15
    :cond_0
    const/4 p0, 0x0

    .line 16
    return p0
.end method

.method public popLimit(I)V
    .locals 0

    .line 1
    iput p1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->currentLimit:I

    .line 2
    .line 3
    invoke-direct {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->recomputeBufferSizeAfterLimit()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public pushLimit(I)I
    .locals 2

    .line 1
    if-ltz p1, :cond_1

    .line 2
    .line 3
    iget v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->totalBytesRetired:I

    .line 4
    .line 5
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 6
    .line 7
    add-int/2addr v0, v1

    .line 8
    add-int/2addr v0, p1

    .line 9
    iget p1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->currentLimit:I

    .line 10
    .line 11
    if-gt v0, p1, :cond_0

    .line 12
    .line 13
    iput v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->currentLimit:I

    .line 14
    .line 15
    invoke-direct {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->recomputeBufferSizeAfterLimit()V

    .line 16
    .line 17
    .line 18
    return p1

    .line 19
    :cond_0
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;->truncatedMessage()Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    throw p0

    .line 24
    :cond_1
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;->negativeSize()Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    throw p0
.end method

.method public readBool()Z
    .locals 4

    .line 1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readRawVarint64()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    const-wide/16 v2, 0x0

    .line 6
    .line 7
    cmp-long p0, v0, v2

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public readBytes()Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;
    .locals 4

    .line 1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readRawVarint32()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    .line 6
    .line 7
    iget v2, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 8
    .line 9
    sub-int/2addr v1, v2

    .line 10
    if-gt v0, v1, :cond_1

    .line 11
    .line 12
    if-lez v0, :cond_1

    .line 13
    .line 14
    iget-boolean v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferIsImmutable:Z

    .line 15
    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    iget-boolean v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->enableAliasing:Z

    .line 19
    .line 20
    if-eqz v1, :cond_0

    .line 21
    .line 22
    new-instance v1, Lkotlin/reflect/jvm/internal/impl/protobuf/BoundedByteString;

    .line 23
    .line 24
    iget-object v2, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->buffer:[B

    .line 25
    .line 26
    iget v3, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 27
    .line 28
    invoke-direct {v1, v2, v3, v0}, Lkotlin/reflect/jvm/internal/impl/protobuf/BoundedByteString;-><init>([BII)V

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    iget-object v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->buffer:[B

    .line 33
    .line 34
    invoke-static {v1, v2, v0}, Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;->copyFrom([BII)Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    :goto_0
    iget v2, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 39
    .line 40
    add-int/2addr v2, v0

    .line 41
    iput v2, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 42
    .line 43
    return-object v1

    .line 44
    :cond_1
    if-nez v0, :cond_2

    .line 45
    .line 46
    sget-object p0, Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;->EMPTY:Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;

    .line 47
    .line 48
    return-object p0

    .line 49
    :cond_2
    new-instance v1, Lkotlin/reflect/jvm/internal/impl/protobuf/LiteralByteString;

    .line 50
    .line 51
    invoke-direct {p0, v0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readRawBytesSlowPath(I)[B

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    invoke-direct {v1, p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/LiteralByteString;-><init>([B)V

    .line 56
    .line 57
    .line 58
    return-object v1
.end method

.method public readDouble()D
    .locals 2

    .line 1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readRawLittleEndian64()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Ljava/lang/Double;->longBitsToDouble(J)D

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    return-wide v0
.end method

.method public readEnum()I
    .locals 0

    .line 1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readRawVarint32()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public readFixed32()I
    .locals 0

    .line 1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readRawLittleEndian32()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public readFixed64()J
    .locals 2

    .line 1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readRawLittleEndian64()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public readFloat()F
    .locals 0

    .line 1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readRawLittleEndian32()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public readGroup(ILkotlin/reflect/jvm/internal/impl/protobuf/MessageLite$Builder;Lkotlin/reflect/jvm/internal/impl/protobuf/ExtensionRegistryLite;)V
    .locals 2

    .line 1
    iget v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->recursionDepth:I

    .line 2
    .line 3
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->recursionLimit:I

    .line 4
    .line 5
    if-ge v0, v1, :cond_0

    .line 6
    .line 7
    add-int/lit8 v0, v0, 0x1

    .line 8
    .line 9
    iput v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->recursionDepth:I

    .line 10
    .line 11
    invoke-interface {p2, p0, p3}, Lkotlin/reflect/jvm/internal/impl/protobuf/MessageLite$Builder;->mergeFrom(Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;Lkotlin/reflect/jvm/internal/impl/protobuf/ExtensionRegistryLite;)Lkotlin/reflect/jvm/internal/impl/protobuf/MessageLite$Builder;

    .line 12
    .line 13
    .line 14
    const/4 p2, 0x4

    .line 15
    invoke-static {p1, p2}, Lkotlin/reflect/jvm/internal/impl/protobuf/WireFormat;->makeTag(II)I

    .line 16
    .line 17
    .line 18
    move-result p1

    .line 19
    invoke-virtual {p0, p1}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->checkLastTagWas(I)V

    .line 20
    .line 21
    .line 22
    iget p1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->recursionDepth:I

    .line 23
    .line 24
    add-int/lit8 p1, p1, -0x1

    .line 25
    .line 26
    iput p1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->recursionDepth:I

    .line 27
    .line 28
    return-void

    .line 29
    :cond_0
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;->recursionLimitExceeded()Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    throw p0
.end method

.method public readInt32()I
    .locals 0

    .line 1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readRawVarint32()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public readInt64()J
    .locals 2

    .line 1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readRawVarint64()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public readMessage(Lkotlin/reflect/jvm/internal/impl/protobuf/Parser;Lkotlin/reflect/jvm/internal/impl/protobuf/ExtensionRegistryLite;)Lkotlin/reflect/jvm/internal/impl/protobuf/MessageLite;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T::",
            "Lkotlin/reflect/jvm/internal/impl/protobuf/MessageLite;",
            ">(",
            "Lkotlin/reflect/jvm/internal/impl/protobuf/Parser<",
            "TT;>;",
            "Lkotlin/reflect/jvm/internal/impl/protobuf/ExtensionRegistryLite;",
            ")TT;"
        }
    .end annotation

    .line 10
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readRawVarint32()I

    move-result v0

    .line 11
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->recursionDepth:I

    iget v2, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->recursionLimit:I

    if-ge v1, v2, :cond_0

    .line 12
    invoke-virtual {p0, v0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->pushLimit(I)I

    move-result v0

    .line 13
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->recursionDepth:I

    add-int/lit8 v1, v1, 0x1

    iput v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->recursionDepth:I

    .line 14
    invoke-interface {p1, p0, p2}, Lkotlin/reflect/jvm/internal/impl/protobuf/Parser;->parsePartialFrom(Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;Lkotlin/reflect/jvm/internal/impl/protobuf/ExtensionRegistryLite;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lkotlin/reflect/jvm/internal/impl/protobuf/MessageLite;

    const/4 p2, 0x0

    .line 15
    invoke-virtual {p0, p2}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->checkLastTagWas(I)V

    .line 16
    iget p2, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->recursionDepth:I

    add-int/lit8 p2, p2, -0x1

    iput p2, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->recursionDepth:I

    .line 17
    invoke-virtual {p0, v0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->popLimit(I)V

    return-object p1

    .line 18
    :cond_0
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;->recursionLimitExceeded()Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;

    move-result-object p0

    throw p0
.end method

.method public readMessage(Lkotlin/reflect/jvm/internal/impl/protobuf/MessageLite$Builder;Lkotlin/reflect/jvm/internal/impl/protobuf/ExtensionRegistryLite;)V
    .locals 3

    .line 1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readRawVarint32()I

    move-result v0

    .line 2
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->recursionDepth:I

    iget v2, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->recursionLimit:I

    if-ge v1, v2, :cond_0

    .line 3
    invoke-virtual {p0, v0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->pushLimit(I)I

    move-result v0

    .line 4
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->recursionDepth:I

    add-int/lit8 v1, v1, 0x1

    iput v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->recursionDepth:I

    .line 5
    invoke-interface {p1, p0, p2}, Lkotlin/reflect/jvm/internal/impl/protobuf/MessageLite$Builder;->mergeFrom(Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;Lkotlin/reflect/jvm/internal/impl/protobuf/ExtensionRegistryLite;)Lkotlin/reflect/jvm/internal/impl/protobuf/MessageLite$Builder;

    const/4 p1, 0x0

    .line 6
    invoke-virtual {p0, p1}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->checkLastTagWas(I)V

    .line 7
    iget p1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->recursionDepth:I

    add-int/lit8 p1, p1, -0x1

    iput p1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->recursionDepth:I

    .line 8
    invoke-virtual {p0, v0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->popLimit(I)V

    return-void

    .line 9
    :cond_0
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;->recursionLimitExceeded()Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;

    move-result-object p0

    throw p0
.end method

.method public readRawByte()B
    .locals 3

    .line 1
    iget v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 2
    .line 3
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    .line 4
    .line 5
    if-ne v0, v1, :cond_0

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    invoke-direct {p0, v0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->refillBuffer(I)V

    .line 9
    .line 10
    .line 11
    :cond_0
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->buffer:[B

    .line 12
    .line 13
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 14
    .line 15
    add-int/lit8 v2, v1, 0x1

    .line 16
    .line 17
    iput v2, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 18
    .line 19
    aget-byte p0, v0, v1

    .line 20
    .line 21
    return p0
.end method

.method public readRawLittleEndian32()I
    .locals 3

    .line 1
    iget v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 2
    .line 3
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    .line 4
    .line 5
    sub-int/2addr v1, v0

    .line 6
    const/4 v2, 0x4

    .line 7
    if-ge v1, v2, :cond_0

    .line 8
    .line 9
    invoke-direct {p0, v2}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->refillBuffer(I)V

    .line 10
    .line 11
    .line 12
    iget v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 13
    .line 14
    :cond_0
    iget-object v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->buffer:[B

    .line 15
    .line 16
    add-int/lit8 v2, v0, 0x4

    .line 17
    .line 18
    iput v2, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 19
    .line 20
    aget-byte p0, v1, v0

    .line 21
    .line 22
    and-int/lit16 p0, p0, 0xff

    .line 23
    .line 24
    add-int/lit8 v2, v0, 0x1

    .line 25
    .line 26
    aget-byte v2, v1, v2

    .line 27
    .line 28
    and-int/lit16 v2, v2, 0xff

    .line 29
    .line 30
    shl-int/lit8 v2, v2, 0x8

    .line 31
    .line 32
    or-int/2addr p0, v2

    .line 33
    add-int/lit8 v2, v0, 0x2

    .line 34
    .line 35
    aget-byte v2, v1, v2

    .line 36
    .line 37
    and-int/lit16 v2, v2, 0xff

    .line 38
    .line 39
    shl-int/lit8 v2, v2, 0x10

    .line 40
    .line 41
    or-int/2addr p0, v2

    .line 42
    add-int/lit8 v0, v0, 0x3

    .line 43
    .line 44
    aget-byte v0, v1, v0

    .line 45
    .line 46
    and-int/lit16 v0, v0, 0xff

    .line 47
    .line 48
    shl-int/lit8 v0, v0, 0x18

    .line 49
    .line 50
    or-int/2addr p0, v0

    .line 51
    return p0
.end method

.method public readRawLittleEndian64()J
    .locals 9

    .line 1
    iget v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 2
    .line 3
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    .line 4
    .line 5
    sub-int/2addr v1, v0

    .line 6
    const/16 v2, 0x8

    .line 7
    .line 8
    if-ge v1, v2, :cond_0

    .line 9
    .line 10
    invoke-direct {p0, v2}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->refillBuffer(I)V

    .line 11
    .line 12
    .line 13
    iget v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 14
    .line 15
    :cond_0
    iget-object v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->buffer:[B

    .line 16
    .line 17
    add-int/lit8 v3, v0, 0x8

    .line 18
    .line 19
    iput v3, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 20
    .line 21
    aget-byte p0, v1, v0

    .line 22
    .line 23
    int-to-long v3, p0

    .line 24
    const-wide/16 v5, 0xff

    .line 25
    .line 26
    and-long/2addr v3, v5

    .line 27
    add-int/lit8 p0, v0, 0x1

    .line 28
    .line 29
    aget-byte p0, v1, p0

    .line 30
    .line 31
    int-to-long v7, p0

    .line 32
    and-long/2addr v7, v5

    .line 33
    shl-long/2addr v7, v2

    .line 34
    or-long v2, v3, v7

    .line 35
    .line 36
    add-int/lit8 p0, v0, 0x2

    .line 37
    .line 38
    aget-byte p0, v1, p0

    .line 39
    .line 40
    int-to-long v7, p0

    .line 41
    and-long/2addr v7, v5

    .line 42
    const/16 p0, 0x10

    .line 43
    .line 44
    shl-long/2addr v7, p0

    .line 45
    or-long/2addr v2, v7

    .line 46
    add-int/lit8 p0, v0, 0x3

    .line 47
    .line 48
    aget-byte p0, v1, p0

    .line 49
    .line 50
    int-to-long v7, p0

    .line 51
    and-long/2addr v7, v5

    .line 52
    const/16 p0, 0x18

    .line 53
    .line 54
    shl-long/2addr v7, p0

    .line 55
    or-long/2addr v2, v7

    .line 56
    add-int/lit8 p0, v0, 0x4

    .line 57
    .line 58
    aget-byte p0, v1, p0

    .line 59
    .line 60
    int-to-long v7, p0

    .line 61
    and-long/2addr v7, v5

    .line 62
    const/16 p0, 0x20

    .line 63
    .line 64
    shl-long/2addr v7, p0

    .line 65
    or-long/2addr v2, v7

    .line 66
    add-int/lit8 p0, v0, 0x5

    .line 67
    .line 68
    aget-byte p0, v1, p0

    .line 69
    .line 70
    int-to-long v7, p0

    .line 71
    and-long/2addr v7, v5

    .line 72
    const/16 p0, 0x28

    .line 73
    .line 74
    shl-long/2addr v7, p0

    .line 75
    or-long/2addr v2, v7

    .line 76
    add-int/lit8 p0, v0, 0x6

    .line 77
    .line 78
    aget-byte p0, v1, p0

    .line 79
    .line 80
    int-to-long v7, p0

    .line 81
    and-long/2addr v7, v5

    .line 82
    const/16 p0, 0x30

    .line 83
    .line 84
    shl-long/2addr v7, p0

    .line 85
    or-long/2addr v2, v7

    .line 86
    add-int/lit8 v0, v0, 0x7

    .line 87
    .line 88
    aget-byte p0, v1, v0

    .line 89
    .line 90
    int-to-long v0, p0

    .line 91
    and-long/2addr v0, v5

    .line 92
    const/16 p0, 0x38

    .line 93
    .line 94
    shl-long/2addr v0, p0

    .line 95
    or-long/2addr v0, v2

    .line 96
    return-wide v0
.end method

.method public readRawVarint32()I
    .locals 11

    .line 1
    iget v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 2
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    if-ne v1, v0, :cond_0

    goto/16 :goto_2

    .line 3
    :cond_0
    iget-object v2, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->buffer:[B

    add-int/lit8 v3, v0, 0x1

    .line 4
    aget-byte v4, v2, v0

    if-ltz v4, :cond_1

    .line 5
    iput v3, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    return v4

    :cond_1
    sub-int/2addr v1, v3

    const/16 v5, 0x9

    if-ge v1, v5, :cond_2

    goto :goto_2

    :cond_2
    add-int/lit8 v1, v0, 0x2

    .line 6
    aget-byte v3, v2, v3

    shl-int/lit8 v3, v3, 0x7

    xor-int/2addr v3, v4

    int-to-long v4, v3

    const-wide/16 v6, 0x0

    cmp-long v8, v4, v6

    if-gez v8, :cond_3

    const-wide/16 v2, -0x80

    xor-long/2addr v2, v4

    long-to-int v0, v2

    goto/16 :goto_3

    :cond_3
    add-int/lit8 v4, v0, 0x3

    .line 7
    aget-byte v1, v2, v1

    shl-int/lit8 v1, v1, 0xe

    xor-int/2addr v1, v3

    int-to-long v8, v1

    cmp-long v3, v8, v6

    if-ltz v3, :cond_4

    const-wide/16 v0, 0x3f80

    xor-long/2addr v0, v8

    long-to-int v0, v0

    :goto_0
    move v1, v4

    goto :goto_3

    :cond_4
    add-int/lit8 v3, v0, 0x4

    .line 8
    aget-byte v4, v2, v4

    shl-int/lit8 v4, v4, 0x15

    xor-int/2addr v1, v4

    int-to-long v4, v1

    cmp-long v6, v4, v6

    if-gez v6, :cond_5

    const-wide/32 v0, -0x1fc080

    xor-long/2addr v0, v4

    long-to-int v0, v0

    :goto_1
    move v1, v3

    goto :goto_3

    :cond_5
    add-int/lit8 v4, v0, 0x5

    .line 9
    aget-byte v3, v2, v3

    shl-int/lit8 v5, v3, 0x1c

    xor-int/2addr v1, v5

    int-to-long v5, v1

    const-wide/32 v7, 0xfe03f80

    xor-long/2addr v5, v7

    long-to-int v1, v5

    if-gez v3, :cond_7

    add-int/lit8 v3, v0, 0x6

    .line 10
    aget-byte v4, v2, v4

    if-gez v4, :cond_8

    add-int/lit8 v4, v0, 0x7

    aget-byte v3, v2, v3

    if-gez v3, :cond_7

    add-int/lit8 v3, v0, 0x8

    aget-byte v4, v2, v4

    if-gez v4, :cond_8

    add-int/lit8 v4, v0, 0x9

    aget-byte v3, v2, v3

    if-gez v3, :cond_7

    add-int/lit8 v0, v0, 0xa

    aget-byte v2, v2, v4

    if-gez v2, :cond_6

    .line 11
    :goto_2
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readRawVarint64SlowPath()J

    move-result-wide v0

    long-to-int p0, v0

    return p0

    :cond_6
    move v10, v1

    move v1, v0

    move v0, v10

    goto :goto_3

    :cond_7
    move v0, v1

    goto :goto_0

    :cond_8
    move v0, v1

    goto :goto_1

    .line 12
    :goto_3
    iput v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    return v0
.end method

.method public readRawVarint64()J
    .locals 10

    .line 1
    iget v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 2
    .line 3
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    .line 4
    .line 5
    if-ne v1, v0, :cond_0

    .line 6
    .line 7
    goto/16 :goto_3

    .line 8
    .line 9
    :cond_0
    iget-object v2, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->buffer:[B

    .line 10
    .line 11
    add-int/lit8 v3, v0, 0x1

    .line 12
    .line 13
    aget-byte v4, v2, v0

    .line 14
    .line 15
    if-ltz v4, :cond_1

    .line 16
    .line 17
    iput v3, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 18
    .line 19
    int-to-long v0, v4

    .line 20
    return-wide v0

    .line 21
    :cond_1
    sub-int/2addr v1, v3

    .line 22
    const/16 v5, 0x9

    .line 23
    .line 24
    if-ge v1, v5, :cond_2

    .line 25
    .line 26
    goto/16 :goto_3

    .line 27
    .line 28
    :cond_2
    add-int/lit8 v1, v0, 0x2

    .line 29
    .line 30
    aget-byte v3, v2, v3

    .line 31
    .line 32
    shl-int/lit8 v3, v3, 0x7

    .line 33
    .line 34
    xor-int/2addr v3, v4

    .line 35
    int-to-long v3, v3

    .line 36
    const-wide/16 v5, 0x0

    .line 37
    .line 38
    cmp-long v7, v3, v5

    .line 39
    .line 40
    if-gez v7, :cond_3

    .line 41
    .line 42
    const-wide/16 v5, -0x80

    .line 43
    .line 44
    :goto_0
    xor-long v2, v3, v5

    .line 45
    .line 46
    goto/16 :goto_4

    .line 47
    .line 48
    :cond_3
    add-int/lit8 v7, v0, 0x3

    .line 49
    .line 50
    aget-byte v1, v2, v1

    .line 51
    .line 52
    shl-int/lit8 v1, v1, 0xe

    .line 53
    .line 54
    int-to-long v8, v1

    .line 55
    xor-long/2addr v3, v8

    .line 56
    cmp-long v1, v3, v5

    .line 57
    .line 58
    if-ltz v1, :cond_4

    .line 59
    .line 60
    const-wide/16 v0, 0x3f80

    .line 61
    .line 62
    :goto_1
    xor-long v2, v3, v0

    .line 63
    .line 64
    :goto_2
    move v1, v7

    .line 65
    goto/16 :goto_4

    .line 66
    .line 67
    :cond_4
    add-int/lit8 v1, v0, 0x4

    .line 68
    .line 69
    aget-byte v7, v2, v7

    .line 70
    .line 71
    shl-int/lit8 v7, v7, 0x15

    .line 72
    .line 73
    int-to-long v7, v7

    .line 74
    xor-long/2addr v3, v7

    .line 75
    cmp-long v7, v3, v5

    .line 76
    .line 77
    if-gez v7, :cond_5

    .line 78
    .line 79
    const-wide/32 v5, -0x1fc080

    .line 80
    .line 81
    .line 82
    goto :goto_0

    .line 83
    :cond_5
    add-int/lit8 v7, v0, 0x5

    .line 84
    .line 85
    aget-byte v1, v2, v1

    .line 86
    .line 87
    int-to-long v8, v1

    .line 88
    const/16 v1, 0x1c

    .line 89
    .line 90
    shl-long/2addr v8, v1

    .line 91
    xor-long/2addr v3, v8

    .line 92
    cmp-long v1, v3, v5

    .line 93
    .line 94
    if-ltz v1, :cond_6

    .line 95
    .line 96
    const-wide/32 v0, 0xfe03f80

    .line 97
    .line 98
    .line 99
    goto :goto_1

    .line 100
    :cond_6
    add-int/lit8 v1, v0, 0x6

    .line 101
    .line 102
    aget-byte v7, v2, v7

    .line 103
    .line 104
    int-to-long v7, v7

    .line 105
    const/16 v9, 0x23

    .line 106
    .line 107
    shl-long/2addr v7, v9

    .line 108
    xor-long/2addr v3, v7

    .line 109
    cmp-long v7, v3, v5

    .line 110
    .line 111
    if-gez v7, :cond_7

    .line 112
    .line 113
    const-wide v5, -0x7f01fc080L

    .line 114
    .line 115
    .line 116
    .line 117
    .line 118
    goto :goto_0

    .line 119
    :cond_7
    add-int/lit8 v7, v0, 0x7

    .line 120
    .line 121
    aget-byte v1, v2, v1

    .line 122
    .line 123
    int-to-long v8, v1

    .line 124
    const/16 v1, 0x2a

    .line 125
    .line 126
    shl-long/2addr v8, v1

    .line 127
    xor-long/2addr v3, v8

    .line 128
    cmp-long v1, v3, v5

    .line 129
    .line 130
    if-ltz v1, :cond_8

    .line 131
    .line 132
    const-wide v0, 0x3f80fe03f80L

    .line 133
    .line 134
    .line 135
    .line 136
    .line 137
    goto :goto_1

    .line 138
    :cond_8
    add-int/lit8 v1, v0, 0x8

    .line 139
    .line 140
    aget-byte v7, v2, v7

    .line 141
    .line 142
    int-to-long v7, v7

    .line 143
    const/16 v9, 0x31

    .line 144
    .line 145
    shl-long/2addr v7, v9

    .line 146
    xor-long/2addr v3, v7

    .line 147
    cmp-long v7, v3, v5

    .line 148
    .line 149
    if-gez v7, :cond_9

    .line 150
    .line 151
    const-wide v5, -0x1fc07f01fc080L

    .line 152
    .line 153
    .line 154
    .line 155
    .line 156
    goto :goto_0

    .line 157
    :cond_9
    add-int/lit8 v7, v0, 0x9

    .line 158
    .line 159
    aget-byte v1, v2, v1

    .line 160
    .line 161
    int-to-long v8, v1

    .line 162
    const/16 v1, 0x38

    .line 163
    .line 164
    shl-long/2addr v8, v1

    .line 165
    xor-long/2addr v3, v8

    .line 166
    const-wide v8, 0xfe03f80fe03f80L

    .line 167
    .line 168
    .line 169
    .line 170
    .line 171
    xor-long/2addr v3, v8

    .line 172
    cmp-long v1, v3, v5

    .line 173
    .line 174
    if-gez v1, :cond_b

    .line 175
    .line 176
    add-int/lit8 v1, v0, 0xa

    .line 177
    .line 178
    aget-byte v0, v2, v7

    .line 179
    .line 180
    int-to-long v7, v0

    .line 181
    cmp-long v0, v7, v5

    .line 182
    .line 183
    if-gez v0, :cond_a

    .line 184
    .line 185
    :goto_3
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readRawVarint64SlowPath()J

    .line 186
    .line 187
    .line 188
    move-result-wide v0

    .line 189
    return-wide v0

    .line 190
    :cond_a
    move-wide v2, v3

    .line 191
    goto :goto_4

    .line 192
    :cond_b
    move-wide v2, v3

    .line 193
    goto/16 :goto_2

    .line 194
    .line 195
    :goto_4
    iput v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 196
    .line 197
    return-wide v2
.end method

.method public readRawVarint64SlowPath()J
    .locals 6

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    const/4 v2, 0x0

    .line 4
    :goto_0
    const/16 v3, 0x40

    .line 5
    .line 6
    if-ge v2, v3, :cond_1

    .line 7
    .line 8
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readRawByte()B

    .line 9
    .line 10
    .line 11
    move-result v3

    .line 12
    and-int/lit8 v4, v3, 0x7f

    .line 13
    .line 14
    int-to-long v4, v4

    .line 15
    shl-long/2addr v4, v2

    .line 16
    or-long/2addr v0, v4

    .line 17
    and-int/lit16 v3, v3, 0x80

    .line 18
    .line 19
    if-nez v3, :cond_0

    .line 20
    .line 21
    return-wide v0

    .line 22
    :cond_0
    add-int/lit8 v2, v2, 0x7

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;->malformedVarint()Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    throw p0
.end method

.method public readSFixed32()I
    .locals 0

    .line 1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readRawLittleEndian32()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public readSFixed64()J
    .locals 2

    .line 1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readRawLittleEndian64()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public readSInt32()I
    .locals 0

    .line 1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readRawVarint32()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->decodeZigZag32(I)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public readSInt64()J
    .locals 2

    .line 1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readRawVarint64()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->decodeZigZag64(J)J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    return-wide v0
.end method

.method public readString()Ljava/lang/String;
    .locals 5

    .line 1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readRawVarint32()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    .line 6
    .line 7
    iget v2, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 8
    .line 9
    sub-int/2addr v1, v2

    .line 10
    const-string v3, "UTF-8"

    .line 11
    .line 12
    if-gt v0, v1, :cond_0

    .line 13
    .line 14
    if-lez v0, :cond_0

    .line 15
    .line 16
    new-instance v1, Ljava/lang/String;

    .line 17
    .line 18
    iget-object v4, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->buffer:[B

    .line 19
    .line 20
    invoke-direct {v1, v4, v2, v0, v3}, Ljava/lang/String;-><init>([BIILjava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iget v2, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 24
    .line 25
    add-int/2addr v2, v0

    .line 26
    iput v2, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 27
    .line 28
    return-object v1

    .line 29
    :cond_0
    if-nez v0, :cond_1

    .line 30
    .line 31
    const-string p0, ""

    .line 32
    .line 33
    return-object p0

    .line 34
    :cond_1
    new-instance v1, Ljava/lang/String;

    .line 35
    .line 36
    invoke-direct {p0, v0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readRawBytesSlowPath(I)[B

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    invoke-direct {v1, p0, v3}, Ljava/lang/String;-><init>([BLjava/lang/String;)V

    .line 41
    .line 42
    .line 43
    return-object v1
.end method

.method public readStringRequireUtf8()Ljava/lang/String;
    .locals 4

    .line 1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readRawVarint32()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 6
    .line 7
    iget v2, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    .line 8
    .line 9
    sub-int/2addr v2, v1

    .line 10
    if-gt v0, v2, :cond_0

    .line 11
    .line 12
    if-lez v0, :cond_0

    .line 13
    .line 14
    iget-object v2, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->buffer:[B

    .line 15
    .line 16
    add-int v3, v1, v0

    .line 17
    .line 18
    iput v3, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    if-nez v0, :cond_1

    .line 22
    .line 23
    const-string p0, ""

    .line 24
    .line 25
    return-object p0

    .line 26
    :cond_1
    invoke-direct {p0, v0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readRawBytesSlowPath(I)[B

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    const/4 v1, 0x0

    .line 31
    :goto_0
    add-int p0, v1, v0

    .line 32
    .line 33
    invoke-static {v2, v1, p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/Utf8;->isValidUtf8([BII)Z

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    if-eqz p0, :cond_2

    .line 38
    .line 39
    new-instance p0, Ljava/lang/String;

    .line 40
    .line 41
    const-string v3, "UTF-8"

    .line 42
    .line 43
    invoke-direct {p0, v2, v1, v0, v3}, Ljava/lang/String;-><init>([BIILjava/lang/String;)V

    .line 44
    .line 45
    .line 46
    return-object p0

    .line 47
    :cond_2
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;->invalidUtf8()Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    throw p0
.end method

.method public readTag()I
    .locals 1

    .line 1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->isAtEnd()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    iput v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->lastTag:I

    .line 9
    .line 10
    return v0

    .line 11
    :cond_0
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readRawVarint32()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    iput v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->lastTag:I

    .line 16
    .line 17
    invoke-static {v0}, Lkotlin/reflect/jvm/internal/impl/protobuf/WireFormat;->getTagFieldNumber(I)I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-eqz v0, :cond_1

    .line 22
    .line 23
    iget p0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->lastTag:I

    .line 24
    .line 25
    return p0

    .line 26
    :cond_1
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;->invalidTag()Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    throw p0
.end method

.method public readUInt32()I
    .locals 0

    .line 1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readRawVarint32()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public readUInt64()J
    .locals 2

    .line 1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readRawVarint64()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public skipField(ILkotlin/reflect/jvm/internal/impl/protobuf/CodedOutputStream;)Z
    .locals 4

    .line 1
    invoke-static {p1}, Lkotlin/reflect/jvm/internal/impl/protobuf/WireFormat;->getTagWireType(I)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x1

    .line 6
    if-eqz v0, :cond_5

    .line 7
    .line 8
    if-eq v0, v1, :cond_4

    .line 9
    .line 10
    const/4 v2, 0x2

    .line 11
    if-eq v0, v2, :cond_3

    .line 12
    .line 13
    const/4 v2, 0x3

    .line 14
    const/4 v3, 0x4

    .line 15
    if-eq v0, v2, :cond_2

    .line 16
    .line 17
    if-eq v0, v3, :cond_1

    .line 18
    .line 19
    const/4 v2, 0x5

    .line 20
    if-ne v0, v2, :cond_0

    .line 21
    .line 22
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readRawLittleEndian32()I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    invoke-virtual {p2, p1}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedOutputStream;->writeRawVarint32(I)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {p2, p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedOutputStream;->writeFixed32NoTag(I)V

    .line 30
    .line 31
    .line 32
    return v1

    .line 33
    :cond_0
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;->invalidWireType()Lkotlin/reflect/jvm/internal/impl/protobuf/InvalidProtocolBufferException;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    throw p0

    .line 38
    :cond_1
    const/4 p0, 0x0

    .line 39
    return p0

    .line 40
    :cond_2
    invoke-virtual {p2, p1}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedOutputStream;->writeRawVarint32(I)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p0, p2}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->skipMessage(Lkotlin/reflect/jvm/internal/impl/protobuf/CodedOutputStream;)V

    .line 44
    .line 45
    .line 46
    invoke-static {p1}, Lkotlin/reflect/jvm/internal/impl/protobuf/WireFormat;->getTagFieldNumber(I)I

    .line 47
    .line 48
    .line 49
    move-result p1

    .line 50
    invoke-static {p1, v3}, Lkotlin/reflect/jvm/internal/impl/protobuf/WireFormat;->makeTag(II)I

    .line 51
    .line 52
    .line 53
    move-result p1

    .line 54
    invoke-virtual {p0, p1}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->checkLastTagWas(I)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {p2, p1}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedOutputStream;->writeRawVarint32(I)V

    .line 58
    .line 59
    .line 60
    return v1

    .line 61
    :cond_3
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readBytes()Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    invoke-virtual {p2, p1}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedOutputStream;->writeRawVarint32(I)V

    .line 66
    .line 67
    .line 68
    invoke-virtual {p2, p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedOutputStream;->writeBytesNoTag(Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;)V

    .line 69
    .line 70
    .line 71
    return v1

    .line 72
    :cond_4
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readRawLittleEndian64()J

    .line 73
    .line 74
    .line 75
    move-result-wide v2

    .line 76
    invoke-virtual {p2, p1}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedOutputStream;->writeRawVarint32(I)V

    .line 77
    .line 78
    .line 79
    invoke-virtual {p2, v2, v3}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedOutputStream;->writeFixed64NoTag(J)V

    .line 80
    .line 81
    .line 82
    return v1

    .line 83
    :cond_5
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readInt64()J

    .line 84
    .line 85
    .line 86
    move-result-wide v2

    .line 87
    invoke-virtual {p2, p1}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedOutputStream;->writeRawVarint32(I)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {p2, v2, v3}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedOutputStream;->writeUInt64NoTag(J)V

    .line 91
    .line 92
    .line 93
    return v1
.end method

.method public skipMessage(Lkotlin/reflect/jvm/internal/impl/protobuf/CodedOutputStream;)V
    .locals 1

    .line 1
    :cond_0
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->readTag()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    invoke-virtual {p0, v0, p1}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->skipField(ILkotlin/reflect/jvm/internal/impl/protobuf/CodedOutputStream;)Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    :cond_1
    return-void
.end method

.method public skipRawBytes(I)V
    .locals 2

    .line 1
    iget v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferSize:I

    .line 2
    .line 3
    iget v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 4
    .line 5
    sub-int/2addr v0, v1

    .line 6
    if-gt p1, v0, :cond_0

    .line 7
    .line 8
    if-ltz p1, :cond_0

    .line 9
    .line 10
    add-int/2addr v1, p1

    .line 11
    iput v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->bufferPos:I

    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    invoke-direct {p0, p1}, Lkotlin/reflect/jvm/internal/impl/protobuf/CodedInputStream;->skipRawBytesSlowPath(I)V

    .line 15
    .line 16
    .line 17
    return-void
.end method
