.class public Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final frameLengthOverhead:I = 0x6


# instance fields
.field private closeFlag:Z

.field private fin:Z

.field private opcode:B

.field private payload:[B


# direct methods
.method public constructor <init>(BZ[B)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->closeFlag:Z

    .line 3
    iput-byte p1, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->opcode:B

    .line 4
    iput-boolean p2, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->fin:Z

    .line 5
    invoke-virtual {p3}, [B->clone()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [B

    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->payload:[B

    return-void
.end method

.method public constructor <init>(Ljava/io/InputStream;)V
    .locals 7

    .line 19
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 20
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->closeFlag:Z

    .line 21
    invoke-virtual {p1}, Ljava/io/InputStream;->read()I

    move-result v1

    int-to-byte v1, v1

    .line 22
    invoke-direct {p0, v1}, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->setFinAndOpCode(B)V

    .line 23
    iget-byte v1, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->opcode:B

    const/16 v2, 0x8

    const/4 v3, 0x1

    const/4 v4, 0x2

    if-ne v1, v4, :cond_9

    .line 24
    invoke-virtual {p1}, Ljava/io/InputStream;->read()I

    move-result v1

    int-to-byte v1, v1

    and-int/lit16 v5, v1, 0x80

    if-eqz v5, :cond_0

    move v5, v3

    goto :goto_0

    :cond_0
    move v5, v0

    :goto_0
    const/16 v3, 0x7f

    and-int/2addr v1, v3

    int-to-byte v1, v1

    if-ne v1, v3, :cond_1

    goto :goto_1

    :cond_1
    const/16 v2, 0x7e

    if-ne v1, v2, :cond_2

    move v2, v4

    goto :goto_1

    :cond_2
    move v2, v0

    :goto_1
    if-lez v2, :cond_3

    move v1, v0

    :cond_3
    :goto_2
    add-int/lit8 v2, v2, -0x1

    if-gez v2, :cond_8

    if-eqz v5, :cond_4

    const/4 v2, 0x4

    .line 25
    new-array v3, v2, [B

    .line 26
    invoke-virtual {p1, v3, v0, v2}, Ljava/io/InputStream;->read([BII)I

    goto :goto_3

    :cond_4
    const/4 v3, 0x0

    .line 27
    :goto_3
    new-array v2, v1, [B

    iput-object v2, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->payload:[B

    move v2, v0

    move v4, v1

    :goto_4
    if-ne v2, v1, :cond_7

    if-eqz v5, :cond_6

    .line 28
    :goto_5
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->payload:[B

    array-length v1, p1

    if-lt v0, v1, :cond_5

    goto :goto_6

    .line 29
    :cond_5
    aget-byte v1, p1, v0

    rem-int/lit8 v2, v0, 0x4

    aget-byte v2, v3, v2

    xor-int/2addr v1, v2

    int-to-byte v1, v1

    aput-byte v1, p1, v0

    add-int/lit8 v0, v0, 0x1

    goto :goto_5

    :cond_6
    :goto_6
    return-void

    .line 30
    :cond_7
    iget-object v6, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->payload:[B

    invoke-virtual {p1, v6, v2, v4}, Ljava/io/InputStream;->read([BII)I

    move-result v6

    add-int/2addr v2, v6

    sub-int/2addr v4, v6

    goto :goto_4

    .line 31
    :cond_8
    invoke-virtual {p1}, Ljava/io/InputStream;->read()I

    move-result v3

    int-to-byte v3, v3

    and-int/lit16 v3, v3, 0xff

    mul-int/lit8 v4, v2, 0x8

    shl-int/2addr v3, v4

    or-int/2addr v1, v3

    goto :goto_2

    :cond_9
    if-ne v1, v2, :cond_a

    .line 32
    iput-boolean v3, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->closeFlag:Z

    return-void

    .line 33
    :cond_a
    new-instance p1, Ljava/io/IOException;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Invalid Frame: Opcode: "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-byte p0, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->opcode:B

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {p1, p0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public constructor <init>([B)V
    .locals 6

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 7
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->closeFlag:Z

    .line 8
    invoke-static {p1}, Ljava/nio/ByteBuffer;->wrap([B)Ljava/nio/ByteBuffer;

    move-result-object p1

    .line 9
    invoke-virtual {p1}, Ljava/nio/ByteBuffer;->get()B

    move-result v1

    .line 10
    invoke-direct {p0, v1}, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->setFinAndOpCode(B)V

    .line 11
    invoke-virtual {p1}, Ljava/nio/ByteBuffer;->get()B

    move-result v1

    and-int/lit16 v2, v1, 0x80

    if-eqz v2, :cond_0

    const/4 v2, 0x1

    goto :goto_0

    :cond_0
    move v2, v0

    :goto_0
    const/16 v3, 0x7f

    and-int/2addr v1, v3

    int-to-byte v1, v1

    if-ne v1, v3, :cond_1

    const/16 v3, 0x8

    goto :goto_1

    :cond_1
    const/16 v3, 0x7e

    if-ne v1, v3, :cond_2

    const/4 v3, 0x2

    goto :goto_1

    :cond_2
    move v3, v0

    :goto_1
    add-int/lit8 v3, v3, -0x1

    if-gtz v3, :cond_6

    if-eqz v2, :cond_3

    const/4 v3, 0x4

    .line 12
    new-array v4, v3, [B

    .line 13
    invoke-virtual {p1, v4, v0, v3}, Ljava/nio/ByteBuffer;->get([BII)Ljava/nio/ByteBuffer;

    goto :goto_2

    :cond_3
    const/4 v4, 0x0

    .line 14
    :goto_2
    new-array v3, v1, [B

    iput-object v3, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->payload:[B

    .line 15
    invoke-virtual {p1, v3, v0, v1}, Ljava/nio/ByteBuffer;->get([BII)Ljava/nio/ByteBuffer;

    if-eqz v2, :cond_5

    .line 16
    :goto_3
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->payload:[B

    array-length v1, p1

    if-lt v0, v1, :cond_4

    goto :goto_4

    .line 17
    :cond_4
    aget-byte v1, p1, v0

    rem-int/lit8 v2, v0, 0x4

    aget-byte v2, v4, v2

    xor-int/2addr v1, v2

    int-to-byte v1, v1

    aput-byte v1, p1, v0

    add-int/lit8 v0, v0, 0x1

    goto :goto_3

    :cond_5
    :goto_4
    return-void

    .line 18
    :cond_6
    invoke-virtual {p1}, Ljava/nio/ByteBuffer;->get()B

    move-result v4

    and-int/lit16 v4, v4, 0xff

    mul-int/lit8 v5, v3, 0x8

    shl-int/2addr v4, v5

    or-int/2addr v1, v4

    goto :goto_1
.end method

.method public static appendFinAndOpCode(Ljava/nio/ByteBuffer;BZ)V
    .locals 0

    .line 1
    if-eqz p2, :cond_0

    .line 2
    .line 3
    const/16 p2, 0x80

    .line 4
    .line 5
    int-to-byte p2, p2

    .line 6
    goto :goto_0

    .line 7
    :cond_0
    const/4 p2, 0x0

    .line 8
    :goto_0
    and-int/lit8 p1, p1, 0xf

    .line 9
    .line 10
    or-int/2addr p1, p2

    .line 11
    int-to-byte p1, p1

    .line 12
    invoke-virtual {p0, p1}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method private static appendLength(Ljava/nio/ByteBuffer;IZ)V
    .locals 2

    .line 1
    if-ltz p1, :cond_3

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    if-eqz p2, :cond_0

    .line 5
    .line 6
    const/16 p2, -0x80

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move p2, v0

    .line 10
    :goto_0
    const v1, 0xffff

    .line 11
    .line 12
    .line 13
    if-le p1, v1, :cond_1

    .line 14
    .line 15
    or-int/lit8 p2, p2, 0x7f

    .line 16
    .line 17
    int-to-byte p2, p2

    .line 18
    invoke-virtual {p0, p2}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0, v0}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0, v0}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0, v0}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 28
    .line 29
    .line 30
    invoke-virtual {p0, v0}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 31
    .line 32
    .line 33
    shr-int/lit8 p2, p1, 0x18

    .line 34
    .line 35
    and-int/lit16 p2, p2, 0xff

    .line 36
    .line 37
    int-to-byte p2, p2

    .line 38
    invoke-virtual {p0, p2}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 39
    .line 40
    .line 41
    shr-int/lit8 p2, p1, 0x10

    .line 42
    .line 43
    and-int/lit16 p2, p2, 0xff

    .line 44
    .line 45
    int-to-byte p2, p2

    .line 46
    invoke-virtual {p0, p2}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 47
    .line 48
    .line 49
    shr-int/lit8 p2, p1, 0x8

    .line 50
    .line 51
    and-int/lit16 p2, p2, 0xff

    .line 52
    .line 53
    int-to-byte p2, p2

    .line 54
    invoke-virtual {p0, p2}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 55
    .line 56
    .line 57
    and-int/lit16 p1, p1, 0xff

    .line 58
    .line 59
    int-to-byte p1, p1

    .line 60
    invoke-virtual {p0, p1}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 61
    .line 62
    .line 63
    return-void

    .line 64
    :cond_1
    const/16 v0, 0x7e

    .line 65
    .line 66
    if-lt p1, v0, :cond_2

    .line 67
    .line 68
    or-int/2addr p2, v0

    .line 69
    int-to-byte p2, p2

    .line 70
    invoke-virtual {p0, p2}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 71
    .line 72
    .line 73
    shr-int/lit8 p2, p1, 0x8

    .line 74
    .line 75
    int-to-byte p2, p2

    .line 76
    invoke-virtual {p0, p2}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 77
    .line 78
    .line 79
    and-int/lit16 p1, p1, 0xff

    .line 80
    .line 81
    int-to-byte p1, p1

    .line 82
    invoke-virtual {p0, p1}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 83
    .line 84
    .line 85
    return-void

    .line 86
    :cond_2
    or-int/2addr p1, p2

    .line 87
    int-to-byte p1, p1

    .line 88
    invoke-virtual {p0, p1}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 89
    .line 90
    .line 91
    return-void

    .line 92
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 93
    .line 94
    const-string p1, "Length cannot be negative"

    .line 95
    .line 96
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    throw p0
.end method

.method public static appendLengthAndMask(Ljava/nio/ByteBuffer;I[B)V
    .locals 1

    .line 1
    if-eqz p2, :cond_0

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    invoke-static {p0, p1, v0}, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->appendLength(Ljava/nio/ByteBuffer;IZ)V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0, p2}, Ljava/nio/ByteBuffer;->put([B)Ljava/nio/ByteBuffer;

    .line 8
    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    const/4 p2, 0x0

    .line 12
    invoke-static {p0, p1, p2}, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->appendLength(Ljava/nio/ByteBuffer;IZ)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public static generateMaskingKey()[B
    .locals 6

    .line 1
    new-instance v0, Ljava/security/SecureRandom;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/security/SecureRandom;-><init>()V

    .line 4
    .line 5
    .line 6
    const/16 v1, 0xff

    .line 7
    .line 8
    invoke-virtual {v0, v1}, Ljava/util/Random;->nextInt(I)I

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    invoke-virtual {v0, v1}, Ljava/util/Random;->nextInt(I)I

    .line 13
    .line 14
    .line 15
    move-result v3

    .line 16
    invoke-virtual {v0, v1}, Ljava/util/Random;->nextInt(I)I

    .line 17
    .line 18
    .line 19
    move-result v4

    .line 20
    invoke-virtual {v0, v1}, Ljava/util/Random;->nextInt(I)I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    int-to-byte v1, v2

    .line 25
    int-to-byte v2, v3

    .line 26
    int-to-byte v3, v4

    .line 27
    int-to-byte v0, v0

    .line 28
    const/4 v4, 0x4

    .line 29
    new-array v4, v4, [B

    .line 30
    .line 31
    const/4 v5, 0x0

    .line 32
    aput-byte v1, v4, v5

    .line 33
    .line 34
    const/4 v1, 0x1

    .line 35
    aput-byte v2, v4, v1

    .line 36
    .line 37
    const/4 v1, 0x2

    .line 38
    aput-byte v3, v4, v1

    .line 39
    .line 40
    const/4 v1, 0x3

    .line 41
    aput-byte v0, v4, v1

    .line 42
    .line 43
    return-object v4
.end method

.method private setFinAndOpCode(B)V
    .locals 1

    .line 1
    and-int/lit16 v0, p1, 0x80

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    goto :goto_0

    .line 7
    :cond_0
    const/4 v0, 0x0

    .line 8
    :goto_0
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->fin:Z

    .line 9
    .line 10
    and-int/lit8 p1, p1, 0xf

    .line 11
    .line 12
    int-to-byte p1, p1

    .line 13
    iput-byte p1, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->opcode:B

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public encodeFrame()[B
    .locals 6

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->payload:[B

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    add-int/lit8 v2, v1, 0x6

    .line 5
    .line 6
    array-length v3, v0

    .line 7
    const v4, 0xffff

    .line 8
    .line 9
    .line 10
    if-le v3, v4, :cond_0

    .line 11
    .line 12
    add-int/lit8 v2, v1, 0xe

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    array-length v0, v0

    .line 16
    const/16 v3, 0x7e

    .line 17
    .line 18
    if-lt v0, v3, :cond_1

    .line 19
    .line 20
    add-int/lit8 v2, v1, 0x8

    .line 21
    .line 22
    :cond_1
    :goto_0
    invoke-static {v2}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    iget-byte v1, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->opcode:B

    .line 27
    .line 28
    iget-boolean v2, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->fin:Z

    .line 29
    .line 30
    invoke-static {v0, v1, v2}, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->appendFinAndOpCode(Ljava/nio/ByteBuffer;BZ)V

    .line 31
    .line 32
    .line 33
    invoke-static {}, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->generateMaskingKey()[B

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->payload:[B

    .line 38
    .line 39
    array-length v2, v2

    .line 40
    invoke-static {v0, v2, v1}, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->appendLengthAndMask(Ljava/nio/ByteBuffer;I[B)V

    .line 41
    .line 42
    .line 43
    const/4 v2, 0x0

    .line 44
    :goto_1
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->payload:[B

    .line 45
    .line 46
    array-length v4, v3

    .line 47
    if-lt v2, v4, :cond_2

    .line 48
    .line 49
    invoke-virtual {v0}, Ljava/nio/ByteBuffer;->flip()Ljava/nio/Buffer;

    .line 50
    .line 51
    .line 52
    invoke-virtual {v0}, Ljava/nio/ByteBuffer;->array()[B

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0

    .line 57
    :cond_2
    aget-byte v4, v3, v2

    .line 58
    .line 59
    rem-int/lit8 v5, v2, 0x4

    .line 60
    .line 61
    aget-byte v5, v1, v5

    .line 62
    .line 63
    xor-int/2addr v4, v5

    .line 64
    int-to-byte v4, v4

    .line 65
    aput-byte v4, v3, v2

    .line 66
    .line 67
    invoke-virtual {v0, v4}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 68
    .line 69
    .line 70
    add-int/lit8 v2, v2, 0x1

    .line 71
    .line 72
    goto :goto_1
.end method

.method public getOpcode()B
    .locals 0

    .line 1
    iget-byte p0, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->opcode:B

    .line 2
    .line 3
    return p0
.end method

.method public getPayload()[B
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->payload:[B

    .line 2
    .line 3
    return-object p0
.end method

.method public isCloseFlag()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->closeFlag:Z

    .line 2
    .line 3
    return p0
.end method

.method public isFin()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/client/websocket/WebSocketFrame;->fin:Z

    .line 2
    .line 3
    return p0
.end method
