.class public Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final FOUR_BYTE_INT_MAX:J = 0xffffffffL

.field protected static final STRING_ENCODING:Ljava/nio/charset/Charset;

.field private static final TWO_BYTE_INT_MAX:I = 0xffff

.field public static final VARIABLE_BYTE_INT_MAX:I = 0xfffffff


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 2
    .line 3
    sput-object v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->STRING_ENCODING:Ljava/nio/charset/Charset;

    .line 4
    .line 5
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance p0, Ljava/lang/IllegalAccessException;

    .line 5
    .line 6
    const-string v0, "Utility Class"

    .line 7
    .line 8
    invoke-direct {p0, v0}, Ljava/lang/IllegalAccessException;-><init>(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    throw p0
.end method

.method public static decodeUTF8(Ljava/io/DataInputStream;)Ljava/lang/String;
    .locals 2

    .line 1
    :try_start_0
    invoke-virtual {p0}, Ljava/io/DataInputStream;->readUnsignedShort()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    new-array v0, v0, [B

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Ljava/io/DataInputStream;->readFully([B)V

    .line 8
    .line 9
    .line 10
    new-instance p0, Ljava/lang/String;

    .line 11
    .line 12
    sget-object v1, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->STRING_ENCODING:Ljava/nio/charset/Charset;

    .line 13
    .line 14
    invoke-direct {p0, v0, v1}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    .line 15
    .line 16
    .line 17
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->validateUTF8String(Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 18
    .line 19
    .line 20
    return-object p0

    .line 21
    :catch_0
    move-exception p0

    .line 22
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 23
    .line 24
    const v1, 0xc352

    .line 25
    .line 26
    .line 27
    invoke-direct {v0, v1, p0}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(ILjava/lang/Throwable;)V

    .line 28
    .line 29
    .line 30
    throw v0
.end method

.method public static encodeUTF8(Ljava/io/DataOutputStream;Ljava/lang/String;)V
    .locals 2

    .line 1
    invoke-static {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->validateUTF8String(Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    :try_start_0
    sget-object v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->STRING_ENCODING:Ljava/nio/charset/Charset;

    .line 5
    .line 6
    invoke-virtual {p1, v0}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    array-length v0, p1

    .line 11
    ushr-int/lit8 v0, v0, 0x8

    .line 12
    .line 13
    and-int/lit16 v0, v0, 0xff

    .line 14
    .line 15
    int-to-byte v0, v0

    .line 16
    array-length v1, p1

    .line 17
    and-int/lit16 v1, v1, 0xff

    .line 18
    .line 19
    int-to-byte v1, v1

    .line 20
    invoke-virtual {p0, v0}, Ljava/io/DataOutputStream;->write(I)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0, v1}, Ljava/io/DataOutputStream;->write(I)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0, p1}, Ljava/io/OutputStream;->write([B)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :catch_0
    move-exception p0

    .line 31
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 32
    .line 33
    invoke-direct {p1, p0}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(Ljava/lang/Throwable;)V

    .line 34
    .line 35
    .line 36
    throw p1
.end method

.method public static encodeVariableByteInteger(I)[B
    .locals 7

    .line 1
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttDataTypes;->validateVariableByteInt(I)V

    .line 2
    .line 3
    .line 4
    int-to-long v0, p0

    .line 5
    new-instance p0, Ljava/io/ByteArrayOutputStream;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/io/ByteArrayOutputStream;-><init>()V

    .line 8
    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    :cond_0
    const-wide/16 v3, 0x80

    .line 12
    .line 13
    rem-long v5, v0, v3

    .line 14
    .line 15
    long-to-int v5, v5

    .line 16
    int-to-byte v5, v5

    .line 17
    div-long/2addr v0, v3

    .line 18
    const-wide/16 v3, 0x0

    .line 19
    .line 20
    cmp-long v3, v0, v3

    .line 21
    .line 22
    if-lez v3, :cond_1

    .line 23
    .line 24
    or-int/lit16 v4, v5, 0x80

    .line 25
    .line 26
    int-to-byte v5, v4

    .line 27
    :cond_1
    invoke-virtual {p0, v5}, Ljava/io/ByteArrayOutputStream;->write(I)V

    .line 28
    .line 29
    .line 30
    add-int/lit8 v2, v2, 0x1

    .line 31
    .line 32
    if-lez v3, :cond_2

    .line 33
    .line 34
    const/4 v3, 0x4

    .line 35
    if-lt v2, v3, :cond_0

    .line 36
    .line 37
    :cond_2
    invoke-virtual {p0}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    return-object p0
.end method

.method public static readUnsignedFourByteInt(Ljava/io/DataInputStream;)Ljava/lang/Long;
    .locals 7

    .line 1
    const/16 v0, 0x8

    .line 2
    .line 3
    new-array v1, v0, [B

    .line 4
    .line 5
    const/4 v2, 0x4

    .line 6
    invoke-virtual {p0, v1, v2, v2}, Ljava/io/DataInputStream;->readFully([BII)V

    .line 7
    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    aget-byte p0, v1, p0

    .line 11
    .line 12
    int-to-long v3, p0

    .line 13
    const/16 p0, 0x38

    .line 14
    .line 15
    shl-long/2addr v3, p0

    .line 16
    const/4 p0, 0x1

    .line 17
    aget-byte p0, v1, p0

    .line 18
    .line 19
    and-int/lit16 p0, p0, 0xff

    .line 20
    .line 21
    int-to-long v5, p0

    .line 22
    const/16 p0, 0x30

    .line 23
    .line 24
    shl-long/2addr v5, p0

    .line 25
    add-long/2addr v3, v5

    .line 26
    const/4 p0, 0x2

    .line 27
    aget-byte p0, v1, p0

    .line 28
    .line 29
    and-int/lit16 p0, p0, 0xff

    .line 30
    .line 31
    int-to-long v5, p0

    .line 32
    const/16 p0, 0x28

    .line 33
    .line 34
    shl-long/2addr v5, p0

    .line 35
    add-long/2addr v3, v5

    .line 36
    const/4 p0, 0x3

    .line 37
    aget-byte p0, v1, p0

    .line 38
    .line 39
    and-int/lit16 p0, p0, 0xff

    .line 40
    .line 41
    int-to-long v5, p0

    .line 42
    const/16 p0, 0x20

    .line 43
    .line 44
    shl-long/2addr v5, p0

    .line 45
    add-long/2addr v3, v5

    .line 46
    aget-byte p0, v1, v2

    .line 47
    .line 48
    and-int/lit16 p0, p0, 0xff

    .line 49
    .line 50
    int-to-long v5, p0

    .line 51
    const/16 p0, 0x18

    .line 52
    .line 53
    shl-long/2addr v5, p0

    .line 54
    add-long/2addr v3, v5

    .line 55
    const/4 p0, 0x5

    .line 56
    aget-byte p0, v1, p0

    .line 57
    .line 58
    and-int/lit16 p0, p0, 0xff

    .line 59
    .line 60
    shl-int/lit8 p0, p0, 0x10

    .line 61
    .line 62
    int-to-long v5, p0

    .line 63
    add-long/2addr v3, v5

    .line 64
    const/4 p0, 0x6

    .line 65
    aget-byte p0, v1, p0

    .line 66
    .line 67
    and-int/lit16 p0, p0, 0xff

    .line 68
    .line 69
    shl-int/2addr p0, v0

    .line 70
    int-to-long v5, p0

    .line 71
    add-long/2addr v3, v5

    .line 72
    const/4 p0, 0x7

    .line 73
    aget-byte p0, v1, p0

    .line 74
    .line 75
    and-int/lit16 p0, p0, 0xff

    .line 76
    .line 77
    int-to-long v0, p0

    .line 78
    add-long/2addr v3, v0

    .line 79
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    return-object p0
.end method

.method public static readUnsignedTwoByteInt(Ljava/io/DataInputStream;)I
    .locals 2

    .line 1
    invoke-virtual {p0}, Ljava/io/InputStream;->read()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p0}, Ljava/io/InputStream;->read()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    or-int v1, v0, p0

    .line 10
    .line 11
    if-ltz v1, :cond_0

    .line 12
    .line 13
    shl-int/lit8 v0, v0, 0x8

    .line 14
    .line 15
    add-int/2addr v0, p0

    .line 16
    return v0

    .line 17
    :cond_0
    new-instance p0, Ljava/io/EOFException;

    .line 18
    .line 19
    invoke-direct {p0}, Ljava/io/EOFException;-><init>()V

    .line 20
    .line 21
    .line 22
    throw p0
.end method

.method public static readVariableByteInteger(Ljava/io/DataInputStream;)Lorg/eclipse/paho/mqttv5/common/packet/util/VariableByteInteger;
    .locals 6

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x1

    .line 3
    move v2, v0

    .line 4
    move v3, v1

    .line 5
    :cond_0
    invoke-virtual {p0}, Ljava/io/DataInputStream;->readByte()B

    .line 6
    .line 7
    .line 8
    move-result v4

    .line 9
    add-int/2addr v0, v1

    .line 10
    and-int/lit8 v5, v4, 0x7f

    .line 11
    .line 12
    mul-int/2addr v5, v3

    .line 13
    add-int/2addr v2, v5

    .line 14
    mul-int/lit16 v3, v3, 0x80

    .line 15
    .line 16
    and-int/lit16 v4, v4, 0x80

    .line 17
    .line 18
    if-nez v4, :cond_0

    .line 19
    .line 20
    if-ltz v2, :cond_1

    .line 21
    .line 22
    const p0, 0xfffffff

    .line 23
    .line 24
    .line 25
    if-gt v2, p0, :cond_1

    .line 26
    .line 27
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/packet/util/VariableByteInteger;

    .line 28
    .line 29
    invoke-direct {p0, v2, v0}, Lorg/eclipse/paho/mqttv5/common/packet/util/VariableByteInteger;-><init>(II)V

    .line 30
    .line 31
    .line 32
    return-object p0

    .line 33
    :cond_1
    new-instance p0, Ljava/io/IOException;

    .line 34
    .line 35
    const-string v0, "This property must be a number between 0 and 268435455. Read value was: "

    .line 36
    .line 37
    invoke-static {v2, v0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    invoke-direct {p0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    throw p0
.end method

.method public static validateFourByteInt(Ljava/lang/Long;)V
    .locals 4

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 5
    .line 6
    .line 7
    move-result-wide v0

    .line 8
    const-wide/16 v2, 0x0

    .line 9
    .line 10
    cmp-long v0, v0, v2

    .line 11
    .line 12
    if-ltz v0, :cond_1

    .line 13
    .line 14
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 15
    .line 16
    .line 17
    move-result-wide v0

    .line 18
    const-wide v2, 0xffffffffL

    .line 19
    .line 20
    .line 21
    .line 22
    .line 23
    cmp-long p0, v0, v2

    .line 24
    .line 25
    if-gtz p0, :cond_1

    .line 26
    .line 27
    :goto_0
    return-void

    .line 28
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 29
    .line 30
    const-string v0, "This property must be a number between 0 and 4294967295"

    .line 31
    .line 32
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    throw p0
.end method

.method public static validateTwoByteInt(Ljava/lang/Integer;)V
    .locals 1

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-ltz v0, :cond_1

    .line 9
    .line 10
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    const v0, 0xffff

    .line 15
    .line 16
    .line 17
    if-gt p0, v0, :cond_1

    .line 18
    .line 19
    :goto_0
    return-void

    .line 20
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 21
    .line 22
    const-string v0, "This property must be a number between 0 and 65535"

    .line 23
    .line 24
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    throw p0
.end method

.method private static validateUTF8String(Ljava/lang/String;)V
    .locals 7

    .line 1
    const/4 v0, 0x0

    .line 2
    move v1, v0

    .line 3
    :goto_0
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 4
    .line 5
    .line 6
    move-result v2

    .line 7
    if-lt v1, v2, :cond_0

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    invoke-virtual {p0, v1}, Ljava/lang/String;->charAt(I)C

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    invoke-static {v2}, Ljava/lang/Character;->isHighSurrogate(C)Z

    .line 15
    .line 16
    .line 17
    move-result v3

    .line 18
    const v4, 0xfffe

    .line 19
    .line 20
    .line 21
    const/4 v5, 0x1

    .line 22
    if-eqz v3, :cond_5

    .line 23
    .line 24
    add-int/lit8 v1, v1, 0x1

    .line 25
    .line 26
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    if-ne v1, v3, :cond_2

    .line 31
    .line 32
    :cond_1
    :goto_1
    move v3, v5

    .line 33
    goto :goto_2

    .line 34
    :cond_2
    invoke-virtual {p0, v1}, Ljava/lang/String;->charAt(I)C

    .line 35
    .line 36
    .line 37
    move-result v3

    .line 38
    invoke-static {v3}, Ljava/lang/Character;->isLowSurrogate(C)Z

    .line 39
    .line 40
    .line 41
    move-result v6

    .line 42
    if-nez v6, :cond_3

    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_3
    and-int/lit16 v6, v2, 0x3ff

    .line 46
    .line 47
    shl-int/lit8 v6, v6, 0xa

    .line 48
    .line 49
    and-int/lit16 v3, v3, 0x3ff

    .line 50
    .line 51
    or-int/2addr v3, v6

    .line 52
    const v6, 0xffff

    .line 53
    .line 54
    .line 55
    and-int/2addr v3, v6

    .line 56
    if-eq v3, v6, :cond_1

    .line 57
    .line 58
    if-ne v3, v4, :cond_4

    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_4
    move v3, v0

    .line 62
    goto :goto_2

    .line 63
    :cond_5
    invoke-static {v2}, Ljava/lang/Character;->isISOControl(C)Z

    .line 64
    .line 65
    .line 66
    move-result v3

    .line 67
    if-nez v3, :cond_1

    .line 68
    .line 69
    invoke-static {v2}, Ljava/lang/Character;->isLowSurrogate(C)Z

    .line 70
    .line 71
    .line 72
    move-result v3

    .line 73
    if-eqz v3, :cond_6

    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_6
    const v3, 0xfdd0

    .line 77
    .line 78
    .line 79
    if-lt v2, v3, :cond_4

    .line 80
    .line 81
    const v3, 0xfddf

    .line 82
    .line 83
    .line 84
    if-le v2, v3, :cond_1

    .line 85
    .line 86
    if-lt v2, v4, :cond_4

    .line 87
    .line 88
    goto :goto_1

    .line 89
    :goto_2
    if-nez v3, :cond_7

    .line 90
    .line 91
    add-int/2addr v1, v5

    .line 92
    goto :goto_0

    .line 93
    :cond_7
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 94
    .line 95
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 96
    .line 97
    .line 98
    move-result-object v0

    .line 99
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    const-string v1, "Invalid UTF-8 char: [%04x]"

    .line 104
    .line 105
    invoke-static {v1, v0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object v0

    .line 109
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    throw p0
.end method

.method public static validateVariableByteInt(I)V
    .locals 1

    .line 1
    if-ltz p0, :cond_0

    .line 2
    .line 3
    const v0, 0xfffffff

    .line 4
    .line 5
    .line 6
    if-gt p0, v0, :cond_0

    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 10
    .line 11
    const-string v0, "This property must be a number between 0 and 268435455"

    .line 12
    .line 13
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    throw p0
.end method

.method public static writeUnsignedFourByteInt(JLjava/io/DataOutputStream;)V
    .locals 2

    .line 1
    const/16 v0, 0x18

    .line 2
    .line 3
    ushr-long v0, p0, v0

    .line 4
    .line 5
    long-to-int v0, v0

    .line 6
    int-to-byte v0, v0

    .line 7
    invoke-virtual {p2, v0}, Ljava/io/DataOutputStream;->writeByte(I)V

    .line 8
    .line 9
    .line 10
    const/16 v0, 0x10

    .line 11
    .line 12
    ushr-long v0, p0, v0

    .line 13
    .line 14
    long-to-int v0, v0

    .line 15
    int-to-byte v0, v0

    .line 16
    invoke-virtual {p2, v0}, Ljava/io/DataOutputStream;->writeByte(I)V

    .line 17
    .line 18
    .line 19
    const/16 v0, 0x8

    .line 20
    .line 21
    ushr-long v0, p0, v0

    .line 22
    .line 23
    long-to-int v0, v0

    .line 24
    int-to-byte v0, v0

    .line 25
    invoke-virtual {p2, v0}, Ljava/io/DataOutputStream;->writeByte(I)V

    .line 26
    .line 27
    .line 28
    long-to-int p0, p0

    .line 29
    int-to-byte p0, p0

    .line 30
    invoke-virtual {p2, p0}, Ljava/io/DataOutputStream;->writeByte(I)V

    .line 31
    .line 32
    .line 33
    return-void
.end method
