.class public final Lms/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final b:Ljava/lang/String;

.field public static final c:Ljava/util/concurrent/atomic/AtomicLong;


# instance fields
.field public final a:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-virtual {v1}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 18
    .line 19
    .line 20
    move-result-wide v1

    .line 21
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    invoke-static {v0}, Lms/f;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    sput-object v0, Lms/d;->b:Ljava/lang/String;

    .line 33
    .line 34
    new-instance v0, Ljava/util/concurrent/atomic/AtomicLong;

    .line 35
    .line 36
    const-wide/16 v1, 0x0

    .line 37
    .line 38
    invoke-direct {v0, v1, v2}, Ljava/util/concurrent/atomic/AtomicLong;-><init>(J)V

    .line 39
    .line 40
    .line 41
    sput-object v0, Lms/d;->c:Ljava/util/concurrent/atomic/AtomicLong;

    .line 42
    .line 43
    return-void
.end method

.method public constructor <init>()V
    .locals 16

    .line 1
    invoke-direct/range {p0 .. p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/Date;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/Date;-><init>()V

    .line 7
    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/util/Date;->getTime()J

    .line 10
    .line 11
    .line 12
    move-result-wide v0

    .line 13
    const-wide/16 v2, 0x3e8

    .line 14
    .line 15
    div-long v4, v0, v2

    .line 16
    .line 17
    rem-long/2addr v0, v2

    .line 18
    const/4 v2, 0x4

    .line 19
    invoke-static {v2}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    long-to-int v4, v4

    .line 24
    invoke-virtual {v3, v4}, Ljava/nio/ByteBuffer;->putInt(I)Ljava/nio/ByteBuffer;

    .line 25
    .line 26
    .line 27
    sget-object v4, Ljava/nio/ByteOrder;->BIG_ENDIAN:Ljava/nio/ByteOrder;

    .line 28
    .line 29
    invoke-virtual {v3, v4}, Ljava/nio/ByteBuffer;->order(Ljava/nio/ByteOrder;)Ljava/nio/ByteBuffer;

    .line 30
    .line 31
    .line 32
    const/4 v4, 0x0

    .line 33
    invoke-virtual {v3, v4}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    .line 34
    .line 35
    .line 36
    invoke-virtual {v3}, Ljava/nio/ByteBuffer;->array()[B

    .line 37
    .line 38
    .line 39
    move-result-object v3

    .line 40
    aget-byte v5, v3, v4

    .line 41
    .line 42
    const/4 v6, 0x1

    .line 43
    aget-byte v7, v3, v6

    .line 44
    .line 45
    const/4 v8, 0x2

    .line 46
    aget-byte v9, v3, v8

    .line 47
    .line 48
    const/4 v10, 0x3

    .line 49
    aget-byte v3, v3, v10

    .line 50
    .line 51
    invoke-static {v0, v1}, Lms/d;->a(J)[B

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    aget-byte v1, v0, v4

    .line 56
    .line 57
    aget-byte v0, v0, v6

    .line 58
    .line 59
    sget-object v11, Lms/d;->c:Ljava/util/concurrent/atomic/AtomicLong;

    .line 60
    .line 61
    invoke-virtual {v11}, Ljava/util/concurrent/atomic/AtomicLong;->incrementAndGet()J

    .line 62
    .line 63
    .line 64
    move-result-wide v11

    .line 65
    invoke-static {v11, v12}, Lms/d;->a(J)[B

    .line 66
    .line 67
    .line 68
    move-result-object v11

    .line 69
    aget-byte v12, v11, v4

    .line 70
    .line 71
    aget-byte v11, v11, v6

    .line 72
    .line 73
    invoke-static {}, Landroid/os/Process;->myPid()I

    .line 74
    .line 75
    .line 76
    move-result v13

    .line 77
    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 78
    .line 79
    .line 80
    move-result-object v13

    .line 81
    invoke-virtual {v13}, Ljava/lang/Integer;->shortValue()S

    .line 82
    .line 83
    .line 84
    move-result v13

    .line 85
    int-to-long v13, v13

    .line 86
    invoke-static {v13, v14}, Lms/d;->a(J)[B

    .line 87
    .line 88
    .line 89
    move-result-object v13

    .line 90
    aget-byte v14, v13, v4

    .line 91
    .line 92
    aget-byte v13, v13, v6

    .line 93
    .line 94
    const/16 v15, 0xa

    .line 95
    .line 96
    new-array v15, v15, [B

    .line 97
    .line 98
    aput-byte v5, v15, v4

    .line 99
    .line 100
    aput-byte v7, v15, v6

    .line 101
    .line 102
    aput-byte v9, v15, v8

    .line 103
    .line 104
    aput-byte v3, v15, v10

    .line 105
    .line 106
    aput-byte v1, v15, v2

    .line 107
    .line 108
    const/4 v1, 0x5

    .line 109
    aput-byte v0, v15, v1

    .line 110
    .line 111
    const/4 v0, 0x6

    .line 112
    aput-byte v12, v15, v0

    .line 113
    .line 114
    const/4 v0, 0x7

    .line 115
    aput-byte v11, v15, v0

    .line 116
    .line 117
    const/16 v0, 0x8

    .line 118
    .line 119
    aput-byte v14, v15, v0

    .line 120
    .line 121
    const/16 v0, 0x9

    .line 122
    .line 123
    aput-byte v13, v15, v0

    .line 124
    .line 125
    invoke-static {v15}, Lms/f;->e([B)Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    sget-object v1, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 130
    .line 131
    const/16 v2, 0xc

    .line 132
    .line 133
    invoke-virtual {v0, v4, v2}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 134
    .line 135
    .line 136
    move-result-object v3

    .line 137
    const/16 v5, 0x10

    .line 138
    .line 139
    invoke-virtual {v0, v2, v5}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 140
    .line 141
    .line 142
    move-result-object v6

    .line 143
    const/16 v7, 0x14

    .line 144
    .line 145
    invoke-virtual {v0, v5, v7}, Ljava/lang/String;->subSequence(II)Ljava/lang/CharSequence;

    .line 146
    .line 147
    .line 148
    move-result-object v0

    .line 149
    sget-object v5, Lms/d;->b:Ljava/lang/String;

    .line 150
    .line 151
    invoke-virtual {v5, v4, v2}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 152
    .line 153
    .line 154
    move-result-object v2

    .line 155
    filled-new-array {v3, v6, v0, v2}, [Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v0

    .line 159
    const-string v2, "%s%s%s%s"

    .line 160
    .line 161
    invoke-static {v1, v2, v0}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object v0

    .line 165
    invoke-virtual {v0, v1}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 166
    .line 167
    .line 168
    move-result-object v0

    .line 169
    move-object/from16 v1, p0

    .line 170
    .line 171
    iput-object v0, v1, Lms/d;->a:Ljava/lang/String;

    .line 172
    .line 173
    return-void
.end method

.method public static a(J)[B
    .locals 1

    .line 1
    const/4 v0, 0x2

    .line 2
    invoke-static {v0}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    long-to-int p0, p0

    .line 7
    int-to-short p0, p0

    .line 8
    invoke-virtual {v0, p0}, Ljava/nio/ByteBuffer;->putShort(S)Ljava/nio/ByteBuffer;

    .line 9
    .line 10
    .line 11
    sget-object p0, Ljava/nio/ByteOrder;->BIG_ENDIAN:Ljava/nio/ByteOrder;

    .line 12
    .line 13
    invoke-virtual {v0, p0}, Ljava/nio/ByteBuffer;->order(Ljava/nio/ByteOrder;)Ljava/nio/ByteBuffer;

    .line 14
    .line 15
    .line 16
    const/4 p0, 0x0

    .line 17
    invoke-virtual {v0, p0}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/nio/ByteBuffer;->array()[B

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method


# virtual methods
.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lms/d;->a:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
