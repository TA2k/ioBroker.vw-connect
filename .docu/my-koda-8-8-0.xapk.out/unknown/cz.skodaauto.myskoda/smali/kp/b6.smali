.class public abstract Lkp/b6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a([B)[B
    .locals 6

    .line 1
    array-length v0, p0

    .line 2
    const/16 v1, 0x10

    .line 3
    .line 4
    if-ne v0, v1, :cond_2

    .line 5
    .line 6
    new-array v0, v1, [B

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    move v3, v2

    .line 10
    :goto_0
    const/16 v4, 0xf

    .line 11
    .line 12
    if-ge v3, v1, :cond_1

    .line 13
    .line 14
    aget-byte v5, p0, v3

    .line 15
    .line 16
    shl-int/lit8 v5, v5, 0x1

    .line 17
    .line 18
    and-int/lit16 v5, v5, 0xfe

    .line 19
    .line 20
    int-to-byte v5, v5

    .line 21
    aput-byte v5, v0, v3

    .line 22
    .line 23
    if-ge v3, v4, :cond_0

    .line 24
    .line 25
    add-int/lit8 v4, v3, 0x1

    .line 26
    .line 27
    aget-byte v4, p0, v4

    .line 28
    .line 29
    shr-int/lit8 v4, v4, 0x7

    .line 30
    .line 31
    and-int/lit8 v4, v4, 0x1

    .line 32
    .line 33
    int-to-byte v4, v4

    .line 34
    or-int/2addr v4, v5

    .line 35
    int-to-byte v4, v4

    .line 36
    aput-byte v4, v0, v3

    .line 37
    .line 38
    :cond_0
    add-int/lit8 v3, v3, 0x1

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_1
    aget-byte v1, v0, v4

    .line 42
    .line 43
    aget-byte p0, p0, v2

    .line 44
    .line 45
    shr-int/lit8 p0, p0, 0x7

    .line 46
    .line 47
    and-int/lit16 p0, p0, 0x87

    .line 48
    .line 49
    int-to-byte p0, p0

    .line 50
    xor-int/2addr p0, v1

    .line 51
    int-to-byte p0, p0

    .line 52
    aput-byte p0, v0, v4

    .line 53
    .line 54
    return-object v0

    .line 55
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 56
    .line 57
    const-string v0, "value must be a block."

    .line 58
    .line 59
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    throw p0
.end method

.method public static b([B)Leb/h;
    .locals 7

    .line 1
    const-string v0, "Error in Data#fromByteArray: "

    .line 2
    .line 3
    const-string v1, "bytes"

    .line 4
    .line 5
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    array-length v1, p0

    .line 9
    const/16 v2, 0x2800

    .line 10
    .line 11
    if-gt v1, v2, :cond_7

    .line 12
    .line 13
    array-length v1, p0

    .line 14
    if-nez v1, :cond_0

    .line 15
    .line 16
    sget-object p0, Leb/h;->b:Leb/h;

    .line 17
    .line 18
    return-object p0

    .line 19
    :cond_0
    new-instance v1, Ljava/util/LinkedHashMap;

    .line 20
    .line 21
    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 22
    .line 23
    .line 24
    :try_start_0
    new-instance v2, Ljava/io/ByteArrayInputStream;

    .line 25
    .line 26
    invoke-direct {v2, p0}, Ljava/io/ByteArrayInputStream;-><init>([B)V

    .line 27
    .line 28
    .line 29
    const/4 p0, 0x2

    .line 30
    new-array p0, p0, [B

    .line 31
    .line 32
    invoke-virtual {v2, p0}, Ljava/io/InputStream;->read([B)I

    .line 33
    .line 34
    .line 35
    const/16 v3, -0x5313

    .line 36
    .line 37
    int-to-byte v3, v3

    .line 38
    const v4, 0xffffac

    .line 39
    .line 40
    .line 41
    int-to-byte v4, v4

    .line 42
    const/4 v5, 0x0

    .line 43
    aget-byte v6, p0, v5

    .line 44
    .line 45
    if-ne v6, v4, :cond_1

    .line 46
    .line 47
    const/4 v4, 0x1

    .line 48
    aget-byte p0, p0, v4

    .line 49
    .line 50
    if-ne p0, v3, :cond_1

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_1
    move v4, v5

    .line 54
    :goto_0
    invoke-virtual {v2}, Ljava/io/ByteArrayInputStream;->reset()V

    .line 55
    .line 56
    .line 57
    if-eqz v4, :cond_3

    .line 58
    .line 59
    new-instance p0, Ljava/io/ObjectInputStream;

    .line 60
    .line 61
    invoke-direct {p0, v2}, Ljava/io/ObjectInputStream;-><init>(Ljava/io/InputStream;)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 62
    .line 63
    .line 64
    :try_start_1
    invoke-virtual {p0}, Ljava/io/ObjectInputStream;->readInt()I

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    :goto_1
    if-ge v5, v2, :cond_2

    .line 69
    .line 70
    invoke-virtual {p0}, Ljava/io/ObjectInputStream;->readUTF()Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object v3

    .line 74
    invoke-virtual {p0}, Ljava/io/ObjectInputStream;->readObject()Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v4

    .line 78
    invoke-interface {v1, v3, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 79
    .line 80
    .line 81
    add-int/lit8 v5, v5, 0x1

    .line 82
    .line 83
    goto :goto_1

    .line 84
    :catchall_0
    move-exception v2

    .line 85
    goto :goto_2

    .line 86
    :cond_2
    :try_start_2
    invoke-virtual {p0}, Ljava/io/ObjectInputStream;->close()V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_1
    .catch Ljava/lang/ClassNotFoundException; {:try_start_2 .. :try_end_2} :catch_0

    .line 87
    .line 88
    .line 89
    goto/16 :goto_7

    .line 90
    .line 91
    :catch_0
    move-exception p0

    .line 92
    goto :goto_5

    .line 93
    :catch_1
    move-exception p0

    .line 94
    goto :goto_6

    .line 95
    :goto_2
    :try_start_3
    throw v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 96
    :catchall_1
    move-exception v3

    .line 97
    :try_start_4
    invoke-static {p0, v2}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 98
    .line 99
    .line 100
    throw v3

    .line 101
    :cond_3
    new-instance p0, Ljava/io/DataInputStream;

    .line 102
    .line 103
    invoke-direct {p0, v2}, Ljava/io/DataInputStream;-><init>(Ljava/io/InputStream;)V
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_1
    .catch Ljava/lang/ClassNotFoundException; {:try_start_4 .. :try_end_4} :catch_0

    .line 104
    .line 105
    .line 106
    :try_start_5
    invoke-virtual {p0}, Ljava/io/DataInputStream;->readShort()S

    .line 107
    .line 108
    .line 109
    move-result v2

    .line 110
    const/16 v3, -0x5411

    .line 111
    .line 112
    if-ne v2, v3, :cond_6

    .line 113
    .line 114
    invoke-virtual {p0}, Ljava/io/DataInputStream;->readShort()S

    .line 115
    .line 116
    .line 117
    move-result v2

    .line 118
    const/4 v3, 0x1

    .line 119
    if-ne v2, v3, :cond_5

    .line 120
    .line 121
    invoke-virtual {p0}, Ljava/io/DataInputStream;->readInt()I

    .line 122
    .line 123
    .line 124
    move-result v2

    .line 125
    :goto_3
    if-ge v5, v2, :cond_4

    .line 126
    .line 127
    invoke-virtual {p0}, Ljava/io/DataInputStream;->readByte()B

    .line 128
    .line 129
    .line 130
    move-result v3

    .line 131
    invoke-static {p0, v3}, Lkp/b6;->c(Ljava/io/DataInputStream;B)Ljava/io/Serializable;

    .line 132
    .line 133
    .line 134
    move-result-object v3

    .line 135
    invoke-virtual {p0}, Ljava/io/DataInputStream;->readUTF()Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object v4

    .line 139
    invoke-interface {v1, v4, v3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 140
    .line 141
    .line 142
    add-int/lit8 v5, v5, 0x1

    .line 143
    .line 144
    goto :goto_3

    .line 145
    :catchall_2
    move-exception v2

    .line 146
    goto :goto_4

    .line 147
    :cond_4
    :try_start_6
    invoke-interface {p0}, Ljava/io/Closeable;->close()V
    :try_end_6
    .catch Ljava/io/IOException; {:try_start_6 .. :try_end_6} :catch_1
    .catch Ljava/lang/ClassNotFoundException; {:try_start_6 .. :try_end_6} :catch_0

    .line 148
    .line 149
    .line 150
    goto :goto_7

    .line 151
    :cond_5
    :try_start_7
    const-string v3, "Unsupported version number: "

    .line 152
    .line 153
    invoke-static {v2, v3}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 154
    .line 155
    .line 156
    move-result-object v2

    .line 157
    new-instance v3, Ljava/lang/IllegalStateException;

    .line 158
    .line 159
    invoke-virtual {v2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 160
    .line 161
    .line 162
    move-result-object v2

    .line 163
    invoke-direct {v3, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    throw v3

    .line 167
    :cond_6
    const-string v3, "Magic number doesn\'t match: "

    .line 168
    .line 169
    invoke-static {v2, v3}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 170
    .line 171
    .line 172
    move-result-object v2

    .line 173
    new-instance v3, Ljava/lang/IllegalStateException;

    .line 174
    .line 175
    invoke-virtual {v2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 176
    .line 177
    .line 178
    move-result-object v2

    .line 179
    invoke-direct {v3, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 180
    .line 181
    .line 182
    throw v3
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_2

    .line 183
    :goto_4
    :try_start_8
    throw v2
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_3

    .line 184
    :catchall_3
    move-exception v3

    .line 185
    :try_start_9
    invoke-static {p0, v2}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 186
    .line 187
    .line 188
    throw v3
    :try_end_9
    .catch Ljava/io/IOException; {:try_start_9 .. :try_end_9} :catch_1
    .catch Ljava/lang/ClassNotFoundException; {:try_start_9 .. :try_end_9} :catch_0

    .line 189
    :goto_5
    sget-object v2, Leb/i;->a:Ljava/lang/String;

    .line 190
    .line 191
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 192
    .line 193
    .line 194
    move-result-object v3

    .line 195
    invoke-virtual {v3, v2, v0, p0}, Leb/w;->c(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 196
    .line 197
    .line 198
    goto :goto_7

    .line 199
    :goto_6
    sget-object v2, Leb/i;->a:Ljava/lang/String;

    .line 200
    .line 201
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 202
    .line 203
    .line 204
    move-result-object v3

    .line 205
    invoke-virtual {v3, v2, v0, p0}, Leb/w;->c(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 206
    .line 207
    .line 208
    :goto_7
    new-instance p0, Leb/h;

    .line 209
    .line 210
    invoke-direct {p0, v1}, Leb/h;-><init>(Ljava/util/LinkedHashMap;)V

    .line 211
    .line 212
    .line 213
    return-object p0

    .line 214
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 215
    .line 216
    const-string v0, "Data cannot occupy more than 10240 bytes when serialized"

    .line 217
    .line 218
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 219
    .line 220
    .line 221
    throw p0
.end method

.method public static final c(Ljava/io/DataInputStream;B)Ljava/io/Serializable;
    .locals 5

    .line 1
    const/4 v0, 0x0

    .line 2
    if-nez p1, :cond_0

    .line 3
    .line 4
    return-object v0

    .line 5
    :cond_0
    const/4 v1, 0x1

    .line 6
    if-ne p1, v1, :cond_1

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/io/DataInputStream;->readBoolean()Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0

    .line 17
    :cond_1
    const/4 v1, 0x2

    .line 18
    if-ne p1, v1, :cond_2

    .line 19
    .line 20
    invoke-virtual {p0}, Ljava/io/DataInputStream;->readByte()B

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    invoke-static {p0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :cond_2
    const/4 v1, 0x3

    .line 30
    if-ne p1, v1, :cond_3

    .line 31
    .line 32
    invoke-virtual {p0}, Ljava/io/DataInputStream;->readInt()I

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0

    .line 41
    :cond_3
    const/4 v1, 0x4

    .line 42
    if-ne p1, v1, :cond_4

    .line 43
    .line 44
    invoke-virtual {p0}, Ljava/io/DataInputStream;->readLong()J

    .line 45
    .line 46
    .line 47
    move-result-wide p0

    .line 48
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0

    .line 53
    :cond_4
    const/4 v1, 0x5

    .line 54
    if-ne p1, v1, :cond_5

    .line 55
    .line 56
    invoke-virtual {p0}, Ljava/io/DataInputStream;->readFloat()F

    .line 57
    .line 58
    .line 59
    move-result p0

    .line 60
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    return-object p0

    .line 65
    :cond_5
    const/4 v1, 0x6

    .line 66
    if-ne p1, v1, :cond_6

    .line 67
    .line 68
    invoke-virtual {p0}, Ljava/io/DataInputStream;->readDouble()D

    .line 69
    .line 70
    .line 71
    move-result-wide p0

    .line 72
    invoke-static {p0, p1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    return-object p0

    .line 77
    :cond_6
    const/4 v1, 0x7

    .line 78
    if-ne p1, v1, :cond_7

    .line 79
    .line 80
    invoke-virtual {p0}, Ljava/io/DataInputStream;->readUTF()Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    return-object p0

    .line 85
    :cond_7
    const/16 v1, 0x8

    .line 86
    .line 87
    const/4 v2, 0x0

    .line 88
    if-ne p1, v1, :cond_9

    .line 89
    .line 90
    invoke-virtual {p0}, Ljava/io/DataInputStream;->readInt()I

    .line 91
    .line 92
    .line 93
    move-result p1

    .line 94
    new-array v0, p1, [Ljava/lang/Boolean;

    .line 95
    .line 96
    :goto_0
    if-ge v2, p1, :cond_8

    .line 97
    .line 98
    invoke-virtual {p0}, Ljava/io/DataInputStream;->readBoolean()Z

    .line 99
    .line 100
    .line 101
    move-result v1

    .line 102
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 103
    .line 104
    .line 105
    move-result-object v1

    .line 106
    aput-object v1, v0, v2

    .line 107
    .line 108
    add-int/lit8 v2, v2, 0x1

    .line 109
    .line 110
    goto :goto_0

    .line 111
    :cond_8
    return-object v0

    .line 112
    :cond_9
    const/16 v1, 0x9

    .line 113
    .line 114
    if-ne p1, v1, :cond_b

    .line 115
    .line 116
    invoke-virtual {p0}, Ljava/io/DataInputStream;->readInt()I

    .line 117
    .line 118
    .line 119
    move-result p1

    .line 120
    new-array v0, p1, [Ljava/lang/Byte;

    .line 121
    .line 122
    :goto_1
    if-ge v2, p1, :cond_a

    .line 123
    .line 124
    invoke-virtual {p0}, Ljava/io/DataInputStream;->readByte()B

    .line 125
    .line 126
    .line 127
    move-result v1

    .line 128
    invoke-static {v1}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 129
    .line 130
    .line 131
    move-result-object v1

    .line 132
    aput-object v1, v0, v2

    .line 133
    .line 134
    add-int/lit8 v2, v2, 0x1

    .line 135
    .line 136
    goto :goto_1

    .line 137
    :cond_a
    return-object v0

    .line 138
    :cond_b
    const/16 v1, 0xa

    .line 139
    .line 140
    if-ne p1, v1, :cond_d

    .line 141
    .line 142
    invoke-virtual {p0}, Ljava/io/DataInputStream;->readInt()I

    .line 143
    .line 144
    .line 145
    move-result p1

    .line 146
    new-array v0, p1, [Ljava/lang/Integer;

    .line 147
    .line 148
    :goto_2
    if-ge v2, p1, :cond_c

    .line 149
    .line 150
    invoke-virtual {p0}, Ljava/io/DataInputStream;->readInt()I

    .line 151
    .line 152
    .line 153
    move-result v1

    .line 154
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 155
    .line 156
    .line 157
    move-result-object v1

    .line 158
    aput-object v1, v0, v2

    .line 159
    .line 160
    add-int/lit8 v2, v2, 0x1

    .line 161
    .line 162
    goto :goto_2

    .line 163
    :cond_c
    return-object v0

    .line 164
    :cond_d
    const/16 v1, 0xb

    .line 165
    .line 166
    if-ne p1, v1, :cond_f

    .line 167
    .line 168
    invoke-virtual {p0}, Ljava/io/DataInputStream;->readInt()I

    .line 169
    .line 170
    .line 171
    move-result p1

    .line 172
    new-array v0, p1, [Ljava/lang/Long;

    .line 173
    .line 174
    :goto_3
    if-ge v2, p1, :cond_e

    .line 175
    .line 176
    invoke-virtual {p0}, Ljava/io/DataInputStream;->readLong()J

    .line 177
    .line 178
    .line 179
    move-result-wide v3

    .line 180
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 181
    .line 182
    .line 183
    move-result-object v1

    .line 184
    aput-object v1, v0, v2

    .line 185
    .line 186
    add-int/lit8 v2, v2, 0x1

    .line 187
    .line 188
    goto :goto_3

    .line 189
    :cond_e
    return-object v0

    .line 190
    :cond_f
    const/16 v1, 0xc

    .line 191
    .line 192
    if-ne p1, v1, :cond_11

    .line 193
    .line 194
    invoke-virtual {p0}, Ljava/io/DataInputStream;->readInt()I

    .line 195
    .line 196
    .line 197
    move-result p1

    .line 198
    new-array v0, p1, [Ljava/lang/Float;

    .line 199
    .line 200
    :goto_4
    if-ge v2, p1, :cond_10

    .line 201
    .line 202
    invoke-virtual {p0}, Ljava/io/DataInputStream;->readFloat()F

    .line 203
    .line 204
    .line 205
    move-result v1

    .line 206
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 207
    .line 208
    .line 209
    move-result-object v1

    .line 210
    aput-object v1, v0, v2

    .line 211
    .line 212
    add-int/lit8 v2, v2, 0x1

    .line 213
    .line 214
    goto :goto_4

    .line 215
    :cond_10
    return-object v0

    .line 216
    :cond_11
    const/16 v1, 0xd

    .line 217
    .line 218
    if-ne p1, v1, :cond_13

    .line 219
    .line 220
    invoke-virtual {p0}, Ljava/io/DataInputStream;->readInt()I

    .line 221
    .line 222
    .line 223
    move-result p1

    .line 224
    new-array v0, p1, [Ljava/lang/Double;

    .line 225
    .line 226
    :goto_5
    if-ge v2, p1, :cond_12

    .line 227
    .line 228
    invoke-virtual {p0}, Ljava/io/DataInputStream;->readDouble()D

    .line 229
    .line 230
    .line 231
    move-result-wide v3

    .line 232
    invoke-static {v3, v4}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 233
    .line 234
    .line 235
    move-result-object v1

    .line 236
    aput-object v1, v0, v2

    .line 237
    .line 238
    add-int/lit8 v2, v2, 0x1

    .line 239
    .line 240
    goto :goto_5

    .line 241
    :cond_12
    return-object v0

    .line 242
    :cond_13
    const/16 v1, 0xe

    .line 243
    .line 244
    if-ne p1, v1, :cond_16

    .line 245
    .line 246
    invoke-virtual {p0}, Ljava/io/DataInputStream;->readInt()I

    .line 247
    .line 248
    .line 249
    move-result p1

    .line 250
    new-array v1, p1, [Ljava/lang/String;

    .line 251
    .line 252
    :goto_6
    if-ge v2, p1, :cond_15

    .line 253
    .line 254
    invoke-virtual {p0}, Ljava/io/DataInputStream;->readUTF()Ljava/lang/String;

    .line 255
    .line 256
    .line 257
    move-result-object v3

    .line 258
    const-string v4, "androidx.work.Data-95ed6082-b8e9-46e8-a73f-ff56f00f5d9d"

    .line 259
    .line 260
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 261
    .line 262
    .line 263
    move-result v4

    .line 264
    if-eqz v4, :cond_14

    .line 265
    .line 266
    move-object v3, v0

    .line 267
    :cond_14
    aput-object v3, v1, v2

    .line 268
    .line 269
    add-int/lit8 v2, v2, 0x1

    .line 270
    .line 271
    goto :goto_6

    .line 272
    :cond_15
    return-object v1

    .line 273
    :cond_16
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 274
    .line 275
    const-string v0, "Unsupported type "

    .line 276
    .line 277
    invoke-static {p1, v0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 278
    .line 279
    .line 280
    move-result-object p1

    .line 281
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 282
    .line 283
    .line 284
    throw p0
.end method

.method public static d(Leb/h;)[B
    .locals 4

    .line 1
    const-string v0, "data"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Leb/h;->a:Ljava/util/HashMap;

    .line 7
    .line 8
    :try_start_0
    new-instance v0, Ljava/io/ByteArrayOutputStream;

    .line 9
    .line 10
    invoke-direct {v0}, Ljava/io/ByteArrayOutputStream;-><init>()V

    .line 11
    .line 12
    .line 13
    new-instance v1, Ljava/io/DataOutputStream;

    .line 14
    .line 15
    invoke-direct {v1, v0}, Ljava/io/DataOutputStream;-><init>(Ljava/io/OutputStream;)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 16
    .line 17
    .line 18
    const/16 v2, -0x5411

    .line 19
    .line 20
    :try_start_1
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->writeShort(I)V

    .line 21
    .line 22
    .line 23
    const/4 v2, 0x1

    .line 24
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->writeShort(I)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0}, Ljava/util/HashMap;->size()I

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->writeInt(I)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    if-eqz v2, :cond_0

    .line 47
    .line 48
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    check-cast v2, Ljava/util/Map$Entry;

    .line 53
    .line 54
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v3

    .line 58
    check-cast v3, Ljava/lang/String;

    .line 59
    .line 60
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    invoke-static {v1, v3, v2}, Lkp/b6;->e(Ljava/io/DataOutputStream;Ljava/lang/String;Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    goto :goto_0

    .line 68
    :catchall_0
    move-exception p0

    .line 69
    goto :goto_1

    .line 70
    :cond_0
    invoke-virtual {v1}, Ljava/io/DataOutputStream;->flush()V

    .line 71
    .line 72
    .line 73
    invoke-virtual {v1}, Ljava/io/DataOutputStream;->size()I

    .line 74
    .line 75
    .line 76
    move-result p0

    .line 77
    const/16 v2, 0x2800

    .line 78
    .line 79
    if-gt p0, v2, :cond_1

    .line 80
    .line 81
    invoke-virtual {v0}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 82
    .line 83
    .line 84
    move-result-object p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 85
    :try_start_2
    invoke-interface {v1}, Ljava/io/Closeable;->close()V

    .line 86
    .line 87
    .line 88
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0

    .line 89
    .line 90
    .line 91
    return-object p0

    .line 92
    :cond_1
    :try_start_3
    const-string p0, "Data cannot occupy more than 10240 bytes when serialized"

    .line 93
    .line 94
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 95
    .line 96
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    throw v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 100
    :goto_1
    :try_start_4
    throw p0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 101
    :catchall_1
    move-exception v0

    .line 102
    :try_start_5
    invoke-static {v1, p0}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 103
    .line 104
    .line 105
    throw v0
    :try_end_5
    .catch Ljava/io/IOException; {:try_start_5 .. :try_end_5} :catch_0

    .line 106
    :catch_0
    move-exception p0

    .line 107
    sget-object v0, Leb/i;->a:Ljava/lang/String;

    .line 108
    .line 109
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 110
    .line 111
    .line 112
    move-result-object v1

    .line 113
    const-string v2, "Error in Data#toByteArray: "

    .line 114
    .line 115
    invoke-virtual {v1, v0, v2, p0}, Leb/w;->c(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 116
    .line 117
    .line 118
    const/4 p0, 0x0

    .line 119
    new-array p0, p0, [B

    .line 120
    .line 121
    return-object p0
.end method

.method public static final e(Ljava/io/DataOutputStream;Ljava/lang/String;Ljava/lang/Object;)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    if-nez v1, :cond_0

    .line 7
    .line 8
    invoke-virtual {v0, v2}, Ljava/io/DataOutputStream;->writeByte(I)V

    .line 9
    .line 10
    .line 11
    goto/16 :goto_9

    .line 12
    .line 13
    :cond_0
    instance-of v3, v1, Ljava/lang/Boolean;

    .line 14
    .line 15
    if-eqz v3, :cond_1

    .line 16
    .line 17
    const/4 v2, 0x1

    .line 18
    invoke-virtual {v0, v2}, Ljava/io/DataOutputStream;->writeByte(I)V

    .line 19
    .line 20
    .line 21
    check-cast v1, Ljava/lang/Boolean;

    .line 22
    .line 23
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    invoke-virtual {v0, v1}, Ljava/io/DataOutputStream;->writeBoolean(Z)V

    .line 28
    .line 29
    .line 30
    goto/16 :goto_9

    .line 31
    .line 32
    :cond_1
    instance-of v3, v1, Ljava/lang/Byte;

    .line 33
    .line 34
    if-eqz v3, :cond_2

    .line 35
    .line 36
    const/4 v2, 0x2

    .line 37
    invoke-virtual {v0, v2}, Ljava/io/DataOutputStream;->writeByte(I)V

    .line 38
    .line 39
    .line 40
    check-cast v1, Ljava/lang/Number;

    .line 41
    .line 42
    invoke-virtual {v1}, Ljava/lang/Number;->byteValue()B

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    invoke-virtual {v0, v1}, Ljava/io/DataOutputStream;->writeByte(I)V

    .line 47
    .line 48
    .line 49
    goto/16 :goto_9

    .line 50
    .line 51
    :cond_2
    instance-of v3, v1, Ljava/lang/Integer;

    .line 52
    .line 53
    if-eqz v3, :cond_3

    .line 54
    .line 55
    const/4 v2, 0x3

    .line 56
    invoke-virtual {v0, v2}, Ljava/io/DataOutputStream;->writeByte(I)V

    .line 57
    .line 58
    .line 59
    check-cast v1, Ljava/lang/Number;

    .line 60
    .line 61
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    invoke-virtual {v0, v1}, Ljava/io/DataOutputStream;->writeInt(I)V

    .line 66
    .line 67
    .line 68
    goto/16 :goto_9

    .line 69
    .line 70
    :cond_3
    instance-of v3, v1, Ljava/lang/Long;

    .line 71
    .line 72
    if-eqz v3, :cond_4

    .line 73
    .line 74
    const/4 v2, 0x4

    .line 75
    invoke-virtual {v0, v2}, Ljava/io/DataOutputStream;->writeByte(I)V

    .line 76
    .line 77
    .line 78
    check-cast v1, Ljava/lang/Number;

    .line 79
    .line 80
    invoke-virtual {v1}, Ljava/lang/Number;->longValue()J

    .line 81
    .line 82
    .line 83
    move-result-wide v1

    .line 84
    invoke-virtual {v0, v1, v2}, Ljava/io/DataOutputStream;->writeLong(J)V

    .line 85
    .line 86
    .line 87
    goto/16 :goto_9

    .line 88
    .line 89
    :cond_4
    instance-of v3, v1, Ljava/lang/Float;

    .line 90
    .line 91
    if-eqz v3, :cond_5

    .line 92
    .line 93
    const/4 v2, 0x5

    .line 94
    invoke-virtual {v0, v2}, Ljava/io/DataOutputStream;->writeByte(I)V

    .line 95
    .line 96
    .line 97
    check-cast v1, Ljava/lang/Number;

    .line 98
    .line 99
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 100
    .line 101
    .line 102
    move-result v1

    .line 103
    invoke-virtual {v0, v1}, Ljava/io/DataOutputStream;->writeFloat(F)V

    .line 104
    .line 105
    .line 106
    goto/16 :goto_9

    .line 107
    .line 108
    :cond_5
    instance-of v3, v1, Ljava/lang/Double;

    .line 109
    .line 110
    if-eqz v3, :cond_6

    .line 111
    .line 112
    const/4 v2, 0x6

    .line 113
    invoke-virtual {v0, v2}, Ljava/io/DataOutputStream;->writeByte(I)V

    .line 114
    .line 115
    .line 116
    check-cast v1, Ljava/lang/Number;

    .line 117
    .line 118
    invoke-virtual {v1}, Ljava/lang/Number;->doubleValue()D

    .line 119
    .line 120
    .line 121
    move-result-wide v1

    .line 122
    invoke-virtual {v0, v1, v2}, Ljava/io/DataOutputStream;->writeDouble(D)V

    .line 123
    .line 124
    .line 125
    goto/16 :goto_9

    .line 126
    .line 127
    :cond_6
    instance-of v3, v1, Ljava/lang/String;

    .line 128
    .line 129
    if-eqz v3, :cond_7

    .line 130
    .line 131
    const/4 v2, 0x7

    .line 132
    invoke-virtual {v0, v2}, Ljava/io/DataOutputStream;->writeByte(I)V

    .line 133
    .line 134
    .line 135
    check-cast v1, Ljava/lang/String;

    .line 136
    .line 137
    invoke-virtual {v0, v1}, Ljava/io/DataOutputStream;->writeUTF(Ljava/lang/String;)V

    .line 138
    .line 139
    .line 140
    goto/16 :goto_9

    .line 141
    .line 142
    :cond_7
    instance-of v3, v1, [Ljava/lang/Object;

    .line 143
    .line 144
    const-string v4, "Unsupported value type "

    .line 145
    .line 146
    if-eqz v3, :cond_25

    .line 147
    .line 148
    check-cast v1, [Ljava/lang/Object;

    .line 149
    .line 150
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 151
    .line 152
    .line 153
    move-result-object v3

    .line 154
    sget-object v5, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 155
    .line 156
    invoke-virtual {v5, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 157
    .line 158
    .line 159
    move-result-object v3

    .line 160
    const-class v6, [Ljava/lang/Boolean;

    .line 161
    .line 162
    invoke-virtual {v5, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 163
    .line 164
    .line 165
    move-result-object v6

    .line 166
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 167
    .line 168
    .line 169
    move-result v6

    .line 170
    const/16 v7, 0xe

    .line 171
    .line 172
    const/16 v8, 0xd

    .line 173
    .line 174
    const/16 v9, 0xc

    .line 175
    .line 176
    const/16 v10, 0xb

    .line 177
    .line 178
    const/16 v11, 0xa

    .line 179
    .line 180
    const/16 v12, 0x9

    .line 181
    .line 182
    const/16 v13, 0x8

    .line 183
    .line 184
    if-eqz v6, :cond_8

    .line 185
    .line 186
    move v3, v13

    .line 187
    goto :goto_0

    .line 188
    :cond_8
    const-class v6, [Ljava/lang/Byte;

    .line 189
    .line 190
    invoke-virtual {v5, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 191
    .line 192
    .line 193
    move-result-object v6

    .line 194
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 195
    .line 196
    .line 197
    move-result v6

    .line 198
    if-eqz v6, :cond_9

    .line 199
    .line 200
    move v3, v12

    .line 201
    goto :goto_0

    .line 202
    :cond_9
    const-class v6, [Ljava/lang/Integer;

    .line 203
    .line 204
    invoke-virtual {v5, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 205
    .line 206
    .line 207
    move-result-object v6

    .line 208
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 209
    .line 210
    .line 211
    move-result v6

    .line 212
    if-eqz v6, :cond_a

    .line 213
    .line 214
    move v3, v11

    .line 215
    goto :goto_0

    .line 216
    :cond_a
    const-class v6, [Ljava/lang/Long;

    .line 217
    .line 218
    invoke-virtual {v5, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 219
    .line 220
    .line 221
    move-result-object v6

    .line 222
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 223
    .line 224
    .line 225
    move-result v6

    .line 226
    if-eqz v6, :cond_b

    .line 227
    .line 228
    move v3, v10

    .line 229
    goto :goto_0

    .line 230
    :cond_b
    const-class v6, [Ljava/lang/Float;

    .line 231
    .line 232
    invoke-virtual {v5, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 233
    .line 234
    .line 235
    move-result-object v6

    .line 236
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 237
    .line 238
    .line 239
    move-result v6

    .line 240
    if-eqz v6, :cond_c

    .line 241
    .line 242
    move v3, v9

    .line 243
    goto :goto_0

    .line 244
    :cond_c
    const-class v6, [Ljava/lang/Double;

    .line 245
    .line 246
    invoke-virtual {v5, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 247
    .line 248
    .line 249
    move-result-object v6

    .line 250
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 251
    .line 252
    .line 253
    move-result v6

    .line 254
    if-eqz v6, :cond_d

    .line 255
    .line 256
    move v3, v8

    .line 257
    goto :goto_0

    .line 258
    :cond_d
    const-class v6, [Ljava/lang/String;

    .line 259
    .line 260
    invoke-virtual {v5, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 261
    .line 262
    .line 263
    move-result-object v6

    .line 264
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 265
    .line 266
    .line 267
    move-result v3

    .line 268
    if-eqz v3, :cond_24

    .line 269
    .line 270
    move v3, v7

    .line 271
    :goto_0
    invoke-virtual {v0, v3}, Ljava/io/DataOutputStream;->writeByte(I)V

    .line 272
    .line 273
    .line 274
    array-length v4, v1

    .line 275
    invoke-virtual {v0, v4}, Ljava/io/DataOutputStream;->writeInt(I)V

    .line 276
    .line 277
    .line 278
    array-length v4, v1

    .line 279
    move v5, v2

    .line 280
    :goto_1
    if-ge v5, v4, :cond_23

    .line 281
    .line 282
    aget-object v6, v1, v5

    .line 283
    .line 284
    const/4 v14, 0x0

    .line 285
    if-ne v3, v13, :cond_10

    .line 286
    .line 287
    instance-of v15, v6, Ljava/lang/Boolean;

    .line 288
    .line 289
    if-eqz v15, :cond_e

    .line 290
    .line 291
    move-object v14, v6

    .line 292
    check-cast v14, Ljava/lang/Boolean;

    .line 293
    .line 294
    :cond_e
    if-eqz v14, :cond_f

    .line 295
    .line 296
    invoke-virtual {v14}, Ljava/lang/Boolean;->booleanValue()Z

    .line 297
    .line 298
    .line 299
    move-result v6

    .line 300
    goto :goto_2

    .line 301
    :cond_f
    move v6, v2

    .line 302
    :goto_2
    invoke-virtual {v0, v6}, Ljava/io/DataOutputStream;->writeBoolean(Z)V

    .line 303
    .line 304
    .line 305
    goto/16 :goto_8

    .line 306
    .line 307
    :cond_10
    if-ne v3, v12, :cond_13

    .line 308
    .line 309
    instance-of v15, v6, Ljava/lang/Byte;

    .line 310
    .line 311
    if-eqz v15, :cond_11

    .line 312
    .line 313
    move-object v14, v6

    .line 314
    check-cast v14, Ljava/lang/Byte;

    .line 315
    .line 316
    :cond_11
    if-eqz v14, :cond_12

    .line 317
    .line 318
    invoke-virtual {v14}, Ljava/lang/Byte;->byteValue()B

    .line 319
    .line 320
    .line 321
    move-result v6

    .line 322
    goto :goto_3

    .line 323
    :cond_12
    move v6, v2

    .line 324
    :goto_3
    invoke-virtual {v0, v6}, Ljava/io/DataOutputStream;->writeByte(I)V

    .line 325
    .line 326
    .line 327
    goto/16 :goto_8

    .line 328
    .line 329
    :cond_13
    if-ne v3, v11, :cond_16

    .line 330
    .line 331
    instance-of v15, v6, Ljava/lang/Integer;

    .line 332
    .line 333
    if-eqz v15, :cond_14

    .line 334
    .line 335
    move-object v14, v6

    .line 336
    check-cast v14, Ljava/lang/Integer;

    .line 337
    .line 338
    :cond_14
    if-eqz v14, :cond_15

    .line 339
    .line 340
    invoke-virtual {v14}, Ljava/lang/Integer;->intValue()I

    .line 341
    .line 342
    .line 343
    move-result v6

    .line 344
    goto :goto_4

    .line 345
    :cond_15
    move v6, v2

    .line 346
    :goto_4
    invoke-virtual {v0, v6}, Ljava/io/DataOutputStream;->writeInt(I)V

    .line 347
    .line 348
    .line 349
    goto :goto_8

    .line 350
    :cond_16
    if-ne v3, v10, :cond_19

    .line 351
    .line 352
    instance-of v15, v6, Ljava/lang/Long;

    .line 353
    .line 354
    if-eqz v15, :cond_17

    .line 355
    .line 356
    move-object v14, v6

    .line 357
    check-cast v14, Ljava/lang/Long;

    .line 358
    .line 359
    :cond_17
    if-eqz v14, :cond_18

    .line 360
    .line 361
    invoke-virtual {v14}, Ljava/lang/Long;->longValue()J

    .line 362
    .line 363
    .line 364
    move-result-wide v14

    .line 365
    goto :goto_5

    .line 366
    :cond_18
    const-wide/16 v14, 0x0

    .line 367
    .line 368
    :goto_5
    invoke-virtual {v0, v14, v15}, Ljava/io/DataOutputStream;->writeLong(J)V

    .line 369
    .line 370
    .line 371
    goto :goto_8

    .line 372
    :cond_19
    if-ne v3, v9, :cond_1c

    .line 373
    .line 374
    instance-of v15, v6, Ljava/lang/Float;

    .line 375
    .line 376
    if-eqz v15, :cond_1a

    .line 377
    .line 378
    move-object v14, v6

    .line 379
    check-cast v14, Ljava/lang/Float;

    .line 380
    .line 381
    :cond_1a
    if-eqz v14, :cond_1b

    .line 382
    .line 383
    invoke-virtual {v14}, Ljava/lang/Float;->floatValue()F

    .line 384
    .line 385
    .line 386
    move-result v6

    .line 387
    goto :goto_6

    .line 388
    :cond_1b
    const/4 v6, 0x0

    .line 389
    :goto_6
    invoke-virtual {v0, v6}, Ljava/io/DataOutputStream;->writeFloat(F)V

    .line 390
    .line 391
    .line 392
    goto :goto_8

    .line 393
    :cond_1c
    if-ne v3, v8, :cond_1f

    .line 394
    .line 395
    instance-of v15, v6, Ljava/lang/Double;

    .line 396
    .line 397
    if-eqz v15, :cond_1d

    .line 398
    .line 399
    move-object v14, v6

    .line 400
    check-cast v14, Ljava/lang/Double;

    .line 401
    .line 402
    :cond_1d
    if-eqz v14, :cond_1e

    .line 403
    .line 404
    invoke-virtual {v14}, Ljava/lang/Double;->doubleValue()D

    .line 405
    .line 406
    .line 407
    move-result-wide v14

    .line 408
    goto :goto_7

    .line 409
    :cond_1e
    const-wide/16 v14, 0x0

    .line 410
    .line 411
    :goto_7
    invoke-virtual {v0, v14, v15}, Ljava/io/DataOutputStream;->writeDouble(D)V

    .line 412
    .line 413
    .line 414
    goto :goto_8

    .line 415
    :cond_1f
    if-ne v3, v7, :cond_22

    .line 416
    .line 417
    instance-of v15, v6, Ljava/lang/String;

    .line 418
    .line 419
    if-eqz v15, :cond_20

    .line 420
    .line 421
    move-object v14, v6

    .line 422
    check-cast v14, Ljava/lang/String;

    .line 423
    .line 424
    :cond_20
    if-nez v14, :cond_21

    .line 425
    .line 426
    const-string v14, "androidx.work.Data-95ed6082-b8e9-46e8-a73f-ff56f00f5d9d"

    .line 427
    .line 428
    :cond_21
    invoke-virtual {v0, v14}, Ljava/io/DataOutputStream;->writeUTF(Ljava/lang/String;)V

    .line 429
    .line 430
    .line 431
    :cond_22
    :goto_8
    add-int/lit8 v5, v5, 0x1

    .line 432
    .line 433
    goto/16 :goto_1

    .line 434
    .line 435
    :cond_23
    :goto_9
    invoke-virtual/range {p0 .. p1}, Ljava/io/DataOutputStream;->writeUTF(Ljava/lang/String;)V

    .line 436
    .line 437
    .line 438
    return-void

    .line 439
    :cond_24
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 440
    .line 441
    new-instance v2, Ljava/lang/StringBuilder;

    .line 442
    .line 443
    invoke-direct {v2, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 444
    .line 445
    .line 446
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 447
    .line 448
    .line 449
    move-result-object v1

    .line 450
    invoke-virtual {v5, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 451
    .line 452
    .line 453
    move-result-object v1

    .line 454
    invoke-interface {v1}, Lhy0/d;->getQualifiedName()Ljava/lang/String;

    .line 455
    .line 456
    .line 457
    move-result-object v1

    .line 458
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 459
    .line 460
    .line 461
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 462
    .line 463
    .line 464
    move-result-object v1

    .line 465
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 466
    .line 467
    .line 468
    throw v0

    .line 469
    :cond_25
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 470
    .line 471
    new-instance v2, Ljava/lang/StringBuilder;

    .line 472
    .line 473
    invoke-direct {v2, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 474
    .line 475
    .line 476
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 477
    .line 478
    .line 479
    move-result-object v1

    .line 480
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 481
    .line 482
    invoke-virtual {v3, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 483
    .line 484
    .line 485
    move-result-object v1

    .line 486
    invoke-interface {v1}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 487
    .line 488
    .line 489
    move-result-object v1

    .line 490
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 491
    .line 492
    .line 493
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 494
    .line 495
    .line 496
    move-result-object v1

    .line 497
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 498
    .line 499
    .line 500
    throw v0
.end method
