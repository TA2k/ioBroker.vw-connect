.class public final Lwz0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lcx0/a;

.field public final b:Ljava/nio/charset/CharsetDecoder;

.field public final c:Ljava/nio/ByteBuffer;

.field public d:Z

.field public e:C


# direct methods
.method public constructor <init>(Lcx0/a;Ljava/nio/charset/Charset;)V
    .locals 2

    .line 1
    const-string v0, "charset"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lwz0/h;->a:Lcx0/a;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/nio/charset/Charset;->newDecoder()Ljava/nio/charset/CharsetDecoder;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    sget-object p2, Ljava/nio/charset/CodingErrorAction;->REPLACE:Ljava/nio/charset/CodingErrorAction;

    .line 16
    .line 17
    invoke-virtual {p1, p2}, Ljava/nio/charset/CharsetDecoder;->onMalformedInput(Ljava/nio/charset/CodingErrorAction;)Ljava/nio/charset/CharsetDecoder;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    invoke-virtual {p1, p2}, Ljava/nio/charset/CharsetDecoder;->onUnmappableCharacter(Ljava/nio/charset/CodingErrorAction;)Ljava/nio/charset/CharsetDecoder;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    const-string p2, "onUnmappableCharacter(...)"

    .line 26
    .line 27
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    iput-object p1, p0, Lwz0/h;->b:Ljava/nio/charset/CharsetDecoder;

    .line 31
    .line 32
    sget-object p1, Lwz0/e;->f:Lwz0/e;

    .line 33
    .line 34
    monitor-enter p1

    .line 35
    :try_start_0
    iget-object p2, p1, Lap0/o;->e:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p2, Lmx0/l;

    .line 38
    .line 39
    invoke-virtual {p2}, Lmx0/l;->isEmpty()Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    const/4 v1, 0x0

    .line 44
    if-eqz v0, :cond_0

    .line 45
    .line 46
    move-object p2, v1

    .line 47
    goto :goto_0

    .line 48
    :cond_0
    invoke-virtual {p2}, Lmx0/l;->removeLast()Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object p2

    .line 52
    :goto_0
    check-cast p2, [B
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 53
    .line 54
    if-eqz p2, :cond_1

    .line 55
    .line 56
    move-object v1, p2

    .line 57
    :cond_1
    monitor-exit p1

    .line 58
    if-nez v1, :cond_2

    .line 59
    .line 60
    const/16 p1, 0x2004

    .line 61
    .line 62
    new-array v1, p1, [B

    .line 63
    .line 64
    :cond_2
    invoke-static {v1}, Ljava/nio/ByteBuffer;->wrap([B)Ljava/nio/ByteBuffer;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    const-string p2, "wrap(...)"

    .line 69
    .line 70
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    iput-object p1, p0, Lwz0/h;->c:Ljava/nio/ByteBuffer;

    .line 74
    .line 75
    invoke-virtual {p1}, Ljava/nio/ByteBuffer;->flip()Ljava/nio/Buffer;

    .line 76
    .line 77
    .line 78
    return-void

    .line 79
    :catchall_0
    move-exception p0

    .line 80
    monitor-exit p1

    .line 81
    throw p0
.end method


# virtual methods
.method public final a([CII)I
    .locals 10

    .line 1
    const/4 v0, 0x0

    .line 2
    if-nez p3, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    if-ltz p2, :cond_15

    .line 6
    .line 7
    array-length v1, p1

    .line 8
    if-ge p2, v1, :cond_15

    .line 9
    .line 10
    if-ltz p3, :cond_15

    .line 11
    .line 12
    add-int v1, p2, p3

    .line 13
    .line 14
    array-length v2, p1

    .line 15
    if-gt v1, v2, :cond_15

    .line 16
    .line 17
    iget-boolean v1, p0, Lwz0/h;->d:Z

    .line 18
    .line 19
    const/4 v2, 0x1

    .line 20
    if-eqz v1, :cond_2

    .line 21
    .line 22
    iget-char v1, p0, Lwz0/h;->e:C

    .line 23
    .line 24
    aput-char v1, p1, p2

    .line 25
    .line 26
    add-int/lit8 p2, p2, 0x1

    .line 27
    .line 28
    add-int/lit8 p3, p3, -0x1

    .line 29
    .line 30
    iput-boolean v0, p0, Lwz0/h;->d:Z

    .line 31
    .line 32
    if-nez p3, :cond_1

    .line 33
    .line 34
    return v2

    .line 35
    :cond_1
    move v1, v2

    .line 36
    goto :goto_0

    .line 37
    :cond_2
    move v1, v0

    .line 38
    :goto_0
    const/4 v3, -0x1

    .line 39
    if-ne p3, v2, :cond_9

    .line 40
    .line 41
    iget-boolean p3, p0, Lwz0/h;->d:Z

    .line 42
    .line 43
    if-eqz p3, :cond_3

    .line 44
    .line 45
    iput-boolean v0, p0, Lwz0/h;->d:Z

    .line 46
    .line 47
    iget-char p0, p0, Lwz0/h;->e:C

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_3
    const/4 p3, 0x2

    .line 51
    new-array v4, p3, [C

    .line 52
    .line 53
    invoke-virtual {p0, v4, v0, p3}, Lwz0/h;->a([CII)I

    .line 54
    .line 55
    .line 56
    move-result v5

    .line 57
    if-eq v5, v3, :cond_6

    .line 58
    .line 59
    if-eq v5, v2, :cond_5

    .line 60
    .line 61
    if-ne v5, p3, :cond_4

    .line 62
    .line 63
    aget-char p3, v4, v2

    .line 64
    .line 65
    iput-char p3, p0, Lwz0/h;->e:C

    .line 66
    .line 67
    iput-boolean v2, p0, Lwz0/h;->d:Z

    .line 68
    .line 69
    aget-char p0, v4, v0

    .line 70
    .line 71
    goto :goto_1

    .line 72
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 73
    .line 74
    new-instance p1, Ljava/lang/StringBuilder;

    .line 75
    .line 76
    const-string p2, "Unreachable state: "

    .line 77
    .line 78
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {p1, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    throw p0

    .line 96
    :cond_5
    aget-char p0, v4, v0

    .line 97
    .line 98
    goto :goto_1

    .line 99
    :cond_6
    move p0, v3

    .line 100
    :goto_1
    if-ne p0, v3, :cond_8

    .line 101
    .line 102
    if-nez v1, :cond_7

    .line 103
    .line 104
    return v3

    .line 105
    :cond_7
    return v1

    .line 106
    :cond_8
    int-to-char p0, p0

    .line 107
    aput-char p0, p1, p2

    .line 108
    .line 109
    add-int/2addr v1, v2

    .line 110
    return v1

    .line 111
    :cond_9
    invoke-static {p1, p2, p3}, Ljava/nio/CharBuffer;->wrap([CII)Ljava/nio/CharBuffer;

    .line 112
    .line 113
    .line 114
    move-result-object p1

    .line 115
    invoke-virtual {p1}, Ljava/nio/Buffer;->position()I

    .line 116
    .line 117
    .line 118
    move-result p2

    .line 119
    if-eqz p2, :cond_a

    .line 120
    .line 121
    invoke-virtual {p1}, Ljava/nio/CharBuffer;->slice()Ljava/nio/CharBuffer;

    .line 122
    .line 123
    .line 124
    move-result-object p1

    .line 125
    :cond_a
    move-object v4, p1

    .line 126
    move p1, v0

    .line 127
    :cond_b
    :goto_2
    iget-object p2, p0, Lwz0/h;->b:Ljava/nio/charset/CharsetDecoder;

    .line 128
    .line 129
    iget-object p3, p0, Lwz0/h;->c:Ljava/nio/ByteBuffer;

    .line 130
    .line 131
    invoke-virtual {p2, p3, v4, p1}, Ljava/nio/charset/CharsetDecoder;->decode(Ljava/nio/ByteBuffer;Ljava/nio/CharBuffer;Z)Ljava/nio/charset/CoderResult;

    .line 132
    .line 133
    .line 134
    move-result-object v5

    .line 135
    invoke-virtual {v5}, Ljava/nio/charset/CoderResult;->isUnderflow()Z

    .line 136
    .line 137
    .line 138
    move-result v6

    .line 139
    if-eqz v6, :cond_f

    .line 140
    .line 141
    if-nez p1, :cond_10

    .line 142
    .line 143
    invoke-virtual {v4}, Ljava/nio/Buffer;->hasRemaining()Z

    .line 144
    .line 145
    .line 146
    move-result v5

    .line 147
    if-eqz v5, :cond_10

    .line 148
    .line 149
    invoke-virtual {p3}, Ljava/nio/ByteBuffer;->compact()Ljava/nio/ByteBuffer;

    .line 150
    .line 151
    .line 152
    :try_start_0
    invoke-virtual {p3}, Ljava/nio/Buffer;->limit()I

    .line 153
    .line 154
    .line 155
    move-result v5

    .line 156
    invoke-virtual {p3}, Ljava/nio/Buffer;->position()I

    .line 157
    .line 158
    .line 159
    move-result v6

    .line 160
    if-gt v6, v5, :cond_c

    .line 161
    .line 162
    sub-int/2addr v5, v6

    .line 163
    goto :goto_3

    .line 164
    :cond_c
    move v5, v0

    .line 165
    :goto_3
    iget-object v7, p0, Lwz0/h;->a:Lcx0/a;

    .line 166
    .line 167
    invoke-virtual {p3}, Ljava/nio/ByteBuffer;->array()[B

    .line 168
    .line 169
    .line 170
    move-result-object v8

    .line 171
    invoke-virtual {p3}, Ljava/nio/ByteBuffer;->arrayOffset()I

    .line 172
    .line 173
    .line 174
    move-result v9

    .line 175
    add-int/2addr v9, v6

    .line 176
    invoke-virtual {v7, v8, v9, v5}, Lcx0/a;->read([BII)I

    .line 177
    .line 178
    .line 179
    move-result v5
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 180
    if-gez v5, :cond_d

    .line 181
    .line 182
    invoke-virtual {p3}, Ljava/nio/ByteBuffer;->flip()Ljava/nio/Buffer;

    .line 183
    .line 184
    .line 185
    goto :goto_4

    .line 186
    :cond_d
    add-int/2addr v6, v5

    .line 187
    :try_start_1
    invoke-virtual {p3, v6}, Ljava/nio/Buffer;->position(I)Ljava/nio/Buffer;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 188
    .line 189
    .line 190
    invoke-virtual {p3}, Ljava/nio/ByteBuffer;->flip()Ljava/nio/Buffer;

    .line 191
    .line 192
    .line 193
    invoke-virtual {p3}, Ljava/nio/Buffer;->remaining()I

    .line 194
    .line 195
    .line 196
    move-result v5

    .line 197
    :goto_4
    if-gez v5, :cond_b

    .line 198
    .line 199
    invoke-virtual {v4}, Ljava/nio/Buffer;->position()I

    .line 200
    .line 201
    .line 202
    move-result p1

    .line 203
    if-nez p1, :cond_e

    .line 204
    .line 205
    invoke-virtual {p3}, Ljava/nio/Buffer;->hasRemaining()Z

    .line 206
    .line 207
    .line 208
    move-result p1

    .line 209
    if-eqz p1, :cond_11

    .line 210
    .line 211
    :cond_e
    invoke-virtual {p2}, Ljava/nio/charset/CharsetDecoder;->reset()Ljava/nio/charset/CharsetDecoder;

    .line 212
    .line 213
    .line 214
    move p1, v2

    .line 215
    goto :goto_2

    .line 216
    :catchall_0
    move-exception p0

    .line 217
    invoke-virtual {p3}, Ljava/nio/ByteBuffer;->flip()Ljava/nio/Buffer;

    .line 218
    .line 219
    .line 220
    throw p0

    .line 221
    :cond_f
    invoke-virtual {v5}, Ljava/nio/charset/CoderResult;->isOverflow()Z

    .line 222
    .line 223
    .line 224
    move-result p3

    .line 225
    if-eqz p3, :cond_14

    .line 226
    .line 227
    invoke-virtual {v4}, Ljava/nio/Buffer;->position()I

    .line 228
    .line 229
    .line 230
    :cond_10
    move v2, p1

    .line 231
    :cond_11
    if-eqz v2, :cond_12

    .line 232
    .line 233
    invoke-virtual {p2}, Ljava/nio/charset/CharsetDecoder;->reset()Ljava/nio/charset/CharsetDecoder;

    .line 234
    .line 235
    .line 236
    :cond_12
    invoke-virtual {v4}, Ljava/nio/Buffer;->position()I

    .line 237
    .line 238
    .line 239
    move-result p0

    .line 240
    if-nez p0, :cond_13

    .line 241
    .line 242
    goto :goto_5

    .line 243
    :cond_13
    invoke-virtual {v4}, Ljava/nio/Buffer;->position()I

    .line 244
    .line 245
    .line 246
    move-result v3

    .line 247
    :goto_5
    add-int/2addr v3, v1

    .line 248
    return v3

    .line 249
    :cond_14
    invoke-virtual {v5}, Ljava/nio/charset/CoderResult;->throwException()V

    .line 250
    .line 251
    .line 252
    goto :goto_2

    .line 253
    :cond_15
    const-string p0, "Unexpected arguments: "

    .line 254
    .line 255
    const-string v0, ", "

    .line 256
    .line 257
    invoke-static {p2, p3, p0, v0, v0}, Lu/w;->j(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 258
    .line 259
    .line 260
    move-result-object p0

    .line 261
    array-length p1, p1

    .line 262
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 263
    .line 264
    .line 265
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 266
    .line 267
    .line 268
    move-result-object p0

    .line 269
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 270
    .line 271
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 272
    .line 273
    .line 274
    move-result-object p0

    .line 275
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 276
    .line 277
    .line 278
    throw p1
.end method
