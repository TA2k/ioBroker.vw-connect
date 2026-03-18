.class public final Lc8/q;
.super Lu7/g;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public i:[I

.field public j:[I


# virtual methods
.method public final d(Ljava/nio/ByteBuffer;)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Lc8/q;->j:[I

    .line 6
    .line 7
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    invoke-virtual {v1}, Ljava/nio/Buffer;->position()I

    .line 11
    .line 12
    .line 13
    move-result v3

    .line 14
    invoke-virtual {v1}, Ljava/nio/Buffer;->limit()I

    .line 15
    .line 16
    .line 17
    move-result v4

    .line 18
    sub-int v5, v4, v3

    .line 19
    .line 20
    iget-object v6, v0, Lu7/g;->b:Lu7/d;

    .line 21
    .line 22
    iget v6, v6, Lu7/d;->d:I

    .line 23
    .line 24
    div-int/2addr v5, v6

    .line 25
    iget-object v6, v0, Lu7/g;->c:Lu7/d;

    .line 26
    .line 27
    iget v6, v6, Lu7/d;->d:I

    .line 28
    .line 29
    mul-int/2addr v5, v6

    .line 30
    invoke-virtual {v0, v5}, Lu7/g;->k(I)Ljava/nio/ByteBuffer;

    .line 31
    .line 32
    .line 33
    move-result-object v5

    .line 34
    :goto_0
    if-ge v3, v4, :cond_e

    .line 35
    .line 36
    array-length v6, v2

    .line 37
    const/4 v8, 0x0

    .line 38
    :goto_1
    if-ge v8, v6, :cond_d

    .line 39
    .line 40
    aget v9, v2, v8

    .line 41
    .line 42
    iget-object v10, v0, Lu7/g;->b:Lu7/d;

    .line 43
    .line 44
    iget v10, v10, Lu7/d;->c:I

    .line 45
    .line 46
    invoke-static {v10}, Lw7/w;->n(I)I

    .line 47
    .line 48
    .line 49
    move-result v10

    .line 50
    mul-int/2addr v10, v9

    .line 51
    add-int/2addr v10, v3

    .line 52
    iget-object v9, v0, Lu7/g;->b:Lu7/d;

    .line 53
    .line 54
    iget v9, v9, Lu7/d;->c:I

    .line 55
    .line 56
    const/4 v11, 0x2

    .line 57
    if-eq v9, v11, :cond_c

    .line 58
    .line 59
    const/4 v11, 0x3

    .line 60
    if-eq v9, v11, :cond_b

    .line 61
    .line 62
    const/4 v12, 0x4

    .line 63
    if-eq v9, v12, :cond_a

    .line 64
    .line 65
    const/16 v12, 0x15

    .line 66
    .line 67
    if-eq v9, v12, :cond_2

    .line 68
    .line 69
    const/16 v12, 0x16

    .line 70
    .line 71
    if-eq v9, v12, :cond_1

    .line 72
    .line 73
    const/high16 v12, 0x10000000

    .line 74
    .line 75
    if-eq v9, v12, :cond_c

    .line 76
    .line 77
    const/high16 v12, 0x50000000

    .line 78
    .line 79
    if-eq v9, v12, :cond_2

    .line 80
    .line 81
    const/high16 v11, 0x60000000

    .line 82
    .line 83
    if-ne v9, v11, :cond_0

    .line 84
    .line 85
    goto :goto_2

    .line 86
    :cond_0
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 87
    .line 88
    new-instance v2, Ljava/lang/StringBuilder;

    .line 89
    .line 90
    const-string v3, "Unexpected encoding: "

    .line 91
    .line 92
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    iget-object v0, v0, Lu7/g;->b:Lu7/d;

    .line 96
    .line 97
    iget v0, v0, Lu7/d;->c:I

    .line 98
    .line 99
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object v0

    .line 106
    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    throw v1

    .line 110
    :cond_1
    :goto_2
    invoke-virtual {v1, v10}, Ljava/nio/ByteBuffer;->getInt(I)I

    .line 111
    .line 112
    .line 113
    move-result v9

    .line 114
    invoke-virtual {v5, v9}, Ljava/nio/ByteBuffer;->putInt(I)Ljava/nio/ByteBuffer;

    .line 115
    .line 116
    .line 117
    goto/16 :goto_b

    .line 118
    .line 119
    :cond_2
    invoke-virtual {v1}, Ljava/nio/ByteBuffer;->order()Ljava/nio/ByteOrder;

    .line 120
    .line 121
    .line 122
    move-result-object v9

    .line 123
    sget-object v12, Ljava/nio/ByteOrder;->BIG_ENDIAN:Ljava/nio/ByteOrder;

    .line 124
    .line 125
    if-ne v9, v12, :cond_3

    .line 126
    .line 127
    move v9, v10

    .line 128
    goto :goto_3

    .line 129
    :cond_3
    add-int/lit8 v9, v10, 0x2

    .line 130
    .line 131
    :goto_3
    invoke-virtual {v1, v9}, Ljava/nio/ByteBuffer;->get(I)B

    .line 132
    .line 133
    .line 134
    move-result v9

    .line 135
    add-int/lit8 v13, v10, 0x1

    .line 136
    .line 137
    invoke-virtual {v1, v13}, Ljava/nio/ByteBuffer;->get(I)B

    .line 138
    .line 139
    .line 140
    move-result v13

    .line 141
    invoke-virtual {v1}, Ljava/nio/ByteBuffer;->order()Ljava/nio/ByteOrder;

    .line 142
    .line 143
    .line 144
    move-result-object v14

    .line 145
    if-ne v14, v12, :cond_4

    .line 146
    .line 147
    add-int/lit8 v10, v10, 0x2

    .line 148
    .line 149
    :cond_4
    invoke-virtual {v1, v10}, Ljava/nio/ByteBuffer;->get(I)B

    .line 150
    .line 151
    .line 152
    move-result v10

    .line 153
    shl-int/lit8 v9, v9, 0x18

    .line 154
    .line 155
    const/high16 v14, -0x1000000

    .line 156
    .line 157
    and-int/2addr v9, v14

    .line 158
    shl-int/lit8 v13, v13, 0x10

    .line 159
    .line 160
    const/high16 v15, 0xff0000

    .line 161
    .line 162
    and-int/2addr v13, v15

    .line 163
    or-int/2addr v9, v13

    .line 164
    shl-int/lit8 v10, v10, 0x8

    .line 165
    .line 166
    const v13, 0xff00

    .line 167
    .line 168
    .line 169
    and-int/2addr v10, v13

    .line 170
    or-int/2addr v9, v10

    .line 171
    shr-int/lit8 v9, v9, 0x8

    .line 172
    .line 173
    and-int v10, v9, v14

    .line 174
    .line 175
    const/4 v14, 0x1

    .line 176
    if-eqz v10, :cond_6

    .line 177
    .line 178
    const/high16 v10, -0x800000    # Float.NEGATIVE_INFINITY

    .line 179
    .line 180
    and-int v7, v9, v10

    .line 181
    .line 182
    if-ne v7, v10, :cond_5

    .line 183
    .line 184
    goto :goto_4

    .line 185
    :cond_5
    const/4 v7, 0x0

    .line 186
    goto :goto_5

    .line 187
    :cond_6
    :goto_4
    move v7, v14

    .line 188
    :goto_5
    new-instance v10, Ljava/lang/StringBuilder;

    .line 189
    .line 190
    move/from16 v16, v13

    .line 191
    .line 192
    const-string v13, "Value out of range of 24-bit integer: "

    .line 193
    .line 194
    invoke-direct {v10, v13}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 195
    .line 196
    .line 197
    invoke-static {v9}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    .line 198
    .line 199
    .line 200
    move-result-object v13

    .line 201
    invoke-virtual {v10, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 202
    .line 203
    .line 204
    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 205
    .line 206
    .line 207
    move-result-object v10

    .line 208
    invoke-static {v7, v10}, Lw7/a;->d(ZLjava/lang/String;)V

    .line 209
    .line 210
    .line 211
    invoke-virtual {v5}, Ljava/nio/Buffer;->remaining()I

    .line 212
    .line 213
    .line 214
    move-result v7

    .line 215
    if-lt v7, v11, :cond_7

    .line 216
    .line 217
    goto :goto_6

    .line 218
    :cond_7
    const/4 v14, 0x0

    .line 219
    :goto_6
    invoke-static {v14}, Lw7/a;->c(Z)V

    .line 220
    .line 221
    .line 222
    invoke-virtual {v5}, Ljava/nio/ByteBuffer;->order()Ljava/nio/ByteOrder;

    .line 223
    .line 224
    .line 225
    move-result-object v7

    .line 226
    if-ne v7, v12, :cond_8

    .line 227
    .line 228
    and-int v7, v9, v15

    .line 229
    .line 230
    shr-int/lit8 v7, v7, 0x10

    .line 231
    .line 232
    :goto_7
    int-to-byte v7, v7

    .line 233
    goto :goto_8

    .line 234
    :cond_8
    and-int/lit16 v7, v9, 0xff

    .line 235
    .line 236
    goto :goto_7

    .line 237
    :goto_8
    and-int v10, v9, v16

    .line 238
    .line 239
    shr-int/lit8 v10, v10, 0x8

    .line 240
    .line 241
    int-to-byte v10, v10

    .line 242
    invoke-virtual {v5}, Ljava/nio/ByteBuffer;->order()Ljava/nio/ByteOrder;

    .line 243
    .line 244
    .line 245
    move-result-object v11

    .line 246
    if-ne v11, v12, :cond_9

    .line 247
    .line 248
    and-int/lit16 v9, v9, 0xff

    .line 249
    .line 250
    :goto_9
    int-to-byte v9, v9

    .line 251
    goto :goto_a

    .line 252
    :cond_9
    and-int/2addr v9, v15

    .line 253
    shr-int/lit8 v9, v9, 0x10

    .line 254
    .line 255
    goto :goto_9

    .line 256
    :goto_a
    invoke-virtual {v5, v7}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 257
    .line 258
    .line 259
    move-result-object v7

    .line 260
    invoke-virtual {v7, v10}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 261
    .line 262
    .line 263
    move-result-object v7

    .line 264
    invoke-virtual {v7, v9}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 265
    .line 266
    .line 267
    goto :goto_b

    .line 268
    :cond_a
    invoke-virtual {v1, v10}, Ljava/nio/ByteBuffer;->getFloat(I)F

    .line 269
    .line 270
    .line 271
    move-result v7

    .line 272
    invoke-virtual {v5, v7}, Ljava/nio/ByteBuffer;->putFloat(F)Ljava/nio/ByteBuffer;

    .line 273
    .line 274
    .line 275
    goto :goto_b

    .line 276
    :cond_b
    invoke-virtual {v1, v10}, Ljava/nio/ByteBuffer;->get(I)B

    .line 277
    .line 278
    .line 279
    move-result v7

    .line 280
    invoke-virtual {v5, v7}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 281
    .line 282
    .line 283
    goto :goto_b

    .line 284
    :cond_c
    invoke-virtual {v1, v10}, Ljava/nio/ByteBuffer;->getShort(I)S

    .line 285
    .line 286
    .line 287
    move-result v7

    .line 288
    invoke-virtual {v5, v7}, Ljava/nio/ByteBuffer;->putShort(S)Ljava/nio/ByteBuffer;

    .line 289
    .line 290
    .line 291
    :goto_b
    add-int/lit8 v8, v8, 0x1

    .line 292
    .line 293
    goto/16 :goto_1

    .line 294
    .line 295
    :cond_d
    iget-object v6, v0, Lu7/g;->b:Lu7/d;

    .line 296
    .line 297
    iget v6, v6, Lu7/d;->d:I

    .line 298
    .line 299
    add-int/2addr v3, v6

    .line 300
    goto/16 :goto_0

    .line 301
    .line 302
    :cond_e
    invoke-virtual {v1, v4}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    .line 303
    .line 304
    .line 305
    invoke-virtual {v5}, Ljava/nio/ByteBuffer;->flip()Ljava/nio/Buffer;

    .line 306
    .line 307
    .line 308
    return-void
.end method

.method public final g(Lu7/d;)Lu7/d;
    .locals 7

    .line 1
    iget v0, p1, Lu7/d;->c:I

    .line 2
    .line 3
    iget-object p0, p0, Lc8/q;->i:[I

    .line 4
    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    sget-object p0, Lu7/d;->e:Lu7/d;

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    iget v1, p1, Lu7/d;->b:I

    .line 11
    .line 12
    invoke-static {v0}, Lw7/w;->A(I)Z

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    if-eqz v2, :cond_6

    .line 17
    .line 18
    array-length v2, p0

    .line 19
    const/4 v3, 0x0

    .line 20
    const/4 v4, 0x1

    .line 21
    if-eq v1, v2, :cond_1

    .line 22
    .line 23
    move v2, v4

    .line 24
    goto :goto_0

    .line 25
    :cond_1
    move v2, v3

    .line 26
    :goto_0
    move v5, v3

    .line 27
    :goto_1
    array-length v6, p0

    .line 28
    if-ge v5, v6, :cond_4

    .line 29
    .line 30
    aget v6, p0, v5

    .line 31
    .line 32
    if-ge v6, v1, :cond_3

    .line 33
    .line 34
    if-eq v6, v5, :cond_2

    .line 35
    .line 36
    move v6, v4

    .line 37
    goto :goto_2

    .line 38
    :cond_2
    move v6, v3

    .line 39
    :goto_2
    or-int/2addr v2, v6

    .line 40
    add-int/lit8 v5, v5, 0x1

    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_3
    new-instance v0, Lu7/e;

    .line 44
    .line 45
    new-instance v1, Ljava/lang/StringBuilder;

    .line 46
    .line 47
    const-string v2, "Channel map ("

    .line 48
    .line 49
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    invoke-static {p0}, Ljava/util/Arrays;->toString([I)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    const-string p0, ") trying to access non-existent input channel."

    .line 60
    .line 61
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    invoke-direct {v0, p0, p1}, Lu7/e;-><init>(Ljava/lang/String;Lu7/d;)V

    .line 69
    .line 70
    .line 71
    throw v0

    .line 72
    :cond_4
    if-eqz v2, :cond_5

    .line 73
    .line 74
    new-instance v1, Lu7/d;

    .line 75
    .line 76
    iget p1, p1, Lu7/d;->a:I

    .line 77
    .line 78
    array-length p0, p0

    .line 79
    invoke-direct {v1, p1, p0, v0}, Lu7/d;-><init>(III)V

    .line 80
    .line 81
    .line 82
    return-object v1

    .line 83
    :cond_5
    sget-object p0, Lu7/d;->e:Lu7/d;

    .line 84
    .line 85
    return-object p0

    .line 86
    :cond_6
    new-instance p0, Lu7/e;

    .line 87
    .line 88
    invoke-direct {p0, p1}, Lu7/e;-><init>(Lu7/d;)V

    .line 89
    .line 90
    .line 91
    throw p0
.end method

.method public final h()V
    .locals 1

    .line 1
    iget-object v0, p0, Lc8/q;->i:[I

    .line 2
    .line 3
    iput-object v0, p0, Lc8/q;->j:[I

    .line 4
    .line 5
    return-void
.end method

.method public final j()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Lc8/q;->j:[I

    .line 3
    .line 4
    iput-object v0, p0, Lc8/q;->i:[I

    .line 5
    .line 6
    return-void
.end method
