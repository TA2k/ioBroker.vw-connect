.class public final Lj9/k;
.super Lj9/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public n:Lca/m;

.field public o:I

.field public p:Z

.field public q:Lo8/a0;

.field public r:Lhu/q;


# virtual methods
.method public final a(J)V
    .locals 2

    .line 1
    iput-wide p1, p0, Lj9/j;->g:J

    .line 2
    .line 3
    const-wide/16 v0, 0x0

    .line 4
    .line 5
    cmp-long p1, p1, v0

    .line 6
    .line 7
    const/4 p2, 0x0

    .line 8
    if-eqz p1, :cond_0

    .line 9
    .line 10
    const/4 p1, 0x1

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    move p1, p2

    .line 13
    :goto_0
    iput-boolean p1, p0, Lj9/k;->p:Z

    .line 14
    .line 15
    iget-object p1, p0, Lj9/k;->q:Lo8/a0;

    .line 16
    .line 17
    if-eqz p1, :cond_1

    .line 18
    .line 19
    iget p2, p1, Lo8/a0;->e:I

    .line 20
    .line 21
    :cond_1
    iput p2, p0, Lj9/k;->o:I

    .line 22
    .line 23
    return-void
.end method

.method public final b(Lw7/p;)J
    .locals 12

    .line 1
    iget-object v0, p1, Lw7/p;->a:[B

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    aget-byte v0, v0, v1

    .line 5
    .line 6
    and-int/lit8 v2, v0, 0x1

    .line 7
    .line 8
    const/4 v3, 0x1

    .line 9
    if-ne v2, v3, :cond_0

    .line 10
    .line 11
    const-wide/16 p0, -0x1

    .line 12
    .line 13
    return-wide p0

    .line 14
    :cond_0
    iget-object v2, p0, Lj9/k;->n:Lca/m;

    .line 15
    .line 16
    invoke-static {v2}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    iget v4, v2, Lca/m;->d:I

    .line 20
    .line 21
    iget-object v5, v2, Lca/m;->e:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v5, Lo8/a0;

    .line 24
    .line 25
    shr-int/2addr v0, v3

    .line 26
    const/16 v6, 0xff

    .line 27
    .line 28
    const/16 v7, 0x8

    .line 29
    .line 30
    rsub-int/lit8 v4, v4, 0x8

    .line 31
    .line 32
    ushr-int v4, v6, v4

    .line 33
    .line 34
    and-int/2addr v0, v4

    .line 35
    iget-object v2, v2, Lca/m;->h:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v2, [La8/t1;

    .line 38
    .line 39
    aget-object v0, v2, v0

    .line 40
    .line 41
    iget-boolean v0, v0, La8/t1;->b:Z

    .line 42
    .line 43
    if-nez v0, :cond_1

    .line 44
    .line 45
    iget v0, v5, Lo8/a0;->e:I

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_1
    iget v0, v5, Lo8/a0;->f:I

    .line 49
    .line 50
    :goto_0
    iget-boolean v2, p0, Lj9/k;->p:Z

    .line 51
    .line 52
    if-eqz v2, :cond_2

    .line 53
    .line 54
    iget v1, p0, Lj9/k;->o:I

    .line 55
    .line 56
    add-int/2addr v1, v0

    .line 57
    div-int/lit8 v1, v1, 0x4

    .line 58
    .line 59
    :cond_2
    int-to-long v1, v1

    .line 60
    iget-object v4, p1, Lw7/p;->a:[B

    .line 61
    .line 62
    array-length v5, v4

    .line 63
    iget v6, p1, Lw7/p;->c:I

    .line 64
    .line 65
    add-int/lit8 v6, v6, 0x4

    .line 66
    .line 67
    if-ge v5, v6, :cond_3

    .line 68
    .line 69
    invoke-static {v4, v6}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 70
    .line 71
    .line 72
    move-result-object v4

    .line 73
    array-length v5, v4

    .line 74
    invoke-virtual {p1, v5, v4}, Lw7/p;->G(I[B)V

    .line 75
    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_3
    invoke-virtual {p1, v6}, Lw7/p;->H(I)V

    .line 79
    .line 80
    .line 81
    :goto_1
    iget-object v4, p1, Lw7/p;->a:[B

    .line 82
    .line 83
    iget p1, p1, Lw7/p;->c:I

    .line 84
    .line 85
    add-int/lit8 v5, p1, -0x4

    .line 86
    .line 87
    const-wide/16 v8, 0xff

    .line 88
    .line 89
    and-long v10, v1, v8

    .line 90
    .line 91
    long-to-int v6, v10

    .line 92
    int-to-byte v6, v6

    .line 93
    aput-byte v6, v4, v5

    .line 94
    .line 95
    add-int/lit8 v5, p1, -0x3

    .line 96
    .line 97
    ushr-long v6, v1, v7

    .line 98
    .line 99
    and-long/2addr v6, v8

    .line 100
    long-to-int v6, v6

    .line 101
    int-to-byte v6, v6

    .line 102
    aput-byte v6, v4, v5

    .line 103
    .line 104
    add-int/lit8 v5, p1, -0x2

    .line 105
    .line 106
    const/16 v6, 0x10

    .line 107
    .line 108
    ushr-long v6, v1, v6

    .line 109
    .line 110
    and-long/2addr v6, v8

    .line 111
    long-to-int v6, v6

    .line 112
    int-to-byte v6, v6

    .line 113
    aput-byte v6, v4, v5

    .line 114
    .line 115
    sub-int/2addr p1, v3

    .line 116
    const/16 v5, 0x18

    .line 117
    .line 118
    ushr-long v5, v1, v5

    .line 119
    .line 120
    and-long/2addr v5, v8

    .line 121
    long-to-int v5, v5

    .line 122
    int-to-byte v5, v5

    .line 123
    aput-byte v5, v4, p1

    .line 124
    .line 125
    iput-boolean v3, p0, Lj9/k;->p:Z

    .line 126
    .line 127
    iput v0, p0, Lj9/k;->o:I

    .line 128
    .line 129
    return-wide v1
.end method

.method public final c(Lw7/p;JLb81/c;)Z
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p4

    .line 6
    .line 7
    iget-object v3, v0, Lj9/k;->n:Lca/m;

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    if-eqz v3, :cond_0

    .line 11
    .line 12
    iget-object v0, v2, Lb81/c;->e:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v0, Lt7/o;

    .line 15
    .line 16
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    return v4

    .line 20
    :cond_0
    iget-object v6, v0, Lj9/k;->q:Lo8/a0;

    .line 21
    .line 22
    const/4 v3, 0x1

    .line 23
    const/4 v5, 0x4

    .line 24
    const/4 v7, -0x1

    .line 25
    if-nez v6, :cond_3

    .line 26
    .line 27
    invoke-static {v3, v1, v4}, Lo8/b;->x(ILw7/p;Z)Z

    .line 28
    .line 29
    .line 30
    invoke-virtual {v1}, Lw7/p;->o()I

    .line 31
    .line 32
    .line 33
    invoke-virtual {v1}, Lw7/p;->w()I

    .line 34
    .line 35
    .line 36
    move-result v4

    .line 37
    invoke-virtual {v1}, Lw7/p;->o()I

    .line 38
    .line 39
    .line 40
    move-result v6

    .line 41
    invoke-virtual {v1}, Lw7/p;->l()I

    .line 42
    .line 43
    .line 44
    move-result v9

    .line 45
    if-gtz v9, :cond_1

    .line 46
    .line 47
    move v9, v7

    .line 48
    :cond_1
    invoke-virtual {v1}, Lw7/p;->l()I

    .line 49
    .line 50
    .line 51
    move-result v10

    .line 52
    if-gtz v10, :cond_2

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_2
    move v7, v10

    .line 56
    :goto_0
    invoke-virtual {v1}, Lw7/p;->l()I

    .line 57
    .line 58
    .line 59
    invoke-virtual {v1}, Lw7/p;->w()I

    .line 60
    .line 61
    .line 62
    move-result v10

    .line 63
    and-int/lit8 v11, v10, 0xf

    .line 64
    .line 65
    int-to-double v11, v11

    .line 66
    const-wide/high16 v13, 0x4000000000000000L    # 2.0

    .line 67
    .line 68
    invoke-static {v13, v14, v11, v12}, Ljava/lang/Math;->pow(DD)D

    .line 69
    .line 70
    .line 71
    move-result-wide v11

    .line 72
    double-to-int v11, v11

    .line 73
    and-int/lit16 v10, v10, 0xf0

    .line 74
    .line 75
    shr-int/lit8 v5, v10, 0x4

    .line 76
    .line 77
    move v10, v9

    .line 78
    int-to-double v8, v5

    .line 79
    invoke-static {v13, v14, v8, v9}, Ljava/lang/Math;->pow(DD)D

    .line 80
    .line 81
    .line 82
    move-result-wide v8

    .line 83
    double-to-int v5, v8

    .line 84
    invoke-virtual {v1}, Lw7/p;->w()I

    .line 85
    .line 86
    .line 87
    iget-object v8, v1, Lw7/p;->a:[B

    .line 88
    .line 89
    iget v1, v1, Lw7/p;->c:I

    .line 90
    .line 91
    invoke-static {v8, v1}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 92
    .line 93
    .line 94
    move-result-object v1

    .line 95
    new-instance v8, Lo8/a0;

    .line 96
    .line 97
    invoke-direct {v8}, Ljava/lang/Object;-><init>()V

    .line 98
    .line 99
    .line 100
    iput v4, v8, Lo8/a0;->a:I

    .line 101
    .line 102
    iput v6, v8, Lo8/a0;->b:I

    .line 103
    .line 104
    iput v10, v8, Lo8/a0;->c:I

    .line 105
    .line 106
    iput v7, v8, Lo8/a0;->d:I

    .line 107
    .line 108
    iput v11, v8, Lo8/a0;->e:I

    .line 109
    .line 110
    iput v5, v8, Lo8/a0;->f:I

    .line 111
    .line 112
    iput-object v1, v8, Lo8/a0;->g:Ljava/io/Serializable;

    .line 113
    .line 114
    iput-object v8, v0, Lj9/k;->q:Lo8/a0;

    .line 115
    .line 116
    :goto_1
    const/4 v8, 0x0

    .line 117
    goto/16 :goto_1f

    .line 118
    .line 119
    :cond_3
    move v8, v7

    .line 120
    iget-object v7, v0, Lj9/k;->r:Lhu/q;

    .line 121
    .line 122
    if-nez v7, :cond_4

    .line 123
    .line 124
    invoke-static {v1, v3, v3}, Lo8/b;->v(Lw7/p;ZZ)Lhu/q;

    .line 125
    .line 126
    .line 127
    move-result-object v1

    .line 128
    iput-object v1, v0, Lj9/k;->r:Lhu/q;

    .line 129
    .line 130
    goto :goto_1

    .line 131
    :cond_4
    iget v9, v1, Lw7/p;->c:I

    .line 132
    .line 133
    move v10, v8

    .line 134
    new-array v8, v9, [B

    .line 135
    .line 136
    iget-object v11, v1, Lw7/p;->a:[B

    .line 137
    .line 138
    invoke-static {v11, v4, v8, v4, v9}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 139
    .line 140
    .line 141
    iget v9, v6, Lo8/a0;->a:I

    .line 142
    .line 143
    const/4 v11, 0x5

    .line 144
    invoke-static {v11, v1, v4}, Lo8/b;->x(ILw7/p;Z)Z

    .line 145
    .line 146
    .line 147
    invoke-virtual {v1}, Lw7/p;->w()I

    .line 148
    .line 149
    .line 150
    move-result v12

    .line 151
    add-int/2addr v12, v3

    .line 152
    new-instance v13, Lm9/f;

    .line 153
    .line 154
    iget-object v14, v1, Lw7/p;->a:[B

    .line 155
    .line 156
    invoke-direct {v13, v14}, Lm9/f;-><init>([B)V

    .line 157
    .line 158
    .line 159
    iget v1, v1, Lw7/p;->b:I

    .line 160
    .line 161
    const/16 v14, 0x8

    .line 162
    .line 163
    mul-int/2addr v1, v14

    .line 164
    invoke-virtual {v13, v1}, Lm9/f;->t(I)V

    .line 165
    .line 166
    .line 167
    move v1, v4

    .line 168
    :goto_2
    const/16 v15, 0x18

    .line 169
    .line 170
    const/4 v4, 0x2

    .line 171
    const/16 v10, 0x10

    .line 172
    .line 173
    if-ge v1, v12, :cond_10

    .line 174
    .line 175
    move/from16 p1, v14

    .line 176
    .line 177
    invoke-virtual {v13, v15}, Lm9/f;->i(I)I

    .line 178
    .line 179
    .line 180
    move-result v14

    .line 181
    const v3, 0x564342

    .line 182
    .line 183
    .line 184
    if-ne v14, v3, :cond_f

    .line 185
    .line 186
    invoke-virtual {v13, v10}, Lm9/f;->i(I)I

    .line 187
    .line 188
    .line 189
    move-result v3

    .line 190
    invoke-virtual {v13, v15}, Lm9/f;->i(I)I

    .line 191
    .line 192
    .line 193
    move-result v10

    .line 194
    invoke-virtual {v13}, Lm9/f;->h()Z

    .line 195
    .line 196
    .line 197
    move-result v14

    .line 198
    if-nez v14, :cond_7

    .line 199
    .line 200
    invoke-virtual {v13}, Lm9/f;->h()Z

    .line 201
    .line 202
    .line 203
    move-result v14

    .line 204
    const/4 v15, 0x0

    .line 205
    :goto_3
    if-ge v15, v10, :cond_9

    .line 206
    .line 207
    if-eqz v14, :cond_5

    .line 208
    .line 209
    invoke-virtual {v13}, Lm9/f;->h()Z

    .line 210
    .line 211
    .line 212
    move-result v18

    .line 213
    if-eqz v18, :cond_6

    .line 214
    .line 215
    invoke-virtual {v13, v11}, Lm9/f;->t(I)V

    .line 216
    .line 217
    .line 218
    goto :goto_4

    .line 219
    :cond_5
    invoke-virtual {v13, v11}, Lm9/f;->t(I)V

    .line 220
    .line 221
    .line 222
    :cond_6
    :goto_4
    add-int/lit8 v15, v15, 0x1

    .line 223
    .line 224
    goto :goto_3

    .line 225
    :cond_7
    invoke-virtual {v13, v11}, Lm9/f;->t(I)V

    .line 226
    .line 227
    .line 228
    const/4 v14, 0x0

    .line 229
    :goto_5
    if-ge v14, v10, :cond_9

    .line 230
    .line 231
    sub-int v15, v10, v14

    .line 232
    .line 233
    const/4 v11, 0x0

    .line 234
    :goto_6
    if-lez v15, :cond_8

    .line 235
    .line 236
    add-int/lit8 v11, v11, 0x1

    .line 237
    .line 238
    ushr-int/lit8 v15, v15, 0x1

    .line 239
    .line 240
    goto :goto_6

    .line 241
    :cond_8
    invoke-virtual {v13, v11}, Lm9/f;->i(I)I

    .line 242
    .line 243
    .line 244
    move-result v11

    .line 245
    add-int/2addr v14, v11

    .line 246
    const/4 v11, 0x5

    .line 247
    goto :goto_5

    .line 248
    :cond_9
    invoke-virtual {v13, v5}, Lm9/f;->i(I)I

    .line 249
    .line 250
    .line 251
    move-result v11

    .line 252
    if-gt v11, v4, :cond_e

    .line 253
    .line 254
    const/4 v14, 0x1

    .line 255
    if-eq v11, v14, :cond_a

    .line 256
    .line 257
    if-ne v11, v4, :cond_d

    .line 258
    .line 259
    :cond_a
    const/16 v4, 0x20

    .line 260
    .line 261
    invoke-virtual {v13, v4}, Lm9/f;->t(I)V

    .line 262
    .line 263
    .line 264
    invoke-virtual {v13, v4}, Lm9/f;->t(I)V

    .line 265
    .line 266
    .line 267
    invoke-virtual {v13, v5}, Lm9/f;->i(I)I

    .line 268
    .line 269
    .line 270
    move-result v4

    .line 271
    add-int/2addr v4, v14

    .line 272
    invoke-virtual {v13, v14}, Lm9/f;->t(I)V

    .line 273
    .line 274
    .line 275
    if-ne v11, v14, :cond_c

    .line 276
    .line 277
    if-eqz v3, :cond_b

    .line 278
    .line 279
    int-to-long v10, v10

    .line 280
    int-to-long v14, v3

    .line 281
    long-to-double v10, v10

    .line 282
    const-wide/high16 v19, 0x3ff0000000000000L    # 1.0

    .line 283
    .line 284
    long-to-double v14, v14

    .line 285
    div-double v14, v19, v14

    .line 286
    .line 287
    invoke-static {v10, v11, v14, v15}, Ljava/lang/Math;->pow(DD)D

    .line 288
    .line 289
    .line 290
    move-result-wide v10

    .line 291
    invoke-static {v10, v11}, Ljava/lang/Math;->floor(D)D

    .line 292
    .line 293
    .line 294
    move-result-wide v10

    .line 295
    double-to-long v10, v10

    .line 296
    goto :goto_7

    .line 297
    :cond_b
    const-wide/16 v10, 0x0

    .line 298
    .line 299
    goto :goto_7

    .line 300
    :cond_c
    int-to-long v10, v10

    .line 301
    int-to-long v14, v3

    .line 302
    mul-long/2addr v10, v14

    .line 303
    :goto_7
    int-to-long v3, v4

    .line 304
    mul-long/2addr v10, v3

    .line 305
    long-to-int v3, v10

    .line 306
    invoke-virtual {v13, v3}, Lm9/f;->t(I)V

    .line 307
    .line 308
    .line 309
    :cond_d
    add-int/lit8 v1, v1, 0x1

    .line 310
    .line 311
    move/from16 v14, p1

    .line 312
    .line 313
    const/4 v3, 0x1

    .line 314
    const/4 v4, 0x0

    .line 315
    const/4 v10, -0x1

    .line 316
    const/4 v11, 0x5

    .line 317
    goto/16 :goto_2

    .line 318
    .line 319
    :cond_e
    new-instance v0, Ljava/lang/StringBuilder;

    .line 320
    .line 321
    const-string v1, "lookup type greater than 2 not decodable: "

    .line 322
    .line 323
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 324
    .line 325
    .line 326
    invoke-virtual {v0, v11}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 327
    .line 328
    .line 329
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 330
    .line 331
    .line 332
    move-result-object v0

    .line 333
    const/4 v1, 0x0

    .line 334
    invoke-static {v1, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 335
    .line 336
    .line 337
    move-result-object v0

    .line 338
    throw v0

    .line 339
    :cond_f
    const/4 v1, 0x0

    .line 340
    new-instance v0, Ljava/lang/StringBuilder;

    .line 341
    .line 342
    const-string v2, "expected code book to start with [0x56, 0x43, 0x42] at "

    .line 343
    .line 344
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 345
    .line 346
    .line 347
    iget v2, v13, Lm9/f;->d:I

    .line 348
    .line 349
    mul-int/lit8 v2, v2, 0x8

    .line 350
    .line 351
    iget v3, v13, Lm9/f;->e:I

    .line 352
    .line 353
    add-int/2addr v2, v3

    .line 354
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 355
    .line 356
    .line 357
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 358
    .line 359
    .line 360
    move-result-object v0

    .line 361
    invoke-static {v1, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 362
    .line 363
    .line 364
    move-result-object v0

    .line 365
    throw v0

    .line 366
    :cond_10
    move/from16 p1, v14

    .line 367
    .line 368
    const/4 v1, 0x6

    .line 369
    invoke-virtual {v13, v1}, Lm9/f;->i(I)I

    .line 370
    .line 371
    .line 372
    move-result v3

    .line 373
    const/16 v17, 0x1

    .line 374
    .line 375
    add-int/lit8 v3, v3, 0x1

    .line 376
    .line 377
    const/4 v11, 0x0

    .line 378
    :goto_8
    if-ge v11, v3, :cond_12

    .line 379
    .line 380
    invoke-virtual {v13, v10}, Lm9/f;->i(I)I

    .line 381
    .line 382
    .line 383
    move-result v12

    .line 384
    if-nez v12, :cond_11

    .line 385
    .line 386
    add-int/lit8 v11, v11, 0x1

    .line 387
    .line 388
    goto :goto_8

    .line 389
    :cond_11
    const-string v0, "placeholder of time domain transforms not zeroed out"

    .line 390
    .line 391
    const/4 v1, 0x0

    .line 392
    invoke-static {v1, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 393
    .line 394
    .line 395
    move-result-object v0

    .line 396
    throw v0

    .line 397
    :cond_12
    invoke-virtual {v13, v1}, Lm9/f;->i(I)I

    .line 398
    .line 399
    .line 400
    move-result v3

    .line 401
    const/4 v14, 0x1

    .line 402
    add-int/2addr v3, v14

    .line 403
    const/4 v11, 0x0

    .line 404
    :goto_9
    const/4 v12, 0x3

    .line 405
    if-ge v11, v3, :cond_1c

    .line 406
    .line 407
    invoke-virtual {v13, v10}, Lm9/f;->i(I)I

    .line 408
    .line 409
    .line 410
    move-result v15

    .line 411
    if-eqz v15, :cond_1a

    .line 412
    .line 413
    if-ne v15, v14, :cond_19

    .line 414
    .line 415
    const/4 v14, 0x5

    .line 416
    invoke-virtual {v13, v14}, Lm9/f;->i(I)I

    .line 417
    .line 418
    .line 419
    move-result v15

    .line 420
    new-array v14, v15, [I

    .line 421
    .line 422
    const/4 v1, 0x0

    .line 423
    const/4 v10, -0x1

    .line 424
    :goto_a
    if-ge v1, v15, :cond_14

    .line 425
    .line 426
    invoke-virtual {v13, v5}, Lm9/f;->i(I)I

    .line 427
    .line 428
    .line 429
    move-result v4

    .line 430
    aput v4, v14, v1

    .line 431
    .line 432
    if-le v4, v10, :cond_13

    .line 433
    .line 434
    move v10, v4

    .line 435
    :cond_13
    add-int/lit8 v1, v1, 0x1

    .line 436
    .line 437
    const/4 v4, 0x2

    .line 438
    goto :goto_a

    .line 439
    :cond_14
    add-int/lit8 v10, v10, 0x1

    .line 440
    .line 441
    new-array v1, v10, [I

    .line 442
    .line 443
    const/4 v4, 0x0

    .line 444
    :goto_b
    if-ge v4, v10, :cond_17

    .line 445
    .line 446
    invoke-virtual {v13, v12}, Lm9/f;->i(I)I

    .line 447
    .line 448
    .line 449
    move-result v21

    .line 450
    const/16 v17, 0x1

    .line 451
    .line 452
    add-int/lit8 v21, v21, 0x1

    .line 453
    .line 454
    aput v21, v1, v4

    .line 455
    .line 456
    const/4 v12, 0x2

    .line 457
    invoke-virtual {v13, v12}, Lm9/f;->i(I)I

    .line 458
    .line 459
    .line 460
    move-result v22

    .line 461
    move/from16 v12, p1

    .line 462
    .line 463
    if-lez v22, :cond_15

    .line 464
    .line 465
    invoke-virtual {v13, v12}, Lm9/f;->t(I)V

    .line 466
    .line 467
    .line 468
    :cond_15
    move-object/from16 v23, v1

    .line 469
    .line 470
    const/4 v5, 0x0

    .line 471
    :goto_c
    shl-int v1, v17, v22

    .line 472
    .line 473
    if-ge v5, v1, :cond_16

    .line 474
    .line 475
    invoke-virtual {v13, v12}, Lm9/f;->t(I)V

    .line 476
    .line 477
    .line 478
    add-int/lit8 v5, v5, 0x1

    .line 479
    .line 480
    const/16 v12, 0x8

    .line 481
    .line 482
    const/16 v17, 0x1

    .line 483
    .line 484
    goto :goto_c

    .line 485
    :cond_16
    add-int/lit8 v4, v4, 0x1

    .line 486
    .line 487
    move-object/from16 v1, v23

    .line 488
    .line 489
    const/16 p1, 0x8

    .line 490
    .line 491
    const/4 v5, 0x4

    .line 492
    const/4 v12, 0x3

    .line 493
    goto :goto_b

    .line 494
    :cond_17
    move-object/from16 v23, v1

    .line 495
    .line 496
    const/4 v12, 0x2

    .line 497
    invoke-virtual {v13, v12}, Lm9/f;->t(I)V

    .line 498
    .line 499
    .line 500
    const/4 v1, 0x4

    .line 501
    invoke-virtual {v13, v1}, Lm9/f;->i(I)I

    .line 502
    .line 503
    .line 504
    move-result v4

    .line 505
    const/4 v1, 0x0

    .line 506
    const/4 v5, 0x0

    .line 507
    const/4 v10, 0x0

    .line 508
    :goto_d
    if-ge v1, v15, :cond_1b

    .line 509
    .line 510
    aget v12, v14, v1

    .line 511
    .line 512
    aget v12, v23, v12

    .line 513
    .line 514
    add-int/2addr v5, v12

    .line 515
    :goto_e
    if-ge v10, v5, :cond_18

    .line 516
    .line 517
    invoke-virtual {v13, v4}, Lm9/f;->t(I)V

    .line 518
    .line 519
    .line 520
    add-int/lit8 v10, v10, 0x1

    .line 521
    .line 522
    goto :goto_e

    .line 523
    :cond_18
    add-int/lit8 v1, v1, 0x1

    .line 524
    .line 525
    goto :goto_d

    .line 526
    :cond_19
    new-instance v0, Ljava/lang/StringBuilder;

    .line 527
    .line 528
    const-string v1, "floor type greater than 1 not decodable: "

    .line 529
    .line 530
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 531
    .line 532
    .line 533
    invoke-virtual {v0, v15}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 534
    .line 535
    .line 536
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 537
    .line 538
    .line 539
    move-result-object v0

    .line 540
    const/4 v1, 0x0

    .line 541
    invoke-static {v1, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 542
    .line 543
    .line 544
    move-result-object v0

    .line 545
    throw v0

    .line 546
    :cond_1a
    move/from16 v12, p1

    .line 547
    .line 548
    invoke-virtual {v13, v12}, Lm9/f;->t(I)V

    .line 549
    .line 550
    .line 551
    const/16 v1, 0x10

    .line 552
    .line 553
    invoke-virtual {v13, v1}, Lm9/f;->t(I)V

    .line 554
    .line 555
    .line 556
    invoke-virtual {v13, v1}, Lm9/f;->t(I)V

    .line 557
    .line 558
    .line 559
    const/4 v1, 0x6

    .line 560
    invoke-virtual {v13, v1}, Lm9/f;->t(I)V

    .line 561
    .line 562
    .line 563
    invoke-virtual {v13, v12}, Lm9/f;->t(I)V

    .line 564
    .line 565
    .line 566
    const/4 v1, 0x4

    .line 567
    invoke-virtual {v13, v1}, Lm9/f;->i(I)I

    .line 568
    .line 569
    .line 570
    move-result v4

    .line 571
    const/16 v17, 0x1

    .line 572
    .line 573
    add-int/lit8 v4, v4, 0x1

    .line 574
    .line 575
    const/4 v1, 0x0

    .line 576
    :goto_f
    if-ge v1, v4, :cond_1b

    .line 577
    .line 578
    invoke-virtual {v13, v12}, Lm9/f;->t(I)V

    .line 579
    .line 580
    .line 581
    add-int/lit8 v1, v1, 0x1

    .line 582
    .line 583
    const/16 v12, 0x8

    .line 584
    .line 585
    goto :goto_f

    .line 586
    :cond_1b
    add-int/lit8 v11, v11, 0x1

    .line 587
    .line 588
    const/16 p1, 0x8

    .line 589
    .line 590
    const/4 v1, 0x6

    .line 591
    const/4 v4, 0x2

    .line 592
    const/4 v5, 0x4

    .line 593
    const/16 v10, 0x10

    .line 594
    .line 595
    const/4 v14, 0x1

    .line 596
    const/16 v15, 0x18

    .line 597
    .line 598
    goto/16 :goto_9

    .line 599
    .line 600
    :cond_1c
    invoke-virtual {v13, v1}, Lm9/f;->i(I)I

    .line 601
    .line 602
    .line 603
    move-result v3

    .line 604
    const/16 v17, 0x1

    .line 605
    .line 606
    add-int/lit8 v3, v3, 0x1

    .line 607
    .line 608
    const/4 v4, 0x0

    .line 609
    :goto_10
    if-ge v4, v3, :cond_23

    .line 610
    .line 611
    const/16 v5, 0x10

    .line 612
    .line 613
    invoke-virtual {v13, v5}, Lm9/f;->i(I)I

    .line 614
    .line 615
    .line 616
    move-result v10

    .line 617
    const/4 v12, 0x2

    .line 618
    if-gt v10, v12, :cond_22

    .line 619
    .line 620
    const/16 v5, 0x18

    .line 621
    .line 622
    invoke-virtual {v13, v5}, Lm9/f;->t(I)V

    .line 623
    .line 624
    .line 625
    invoke-virtual {v13, v5}, Lm9/f;->t(I)V

    .line 626
    .line 627
    .line 628
    invoke-virtual {v13, v5}, Lm9/f;->t(I)V

    .line 629
    .line 630
    .line 631
    invoke-virtual {v13, v1}, Lm9/f;->i(I)I

    .line 632
    .line 633
    .line 634
    move-result v10

    .line 635
    add-int/lit8 v10, v10, 0x1

    .line 636
    .line 637
    const/16 v12, 0x8

    .line 638
    .line 639
    invoke-virtual {v13, v12}, Lm9/f;->t(I)V

    .line 640
    .line 641
    .line 642
    new-array v1, v10, [I

    .line 643
    .line 644
    const/4 v11, 0x0

    .line 645
    :goto_11
    if-ge v11, v10, :cond_1e

    .line 646
    .line 647
    const/4 v14, 0x3

    .line 648
    invoke-virtual {v13, v14}, Lm9/f;->i(I)I

    .line 649
    .line 650
    .line 651
    move-result v15

    .line 652
    invoke-virtual {v13}, Lm9/f;->h()Z

    .line 653
    .line 654
    .line 655
    move-result v16

    .line 656
    const/4 v5, 0x5

    .line 657
    if-eqz v16, :cond_1d

    .line 658
    .line 659
    invoke-virtual {v13, v5}, Lm9/f;->i(I)I

    .line 660
    .line 661
    .line 662
    move-result v16

    .line 663
    goto :goto_12

    .line 664
    :cond_1d
    const/16 v16, 0x0

    .line 665
    .line 666
    :goto_12
    mul-int/lit8 v16, v16, 0x8

    .line 667
    .line 668
    add-int v16, v16, v15

    .line 669
    .line 670
    aput v16, v1, v11

    .line 671
    .line 672
    add-int/lit8 v11, v11, 0x1

    .line 673
    .line 674
    const/16 v5, 0x18

    .line 675
    .line 676
    goto :goto_11

    .line 677
    :cond_1e
    const/4 v5, 0x5

    .line 678
    const/4 v14, 0x3

    .line 679
    const/4 v11, 0x0

    .line 680
    :goto_13
    if-ge v11, v10, :cond_21

    .line 681
    .line 682
    const/4 v15, 0x0

    .line 683
    :goto_14
    if-ge v15, v12, :cond_20

    .line 684
    .line 685
    aget v16, v1, v11

    .line 686
    .line 687
    const/16 v17, 0x1

    .line 688
    .line 689
    shl-int v18, v17, v15

    .line 690
    .line 691
    and-int v16, v16, v18

    .line 692
    .line 693
    if-eqz v16, :cond_1f

    .line 694
    .line 695
    invoke-virtual {v13, v12}, Lm9/f;->t(I)V

    .line 696
    .line 697
    .line 698
    :cond_1f
    add-int/lit8 v15, v15, 0x1

    .line 699
    .line 700
    const/16 v12, 0x8

    .line 701
    .line 702
    goto :goto_14

    .line 703
    :cond_20
    add-int/lit8 v11, v11, 0x1

    .line 704
    .line 705
    const/16 v12, 0x8

    .line 706
    .line 707
    goto :goto_13

    .line 708
    :cond_21
    add-int/lit8 v4, v4, 0x1

    .line 709
    .line 710
    const/4 v1, 0x6

    .line 711
    const/16 v17, 0x1

    .line 712
    .line 713
    goto :goto_10

    .line 714
    :cond_22
    const-string v0, "residueType greater than 2 is not decodable"

    .line 715
    .line 716
    const/4 v1, 0x0

    .line 717
    invoke-static {v1, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 718
    .line 719
    .line 720
    move-result-object v0

    .line 721
    throw v0

    .line 722
    :cond_23
    invoke-virtual {v13, v1}, Lm9/f;->i(I)I

    .line 723
    .line 724
    .line 725
    move-result v3

    .line 726
    const/16 v17, 0x1

    .line 727
    .line 728
    add-int/lit8 v3, v3, 0x1

    .line 729
    .line 730
    const/4 v1, 0x0

    .line 731
    :goto_15
    if-ge v1, v3, :cond_2c

    .line 732
    .line 733
    const/16 v5, 0x10

    .line 734
    .line 735
    invoke-virtual {v13, v5}, Lm9/f;->i(I)I

    .line 736
    .line 737
    .line 738
    move-result v4

    .line 739
    if-eqz v4, :cond_24

    .line 740
    .line 741
    new-instance v5, Ljava/lang/StringBuilder;

    .line 742
    .line 743
    const-string v10, "mapping type other than 0 not supported: "

    .line 744
    .line 745
    invoke-direct {v5, v10}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 746
    .line 747
    .line 748
    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 749
    .line 750
    .line 751
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 752
    .line 753
    .line 754
    move-result-object v4

    .line 755
    const-string v5, "VorbisUtil"

    .line 756
    .line 757
    invoke-static {v5, v4}, Lw7/a;->o(Ljava/lang/String;Ljava/lang/String;)V

    .line 758
    .line 759
    .line 760
    const/4 v10, 0x4

    .line 761
    const/4 v12, 0x2

    .line 762
    goto/16 :goto_1c

    .line 763
    .line 764
    :cond_24
    invoke-virtual {v13}, Lm9/f;->h()Z

    .line 765
    .line 766
    .line 767
    move-result v4

    .line 768
    if-eqz v4, :cond_25

    .line 769
    .line 770
    const/4 v4, 0x4

    .line 771
    invoke-virtual {v13, v4}, Lm9/f;->i(I)I

    .line 772
    .line 773
    .line 774
    move-result v5

    .line 775
    const/16 v17, 0x1

    .line 776
    .line 777
    add-int/lit8 v4, v5, 0x1

    .line 778
    .line 779
    goto :goto_16

    .line 780
    :cond_25
    const/16 v17, 0x1

    .line 781
    .line 782
    move/from16 v4, v17

    .line 783
    .line 784
    :goto_16
    invoke-virtual {v13}, Lm9/f;->h()Z

    .line 785
    .line 786
    .line 787
    move-result v5

    .line 788
    if-eqz v5, :cond_28

    .line 789
    .line 790
    const/16 v12, 0x8

    .line 791
    .line 792
    invoke-virtual {v13, v12}, Lm9/f;->i(I)I

    .line 793
    .line 794
    .line 795
    move-result v5

    .line 796
    add-int/lit8 v5, v5, 0x1

    .line 797
    .line 798
    const/4 v10, 0x0

    .line 799
    :goto_17
    if-ge v10, v5, :cond_28

    .line 800
    .line 801
    add-int/lit8 v11, v9, -0x1

    .line 802
    .line 803
    move v12, v11

    .line 804
    const/4 v14, 0x0

    .line 805
    :goto_18
    if-lez v12, :cond_26

    .line 806
    .line 807
    add-int/lit8 v14, v14, 0x1

    .line 808
    .line 809
    ushr-int/lit8 v12, v12, 0x1

    .line 810
    .line 811
    goto :goto_18

    .line 812
    :cond_26
    invoke-virtual {v13, v14}, Lm9/f;->t(I)V

    .line 813
    .line 814
    .line 815
    const/4 v12, 0x0

    .line 816
    :goto_19
    if-lez v11, :cond_27

    .line 817
    .line 818
    add-int/lit8 v12, v12, 0x1

    .line 819
    .line 820
    ushr-int/lit8 v11, v11, 0x1

    .line 821
    .line 822
    goto :goto_19

    .line 823
    :cond_27
    invoke-virtual {v13, v12}, Lm9/f;->t(I)V

    .line 824
    .line 825
    .line 826
    add-int/lit8 v10, v10, 0x1

    .line 827
    .line 828
    goto :goto_17

    .line 829
    :cond_28
    const/4 v12, 0x2

    .line 830
    invoke-virtual {v13, v12}, Lm9/f;->i(I)I

    .line 831
    .line 832
    .line 833
    move-result v5

    .line 834
    if-nez v5, :cond_2b

    .line 835
    .line 836
    const/4 v14, 0x1

    .line 837
    if-le v4, v14, :cond_29

    .line 838
    .line 839
    const/4 v5, 0x0

    .line 840
    :goto_1a
    if-ge v5, v9, :cond_29

    .line 841
    .line 842
    const/4 v10, 0x4

    .line 843
    invoke-virtual {v13, v10}, Lm9/f;->t(I)V

    .line 844
    .line 845
    .line 846
    add-int/lit8 v5, v5, 0x1

    .line 847
    .line 848
    goto :goto_1a

    .line 849
    :cond_29
    const/4 v10, 0x4

    .line 850
    const/4 v5, 0x0

    .line 851
    :goto_1b
    if-ge v5, v4, :cond_2a

    .line 852
    .line 853
    const/16 v11, 0x8

    .line 854
    .line 855
    invoke-virtual {v13, v11}, Lm9/f;->t(I)V

    .line 856
    .line 857
    .line 858
    invoke-virtual {v13, v11}, Lm9/f;->t(I)V

    .line 859
    .line 860
    .line 861
    invoke-virtual {v13, v11}, Lm9/f;->t(I)V

    .line 862
    .line 863
    .line 864
    add-int/lit8 v5, v5, 0x1

    .line 865
    .line 866
    goto :goto_1b

    .line 867
    :cond_2a
    :goto_1c
    add-int/lit8 v1, v1, 0x1

    .line 868
    .line 869
    goto/16 :goto_15

    .line 870
    .line 871
    :cond_2b
    const-string v0, "to reserved bits must be zero after mapping coupling steps"

    .line 872
    .line 873
    const/4 v1, 0x0

    .line 874
    invoke-static {v1, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 875
    .line 876
    .line 877
    move-result-object v0

    .line 878
    throw v0

    .line 879
    :cond_2c
    const/4 v1, 0x6

    .line 880
    invoke-virtual {v13, v1}, Lm9/f;->i(I)I

    .line 881
    .line 882
    .line 883
    move-result v1

    .line 884
    add-int/lit8 v3, v1, 0x1

    .line 885
    .line 886
    new-array v9, v3, [La8/t1;

    .line 887
    .line 888
    const/4 v4, 0x0

    .line 889
    :goto_1d
    if-ge v4, v3, :cond_2d

    .line 890
    .line 891
    invoke-virtual {v13}, Lm9/f;->h()Z

    .line 892
    .line 893
    .line 894
    move-result v5

    .line 895
    const/16 v10, 0x10

    .line 896
    .line 897
    invoke-virtual {v13, v10}, Lm9/f;->i(I)I

    .line 898
    .line 899
    .line 900
    invoke-virtual {v13, v10}, Lm9/f;->i(I)I

    .line 901
    .line 902
    .line 903
    const/16 v12, 0x8

    .line 904
    .line 905
    invoke-virtual {v13, v12}, Lm9/f;->i(I)I

    .line 906
    .line 907
    .line 908
    new-instance v11, La8/t1;

    .line 909
    .line 910
    invoke-direct {v11, v5}, La8/t1;-><init>(Z)V

    .line 911
    .line 912
    .line 913
    aput-object v11, v9, v4

    .line 914
    .line 915
    add-int/lit8 v4, v4, 0x1

    .line 916
    .line 917
    goto :goto_1d

    .line 918
    :cond_2d
    invoke-virtual {v13}, Lm9/f;->h()Z

    .line 919
    .line 920
    .line 921
    move-result v3

    .line 922
    if-eqz v3, :cond_30

    .line 923
    .line 924
    const/4 v10, 0x0

    .line 925
    :goto_1e
    if-lez v1, :cond_2e

    .line 926
    .line 927
    add-int/lit8 v10, v10, 0x1

    .line 928
    .line 929
    ushr-int/lit8 v1, v1, 0x1

    .line 930
    .line 931
    goto :goto_1e

    .line 932
    :cond_2e
    new-instance v5, Lca/m;

    .line 933
    .line 934
    invoke-direct/range {v5 .. v10}, Lca/m;-><init>(Lo8/a0;Lhu/q;[B[La8/t1;I)V

    .line 935
    .line 936
    .line 937
    move-object v8, v5

    .line 938
    :goto_1f
    iput-object v8, v0, Lj9/k;->n:Lca/m;

    .line 939
    .line 940
    if-nez v8, :cond_2f

    .line 941
    .line 942
    const/16 v17, 0x1

    .line 943
    .line 944
    return v17

    .line 945
    :cond_2f
    iget-object v0, v8, Lca/m;->e:Ljava/lang/Object;

    .line 946
    .line 947
    check-cast v0, Lo8/a0;

    .line 948
    .line 949
    new-instance v1, Ljava/util/ArrayList;

    .line 950
    .line 951
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 952
    .line 953
    .line 954
    iget-object v3, v0, Lo8/a0;->g:Ljava/io/Serializable;

    .line 955
    .line 956
    check-cast v3, [B

    .line 957
    .line 958
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 959
    .line 960
    .line 961
    iget-object v3, v8, Lca/m;->g:Ljava/lang/Object;

    .line 962
    .line 963
    check-cast v3, [B

    .line 964
    .line 965
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 966
    .line 967
    .line 968
    iget-object v3, v8, Lca/m;->f:Ljava/lang/Object;

    .line 969
    .line 970
    check-cast v3, Lhu/q;

    .line 971
    .line 972
    iget-object v3, v3, Lhu/q;->e:Ljava/lang/Object;

    .line 973
    .line 974
    check-cast v3, [Ljava/lang/String;

    .line 975
    .line 976
    invoke-static {v3}, Lhr/h0;->r([Ljava/lang/Object;)Lhr/x0;

    .line 977
    .line 978
    .line 979
    move-result-object v3

    .line 980
    invoke-static {v3}, Lo8/b;->r(Ljava/util/List;)Lt7/c0;

    .line 981
    .line 982
    .line 983
    move-result-object v3

    .line 984
    new-instance v4, Lt7/n;

    .line 985
    .line 986
    invoke-direct {v4}, Lt7/n;-><init>()V

    .line 987
    .line 988
    .line 989
    const-string v5, "audio/ogg"

    .line 990
    .line 991
    invoke-static {v5}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 992
    .line 993
    .line 994
    move-result-object v5

    .line 995
    iput-object v5, v4, Lt7/n;->l:Ljava/lang/String;

    .line 996
    .line 997
    const-string v5, "audio/vorbis"

    .line 998
    .line 999
    invoke-static {v5}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 1000
    .line 1001
    .line 1002
    move-result-object v5

    .line 1003
    iput-object v5, v4, Lt7/n;->m:Ljava/lang/String;

    .line 1004
    .line 1005
    iget v5, v0, Lo8/a0;->d:I

    .line 1006
    .line 1007
    iput v5, v4, Lt7/n;->h:I

    .line 1008
    .line 1009
    iget v5, v0, Lo8/a0;->c:I

    .line 1010
    .line 1011
    iput v5, v4, Lt7/n;->i:I

    .line 1012
    .line 1013
    iget v5, v0, Lo8/a0;->a:I

    .line 1014
    .line 1015
    iput v5, v4, Lt7/n;->E:I

    .line 1016
    .line 1017
    iget v0, v0, Lo8/a0;->b:I

    .line 1018
    .line 1019
    iput v0, v4, Lt7/n;->F:I

    .line 1020
    .line 1021
    iput-object v1, v4, Lt7/n;->p:Ljava/util/List;

    .line 1022
    .line 1023
    iput-object v3, v4, Lt7/n;->k:Lt7/c0;

    .line 1024
    .line 1025
    new-instance v0, Lt7/o;

    .line 1026
    .line 1027
    invoke-direct {v0, v4}, Lt7/o;-><init>(Lt7/n;)V

    .line 1028
    .line 1029
    .line 1030
    iput-object v0, v2, Lb81/c;->e:Ljava/lang/Object;

    .line 1031
    .line 1032
    const/16 v17, 0x1

    .line 1033
    .line 1034
    return v17

    .line 1035
    :cond_30
    const-string v0, "framing bit after modes not set as expected"

    .line 1036
    .line 1037
    const/4 v1, 0x0

    .line 1038
    invoke-static {v1, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 1039
    .line 1040
    .line 1041
    move-result-object v0

    .line 1042
    throw v0
.end method

.method public final d(Z)V
    .locals 0

    .line 1
    invoke-super {p0, p1}, Lj9/j;->d(Z)V

    .line 2
    .line 3
    .line 4
    if-eqz p1, :cond_0

    .line 5
    .line 6
    const/4 p1, 0x0

    .line 7
    iput-object p1, p0, Lj9/k;->n:Lca/m;

    .line 8
    .line 9
    iput-object p1, p0, Lj9/k;->q:Lo8/a0;

    .line 10
    .line 11
    iput-object p1, p0, Lj9/k;->r:Lhu/q;

    .line 12
    .line 13
    :cond_0
    const/4 p1, 0x0

    .line 14
    iput p1, p0, Lj9/k;->o:I

    .line 15
    .line 16
    iput-boolean p1, p0, Lj9/k;->p:Z

    .line 17
    .line 18
    return-void
.end method
