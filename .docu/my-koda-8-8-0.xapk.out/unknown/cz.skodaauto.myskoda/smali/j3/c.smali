.class public final Lj3/c;
.super Lj3/c0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public b:[F

.field public final c:Ljava/util/ArrayList;

.field public d:Z

.field public e:J

.field public f:Ljava/util/List;

.field public g:Z

.field public h:Le3/i;

.field public i:Lay0/k;

.field public final j:La3/f;

.field public k:Ljava/lang/String;

.field public l:F

.field public m:F

.field public n:F

.field public o:F

.field public p:F

.field public q:F

.field public r:F

.field public s:Z


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lj3/c;->c:Ljava/util/ArrayList;

    .line 10
    .line 11
    const/4 v0, 0x1

    .line 12
    iput-boolean v0, p0, Lj3/c;->d:Z

    .line 13
    .line 14
    sget-wide v1, Le3/s;->i:J

    .line 15
    .line 16
    iput-wide v1, p0, Lj3/c;->e:J

    .line 17
    .line 18
    sget v1, Lj3/h0;->a:I

    .line 19
    .line 20
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 21
    .line 22
    iput-object v1, p0, Lj3/c;->f:Ljava/util/List;

    .line 23
    .line 24
    iput-boolean v0, p0, Lj3/c;->g:Z

    .line 25
    .line 26
    new-instance v1, La3/f;

    .line 27
    .line 28
    const/16 v2, 0x13

    .line 29
    .line 30
    invoke-direct {v1, p0, v2}, La3/f;-><init>(Ljava/lang/Object;I)V

    .line 31
    .line 32
    .line 33
    iput-object v1, p0, Lj3/c;->j:La3/f;

    .line 34
    .line 35
    const-string v1, ""

    .line 36
    .line 37
    iput-object v1, p0, Lj3/c;->k:Ljava/lang/String;

    .line 38
    .line 39
    const/high16 v1, 0x3f800000    # 1.0f

    .line 40
    .line 41
    iput v1, p0, Lj3/c;->o:F

    .line 42
    .line 43
    iput v1, p0, Lj3/c;->p:F

    .line 44
    .line 45
    iput-boolean v0, p0, Lj3/c;->s:Z

    .line 46
    .line 47
    return-void
.end method


# virtual methods
.method public final a(Lg3/d;)V
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-boolean v1, v0, Lj3/c;->s:Z

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    const/4 v3, 0x0

    .line 7
    if-eqz v1, :cond_3

    .line 8
    .line 9
    iget-object v1, v0, Lj3/c;->b:[F

    .line 10
    .line 11
    if-nez v1, :cond_0

    .line 12
    .line 13
    invoke-static {}, Le3/c0;->a()[F

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    iput-object v1, v0, Lj3/c;->b:[F

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    invoke-static {v1}, Le3/c0;->d([F)V

    .line 21
    .line 22
    .line 23
    :goto_0
    iget v4, v0, Lj3/c;->q:F

    .line 24
    .line 25
    iget v5, v0, Lj3/c;->m:F

    .line 26
    .line 27
    add-float/2addr v4, v5

    .line 28
    iget v5, v0, Lj3/c;->r:F

    .line 29
    .line 30
    iget v6, v0, Lj3/c;->n:F

    .line 31
    .line 32
    add-float/2addr v5, v6

    .line 33
    invoke-static {v1, v4, v5}, Le3/c0;->f([FFF)V

    .line 34
    .line 35
    .line 36
    iget v4, v0, Lj3/c;->l:F

    .line 37
    .line 38
    array-length v5, v1

    .line 39
    const/16 v6, 0x10

    .line 40
    .line 41
    if-ge v5, v6, :cond_1

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_1
    float-to-double v4, v4

    .line 45
    const-wide v6, 0x3f91df46a2529d39L    # 0.017453292519943295

    .line 46
    .line 47
    .line 48
    .line 49
    .line 50
    mul-double/2addr v4, v6

    .line 51
    invoke-static {v4, v5}, Ljava/lang/Math;->sin(D)D

    .line 52
    .line 53
    .line 54
    move-result-wide v6

    .line 55
    double-to-float v6, v6

    .line 56
    invoke-static {v4, v5}, Ljava/lang/Math;->cos(D)D

    .line 57
    .line 58
    .line 59
    move-result-wide v4

    .line 60
    double-to-float v4, v4

    .line 61
    const/4 v5, 0x0

    .line 62
    aget v7, v1, v5

    .line 63
    .line 64
    const/4 v8, 0x4

    .line 65
    aget v9, v1, v8

    .line 66
    .line 67
    mul-float v10, v4, v7

    .line 68
    .line 69
    mul-float v11, v6, v9

    .line 70
    .line 71
    add-float/2addr v11, v10

    .line 72
    neg-float v10, v6

    .line 73
    mul-float/2addr v7, v10

    .line 74
    mul-float/2addr v9, v4

    .line 75
    add-float/2addr v9, v7

    .line 76
    const/4 v7, 0x1

    .line 77
    aget v12, v1, v7

    .line 78
    .line 79
    const/4 v13, 0x5

    .line 80
    aget v14, v1, v13

    .line 81
    .line 82
    mul-float v15, v4, v12

    .line 83
    .line 84
    mul-float v16, v6, v14

    .line 85
    .line 86
    add-float v16, v16, v15

    .line 87
    .line 88
    mul-float/2addr v12, v10

    .line 89
    mul-float/2addr v14, v4

    .line 90
    add-float/2addr v14, v12

    .line 91
    const/4 v12, 0x2

    .line 92
    aget v15, v1, v12

    .line 93
    .line 94
    const/16 v17, 0x6

    .line 95
    .line 96
    aget v18, v1, v17

    .line 97
    .line 98
    mul-float v19, v4, v15

    .line 99
    .line 100
    mul-float v20, v6, v18

    .line 101
    .line 102
    add-float v20, v20, v19

    .line 103
    .line 104
    mul-float/2addr v15, v10

    .line 105
    mul-float v18, v18, v4

    .line 106
    .line 107
    add-float v18, v18, v15

    .line 108
    .line 109
    const/4 v15, 0x3

    .line 110
    aget v19, v1, v15

    .line 111
    .line 112
    const/16 v21, 0x7

    .line 113
    .line 114
    aget v22, v1, v21

    .line 115
    .line 116
    mul-float v23, v4, v19

    .line 117
    .line 118
    mul-float v6, v6, v22

    .line 119
    .line 120
    add-float v6, v6, v23

    .line 121
    .line 122
    mul-float v10, v10, v19

    .line 123
    .line 124
    mul-float v4, v4, v22

    .line 125
    .line 126
    add-float/2addr v4, v10

    .line 127
    aput v11, v1, v5

    .line 128
    .line 129
    aput v16, v1, v7

    .line 130
    .line 131
    aput v20, v1, v12

    .line 132
    .line 133
    aput v6, v1, v15

    .line 134
    .line 135
    aput v9, v1, v8

    .line 136
    .line 137
    aput v14, v1, v13

    .line 138
    .line 139
    aput v18, v1, v17

    .line 140
    .line 141
    aput v4, v1, v21

    .line 142
    .line 143
    :goto_1
    iget v4, v0, Lj3/c;->o:F

    .line 144
    .line 145
    iget v5, v0, Lj3/c;->p:F

    .line 146
    .line 147
    array-length v6, v1

    .line 148
    const/16 v7, 0x10

    .line 149
    .line 150
    if-ge v6, v7, :cond_2

    .line 151
    .line 152
    goto :goto_2

    .line 153
    :cond_2
    aget v6, v1, v3

    .line 154
    .line 155
    mul-float/2addr v6, v4

    .line 156
    aput v6, v1, v3

    .line 157
    .line 158
    aget v6, v1, v2

    .line 159
    .line 160
    mul-float/2addr v6, v4

    .line 161
    aput v6, v1, v2

    .line 162
    .line 163
    const/4 v6, 0x2

    .line 164
    aget v7, v1, v6

    .line 165
    .line 166
    mul-float/2addr v7, v4

    .line 167
    aput v7, v1, v6

    .line 168
    .line 169
    const/4 v6, 0x3

    .line 170
    aget v7, v1, v6

    .line 171
    .line 172
    mul-float/2addr v7, v4

    .line 173
    aput v7, v1, v6

    .line 174
    .line 175
    const/4 v4, 0x4

    .line 176
    aget v6, v1, v4

    .line 177
    .line 178
    mul-float/2addr v6, v5

    .line 179
    aput v6, v1, v4

    .line 180
    .line 181
    const/4 v4, 0x5

    .line 182
    aget v6, v1, v4

    .line 183
    .line 184
    mul-float/2addr v6, v5

    .line 185
    aput v6, v1, v4

    .line 186
    .line 187
    const/4 v4, 0x6

    .line 188
    aget v6, v1, v4

    .line 189
    .line 190
    mul-float/2addr v6, v5

    .line 191
    aput v6, v1, v4

    .line 192
    .line 193
    const/4 v4, 0x7

    .line 194
    aget v6, v1, v4

    .line 195
    .line 196
    mul-float/2addr v6, v5

    .line 197
    aput v6, v1, v4

    .line 198
    .line 199
    const/16 v4, 0x8

    .line 200
    .line 201
    aget v5, v1, v4

    .line 202
    .line 203
    const/high16 v6, 0x3f800000    # 1.0f

    .line 204
    .line 205
    mul-float/2addr v5, v6

    .line 206
    aput v5, v1, v4

    .line 207
    .line 208
    const/16 v4, 0x9

    .line 209
    .line 210
    aget v5, v1, v4

    .line 211
    .line 212
    mul-float/2addr v5, v6

    .line 213
    aput v5, v1, v4

    .line 214
    .line 215
    const/16 v4, 0xa

    .line 216
    .line 217
    aget v5, v1, v4

    .line 218
    .line 219
    mul-float/2addr v5, v6

    .line 220
    aput v5, v1, v4

    .line 221
    .line 222
    const/16 v4, 0xb

    .line 223
    .line 224
    aget v5, v1, v4

    .line 225
    .line 226
    mul-float/2addr v5, v6

    .line 227
    aput v5, v1, v4

    .line 228
    .line 229
    :goto_2
    iget v4, v0, Lj3/c;->m:F

    .line 230
    .line 231
    neg-float v4, v4

    .line 232
    iget v5, v0, Lj3/c;->n:F

    .line 233
    .line 234
    neg-float v5, v5

    .line 235
    invoke-static {v1, v4, v5}, Le3/c0;->f([FFF)V

    .line 236
    .line 237
    .line 238
    iput-boolean v3, v0, Lj3/c;->s:Z

    .line 239
    .line 240
    :cond_3
    iget-boolean v1, v0, Lj3/c;->g:Z

    .line 241
    .line 242
    if-eqz v1, :cond_6

    .line 243
    .line 244
    iget-object v1, v0, Lj3/c;->f:Ljava/util/List;

    .line 245
    .line 246
    check-cast v1, Ljava/util/Collection;

    .line 247
    .line 248
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 249
    .line 250
    .line 251
    move-result v1

    .line 252
    if-nez v1, :cond_5

    .line 253
    .line 254
    iget-object v1, v0, Lj3/c;->h:Le3/i;

    .line 255
    .line 256
    if-nez v1, :cond_4

    .line 257
    .line 258
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 259
    .line 260
    .line 261
    move-result-object v1

    .line 262
    iput-object v1, v0, Lj3/c;->h:Le3/i;

    .line 263
    .line 264
    :cond_4
    iget-object v4, v0, Lj3/c;->f:Ljava/util/List;

    .line 265
    .line 266
    invoke-static {v4, v1}, Lj3/b;->d(Ljava/util/List;Le3/i;)V

    .line 267
    .line 268
    .line 269
    :cond_5
    iput-boolean v3, v0, Lj3/c;->g:Z

    .line 270
    .line 271
    :cond_6
    invoke-interface/range {p1 .. p1}, Lg3/d;->x0()Lgw0/c;

    .line 272
    .line 273
    .line 274
    move-result-object v1

    .line 275
    invoke-virtual {v1}, Lgw0/c;->o()J

    .line 276
    .line 277
    .line 278
    move-result-wide v4

    .line 279
    invoke-virtual {v1}, Lgw0/c;->h()Le3/r;

    .line 280
    .line 281
    .line 282
    move-result-object v6

    .line 283
    invoke-interface {v6}, Le3/r;->o()V

    .line 284
    .line 285
    .line 286
    :try_start_0
    iget-object v6, v1, Lgw0/c;->e:Ljava/lang/Object;

    .line 287
    .line 288
    check-cast v6, Lbu/c;

    .line 289
    .line 290
    iget-object v6, v6, Lbu/c;->e:Ljava/lang/Object;

    .line 291
    .line 292
    check-cast v6, Lgw0/c;

    .line 293
    .line 294
    iget-object v7, v0, Lj3/c;->b:[F

    .line 295
    .line 296
    if-eqz v7, :cond_7

    .line 297
    .line 298
    invoke-virtual {v6}, Lgw0/c;->h()Le3/r;

    .line 299
    .line 300
    .line 301
    move-result-object v8

    .line 302
    invoke-interface {v8, v7}, Le3/r;->q([F)V

    .line 303
    .line 304
    .line 305
    :cond_7
    iget-object v7, v0, Lj3/c;->h:Le3/i;

    .line 306
    .line 307
    iget-object v8, v0, Lj3/c;->f:Ljava/util/List;

    .line 308
    .line 309
    check-cast v8, Ljava/util/Collection;

    .line 310
    .line 311
    invoke-interface {v8}, Ljava/util/Collection;->isEmpty()Z

    .line 312
    .line 313
    .line 314
    move-result v8

    .line 315
    if-nez v8, :cond_8

    .line 316
    .line 317
    if-eqz v7, :cond_8

    .line 318
    .line 319
    invoke-virtual {v6}, Lgw0/c;->h()Le3/r;

    .line 320
    .line 321
    .line 322
    move-result-object v6

    .line 323
    invoke-interface {v6, v7, v2}, Le3/r;->e(Le3/i;I)V

    .line 324
    .line 325
    .line 326
    :cond_8
    iget-object v0, v0, Lj3/c;->c:Ljava/util/ArrayList;

    .line 327
    .line 328
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 329
    .line 330
    .line 331
    move-result v2

    .line 332
    :goto_3
    if-ge v3, v2, :cond_9

    .line 333
    .line 334
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 335
    .line 336
    .line 337
    move-result-object v6

    .line 338
    check-cast v6, Lj3/c0;

    .line 339
    .line 340
    move-object/from16 v7, p1

    .line 341
    .line 342
    invoke-virtual {v6, v7}, Lj3/c0;->a(Lg3/d;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 343
    .line 344
    .line 345
    add-int/lit8 v3, v3, 0x1

    .line 346
    .line 347
    goto :goto_3

    .line 348
    :catchall_0
    move-exception v0

    .line 349
    goto :goto_4

    .line 350
    :cond_9
    invoke-static {v1, v4, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 351
    .line 352
    .line 353
    return-void

    .line 354
    :goto_4
    invoke-static {v1, v4, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 355
    .line 356
    .line 357
    throw v0
.end method

.method public final b()Lay0/k;
    .locals 0

    .line 1
    iget-object p0, p0, Lj3/c;->i:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public final d(La3/f;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lj3/c;->i:Lay0/k;

    .line 2
    .line 3
    return-void
.end method

.method public final e(ILj3/c0;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lj3/c;->c:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-ge p1, v1, :cond_0

    .line 8
    .line 9
    invoke-virtual {v0, p1, p2}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    invoke-virtual {v0, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    :goto_0
    invoke-virtual {p0, p2}, Lj3/c;->g(Lj3/c0;)V

    .line 17
    .line 18
    .line 19
    iget-object p1, p0, Lj3/c;->j:La3/f;

    .line 20
    .line 21
    invoke-virtual {p2, p1}, Lj3/c0;->d(La3/f;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0}, Lj3/c0;->c()V

    .line 25
    .line 26
    .line 27
    return-void
.end method

.method public final f(J)V
    .locals 4

    .line 1
    iget-boolean v0, p0, Lj3/c;->d:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    const-wide/16 v0, 0x10

    .line 7
    .line 8
    cmp-long v2, p1, v0

    .line 9
    .line 10
    if-eqz v2, :cond_3

    .line 11
    .line 12
    iget-wide v2, p0, Lj3/c;->e:J

    .line 13
    .line 14
    cmp-long v0, v2, v0

    .line 15
    .line 16
    if-nez v0, :cond_1

    .line 17
    .line 18
    iput-wide p1, p0, Lj3/c;->e:J

    .line 19
    .line 20
    return-void

    .line 21
    :cond_1
    sget v0, Lj3/h0;->a:I

    .line 22
    .line 23
    invoke-static {v2, v3}, Le3/s;->h(J)F

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    invoke-static {p1, p2}, Le3/s;->h(J)F

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    cmpg-float v0, v0, v1

    .line 32
    .line 33
    if-nez v0, :cond_2

    .line 34
    .line 35
    invoke-static {v2, v3}, Le3/s;->g(J)F

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    invoke-static {p1, p2}, Le3/s;->g(J)F

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    cmpg-float v0, v0, v1

    .line 44
    .line 45
    if-nez v0, :cond_2

    .line 46
    .line 47
    invoke-static {v2, v3}, Le3/s;->e(J)F

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    invoke-static {p1, p2}, Le3/s;->e(J)F

    .line 52
    .line 53
    .line 54
    move-result p1

    .line 55
    cmpg-float p1, v0, p1

    .line 56
    .line 57
    if-nez p1, :cond_2

    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_2
    const/4 p1, 0x0

    .line 61
    iput-boolean p1, p0, Lj3/c;->d:Z

    .line 62
    .line 63
    sget-wide p1, Le3/s;->i:J

    .line 64
    .line 65
    iput-wide p1, p0, Lj3/c;->e:J

    .line 66
    .line 67
    :cond_3
    :goto_0
    return-void
.end method

.method public final g(Lj3/c0;)V
    .locals 4

    .line 1
    instance-of v0, p1, Lj3/h;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_5

    .line 5
    .line 6
    check-cast p1, Lj3/h;

    .line 7
    .line 8
    iget-object v0, p1, Lj3/h;->b:Le3/p;

    .line 9
    .line 10
    iget-boolean v2, p0, Lj3/c;->d:Z

    .line 11
    .line 12
    if-nez v2, :cond_0

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    if-eqz v0, :cond_2

    .line 16
    .line 17
    instance-of v2, v0, Le3/p0;

    .line 18
    .line 19
    if-eqz v2, :cond_1

    .line 20
    .line 21
    check-cast v0, Le3/p0;

    .line 22
    .line 23
    iget-wide v2, v0, Le3/p0;->a:J

    .line 24
    .line 25
    invoke-virtual {p0, v2, v3}, Lj3/c;->f(J)V

    .line 26
    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_1
    iput-boolean v1, p0, Lj3/c;->d:Z

    .line 30
    .line 31
    sget-wide v2, Le3/s;->i:J

    .line 32
    .line 33
    iput-wide v2, p0, Lj3/c;->e:J

    .line 34
    .line 35
    :cond_2
    :goto_0
    iget-object p1, p1, Lj3/h;->g:Le3/p;

    .line 36
    .line 37
    iget-boolean v0, p0, Lj3/c;->d:Z

    .line 38
    .line 39
    if-nez v0, :cond_3

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_3
    if-eqz p1, :cond_7

    .line 43
    .line 44
    instance-of v0, p1, Le3/p0;

    .line 45
    .line 46
    if-eqz v0, :cond_4

    .line 47
    .line 48
    check-cast p1, Le3/p0;

    .line 49
    .line 50
    iget-wide v0, p1, Le3/p0;->a:J

    .line 51
    .line 52
    invoke-virtual {p0, v0, v1}, Lj3/c;->f(J)V

    .line 53
    .line 54
    .line 55
    return-void

    .line 56
    :cond_4
    iput-boolean v1, p0, Lj3/c;->d:Z

    .line 57
    .line 58
    sget-wide v0, Le3/s;->i:J

    .line 59
    .line 60
    iput-wide v0, p0, Lj3/c;->e:J

    .line 61
    .line 62
    return-void

    .line 63
    :cond_5
    instance-of v0, p1, Lj3/c;

    .line 64
    .line 65
    if-eqz v0, :cond_7

    .line 66
    .line 67
    check-cast p1, Lj3/c;

    .line 68
    .line 69
    iget-boolean v0, p1, Lj3/c;->d:Z

    .line 70
    .line 71
    if-eqz v0, :cond_6

    .line 72
    .line 73
    iget-boolean v0, p0, Lj3/c;->d:Z

    .line 74
    .line 75
    if-eqz v0, :cond_6

    .line 76
    .line 77
    iget-wide v0, p1, Lj3/c;->e:J

    .line 78
    .line 79
    invoke-virtual {p0, v0, v1}, Lj3/c;->f(J)V

    .line 80
    .line 81
    .line 82
    return-void

    .line 83
    :cond_6
    iput-boolean v1, p0, Lj3/c;->d:Z

    .line 84
    .line 85
    sget-wide v0, Le3/s;->i:J

    .line 86
    .line 87
    iput-wide v0, p0, Lj3/c;->e:J

    .line 88
    .line 89
    :cond_7
    :goto_1
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "VGroup: "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lj3/c;->k:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lj3/c;->c:Ljava/util/ArrayList;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    const/4 v2, 0x0

    .line 20
    :goto_0
    if-ge v2, v1, :cond_0

    .line 21
    .line 22
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v3

    .line 26
    check-cast v3, Lj3/c0;

    .line 27
    .line 28
    const-string v4, "\t"

    .line 29
    .line 30
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    invoke-virtual {v3}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v3

    .line 37
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    const-string v3, "\n"

    .line 41
    .line 42
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    add-int/lit8 v2, v2, 0x1

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_0
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0
.end method
