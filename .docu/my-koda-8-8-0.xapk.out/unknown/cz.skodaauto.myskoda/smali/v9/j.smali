.class public final Lv9/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv9/h;


# static fields
.field public static final r:[D


# instance fields
.field public a:Ljava/lang/String;

.field public b:Lo8/i0;

.field public final c:Lv9/c0;

.field public final d:Ljava/lang/String;

.field public final e:Lw7/p;

.field public final f:La8/n0;

.field public final g:[Z

.field public final h:Lv9/i;

.field public i:J

.field public j:Z

.field public k:Z

.field public l:J

.field public m:J

.field public n:J

.field public o:J

.field public p:Z

.field public q:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x8

    .line 2
    .line 3
    new-array v0, v0, [D

    .line 4
    .line 5
    fill-array-data v0, :array_0

    .line 6
    .line 7
    .line 8
    sput-object v0, Lv9/j;->r:[D

    .line 9
    .line 10
    return-void

    .line 11
    :array_0
    .array-data 8
        0x4037f9dcb5112287L    # 23.976023976023978
        0x4038000000000000L    # 24.0
        0x4039000000000000L    # 25.0
        0x403df853e2556b28L    # 29.97002997002997
        0x403e000000000000L    # 30.0
        0x4049000000000000L    # 50.0
        0x404df853e2556b28L    # 59.94005994005994
        0x404e000000000000L    # 60.0
    .end array-data
.end method

.method public constructor <init>(Lv9/c0;Ljava/lang/String;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lv9/j;->c:Lv9/c0;

    .line 5
    .line 6
    iput-object p2, p0, Lv9/j;->d:Ljava/lang/String;

    .line 7
    .line 8
    const/4 p2, 0x4

    .line 9
    new-array p2, p2, [Z

    .line 10
    .line 11
    iput-object p2, p0, Lv9/j;->g:[Z

    .line 12
    .line 13
    new-instance p2, Lv9/i;

    .line 14
    .line 15
    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    .line 16
    .line 17
    .line 18
    const/16 v0, 0x80

    .line 19
    .line 20
    new-array v0, v0, [B

    .line 21
    .line 22
    iput-object v0, p2, Lv9/i;->d:[B

    .line 23
    .line 24
    iput-object p2, p0, Lv9/j;->h:Lv9/i;

    .line 25
    .line 26
    if-eqz p1, :cond_0

    .line 27
    .line 28
    new-instance p1, La8/n0;

    .line 29
    .line 30
    const/16 p2, 0xb2

    .line 31
    .line 32
    invoke-direct {p1, p2}, La8/n0;-><init>(I)V

    .line 33
    .line 34
    .line 35
    iput-object p1, p0, Lv9/j;->f:La8/n0;

    .line 36
    .line 37
    new-instance p1, Lw7/p;

    .line 38
    .line 39
    invoke-direct {p1}, Lw7/p;-><init>()V

    .line 40
    .line 41
    .line 42
    iput-object p1, p0, Lv9/j;->e:Lw7/p;

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_0
    const/4 p1, 0x0

    .line 46
    iput-object p1, p0, Lv9/j;->f:La8/n0;

    .line 47
    .line 48
    iput-object p1, p0, Lv9/j;->e:Lw7/p;

    .line 49
    .line 50
    :goto_0
    const-wide p1, -0x7fffffffffffffffL    # -4.9E-324

    .line 51
    .line 52
    .line 53
    .line 54
    .line 55
    iput-wide p1, p0, Lv9/j;->m:J

    .line 56
    .line 57
    iput-wide p1, p0, Lv9/j;->o:J

    .line 58
    .line 59
    return-void
.end method


# virtual methods
.method public final b(Lw7/p;)V
    .locals 28

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Lv9/j;->b:Lo8/i0;

    .line 6
    .line 7
    invoke-static {v2}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    iget v2, v1, Lw7/p;->b:I

    .line 11
    .line 12
    iget v3, v1, Lw7/p;->c:I

    .line 13
    .line 14
    iget-object v4, v1, Lw7/p;->a:[B

    .line 15
    .line 16
    iget-wide v5, v0, Lv9/j;->i:J

    .line 17
    .line 18
    invoke-virtual {v1}, Lw7/p;->a()I

    .line 19
    .line 20
    .line 21
    move-result v7

    .line 22
    int-to-long v7, v7

    .line 23
    add-long/2addr v5, v7

    .line 24
    iput-wide v5, v0, Lv9/j;->i:J

    .line 25
    .line 26
    iget-object v5, v0, Lv9/j;->b:Lo8/i0;

    .line 27
    .line 28
    invoke-virtual {v1}, Lw7/p;->a()I

    .line 29
    .line 30
    .line 31
    move-result v6

    .line 32
    const/4 v7, 0x0

    .line 33
    invoke-interface {v5, v1, v6, v7}, Lo8/i0;->a(Lw7/p;II)V

    .line 34
    .line 35
    .line 36
    :goto_0
    iget-object v5, v0, Lv9/j;->g:[Z

    .line 37
    .line 38
    invoke-static {v4, v2, v3, v5}, Lx7/n;->b([BII[Z)I

    .line 39
    .line 40
    .line 41
    move-result v5

    .line 42
    iget-object v6, v0, Lv9/j;->h:Lv9/i;

    .line 43
    .line 44
    iget-object v8, v0, Lv9/j;->f:La8/n0;

    .line 45
    .line 46
    if-ne v5, v3, :cond_2

    .line 47
    .line 48
    iget-boolean v0, v0, Lv9/j;->k:Z

    .line 49
    .line 50
    if-nez v0, :cond_0

    .line 51
    .line 52
    invoke-virtual {v6, v4, v2, v3}, Lv9/i;->a([BII)V

    .line 53
    .line 54
    .line 55
    :cond_0
    if-eqz v8, :cond_1

    .line 56
    .line 57
    invoke-virtual {v8, v4, v2, v3}, La8/n0;->a([BII)V

    .line 58
    .line 59
    .line 60
    :cond_1
    return-void

    .line 61
    :cond_2
    iget-object v9, v1, Lw7/p;->a:[B

    .line 62
    .line 63
    add-int/lit8 v10, v5, 0x3

    .line 64
    .line 65
    aget-byte v9, v9, v10

    .line 66
    .line 67
    and-int/lit16 v9, v9, 0xff

    .line 68
    .line 69
    sub-int v11, v5, v2

    .line 70
    .line 71
    iget-boolean v12, v0, Lv9/j;->k:Z

    .line 72
    .line 73
    if-nez v12, :cond_d

    .line 74
    .line 75
    if-lez v11, :cond_3

    .line 76
    .line 77
    invoke-virtual {v6, v4, v2, v5}, Lv9/i;->a([BII)V

    .line 78
    .line 79
    .line 80
    :cond_3
    if-gez v11, :cond_4

    .line 81
    .line 82
    neg-int v12, v11

    .line 83
    goto :goto_1

    .line 84
    :cond_4
    move v12, v7

    .line 85
    :goto_1
    iget-boolean v15, v6, Lv9/i;->a:Z

    .line 86
    .line 87
    if-eqz v15, :cond_b

    .line 88
    .line 89
    iget v15, v6, Lv9/i;->b:I

    .line 90
    .line 91
    sub-int/2addr v15, v12

    .line 92
    iput v15, v6, Lv9/i;->b:I

    .line 93
    .line 94
    iget v12, v6, Lv9/i;->c:I

    .line 95
    .line 96
    if-nez v12, :cond_5

    .line 97
    .line 98
    const/16 v12, 0xb5

    .line 99
    .line 100
    if-ne v9, v12, :cond_5

    .line 101
    .line 102
    iput v15, v6, Lv9/i;->c:I

    .line 103
    .line 104
    move/from16 v20, v3

    .line 105
    .line 106
    goto/16 :goto_5

    .line 107
    .line 108
    :cond_5
    iput-boolean v7, v6, Lv9/i;->a:Z

    .line 109
    .line 110
    iget-object v12, v0, Lv9/j;->a:Ljava/lang/String;

    .line 111
    .line 112
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 113
    .line 114
    .line 115
    iget-object v15, v6, Lv9/i;->d:[B

    .line 116
    .line 117
    iget v7, v6, Lv9/i;->b:I

    .line 118
    .line 119
    invoke-static {v15, v7}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 120
    .line 121
    .line 122
    move-result-object v7

    .line 123
    const/4 v15, 0x4

    .line 124
    const/16 v16, 0x1

    .line 125
    .line 126
    aget-byte v14, v7, v15

    .line 127
    .line 128
    and-int/lit16 v14, v14, 0xff

    .line 129
    .line 130
    const/16 v17, 0x5

    .line 131
    .line 132
    move/from16 v18, v15

    .line 133
    .line 134
    aget-byte v15, v7, v17

    .line 135
    .line 136
    and-int/lit16 v13, v15, 0xff

    .line 137
    .line 138
    const/16 v19, 0x6

    .line 139
    .line 140
    move/from16 v20, v3

    .line 141
    .line 142
    aget-byte v3, v7, v19

    .line 143
    .line 144
    and-int/lit16 v3, v3, 0xff

    .line 145
    .line 146
    shl-int/lit8 v14, v14, 0x4

    .line 147
    .line 148
    shr-int/lit8 v13, v13, 0x4

    .line 149
    .line 150
    or-int/2addr v13, v14

    .line 151
    and-int/lit8 v14, v15, 0xf

    .line 152
    .line 153
    const/16 v15, 0x8

    .line 154
    .line 155
    shl-int/2addr v14, v15

    .line 156
    or-int/2addr v3, v14

    .line 157
    const/16 v19, 0x7

    .line 158
    .line 159
    aget-byte v14, v7, v19

    .line 160
    .line 161
    and-int/lit16 v14, v14, 0xf0

    .line 162
    .line 163
    shr-int/lit8 v14, v14, 0x4

    .line 164
    .line 165
    const/4 v15, 0x2

    .line 166
    if-eq v14, v15, :cond_8

    .line 167
    .line 168
    const/4 v15, 0x3

    .line 169
    if-eq v14, v15, :cond_7

    .line 170
    .line 171
    move/from16 v15, v18

    .line 172
    .line 173
    if-eq v14, v15, :cond_6

    .line 174
    .line 175
    const/high16 v14, 0x3f800000    # 1.0f

    .line 176
    .line 177
    goto :goto_3

    .line 178
    :cond_6
    mul-int/lit8 v14, v3, 0x79

    .line 179
    .line 180
    int-to-float v14, v14

    .line 181
    mul-int/lit8 v15, v13, 0x64

    .line 182
    .line 183
    :goto_2
    int-to-float v15, v15

    .line 184
    div-float/2addr v14, v15

    .line 185
    goto :goto_3

    .line 186
    :cond_7
    mul-int/lit8 v14, v3, 0x10

    .line 187
    .line 188
    int-to-float v14, v14

    .line 189
    mul-int/lit8 v15, v13, 0x9

    .line 190
    .line 191
    goto :goto_2

    .line 192
    :cond_8
    mul-int/lit8 v14, v3, 0x4

    .line 193
    .line 194
    int-to-float v14, v14

    .line 195
    mul-int/lit8 v15, v13, 0x3

    .line 196
    .line 197
    goto :goto_2

    .line 198
    :goto_3
    new-instance v15, Lt7/n;

    .line 199
    .line 200
    invoke-direct {v15}, Lt7/n;-><init>()V

    .line 201
    .line 202
    .line 203
    iput-object v12, v15, Lt7/n;->a:Ljava/lang/String;

    .line 204
    .line 205
    iget-object v12, v0, Lv9/j;->d:Ljava/lang/String;

    .line 206
    .line 207
    invoke-static {v12}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 208
    .line 209
    .line 210
    move-result-object v12

    .line 211
    iput-object v12, v15, Lt7/n;->l:Ljava/lang/String;

    .line 212
    .line 213
    const-string v12, "video/mpeg2"

    .line 214
    .line 215
    invoke-static {v12}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 216
    .line 217
    .line 218
    move-result-object v12

    .line 219
    iput-object v12, v15, Lt7/n;->m:Ljava/lang/String;

    .line 220
    .line 221
    iput v13, v15, Lt7/n;->t:I

    .line 222
    .line 223
    iput v3, v15, Lt7/n;->u:I

    .line 224
    .line 225
    iput v14, v15, Lt7/n;->z:F

    .line 226
    .line 227
    invoke-static {v7}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 228
    .line 229
    .line 230
    move-result-object v3

    .line 231
    iput-object v3, v15, Lt7/n;->p:Ljava/util/List;

    .line 232
    .line 233
    new-instance v3, Lt7/o;

    .line 234
    .line 235
    invoke-direct {v3, v15}, Lt7/o;-><init>(Lt7/n;)V

    .line 236
    .line 237
    .line 238
    aget-byte v12, v7, v19

    .line 239
    .line 240
    and-int/lit8 v12, v12, 0xf

    .line 241
    .line 242
    add-int/lit8 v12, v12, -0x1

    .line 243
    .line 244
    if-ltz v12, :cond_a

    .line 245
    .line 246
    const/16 v13, 0x8

    .line 247
    .line 248
    if-ge v12, v13, :cond_a

    .line 249
    .line 250
    sget-object v13, Lv9/j;->r:[D

    .line 251
    .line 252
    aget-wide v12, v13, v12

    .line 253
    .line 254
    iget v6, v6, Lv9/i;->c:I

    .line 255
    .line 256
    add-int/lit8 v6, v6, 0x9

    .line 257
    .line 258
    aget-byte v6, v7, v6

    .line 259
    .line 260
    and-int/lit8 v7, v6, 0x60

    .line 261
    .line 262
    shr-int/lit8 v7, v7, 0x5

    .line 263
    .line 264
    and-int/lit8 v6, v6, 0x1f

    .line 265
    .line 266
    if-eq v7, v6, :cond_9

    .line 267
    .line 268
    int-to-double v14, v7

    .line 269
    const-wide/high16 v17, 0x3ff0000000000000L    # 1.0

    .line 270
    .line 271
    add-double v14, v14, v17

    .line 272
    .line 273
    add-int/lit8 v6, v6, 0x1

    .line 274
    .line 275
    int-to-double v6, v6

    .line 276
    div-double/2addr v14, v6

    .line 277
    mul-double/2addr v12, v14

    .line 278
    :cond_9
    const-wide v6, 0x412e848000000000L    # 1000000.0

    .line 279
    .line 280
    .line 281
    .line 282
    .line 283
    div-double/2addr v6, v12

    .line 284
    double-to-long v6, v6

    .line 285
    goto :goto_4

    .line 286
    :cond_a
    const-wide/16 v6, 0x0

    .line 287
    .line 288
    :goto_4
    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 289
    .line 290
    .line 291
    move-result-object v6

    .line 292
    invoke-static {v3, v6}, Landroid/util/Pair;->create(Ljava/lang/Object;Ljava/lang/Object;)Landroid/util/Pair;

    .line 293
    .line 294
    .line 295
    move-result-object v3

    .line 296
    iget-object v6, v0, Lv9/j;->b:Lo8/i0;

    .line 297
    .line 298
    iget-object v7, v3, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 299
    .line 300
    check-cast v7, Lt7/o;

    .line 301
    .line 302
    invoke-interface {v6, v7}, Lo8/i0;->c(Lt7/o;)V

    .line 303
    .line 304
    .line 305
    iget-object v3, v3, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 306
    .line 307
    check-cast v3, Ljava/lang/Long;

    .line 308
    .line 309
    invoke-virtual {v3}, Ljava/lang/Long;->longValue()J

    .line 310
    .line 311
    .line 312
    move-result-wide v6

    .line 313
    iput-wide v6, v0, Lv9/j;->l:J

    .line 314
    .line 315
    move/from16 v3, v16

    .line 316
    .line 317
    iput-boolean v3, v0, Lv9/j;->k:Z

    .line 318
    .line 319
    goto :goto_6

    .line 320
    :cond_b
    move/from16 v20, v3

    .line 321
    .line 322
    const/4 v3, 0x1

    .line 323
    const/16 v7, 0xb3

    .line 324
    .line 325
    if-ne v9, v7, :cond_c

    .line 326
    .line 327
    iput-boolean v3, v6, Lv9/i;->a:Z

    .line 328
    .line 329
    :cond_c
    :goto_5
    sget-object v3, Lv9/i;->e:[B

    .line 330
    .line 331
    const/4 v7, 0x0

    .line 332
    const/4 v15, 0x3

    .line 333
    invoke-virtual {v6, v3, v7, v15}, Lv9/i;->a([BII)V

    .line 334
    .line 335
    .line 336
    goto :goto_6

    .line 337
    :cond_d
    move/from16 v20, v3

    .line 338
    .line 339
    :goto_6
    if-eqz v8, :cond_10

    .line 340
    .line 341
    if-lez v11, :cond_e

    .line 342
    .line 343
    invoke-virtual {v8, v4, v2, v5}, La8/n0;->a([BII)V

    .line 344
    .line 345
    .line 346
    const/4 v7, 0x0

    .line 347
    goto :goto_7

    .line 348
    :cond_e
    neg-int v7, v11

    .line 349
    :goto_7
    invoke-virtual {v8, v7}, La8/n0;->e(I)Z

    .line 350
    .line 351
    .line 352
    move-result v2

    .line 353
    if-eqz v2, :cond_f

    .line 354
    .line 355
    iget-object v2, v8, La8/n0;->f:Ljava/lang/Object;

    .line 356
    .line 357
    check-cast v2, [B

    .line 358
    .line 359
    iget v3, v8, La8/n0;->c:I

    .line 360
    .line 361
    invoke-static {v3, v2}, Lx7/n;->m(I[B)I

    .line 362
    .line 363
    .line 364
    move-result v2

    .line 365
    sget-object v3, Lw7/w;->a:Ljava/lang/String;

    .line 366
    .line 367
    iget-object v3, v8, La8/n0;->f:Ljava/lang/Object;

    .line 368
    .line 369
    check-cast v3, [B

    .line 370
    .line 371
    iget-object v6, v0, Lv9/j;->e:Lw7/p;

    .line 372
    .line 373
    invoke-virtual {v6, v2, v3}, Lw7/p;->G(I[B)V

    .line 374
    .line 375
    .line 376
    iget-object v2, v0, Lv9/j;->c:Lv9/c0;

    .line 377
    .line 378
    iget-wide v11, v0, Lv9/j;->o:J

    .line 379
    .line 380
    invoke-virtual {v2, v11, v12, v6}, Lv9/c0;->a(JLw7/p;)V

    .line 381
    .line 382
    .line 383
    :cond_f
    const/16 v2, 0xb2

    .line 384
    .line 385
    if-ne v9, v2, :cond_10

    .line 386
    .line 387
    iget-object v2, v1, Lw7/p;->a:[B

    .line 388
    .line 389
    add-int/lit8 v3, v5, 0x2

    .line 390
    .line 391
    aget-byte v2, v2, v3

    .line 392
    .line 393
    const/4 v3, 0x1

    .line 394
    if-ne v2, v3, :cond_11

    .line 395
    .line 396
    invoke-virtual {v8, v9}, La8/n0;->h(I)V

    .line 397
    .line 398
    .line 399
    goto :goto_8

    .line 400
    :cond_10
    const/4 v3, 0x1

    .line 401
    :cond_11
    :goto_8
    if-eqz v9, :cond_14

    .line 402
    .line 403
    const/16 v7, 0xb3

    .line 404
    .line 405
    if-ne v9, v7, :cond_12

    .line 406
    .line 407
    goto :goto_9

    .line 408
    :cond_12
    const/16 v2, 0xb8

    .line 409
    .line 410
    if-ne v9, v2, :cond_13

    .line 411
    .line 412
    iput-boolean v3, v0, Lv9/j;->p:Z

    .line 413
    .line 414
    :cond_13
    const/4 v7, 0x0

    .line 415
    goto/16 :goto_e

    .line 416
    .line 417
    :cond_14
    :goto_9
    sub-int v26, v20, v5

    .line 418
    .line 419
    iget-boolean v2, v0, Lv9/j;->q:Z

    .line 420
    .line 421
    const-wide v5, -0x7fffffffffffffffL    # -4.9E-324

    .line 422
    .line 423
    .line 424
    .line 425
    .line 426
    if-eqz v2, :cond_15

    .line 427
    .line 428
    iget-boolean v2, v0, Lv9/j;->k:Z

    .line 429
    .line 430
    if-eqz v2, :cond_15

    .line 431
    .line 432
    iget-wide v2, v0, Lv9/j;->o:J

    .line 433
    .line 434
    cmp-long v7, v2, v5

    .line 435
    .line 436
    if-eqz v7, :cond_15

    .line 437
    .line 438
    iget-boolean v7, v0, Lv9/j;->p:Z

    .line 439
    .line 440
    iget-wide v11, v0, Lv9/j;->i:J

    .line 441
    .line 442
    iget-wide v13, v0, Lv9/j;->n:J

    .line 443
    .line 444
    sub-long/2addr v11, v13

    .line 445
    long-to-int v8, v11

    .line 446
    sub-int v25, v8, v26

    .line 447
    .line 448
    iget-object v8, v0, Lv9/j;->b:Lo8/i0;

    .line 449
    .line 450
    const/16 v27, 0x0

    .line 451
    .line 452
    move-wide/from16 v22, v2

    .line 453
    .line 454
    move/from16 v24, v7

    .line 455
    .line 456
    move-object/from16 v21, v8

    .line 457
    .line 458
    invoke-interface/range {v21 .. v27}, Lo8/i0;->b(JIIILo8/h0;)V

    .line 459
    .line 460
    .line 461
    :cond_15
    move/from16 v3, v26

    .line 462
    .line 463
    iget-boolean v2, v0, Lv9/j;->j:Z

    .line 464
    .line 465
    if-eqz v2, :cond_17

    .line 466
    .line 467
    iget-boolean v2, v0, Lv9/j;->q:Z

    .line 468
    .line 469
    if-eqz v2, :cond_16

    .line 470
    .line 471
    goto :goto_a

    .line 472
    :cond_16
    const/4 v3, 0x1

    .line 473
    const/4 v7, 0x0

    .line 474
    goto :goto_c

    .line 475
    :cond_17
    :goto_a
    iget-wide v7, v0, Lv9/j;->i:J

    .line 476
    .line 477
    int-to-long v2, v3

    .line 478
    sub-long/2addr v7, v2

    .line 479
    iput-wide v7, v0, Lv9/j;->n:J

    .line 480
    .line 481
    iget-wide v2, v0, Lv9/j;->m:J

    .line 482
    .line 483
    cmp-long v7, v2, v5

    .line 484
    .line 485
    if-eqz v7, :cond_18

    .line 486
    .line 487
    goto :goto_b

    .line 488
    :cond_18
    iget-wide v2, v0, Lv9/j;->o:J

    .line 489
    .line 490
    cmp-long v7, v2, v5

    .line 491
    .line 492
    if-eqz v7, :cond_19

    .line 493
    .line 494
    iget-wide v7, v0, Lv9/j;->l:J

    .line 495
    .line 496
    add-long/2addr v2, v7

    .line 497
    goto :goto_b

    .line 498
    :cond_19
    move-wide v2, v5

    .line 499
    :goto_b
    iput-wide v2, v0, Lv9/j;->o:J

    .line 500
    .line 501
    const/4 v7, 0x0

    .line 502
    iput-boolean v7, v0, Lv9/j;->p:Z

    .line 503
    .line 504
    iput-wide v5, v0, Lv9/j;->m:J

    .line 505
    .line 506
    const/4 v3, 0x1

    .line 507
    iput-boolean v3, v0, Lv9/j;->j:Z

    .line 508
    .line 509
    :goto_c
    if-nez v9, :cond_1a

    .line 510
    .line 511
    move v14, v3

    .line 512
    goto :goto_d

    .line 513
    :cond_1a
    move v14, v7

    .line 514
    :goto_d
    iput-boolean v14, v0, Lv9/j;->q:Z

    .line 515
    .line 516
    :goto_e
    move v2, v10

    .line 517
    move/from16 v3, v20

    .line 518
    .line 519
    goto/16 :goto_0
.end method

.method public final c()V
    .locals 4

    .line 1
    iget-object v0, p0, Lv9/j;->g:[Z

    .line 2
    .line 3
    invoke-static {v0}, Lx7/n;->a([Z)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lv9/j;->h:Lv9/i;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    iput-boolean v1, v0, Lv9/i;->a:Z

    .line 10
    .line 11
    iput v1, v0, Lv9/i;->b:I

    .line 12
    .line 13
    iput v1, v0, Lv9/i;->c:I

    .line 14
    .line 15
    iget-object v0, p0, Lv9/j;->f:La8/n0;

    .line 16
    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    invoke-virtual {v0}, La8/n0;->g()V

    .line 20
    .line 21
    .line 22
    :cond_0
    const-wide/16 v2, 0x0

    .line 23
    .line 24
    iput-wide v2, p0, Lv9/j;->i:J

    .line 25
    .line 26
    iput-boolean v1, p0, Lv9/j;->j:Z

    .line 27
    .line 28
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 29
    .line 30
    .line 31
    .line 32
    .line 33
    iput-wide v0, p0, Lv9/j;->m:J

    .line 34
    .line 35
    iput-wide v0, p0, Lv9/j;->o:J

    .line 36
    .line 37
    return-void
.end method

.method public final d(Lo8/q;Lh11/h;)V
    .locals 2

    .line 1
    invoke-virtual {p2}, Lh11/h;->d()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p2}, Lh11/h;->i()V

    .line 5
    .line 6
    .line 7
    iget-object v0, p2, Lh11/h;->h:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v0, Ljava/lang/String;

    .line 10
    .line 11
    iput-object v0, p0, Lv9/j;->a:Ljava/lang/String;

    .line 12
    .line 13
    invoke-virtual {p2}, Lh11/h;->i()V

    .line 14
    .line 15
    .line 16
    iget v0, p2, Lh11/h;->f:I

    .line 17
    .line 18
    const/4 v1, 0x2

    .line 19
    invoke-interface {p1, v0, v1}, Lo8/q;->q(II)Lo8/i0;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    iput-object v0, p0, Lv9/j;->b:Lo8/i0;

    .line 24
    .line 25
    iget-object p0, p0, Lv9/j;->c:Lv9/c0;

    .line 26
    .line 27
    if-eqz p0, :cond_0

    .line 28
    .line 29
    invoke-virtual {p0, p1, p2}, Lv9/c0;->b(Lo8/q;Lh11/h;)V

    .line 30
    .line 31
    .line 32
    :cond_0
    return-void
.end method

.method public final e(Z)V
    .locals 8

    .line 1
    iget-object v0, p0, Lv9/j;->b:Lo8/i0;

    .line 2
    .line 3
    invoke-static {v0}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    if-eqz p1, :cond_0

    .line 7
    .line 8
    iget-boolean v4, p0, Lv9/j;->p:Z

    .line 9
    .line 10
    iget-wide v0, p0, Lv9/j;->i:J

    .line 11
    .line 12
    iget-wide v2, p0, Lv9/j;->n:J

    .line 13
    .line 14
    sub-long/2addr v0, v2

    .line 15
    long-to-int v5, v0

    .line 16
    iget-object v1, p0, Lv9/j;->b:Lo8/i0;

    .line 17
    .line 18
    iget-wide v2, p0, Lv9/j;->o:J

    .line 19
    .line 20
    const/4 v6, 0x0

    .line 21
    const/4 v7, 0x0

    .line 22
    invoke-interface/range {v1 .. v7}, Lo8/i0;->b(JIIILo8/h0;)V

    .line 23
    .line 24
    .line 25
    :cond_0
    return-void
.end method

.method public final f(IJ)V
    .locals 0

    .line 1
    iput-wide p2, p0, Lv9/j;->m:J

    .line 2
    .line 3
    return-void
.end method
