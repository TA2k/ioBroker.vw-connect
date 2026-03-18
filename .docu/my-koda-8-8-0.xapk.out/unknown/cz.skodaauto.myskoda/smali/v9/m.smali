.class public final Lv9/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv9/h;


# static fields
.field public static final l:[F


# instance fields
.field public final a:Lv9/c0;

.field public final b:Lw7/p;

.field public final c:[Z

.field public final d:Lv9/k;

.field public final e:La8/n0;

.field public f:Lv9/l;

.field public g:J

.field public h:Ljava/lang/String;

.field public i:Lo8/i0;

.field public j:Z

.field public k:J


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/4 v0, 0x7

    .line 2
    new-array v0, v0, [F

    .line 3
    .line 4
    fill-array-data v0, :array_0

    .line 5
    .line 6
    .line 7
    sput-object v0, Lv9/m;->l:[F

    .line 8
    .line 9
    return-void

    .line 10
    nop

    .line 11
    :array_0
    .array-data 4
        0x3f800000    # 1.0f
        0x3f800000    # 1.0f
        0x3f8ba2e9
        0x3f68ba2f
        0x3fba2e8c
        0x3f9b26ca
        0x3f800000    # 1.0f
    .end array-data
.end method

.method public constructor <init>(Lv9/c0;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lv9/m;->a:Lv9/c0;

    .line 5
    .line 6
    const/4 p1, 0x4

    .line 7
    new-array p1, p1, [Z

    .line 8
    .line 9
    iput-object p1, p0, Lv9/m;->c:[Z

    .line 10
    .line 11
    new-instance p1, Lv9/k;

    .line 12
    .line 13
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    const/16 v0, 0x80

    .line 17
    .line 18
    new-array v0, v0, [B

    .line 19
    .line 20
    iput-object v0, p1, Lv9/k;->e:[B

    .line 21
    .line 22
    iput-object p1, p0, Lv9/m;->d:Lv9/k;

    .line 23
    .line 24
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 25
    .line 26
    .line 27
    .line 28
    .line 29
    iput-wide v0, p0, Lv9/m;->k:J

    .line 30
    .line 31
    new-instance p1, La8/n0;

    .line 32
    .line 33
    const/16 v0, 0xb2

    .line 34
    .line 35
    invoke-direct {p1, v0}, La8/n0;-><init>(I)V

    .line 36
    .line 37
    .line 38
    iput-object p1, p0, Lv9/m;->e:La8/n0;

    .line 39
    .line 40
    new-instance p1, Lw7/p;

    .line 41
    .line 42
    invoke-direct {p1}, Lw7/p;-><init>()V

    .line 43
    .line 44
    .line 45
    iput-object p1, p0, Lv9/m;->b:Lw7/p;

    .line 46
    .line 47
    return-void
.end method


# virtual methods
.method public final b(Lw7/p;)V
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Lv9/m;->f:Lv9/l;

    .line 6
    .line 7
    invoke-static {v2}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    iget-object v2, v0, Lv9/m;->i:Lo8/i0;

    .line 11
    .line 12
    invoke-static {v2}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    iget v2, v1, Lw7/p;->b:I

    .line 16
    .line 17
    iget v3, v1, Lw7/p;->c:I

    .line 18
    .line 19
    iget-object v4, v1, Lw7/p;->a:[B

    .line 20
    .line 21
    iget-wide v5, v0, Lv9/m;->g:J

    .line 22
    .line 23
    invoke-virtual {v1}, Lw7/p;->a()I

    .line 24
    .line 25
    .line 26
    move-result v7

    .line 27
    int-to-long v7, v7

    .line 28
    add-long/2addr v5, v7

    .line 29
    iput-wide v5, v0, Lv9/m;->g:J

    .line 30
    .line 31
    iget-object v5, v0, Lv9/m;->i:Lo8/i0;

    .line 32
    .line 33
    invoke-virtual {v1}, Lw7/p;->a()I

    .line 34
    .line 35
    .line 36
    move-result v6

    .line 37
    const/4 v7, 0x0

    .line 38
    invoke-interface {v5, v1, v6, v7}, Lo8/i0;->a(Lw7/p;II)V

    .line 39
    .line 40
    .line 41
    :goto_0
    iget-object v5, v0, Lv9/m;->c:[Z

    .line 42
    .line 43
    invoke-static {v4, v2, v3, v5}, Lx7/n;->b([BII[Z)I

    .line 44
    .line 45
    .line 46
    move-result v5

    .line 47
    iget-object v6, v0, Lv9/m;->d:Lv9/k;

    .line 48
    .line 49
    iget-object v8, v0, Lv9/m;->e:La8/n0;

    .line 50
    .line 51
    if-ne v5, v3, :cond_2

    .line 52
    .line 53
    iget-boolean v1, v0, Lv9/m;->j:Z

    .line 54
    .line 55
    if-nez v1, :cond_0

    .line 56
    .line 57
    invoke-virtual {v6, v4, v2, v3}, Lv9/k;->a([BII)V

    .line 58
    .line 59
    .line 60
    :cond_0
    iget-object v0, v0, Lv9/m;->f:Lv9/l;

    .line 61
    .line 62
    invoke-virtual {v0, v4, v2, v3}, Lv9/l;->a([BII)V

    .line 63
    .line 64
    .line 65
    if-eqz v8, :cond_1

    .line 66
    .line 67
    invoke-virtual {v8, v4, v2, v3}, La8/n0;->a([BII)V

    .line 68
    .line 69
    .line 70
    :cond_1
    return-void

    .line 71
    :cond_2
    iget-object v9, v1, Lw7/p;->a:[B

    .line 72
    .line 73
    add-int/lit8 v10, v5, 0x3

    .line 74
    .line 75
    aget-byte v9, v9, v10

    .line 76
    .line 77
    and-int/lit16 v11, v9, 0xff

    .line 78
    .line 79
    sub-int v12, v5, v2

    .line 80
    .line 81
    iget-boolean v13, v0, Lv9/m;->j:Z

    .line 82
    .line 83
    if-nez v13, :cond_19

    .line 84
    .line 85
    if-lez v12, :cond_3

    .line 86
    .line 87
    invoke-virtual {v6, v4, v2, v5}, Lv9/k;->a([BII)V

    .line 88
    .line 89
    .line 90
    :cond_3
    if-gez v12, :cond_4

    .line 91
    .line 92
    neg-int v13, v12

    .line 93
    goto :goto_1

    .line 94
    :cond_4
    move v13, v7

    .line 95
    :goto_1
    iget v7, v6, Lv9/k;->b:I

    .line 96
    .line 97
    if-eqz v7, :cond_17

    .line 98
    .line 99
    const-string v14, "H263Reader"

    .line 100
    .line 101
    const-string v15, "Unexpected start code value"

    .line 102
    .line 103
    move/from16 v16, v3

    .line 104
    .line 105
    const/4 v3, 0x1

    .line 106
    if-eq v7, v3, :cond_15

    .line 107
    .line 108
    const/4 v3, 0x2

    .line 109
    if-eq v7, v3, :cond_13

    .line 110
    .line 111
    const/4 v3, 0x4

    .line 112
    move/from16 v17, v10

    .line 113
    .line 114
    const/4 v10, 0x3

    .line 115
    if-eq v7, v10, :cond_11

    .line 116
    .line 117
    if-ne v7, v3, :cond_10

    .line 118
    .line 119
    const/16 v7, 0xb3

    .line 120
    .line 121
    if-eq v11, v7, :cond_6

    .line 122
    .line 123
    const/16 v7, 0xb5

    .line 124
    .line 125
    if-ne v11, v7, :cond_5

    .line 126
    .line 127
    goto :goto_2

    .line 128
    :cond_5
    const/4 v7, 0x0

    .line 129
    goto/16 :goto_7

    .line 130
    .line 131
    :cond_6
    :goto_2
    iget v7, v6, Lv9/k;->c:I

    .line 132
    .line 133
    sub-int/2addr v7, v13

    .line 134
    iput v7, v6, Lv9/k;->c:I

    .line 135
    .line 136
    const/4 v7, 0x0

    .line 137
    iput-boolean v7, v6, Lv9/k;->a:Z

    .line 138
    .line 139
    iget-object v7, v0, Lv9/m;->i:Lo8/i0;

    .line 140
    .line 141
    iget v9, v6, Lv9/k;->d:I

    .line 142
    .line 143
    iget-object v10, v0, Lv9/m;->h:Ljava/lang/String;

    .line 144
    .line 145
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 146
    .line 147
    .line 148
    iget-object v13, v6, Lv9/k;->e:[B

    .line 149
    .line 150
    iget v6, v6, Lv9/k;->c:I

    .line 151
    .line 152
    invoke-static {v13, v6}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 153
    .line 154
    .line 155
    move-result-object v6

    .line 156
    new-instance v13, Lm9/f;

    .line 157
    .line 158
    array-length v15, v6

    .line 159
    invoke-direct {v13, v15, v6}, Lm9/f;-><init>(I[B)V

    .line 160
    .line 161
    .line 162
    invoke-virtual {v13, v9}, Lm9/f;->u(I)V

    .line 163
    .line 164
    .line 165
    invoke-virtual {v13, v3}, Lm9/f;->u(I)V

    .line 166
    .line 167
    .line 168
    invoke-virtual {v13}, Lm9/f;->s()V

    .line 169
    .line 170
    .line 171
    const/16 v9, 0x8

    .line 172
    .line 173
    invoke-virtual {v13, v9}, Lm9/f;->t(I)V

    .line 174
    .line 175
    .line 176
    invoke-virtual {v13}, Lm9/f;->h()Z

    .line 177
    .line 178
    .line 179
    move-result v15

    .line 180
    if-eqz v15, :cond_7

    .line 181
    .line 182
    invoke-virtual {v13, v3}, Lm9/f;->t(I)V

    .line 183
    .line 184
    .line 185
    const/4 v15, 0x3

    .line 186
    invoke-virtual {v13, v15}, Lm9/f;->t(I)V

    .line 187
    .line 188
    .line 189
    :cond_7
    invoke-virtual {v13, v3}, Lm9/f;->i(I)I

    .line 190
    .line 191
    .line 192
    move-result v3

    .line 193
    const-string v15, "Invalid aspect ratio"

    .line 194
    .line 195
    move-object/from16 v18, v6

    .line 196
    .line 197
    const/16 v6, 0xf

    .line 198
    .line 199
    if-ne v3, v6, :cond_9

    .line 200
    .line 201
    invoke-virtual {v13, v9}, Lm9/f;->i(I)I

    .line 202
    .line 203
    .line 204
    move-result v3

    .line 205
    invoke-virtual {v13, v9}, Lm9/f;->i(I)I

    .line 206
    .line 207
    .line 208
    move-result v9

    .line 209
    if-nez v9, :cond_8

    .line 210
    .line 211
    invoke-static {v14, v15}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 212
    .line 213
    .line 214
    goto :goto_3

    .line 215
    :cond_8
    int-to-float v3, v3

    .line 216
    int-to-float v9, v9

    .line 217
    div-float v15, v3, v9

    .line 218
    .line 219
    goto :goto_4

    .line 220
    :cond_9
    const/4 v9, 0x7

    .line 221
    if-ge v3, v9, :cond_a

    .line 222
    .line 223
    sget-object v9, Lv9/m;->l:[F

    .line 224
    .line 225
    aget v15, v9, v3

    .line 226
    .line 227
    goto :goto_4

    .line 228
    :cond_a
    invoke-static {v14, v15}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 229
    .line 230
    .line 231
    :goto_3
    const/high16 v15, 0x3f800000    # 1.0f

    .line 232
    .line 233
    :goto_4
    invoke-virtual {v13}, Lm9/f;->h()Z

    .line 234
    .line 235
    .line 236
    move-result v3

    .line 237
    if-eqz v3, :cond_b

    .line 238
    .line 239
    const/4 v3, 0x2

    .line 240
    invoke-virtual {v13, v3}, Lm9/f;->t(I)V

    .line 241
    .line 242
    .line 243
    const/4 v3, 0x1

    .line 244
    invoke-virtual {v13, v3}, Lm9/f;->t(I)V

    .line 245
    .line 246
    .line 247
    invoke-virtual {v13}, Lm9/f;->h()Z

    .line 248
    .line 249
    .line 250
    move-result v3

    .line 251
    if-eqz v3, :cond_b

    .line 252
    .line 253
    invoke-virtual {v13, v6}, Lm9/f;->t(I)V

    .line 254
    .line 255
    .line 256
    invoke-virtual {v13}, Lm9/f;->s()V

    .line 257
    .line 258
    .line 259
    invoke-virtual {v13, v6}, Lm9/f;->t(I)V

    .line 260
    .line 261
    .line 262
    invoke-virtual {v13}, Lm9/f;->s()V

    .line 263
    .line 264
    .line 265
    invoke-virtual {v13, v6}, Lm9/f;->t(I)V

    .line 266
    .line 267
    .line 268
    invoke-virtual {v13}, Lm9/f;->s()V

    .line 269
    .line 270
    .line 271
    const/4 v3, 0x3

    .line 272
    invoke-virtual {v13, v3}, Lm9/f;->t(I)V

    .line 273
    .line 274
    .line 275
    const/16 v3, 0xb

    .line 276
    .line 277
    invoke-virtual {v13, v3}, Lm9/f;->t(I)V

    .line 278
    .line 279
    .line 280
    invoke-virtual {v13}, Lm9/f;->s()V

    .line 281
    .line 282
    .line 283
    invoke-virtual {v13, v6}, Lm9/f;->t(I)V

    .line 284
    .line 285
    .line 286
    invoke-virtual {v13}, Lm9/f;->s()V

    .line 287
    .line 288
    .line 289
    :cond_b
    const/4 v3, 0x2

    .line 290
    invoke-virtual {v13, v3}, Lm9/f;->i(I)I

    .line 291
    .line 292
    .line 293
    move-result v3

    .line 294
    if-eqz v3, :cond_c

    .line 295
    .line 296
    const-string v3, "Unhandled video object layer shape"

    .line 297
    .line 298
    invoke-static {v14, v3}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 299
    .line 300
    .line 301
    :cond_c
    invoke-virtual {v13}, Lm9/f;->s()V

    .line 302
    .line 303
    .line 304
    const/16 v3, 0x10

    .line 305
    .line 306
    invoke-virtual {v13, v3}, Lm9/f;->i(I)I

    .line 307
    .line 308
    .line 309
    move-result v3

    .line 310
    invoke-virtual {v13}, Lm9/f;->s()V

    .line 311
    .line 312
    .line 313
    invoke-virtual {v13}, Lm9/f;->h()Z

    .line 314
    .line 315
    .line 316
    move-result v6

    .line 317
    if-eqz v6, :cond_f

    .line 318
    .line 319
    if-nez v3, :cond_d

    .line 320
    .line 321
    const-string v3, "Invalid vop_increment_time_resolution"

    .line 322
    .line 323
    invoke-static {v14, v3}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 324
    .line 325
    .line 326
    goto :goto_6

    .line 327
    :cond_d
    add-int/lit8 v3, v3, -0x1

    .line 328
    .line 329
    const/4 v6, 0x0

    .line 330
    :goto_5
    if-lez v3, :cond_e

    .line 331
    .line 332
    add-int/lit8 v6, v6, 0x1

    .line 333
    .line 334
    shr-int/lit8 v3, v3, 0x1

    .line 335
    .line 336
    goto :goto_5

    .line 337
    :cond_e
    invoke-virtual {v13, v6}, Lm9/f;->t(I)V

    .line 338
    .line 339
    .line 340
    :cond_f
    :goto_6
    invoke-virtual {v13}, Lm9/f;->s()V

    .line 341
    .line 342
    .line 343
    const/16 v3, 0xd

    .line 344
    .line 345
    invoke-virtual {v13, v3}, Lm9/f;->i(I)I

    .line 346
    .line 347
    .line 348
    move-result v6

    .line 349
    invoke-virtual {v13}, Lm9/f;->s()V

    .line 350
    .line 351
    .line 352
    invoke-virtual {v13, v3}, Lm9/f;->i(I)I

    .line 353
    .line 354
    .line 355
    move-result v3

    .line 356
    invoke-virtual {v13}, Lm9/f;->s()V

    .line 357
    .line 358
    .line 359
    invoke-virtual {v13}, Lm9/f;->s()V

    .line 360
    .line 361
    .line 362
    new-instance v9, Lt7/n;

    .line 363
    .line 364
    invoke-direct {v9}, Lt7/n;-><init>()V

    .line 365
    .line 366
    .line 367
    iput-object v10, v9, Lt7/n;->a:Ljava/lang/String;

    .line 368
    .line 369
    const-string v10, "video/mp2t"

    .line 370
    .line 371
    invoke-static {v10}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 372
    .line 373
    .line 374
    move-result-object v10

    .line 375
    iput-object v10, v9, Lt7/n;->l:Ljava/lang/String;

    .line 376
    .line 377
    const-string v10, "video/mp4v-es"

    .line 378
    .line 379
    invoke-static {v10}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 380
    .line 381
    .line 382
    move-result-object v10

    .line 383
    iput-object v10, v9, Lt7/n;->m:Ljava/lang/String;

    .line 384
    .line 385
    iput v6, v9, Lt7/n;->t:I

    .line 386
    .line 387
    iput v3, v9, Lt7/n;->u:I

    .line 388
    .line 389
    iput v15, v9, Lt7/n;->z:F

    .line 390
    .line 391
    invoke-static/range {v18 .. v18}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 392
    .line 393
    .line 394
    move-result-object v3

    .line 395
    iput-object v3, v9, Lt7/n;->p:Ljava/util/List;

    .line 396
    .line 397
    invoke-static {v9, v7}, Lf2/m0;->x(Lt7/n;Lo8/i0;)V

    .line 398
    .line 399
    .line 400
    const/4 v3, 0x1

    .line 401
    iput-boolean v3, v0, Lv9/m;->j:Z

    .line 402
    .line 403
    goto :goto_8

    .line 404
    :cond_10
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 405
    .line 406
    invoke-direct {v0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 407
    .line 408
    .line 409
    throw v0

    .line 410
    :cond_11
    and-int/lit16 v7, v9, 0xf0

    .line 411
    .line 412
    const/16 v9, 0x20

    .line 413
    .line 414
    if-eq v7, v9, :cond_12

    .line 415
    .line 416
    invoke-static {v14, v15}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 417
    .line 418
    .line 419
    const/4 v7, 0x0

    .line 420
    iput-boolean v7, v6, Lv9/k;->a:Z

    .line 421
    .line 422
    iput v7, v6, Lv9/k;->c:I

    .line 423
    .line 424
    iput v7, v6, Lv9/k;->b:I

    .line 425
    .line 426
    goto :goto_7

    .line 427
    :cond_12
    const/4 v7, 0x0

    .line 428
    iget v9, v6, Lv9/k;->c:I

    .line 429
    .line 430
    iput v9, v6, Lv9/k;->d:I

    .line 431
    .line 432
    iput v3, v6, Lv9/k;->b:I

    .line 433
    .line 434
    goto :goto_7

    .line 435
    :cond_13
    move/from16 v17, v10

    .line 436
    .line 437
    const/4 v7, 0x0

    .line 438
    const/16 v3, 0x1f

    .line 439
    .line 440
    if-le v11, v3, :cond_14

    .line 441
    .line 442
    invoke-static {v14, v15}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 443
    .line 444
    .line 445
    iput-boolean v7, v6, Lv9/k;->a:Z

    .line 446
    .line 447
    iput v7, v6, Lv9/k;->c:I

    .line 448
    .line 449
    iput v7, v6, Lv9/k;->b:I

    .line 450
    .line 451
    goto :goto_7

    .line 452
    :cond_14
    const/4 v15, 0x3

    .line 453
    iput v15, v6, Lv9/k;->b:I

    .line 454
    .line 455
    goto :goto_7

    .line 456
    :cond_15
    move/from16 v17, v10

    .line 457
    .line 458
    const/16 v3, 0xb5

    .line 459
    .line 460
    const/4 v7, 0x0

    .line 461
    if-eq v11, v3, :cond_16

    .line 462
    .line 463
    invoke-static {v14, v15}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 464
    .line 465
    .line 466
    iput-boolean v7, v6, Lv9/k;->a:Z

    .line 467
    .line 468
    iput v7, v6, Lv9/k;->c:I

    .line 469
    .line 470
    iput v7, v6, Lv9/k;->b:I

    .line 471
    .line 472
    goto :goto_7

    .line 473
    :cond_16
    const/4 v3, 0x2

    .line 474
    iput v3, v6, Lv9/k;->b:I

    .line 475
    .line 476
    goto :goto_7

    .line 477
    :cond_17
    move/from16 v16, v3

    .line 478
    .line 479
    move/from16 v17, v10

    .line 480
    .line 481
    const/4 v7, 0x0

    .line 482
    const/16 v3, 0xb0

    .line 483
    .line 484
    if-ne v11, v3, :cond_18

    .line 485
    .line 486
    const/4 v3, 0x1

    .line 487
    iput v3, v6, Lv9/k;->b:I

    .line 488
    .line 489
    iput-boolean v3, v6, Lv9/k;->a:Z

    .line 490
    .line 491
    :cond_18
    :goto_7
    sget-object v3, Lv9/k;->f:[B

    .line 492
    .line 493
    const/4 v15, 0x3

    .line 494
    invoke-virtual {v6, v3, v7, v15}, Lv9/k;->a([BII)V

    .line 495
    .line 496
    .line 497
    goto :goto_8

    .line 498
    :cond_19
    move/from16 v16, v3

    .line 499
    .line 500
    move/from16 v17, v10

    .line 501
    .line 502
    :goto_8
    iget-object v3, v0, Lv9/m;->f:Lv9/l;

    .line 503
    .line 504
    invoke-virtual {v3, v4, v2, v5}, Lv9/l;->a([BII)V

    .line 505
    .line 506
    .line 507
    if-eqz v8, :cond_1c

    .line 508
    .line 509
    if-lez v12, :cond_1a

    .line 510
    .line 511
    invoke-virtual {v8, v4, v2, v5}, La8/n0;->a([BII)V

    .line 512
    .line 513
    .line 514
    const/4 v2, 0x0

    .line 515
    goto :goto_9

    .line 516
    :cond_1a
    neg-int v2, v12

    .line 517
    :goto_9
    invoke-virtual {v8, v2}, La8/n0;->e(I)Z

    .line 518
    .line 519
    .line 520
    move-result v2

    .line 521
    if-eqz v2, :cond_1b

    .line 522
    .line 523
    iget-object v2, v8, La8/n0;->f:Ljava/lang/Object;

    .line 524
    .line 525
    check-cast v2, [B

    .line 526
    .line 527
    iget v3, v8, La8/n0;->c:I

    .line 528
    .line 529
    invoke-static {v3, v2}, Lx7/n;->m(I[B)I

    .line 530
    .line 531
    .line 532
    move-result v2

    .line 533
    sget-object v3, Lw7/w;->a:Ljava/lang/String;

    .line 534
    .line 535
    iget-object v3, v8, La8/n0;->f:Ljava/lang/Object;

    .line 536
    .line 537
    check-cast v3, [B

    .line 538
    .line 539
    iget-object v6, v0, Lv9/m;->b:Lw7/p;

    .line 540
    .line 541
    invoke-virtual {v6, v2, v3}, Lw7/p;->G(I[B)V

    .line 542
    .line 543
    .line 544
    iget-object v2, v0, Lv9/m;->a:Lv9/c0;

    .line 545
    .line 546
    iget-wide v9, v0, Lv9/m;->k:J

    .line 547
    .line 548
    invoke-virtual {v2, v9, v10, v6}, Lv9/c0;->a(JLw7/p;)V

    .line 549
    .line 550
    .line 551
    :cond_1b
    const/16 v2, 0xb2

    .line 552
    .line 553
    if-ne v11, v2, :cond_1c

    .line 554
    .line 555
    iget-object v2, v1, Lw7/p;->a:[B

    .line 556
    .line 557
    add-int/lit8 v3, v5, 0x2

    .line 558
    .line 559
    aget-byte v2, v2, v3

    .line 560
    .line 561
    const/4 v3, 0x1

    .line 562
    if-ne v2, v3, :cond_1d

    .line 563
    .line 564
    invoke-virtual {v8, v11}, La8/n0;->h(I)V

    .line 565
    .line 566
    .line 567
    goto :goto_a

    .line 568
    :cond_1c
    const/4 v3, 0x1

    .line 569
    :cond_1d
    :goto_a
    sub-int v2, v16, v5

    .line 570
    .line 571
    iget-wide v5, v0, Lv9/m;->g:J

    .line 572
    .line 573
    int-to-long v7, v2

    .line 574
    sub-long/2addr v5, v7

    .line 575
    iget-object v7, v0, Lv9/m;->f:Lv9/l;

    .line 576
    .line 577
    iget-boolean v8, v0, Lv9/m;->j:Z

    .line 578
    .line 579
    invoke-virtual {v7, v5, v6, v2, v8}, Lv9/l;->b(JIZ)V

    .line 580
    .line 581
    .line 582
    iget-object v2, v0, Lv9/m;->f:Lv9/l;

    .line 583
    .line 584
    iget-wide v5, v0, Lv9/m;->k:J

    .line 585
    .line 586
    iput v11, v2, Lv9/l;->e:I

    .line 587
    .line 588
    const/4 v7, 0x0

    .line 589
    iput-boolean v7, v2, Lv9/l;->d:Z

    .line 590
    .line 591
    const/16 v7, 0xb6

    .line 592
    .line 593
    if-eq v11, v7, :cond_1f

    .line 594
    .line 595
    const/16 v8, 0xb3

    .line 596
    .line 597
    if-ne v11, v8, :cond_1e

    .line 598
    .line 599
    goto :goto_b

    .line 600
    :cond_1e
    const/4 v8, 0x0

    .line 601
    goto :goto_c

    .line 602
    :cond_1f
    :goto_b
    move v8, v3

    .line 603
    :goto_c
    iput-boolean v8, v2, Lv9/l;->b:Z

    .line 604
    .line 605
    if-ne v11, v7, :cond_20

    .line 606
    .line 607
    move v15, v3

    .line 608
    goto :goto_d

    .line 609
    :cond_20
    const/4 v15, 0x0

    .line 610
    :goto_d
    iput-boolean v15, v2, Lv9/l;->c:Z

    .line 611
    .line 612
    const/4 v7, 0x0

    .line 613
    iput v7, v2, Lv9/l;->f:I

    .line 614
    .line 615
    iput-wide v5, v2, Lv9/l;->h:J

    .line 616
    .line 617
    move/from16 v3, v16

    .line 618
    .line 619
    move/from16 v2, v17

    .line 620
    .line 621
    goto/16 :goto_0
.end method

.method public final c()V
    .locals 2

    .line 1
    iget-object v0, p0, Lv9/m;->c:[Z

    .line 2
    .line 3
    invoke-static {v0}, Lx7/n;->a([Z)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lv9/m;->d:Lv9/k;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    iput-boolean v1, v0, Lv9/k;->a:Z

    .line 10
    .line 11
    iput v1, v0, Lv9/k;->c:I

    .line 12
    .line 13
    iput v1, v0, Lv9/k;->b:I

    .line 14
    .line 15
    iget-object v0, p0, Lv9/m;->f:Lv9/l;

    .line 16
    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    iput-boolean v1, v0, Lv9/l;->b:Z

    .line 20
    .line 21
    iput-boolean v1, v0, Lv9/l;->c:Z

    .line 22
    .line 23
    iput-boolean v1, v0, Lv9/l;->d:Z

    .line 24
    .line 25
    const/4 v1, -0x1

    .line 26
    iput v1, v0, Lv9/l;->e:I

    .line 27
    .line 28
    :cond_0
    iget-object v0, p0, Lv9/m;->e:La8/n0;

    .line 29
    .line 30
    if-eqz v0, :cond_1

    .line 31
    .line 32
    invoke-virtual {v0}, La8/n0;->g()V

    .line 33
    .line 34
    .line 35
    :cond_1
    const-wide/16 v0, 0x0

    .line 36
    .line 37
    iput-wide v0, p0, Lv9/m;->g:J

    .line 38
    .line 39
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 40
    .line 41
    .line 42
    .line 43
    .line 44
    iput-wide v0, p0, Lv9/m;->k:J

    .line 45
    .line 46
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
    iput-object v0, p0, Lv9/m;->h:Ljava/lang/String;

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
    iput-object v0, p0, Lv9/m;->i:Lo8/i0;

    .line 24
    .line 25
    new-instance v1, Lv9/l;

    .line 26
    .line 27
    invoke-direct {v1, v0}, Lv9/l;-><init>(Lo8/i0;)V

    .line 28
    .line 29
    .line 30
    iput-object v1, p0, Lv9/m;->f:Lv9/l;

    .line 31
    .line 32
    iget-object p0, p0, Lv9/m;->a:Lv9/c0;

    .line 33
    .line 34
    invoke-virtual {p0, p1, p2}, Lv9/c0;->b(Lo8/q;Lh11/h;)V

    .line 35
    .line 36
    .line 37
    return-void
.end method

.method public final e(Z)V
    .locals 4

    .line 1
    iget-object v0, p0, Lv9/m;->f:Lv9/l;

    .line 2
    .line 3
    invoke-static {v0}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    if-eqz p1, :cond_0

    .line 7
    .line 8
    iget-object p1, p0, Lv9/m;->f:Lv9/l;

    .line 9
    .line 10
    iget-wide v0, p0, Lv9/m;->g:J

    .line 11
    .line 12
    iget-boolean v2, p0, Lv9/m;->j:Z

    .line 13
    .line 14
    const/4 v3, 0x0

    .line 15
    invoke-virtual {p1, v0, v1, v3, v2}, Lv9/l;->b(JIZ)V

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Lv9/m;->f:Lv9/l;

    .line 19
    .line 20
    iput-boolean v3, p0, Lv9/l;->b:Z

    .line 21
    .line 22
    iput-boolean v3, p0, Lv9/l;->c:Z

    .line 23
    .line 24
    iput-boolean v3, p0, Lv9/l;->d:Z

    .line 25
    .line 26
    const/4 p1, -0x1

    .line 27
    iput p1, p0, Lv9/l;->e:I

    .line 28
    .line 29
    :cond_0
    return-void
.end method

.method public final f(IJ)V
    .locals 0

    .line 1
    iput-wide p2, p0, Lv9/m;->k:J

    .line 2
    .line 3
    return-void
.end method
