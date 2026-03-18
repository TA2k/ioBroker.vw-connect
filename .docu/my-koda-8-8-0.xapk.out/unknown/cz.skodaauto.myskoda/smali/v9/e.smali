.class public final Lv9/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv9/h;


# static fields
.field public static final x:[B


# instance fields
.field public final a:Z

.field public final b:Lm9/f;

.field public final c:Lw7/p;

.field public final d:Ljava/lang/String;

.field public final e:I

.field public final f:Ljava/lang/String;

.field public g:Ljava/lang/String;

.field public h:Lo8/i0;

.field public i:Lo8/i0;

.field public j:I

.field public k:I

.field public l:I

.field public m:Z

.field public n:Z

.field public o:I

.field public p:I

.field public q:I

.field public r:Z

.field public s:J

.field public t:I

.field public u:J

.field public v:Lo8/i0;

.field public w:J


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/4 v0, 0x3

    .line 2
    new-array v0, v0, [B

    .line 3
    .line 4
    fill-array-data v0, :array_0

    .line 5
    .line 6
    .line 7
    sput-object v0, Lv9/e;->x:[B

    .line 8
    .line 9
    return-void

    .line 10
    nop

    .line 11
    :array_0
    .array-data 1
        0x49t
        0x44t
        0x33t
    .end array-data
.end method

.method public constructor <init>(Ljava/lang/String;ILjava/lang/String;Z)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lm9/f;

    .line 5
    .line 6
    const/4 v1, 0x7

    .line 7
    new-array v2, v1, [B

    .line 8
    .line 9
    invoke-direct {v0, v1, v2}, Lm9/f;-><init>(I[B)V

    .line 10
    .line 11
    .line 12
    iput-object v0, p0, Lv9/e;->b:Lm9/f;

    .line 13
    .line 14
    new-instance v0, Lw7/p;

    .line 15
    .line 16
    sget-object v1, Lv9/e;->x:[B

    .line 17
    .line 18
    const/16 v2, 0xa

    .line 19
    .line 20
    invoke-static {v1, v2}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    invoke-direct {v0, v1}, Lw7/p;-><init>([B)V

    .line 25
    .line 26
    .line 27
    iput-object v0, p0, Lv9/e;->c:Lw7/p;

    .line 28
    .line 29
    const/4 v0, -0x1

    .line 30
    iput v0, p0, Lv9/e;->o:I

    .line 31
    .line 32
    iput v0, p0, Lv9/e;->p:I

    .line 33
    .line 34
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 35
    .line 36
    .line 37
    .line 38
    .line 39
    iput-wide v0, p0, Lv9/e;->s:J

    .line 40
    .line 41
    iput-wide v0, p0, Lv9/e;->u:J

    .line 42
    .line 43
    iput-boolean p4, p0, Lv9/e;->a:Z

    .line 44
    .line 45
    iput-object p1, p0, Lv9/e;->d:Ljava/lang/String;

    .line 46
    .line 47
    iput p2, p0, Lv9/e;->e:I

    .line 48
    .line 49
    iput-object p3, p0, Lv9/e;->f:Ljava/lang/String;

    .line 50
    .line 51
    const/4 p1, 0x0

    .line 52
    iput p1, p0, Lv9/e;->j:I

    .line 53
    .line 54
    iput p1, p0, Lv9/e;->k:I

    .line 55
    .line 56
    const/16 p1, 0x100

    .line 57
    .line 58
    iput p1, p0, Lv9/e;->l:I

    .line 59
    .line 60
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
    iget-object v2, v0, Lv9/e;->h:Lo8/i0;

    .line 6
    .line 7
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    sget-object v2, Lw7/w;->a:Ljava/lang/String;

    .line 11
    .line 12
    :cond_0
    :goto_0
    invoke-virtual {v1}, Lw7/p;->a()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    if-lez v2, :cond_27

    .line 17
    .line 18
    iget v2, v0, Lv9/e;->j:I

    .line 19
    .line 20
    const/16 v3, 0x100

    .line 21
    .line 22
    const/4 v4, -0x1

    .line 23
    const/16 v5, 0xd

    .line 24
    .line 25
    iget-object v6, v0, Lv9/e;->c:Lw7/p;

    .line 26
    .line 27
    const/4 v7, 0x7

    .line 28
    const/4 v8, 0x3

    .line 29
    iget-object v9, v0, Lv9/e;->b:Lm9/f;

    .line 30
    .line 31
    const/4 v10, 0x4

    .line 32
    const/4 v11, 0x2

    .line 33
    const/4 v12, 0x0

    .line 34
    const/4 v13, 0x1

    .line 35
    if-eqz v2, :cond_d

    .line 36
    .line 37
    if-eq v2, v13, :cond_9

    .line 38
    .line 39
    const/16 v4, 0xa

    .line 40
    .line 41
    if-eq v2, v11, :cond_8

    .line 42
    .line 43
    if-eq v2, v8, :cond_3

    .line 44
    .line 45
    if-ne v2, v10, :cond_2

    .line 46
    .line 47
    invoke-virtual {v1}, Lw7/p;->a()I

    .line 48
    .line 49
    .line 50
    move-result v2

    .line 51
    iget v4, v0, Lv9/e;->t:I

    .line 52
    .line 53
    iget v5, v0, Lv9/e;->k:I

    .line 54
    .line 55
    sub-int/2addr v4, v5

    .line 56
    invoke-static {v2, v4}, Ljava/lang/Math;->min(II)I

    .line 57
    .line 58
    .line 59
    move-result v2

    .line 60
    iget-object v4, v0, Lv9/e;->v:Lo8/i0;

    .line 61
    .line 62
    invoke-interface {v4, v1, v2, v12}, Lo8/i0;->a(Lw7/p;II)V

    .line 63
    .line 64
    .line 65
    iget v4, v0, Lv9/e;->k:I

    .line 66
    .line 67
    add-int/2addr v4, v2

    .line 68
    iput v4, v0, Lv9/e;->k:I

    .line 69
    .line 70
    iget v2, v0, Lv9/e;->t:I

    .line 71
    .line 72
    if-ne v4, v2, :cond_0

    .line 73
    .line 74
    iget-wide v4, v0, Lv9/e;->u:J

    .line 75
    .line 76
    const-wide v6, -0x7fffffffffffffffL    # -4.9E-324

    .line 77
    .line 78
    .line 79
    .line 80
    .line 81
    cmp-long v2, v4, v6

    .line 82
    .line 83
    if-eqz v2, :cond_1

    .line 84
    .line 85
    goto :goto_1

    .line 86
    :cond_1
    move v13, v12

    .line 87
    :goto_1
    invoke-static {v13}, Lw7/a;->j(Z)V

    .line 88
    .line 89
    .line 90
    iget-object v4, v0, Lv9/e;->v:Lo8/i0;

    .line 91
    .line 92
    iget-wide v5, v0, Lv9/e;->u:J

    .line 93
    .line 94
    iget v8, v0, Lv9/e;->t:I

    .line 95
    .line 96
    const/4 v9, 0x0

    .line 97
    const/4 v10, 0x0

    .line 98
    const/4 v7, 0x1

    .line 99
    invoke-interface/range {v4 .. v10}, Lo8/i0;->b(JIIILo8/h0;)V

    .line 100
    .line 101
    .line 102
    iget-wide v4, v0, Lv9/e;->u:J

    .line 103
    .line 104
    iget-wide v6, v0, Lv9/e;->w:J

    .line 105
    .line 106
    add-long/2addr v4, v6

    .line 107
    iput-wide v4, v0, Lv9/e;->u:J

    .line 108
    .line 109
    iput v12, v0, Lv9/e;->j:I

    .line 110
    .line 111
    iput v12, v0, Lv9/e;->k:I

    .line 112
    .line 113
    iput v3, v0, Lv9/e;->l:I

    .line 114
    .line 115
    goto :goto_0

    .line 116
    :cond_2
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 117
    .line 118
    invoke-direct {v0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 119
    .line 120
    .line 121
    throw v0

    .line 122
    :cond_3
    iget-boolean v2, v0, Lv9/e;->m:Z

    .line 123
    .line 124
    const/4 v3, 0x5

    .line 125
    if-eqz v2, :cond_4

    .line 126
    .line 127
    move v2, v7

    .line 128
    goto :goto_2

    .line 129
    :cond_4
    move v2, v3

    .line 130
    :goto_2
    iget-object v6, v9, Lm9/f;->b:[B

    .line 131
    .line 132
    invoke-virtual {v1}, Lw7/p;->a()I

    .line 133
    .line 134
    .line 135
    move-result v14

    .line 136
    iget v15, v0, Lv9/e;->k:I

    .line 137
    .line 138
    sub-int v15, v2, v15

    .line 139
    .line 140
    invoke-static {v14, v15}, Ljava/lang/Math;->min(II)I

    .line 141
    .line 142
    .line 143
    move-result v14

    .line 144
    iget v15, v0, Lv9/e;->k:I

    .line 145
    .line 146
    invoke-virtual {v1, v6, v15, v14}, Lw7/p;->h([BII)V

    .line 147
    .line 148
    .line 149
    iget v6, v0, Lv9/e;->k:I

    .line 150
    .line 151
    add-int/2addr v6, v14

    .line 152
    iput v6, v0, Lv9/e;->k:I

    .line 153
    .line 154
    if-ne v6, v2, :cond_0

    .line 155
    .line 156
    invoke-virtual {v9, v12}, Lm9/f;->q(I)V

    .line 157
    .line 158
    .line 159
    iget-boolean v2, v0, Lv9/e;->r:Z

    .line 160
    .line 161
    if-nez v2, :cond_6

    .line 162
    .line 163
    invoke-virtual {v9, v11}, Lm9/f;->i(I)I

    .line 164
    .line 165
    .line 166
    move-result v2

    .line 167
    add-int/2addr v2, v13

    .line 168
    if-eq v2, v11, :cond_5

    .line 169
    .line 170
    new-instance v4, Ljava/lang/StringBuilder;

    .line 171
    .line 172
    const-string v6, "Detected audio object type: "

    .line 173
    .line 174
    invoke-direct {v4, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 175
    .line 176
    .line 177
    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 178
    .line 179
    .line 180
    const-string v2, ", but assuming AAC LC."

    .line 181
    .line 182
    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 183
    .line 184
    .line 185
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 186
    .line 187
    .line 188
    move-result-object v2

    .line 189
    const-string v4, "AdtsReader"

    .line 190
    .line 191
    invoke-static {v4, v2}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 192
    .line 193
    .line 194
    move v2, v11

    .line 195
    :cond_5
    invoke-virtual {v9, v3}, Lm9/f;->t(I)V

    .line 196
    .line 197
    .line 198
    invoke-virtual {v9, v8}, Lm9/f;->i(I)I

    .line 199
    .line 200
    .line 201
    move-result v3

    .line 202
    iget v4, v0, Lv9/e;->p:I

    .line 203
    .line 204
    shl-int/2addr v2, v8

    .line 205
    and-int/lit16 v2, v2, 0xf8

    .line 206
    .line 207
    shr-int/lit8 v6, v4, 0x1

    .line 208
    .line 209
    and-int/2addr v6, v7

    .line 210
    or-int/2addr v2, v6

    .line 211
    int-to-byte v2, v2

    .line 212
    shl-int/2addr v4, v7

    .line 213
    and-int/lit16 v4, v4, 0x80

    .line 214
    .line 215
    shl-int/2addr v3, v8

    .line 216
    and-int/lit8 v3, v3, 0x78

    .line 217
    .line 218
    or-int/2addr v3, v4

    .line 219
    int-to-byte v3, v3

    .line 220
    new-array v4, v11, [B

    .line 221
    .line 222
    aput-byte v2, v4, v12

    .line 223
    .line 224
    aput-byte v3, v4, v13

    .line 225
    .line 226
    new-instance v2, Lm9/f;

    .line 227
    .line 228
    invoke-direct {v2, v11, v4}, Lm9/f;-><init>(I[B)V

    .line 229
    .line 230
    .line 231
    invoke-static {v2, v12}, Lo8/b;->n(Lm9/f;Z)Lo8/a;

    .line 232
    .line 233
    .line 234
    move-result-object v2

    .line 235
    new-instance v3, Lt7/n;

    .line 236
    .line 237
    invoke-direct {v3}, Lt7/n;-><init>()V

    .line 238
    .line 239
    .line 240
    iget-object v6, v0, Lv9/e;->g:Ljava/lang/String;

    .line 241
    .line 242
    iput-object v6, v3, Lt7/n;->a:Ljava/lang/String;

    .line 243
    .line 244
    iget-object v6, v0, Lv9/e;->f:Ljava/lang/String;

    .line 245
    .line 246
    invoke-static {v6}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 247
    .line 248
    .line 249
    move-result-object v6

    .line 250
    iput-object v6, v3, Lt7/n;->l:Ljava/lang/String;

    .line 251
    .line 252
    const-string v6, "audio/mp4a-latm"

    .line 253
    .line 254
    invoke-static {v6}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 255
    .line 256
    .line 257
    move-result-object v6

    .line 258
    iput-object v6, v3, Lt7/n;->m:Ljava/lang/String;

    .line 259
    .line 260
    iget-object v6, v2, Lo8/a;->a:Ljava/lang/String;

    .line 261
    .line 262
    iput-object v6, v3, Lt7/n;->j:Ljava/lang/String;

    .line 263
    .line 264
    iget v6, v2, Lo8/a;->c:I

    .line 265
    .line 266
    iput v6, v3, Lt7/n;->E:I

    .line 267
    .line 268
    iget v2, v2, Lo8/a;->b:I

    .line 269
    .line 270
    iput v2, v3, Lt7/n;->F:I

    .line 271
    .line 272
    invoke-static {v4}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 273
    .line 274
    .line 275
    move-result-object v2

    .line 276
    iput-object v2, v3, Lt7/n;->p:Ljava/util/List;

    .line 277
    .line 278
    iget-object v2, v0, Lv9/e;->d:Ljava/lang/String;

    .line 279
    .line 280
    iput-object v2, v3, Lt7/n;->d:Ljava/lang/String;

    .line 281
    .line 282
    iget v2, v0, Lv9/e;->e:I

    .line 283
    .line 284
    iput v2, v3, Lt7/n;->f:I

    .line 285
    .line 286
    new-instance v2, Lt7/o;

    .line 287
    .line 288
    invoke-direct {v2, v3}, Lt7/o;-><init>(Lt7/n;)V

    .line 289
    .line 290
    .line 291
    iget v3, v2, Lt7/o;->G:I

    .line 292
    .line 293
    int-to-long v3, v3

    .line 294
    const-wide/32 v6, 0x3d090000

    .line 295
    .line 296
    .line 297
    div-long/2addr v6, v3

    .line 298
    iput-wide v6, v0, Lv9/e;->s:J

    .line 299
    .line 300
    iget-object v3, v0, Lv9/e;->h:Lo8/i0;

    .line 301
    .line 302
    invoke-interface {v3, v2}, Lo8/i0;->c(Lt7/o;)V

    .line 303
    .line 304
    .line 305
    iput-boolean v13, v0, Lv9/e;->r:Z

    .line 306
    .line 307
    goto :goto_3

    .line 308
    :cond_6
    invoke-virtual {v9, v4}, Lm9/f;->t(I)V

    .line 309
    .line 310
    .line 311
    :goto_3
    invoke-virtual {v9, v10}, Lm9/f;->t(I)V

    .line 312
    .line 313
    .line 314
    invoke-virtual {v9, v5}, Lm9/f;->i(I)I

    .line 315
    .line 316
    .line 317
    move-result v2

    .line 318
    add-int/lit8 v3, v2, -0x7

    .line 319
    .line 320
    iget-boolean v4, v0, Lv9/e;->m:Z

    .line 321
    .line 322
    if-eqz v4, :cond_7

    .line 323
    .line 324
    add-int/lit8 v3, v2, -0x9

    .line 325
    .line 326
    :cond_7
    iget-object v2, v0, Lv9/e;->h:Lo8/i0;

    .line 327
    .line 328
    iget-wide v4, v0, Lv9/e;->s:J

    .line 329
    .line 330
    iput v10, v0, Lv9/e;->j:I

    .line 331
    .line 332
    iput v12, v0, Lv9/e;->k:I

    .line 333
    .line 334
    iput-object v2, v0, Lv9/e;->v:Lo8/i0;

    .line 335
    .line 336
    iput-wide v4, v0, Lv9/e;->w:J

    .line 337
    .line 338
    iput v3, v0, Lv9/e;->t:I

    .line 339
    .line 340
    goto/16 :goto_0

    .line 341
    .line 342
    :cond_8
    iget-object v2, v6, Lw7/p;->a:[B

    .line 343
    .line 344
    invoke-virtual {v1}, Lw7/p;->a()I

    .line 345
    .line 346
    .line 347
    move-result v3

    .line 348
    iget v5, v0, Lv9/e;->k:I

    .line 349
    .line 350
    rsub-int/lit8 v5, v5, 0xa

    .line 351
    .line 352
    invoke-static {v3, v5}, Ljava/lang/Math;->min(II)I

    .line 353
    .line 354
    .line 355
    move-result v3

    .line 356
    iget v5, v0, Lv9/e;->k:I

    .line 357
    .line 358
    invoke-virtual {v1, v2, v5, v3}, Lw7/p;->h([BII)V

    .line 359
    .line 360
    .line 361
    iget v2, v0, Lv9/e;->k:I

    .line 362
    .line 363
    add-int/2addr v2, v3

    .line 364
    iput v2, v0, Lv9/e;->k:I

    .line 365
    .line 366
    if-ne v2, v4, :cond_0

    .line 367
    .line 368
    iget-object v2, v0, Lv9/e;->i:Lo8/i0;

    .line 369
    .line 370
    invoke-interface {v2, v6, v4, v12}, Lo8/i0;->a(Lw7/p;II)V

    .line 371
    .line 372
    .line 373
    const/4 v2, 0x6

    .line 374
    invoke-virtual {v6, v2}, Lw7/p;->I(I)V

    .line 375
    .line 376
    .line 377
    iget-object v2, v0, Lv9/e;->i:Lo8/i0;

    .line 378
    .line 379
    invoke-virtual {v6}, Lw7/p;->v()I

    .line 380
    .line 381
    .line 382
    move-result v3

    .line 383
    add-int/2addr v3, v4

    .line 384
    iput v10, v0, Lv9/e;->j:I

    .line 385
    .line 386
    iput v4, v0, Lv9/e;->k:I

    .line 387
    .line 388
    iput-object v2, v0, Lv9/e;->v:Lo8/i0;

    .line 389
    .line 390
    const-wide/16 v4, 0x0

    .line 391
    .line 392
    iput-wide v4, v0, Lv9/e;->w:J

    .line 393
    .line 394
    iput v3, v0, Lv9/e;->t:I

    .line 395
    .line 396
    goto/16 :goto_0

    .line 397
    .line 398
    :cond_9
    invoke-virtual {v1}, Lw7/p;->a()I

    .line 399
    .line 400
    .line 401
    move-result v2

    .line 402
    if-nez v2, :cond_a

    .line 403
    .line 404
    goto/16 :goto_0

    .line 405
    .line 406
    :cond_a
    iget-object v2, v9, Lm9/f;->b:[B

    .line 407
    .line 408
    iget-object v5, v1, Lw7/p;->a:[B

    .line 409
    .line 410
    iget v6, v1, Lw7/p;->b:I

    .line 411
    .line 412
    aget-byte v5, v5, v6

    .line 413
    .line 414
    aput-byte v5, v2, v12

    .line 415
    .line 416
    invoke-virtual {v9, v11}, Lm9/f;->q(I)V

    .line 417
    .line 418
    .line 419
    invoke-virtual {v9, v10}, Lm9/f;->i(I)I

    .line 420
    .line 421
    .line 422
    move-result v2

    .line 423
    iget v5, v0, Lv9/e;->p:I

    .line 424
    .line 425
    if-eq v5, v4, :cond_b

    .line 426
    .line 427
    if-eq v2, v5, :cond_b

    .line 428
    .line 429
    iput-boolean v12, v0, Lv9/e;->n:Z

    .line 430
    .line 431
    iput v12, v0, Lv9/e;->j:I

    .line 432
    .line 433
    iput v12, v0, Lv9/e;->k:I

    .line 434
    .line 435
    iput v3, v0, Lv9/e;->l:I

    .line 436
    .line 437
    goto/16 :goto_0

    .line 438
    .line 439
    :cond_b
    iget-boolean v3, v0, Lv9/e;->n:Z

    .line 440
    .line 441
    if-nez v3, :cond_c

    .line 442
    .line 443
    iput-boolean v13, v0, Lv9/e;->n:Z

    .line 444
    .line 445
    iget v3, v0, Lv9/e;->q:I

    .line 446
    .line 447
    iput v3, v0, Lv9/e;->o:I

    .line 448
    .line 449
    iput v2, v0, Lv9/e;->p:I

    .line 450
    .line 451
    :cond_c
    iput v8, v0, Lv9/e;->j:I

    .line 452
    .line 453
    iput v12, v0, Lv9/e;->k:I

    .line 454
    .line 455
    goto/16 :goto_0

    .line 456
    .line 457
    :cond_d
    iget-object v2, v1, Lw7/p;->a:[B

    .line 458
    .line 459
    iget v14, v1, Lw7/p;->b:I

    .line 460
    .line 461
    iget v15, v1, Lw7/p;->c:I

    .line 462
    .line 463
    :goto_4
    if-ge v14, v15, :cond_26

    .line 464
    .line 465
    add-int/lit8 v3, v14, 0x1

    .line 466
    .line 467
    move/from16 v16, v8

    .line 468
    .line 469
    aget-byte v8, v2, v14

    .line 470
    .line 471
    and-int/lit16 v7, v8, 0xff

    .line 472
    .line 473
    iget v5, v0, Lv9/e;->l:I

    .line 474
    .line 475
    const/16 v11, 0x200

    .line 476
    .line 477
    if-ne v5, v11, :cond_20

    .line 478
    .line 479
    int-to-byte v5, v7

    .line 480
    and-int/lit16 v5, v5, 0xff

    .line 481
    .line 482
    const v17, 0xff00

    .line 483
    .line 484
    .line 485
    or-int v5, v17, v5

    .line 486
    .line 487
    const v18, 0xfff6

    .line 488
    .line 489
    .line 490
    and-int v5, v5, v18

    .line 491
    .line 492
    const v11, 0xfff0

    .line 493
    .line 494
    .line 495
    if-ne v5, v11, :cond_20

    .line 496
    .line 497
    iget-boolean v5, v0, Lv9/e;->n:Z

    .line 498
    .line 499
    if-nez v5, :cond_1d

    .line 500
    .line 501
    add-int/lit8 v5, v14, -0x1

    .line 502
    .line 503
    invoke-virtual {v1, v14}, Lw7/p;->I(I)V

    .line 504
    .line 505
    .line 506
    iget-object v11, v9, Lm9/f;->b:[B

    .line 507
    .line 508
    invoke-virtual {v1}, Lw7/p;->a()I

    .line 509
    .line 510
    .line 511
    move-result v4

    .line 512
    if-ge v4, v13, :cond_e

    .line 513
    .line 514
    :goto_5
    const/4 v12, -0x1

    .line 515
    goto/16 :goto_7

    .line 516
    .line 517
    :cond_e
    invoke-virtual {v1, v11, v12, v13}, Lw7/p;->h([BII)V

    .line 518
    .line 519
    .line 520
    invoke-virtual {v9, v10}, Lm9/f;->q(I)V

    .line 521
    .line 522
    .line 523
    invoke-virtual {v9, v13}, Lm9/f;->i(I)I

    .line 524
    .line 525
    .line 526
    move-result v4

    .line 527
    iget v11, v0, Lv9/e;->o:I

    .line 528
    .line 529
    const/4 v10, -0x1

    .line 530
    if-eq v11, v10, :cond_f

    .line 531
    .line 532
    if-eq v4, v11, :cond_f

    .line 533
    .line 534
    move v12, v10

    .line 535
    goto/16 :goto_7

    .line 536
    .line 537
    :cond_f
    iget v11, v0, Lv9/e;->p:I

    .line 538
    .line 539
    if-eq v11, v10, :cond_12

    .line 540
    .line 541
    iget-object v10, v9, Lm9/f;->b:[B

    .line 542
    .line 543
    invoke-virtual {v1}, Lw7/p;->a()I

    .line 544
    .line 545
    .line 546
    move-result v11

    .line 547
    if-ge v11, v13, :cond_10

    .line 548
    .line 549
    goto/16 :goto_8

    .line 550
    .line 551
    :cond_10
    invoke-virtual {v1, v10, v12, v13}, Lw7/p;->h([BII)V

    .line 552
    .line 553
    .line 554
    const/4 v10, 0x2

    .line 555
    invoke-virtual {v9, v10}, Lm9/f;->q(I)V

    .line 556
    .line 557
    .line 558
    const/4 v10, 0x4

    .line 559
    invoke-virtual {v9, v10}, Lm9/f;->i(I)I

    .line 560
    .line 561
    .line 562
    move-result v11

    .line 563
    iget v13, v0, Lv9/e;->p:I

    .line 564
    .line 565
    if-eq v11, v13, :cond_11

    .line 566
    .line 567
    goto :goto_5

    .line 568
    :cond_11
    invoke-virtual {v1, v3}, Lw7/p;->I(I)V

    .line 569
    .line 570
    .line 571
    goto :goto_6

    .line 572
    :cond_12
    const/4 v10, 0x4

    .line 573
    :goto_6
    iget-object v11, v9, Lm9/f;->b:[B

    .line 574
    .line 575
    invoke-virtual {v1}, Lw7/p;->a()I

    .line 576
    .line 577
    .line 578
    move-result v13

    .line 579
    if-ge v13, v10, :cond_13

    .line 580
    .line 581
    goto :goto_8

    .line 582
    :cond_13
    invoke-virtual {v1, v11, v12, v10}, Lw7/p;->h([BII)V

    .line 583
    .line 584
    .line 585
    const/16 v11, 0xe

    .line 586
    .line 587
    invoke-virtual {v9, v11}, Lm9/f;->q(I)V

    .line 588
    .line 589
    .line 590
    const/16 v11, 0xd

    .line 591
    .line 592
    invoke-virtual {v9, v11}, Lm9/f;->i(I)I

    .line 593
    .line 594
    .line 595
    move-result v13

    .line 596
    const/4 v10, 0x7

    .line 597
    if-ge v13, v10, :cond_14

    .line 598
    .line 599
    goto :goto_5

    .line 600
    :cond_14
    iget-object v10, v1, Lw7/p;->a:[B

    .line 601
    .line 602
    iget v11, v1, Lw7/p;->c:I

    .line 603
    .line 604
    add-int/2addr v5, v13

    .line 605
    if-lt v5, v11, :cond_15

    .line 606
    .line 607
    goto :goto_8

    .line 608
    :cond_15
    aget-byte v13, v10, v5

    .line 609
    .line 610
    const/4 v12, -0x1

    .line 611
    if-ne v13, v12, :cond_17

    .line 612
    .line 613
    add-int/lit8 v5, v5, 0x1

    .line 614
    .line 615
    if-ne v5, v11, :cond_16

    .line 616
    .line 617
    goto :goto_8

    .line 618
    :cond_16
    aget-byte v5, v10, v5

    .line 619
    .line 620
    and-int/lit16 v10, v5, 0xff

    .line 621
    .line 622
    or-int v10, v17, v10

    .line 623
    .line 624
    and-int v10, v10, v18

    .line 625
    .line 626
    const v11, 0xfff0

    .line 627
    .line 628
    .line 629
    if-ne v10, v11, :cond_1c

    .line 630
    .line 631
    and-int/lit8 v5, v5, 0x8

    .line 632
    .line 633
    shr-int/lit8 v5, v5, 0x3

    .line 634
    .line 635
    if-ne v5, v4, :cond_1c

    .line 636
    .line 637
    goto :goto_8

    .line 638
    :cond_17
    const/16 v4, 0x49

    .line 639
    .line 640
    if-eq v13, v4, :cond_18

    .line 641
    .line 642
    goto :goto_7

    .line 643
    :cond_18
    add-int/lit8 v4, v5, 0x1

    .line 644
    .line 645
    if-ne v4, v11, :cond_19

    .line 646
    .line 647
    goto :goto_8

    .line 648
    :cond_19
    aget-byte v4, v10, v4

    .line 649
    .line 650
    const/16 v13, 0x44

    .line 651
    .line 652
    if-eq v4, v13, :cond_1a

    .line 653
    .line 654
    goto :goto_7

    .line 655
    :cond_1a
    add-int/lit8 v5, v5, 0x2

    .line 656
    .line 657
    if-ne v5, v11, :cond_1b

    .line 658
    .line 659
    goto :goto_8

    .line 660
    :cond_1b
    aget-byte v4, v10, v5

    .line 661
    .line 662
    const/16 v5, 0x33

    .line 663
    .line 664
    if-ne v4, v5, :cond_1c

    .line 665
    .line 666
    goto :goto_8

    .line 667
    :cond_1c
    :goto_7
    const/4 v4, 0x1

    .line 668
    goto :goto_b

    .line 669
    :cond_1d
    :goto_8
    and-int/lit8 v2, v8, 0x8

    .line 670
    .line 671
    shr-int/lit8 v2, v2, 0x3

    .line 672
    .line 673
    iput v2, v0, Lv9/e;->q:I

    .line 674
    .line 675
    and-int/lit8 v2, v8, 0x1

    .line 676
    .line 677
    if-nez v2, :cond_1e

    .line 678
    .line 679
    const/4 v2, 0x1

    .line 680
    goto :goto_9

    .line 681
    :cond_1e
    const/4 v2, 0x0

    .line 682
    :goto_9
    iput-boolean v2, v0, Lv9/e;->m:Z

    .line 683
    .line 684
    iget-boolean v2, v0, Lv9/e;->n:Z

    .line 685
    .line 686
    if-nez v2, :cond_1f

    .line 687
    .line 688
    const/4 v4, 0x1

    .line 689
    iput v4, v0, Lv9/e;->j:I

    .line 690
    .line 691
    const/4 v2, 0x0

    .line 692
    iput v2, v0, Lv9/e;->k:I

    .line 693
    .line 694
    goto :goto_a

    .line 695
    :cond_1f
    move/from16 v4, v16

    .line 696
    .line 697
    const/4 v2, 0x0

    .line 698
    iput v4, v0, Lv9/e;->j:I

    .line 699
    .line 700
    iput v2, v0, Lv9/e;->k:I

    .line 701
    .line 702
    :goto_a
    invoke-virtual {v1, v3}, Lw7/p;->I(I)V

    .line 703
    .line 704
    .line 705
    goto/16 :goto_0

    .line 706
    .line 707
    :cond_20
    move v12, v4

    .line 708
    move v4, v13

    .line 709
    :goto_b
    iget v5, v0, Lv9/e;->l:I

    .line 710
    .line 711
    or-int/2addr v7, v5

    .line 712
    const/16 v8, 0x149

    .line 713
    .line 714
    if-eq v7, v8, :cond_25

    .line 715
    .line 716
    const/16 v8, 0x1ff

    .line 717
    .line 718
    if-eq v7, v8, :cond_24

    .line 719
    .line 720
    const/16 v8, 0x344

    .line 721
    .line 722
    if-eq v7, v8, :cond_23

    .line 723
    .line 724
    const/16 v8, 0x433

    .line 725
    .line 726
    if-eq v7, v8, :cond_22

    .line 727
    .line 728
    const/16 v7, 0x100

    .line 729
    .line 730
    if-eq v5, v7, :cond_21

    .line 731
    .line 732
    iput v7, v0, Lv9/e;->l:I

    .line 733
    .line 734
    const/4 v5, 0x3

    .line 735
    const/4 v8, 0x0

    .line 736
    const/4 v10, 0x2

    .line 737
    goto :goto_d

    .line 738
    :cond_21
    const/4 v5, 0x3

    .line 739
    const/4 v8, 0x0

    .line 740
    const/4 v10, 0x2

    .line 741
    goto :goto_c

    .line 742
    :cond_22
    const/4 v10, 0x2

    .line 743
    iput v10, v0, Lv9/e;->j:I

    .line 744
    .line 745
    const/4 v5, 0x3

    .line 746
    iput v5, v0, Lv9/e;->k:I

    .line 747
    .line 748
    const/4 v8, 0x0

    .line 749
    iput v8, v0, Lv9/e;->t:I

    .line 750
    .line 751
    invoke-virtual {v6, v8}, Lw7/p;->I(I)V

    .line 752
    .line 753
    .line 754
    invoke-virtual {v1, v3}, Lw7/p;->I(I)V

    .line 755
    .line 756
    .line 757
    goto/16 :goto_0

    .line 758
    .line 759
    :cond_23
    const/4 v5, 0x3

    .line 760
    const/16 v7, 0x100

    .line 761
    .line 762
    const/4 v8, 0x0

    .line 763
    const/4 v10, 0x2

    .line 764
    const/16 v11, 0x400

    .line 765
    .line 766
    iput v11, v0, Lv9/e;->l:I

    .line 767
    .line 768
    goto :goto_c

    .line 769
    :cond_24
    const/4 v5, 0x3

    .line 770
    const/16 v7, 0x100

    .line 771
    .line 772
    const/4 v8, 0x0

    .line 773
    const/4 v10, 0x2

    .line 774
    const/16 v11, 0x200

    .line 775
    .line 776
    iput v11, v0, Lv9/e;->l:I

    .line 777
    .line 778
    goto :goto_c

    .line 779
    :cond_25
    const/4 v5, 0x3

    .line 780
    const/16 v7, 0x100

    .line 781
    .line 782
    const/4 v8, 0x0

    .line 783
    const/4 v10, 0x2

    .line 784
    const/16 v11, 0x300

    .line 785
    .line 786
    iput v11, v0, Lv9/e;->l:I

    .line 787
    .line 788
    :goto_c
    move v14, v3

    .line 789
    :goto_d
    move v13, v4

    .line 790
    move v3, v7

    .line 791
    move v11, v10

    .line 792
    move v4, v12

    .line 793
    const/4 v7, 0x7

    .line 794
    const/4 v10, 0x4

    .line 795
    move v12, v8

    .line 796
    move v8, v5

    .line 797
    const/16 v5, 0xd

    .line 798
    .line 799
    goto/16 :goto_4

    .line 800
    .line 801
    :cond_26
    invoke-virtual {v1, v14}, Lw7/p;->I(I)V

    .line 802
    .line 803
    .line 804
    goto/16 :goto_0

    .line 805
    .line 806
    :cond_27
    return-void
.end method

.method public final c()V
    .locals 2

    .line 1
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 2
    .line 3
    .line 4
    .line 5
    .line 6
    iput-wide v0, p0, Lv9/e;->u:J

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    iput-boolean v0, p0, Lv9/e;->n:Z

    .line 10
    .line 11
    iput v0, p0, Lv9/e;->j:I

    .line 12
    .line 13
    iput v0, p0, Lv9/e;->k:I

    .line 14
    .line 15
    const/16 v0, 0x100

    .line 16
    .line 17
    iput v0, p0, Lv9/e;->l:I

    .line 18
    .line 19
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
    iput-object v0, p0, Lv9/e;->g:Ljava/lang/String;

    .line 12
    .line 13
    invoke-virtual {p2}, Lh11/h;->i()V

    .line 14
    .line 15
    .line 16
    iget v0, p2, Lh11/h;->f:I

    .line 17
    .line 18
    const/4 v1, 0x1

    .line 19
    invoke-interface {p1, v0, v1}, Lo8/q;->q(II)Lo8/i0;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    iput-object v0, p0, Lv9/e;->h:Lo8/i0;

    .line 24
    .line 25
    iput-object v0, p0, Lv9/e;->v:Lo8/i0;

    .line 26
    .line 27
    iget-boolean v0, p0, Lv9/e;->a:Z

    .line 28
    .line 29
    if-eqz v0, :cond_0

    .line 30
    .line 31
    invoke-virtual {p2}, Lh11/h;->d()V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p2}, Lh11/h;->i()V

    .line 35
    .line 36
    .line 37
    iget v0, p2, Lh11/h;->f:I

    .line 38
    .line 39
    const/4 v1, 0x5

    .line 40
    invoke-interface {p1, v0, v1}, Lo8/q;->q(II)Lo8/i0;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    iput-object p1, p0, Lv9/e;->i:Lo8/i0;

    .line 45
    .line 46
    new-instance v0, Lt7/n;

    .line 47
    .line 48
    invoke-direct {v0}, Lt7/n;-><init>()V

    .line 49
    .line 50
    .line 51
    invoke-virtual {p2}, Lh11/h;->i()V

    .line 52
    .line 53
    .line 54
    iget-object p2, p2, Lh11/h;->h:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast p2, Ljava/lang/String;

    .line 57
    .line 58
    iput-object p2, v0, Lt7/n;->a:Ljava/lang/String;

    .line 59
    .line 60
    iget-object p0, p0, Lv9/e;->f:Ljava/lang/String;

    .line 61
    .line 62
    invoke-static {p0}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    iput-object p0, v0, Lt7/n;->l:Ljava/lang/String;

    .line 67
    .line 68
    const-string p0, "application/id3"

    .line 69
    .line 70
    invoke-static {p0}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    iput-object p0, v0, Lt7/n;->m:Ljava/lang/String;

    .line 75
    .line 76
    invoke-static {v0, p1}, Lf2/m0;->x(Lt7/n;Lo8/i0;)V

    .line 77
    .line 78
    .line 79
    return-void

    .line 80
    :cond_0
    new-instance p1, Lo8/n;

    .line 81
    .line 82
    invoke-direct {p1}, Lo8/n;-><init>()V

    .line 83
    .line 84
    .line 85
    iput-object p1, p0, Lv9/e;->i:Lo8/i0;

    .line 86
    .line 87
    return-void
.end method

.method public final e(Z)V
    .locals 0

    .line 1
    return-void
.end method

.method public final f(IJ)V
    .locals 0

    .line 1
    iput-wide p2, p0, Lv9/e;->u:J

    .line 2
    .line 3
    return-void
.end method
