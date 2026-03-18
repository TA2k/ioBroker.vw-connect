.class public final Lh2/i6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Z

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;

.field public final synthetic l:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lay0/n;Lc1/c;Lh2/r8;Lay0/n;Lt2/b;Lay0/a;Lvy0/b0;Z)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lh2/i6;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/i6;->e:Ljava/lang/Object;

    iput-object p2, p0, Lh2/i6;->j:Ljava/lang/Object;

    iput-object p3, p0, Lh2/i6;->f:Ljava/lang/Object;

    iput-object p4, p0, Lh2/i6;->k:Ljava/lang/Object;

    iput-object p5, p0, Lh2/i6;->l:Ljava/lang/Object;

    iput-object p6, p0, Lh2/i6;->g:Ljava/lang/Object;

    iput-object p7, p0, Lh2/i6;->h:Ljava/lang/Object;

    iput-boolean p8, p0, Lh2/i6;->i:Z

    return-void
.end method

.method public constructor <init>(Lg4/p0;Lg4/p0;Lc1/t1;Lc1/t1;ZLc1/t1;Lay0/o;Li2/e1;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lh2/i6;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/i6;->f:Ljava/lang/Object;

    iput-object p2, p0, Lh2/i6;->g:Ljava/lang/Object;

    iput-object p3, p0, Lh2/i6;->h:Ljava/lang/Object;

    iput-object p4, p0, Lh2/i6;->j:Ljava/lang/Object;

    iput-boolean p5, p0, Lh2/i6;->i:Z

    iput-object p6, p0, Lh2/i6;->k:Ljava/lang/Object;

    iput-object p7, p0, Lh2/i6;->l:Ljava/lang/Object;

    iput-object p8, p0, Lh2/i6;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lh2/r8;Lay0/a;Lvy0/b0;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/n;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lh2/i6;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/i6;->f:Ljava/lang/Object;

    iput-object p2, p0, Lh2/i6;->g:Ljava/lang/Object;

    iput-object p3, p0, Lh2/i6;->h:Ljava/lang/Object;

    iput-boolean p4, p0, Lh2/i6;->i:Z

    iput-object p5, p0, Lh2/i6;->j:Ljava/lang/Object;

    iput-object p6, p0, Lh2/i6;->k:Ljava/lang/Object;

    iput-object p7, p0, Lh2/i6;->l:Ljava/lang/Object;

    iput-object p8, p0, Lh2/i6;->e:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 52

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lh2/i6;->d:I

    .line 4
    .line 5
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 6
    .line 7
    iget-boolean v3, v0, Lh2/i6;->i:Z

    .line 8
    .line 9
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    iget-object v5, v0, Lh2/i6;->e:Ljava/lang/Object;

    .line 12
    .line 13
    iget-object v6, v0, Lh2/i6;->f:Ljava/lang/Object;

    .line 14
    .line 15
    const/4 v7, 0x2

    .line 16
    const/4 v8, 0x1

    .line 17
    iget-object v9, v0, Lh2/i6;->l:Ljava/lang/Object;

    .line 18
    .line 19
    iget-object v10, v0, Lh2/i6;->j:Ljava/lang/Object;

    .line 20
    .line 21
    iget-object v11, v0, Lh2/i6;->k:Ljava/lang/Object;

    .line 22
    .line 23
    iget-object v12, v0, Lh2/i6;->h:Ljava/lang/Object;

    .line 24
    .line 25
    iget-object v13, v0, Lh2/i6;->g:Ljava/lang/Object;

    .line 26
    .line 27
    const/4 v14, 0x0

    .line 28
    packed-switch v1, :pswitch_data_0

    .line 29
    .line 30
    .line 31
    move-object/from16 v0, p1

    .line 32
    .line 33
    check-cast v0, Ll2/o;

    .line 34
    .line 35
    move-object/from16 v1, p2

    .line 36
    .line 37
    check-cast v1, Ljava/lang/Number;

    .line 38
    .line 39
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    and-int/lit8 v2, v1, 0x3

    .line 44
    .line 45
    if-eq v2, v7, :cond_0

    .line 46
    .line 47
    move v14, v8

    .line 48
    :cond_0
    and-int/2addr v1, v8

    .line 49
    check-cast v0, Ll2/t;

    .line 50
    .line 51
    invoke-virtual {v0, v1, v14}, Ll2/t;->O(IZ)Z

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    if-eqz v1, :cond_19

    .line 56
    .line 57
    check-cast v6, Lg4/p0;

    .line 58
    .line 59
    check-cast v13, Lg4/p0;

    .line 60
    .line 61
    check-cast v12, Ll2/t2;

    .line 62
    .line 63
    invoke-interface {v12}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    check-cast v1, Ljava/lang/Number;

    .line 68
    .line 69
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 70
    .line 71
    .line 72
    move-result v1

    .line 73
    new-instance v14, Lg4/p0;

    .line 74
    .line 75
    iget-object v2, v6, Lg4/p0;->a:Lg4/g0;

    .line 76
    .line 77
    iget-object v7, v13, Lg4/p0;->a:Lg4/g0;

    .line 78
    .line 79
    sget-object v12, Lg4/h0;->d:Lr4/o;

    .line 80
    .line 81
    iget-object v12, v2, Lg4/g0;->a:Lr4/o;

    .line 82
    .line 83
    iget-object v15, v7, Lg4/g0;->a:Lr4/o;

    .line 84
    .line 85
    instance-of v8, v12, Lr4/b;

    .line 86
    .line 87
    sget-object v17, Lr4/n;->a:Lr4/n;

    .line 88
    .line 89
    const-wide/16 v18, 0x10

    .line 90
    .line 91
    move-object/from16 v29, v4

    .line 92
    .line 93
    if-nez v8, :cond_3

    .line 94
    .line 95
    instance-of v4, v15, Lr4/b;

    .line 96
    .line 97
    move-object/from16 v30, v5

    .line 98
    .line 99
    if-nez v4, :cond_2

    .line 100
    .line 101
    invoke-interface {v12}, Lr4/o;->a()J

    .line 102
    .line 103
    .line 104
    move-result-wide v4

    .line 105
    move-object/from16 v31, v9

    .line 106
    .line 107
    invoke-interface {v15}, Lr4/o;->a()J

    .line 108
    .line 109
    .line 110
    move-result-wide v8

    .line 111
    invoke-static {v4, v5, v8, v9, v1}, Le3/j0;->q(JJF)J

    .line 112
    .line 113
    .line 114
    move-result-wide v4

    .line 115
    cmp-long v8, v4, v18

    .line 116
    .line 117
    if-eqz v8, :cond_1

    .line 118
    .line 119
    new-instance v8, Lr4/c;

    .line 120
    .line 121
    invoke-direct {v8, v4, v5}, Lr4/c;-><init>(J)V

    .line 122
    .line 123
    .line 124
    :goto_0
    move-object/from16 v17, v8

    .line 125
    .line 126
    :cond_1
    :goto_1
    move-object/from16 v33, v17

    .line 127
    .line 128
    goto :goto_4

    .line 129
    :cond_2
    :goto_2
    move-object/from16 v31, v9

    .line 130
    .line 131
    goto :goto_3

    .line 132
    :cond_3
    move-object/from16 v30, v5

    .line 133
    .line 134
    goto :goto_2

    .line 135
    :goto_3
    if-eqz v8, :cond_7

    .line 136
    .line 137
    instance-of v4, v15, Lr4/b;

    .line 138
    .line 139
    if-eqz v4, :cond_7

    .line 140
    .line 141
    check-cast v12, Lr4/b;

    .line 142
    .line 143
    iget-object v4, v12, Lr4/b;->a:Le3/l0;

    .line 144
    .line 145
    check-cast v15, Lr4/b;

    .line 146
    .line 147
    iget-object v5, v15, Lr4/b;->a:Le3/l0;

    .line 148
    .line 149
    invoke-static {v4, v5, v1}, Lg4/h0;->b(Ljava/lang/Object;Ljava/lang/Object;F)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object v4

    .line 153
    check-cast v4, Le3/p;

    .line 154
    .line 155
    iget v5, v12, Lr4/b;->b:F

    .line 156
    .line 157
    iget v8, v15, Lr4/b;->b:F

    .line 158
    .line 159
    invoke-static {v5, v8, v1}, Llp/wa;->b(FFF)F

    .line 160
    .line 161
    .line 162
    move-result v5

    .line 163
    if-nez v4, :cond_4

    .line 164
    .line 165
    goto :goto_1

    .line 166
    :cond_4
    instance-of v8, v4, Le3/p0;

    .line 167
    .line 168
    if-eqz v8, :cond_5

    .line 169
    .line 170
    check-cast v4, Le3/p0;

    .line 171
    .line 172
    iget-wide v8, v4, Le3/p0;->a:J

    .line 173
    .line 174
    invoke-static {v8, v9, v5}, Lkp/i;->b(JF)J

    .line 175
    .line 176
    .line 177
    move-result-wide v4

    .line 178
    cmp-long v8, v4, v18

    .line 179
    .line 180
    if-eqz v8, :cond_1

    .line 181
    .line 182
    new-instance v8, Lr4/c;

    .line 183
    .line 184
    invoke-direct {v8, v4, v5}, Lr4/c;-><init>(J)V

    .line 185
    .line 186
    .line 187
    goto :goto_0

    .line 188
    :cond_5
    instance-of v8, v4, Le3/l0;

    .line 189
    .line 190
    if-eqz v8, :cond_6

    .line 191
    .line 192
    new-instance v8, Lr4/b;

    .line 193
    .line 194
    check-cast v4, Le3/l0;

    .line 195
    .line 196
    invoke-direct {v8, v4, v5}, Lr4/b;-><init>(Le3/l0;F)V

    .line 197
    .line 198
    .line 199
    goto :goto_0

    .line 200
    :cond_6
    new-instance v0, La8/r0;

    .line 201
    .line 202
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 203
    .line 204
    .line 205
    throw v0

    .line 206
    :cond_7
    invoke-static {v12, v15, v1}, Lg4/h0;->b(Ljava/lang/Object;Ljava/lang/Object;F)Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    move-result-object v4

    .line 210
    move-object/from16 v17, v4

    .line 211
    .line 212
    check-cast v17, Lr4/o;

    .line 213
    .line 214
    goto :goto_1

    .line 215
    :goto_4
    iget-object v4, v2, Lg4/g0;->f:Lk4/n;

    .line 216
    .line 217
    iget-object v5, v7, Lg4/g0;->f:Lk4/n;

    .line 218
    .line 219
    invoke-static {v4, v5, v1}, Lg4/h0;->b(Ljava/lang/Object;Ljava/lang/Object;F)Ljava/lang/Object;

    .line 220
    .line 221
    .line 222
    move-result-object v4

    .line 223
    move-object/from16 v39, v4

    .line 224
    .line 225
    check-cast v39, Lk4/n;

    .line 226
    .line 227
    iget-wide v4, v2, Lg4/g0;->b:J

    .line 228
    .line 229
    iget-wide v8, v7, Lg4/g0;->b:J

    .line 230
    .line 231
    invoke-static {v4, v5, v8, v9, v1}, Lg4/h0;->c(JJF)J

    .line 232
    .line 233
    .line 234
    move-result-wide v34

    .line 235
    iget-object v4, v2, Lg4/g0;->c:Lk4/x;

    .line 236
    .line 237
    if-nez v4, :cond_8

    .line 238
    .line 239
    sget-object v4, Lk4/x;->l:Lk4/x;

    .line 240
    .line 241
    :cond_8
    iget-object v5, v7, Lg4/g0;->c:Lk4/x;

    .line 242
    .line 243
    if-nez v5, :cond_9

    .line 244
    .line 245
    sget-object v5, Lk4/x;->l:Lk4/x;

    .line 246
    .line 247
    :cond_9
    iget v4, v4, Lk4/x;->d:I

    .line 248
    .line 249
    iget v5, v5, Lk4/x;->d:I

    .line 250
    .line 251
    invoke-static {v1, v4, v5}, Llp/wa;->c(FII)I

    .line 252
    .line 253
    .line 254
    move-result v4

    .line 255
    const/16 v5, 0x3e8

    .line 256
    .line 257
    const/4 v8, 0x1

    .line 258
    invoke-static {v4, v8, v5}, Lkp/r9;->e(III)I

    .line 259
    .line 260
    .line 261
    move-result v4

    .line 262
    new-instance v5, Lk4/x;

    .line 263
    .line 264
    invoke-direct {v5, v4}, Lk4/x;-><init>(I)V

    .line 265
    .line 266
    .line 267
    iget-object v4, v2, Lg4/g0;->d:Lk4/t;

    .line 268
    .line 269
    iget-object v8, v7, Lg4/g0;->d:Lk4/t;

    .line 270
    .line 271
    invoke-static {v4, v8, v1}, Lg4/h0;->b(Ljava/lang/Object;Ljava/lang/Object;F)Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    move-result-object v4

    .line 275
    move-object/from16 v37, v4

    .line 276
    .line 277
    check-cast v37, Lk4/t;

    .line 278
    .line 279
    iget-object v4, v2, Lg4/g0;->e:Lk4/u;

    .line 280
    .line 281
    iget-object v8, v7, Lg4/g0;->e:Lk4/u;

    .line 282
    .line 283
    invoke-static {v4, v8, v1}, Lg4/h0;->b(Ljava/lang/Object;Ljava/lang/Object;F)Ljava/lang/Object;

    .line 284
    .line 285
    .line 286
    move-result-object v4

    .line 287
    move-object/from16 v38, v4

    .line 288
    .line 289
    check-cast v38, Lk4/u;

    .line 290
    .line 291
    iget-object v4, v2, Lg4/g0;->g:Ljava/lang/String;

    .line 292
    .line 293
    iget-object v8, v7, Lg4/g0;->g:Ljava/lang/String;

    .line 294
    .line 295
    invoke-static {v4, v8, v1}, Lg4/h0;->b(Ljava/lang/Object;Ljava/lang/Object;F)Ljava/lang/Object;

    .line 296
    .line 297
    .line 298
    move-result-object v4

    .line 299
    move-object/from16 v40, v4

    .line 300
    .line 301
    check-cast v40, Ljava/lang/String;

    .line 302
    .line 303
    iget-wide v8, v2, Lg4/g0;->h:J

    .line 304
    .line 305
    move-object/from16 v36, v5

    .line 306
    .line 307
    iget-wide v4, v7, Lg4/g0;->h:J

    .line 308
    .line 309
    invoke-static {v8, v9, v4, v5, v1}, Lg4/h0;->c(JJF)J

    .line 310
    .line 311
    .line 312
    move-result-wide v41

    .line 313
    iget-object v4, v2, Lg4/g0;->i:Lr4/a;

    .line 314
    .line 315
    const/4 v5, 0x0

    .line 316
    if-eqz v4, :cond_a

    .line 317
    .line 318
    iget v4, v4, Lr4/a;->a:F

    .line 319
    .line 320
    goto :goto_5

    .line 321
    :cond_a
    move v4, v5

    .line 322
    :goto_5
    iget-object v8, v7, Lg4/g0;->i:Lr4/a;

    .line 323
    .line 324
    if-eqz v8, :cond_b

    .line 325
    .line 326
    iget v5, v8, Lr4/a;->a:F

    .line 327
    .line 328
    :cond_b
    invoke-static {v4, v5, v1}, Llp/wa;->b(FFF)F

    .line 329
    .line 330
    .line 331
    move-result v4

    .line 332
    iget-object v5, v2, Lg4/g0;->j:Lr4/p;

    .line 333
    .line 334
    sget-object v8, Lr4/p;->c:Lr4/p;

    .line 335
    .line 336
    if-nez v5, :cond_c

    .line 337
    .line 338
    move-object v5, v8

    .line 339
    :cond_c
    iget-object v9, v7, Lg4/g0;->j:Lr4/p;

    .line 340
    .line 341
    if-nez v9, :cond_d

    .line 342
    .line 343
    goto :goto_6

    .line 344
    :cond_d
    move-object v8, v9

    .line 345
    :goto_6
    new-instance v9, Lr4/p;

    .line 346
    .line 347
    iget v12, v5, Lr4/p;->a:F

    .line 348
    .line 349
    iget v15, v8, Lr4/p;->a:F

    .line 350
    .line 351
    invoke-static {v12, v15, v1}, Llp/wa;->b(FFF)F

    .line 352
    .line 353
    .line 354
    move-result v12

    .line 355
    iget v5, v5, Lr4/p;->b:F

    .line 356
    .line 357
    iget v8, v8, Lr4/p;->b:F

    .line 358
    .line 359
    invoke-static {v5, v8, v1}, Llp/wa;->b(FFF)F

    .line 360
    .line 361
    .line 362
    move-result v5

    .line 363
    invoke-direct {v9, v12, v5}, Lr4/p;-><init>(FF)V

    .line 364
    .line 365
    .line 366
    iget-object v5, v2, Lg4/g0;->k:Ln4/b;

    .line 367
    .line 368
    iget-object v8, v7, Lg4/g0;->k:Ln4/b;

    .line 369
    .line 370
    invoke-static {v5, v8, v1}, Lg4/h0;->b(Ljava/lang/Object;Ljava/lang/Object;F)Ljava/lang/Object;

    .line 371
    .line 372
    .line 373
    move-result-object v5

    .line 374
    move-object/from16 v45, v5

    .line 375
    .line 376
    check-cast v45, Ln4/b;

    .line 377
    .line 378
    move-object/from16 v44, v9

    .line 379
    .line 380
    iget-wide v8, v2, Lg4/g0;->l:J

    .line 381
    .line 382
    move-object v5, v10

    .line 383
    move-object v15, v11

    .line 384
    iget-wide v10, v7, Lg4/g0;->l:J

    .line 385
    .line 386
    invoke-static {v8, v9, v10, v11, v1}, Le3/j0;->q(JJF)J

    .line 387
    .line 388
    .line 389
    move-result-wide v46

    .line 390
    iget-object v8, v2, Lg4/g0;->m:Lr4/l;

    .line 391
    .line 392
    iget-object v9, v7, Lg4/g0;->m:Lr4/l;

    .line 393
    .line 394
    invoke-static {v8, v9, v1}, Lg4/h0;->b(Ljava/lang/Object;Ljava/lang/Object;F)Ljava/lang/Object;

    .line 395
    .line 396
    .line 397
    move-result-object v8

    .line 398
    move-object/from16 v48, v8

    .line 399
    .line 400
    check-cast v48, Lr4/l;

    .line 401
    .line 402
    iget-object v8, v2, Lg4/g0;->n:Le3/m0;

    .line 403
    .line 404
    if-nez v8, :cond_e

    .line 405
    .line 406
    new-instance v8, Le3/m0;

    .line 407
    .line 408
    invoke-direct {v8}, Le3/m0;-><init>()V

    .line 409
    .line 410
    .line 411
    :cond_e
    iget-object v9, v7, Lg4/g0;->n:Le3/m0;

    .line 412
    .line 413
    if-nez v9, :cond_f

    .line 414
    .line 415
    new-instance v9, Le3/m0;

    .line 416
    .line 417
    invoke-direct {v9}, Le3/m0;-><init>()V

    .line 418
    .line 419
    .line 420
    :cond_f
    new-instance v16, Le3/m0;

    .line 421
    .line 422
    iget-wide v10, v8, Le3/m0;->a:J

    .line 423
    .line 424
    move-object/from16 p0, v14

    .line 425
    .line 426
    move-object/from16 v22, v15

    .line 427
    .line 428
    iget-wide v14, v9, Le3/m0;->a:J

    .line 429
    .line 430
    invoke-static {v10, v11, v14, v15, v1}, Le3/j0;->q(JJF)J

    .line 431
    .line 432
    .line 433
    move-result-wide v17

    .line 434
    iget-wide v10, v8, Le3/m0;->b:J

    .line 435
    .line 436
    iget-wide v14, v9, Le3/m0;->b:J

    .line 437
    .line 438
    move-object/from16 p1, v13

    .line 439
    .line 440
    const/16 p2, 0x20

    .line 441
    .line 442
    shr-long v12, v10, p2

    .line 443
    .line 444
    long-to-int v12, v12

    .line 445
    invoke-static {v12}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 446
    .line 447
    .line 448
    move-result v12

    .line 449
    move-wide/from16 v19, v10

    .line 450
    .line 451
    shr-long v10, v14, p2

    .line 452
    .line 453
    long-to-int v10, v10

    .line 454
    invoke-static {v10}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 455
    .line 456
    .line 457
    move-result v10

    .line 458
    invoke-static {v12, v10, v1}, Llp/wa;->b(FFF)F

    .line 459
    .line 460
    .line 461
    move-result v10

    .line 462
    const-wide v23, 0xffffffffL

    .line 463
    .line 464
    .line 465
    .line 466
    .line 467
    and-long v11, v19, v23

    .line 468
    .line 469
    long-to-int v11, v11

    .line 470
    invoke-static {v11}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 471
    .line 472
    .line 473
    move-result v11

    .line 474
    and-long v12, v14, v23

    .line 475
    .line 476
    long-to-int v12, v12

    .line 477
    invoke-static {v12}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 478
    .line 479
    .line 480
    move-result v12

    .line 481
    invoke-static {v11, v12, v1}, Llp/wa;->b(FFF)F

    .line 482
    .line 483
    .line 484
    move-result v11

    .line 485
    invoke-static {v10}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 486
    .line 487
    .line 488
    move-result v10

    .line 489
    int-to-long v12, v10

    .line 490
    invoke-static {v11}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 491
    .line 492
    .line 493
    move-result v10

    .line 494
    int-to-long v10, v10

    .line 495
    shl-long v12, v12, p2

    .line 496
    .line 497
    and-long v10, v10, v23

    .line 498
    .line 499
    or-long v19, v12, v10

    .line 500
    .line 501
    iget v8, v8, Le3/m0;->c:F

    .line 502
    .line 503
    iget v9, v9, Le3/m0;->c:F

    .line 504
    .line 505
    invoke-static {v8, v9, v1}, Llp/wa;->b(FFF)F

    .line 506
    .line 507
    .line 508
    move-result v21

    .line 509
    invoke-direct/range {v16 .. v21}, Le3/m0;-><init>(JJF)V

    .line 510
    .line 511
    .line 512
    iget-object v8, v2, Lg4/g0;->o:Lg4/x;

    .line 513
    .line 514
    iget-object v9, v7, Lg4/g0;->o:Lg4/x;

    .line 515
    .line 516
    if-nez v8, :cond_10

    .line 517
    .line 518
    if-nez v9, :cond_10

    .line 519
    .line 520
    const/16 v50, 0x0

    .line 521
    .line 522
    goto :goto_7

    .line 523
    :cond_10
    if-nez v8, :cond_11

    .line 524
    .line 525
    sget-object v8, Lg4/x;->a:Lg4/x;

    .line 526
    .line 527
    :cond_11
    move-object/from16 v50, v8

    .line 528
    .line 529
    :goto_7
    iget-object v2, v2, Lg4/g0;->p:Lg3/e;

    .line 530
    .line 531
    iget-object v7, v7, Lg4/g0;->p:Lg3/e;

    .line 532
    .line 533
    invoke-static {v2, v7, v1}, Lg4/h0;->b(Ljava/lang/Object;Ljava/lang/Object;F)Ljava/lang/Object;

    .line 534
    .line 535
    .line 536
    move-result-object v2

    .line 537
    move-object/from16 v51, v2

    .line 538
    .line 539
    check-cast v51, Lg3/e;

    .line 540
    .line 541
    new-instance v32, Lg4/g0;

    .line 542
    .line 543
    new-instance v2, Lr4/a;

    .line 544
    .line 545
    invoke-direct {v2, v4}, Lr4/a;-><init>(F)V

    .line 546
    .line 547
    .line 548
    move-object/from16 v43, v2

    .line 549
    .line 550
    move-object/from16 v49, v16

    .line 551
    .line 552
    invoke-direct/range {v32 .. v51}, Lg4/g0;-><init>(Lr4/o;JLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;Lg4/x;Lg3/e;)V

    .line 553
    .line 554
    .line 555
    move-object/from16 v2, v32

    .line 556
    .line 557
    iget-object v4, v6, Lg4/p0;->b:Lg4/t;

    .line 558
    .line 559
    move-object/from16 v13, p1

    .line 560
    .line 561
    iget-object v6, v13, Lg4/p0;->b:Lg4/t;

    .line 562
    .line 563
    sget v7, Lg4/u;->b:I

    .line 564
    .line 565
    new-instance v11, Lg4/t;

    .line 566
    .line 567
    iget v7, v4, Lg4/t;->a:I

    .line 568
    .line 569
    new-instance v8, Lr4/k;

    .line 570
    .line 571
    invoke-direct {v8, v7}, Lr4/k;-><init>(I)V

    .line 572
    .line 573
    .line 574
    iget v7, v6, Lg4/t;->a:I

    .line 575
    .line 576
    new-instance v9, Lr4/k;

    .line 577
    .line 578
    invoke-direct {v9, v7}, Lr4/k;-><init>(I)V

    .line 579
    .line 580
    .line 581
    invoke-static {v8, v9, v1}, Lg4/h0;->b(Ljava/lang/Object;Ljava/lang/Object;F)Ljava/lang/Object;

    .line 582
    .line 583
    .line 584
    move-result-object v7

    .line 585
    check-cast v7, Lr4/k;

    .line 586
    .line 587
    iget v12, v7, Lr4/k;->a:I

    .line 588
    .line 589
    iget v7, v4, Lg4/t;->b:I

    .line 590
    .line 591
    new-instance v8, Lr4/m;

    .line 592
    .line 593
    invoke-direct {v8, v7}, Lr4/m;-><init>(I)V

    .line 594
    .line 595
    .line 596
    iget v7, v6, Lg4/t;->b:I

    .line 597
    .line 598
    new-instance v9, Lr4/m;

    .line 599
    .line 600
    invoke-direct {v9, v7}, Lr4/m;-><init>(I)V

    .line 601
    .line 602
    .line 603
    invoke-static {v8, v9, v1}, Lg4/h0;->b(Ljava/lang/Object;Ljava/lang/Object;F)Ljava/lang/Object;

    .line 604
    .line 605
    .line 606
    move-result-object v7

    .line 607
    check-cast v7, Lr4/m;

    .line 608
    .line 609
    iget v13, v7, Lr4/m;->a:I

    .line 610
    .line 611
    iget-wide v7, v4, Lg4/t;->c:J

    .line 612
    .line 613
    iget-wide v14, v6, Lg4/t;->c:J

    .line 614
    .line 615
    invoke-static {v7, v8, v14, v15, v1}, Lg4/h0;->c(JJF)J

    .line 616
    .line 617
    .line 618
    move-result-wide v14

    .line 619
    iget-object v7, v4, Lg4/t;->d:Lr4/q;

    .line 620
    .line 621
    if-nez v7, :cond_12

    .line 622
    .line 623
    sget-object v7, Lr4/q;->c:Lr4/q;

    .line 624
    .line 625
    :cond_12
    iget-object v8, v6, Lg4/t;->d:Lr4/q;

    .line 626
    .line 627
    if-nez v8, :cond_13

    .line 628
    .line 629
    sget-object v8, Lr4/q;->c:Lr4/q;

    .line 630
    .line 631
    :cond_13
    new-instance v9, Lr4/q;

    .line 632
    .line 633
    move-object/from16 p2, v11

    .line 634
    .line 635
    iget-wide v10, v7, Lr4/q;->a:J

    .line 636
    .line 637
    move/from16 v16, v12

    .line 638
    .line 639
    move/from16 v17, v13

    .line 640
    .line 641
    iget-wide v12, v8, Lr4/q;->a:J

    .line 642
    .line 643
    invoke-static {v10, v11, v12, v13, v1}, Lg4/h0;->c(JJF)J

    .line 644
    .line 645
    .line 646
    move-result-wide v10

    .line 647
    iget-wide v12, v7, Lr4/q;->b:J

    .line 648
    .line 649
    iget-wide v7, v8, Lr4/q;->b:J

    .line 650
    .line 651
    invoke-static {v12, v13, v7, v8, v1}, Lg4/h0;->c(JJF)J

    .line 652
    .line 653
    .line 654
    move-result-wide v7

    .line 655
    invoke-direct {v9, v10, v11, v7, v8}, Lr4/q;-><init>(JJ)V

    .line 656
    .line 657
    .line 658
    iget-object v7, v4, Lg4/t;->e:Lg4/w;

    .line 659
    .line 660
    iget-object v8, v6, Lg4/t;->e:Lg4/w;

    .line 661
    .line 662
    if-nez v7, :cond_14

    .line 663
    .line 664
    if-nez v8, :cond_14

    .line 665
    .line 666
    const/4 v10, 0x0

    .line 667
    goto :goto_8

    .line 668
    :cond_14
    sget-object v10, Lg4/w;->b:Lg4/w;

    .line 669
    .line 670
    if-nez v7, :cond_15

    .line 671
    .line 672
    move-object v7, v10

    .line 673
    :cond_15
    iget-boolean v11, v7, Lg4/w;->a:Z

    .line 674
    .line 675
    if-nez v8, :cond_16

    .line 676
    .line 677
    move-object v8, v10

    .line 678
    :cond_16
    iget-boolean v8, v8, Lg4/w;->a:Z

    .line 679
    .line 680
    if-ne v11, v8, :cond_17

    .line 681
    .line 682
    move-object v10, v7

    .line 683
    goto :goto_8

    .line 684
    :cond_17
    new-instance v10, Lg4/w;

    .line 685
    .line 686
    new-instance v7, Lg4/k;

    .line 687
    .line 688
    invoke-direct {v7}, Ljava/lang/Object;-><init>()V

    .line 689
    .line 690
    .line 691
    new-instance v12, Lg4/k;

    .line 692
    .line 693
    invoke-direct {v12}, Ljava/lang/Object;-><init>()V

    .line 694
    .line 695
    .line 696
    invoke-static {v7, v12, v1}, Lg4/h0;->b(Ljava/lang/Object;Ljava/lang/Object;F)Ljava/lang/Object;

    .line 697
    .line 698
    .line 699
    move-result-object v7

    .line 700
    check-cast v7, Lg4/k;

    .line 701
    .line 702
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 703
    .line 704
    .line 705
    invoke-static {v11}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 706
    .line 707
    .line 708
    move-result-object v7

    .line 709
    invoke-static {v8}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 710
    .line 711
    .line 712
    move-result-object v8

    .line 713
    invoke-static {v7, v8, v1}, Lg4/h0;->b(Ljava/lang/Object;Ljava/lang/Object;F)Ljava/lang/Object;

    .line 714
    .line 715
    .line 716
    move-result-object v7

    .line 717
    check-cast v7, Ljava/lang/Boolean;

    .line 718
    .line 719
    invoke-virtual {v7}, Ljava/lang/Boolean;->booleanValue()Z

    .line 720
    .line 721
    .line 722
    move-result v7

    .line 723
    invoke-direct {v10, v7}, Lg4/w;-><init>(Z)V

    .line 724
    .line 725
    .line 726
    :goto_8
    iget-object v7, v4, Lg4/t;->f:Lr4/i;

    .line 727
    .line 728
    iget-object v8, v6, Lg4/t;->f:Lr4/i;

    .line 729
    .line 730
    invoke-static {v7, v8, v1}, Lg4/h0;->b(Ljava/lang/Object;Ljava/lang/Object;F)Ljava/lang/Object;

    .line 731
    .line 732
    .line 733
    move-result-object v7

    .line 734
    move-object/from16 v18, v7

    .line 735
    .line 736
    check-cast v18, Lr4/i;

    .line 737
    .line 738
    iget v7, v4, Lg4/t;->g:I

    .line 739
    .line 740
    new-instance v8, Lr4/e;

    .line 741
    .line 742
    invoke-direct {v8, v7}, Lr4/e;-><init>(I)V

    .line 743
    .line 744
    .line 745
    iget v7, v6, Lg4/t;->g:I

    .line 746
    .line 747
    new-instance v11, Lr4/e;

    .line 748
    .line 749
    invoke-direct {v11, v7}, Lr4/e;-><init>(I)V

    .line 750
    .line 751
    .line 752
    invoke-static {v8, v11, v1}, Lg4/h0;->b(Ljava/lang/Object;Ljava/lang/Object;F)Ljava/lang/Object;

    .line 753
    .line 754
    .line 755
    move-result-object v7

    .line 756
    check-cast v7, Lr4/e;

    .line 757
    .line 758
    iget v7, v7, Lr4/e;->a:I

    .line 759
    .line 760
    iget v8, v4, Lg4/t;->h:I

    .line 761
    .line 762
    new-instance v11, Lr4/d;

    .line 763
    .line 764
    invoke-direct {v11, v8}, Lr4/d;-><init>(I)V

    .line 765
    .line 766
    .line 767
    iget v8, v6, Lg4/t;->h:I

    .line 768
    .line 769
    new-instance v12, Lr4/d;

    .line 770
    .line 771
    invoke-direct {v12, v8}, Lr4/d;-><init>(I)V

    .line 772
    .line 773
    .line 774
    invoke-static {v11, v12, v1}, Lg4/h0;->b(Ljava/lang/Object;Ljava/lang/Object;F)Ljava/lang/Object;

    .line 775
    .line 776
    .line 777
    move-result-object v8

    .line 778
    check-cast v8, Lr4/d;

    .line 779
    .line 780
    iget v8, v8, Lr4/d;->a:I

    .line 781
    .line 782
    iget-object v4, v4, Lg4/t;->i:Lr4/s;

    .line 783
    .line 784
    iget-object v6, v6, Lg4/t;->i:Lr4/s;

    .line 785
    .line 786
    invoke-static {v4, v6, v1}, Lg4/h0;->b(Ljava/lang/Object;Ljava/lang/Object;F)Ljava/lang/Object;

    .line 787
    .line 788
    .line 789
    move-result-object v1

    .line 790
    move-object/from16 v21, v1

    .line 791
    .line 792
    check-cast v21, Lr4/s;

    .line 793
    .line 794
    move-object/from16 v11, p2

    .line 795
    .line 796
    move/from16 v19, v7

    .line 797
    .line 798
    move/from16 v20, v8

    .line 799
    .line 800
    move/from16 v12, v16

    .line 801
    .line 802
    move/from16 v13, v17

    .line 803
    .line 804
    move-object/from16 v16, v9

    .line 805
    .line 806
    move-object/from16 v17, v10

    .line 807
    .line 808
    invoke-direct/range {v11 .. v21}, Lg4/t;-><init>(IIJLr4/q;Lg4/w;Lr4/i;IILr4/s;)V

    .line 809
    .line 810
    .line 811
    move-object/from16 v14, p0

    .line 812
    .line 813
    invoke-direct {v14, v2, v11}, Lg4/p0;-><init>(Lg4/g0;Lg4/t;)V

    .line 814
    .line 815
    .line 816
    move-object/from16 v11, v22

    .line 817
    .line 818
    check-cast v11, Ll2/t2;

    .line 819
    .line 820
    if-eqz v3, :cond_18

    .line 821
    .line 822
    invoke-interface {v11}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 823
    .line 824
    .line 825
    move-result-object v1

    .line 826
    check-cast v1, Le3/s;

    .line 827
    .line 828
    iget-wide v1, v1, Le3/s;->a:J

    .line 829
    .line 830
    const/16 v27, 0x0

    .line 831
    .line 832
    const v28, 0xfffffe

    .line 833
    .line 834
    .line 835
    const-wide/16 v17, 0x0

    .line 836
    .line 837
    const/16 v19, 0x0

    .line 838
    .line 839
    const/16 v20, 0x0

    .line 840
    .line 841
    const-wide/16 v21, 0x0

    .line 842
    .line 843
    const/16 v23, 0x0

    .line 844
    .line 845
    const-wide/16 v24, 0x0

    .line 846
    .line 847
    const/16 v26, 0x0

    .line 848
    .line 849
    move-wide v15, v1

    .line 850
    invoke-static/range {v14 .. v28}, Lg4/p0;->a(Lg4/p0;JJLk4/x;Lk4/n;JIJLg4/y;Lr4/i;I)Lg4/p0;

    .line 851
    .line 852
    .line 853
    move-result-object v14

    .line 854
    :cond_18
    move-object/from16 v17, v14

    .line 855
    .line 856
    move-object v10, v5

    .line 857
    check-cast v10, Ll2/t2;

    .line 858
    .line 859
    invoke-interface {v10}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 860
    .line 861
    .line 862
    move-result-object v1

    .line 863
    check-cast v1, Le3/s;

    .line 864
    .line 865
    iget-wide v1, v1, Le3/s;->a:J

    .line 866
    .line 867
    new-instance v3, Laa/p;

    .line 868
    .line 869
    move-object/from16 v9, v31

    .line 870
    .line 871
    check-cast v9, Lay0/o;

    .line 872
    .line 873
    move-object/from16 v5, v30

    .line 874
    .line 875
    check-cast v5, Li2/e1;

    .line 876
    .line 877
    const/16 v4, 0xe

    .line 878
    .line 879
    invoke-direct {v3, v4, v9, v5}, Laa/p;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 880
    .line 881
    .line 882
    const v4, 0x44fdd1bf

    .line 883
    .line 884
    .line 885
    invoke-static {v4, v0, v3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 886
    .line 887
    .line 888
    move-result-object v18

    .line 889
    const/16 v20, 0x180

    .line 890
    .line 891
    move-object/from16 v19, v0

    .line 892
    .line 893
    move-wide v15, v1

    .line 894
    invoke-static/range {v15 .. v20}, Li2/h1;->b(JLg4/p0;Lay0/n;Ll2/o;I)V

    .line 895
    .line 896
    .line 897
    goto :goto_9

    .line 898
    :cond_19
    move-object/from16 v19, v0

    .line 899
    .line 900
    move-object/from16 v29, v4

    .line 901
    .line 902
    invoke-virtual/range {v19 .. v19}, Ll2/t;->R()V

    .line 903
    .line 904
    .line 905
    :goto_9
    return-object v29

    .line 906
    :pswitch_0
    move-object/from16 v29, v4

    .line 907
    .line 908
    move-object/from16 v30, v5

    .line 909
    .line 910
    move-object/from16 v31, v9

    .line 911
    .line 912
    move-object v5, v10

    .line 913
    move-object/from16 v22, v11

    .line 914
    .line 915
    move-object v1, v6

    .line 916
    check-cast v1, Lh2/r8;

    .line 917
    .line 918
    move-object/from16 v3, p1

    .line 919
    .line 920
    check-cast v3, Ll2/o;

    .line 921
    .line 922
    move-object/from16 v4, p2

    .line 923
    .line 924
    check-cast v4, Ljava/lang/Number;

    .line 925
    .line 926
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 927
    .line 928
    .line 929
    move-result v4

    .line 930
    move-object v10, v5

    .line 931
    check-cast v10, Lc1/c;

    .line 932
    .line 933
    and-int/lit8 v5, v4, 0x3

    .line 934
    .line 935
    if-eq v5, v7, :cond_1a

    .line 936
    .line 937
    const/4 v5, 0x1

    .line 938
    :goto_a
    const/16 v16, 0x1

    .line 939
    .line 940
    goto :goto_b

    .line 941
    :cond_1a
    move v5, v14

    .line 942
    goto :goto_a

    .line 943
    :goto_b
    and-int/lit8 v4, v4, 0x1

    .line 944
    .line 945
    move-object v9, v3

    .line 946
    check-cast v9, Ll2/t;

    .line 947
    .line 948
    invoke-virtual {v9, v4, v5}, Ll2/t;->O(IZ)Z

    .line 949
    .line 950
    .line 951
    move-result v3

    .line 952
    if-eqz v3, :cond_21

    .line 953
    .line 954
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 955
    .line 956
    const/high16 v4, 0x3f800000    # 1.0f

    .line 957
    .line 958
    invoke-static {v3, v4}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 959
    .line 960
    .line 961
    move-result-object v3

    .line 962
    move-object/from16 v5, v30

    .line 963
    .line 964
    check-cast v5, Lay0/n;

    .line 965
    .line 966
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 967
    .line 968
    .line 969
    move-result-object v4

    .line 970
    invoke-interface {v5, v9, v4}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 971
    .line 972
    .line 973
    move-result-object v4

    .line 974
    check-cast v4, Lk1/q1;

    .line 975
    .line 976
    invoke-static {v3, v4}, Lk1/d;->r(Lx2/s;Lk1/q1;)Lx2/s;

    .line 977
    .line 978
    .line 979
    move-result-object v3

    .line 980
    invoke-virtual {v9, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 981
    .line 982
    .line 983
    move-result v4

    .line 984
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 985
    .line 986
    .line 987
    move-result-object v5

    .line 988
    if-nez v4, :cond_1b

    .line 989
    .line 990
    if-ne v5, v2, :cond_1c

    .line 991
    .line 992
    :cond_1b
    new-instance v5, Le81/w;

    .line 993
    .line 994
    const/16 v2, 0x11

    .line 995
    .line 996
    invoke-direct {v5, v10, v2}, Le81/w;-><init>(Ljava/lang/Object;I)V

    .line 997
    .line 998
    .line 999
    invoke-virtual {v9, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1000
    .line 1001
    .line 1002
    :cond_1c
    check-cast v5, Lay0/k;

    .line 1003
    .line 1004
    invoke-static {v3, v5}, Landroidx/compose/ui/graphics/a;->a(Lx2/s;Lay0/k;)Lx2/s;

    .line 1005
    .line 1006
    .line 1007
    move-result-object v2

    .line 1008
    new-instance v3, Lh2/z;

    .line 1009
    .line 1010
    invoke-direct {v3, v1, v14}, Lh2/z;-><init>(Lh2/r8;I)V

    .line 1011
    .line 1012
    .line 1013
    invoke-static {v2, v3}, Landroidx/compose/ui/graphics/a;->a(Lx2/s;Lay0/k;)Lx2/s;

    .line 1014
    .line 1015
    .line 1016
    move-result-object v2

    .line 1017
    move-object/from16 v8, v22

    .line 1018
    .line 1019
    check-cast v8, Lay0/n;

    .line 1020
    .line 1021
    move-object/from16 v10, v31

    .line 1022
    .line 1023
    check-cast v10, Lt2/b;

    .line 1024
    .line 1025
    check-cast v13, Lay0/a;

    .line 1026
    .line 1027
    move-object v3, v12

    .line 1028
    check-cast v3, Lvy0/b0;

    .line 1029
    .line 1030
    sget-object v4, Lk1/j;->c:Lk1/e;

    .line 1031
    .line 1032
    sget-object v5, Lx2/c;->p:Lx2/h;

    .line 1033
    .line 1034
    invoke-static {v4, v5, v9, v14}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 1035
    .line 1036
    .line 1037
    move-result-object v4

    .line 1038
    iget-wide v5, v9, Ll2/t;->T:J

    .line 1039
    .line 1040
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 1041
    .line 1042
    .line 1043
    move-result v5

    .line 1044
    invoke-virtual {v9}, Ll2/t;->m()Ll2/p1;

    .line 1045
    .line 1046
    .line 1047
    move-result-object v6

    .line 1048
    invoke-static {v9, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 1049
    .line 1050
    .line 1051
    move-result-object v2

    .line 1052
    sget-object v7, Lv3/k;->m1:Lv3/j;

    .line 1053
    .line 1054
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1055
    .line 1056
    .line 1057
    sget-object v7, Lv3/j;->b:Lv3/i;

    .line 1058
    .line 1059
    invoke-virtual {v9}, Ll2/t;->c0()V

    .line 1060
    .line 1061
    .line 1062
    iget-boolean v11, v9, Ll2/t;->S:Z

    .line 1063
    .line 1064
    if-eqz v11, :cond_1d

    .line 1065
    .line 1066
    invoke-virtual {v9, v7}, Ll2/t;->l(Lay0/a;)V

    .line 1067
    .line 1068
    .line 1069
    goto :goto_c

    .line 1070
    :cond_1d
    invoke-virtual {v9}, Ll2/t;->m0()V

    .line 1071
    .line 1072
    .line 1073
    :goto_c
    sget-object v7, Lv3/j;->g:Lv3/h;

    .line 1074
    .line 1075
    invoke-static {v7, v4, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1076
    .line 1077
    .line 1078
    sget-object v4, Lv3/j;->f:Lv3/h;

    .line 1079
    .line 1080
    invoke-static {v4, v6, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1081
    .line 1082
    .line 1083
    sget-object v4, Lv3/j;->j:Lv3/h;

    .line 1084
    .line 1085
    iget-boolean v6, v9, Ll2/t;->S:Z

    .line 1086
    .line 1087
    if-nez v6, :cond_1e

    .line 1088
    .line 1089
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 1090
    .line 1091
    .line 1092
    move-result-object v6

    .line 1093
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1094
    .line 1095
    .line 1096
    move-result-object v7

    .line 1097
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1098
    .line 1099
    .line 1100
    move-result v6

    .line 1101
    if-nez v6, :cond_1f

    .line 1102
    .line 1103
    :cond_1e
    invoke-static {v5, v9, v5, v4}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 1104
    .line 1105
    .line 1106
    :cond_1f
    sget-object v4, Lv3/j;->d:Lv3/h;

    .line 1107
    .line 1108
    invoke-static {v4, v2, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1109
    .line 1110
    .line 1111
    if-eqz v8, :cond_20

    .line 1112
    .line 1113
    const v2, 0x50a4256d

    .line 1114
    .line 1115
    .line 1116
    invoke-virtual {v9, v2}, Ll2/t;->Y(I)V

    .line 1117
    .line 1118
    .line 1119
    const v2, 0x7f12058e

    .line 1120
    .line 1121
    .line 1122
    invoke-static {v9, v2}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 1123
    .line 1124
    .line 1125
    move-result-object v7

    .line 1126
    const v2, 0x7f12058f

    .line 1127
    .line 1128
    .line 1129
    invoke-static {v9, v2}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 1130
    .line 1131
    .line 1132
    move-result-object v5

    .line 1133
    const v2, 0x7f120591

    .line 1134
    .line 1135
    .line 1136
    invoke-static {v9, v2}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 1137
    .line 1138
    .line 1139
    move-result-object v6

    .line 1140
    new-instance v2, Lh2/i6;

    .line 1141
    .line 1142
    iget-boolean v4, v0, Lh2/i6;->i:Z

    .line 1143
    .line 1144
    move-object v0, v2

    .line 1145
    move-object v2, v13

    .line 1146
    invoke-direct/range {v0 .. v8}, Lh2/i6;-><init>(Lh2/r8;Lay0/a;Lvy0/b0;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/n;)V

    .line 1147
    .line 1148
    .line 1149
    const v1, 0x773d37a4

    .line 1150
    .line 1151
    .line 1152
    invoke-static {v1, v9, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 1153
    .line 1154
    .line 1155
    move-result-object v0

    .line 1156
    const/16 v1, 0x36

    .line 1157
    .line 1158
    invoke-static {v0, v9, v1}, Lh2/m8;->a(Lt2/b;Ll2/o;I)V

    .line 1159
    .line 1160
    .line 1161
    invoke-virtual {v9, v14}, Ll2/t;->q(Z)V

    .line 1162
    .line 1163
    .line 1164
    goto :goto_d

    .line 1165
    :cond_20
    const v0, 0x50d311ed

    .line 1166
    .line 1167
    .line 1168
    invoke-virtual {v9, v0}, Ll2/t;->Y(I)V

    .line 1169
    .line 1170
    .line 1171
    invoke-virtual {v9, v14}, Ll2/t;->q(Z)V

    .line 1172
    .line 1173
    .line 1174
    :goto_d
    const/4 v0, 0x6

    .line 1175
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1176
    .line 1177
    .line 1178
    move-result-object v0

    .line 1179
    sget-object v1, Lk1/t;->a:Lk1/t;

    .line 1180
    .line 1181
    invoke-virtual {v10, v1, v9, v0}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1182
    .line 1183
    .line 1184
    const/4 v8, 0x1

    .line 1185
    invoke-virtual {v9, v8}, Ll2/t;->q(Z)V

    .line 1186
    .line 1187
    .line 1188
    goto :goto_e

    .line 1189
    :cond_21
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 1190
    .line 1191
    .line 1192
    :goto_e
    return-object v29

    .line 1193
    :pswitch_1
    move-object/from16 v29, v4

    .line 1194
    .line 1195
    move-object/from16 v30, v5

    .line 1196
    .line 1197
    move-object/from16 v31, v9

    .line 1198
    .line 1199
    move-object v5, v10

    .line 1200
    move-object/from16 v22, v11

    .line 1201
    .line 1202
    move-object/from16 v1, p1

    .line 1203
    .line 1204
    check-cast v1, Ll2/o;

    .line 1205
    .line 1206
    move-object/from16 v4, p2

    .line 1207
    .line 1208
    check-cast v4, Ljava/lang/Number;

    .line 1209
    .line 1210
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 1211
    .line 1212
    .line 1213
    move-result v4

    .line 1214
    move-object v8, v12

    .line 1215
    check-cast v8, Lvy0/b0;

    .line 1216
    .line 1217
    move-object v9, v13

    .line 1218
    check-cast v9, Lay0/a;

    .line 1219
    .line 1220
    check-cast v6, Lh2/r8;

    .line 1221
    .line 1222
    and-int/lit8 v10, v4, 0x3

    .line 1223
    .line 1224
    if-eq v10, v7, :cond_22

    .line 1225
    .line 1226
    const/4 v7, 0x1

    .line 1227
    :goto_f
    const/16 v16, 0x1

    .line 1228
    .line 1229
    goto :goto_10

    .line 1230
    :cond_22
    move v7, v14

    .line 1231
    goto :goto_f

    .line 1232
    :goto_10
    and-int/lit8 v4, v4, 0x1

    .line 1233
    .line 1234
    check-cast v1, Ll2/t;

    .line 1235
    .line 1236
    invoke-virtual {v1, v4, v7}, Ll2/t;->O(IZ)Z

    .line 1237
    .line 1238
    .line 1239
    move-result v4

    .line 1240
    if-eqz v4, :cond_2a

    .line 1241
    .line 1242
    invoke-virtual {v1, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 1243
    .line 1244
    .line 1245
    move-result v4

    .line 1246
    invoke-virtual {v1, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 1247
    .line 1248
    .line 1249
    move-result v7

    .line 1250
    or-int/2addr v4, v7

    .line 1251
    invoke-virtual {v1, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 1252
    .line 1253
    .line 1254
    move-result v7

    .line 1255
    or-int/2addr v4, v7

    .line 1256
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 1257
    .line 1258
    .line 1259
    move-result-object v7

    .line 1260
    if-nez v4, :cond_23

    .line 1261
    .line 1262
    if-ne v7, v2, :cond_24

    .line 1263
    .line 1264
    :cond_23
    new-instance v7, Lh2/a6;

    .line 1265
    .line 1266
    invoke-direct {v7, v6, v9, v8}, Lh2/a6;-><init>(Lh2/r8;Lay0/a;Lvy0/b0;)V

    .line 1267
    .line 1268
    .line 1269
    invoke-virtual {v1, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1270
    .line 1271
    .line 1272
    :cond_24
    check-cast v7, Lay0/a;

    .line 1273
    .line 1274
    invoke-static {v7}, Landroidx/compose/foundation/a;->e(Lay0/a;)Lx2/s;

    .line 1275
    .line 1276
    .line 1277
    move-result-object v4

    .line 1278
    invoke-virtual {v1, v3}, Ll2/t;->h(Z)Z

    .line 1279
    .line 1280
    .line 1281
    move-result v3

    .line 1282
    invoke-virtual {v1, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 1283
    .line 1284
    .line 1285
    move-result v7

    .line 1286
    or-int/2addr v3, v7

    .line 1287
    move-object v10, v5

    .line 1288
    check-cast v10, Ljava/lang/String;

    .line 1289
    .line 1290
    invoke-virtual {v1, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 1291
    .line 1292
    .line 1293
    move-result v7

    .line 1294
    or-int/2addr v3, v7

    .line 1295
    invoke-virtual {v1, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 1296
    .line 1297
    .line 1298
    move-result v7

    .line 1299
    or-int/2addr v3, v7

    .line 1300
    move-object/from16 v11, v22

    .line 1301
    .line 1302
    check-cast v11, Ljava/lang/String;

    .line 1303
    .line 1304
    invoke-virtual {v1, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 1305
    .line 1306
    .line 1307
    move-result v7

    .line 1308
    or-int/2addr v3, v7

    .line 1309
    invoke-virtual {v1, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 1310
    .line 1311
    .line 1312
    move-result v7

    .line 1313
    or-int/2addr v3, v7

    .line 1314
    move-object/from16 v9, v31

    .line 1315
    .line 1316
    check-cast v9, Ljava/lang/String;

    .line 1317
    .line 1318
    invoke-virtual {v1, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 1319
    .line 1320
    .line 1321
    move-result v7

    .line 1322
    or-int/2addr v3, v7

    .line 1323
    move-object/from16 v35, v5

    .line 1324
    .line 1325
    check-cast v35, Ljava/lang/String;

    .line 1326
    .line 1327
    move-object/from16 v36, v22

    .line 1328
    .line 1329
    check-cast v36, Ljava/lang/String;

    .line 1330
    .line 1331
    move-object/from16 v37, v31

    .line 1332
    .line 1333
    check-cast v37, Ljava/lang/String;

    .line 1334
    .line 1335
    move-object/from16 v38, v13

    .line 1336
    .line 1337
    check-cast v38, Lay0/a;

    .line 1338
    .line 1339
    move-object/from16 v39, v12

    .line 1340
    .line 1341
    check-cast v39, Lvy0/b0;

    .line 1342
    .line 1343
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 1344
    .line 1345
    .line 1346
    move-result-object v5

    .line 1347
    if-nez v3, :cond_25

    .line 1348
    .line 1349
    if-ne v5, v2, :cond_26

    .line 1350
    .line 1351
    :cond_25
    new-instance v32, Lh2/h6;

    .line 1352
    .line 1353
    iget-boolean v0, v0, Lh2/i6;->i:Z

    .line 1354
    .line 1355
    move/from16 v33, v0

    .line 1356
    .line 1357
    move-object/from16 v34, v6

    .line 1358
    .line 1359
    invoke-direct/range {v32 .. v39}, Lh2/h6;-><init>(ZLh2/r8;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/a;Lvy0/b0;)V

    .line 1360
    .line 1361
    .line 1362
    move-object/from16 v5, v32

    .line 1363
    .line 1364
    invoke-virtual {v1, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1365
    .line 1366
    .line 1367
    :cond_26
    check-cast v5, Lay0/k;

    .line 1368
    .line 1369
    const/4 v8, 0x1

    .line 1370
    invoke-static {v4, v8, v5}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 1371
    .line 1372
    .line 1373
    move-result-object v0

    .line 1374
    move-object/from16 v5, v30

    .line 1375
    .line 1376
    check-cast v5, Lay0/n;

    .line 1377
    .line 1378
    sget-object v2, Lx2/c;->d:Lx2/j;

    .line 1379
    .line 1380
    invoke-static {v2, v14}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 1381
    .line 1382
    .line 1383
    move-result-object v2

    .line 1384
    iget-wide v3, v1, Ll2/t;->T:J

    .line 1385
    .line 1386
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 1387
    .line 1388
    .line 1389
    move-result v3

    .line 1390
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 1391
    .line 1392
    .line 1393
    move-result-object v4

    .line 1394
    invoke-static {v1, v0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 1395
    .line 1396
    .line 1397
    move-result-object v0

    .line 1398
    sget-object v6, Lv3/k;->m1:Lv3/j;

    .line 1399
    .line 1400
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1401
    .line 1402
    .line 1403
    sget-object v6, Lv3/j;->b:Lv3/i;

    .line 1404
    .line 1405
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 1406
    .line 1407
    .line 1408
    iget-boolean v7, v1, Ll2/t;->S:Z

    .line 1409
    .line 1410
    if-eqz v7, :cond_27

    .line 1411
    .line 1412
    invoke-virtual {v1, v6}, Ll2/t;->l(Lay0/a;)V

    .line 1413
    .line 1414
    .line 1415
    goto :goto_11

    .line 1416
    :cond_27
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 1417
    .line 1418
    .line 1419
    :goto_11
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 1420
    .line 1421
    invoke-static {v6, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1422
    .line 1423
    .line 1424
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 1425
    .line 1426
    invoke-static {v2, v4, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1427
    .line 1428
    .line 1429
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 1430
    .line 1431
    iget-boolean v4, v1, Ll2/t;->S:Z

    .line 1432
    .line 1433
    if-nez v4, :cond_28

    .line 1434
    .line 1435
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 1436
    .line 1437
    .line 1438
    move-result-object v4

    .line 1439
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1440
    .line 1441
    .line 1442
    move-result-object v6

    .line 1443
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1444
    .line 1445
    .line 1446
    move-result v4

    .line 1447
    if-nez v4, :cond_29

    .line 1448
    .line 1449
    :cond_28
    invoke-static {v3, v1, v3, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 1450
    .line 1451
    .line 1452
    :cond_29
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 1453
    .line 1454
    invoke-static {v2, v0, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1455
    .line 1456
    .line 1457
    const/4 v8, 0x1

    .line 1458
    invoke-static {v14, v5, v1, v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->u(ILay0/n;Ll2/t;Z)V

    .line 1459
    .line 1460
    .line 1461
    goto :goto_12

    .line 1462
    :cond_2a
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 1463
    .line 1464
    .line 1465
    :goto_12
    return-object v29

    .line 1466
    nop

    .line 1467
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
