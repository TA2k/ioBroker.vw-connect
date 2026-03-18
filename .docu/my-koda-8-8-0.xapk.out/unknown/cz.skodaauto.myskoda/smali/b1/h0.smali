.class public final Lb1/h0;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:I

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;

.field public final synthetic l:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lc1/w1;Lx2/s;Lc1/a0;Lay0/k;Lt2/b;I)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lb1/h0;->f:I

    .line 1
    iput-object p1, p0, Lb1/h0;->h:Ljava/lang/Object;

    iput-object p2, p0, Lb1/h0;->i:Ljava/lang/Object;

    iput-object p3, p0, Lb1/h0;->j:Ljava/lang/Object;

    iput-object p4, p0, Lb1/h0;->k:Ljava/lang/Object;

    iput-object p5, p0, Lb1/h0;->l:Ljava/lang/Object;

    iput p6, p0, Lb1/h0;->g:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method

.method public constructor <init>(Ll2/b1;Lz4/k;Lay0/a;ILjava/lang/String;Ljava/lang/String;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lb1/h0;->f:I

    .line 2
    iput-object p1, p0, Lb1/h0;->h:Ljava/lang/Object;

    iput-object p2, p0, Lb1/h0;->i:Ljava/lang/Object;

    iput-object p3, p0, Lb1/h0;->j:Ljava/lang/Object;

    iput p4, p0, Lb1/h0;->g:I

    iput-object p5, p0, Lb1/h0;->k:Ljava/lang/Object;

    iput-object p6, p0, Lb1/h0;->l:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method

.method public constructor <init>(Lvv/m0;Lg4/g;Lx2/s;Lay0/k;Ljava/util/Map;I)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Lb1/h0;->f:I

    .line 3
    iput-object p1, p0, Lb1/h0;->h:Ljava/lang/Object;

    iput-object p2, p0, Lb1/h0;->j:Ljava/lang/Object;

    iput-object p3, p0, Lb1/h0;->i:Ljava/lang/Object;

    iput-object p4, p0, Lb1/h0;->k:Ljava/lang/Object;

    iput-object p5, p0, Lb1/h0;->l:Ljava/lang/Object;

    iput p6, p0, Lb1/h0;->g:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method

.method public constructor <init>(Lx2/s;Lkn/m0;Lx2/d;Lay0/k;Lt2/b;I)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lb1/h0;->f:I

    .line 4
    iput-object p1, p0, Lb1/h0;->i:Ljava/lang/Object;

    iput-object p2, p0, Lb1/h0;->h:Ljava/lang/Object;

    iput-object p3, p0, Lb1/h0;->j:Ljava/lang/Object;

    check-cast p4, Lkotlin/jvm/internal/n;

    iput-object p4, p0, Lb1/h0;->k:Ljava/lang/Object;

    iput-object p5, p0, Lb1/h0;->l:Ljava/lang/Object;

    iput p6, p0, Lb1/h0;->g:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 35

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lb1/h0;->f:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v7, p1

    .line 9
    .line 10
    check-cast v7, Ll2/o;

    .line 11
    .line 12
    move-object/from16 v1, p2

    .line 13
    .line 14
    check-cast v1, Ljava/lang/Number;

    .line 15
    .line 16
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 17
    .line 18
    .line 19
    iget-object v1, v0, Lb1/h0;->h:Ljava/lang/Object;

    .line 20
    .line 21
    move-object v2, v1

    .line 22
    check-cast v2, Lvv/m0;

    .line 23
    .line 24
    iget-object v1, v0, Lb1/h0;->j:Ljava/lang/Object;

    .line 25
    .line 26
    move-object v3, v1

    .line 27
    check-cast v3, Lg4/g;

    .line 28
    .line 29
    iget-object v1, v0, Lb1/h0;->i:Ljava/lang/Object;

    .line 30
    .line 31
    move-object v4, v1

    .line 32
    check-cast v4, Lx2/s;

    .line 33
    .line 34
    iget-object v1, v0, Lb1/h0;->k:Ljava/lang/Object;

    .line 35
    .line 36
    move-object v5, v1

    .line 37
    check-cast v5, Lay0/k;

    .line 38
    .line 39
    iget-object v1, v0, Lb1/h0;->l:Ljava/lang/Object;

    .line 40
    .line 41
    move-object v6, v1

    .line 42
    check-cast v6, Ljava/util/Map;

    .line 43
    .line 44
    iget v0, v0, Lb1/h0;->g:I

    .line 45
    .line 46
    or-int/lit8 v0, v0, 0x1

    .line 47
    .line 48
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 49
    .line 50
    .line 51
    move-result v8

    .line 52
    invoke-static/range {v2 .. v8}, Lvv/l0;->b(Lvv/m0;Lg4/g;Lx2/s;Lay0/k;Ljava/util/Map;Ll2/o;I)V

    .line 53
    .line 54
    .line 55
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    return-object v0

    .line 58
    :pswitch_0
    move-object/from16 v6, p1

    .line 59
    .line 60
    check-cast v6, Ll2/o;

    .line 61
    .line 62
    move-object/from16 v1, p2

    .line 63
    .line 64
    check-cast v1, Ljava/lang/Number;

    .line 65
    .line 66
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 67
    .line 68
    .line 69
    iget-object v1, v0, Lb1/h0;->i:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast v1, Lx2/s;

    .line 72
    .line 73
    iget-object v2, v0, Lb1/h0;->h:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast v2, Lkn/m0;

    .line 76
    .line 77
    iget-object v3, v0, Lb1/h0;->j:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast v3, Lx2/d;

    .line 80
    .line 81
    iget-object v4, v0, Lb1/h0;->k:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast v4, Lkotlin/jvm/internal/n;

    .line 84
    .line 85
    iget-object v5, v0, Lb1/h0;->l:Ljava/lang/Object;

    .line 86
    .line 87
    check-cast v5, Lt2/b;

    .line 88
    .line 89
    iget v0, v0, Lb1/h0;->g:I

    .line 90
    .line 91
    or-int/lit8 v0, v0, 0x1

    .line 92
    .line 93
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 94
    .line 95
    .line 96
    move-result v7

    .line 97
    invoke-static/range {v1 .. v7}, Llp/sd;->c(Lx2/s;Lkn/m0;Lx2/d;Lay0/k;Lt2/b;Ll2/o;I)V

    .line 98
    .line 99
    .line 100
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 101
    .line 102
    return-object v0

    .line 103
    :pswitch_1
    move-object/from16 v1, p1

    .line 104
    .line 105
    check-cast v1, Ll2/o;

    .line 106
    .line 107
    move-object/from16 v2, p2

    .line 108
    .line 109
    check-cast v2, Ljava/lang/Number;

    .line 110
    .line 111
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 112
    .line 113
    .line 114
    move-result v2

    .line 115
    iget-object v3, v0, Lb1/h0;->i:Ljava/lang/Object;

    .line 116
    .line 117
    check-cast v3, Lz4/k;

    .line 118
    .line 119
    and-int/lit8 v2, v2, 0x3

    .line 120
    .line 121
    const/4 v4, 0x2

    .line 122
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 123
    .line 124
    if-ne v2, v4, :cond_1

    .line 125
    .line 126
    move-object v2, v1

    .line 127
    check-cast v2, Ll2/t;

    .line 128
    .line 129
    invoke-virtual {v2}, Ll2/t;->A()Z

    .line 130
    .line 131
    .line 132
    move-result v4

    .line 133
    if-nez v4, :cond_0

    .line 134
    .line 135
    goto :goto_0

    .line 136
    :cond_0
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 137
    .line 138
    .line 139
    move-object/from16 p2, v5

    .line 140
    .line 141
    goto/16 :goto_6

    .line 142
    .line 143
    :cond_1
    :goto_0
    iget-object v2, v0, Lb1/h0;->h:Ljava/lang/Object;

    .line 144
    .line 145
    check-cast v2, Ll2/b1;

    .line 146
    .line 147
    invoke-interface {v2, v5}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 148
    .line 149
    .line 150
    iget v2, v3, Lz4/k;->b:I

    .line 151
    .line 152
    invoke-virtual {v3}, Lz4/k;->e()V

    .line 153
    .line 154
    .line 155
    move-object v13, v1

    .line 156
    check-cast v13, Ll2/t;

    .line 157
    .line 158
    const v1, -0x459c5b35

    .line 159
    .line 160
    .line 161
    invoke-virtual {v13, v1}, Ll2/t;->Y(I)V

    .line 162
    .line 163
    .line 164
    invoke-virtual {v3}, Lz4/k;->d()Lt1/j0;

    .line 165
    .line 166
    .line 167
    move-result-object v1

    .line 168
    iget-object v1, v1, Lt1/j0;->e:Ljava/lang/Object;

    .line 169
    .line 170
    check-cast v1, Lz4/k;

    .line 171
    .line 172
    invoke-virtual {v1}, Lz4/k;->c()Lz4/f;

    .line 173
    .line 174
    .line 175
    move-result-object v4

    .line 176
    invoke-virtual {v1}, Lz4/k;->c()Lz4/f;

    .line 177
    .line 178
    .line 179
    move-result-object v1

    .line 180
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object v6

    .line 184
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 185
    .line 186
    if-ne v6, v7, :cond_2

    .line 187
    .line 188
    sget-object v6, Lel/d;->e:Lel/d;

    .line 189
    .line 190
    invoke-virtual {v13, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 191
    .line 192
    .line 193
    :cond_2
    check-cast v6, Lay0/k;

    .line 194
    .line 195
    sget-object v8, Lx2/p;->b:Lx2/p;

    .line 196
    .line 197
    invoke-static {v8, v4, v6}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 198
    .line 199
    .line 200
    move-result-object v14

    .line 201
    const/4 v4, 0x5

    .line 202
    int-to-float v6, v4

    .line 203
    const/16 v18, 0x0

    .line 204
    .line 205
    const/16 v19, 0xb

    .line 206
    .line 207
    const/4 v15, 0x0

    .line 208
    const/16 v16, 0x0

    .line 209
    .line 210
    move/from16 v17, v6

    .line 211
    .line 212
    invoke-static/range {v14 .. v19}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 213
    .line 214
    .line 215
    move-result-object v6

    .line 216
    sget-object v9, Lk1/j;->c:Lk1/e;

    .line 217
    .line 218
    sget-object v10, Lx2/c;->p:Lx2/h;

    .line 219
    .line 220
    const/4 v11, 0x0

    .line 221
    invoke-static {v9, v10, v13, v11}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 222
    .line 223
    .line 224
    move-result-object v9

    .line 225
    iget-wide v14, v13, Ll2/t;->T:J

    .line 226
    .line 227
    invoke-static {v14, v15}, Ljava/lang/Long;->hashCode(J)I

    .line 228
    .line 229
    .line 230
    move-result v10

    .line 231
    invoke-virtual {v13}, Ll2/t;->m()Ll2/p1;

    .line 232
    .line 233
    .line 234
    move-result-object v12

    .line 235
    invoke-static {v13, v6}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 236
    .line 237
    .line 238
    move-result-object v6

    .line 239
    sget-object v14, Lv3/k;->m1:Lv3/j;

    .line 240
    .line 241
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 242
    .line 243
    .line 244
    sget-object v14, Lv3/j;->b:Lv3/i;

    .line 245
    .line 246
    invoke-virtual {v13}, Ll2/t;->c0()V

    .line 247
    .line 248
    .line 249
    iget-boolean v15, v13, Ll2/t;->S:Z

    .line 250
    .line 251
    if-eqz v15, :cond_3

    .line 252
    .line 253
    invoke-virtual {v13, v14}, Ll2/t;->l(Lay0/a;)V

    .line 254
    .line 255
    .line 256
    goto :goto_1

    .line 257
    :cond_3
    invoke-virtual {v13}, Ll2/t;->m0()V

    .line 258
    .line 259
    .line 260
    :goto_1
    sget-object v14, Lv3/j;->g:Lv3/h;

    .line 261
    .line 262
    invoke-static {v14, v9, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 263
    .line 264
    .line 265
    sget-object v9, Lv3/j;->f:Lv3/h;

    .line 266
    .line 267
    invoke-static {v9, v12, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 268
    .line 269
    .line 270
    sget-object v9, Lv3/j;->j:Lv3/h;

    .line 271
    .line 272
    iget-boolean v12, v13, Ll2/t;->S:Z

    .line 273
    .line 274
    if-nez v12, :cond_4

    .line 275
    .line 276
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 277
    .line 278
    .line 279
    move-result-object v12

    .line 280
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 281
    .line 282
    .line 283
    move-result-object v14

    .line 284
    invoke-static {v12, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 285
    .line 286
    .line 287
    move-result v12

    .line 288
    if-nez v12, :cond_5

    .line 289
    .line 290
    :cond_4
    invoke-static {v10, v13, v10, v9}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 291
    .line 292
    .line 293
    :cond_5
    sget-object v9, Lv3/j;->d:Lv3/h;

    .line 294
    .line 295
    invoke-static {v9, v6, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 296
    .line 297
    .line 298
    iget-object v6, v0, Lb1/h0;->k:Ljava/lang/Object;

    .line 299
    .line 300
    check-cast v6, Ljava/lang/String;

    .line 301
    .line 302
    sget-object v9, Lj91/j;->a:Ll2/u2;

    .line 303
    .line 304
    invoke-virtual {v13, v9}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 305
    .line 306
    .line 307
    move-result-object v10

    .line 308
    check-cast v10, Lj91/f;

    .line 309
    .line 310
    invoke-virtual {v10}, Lj91/f;->b()Lg4/p0;

    .line 311
    .line 312
    .line 313
    move-result-object v10

    .line 314
    sget-object v12, Lj91/h;->a:Ll2/u2;

    .line 315
    .line 316
    invoke-virtual {v13, v12}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 317
    .line 318
    .line 319
    move-result-object v14

    .line 320
    check-cast v14, Lj91/e;

    .line 321
    .line 322
    invoke-virtual {v14}, Lj91/e;->q()J

    .line 323
    .line 324
    .line 325
    move-result-wide v14

    .line 326
    const/16 v26, 0x0

    .line 327
    .line 328
    const v27, 0xfff4

    .line 329
    .line 330
    .line 331
    move-object/from16 v16, v8

    .line 332
    .line 333
    const/4 v8, 0x0

    .line 334
    move/from16 v18, v11

    .line 335
    .line 336
    move-object/from16 v17, v12

    .line 337
    .line 338
    const-wide/16 v11, 0x0

    .line 339
    .line 340
    move-object/from16 v24, v13

    .line 341
    .line 342
    const/4 v13, 0x0

    .line 343
    move-object/from16 v20, v7

    .line 344
    .line 345
    move-object/from16 v19, v9

    .line 346
    .line 347
    move-object v7, v10

    .line 348
    move-wide v9, v14

    .line 349
    const-wide/16 v14, 0x0

    .line 350
    .line 351
    move-object/from16 v21, v16

    .line 352
    .line 353
    const/16 v16, 0x0

    .line 354
    .line 355
    move-object/from16 v22, v17

    .line 356
    .line 357
    const/16 v17, 0x0

    .line 358
    .line 359
    move/from16 v25, v18

    .line 360
    .line 361
    move-object/from16 v23, v19

    .line 362
    .line 363
    const-wide/16 v18, 0x0

    .line 364
    .line 365
    move-object/from16 v28, v20

    .line 366
    .line 367
    const/16 v20, 0x0

    .line 368
    .line 369
    move-object/from16 v29, v21

    .line 370
    .line 371
    const/16 v21, 0x0

    .line 372
    .line 373
    move-object/from16 v30, v22

    .line 374
    .line 375
    const/16 v22, 0x0

    .line 376
    .line 377
    move-object/from16 v31, v23

    .line 378
    .line 379
    const/16 v23, 0x0

    .line 380
    .line 381
    move/from16 v32, v25

    .line 382
    .line 383
    const/16 v25, 0x0

    .line 384
    .line 385
    move-object/from16 p2, v5

    .line 386
    .line 387
    move-object/from16 v34, v28

    .line 388
    .line 389
    move-object/from16 v33, v29

    .line 390
    .line 391
    move-object/from16 v5, v30

    .line 392
    .line 393
    move-object/from16 v4, v31

    .line 394
    .line 395
    move/from16 v28, v2

    .line 396
    .line 397
    move/from16 v2, v32

    .line 398
    .line 399
    invoke-static/range {v6 .. v27}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 400
    .line 401
    .line 402
    move-object/from16 v13, v24

    .line 403
    .line 404
    iget-object v6, v0, Lb1/h0;->l:Ljava/lang/Object;

    .line 405
    .line 406
    check-cast v6, Ljava/lang/String;

    .line 407
    .line 408
    if-nez v6, :cond_6

    .line 409
    .line 410
    const v4, -0x1c72617d

    .line 411
    .line 412
    .line 413
    invoke-virtual {v13, v4}, Ll2/t;->Y(I)V

    .line 414
    .line 415
    .line 416
    :goto_2
    invoke-virtual {v13, v2}, Ll2/t;->q(Z)V

    .line 417
    .line 418
    .line 419
    goto :goto_3

    .line 420
    :cond_6
    const v6, -0x1c72617c

    .line 421
    .line 422
    .line 423
    invoke-virtual {v13, v6}, Ll2/t;->Y(I)V

    .line 424
    .line 425
    .line 426
    iget-object v6, v0, Lb1/h0;->l:Ljava/lang/Object;

    .line 427
    .line 428
    check-cast v6, Ljava/lang/String;

    .line 429
    .line 430
    invoke-virtual {v13, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 431
    .line 432
    .line 433
    move-result-object v4

    .line 434
    check-cast v4, Lj91/f;

    .line 435
    .line 436
    invoke-virtual {v4}, Lj91/f;->e()Lg4/p0;

    .line 437
    .line 438
    .line 439
    move-result-object v7

    .line 440
    invoke-virtual {v13, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 441
    .line 442
    .line 443
    move-result-object v4

    .line 444
    check-cast v4, Lj91/e;

    .line 445
    .line 446
    invoke-virtual {v4}, Lj91/e;->s()J

    .line 447
    .line 448
    .line 449
    move-result-wide v9

    .line 450
    const/16 v26, 0x0

    .line 451
    .line 452
    const v27, 0xfff4

    .line 453
    .line 454
    .line 455
    const/4 v8, 0x0

    .line 456
    const-wide/16 v11, 0x0

    .line 457
    .line 458
    move-object/from16 v24, v13

    .line 459
    .line 460
    const/4 v13, 0x0

    .line 461
    const-wide/16 v14, 0x0

    .line 462
    .line 463
    const/16 v16, 0x0

    .line 464
    .line 465
    const/16 v17, 0x0

    .line 466
    .line 467
    const-wide/16 v18, 0x0

    .line 468
    .line 469
    const/16 v20, 0x0

    .line 470
    .line 471
    const/16 v21, 0x0

    .line 472
    .line 473
    const/16 v22, 0x0

    .line 474
    .line 475
    const/16 v23, 0x0

    .line 476
    .line 477
    const/16 v25, 0x0

    .line 478
    .line 479
    invoke-static/range {v6 .. v27}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 480
    .line 481
    .line 482
    move-object/from16 v13, v24

    .line 483
    .line 484
    goto :goto_2

    .line 485
    :goto_3
    const/4 v4, 0x1

    .line 486
    invoke-virtual {v13, v4}, Ll2/t;->q(Z)V

    .line 487
    .line 488
    .line 489
    iget v4, v0, Lb1/h0;->g:I

    .line 490
    .line 491
    invoke-static {v4, v2, v13}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 492
    .line 493
    .line 494
    move-result-object v6

    .line 495
    const v7, 0x7f0803a7

    .line 496
    .line 497
    .line 498
    const v8, 0x7f080348

    .line 499
    .line 500
    .line 501
    if-ne v4, v7, :cond_7

    .line 502
    .line 503
    const-string v7, "External Link"

    .line 504
    .line 505
    goto :goto_4

    .line 506
    :cond_7
    if-ne v4, v8, :cond_8

    .line 507
    .line 508
    const-string v7, "Update"

    .line 509
    .line 510
    goto :goto_4

    .line 511
    :cond_8
    const-string v7, "Arrow"

    .line 512
    .line 513
    :goto_4
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 514
    .line 515
    .line 516
    move-result-object v9

    .line 517
    move-object/from16 v10, v34

    .line 518
    .line 519
    if-ne v9, v10, :cond_9

    .line 520
    .line 521
    sget-object v9, Lel/d;->f:Lel/d;

    .line 522
    .line 523
    invoke-virtual {v13, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 524
    .line 525
    .line 526
    :cond_9
    check-cast v9, Lay0/k;

    .line 527
    .line 528
    move-object/from16 v10, v33

    .line 529
    .line 530
    invoke-static {v10, v1, v9}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 531
    .line 532
    .line 533
    move-result-object v1

    .line 534
    if-ne v4, v8, :cond_a

    .line 535
    .line 536
    const v4, -0x72a6e0e3

    .line 537
    .line 538
    .line 539
    invoke-virtual {v13, v4}, Ll2/t;->Y(I)V

    .line 540
    .line 541
    .line 542
    invoke-virtual {v13, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 543
    .line 544
    .line 545
    move-result-object v4

    .line 546
    check-cast v4, Lj91/e;

    .line 547
    .line 548
    invoke-virtual {v4}, Lj91/e;->u()J

    .line 549
    .line 550
    .line 551
    move-result-wide v4

    .line 552
    invoke-virtual {v13, v2}, Ll2/t;->q(Z)V

    .line 553
    .line 554
    .line 555
    goto :goto_5

    .line 556
    :cond_a
    const v4, -0x72a6dc3f

    .line 557
    .line 558
    .line 559
    invoke-virtual {v13, v4}, Ll2/t;->Y(I)V

    .line 560
    .line 561
    .line 562
    invoke-virtual {v13, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 563
    .line 564
    .line 565
    move-result-object v4

    .line 566
    check-cast v4, Lj91/e;

    .line 567
    .line 568
    invoke-virtual {v4}, Lj91/e;->q()J

    .line 569
    .line 570
    .line 571
    move-result-wide v4

    .line 572
    invoke-virtual {v13, v2}, Ll2/t;->q(Z)V

    .line 573
    .line 574
    .line 575
    :goto_5
    new-instance v12, Le3/m;

    .line 576
    .line 577
    const/4 v8, 0x5

    .line 578
    invoke-direct {v12, v4, v5, v8}, Le3/m;-><init>(JI)V

    .line 579
    .line 580
    .line 581
    const/4 v14, 0x0

    .line 582
    const/16 v15, 0x38

    .line 583
    .line 584
    const/4 v9, 0x0

    .line 585
    const/4 v10, 0x0

    .line 586
    const/4 v11, 0x0

    .line 587
    move-object v8, v1

    .line 588
    invoke-static/range {v6 .. v15}, Lkp/m;->a(Li3/c;Ljava/lang/String;Lx2/s;Lx2/e;Lt3/k;FLe3/m;Ll2/o;II)V

    .line 589
    .line 590
    .line 591
    invoke-virtual {v13, v2}, Ll2/t;->q(Z)V

    .line 592
    .line 593
    .line 594
    iget v1, v3, Lz4/k;->b:I

    .line 595
    .line 596
    move/from16 v2, v28

    .line 597
    .line 598
    if-eq v1, v2, :cond_b

    .line 599
    .line 600
    iget-object v0, v0, Lb1/h0;->j:Ljava/lang/Object;

    .line 601
    .line 602
    check-cast v0, Lay0/a;

    .line 603
    .line 604
    invoke-static {v0, v13}, Ll2/l0;->g(Lay0/a;Ll2/o;)V

    .line 605
    .line 606
    .line 607
    :cond_b
    :goto_6
    return-object p2

    .line 608
    :pswitch_2
    move-object/from16 v6, p1

    .line 609
    .line 610
    check-cast v6, Ll2/o;

    .line 611
    .line 612
    move-object/from16 v1, p2

    .line 613
    .line 614
    check-cast v1, Ljava/lang/Number;

    .line 615
    .line 616
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 617
    .line 618
    .line 619
    iget-object v1, v0, Lb1/h0;->h:Ljava/lang/Object;

    .line 620
    .line 621
    check-cast v1, Lc1/w1;

    .line 622
    .line 623
    iget-object v2, v0, Lb1/h0;->i:Ljava/lang/Object;

    .line 624
    .line 625
    check-cast v2, Lx2/s;

    .line 626
    .line 627
    iget-object v3, v0, Lb1/h0;->j:Ljava/lang/Object;

    .line 628
    .line 629
    check-cast v3, Lc1/a0;

    .line 630
    .line 631
    iget-object v4, v0, Lb1/h0;->k:Ljava/lang/Object;

    .line 632
    .line 633
    check-cast v4, Lay0/k;

    .line 634
    .line 635
    iget-object v5, v0, Lb1/h0;->l:Ljava/lang/Object;

    .line 636
    .line 637
    check-cast v5, Lt2/b;

    .line 638
    .line 639
    iget v0, v0, Lb1/h0;->g:I

    .line 640
    .line 641
    or-int/lit8 v0, v0, 0x1

    .line 642
    .line 643
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 644
    .line 645
    .line 646
    move-result v7

    .line 647
    invoke-static/range {v1 .. v7}, Ljp/w1;->a(Lc1/w1;Lx2/s;Lc1/a0;Lay0/k;Lt2/b;Ll2/o;I)V

    .line 648
    .line 649
    .line 650
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 651
    .line 652
    return-object v0

    .line 653
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
