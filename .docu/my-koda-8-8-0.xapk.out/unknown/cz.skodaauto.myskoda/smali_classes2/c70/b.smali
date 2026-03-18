.class public final Lc70/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lc70/e;


# direct methods
.method public synthetic constructor <init>(Lc70/e;I)V
    .locals 0

    .line 1
    iput p2, p0, Lc70/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lc70/b;->e:Lc70/e;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public b(Lne0/s;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 30

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    instance-of v2, v1, Lc70/a;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lc70/a;

    .line 11
    .line 12
    iget v3, v2, Lc70/a;->h:I

    .line 13
    .line 14
    const/high16 v4, -0x80000000

    .line 15
    .line 16
    and-int v5, v3, v4

    .line 17
    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    sub-int/2addr v3, v4

    .line 21
    iput v3, v2, Lc70/a;->h:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lc70/a;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Lc70/a;-><init>(Lc70/b;Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Lc70/a;->f:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lc70/a;->h:I

    .line 34
    .line 35
    const/4 v5, 0x1

    .line 36
    if-eqz v4, :cond_2

    .line 37
    .line 38
    if-ne v4, v5, :cond_1

    .line 39
    .line 40
    iget-object v0, v2, Lc70/a;->e:Lne0/s;

    .line 41
    .line 42
    iget-object v2, v2, Lc70/a;->d:Lc70/e;

    .line 43
    .line 44
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw v0

    .line 56
    :cond_2
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    iget-object v0, v0, Lc70/b;->e:Lc70/e;

    .line 60
    .line 61
    iget-object v1, v0, Lc70/e;->k:Lcs0/l;

    .line 62
    .line 63
    iput-object v0, v2, Lc70/a;->d:Lc70/e;

    .line 64
    .line 65
    move-object/from16 v4, p1

    .line 66
    .line 67
    iput-object v4, v2, Lc70/a;->e:Lne0/s;

    .line 68
    .line 69
    iput v5, v2, Lc70/a;->h:I

    .line 70
    .line 71
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 72
    .line 73
    .line 74
    invoke-virtual {v1, v2}, Lcs0/l;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v1

    .line 78
    if-ne v1, v3, :cond_3

    .line 79
    .line 80
    return-object v3

    .line 81
    :cond_3
    move-object v2, v0

    .line 82
    move-object v0, v4

    .line 83
    :goto_1
    check-cast v1, Lqr0/s;

    .line 84
    .line 85
    iget-object v3, v2, Lc70/e;->m:Lij0/a;

    .line 86
    .line 87
    instance-of v4, v0, Lne0/e;

    .line 88
    .line 89
    const v6, 0x7f1201aa

    .line 90
    .line 91
    .line 92
    const/4 v7, 0x0

    .line 93
    if-eqz v4, :cond_f

    .line 94
    .line 95
    check-cast v0, Lne0/e;

    .line 96
    .line 97
    iget-object v0, v0, Lne0/e;->a:Ljava/lang/Object;

    .line 98
    .line 99
    check-cast v0, Lfp0/e;

    .line 100
    .line 101
    iget-object v4, v0, Lfp0/e;->c:Lfp0/b;

    .line 102
    .line 103
    iget-object v8, v0, Lfp0/e;->d:Lfp0/b;

    .line 104
    .line 105
    iget-object v9, v4, Lfp0/b;->c:Ljava/lang/Integer;

    .line 106
    .line 107
    if-eqz v9, :cond_4

    .line 108
    .line 109
    invoke-virtual {v9}, Ljava/lang/Integer;->intValue()I

    .line 110
    .line 111
    .line 112
    move-result v9

    .line 113
    int-to-float v9, v9

    .line 114
    goto :goto_2

    .line 115
    :cond_4
    const/4 v9, 0x0

    .line 116
    :goto_2
    if-eqz v8, :cond_5

    .line 117
    .line 118
    iget-object v11, v8, Lfp0/b;->c:Ljava/lang/Integer;

    .line 119
    .line 120
    if-eqz v11, :cond_5

    .line 121
    .line 122
    invoke-virtual {v11}, Ljava/lang/Integer;->intValue()I

    .line 123
    .line 124
    .line 125
    move-result v11

    .line 126
    int-to-float v11, v11

    .line 127
    invoke-static {v11}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 128
    .line 129
    .line 130
    move-result-object v11

    .line 131
    goto :goto_3

    .line 132
    :cond_5
    const/4 v11, 0x0

    .line 133
    :goto_3
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 134
    .line 135
    .line 136
    move-result-object v12

    .line 137
    move-object v13, v12

    .line 138
    check-cast v13, Lc70/d;

    .line 139
    .line 140
    if-eqz v8, :cond_6

    .line 141
    .line 142
    const v12, 0x7f120482

    .line 143
    .line 144
    .line 145
    goto :goto_4

    .line 146
    :cond_6
    const v12, 0x7f1204a9

    .line 147
    .line 148
    .line 149
    :goto_4
    new-array v14, v7, [Ljava/lang/Object;

    .line 150
    .line 151
    check-cast v3, Ljj0/f;

    .line 152
    .line 153
    invoke-virtual {v3, v12, v14}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 154
    .line 155
    .line 156
    move-result-object v15

    .line 157
    iget-object v12, v0, Lfp0/e;->e:Lqr0/d;

    .line 158
    .line 159
    move-object/from16 p1, v11

    .line 160
    .line 161
    if-eqz v12, :cond_8

    .line 162
    .line 163
    iget-wide v10, v12, Lqr0/d;->a:D

    .line 164
    .line 165
    sget-object v12, Lqr0/e;->d:Lqr0/e;

    .line 166
    .line 167
    invoke-static {v10, v11, v1, v12}, Lkp/f6;->a(DLqr0/s;Lqr0/e;)Ljava/lang/String;

    .line 168
    .line 169
    .line 170
    move-result-object v1

    .line 171
    if-nez v1, :cond_7

    .line 172
    .line 173
    goto :goto_6

    .line 174
    :cond_7
    :goto_5
    move-object/from16 v16, v1

    .line 175
    .line 176
    goto :goto_7

    .line 177
    :cond_8
    :goto_6
    new-array v1, v7, [Ljava/lang/Object;

    .line 178
    .line 179
    invoke-virtual {v3, v6, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 180
    .line 181
    .line 182
    move-result-object v1

    .line 183
    goto :goto_5

    .line 184
    :goto_7
    iget-boolean v1, v0, Lfp0/e;->g:Z

    .line 185
    .line 186
    if-eqz v1, :cond_9

    .line 187
    .line 188
    invoke-static {v0}, Ljp/fd;->e(Lfp0/e;)Z

    .line 189
    .line 190
    .line 191
    move-result v1

    .line 192
    if-eqz v1, :cond_9

    .line 193
    .line 194
    const v1, 0x7f1204a8

    .line 195
    .line 196
    .line 197
    new-array v6, v7, [Ljava/lang/Object;

    .line 198
    .line 199
    invoke-virtual {v3, v1, v6}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 200
    .line 201
    .line 202
    move-result-object v1

    .line 203
    :goto_8
    move-object/from16 v17, v1

    .line 204
    .line 205
    goto :goto_9

    .line 206
    :cond_9
    const-string v1, ""

    .line 207
    .line 208
    goto :goto_8

    .line 209
    :goto_9
    iget-boolean v1, v0, Lfp0/e;->h:Z

    .line 210
    .line 211
    if-eqz v1, :cond_a

    .line 212
    .line 213
    invoke-static {v0}, Ljp/fd;->e(Lfp0/e;)Z

    .line 214
    .line 215
    .line 216
    move-result v0

    .line 217
    if-eqz v0, :cond_a

    .line 218
    .line 219
    move/from16 v18, v5

    .line 220
    .line 221
    goto :goto_a

    .line 222
    :cond_a
    move/from16 v18, v7

    .line 223
    .line 224
    :goto_a
    sget-object v14, Llf0/i;->j:Llf0/i;

    .line 225
    .line 226
    iget-object v0, v4, Lfp0/b;->a:Lfp0/c;

    .line 227
    .line 228
    invoke-static {v0}, Ljp/fd;->j(Lfp0/c;)Lvf0/k;

    .line 229
    .line 230
    .line 231
    move-result-object v23

    .line 232
    if-eqz v8, :cond_b

    .line 233
    .line 234
    iget-object v0, v8, Lfp0/b;->a:Lfp0/c;

    .line 235
    .line 236
    if-eqz v0, :cond_b

    .line 237
    .line 238
    invoke-static {v0}, Ljp/fd;->j(Lfp0/c;)Lvf0/k;

    .line 239
    .line 240
    .line 241
    move-result-object v0

    .line 242
    move-object/from16 v24, v0

    .line 243
    .line 244
    goto :goto_b

    .line 245
    :cond_b
    const/16 v24, 0x0

    .line 246
    .line 247
    :goto_b
    if-eqz v8, :cond_c

    .line 248
    .line 249
    iget-object v0, v8, Lfp0/b;->a:Lfp0/c;

    .line 250
    .line 251
    sget-object v1, Lfp0/c;->f:Lfp0/c;

    .line 252
    .line 253
    if-eq v0, v1, :cond_c

    .line 254
    .line 255
    move/from16 v22, v5

    .line 256
    .line 257
    goto :goto_c

    .line 258
    :cond_c
    move/from16 v22, v7

    .line 259
    .line 260
    :goto_c
    const/16 v0, 0x64

    .line 261
    .line 262
    int-to-float v0, v0

    .line 263
    div-float v25, v9, v0

    .line 264
    .line 265
    if-eqz p1, :cond_d

    .line 266
    .line 267
    invoke-virtual/range {p1 .. p1}, Ljava/lang/Float;->floatValue()F

    .line 268
    .line 269
    .line 270
    move-result v1

    .line 271
    div-float/2addr v1, v0

    .line 272
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 273
    .line 274
    .line 275
    move-result-object v10

    .line 276
    move-object/from16 v26, v10

    .line 277
    .line 278
    goto :goto_d

    .line 279
    :cond_d
    const/16 v26, 0x0

    .line 280
    .line 281
    :goto_d
    iget-object v0, v4, Lfp0/b;->e:Lfp0/f;

    .line 282
    .line 283
    invoke-static {v0}, Ljp/fd;->l(Lfp0/f;)Lvf0/l;

    .line 284
    .line 285
    .line 286
    move-result-object v27

    .line 287
    if-eqz v8, :cond_e

    .line 288
    .line 289
    iget-object v0, v8, Lfp0/b;->e:Lfp0/f;

    .line 290
    .line 291
    if-eqz v0, :cond_e

    .line 292
    .line 293
    invoke-static {v0}, Ljp/fd;->l(Lfp0/f;)Lvf0/l;

    .line 294
    .line 295
    .line 296
    move-result-object v0

    .line 297
    :goto_e
    move-object/from16 v28, v0

    .line 298
    .line 299
    goto :goto_f

    .line 300
    :cond_e
    sget-object v0, Lvf0/l;->d:Lvf0/l;

    .line 301
    .line 302
    goto :goto_e

    .line 303
    :goto_f
    const/16 v21, 0x0

    .line 304
    .line 305
    const/16 v29, 0xc0

    .line 306
    .line 307
    const/16 v19, 0x0

    .line 308
    .line 309
    const/16 v20, 0x0

    .line 310
    .line 311
    invoke-static/range {v13 .. v29}, Lc70/d;->a(Lc70/d;Llf0/i;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZZLvf0/k;Lvf0/k;FLjava/lang/Float;Lvf0/l;Lvf0/l;I)Lc70/d;

    .line 312
    .line 313
    .line 314
    move-result-object v0

    .line 315
    goto :goto_10

    .line 316
    :cond_f
    instance-of v1, v0, Lne0/c;

    .line 317
    .line 318
    if-eqz v1, :cond_11

    .line 319
    .line 320
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 321
    .line 322
    .line 323
    move-result-object v0

    .line 324
    check-cast v0, Lc70/d;

    .line 325
    .line 326
    iget-boolean v0, v0, Lc70/d;->f:Z

    .line 327
    .line 328
    if-eqz v0, :cond_10

    .line 329
    .line 330
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 331
    .line 332
    .line 333
    move-result-object v0

    .line 334
    move-object v8, v0

    .line 335
    check-cast v8, Lc70/d;

    .line 336
    .line 337
    new-array v0, v7, [Ljava/lang/Object;

    .line 338
    .line 339
    check-cast v3, Ljj0/f;

    .line 340
    .line 341
    invoke-virtual {v3, v6, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 342
    .line 343
    .line 344
    move-result-object v11

    .line 345
    sget-object v9, Llf0/i;->j:Llf0/i;

    .line 346
    .line 347
    const/16 v23, 0x0

    .line 348
    .line 349
    const/16 v24, 0x7fd2

    .line 350
    .line 351
    const/4 v10, 0x0

    .line 352
    const-string v12, ""

    .line 353
    .line 354
    const/4 v13, 0x0

    .line 355
    const/4 v14, 0x0

    .line 356
    const/4 v15, 0x0

    .line 357
    const/16 v16, 0x0

    .line 358
    .line 359
    const/16 v17, 0x0

    .line 360
    .line 361
    const/16 v18, 0x0

    .line 362
    .line 363
    const/16 v19, 0x0

    .line 364
    .line 365
    const/16 v20, 0x0

    .line 366
    .line 367
    const/16 v21, 0x0

    .line 368
    .line 369
    const/16 v22, 0x0

    .line 370
    .line 371
    invoke-static/range {v8 .. v24}, Lc70/d;->a(Lc70/d;Llf0/i;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZZLvf0/k;Lvf0/k;FLjava/lang/Float;Lvf0/l;Lvf0/l;I)Lc70/d;

    .line 372
    .line 373
    .line 374
    move-result-object v0

    .line 375
    goto :goto_10

    .line 376
    :cond_10
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 377
    .line 378
    .line 379
    move-result-object v0

    .line 380
    check-cast v0, Lc70/d;

    .line 381
    .line 382
    goto :goto_10

    .line 383
    :cond_11
    sget-object v1, Lne0/d;->a:Lne0/d;

    .line 384
    .line 385
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 386
    .line 387
    .line 388
    move-result v0

    .line 389
    if-eqz v0, :cond_12

    .line 390
    .line 391
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 392
    .line 393
    .line 394
    move-result-object v0

    .line 395
    move-object v3, v0

    .line 396
    check-cast v3, Lc70/d;

    .line 397
    .line 398
    sget-object v4, Llf0/i;->j:Llf0/i;

    .line 399
    .line 400
    const/16 v18, 0x0

    .line 401
    .line 402
    const/16 v19, 0x7fde

    .line 403
    .line 404
    const/4 v5, 0x0

    .line 405
    const/4 v6, 0x0

    .line 406
    const/4 v7, 0x0

    .line 407
    const/4 v8, 0x0

    .line 408
    const/4 v9, 0x1

    .line 409
    const/4 v10, 0x0

    .line 410
    const/4 v11, 0x0

    .line 411
    const/4 v12, 0x0

    .line 412
    const/4 v13, 0x0

    .line 413
    const/4 v14, 0x0

    .line 414
    const/4 v15, 0x0

    .line 415
    const/16 v16, 0x0

    .line 416
    .line 417
    const/16 v17, 0x0

    .line 418
    .line 419
    invoke-static/range {v3 .. v19}, Lc70/d;->a(Lc70/d;Llf0/i;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZZLvf0/k;Lvf0/k;FLjava/lang/Float;Lvf0/l;Lvf0/l;I)Lc70/d;

    .line 420
    .line 421
    .line 422
    move-result-object v0

    .line 423
    :goto_10
    invoke-virtual {v2, v0}, Lql0/j;->g(Lql0/h;)V

    .line 424
    .line 425
    .line 426
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 427
    .line 428
    return-object v0

    .line 429
    :cond_12
    new-instance v0, La8/r0;

    .line 430
    .line 431
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 432
    .line 433
    .line 434
    throw v0
.end method

.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lc70/b;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Ljava/lang/Boolean;

    .line 11
    .line 12
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 13
    .line 14
    .line 15
    move-result v10

    .line 16
    iget-object v0, v0, Lc70/b;->e:Lc70/e;

    .line 17
    .line 18
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    move-object v2, v1

    .line 23
    check-cast v2, Lc70/d;

    .line 24
    .line 25
    const/16 v17, 0x0

    .line 26
    .line 27
    const/16 v18, 0x7f7f

    .line 28
    .line 29
    const/4 v3, 0x0

    .line 30
    const/4 v4, 0x0

    .line 31
    const/4 v5, 0x0

    .line 32
    const/4 v6, 0x0

    .line 33
    const/4 v7, 0x0

    .line 34
    const/4 v8, 0x0

    .line 35
    const/4 v9, 0x0

    .line 36
    const/4 v11, 0x0

    .line 37
    const/4 v12, 0x0

    .line 38
    const/4 v13, 0x0

    .line 39
    const/4 v14, 0x0

    .line 40
    const/4 v15, 0x0

    .line 41
    const/16 v16, 0x0

    .line 42
    .line 43
    invoke-static/range {v2 .. v18}, Lc70/d;->a(Lc70/d;Llf0/i;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZZLvf0/k;Lvf0/k;FLjava/lang/Float;Lvf0/l;Lvf0/l;I)Lc70/d;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 48
    .line 49
    .line 50
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    return-object v0

    .line 53
    :pswitch_0
    move-object/from16 v1, p1

    .line 54
    .line 55
    check-cast v1, Lss0/j0;

    .line 56
    .line 57
    new-instance v1, Lc70/d;

    .line 58
    .line 59
    iget-object v0, v0, Lc70/b;->e:Lc70/e;

    .line 60
    .line 61
    iget-object v2, v0, Lc70/e;->m:Lij0/a;

    .line 62
    .line 63
    const/4 v3, 0x0

    .line 64
    new-array v3, v3, [Ljava/lang/Object;

    .line 65
    .line 66
    check-cast v2, Ljj0/f;

    .line 67
    .line 68
    const v4, 0x7f1204a9

    .line 69
    .line 70
    .line 71
    invoke-virtual {v2, v4, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v2

    .line 75
    const/16 v3, 0x7ffd

    .line 76
    .line 77
    const/4 v4, 0x0

    .line 78
    invoke-direct {v1, v3, v2, v4}, Lc70/d;-><init>(ILjava/lang/String;Llf0/i;)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 82
    .line 83
    .line 84
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 85
    .line 86
    return-object v0

    .line 87
    :pswitch_1
    move-object/from16 v1, p1

    .line 88
    .line 89
    check-cast v1, Lne0/s;

    .line 90
    .line 91
    move-object/from16 v2, p2

    .line 92
    .line 93
    invoke-virtual {v0, v1, v2}, Lc70/b;->b(Lne0/s;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    return-object v0

    .line 98
    nop

    .line 99
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
