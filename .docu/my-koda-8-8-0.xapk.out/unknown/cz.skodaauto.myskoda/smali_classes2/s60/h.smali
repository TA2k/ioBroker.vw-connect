.class public final synthetic Ls60/h;
.super Lkotlin/jvm/internal/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V
    .locals 1

    .line 1
    iput p7, p0, Ls60/h;->d:I

    .line 2
    .line 3
    move-object v0, p4

    .line 4
    move-object p4, p2

    .line 5
    move p2, p6

    .line 6
    move-object p6, p5

    .line 7
    move-object p5, v0

    .line 8
    invoke-direct/range {p0 .. p6}, Lkotlin/jvm/internal/j;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 30

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ls60/h;->d:I

    .line 4
    .line 5
    const/4 v2, 0x4

    .line 6
    const/4 v3, 0x2

    .line 7
    const/4 v5, 0x1

    .line 8
    const/4 v6, 0x3

    .line 9
    const/4 v7, 0x0

    .line 10
    const-string v8, "p0"

    .line 11
    .line 12
    sget-object v9, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    packed-switch v1, :pswitch_data_0

    .line 15
    .line 16
    .line 17
    move-object/from16 v1, p1

    .line 18
    .line 19
    check-cast v1, Ljava/lang/Number;

    .line 20
    .line 21
    invoke-virtual {v1}, Ljava/lang/Number;->longValue()J

    .line 22
    .line 23
    .line 24
    move-result-wide v1

    .line 25
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast v0, Ls10/l;

    .line 28
    .line 29
    iget-object v3, v0, Ls10/l;->n:Ljava/util/List;

    .line 30
    .line 31
    check-cast v3, Ljava/lang/Iterable;

    .line 32
    .line 33
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object v3

    .line 37
    :cond_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result v4

    .line 41
    if-eqz v4, :cond_1

    .line 42
    .line 43
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v4

    .line 47
    move-object v5, v4

    .line 48
    check-cast v5, Lr10/b;

    .line 49
    .line 50
    iget-object v5, v5, Lr10/b;->g:Lao0/c;

    .line 51
    .line 52
    iget-wide v5, v5, Lao0/c;->a:J

    .line 53
    .line 54
    cmp-long v5, v5, v1

    .line 55
    .line 56
    if-nez v5, :cond_0

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_1
    move-object v4, v7

    .line 60
    :goto_0
    check-cast v4, Lr10/b;

    .line 61
    .line 62
    if-eqz v4, :cond_2

    .line 63
    .line 64
    iget-object v0, v0, Ls10/l;->h:Lq10/u;

    .line 65
    .line 66
    iget-object v1, v0, Lq10/u;->b:Lq10/f;

    .line 67
    .line 68
    check-cast v1, Lo10/t;

    .line 69
    .line 70
    iget-object v1, v1, Lo10/t;->i:Lyy0/c2;

    .line 71
    .line 72
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 73
    .line 74
    .line 75
    invoke-virtual {v1, v7, v4}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    iget-object v0, v0, Lq10/u;->a:Lq10/a;

    .line 79
    .line 80
    check-cast v0, Liy/b;

    .line 81
    .line 82
    sget-object v1, Lly/b;->X:Lly/b;

    .line 83
    .line 84
    invoke-interface {v0, v1}, Ltl0/a;->a(Lul0/f;)V

    .line 85
    .line 86
    .line 87
    :cond_2
    return-object v9

    .line 88
    :pswitch_0
    move-object/from16 v15, p1

    .line 89
    .line 90
    check-cast v15, Ls10/o;

    .line 91
    .line 92
    invoke-static {v15, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 96
    .line 97
    check-cast v0, Ls10/s;

    .line 98
    .line 99
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 100
    .line 101
    .line 102
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 103
    .line 104
    .line 105
    move-result-object v1

    .line 106
    move-object v10, v1

    .line 107
    check-cast v10, Ls10/q;

    .line 108
    .line 109
    const/16 v16, 0x0

    .line 110
    .line 111
    const/16 v17, 0x2f

    .line 112
    .line 113
    const/4 v11, 0x0

    .line 114
    const/4 v12, 0x0

    .line 115
    const/4 v13, 0x0

    .line 116
    const/4 v14, 0x0

    .line 117
    invoke-static/range {v10 .. v17}, Ls10/q;->a(Ls10/q;Ler0/g;Llf0/i;ZZLs10/o;Ls10/p;I)Ls10/q;

    .line 118
    .line 119
    .line 120
    move-result-object v1

    .line 121
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 122
    .line 123
    .line 124
    return-object v9

    .line 125
    :pswitch_1
    move-object/from16 v1, p1

    .line 126
    .line 127
    check-cast v1, Ljava/lang/Number;

    .line 128
    .line 129
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 130
    .line 131
    .line 132
    move-result v15

    .line 133
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 134
    .line 135
    check-cast v0, Ls10/e;

    .line 136
    .line 137
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 138
    .line 139
    .line 140
    move-result-object v1

    .line 141
    move-object v10, v1

    .line 142
    check-cast v10, Ls10/b;

    .line 143
    .line 144
    const/16 v17, 0x0

    .line 145
    .line 146
    const/16 v18, 0xef

    .line 147
    .line 148
    const/4 v11, 0x0

    .line 149
    const/4 v12, 0x0

    .line 150
    const/4 v13, 0x0

    .line 151
    const/4 v14, 0x0

    .line 152
    const/16 v16, 0x0

    .line 153
    .line 154
    invoke-static/range {v10 .. v18}, Ls10/b;->a(Ls10/b;Lql0/g;Ljava/lang/String;ILjava/lang/String;IZZI)Ls10/b;

    .line 155
    .line 156
    .line 157
    move-result-object v1

    .line 158
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 159
    .line 160
    .line 161
    return-object v9

    .line 162
    :pswitch_2
    move-object/from16 v1, p1

    .line 163
    .line 164
    check-cast v1, Ln3/b;

    .line 165
    .line 166
    iget-object v1, v1, Ln3/b;->a:Landroid/view/KeyEvent;

    .line 167
    .line 168
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 169
    .line 170
    check-cast v0, Lt1/a1;

    .line 171
    .line 172
    iget-object v6, v0, Lt1/a1;->f:Le2/c1;

    .line 173
    .line 174
    iget-boolean v8, v0, Lt1/a1;->d:Z

    .line 175
    .line 176
    invoke-virtual {v1}, Landroid/view/KeyEvent;->getAction()I

    .line 177
    .line 178
    .line 179
    move-result v9

    .line 180
    if-nez v9, :cond_7

    .line 181
    .line 182
    invoke-virtual {v1}, Landroid/view/KeyEvent;->getUnicodeChar()I

    .line 183
    .line 184
    .line 185
    move-result v9

    .line 186
    invoke-static {v9}, Ljava/lang/Character;->isISOControl(I)Z

    .line 187
    .line 188
    .line 189
    move-result v9

    .line 190
    if-nez v9, :cond_7

    .line 191
    .line 192
    iget-object v9, v0, Lt1/a1;->i:Lt1/a0;

    .line 193
    .line 194
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 195
    .line 196
    .line 197
    invoke-virtual {v1}, Landroid/view/KeyEvent;->getUnicodeChar()I

    .line 198
    .line 199
    .line 200
    move-result v10

    .line 201
    const/high16 v11, -0x80000000

    .line 202
    .line 203
    and-int/2addr v11, v10

    .line 204
    if-eqz v11, :cond_3

    .line 205
    .line 206
    const v11, 0x7fffffff

    .line 207
    .line 208
    .line 209
    and-int/2addr v10, v11

    .line 210
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 211
    .line 212
    .line 213
    move-result-object v10

    .line 214
    iput-object v10, v9, Lt1/a0;->a:Ljava/lang/Integer;

    .line 215
    .line 216
    move-object v9, v7

    .line 217
    goto :goto_1

    .line 218
    :cond_3
    iget-object v11, v9, Lt1/a0;->a:Ljava/lang/Integer;

    .line 219
    .line 220
    if-eqz v11, :cond_6

    .line 221
    .line 222
    iput-object v7, v9, Lt1/a0;->a:Ljava/lang/Integer;

    .line 223
    .line 224
    invoke-virtual {v11}, Ljava/lang/Integer;->intValue()I

    .line 225
    .line 226
    .line 227
    move-result v9

    .line 228
    invoke-static {v9, v10}, Landroid/view/KeyCharacterMap;->getDeadChar(II)I

    .line 229
    .line 230
    .line 231
    move-result v9

    .line 232
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 233
    .line 234
    .line 235
    move-result-object v11

    .line 236
    if-nez v9, :cond_4

    .line 237
    .line 238
    move-object v11, v7

    .line 239
    :cond_4
    if-eqz v11, :cond_5

    .line 240
    .line 241
    invoke-virtual {v11}, Ljava/lang/Integer;->intValue()I

    .line 242
    .line 243
    .line 244
    move-result v10

    .line 245
    :cond_5
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 246
    .line 247
    .line 248
    move-result-object v9

    .line 249
    goto :goto_1

    .line 250
    :cond_6
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 251
    .line 252
    .line 253
    move-result-object v9

    .line 254
    :goto_1
    if-eqz v9, :cond_7

    .line 255
    .line 256
    invoke-virtual {v9}, Ljava/lang/Integer;->intValue()I

    .line 257
    .line 258
    .line 259
    move-result v9

    .line 260
    new-instance v10, Ljava/lang/StringBuilder;

    .line 261
    .line 262
    invoke-direct {v10}, Ljava/lang/StringBuilder;-><init>()V

    .line 263
    .line 264
    .line 265
    invoke-virtual {v10, v9}, Ljava/lang/StringBuilder;->appendCodePoint(I)Ljava/lang/StringBuilder;

    .line 266
    .line 267
    .line 268
    move-result-object v9

    .line 269
    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 270
    .line 271
    .line 272
    move-result-object v9

    .line 273
    new-instance v10, Ll4/a;

    .line 274
    .line 275
    invoke-direct {v10, v9, v5}, Ll4/a;-><init>(Ljava/lang/String;I)V

    .line 276
    .line 277
    .line 278
    goto :goto_2

    .line 279
    :cond_7
    move-object v10, v7

    .line 280
    :goto_2
    if-eqz v10, :cond_9

    .line 281
    .line 282
    if-eqz v8, :cond_8

    .line 283
    .line 284
    invoke-static {v10}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 285
    .line 286
    .line 287
    move-result-object v1

    .line 288
    invoke-virtual {v0, v1}, Lt1/a1;->a(Ljava/util/List;)V

    .line 289
    .line 290
    .line 291
    iput-object v7, v6, Le2/c1;->a:Ljava/lang/Float;

    .line 292
    .line 293
    move v4, v5

    .line 294
    goto :goto_4

    .line 295
    :cond_8
    :goto_3
    const/4 v4, 0x0

    .line 296
    goto :goto_4

    .line 297
    :cond_9
    invoke-static {v1}, Ln3/c;->c(Landroid/view/KeyEvent;)I

    .line 298
    .line 299
    .line 300
    move-result v7

    .line 301
    if-ne v7, v3, :cond_8

    .line 302
    .line 303
    iget-object v3, v0, Lt1/a1;->j:Lt1/h0;

    .line 304
    .line 305
    invoke-virtual {v3, v1}, Lt1/h0;->a(Landroid/view/KeyEvent;)Lt1/g0;

    .line 306
    .line 307
    .line 308
    move-result-object v1

    .line 309
    if-eqz v1, :cond_8

    .line 310
    .line 311
    iget-boolean v3, v1, Lt1/g0;->d:Z

    .line 312
    .line 313
    if-eqz v3, :cond_a

    .line 314
    .line 315
    if-nez v8, :cond_a

    .line 316
    .line 317
    goto :goto_3

    .line 318
    :cond_a
    new-instance v3, Lkotlin/jvm/internal/b0;

    .line 319
    .line 320
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 321
    .line 322
    .line 323
    iput-boolean v5, v3, Lkotlin/jvm/internal/b0;->d:Z

    .line 324
    .line 325
    new-instance v4, Lkv0/e;

    .line 326
    .line 327
    const/16 v7, 0x13

    .line 328
    .line 329
    invoke-direct {v4, v1, v0, v3, v7}, Lkv0/e;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 330
    .line 331
    .line 332
    new-instance v1, Le2/m0;

    .line 333
    .line 334
    iget-object v7, v0, Lt1/a1;->c:Ll4/v;

    .line 335
    .line 336
    iget-object v8, v0, Lt1/a1;->g:Ll4/p;

    .line 337
    .line 338
    iget-object v9, v0, Lt1/a1;->a:Lt1/p0;

    .line 339
    .line 340
    invoke-virtual {v9}, Lt1/p0;->d()Lt1/j1;

    .line 341
    .line 342
    .line 343
    move-result-object v9

    .line 344
    invoke-direct {v1, v7, v8, v9, v6}, Le2/m0;-><init>(Ll4/v;Ll4/p;Lt1/j1;Le2/c1;)V

    .line 345
    .line 346
    .line 347
    invoke-virtual {v4, v1}, Lkv0/e;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 348
    .line 349
    .line 350
    iget-wide v8, v1, Le2/m0;->f:J

    .line 351
    .line 352
    iget-wide v10, v7, Ll4/v;->b:J

    .line 353
    .line 354
    invoke-static {v8, v9, v10, v11}, Lg4/o0;->b(JJ)Z

    .line 355
    .line 356
    .line 357
    move-result v4

    .line 358
    iget-object v6, v1, Le2/m0;->g:Lg4/g;

    .line 359
    .line 360
    if-eqz v4, :cond_b

    .line 361
    .line 362
    iget-object v4, v7, Ll4/v;->a:Lg4/g;

    .line 363
    .line 364
    invoke-static {v6, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 365
    .line 366
    .line 367
    move-result v4

    .line 368
    if-nez v4, :cond_c

    .line 369
    .line 370
    :cond_b
    iget-object v4, v0, Lt1/a1;->k:Lay0/k;

    .line 371
    .line 372
    iget-wide v8, v1, Le2/m0;->f:J

    .line 373
    .line 374
    invoke-static {v7, v6, v8, v9, v2}, Ll4/v;->a(Ll4/v;Lg4/g;JI)Ll4/v;

    .line 375
    .line 376
    .line 377
    move-result-object v1

    .line 378
    invoke-interface {v4, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 379
    .line 380
    .line 381
    :cond_c
    iget-object v0, v0, Lt1/a1;->h:Lt1/n1;

    .line 382
    .line 383
    if-eqz v0, :cond_d

    .line 384
    .line 385
    iput-boolean v5, v0, Lt1/n1;->e:Z

    .line 386
    .line 387
    :cond_d
    iget-boolean v4, v3, Lkotlin/jvm/internal/b0;->d:Z

    .line 388
    .line 389
    :goto_4
    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 390
    .line 391
    .line 392
    move-result-object v0

    .line 393
    return-object v0

    .line 394
    :pswitch_3
    move-object/from16 v1, p1

    .line 395
    .line 396
    check-cast v1, Ljava/lang/Number;

    .line 397
    .line 398
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 399
    .line 400
    .line 401
    move-result v1

    .line 402
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 403
    .line 404
    check-cast v0, Lrm0/c;

    .line 405
    .line 406
    invoke-virtual {v0, v1}, Lrm0/c;->h(I)V

    .line 407
    .line 408
    .line 409
    return-object v9

    .line 410
    :pswitch_4
    move-object/from16 v1, p1

    .line 411
    .line 412
    check-cast v1, Lsh/d;

    .line 413
    .line 414
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 415
    .line 416
    .line 417
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 418
    .line 419
    check-cast v0, Lsh/g;

    .line 420
    .line 421
    invoke-virtual {v0, v1}, Lsh/g;->a(Lsh/d;)V

    .line 422
    .line 423
    .line 424
    return-object v9

    .line 425
    :pswitch_5
    move-object/from16 v1, p1

    .line 426
    .line 427
    check-cast v1, Lsh/d;

    .line 428
    .line 429
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 430
    .line 431
    .line 432
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 433
    .line 434
    check-cast v0, Lsh/g;

    .line 435
    .line 436
    invoke-virtual {v0, v1}, Lsh/g;->a(Lsh/d;)V

    .line 437
    .line 438
    .line 439
    return-object v9

    .line 440
    :pswitch_6
    move-object/from16 v1, p1

    .line 441
    .line 442
    check-cast v1, Lsg/n;

    .line 443
    .line 444
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 445
    .line 446
    .line 447
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 448
    .line 449
    check-cast v0, Lsg/p;

    .line 450
    .line 451
    invoke-virtual {v0, v1}, Lsg/p;->b(Lsg/n;)V

    .line 452
    .line 453
    .line 454
    return-object v9

    .line 455
    :pswitch_7
    move-object/from16 v1, p1

    .line 456
    .line 457
    check-cast v1, Lkg/p0;

    .line 458
    .line 459
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 460
    .line 461
    .line 462
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 463
    .line 464
    check-cast v0, Lsg/e;

    .line 465
    .line 466
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 467
    .line 468
    .line 469
    iget-object v2, v0, Lsg/e;->b:Lxh/e;

    .line 470
    .line 471
    new-instance v3, Lsg/q;

    .line 472
    .line 473
    iget-object v4, v0, Lsg/e;->d:Ljava/util/List;

    .line 474
    .line 475
    if-eqz v4, :cond_10

    .line 476
    .line 477
    iget-object v5, v0, Lsg/e;->e:Lnc/z;

    .line 478
    .line 479
    if-eqz v5, :cond_f

    .line 480
    .line 481
    iget-object v0, v0, Lsg/e;->f:Ljava/lang/String;

    .line 482
    .line 483
    if-eqz v0, :cond_e

    .line 484
    .line 485
    invoke-direct {v3, v1, v4, v5, v0}, Lsg/q;-><init>(Lkg/p0;Ljava/util/List;Lnc/z;Ljava/lang/String;)V

    .line 486
    .line 487
    .line 488
    invoke-virtual {v2, v3}, Lxh/e;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 489
    .line 490
    .line 491
    return-object v9

    .line 492
    :cond_e
    const-string v0, "formattedFollowUpStartDate"

    .line 493
    .line 494
    invoke-static {v0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 495
    .line 496
    .line 497
    throw v7

    .line 498
    :cond_f
    const-string v0, "paymentOption"

    .line 499
    .line 500
    invoke-static {v0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 501
    .line 502
    .line 503
    throw v7

    .line 504
    :cond_10
    const-string v0, "documents"

    .line 505
    .line 506
    invoke-static {v0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 507
    .line 508
    .line 509
    throw v7

    .line 510
    :pswitch_8
    move-object/from16 v1, p1

    .line 511
    .line 512
    check-cast v1, Lkotlin/coroutines/Continuation;

    .line 513
    .line 514
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 515
    .line 516
    check-cast v0, Lsg/e;

    .line 517
    .line 518
    invoke-virtual {v0, v1}, Lsg/e;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 519
    .line 520
    .line 521
    move-result-object v0

    .line 522
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 523
    .line 524
    if-ne v0, v1, :cond_11

    .line 525
    .line 526
    goto :goto_5

    .line 527
    :cond_11
    new-instance v1, Llx0/o;

    .line 528
    .line 529
    invoke-direct {v1, v0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 530
    .line 531
    .line 532
    move-object v0, v1

    .line 533
    :goto_5
    return-object v0

    .line 534
    :pswitch_9
    move-object/from16 v2, p1

    .line 535
    .line 536
    check-cast v2, Lkg/p0;

    .line 537
    .line 538
    invoke-static {v2, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 539
    .line 540
    .line 541
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 542
    .line 543
    check-cast v0, Lsg/b;

    .line 544
    .line 545
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 546
    .line 547
    .line 548
    iget-object v8, v0, Lsg/b;->c:Lxh/e;

    .line 549
    .line 550
    new-instance v1, Lsg/i;

    .line 551
    .line 552
    iget-object v3, v0, Lsg/b;->d:Ljava/util/List;

    .line 553
    .line 554
    if-eqz v3, :cond_14

    .line 555
    .line 556
    iget-boolean v4, v0, Lsg/b;->e:Z

    .line 557
    .line 558
    iget-object v5, v0, Lsg/b;->f:Ljava/util/List;

    .line 559
    .line 560
    if-eqz v5, :cond_13

    .line 561
    .line 562
    iget-object v6, v0, Lsg/b;->g:Lac/a0;

    .line 563
    .line 564
    if-eqz v6, :cond_12

    .line 565
    .line 566
    iget-object v7, v0, Lsg/b;->h:Lnc/z;

    .line 567
    .line 568
    invoke-direct/range {v1 .. v7}, Lsg/i;-><init>(Lkg/p0;Ljava/util/List;ZLjava/util/List;Lac/a0;Lnc/z;)V

    .line 569
    .line 570
    .line 571
    invoke-virtual {v8, v1}, Lxh/e;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 572
    .line 573
    .line 574
    return-object v9

    .line 575
    :cond_12
    const-string v0, "userLegalCountry"

    .line 576
    .line 577
    invoke-static {v0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 578
    .line 579
    .line 580
    throw v7

    .line 581
    :cond_13
    const-string v0, "availableShippingCountries"

    .line 582
    .line 583
    invoke-static {v0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 584
    .line 585
    .line 586
    throw v7

    .line 587
    :cond_14
    const-string v0, "legalTexts"

    .line 588
    .line 589
    invoke-static {v0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 590
    .line 591
    .line 592
    throw v7

    .line 593
    :pswitch_a
    move-object/from16 v1, p1

    .line 594
    .line 595
    check-cast v1, Lkotlin/coroutines/Continuation;

    .line 596
    .line 597
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 598
    .line 599
    check-cast v0, Lsg/b;

    .line 600
    .line 601
    invoke-virtual {v0, v1}, Lsg/b;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 602
    .line 603
    .line 604
    move-result-object v0

    .line 605
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 606
    .line 607
    if-ne v0, v1, :cond_15

    .line 608
    .line 609
    goto :goto_6

    .line 610
    :cond_15
    new-instance v1, Llx0/o;

    .line 611
    .line 612
    invoke-direct {v1, v0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 613
    .line 614
    .line 615
    move-object v0, v1

    .line 616
    :goto_6
    return-object v0

    .line 617
    :pswitch_b
    move-object/from16 v1, p1

    .line 618
    .line 619
    check-cast v1, Lsg/n;

    .line 620
    .line 621
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 622
    .line 623
    .line 624
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 625
    .line 626
    check-cast v0, Lsg/p;

    .line 627
    .line 628
    invoke-virtual {v0, v1}, Lsg/p;->b(Lsg/n;)V

    .line 629
    .line 630
    .line 631
    return-object v9

    .line 632
    :pswitch_c
    move-object/from16 v1, p1

    .line 633
    .line 634
    check-cast v1, Lsf/e;

    .line 635
    .line 636
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 637
    .line 638
    .line 639
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 640
    .line 641
    check-cast v0, Lsf/f;

    .line 642
    .line 643
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 644
    .line 645
    .line 646
    sget-object v2, Lsf/d;->b:Lsf/d;

    .line 647
    .line 648
    invoke-virtual {v1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 649
    .line 650
    .line 651
    move-result v2

    .line 652
    if-eqz v2, :cond_16

    .line 653
    .line 654
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 655
    .line 656
    .line 657
    move-result-object v1

    .line 658
    new-instance v2, Lrp0/a;

    .line 659
    .line 660
    const/16 v3, 0x8

    .line 661
    .line 662
    invoke-direct {v2, v0, v7, v3}, Lrp0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 663
    .line 664
    .line 665
    invoke-static {v1, v7, v7, v2, v6}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 666
    .line 667
    .line 668
    goto :goto_7

    .line 669
    :cond_16
    sget-object v2, Lsf/d;->a:Lsf/d;

    .line 670
    .line 671
    invoke-virtual {v1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 672
    .line 673
    .line 674
    move-result v2

    .line 675
    if-eqz v2, :cond_17

    .line 676
    .line 677
    iget-object v0, v0, Lsf/f;->e:Lyj/b;

    .line 678
    .line 679
    invoke-virtual {v0}, Lyj/b;->invoke()Ljava/lang/Object;

    .line 680
    .line 681
    .line 682
    goto :goto_7

    .line 683
    :cond_17
    sget-object v2, Lsf/d;->c:Lsf/d;

    .line 684
    .line 685
    invoke-virtual {v1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 686
    .line 687
    .line 688
    move-result v1

    .line 689
    if-eqz v1, :cond_18

    .line 690
    .line 691
    iget-object v0, v0, Lsf/f;->g:Lyy0/c2;

    .line 692
    .line 693
    new-instance v1, Llc/q;

    .line 694
    .line 695
    invoke-direct {v1, v9}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 696
    .line 697
    .line 698
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 699
    .line 700
    .line 701
    invoke-virtual {v0, v7, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 702
    .line 703
    .line 704
    :goto_7
    return-object v9

    .line 705
    :cond_18
    new-instance v0, La8/r0;

    .line 706
    .line 707
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 708
    .line 709
    .line 710
    throw v0

    .line 711
    :pswitch_d
    move-object/from16 v1, p1

    .line 712
    .line 713
    check-cast v1, Lse/e;

    .line 714
    .line 715
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 716
    .line 717
    .line 718
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 719
    .line 720
    check-cast v0, Lse/g;

    .line 721
    .line 722
    invoke-virtual {v0, v1}, Lse/g;->a(Lse/e;)V

    .line 723
    .line 724
    .line 725
    return-object v9

    .line 726
    :pswitch_e
    move-object/from16 v1, p1

    .line 727
    .line 728
    check-cast v1, Lsd/c;

    .line 729
    .line 730
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 731
    .line 732
    .line 733
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 734
    .line 735
    check-cast v0, Lsd/e;

    .line 736
    .line 737
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 738
    .line 739
    .line 740
    instance-of v2, v1, Lsd/c;

    .line 741
    .line 742
    if-eqz v2, :cond_19

    .line 743
    .line 744
    iget-object v0, v0, Lsd/e;->d:Lzb/s0;

    .line 745
    .line 746
    iget-object v1, v1, Lsd/c;->a:Ljava/lang/String;

    .line 747
    .line 748
    invoke-virtual {v0, v1}, Lzb/s0;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 749
    .line 750
    .line 751
    return-object v9

    .line 752
    :cond_19
    new-instance v0, La8/r0;

    .line 753
    .line 754
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 755
    .line 756
    .line 757
    throw v0

    .line 758
    :pswitch_f
    move-object/from16 v1, p1

    .line 759
    .line 760
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 761
    .line 762
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 763
    .line 764
    .line 765
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 766
    .line 767
    check-cast v0, Ls81/b;

    .line 768
    .line 769
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 770
    .line 771
    .line 772
    instance-of v8, v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 773
    .line 774
    if-eqz v8, :cond_1a

    .line 775
    .line 776
    move-object v8, v1

    .line 777
    check-cast v8, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 778
    .line 779
    invoke-static {v8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/util/StateMachineMessageSentInputExtensionsKt;->getUserAction(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;)Ls71/q;

    .line 780
    .line 781
    .line 782
    move-result-object v8

    .line 783
    sget-object v9, Ls71/p;->e:Ls71/p;

    .line 784
    .line 785
    if-ne v8, v9, :cond_1a

    .line 786
    .line 787
    iput-boolean v5, v0, Ls81/b;->b:Z

    .line 788
    .line 789
    :cond_1a
    instance-of v8, v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 790
    .line 791
    if-eqz v8, :cond_1b

    .line 792
    .line 793
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 794
    .line 795
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;->getData()Ljava/lang/Object;

    .line 796
    .line 797
    .line 798
    move-result-object v8

    .line 799
    instance-of v8, v8, Lu81/a;

    .line 800
    .line 801
    if-nez v8, :cond_1c

    .line 802
    .line 803
    :cond_1b
    move-object v4, v7

    .line 804
    goto/16 :goto_26

    .line 805
    .line 806
    :cond_1c
    invoke-static {v1}, Lps/t1;->e(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 807
    .line 808
    .line 809
    move-result-object v8

    .line 810
    sget-object v9, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;->ABORTED_RESUMING_NOT_POSSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 811
    .line 812
    if-ne v8, v9, :cond_1d

    .line 813
    .line 814
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->getStateCallback$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;

    .line 815
    .line 816
    .line 817
    move-result-object v8

    .line 818
    sget-object v10, Ls71/m;->i:Ls71/m;

    .line 819
    .line 820
    invoke-interface {v8, v10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;->onSideEffect(Ljava/lang/Object;)V

    .line 821
    .line 822
    .line 823
    :cond_1d
    iget-boolean v8, v0, Ls81/b;->b:Z

    .line 824
    .line 825
    invoke-static {v1}, Lps/t1;->g(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

    .line 826
    .line 827
    .line 828
    move-result-object v10

    .line 829
    invoke-static {v1}, Lps/t1;->h(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;

    .line 830
    .line 831
    .line 832
    move-result-object v11

    .line 833
    invoke-static {v1}, Lps/t1;->i(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;

    .line 834
    .line 835
    .line 836
    move-result-object v12

    .line 837
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;->getData()Ljava/lang/Object;

    .line 838
    .line 839
    .line 840
    move-result-object v13

    .line 841
    instance-of v14, v13, Lu81/a;

    .line 842
    .line 843
    if-eqz v14, :cond_1e

    .line 844
    .line 845
    check-cast v13, Lu81/a;

    .line 846
    .line 847
    goto :goto_8

    .line 848
    :cond_1e
    move-object v13, v7

    .line 849
    :goto_8
    if-eqz v13, :cond_1f

    .line 850
    .line 851
    iget-object v13, v13, Lu81/a;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;

    .line 852
    .line 853
    goto :goto_9

    .line 854
    :cond_1f
    move-object v13, v7

    .line 855
    :goto_9
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;->getData()Ljava/lang/Object;

    .line 856
    .line 857
    .line 858
    move-result-object v14

    .line 859
    instance-of v15, v14, Lu81/a;

    .line 860
    .line 861
    if-eqz v15, :cond_20

    .line 862
    .line 863
    check-cast v14, Lu81/a;

    .line 864
    .line 865
    goto :goto_a

    .line 866
    :cond_20
    move-object v14, v7

    .line 867
    :goto_a
    if-eqz v14, :cond_21

    .line 868
    .line 869
    iget-object v14, v14, Lu81/a;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;

    .line 870
    .line 871
    goto :goto_b

    .line 872
    :cond_21
    move-object v14, v7

    .line 873
    :goto_b
    invoke-static {v1}, Lps/t1;->d(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ljava/util/Set;

    .line 874
    .line 875
    .line 876
    move-result-object v15

    .line 877
    invoke-static {v1}, Lps/t1;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ljava/util/Set;

    .line 878
    .line 879
    .line 880
    move-result-object v26

    .line 881
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->getCurrentState()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 882
    .line 883
    .line 884
    move-result-object v7

    .line 885
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;->getData()Ljava/lang/Object;

    .line 886
    .line 887
    .line 888
    move-result-object v2

    .line 889
    instance-of v6, v2, Lu81/a;

    .line 890
    .line 891
    if-eqz v6, :cond_22

    .line 892
    .line 893
    check-cast v2, Lu81/a;

    .line 894
    .line 895
    goto :goto_c

    .line 896
    :cond_22
    const/4 v2, 0x0

    .line 897
    :goto_c
    if-eqz v2, :cond_23

    .line 898
    .line 899
    iget-object v2, v2, Lu81/a;->g:Ll71/c;

    .line 900
    .line 901
    goto :goto_d

    .line 902
    :cond_23
    const/4 v2, 0x0

    .line 903
    :goto_d
    invoke-static {v1}, Lps/t1;->c(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Z

    .line 904
    .line 905
    .line 906
    move-result v1

    .line 907
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->getLogger()Lo71/a;

    .line 908
    .line 909
    .line 910
    move-result-object v6

    .line 911
    invoke-virtual {v10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->getFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 912
    .line 913
    .line 914
    move-result-object v17

    .line 915
    if-nez v17, :cond_24

    .line 916
    .line 917
    sget-object v17, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 918
    .line 919
    :cond_24
    move-object/from16 v3, v17

    .line 920
    .line 921
    invoke-virtual {v11}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->getParkingManeuverDirectionSideStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 922
    .line 923
    .line 924
    move-result-object v17

    .line 925
    if-eqz v17, :cond_25

    .line 926
    .line 927
    invoke-static/range {v17 .. v17}, Lpm/a;->e(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;)Ls71/h;

    .line 928
    .line 929
    .line 930
    move-result-object v17

    .line 931
    :goto_e
    move-object/from16 v5, v17

    .line 932
    .line 933
    goto :goto_f

    .line 934
    :cond_25
    sget-object v17, Ls71/h;->d:Ls71/h;

    .line 935
    .line 936
    goto :goto_e

    .line 937
    :goto_f
    invoke-virtual {v10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->getStoppingReasonStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 938
    .line 939
    .line 940
    move-result-object v17

    .line 941
    if-nez v17, :cond_26

    .line 942
    .line 943
    sget-object v17, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->NO_REASON:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 944
    .line 945
    :cond_26
    move-object/from16 v18, v17

    .line 946
    .line 947
    instance-of v4, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState;

    .line 948
    .line 949
    invoke-virtual {v10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->isTouchDiagnosisRequest()Z

    .line 950
    .line 951
    .line 952
    move-result v28

    .line 953
    move-object/from16 p0, v0

    .line 954
    .line 955
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;->NOT_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 956
    .line 957
    if-ne v3, v0, :cond_27

    .line 958
    .line 959
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState;

    .line 960
    .line 961
    if-nez v0, :cond_27

    .line 962
    .line 963
    const/16 p1, 0x1

    .line 964
    .line 965
    goto :goto_10

    .line 966
    :cond_27
    const/16 p1, 0x0

    .line 967
    .line 968
    :goto_10
    sget-object v0, Ls81/b;->e:Ljava/util/Set;

    .line 969
    .line 970
    invoke-interface {v0, v3}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 971
    .line 972
    .line 973
    move-result v17

    .line 974
    if-nez v17, :cond_29

    .line 975
    .line 976
    :cond_28
    :goto_11
    const/4 v8, 0x0

    .line 977
    :goto_12
    const/16 v17, 0x0

    .line 978
    .line 979
    goto :goto_14

    .line 980
    :cond_29
    if-eqz v4, :cond_2a

    .line 981
    .line 982
    :goto_13
    const/4 v8, 0x1

    .line 983
    goto :goto_12

    .line 984
    :cond_2a
    if-eqz p1, :cond_2b

    .line 985
    .line 986
    goto :goto_11

    .line 987
    :cond_2b
    if-nez v8, :cond_28

    .line 988
    .line 989
    goto :goto_13

    .line 990
    :goto_14
    new-instance v16, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 991
    .line 992
    move/from16 p1, v1

    .line 993
    .line 994
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleStatusPPE;

    .line 995
    .line 996
    invoke-virtual {v11}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->getObstacleDetectedStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;

    .line 997
    .line 998
    .line 999
    move-result-object v19

    .line 1000
    if-nez v19, :cond_2c

    .line 1001
    .line 1002
    sget-object v19, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;->NOT_DETECTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;

    .line 1003
    .line 1004
    :cond_2c
    move/from16 v29, v4

    .line 1005
    .line 1006
    move-object/from16 v4, v19

    .line 1007
    .line 1008
    move-object/from16 v19, v10

    .line 1009
    .line 1010
    invoke-virtual/range {v19 .. v19}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->getObstacleArea()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;

    .line 1011
    .line 1012
    .line 1013
    move-result-object v10

    .line 1014
    invoke-direct {v1, v4, v10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleStatusPPE;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;)V

    .line 1015
    .line 1016
    .line 1017
    invoke-virtual/range {v19 .. v19}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->getFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 1018
    .line 1019
    .line 1020
    move-result-object v4

    .line 1021
    if-nez v4, :cond_2d

    .line 1022
    .line 1023
    sget-object v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 1024
    .line 1025
    :cond_2d
    invoke-virtual {v11}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->getKeyStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

    .line 1026
    .line 1027
    .line 1028
    move-result-object v10

    .line 1029
    if-nez v10, :cond_2e

    .line 1030
    .line 1031
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

    .line 1032
    .line 1033
    :cond_2e
    move-object/from16 v20, v10

    .line 1034
    .line 1035
    invoke-virtual {v11}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->getParkingReversibleAvailability()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;

    .line 1036
    .line 1037
    .line 1038
    move-result-object v10

    .line 1039
    move-object/from16 v21, v1

    .line 1040
    .line 1041
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;->REVERSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;

    .line 1042
    .line 1043
    if-ne v10, v1, :cond_2f

    .line 1044
    .line 1045
    move-object/from16 v1, v17

    .line 1046
    .line 1047
    move-object/from16 v17, v18

    .line 1048
    .line 1049
    move-object/from16 v18, v21

    .line 1050
    .line 1051
    const/16 v21, 0x1

    .line 1052
    .line 1053
    goto :goto_15

    .line 1054
    :cond_2f
    move-object/from16 v1, v17

    .line 1055
    .line 1056
    move-object/from16 v17, v18

    .line 1057
    .line 1058
    move-object/from16 v18, v21

    .line 1059
    .line 1060
    const/16 v21, 0x0

    .line 1061
    .line 1062
    :goto_15
    invoke-virtual/range {v19 .. v19}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->getFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 1063
    .line 1064
    .line 1065
    move-result-object v10

    .line 1066
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;->ABORTED_RESUMING_POSSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 1067
    .line 1068
    if-ne v10, v1, :cond_30

    .line 1069
    .line 1070
    invoke-virtual/range {v19 .. v19}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->getStoppingReasonStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 1071
    .line 1072
    .line 1073
    move-result-object v10

    .line 1074
    move-object/from16 v19, v4

    .line 1075
    .line 1076
    sget-object v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->RECEPTION_OBSTRUCTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 1077
    .line 1078
    if-ne v10, v4, :cond_31

    .line 1079
    .line 1080
    const/16 v22, 0x1

    .line 1081
    .line 1082
    :goto_16
    const/4 v4, 0x0

    .line 1083
    goto :goto_17

    .line 1084
    :cond_30
    move-object/from16 v19, v4

    .line 1085
    .line 1086
    :cond_31
    const/16 v22, 0x0

    .line 1087
    .line 1088
    goto :goto_16

    .line 1089
    :goto_17
    invoke-virtual {v11}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->getParkingManeuverDirectionSideStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 1090
    .line 1091
    .line 1092
    move-result-object v10

    .line 1093
    if-eqz v10, :cond_32

    .line 1094
    .line 1095
    invoke-static {v10}, Lpm/a;->e(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;)Ls71/h;

    .line 1096
    .line 1097
    .line 1098
    move-result-object v10

    .line 1099
    :goto_18
    move-object/from16 v23, v10

    .line 1100
    .line 1101
    goto :goto_19

    .line 1102
    :cond_32
    sget-object v10, Ls71/h;->d:Ls71/h;

    .line 1103
    .line 1104
    goto :goto_18

    .line 1105
    :goto_19
    invoke-virtual {v12}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isElectricalVehicle$remoteparkassistcoremeb_release()Z

    .line 1106
    .line 1107
    .line 1108
    move-result v24

    .line 1109
    if-eqz v13, :cond_33

    .line 1110
    .line 1111
    invoke-static {v13, v14}, Llp/le;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;)Lx81/b;

    .line 1112
    .line 1113
    .line 1114
    move-result-object v10

    .line 1115
    move-object/from16 v25, v10

    .line 1116
    .line 1117
    goto :goto_1a

    .line 1118
    :cond_33
    move-object/from16 v25, v4

    .line 1119
    .line 1120
    :goto_1a
    sget-object v10, Ls71/k;->d:Lwe0/b;

    .line 1121
    .line 1122
    invoke-virtual {v11}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->getParkingManeuverDirectionSideStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 1123
    .line 1124
    .line 1125
    move-result-object v13

    .line 1126
    if-eqz v13, :cond_34

    .line 1127
    .line 1128
    invoke-static {v13}, Lpm/a;->g(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;)Ls71/j;

    .line 1129
    .line 1130
    .line 1131
    move-result-object v13

    .line 1132
    goto :goto_1b

    .line 1133
    :cond_34
    move-object v13, v4

    .line 1134
    :goto_1b
    invoke-virtual {v11}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->getParkingManeuverType()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 1135
    .line 1136
    .line 1137
    move-result-object v14

    .line 1138
    if-eqz v14, :cond_35

    .line 1139
    .line 1140
    invoke-static {v14}, Lpm/a;->f(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;)Ls71/i;

    .line 1141
    .line 1142
    .line 1143
    move-result-object v14

    .line 1144
    goto :goto_1c

    .line 1145
    :cond_35
    move-object v14, v4

    .line 1146
    :goto_1c
    invoke-virtual {v11}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->getParkingManeuverDirectionSideStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 1147
    .line 1148
    .line 1149
    move-result-object v27

    .line 1150
    if-eqz v27, :cond_36

    .line 1151
    .line 1152
    sget-object v4, Ly81/a;->d:[I

    .line 1153
    .line 1154
    invoke-virtual/range {v27 .. v27}, Ljava/lang/Enum;->ordinal()I

    .line 1155
    .line 1156
    .line 1157
    move-result v27

    .line 1158
    aget v4, v4, v27

    .line 1159
    .line 1160
    packed-switch v4, :pswitch_data_1

    .line 1161
    .line 1162
    .line 1163
    new-instance v0, La8/r0;

    .line 1164
    .line 1165
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 1166
    .line 1167
    .line 1168
    throw v0

    .line 1169
    :pswitch_10
    sget-object v4, Ls71/g;->f:Ls71/g;

    .line 1170
    .line 1171
    goto :goto_1d

    .line 1172
    :pswitch_11
    sget-object v4, Ls71/g;->e:Ls71/g;

    .line 1173
    .line 1174
    goto :goto_1d

    .line 1175
    :pswitch_12
    sget-object v4, Ls71/g;->d:Ls71/g;

    .line 1176
    .line 1177
    :cond_36
    :goto_1d
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1178
    .line 1179
    .line 1180
    invoke-static {v4, v13, v14}, Lwe0/b;->s(Ls71/g;Ls71/j;Ls71/i;)Ls71/k;

    .line 1181
    .line 1182
    .line 1183
    move-result-object v27

    .line 1184
    invoke-direct/range {v16 .. v27}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;ZZLs71/h;ZLx81/b;Ljava/util/Set;Ls71/k;)V

    .line 1185
    .line 1186
    .line 1187
    move-object/from16 v10, v16

    .line 1188
    .line 1189
    move-object/from16 v4, v17

    .line 1190
    .line 1191
    if-ne v3, v9, :cond_38

    .line 1192
    .line 1193
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->NO_REASON:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 1194
    .line 1195
    if-eq v4, v0, :cond_37

    .line 1196
    .line 1197
    new-instance v18, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFailedState;

    .line 1198
    .line 1199
    sget-object v22, Lw81/a;->d:Lw81/a;

    .line 1200
    .line 1201
    const/16 v23, 0x6

    .line 1202
    .line 1203
    const/16 v24, 0x0

    .line 1204
    .line 1205
    const/16 v20, 0x0

    .line 1206
    .line 1207
    const/16 v21, 0x0

    .line 1208
    .line 1209
    move-object/from16 v19, v4

    .line 1210
    .line 1211
    invoke-direct/range {v18 .. v24}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFailedState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;Ll71/c;ZLw81/a;ILkotlin/jvm/internal/g;)V

    .line 1212
    .line 1213
    .line 1214
    :goto_1e
    move-object/from16 v7, v18

    .line 1215
    .line 1216
    goto/16 :goto_25

    .line 1217
    .line 1218
    :cond_37
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState;

    .line 1219
    .line 1220
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;->m:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;

    .line 1221
    .line 1222
    const/4 v1, 0x0

    .line 1223
    invoke-static {v11, v12, v5, v1}, Llp/dd;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;Ls71/h;Z)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;

    .line 1224
    .line 1225
    .line 1226
    move-result-object v1

    .line 1227
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;)V

    .line 1228
    .line 1229
    .line 1230
    :goto_1f
    move-object v7, v0

    .line 1231
    goto/16 :goto_25

    .line 1232
    .line 1233
    :cond_38
    move-object/from16 v17, v4

    .line 1234
    .line 1235
    sget-object v4, Ll71/c;->e:Ll71/c;

    .line 1236
    .line 1237
    if-ne v2, v4, :cond_39

    .line 1238
    .line 1239
    move-object/from16 v18, v17

    .line 1240
    .line 1241
    new-instance v17, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFailedState;

    .line 1242
    .line 1243
    sget-object v21, Lw81/a;->d:Lw81/a;

    .line 1244
    .line 1245
    const/16 v22, 0x4

    .line 1246
    .line 1247
    const/16 v23, 0x0

    .line 1248
    .line 1249
    const/16 v20, 0x0

    .line 1250
    .line 1251
    move-object/from16 v19, v2

    .line 1252
    .line 1253
    invoke-direct/range {v17 .. v23}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFailedState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;Ll71/c;ZLw81/a;ILkotlin/jvm/internal/g;)V

    .line 1254
    .line 1255
    .line 1256
    :goto_20
    move-object/from16 v7, v17

    .line 1257
    .line 1258
    goto/16 :goto_25

    .line 1259
    .line 1260
    :cond_39
    sget-object v4, Ll71/c;->d:Ll71/c;

    .line 1261
    .line 1262
    if-ne v2, v4, :cond_3a

    .line 1263
    .line 1264
    sget-object v4, Ls71/h;->f:Ls71/h;

    .line 1265
    .line 1266
    if-ne v5, v4, :cond_3a

    .line 1267
    .line 1268
    move-object/from16 v18, v17

    .line 1269
    .line 1270
    new-instance v17, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFailedState;

    .line 1271
    .line 1272
    sget-object v21, Lw81/a;->d:Lw81/a;

    .line 1273
    .line 1274
    const/16 v22, 0x4

    .line 1275
    .line 1276
    const/16 v23, 0x0

    .line 1277
    .line 1278
    const/16 v20, 0x0

    .line 1279
    .line 1280
    move-object/from16 v19, v2

    .line 1281
    .line 1282
    invoke-direct/range {v17 .. v23}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFailedState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;Ll71/c;ZLw81/a;ILkotlin/jvm/internal/g;)V

    .line 1283
    .line 1284
    .line 1285
    goto :goto_20

    .line 1286
    :cond_3a
    if-eqz p1, :cond_3e

    .line 1287
    .line 1288
    if-eqz v6, :cond_3b

    .line 1289
    .line 1290
    const-string v0, "PPEStateMachine disconnects because the car is no longer connected."

    .line 1291
    .line 1292
    invoke-static {v6, v0}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 1293
    .line 1294
    .line 1295
    :cond_3b
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFailedState;

    .line 1296
    .line 1297
    if-nez v0, :cond_3d

    .line 1298
    .line 1299
    instance-of v0, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState;

    .line 1300
    .line 1301
    if-eqz v0, :cond_3c

    .line 1302
    .line 1303
    goto :goto_21

    .line 1304
    :cond_3c
    new-instance v18, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFailedState;

    .line 1305
    .line 1306
    sget-object v22, Lw81/a;->d:Lw81/a;

    .line 1307
    .line 1308
    const/16 v23, 0x6

    .line 1309
    .line 1310
    const/16 v24, 0x0

    .line 1311
    .line 1312
    const/16 v20, 0x0

    .line 1313
    .line 1314
    const/16 v21, 0x0

    .line 1315
    .line 1316
    move-object/from16 v19, v17

    .line 1317
    .line 1318
    invoke-direct/range {v18 .. v24}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFailedState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;Ll71/c;ZLw81/a;ILkotlin/jvm/internal/g;)V

    .line 1319
    .line 1320
    .line 1321
    goto :goto_1e

    .line 1322
    :cond_3d
    :goto_21
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->getStateCallback$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;

    .line 1323
    .line 1324
    .line 1325
    move-result-object v0

    .line 1326
    sget-object v1, Ls71/m;->h:Ls71/m;

    .line 1327
    .line 1328
    invoke-interface {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;->onSideEffect(Ljava/lang/Object;)V

    .line 1329
    .line 1330
    .line 1331
    check-cast v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPEScreenState;

    .line 1332
    .line 1333
    goto/16 :goto_25

    .line 1334
    .line 1335
    :cond_3e
    if-ne v3, v1, :cond_3f

    .line 1336
    .line 1337
    instance-of v1, v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPEScreenState;

    .line 1338
    .line 1339
    if-eqz v1, :cond_3f

    .line 1340
    .line 1341
    check-cast v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPEScreenState;

    .line 1342
    .line 1343
    goto/16 :goto_25

    .line 1344
    .line 1345
    :cond_3f
    if-eqz v28, :cond_40

    .line 1346
    .line 1347
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState;

    .line 1348
    .line 1349
    const/4 v1, 0x1

    .line 1350
    invoke-direct {v0, v10, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;Z)V

    .line 1351
    .line 1352
    .line 1353
    goto :goto_1f

    .line 1354
    :cond_40
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;->STARTING_UP:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 1355
    .line 1356
    const-string v2, "!"

    .line 1357
    .line 1358
    const-string v4, "PPEStateMachine.createScreenState("

    .line 1359
    .line 1360
    if-ne v3, v1, :cond_42

    .line 1361
    .line 1362
    if-eqz v6, :cond_41

    .line 1363
    .line 1364
    new-instance v0, Ljava/lang/StringBuilder;

    .line 1365
    .line 1366
    invoke-direct {v0, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1367
    .line 1368
    .line 1369
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1370
    .line 1371
    .line 1372
    const-string v1, "): PPETouchDiagnosisState & ParkingManeuverStatus: "

    .line 1373
    .line 1374
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1375
    .line 1376
    .line 1377
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1378
    .line 1379
    .line 1380
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1381
    .line 1382
    .line 1383
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1384
    .line 1385
    .line 1386
    move-result-object v0

    .line 1387
    invoke-static {v6, v0}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 1388
    .line 1389
    .line 1390
    :cond_41
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState;

    .line 1391
    .line 1392
    const/4 v1, 0x0

    .line 1393
    invoke-direct {v0, v10, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;Z)V

    .line 1394
    .line 1395
    .line 1396
    goto/16 :goto_1f

    .line 1397
    .line 1398
    :cond_42
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;->ENGINE_READY_TO_START:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 1399
    .line 1400
    sget-object v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;->ENGINE_START_REQUESTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 1401
    .line 1402
    filled-new-array {v1, v7}, [Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 1403
    .line 1404
    .line 1405
    move-result-object v1

    .line 1406
    invoke-static {v1}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 1407
    .line 1408
    .line 1409
    move-result-object v1

    .line 1410
    invoke-interface {v1, v3}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 1411
    .line 1412
    .line 1413
    move-result v1

    .line 1414
    if-eqz v1, :cond_43

    .line 1415
    .line 1416
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState;

    .line 1417
    .line 1418
    invoke-direct {v0, v10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;)V

    .line 1419
    .line 1420
    .line 1421
    goto/16 :goto_1f

    .line 1422
    .line 1423
    :cond_43
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;->READY_TO_START:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 1424
    .line 1425
    const-string v7, "): PPETouchDiagnosisState but ParkingManeuverStatus: "

    .line 1426
    .line 1427
    if-ne v3, v1, :cond_49

    .line 1428
    .line 1429
    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    .line 1430
    .line 1431
    .line 1432
    move-result v0

    .line 1433
    if-eqz v0, :cond_47

    .line 1434
    .line 1435
    const/4 v1, 0x1

    .line 1436
    if-eq v0, v1, :cond_46

    .line 1437
    .line 1438
    const/4 v1, 0x2

    .line 1439
    if-eq v0, v1, :cond_45

    .line 1440
    .line 1441
    const/4 v1, 0x3

    .line 1442
    if-eq v0, v1, :cond_46

    .line 1443
    .line 1444
    const/4 v1, 0x4

    .line 1445
    if-ne v0, v1, :cond_44

    .line 1446
    .line 1447
    goto :goto_22

    .line 1448
    :cond_44
    new-instance v0, La8/r0;

    .line 1449
    .line 1450
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 1451
    .line 1452
    .line 1453
    throw v0

    .line 1454
    :cond_45
    :goto_22
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState;

    .line 1455
    .line 1456
    invoke-direct {v0, v10, v15}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;Ljava/util/Set;)V

    .line 1457
    .line 1458
    .line 1459
    goto/16 :goto_1f

    .line 1460
    .line 1461
    :cond_46
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState;

    .line 1462
    .line 1463
    invoke-direct {v0, v10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;)V

    .line 1464
    .line 1465
    .line 1466
    goto/16 :goto_1f

    .line 1467
    .line 1468
    :cond_47
    if-eqz v6, :cond_48

    .line 1469
    .line 1470
    new-instance v0, Ljava/lang/StringBuilder;

    .line 1471
    .line 1472
    invoke-direct {v0, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1473
    .line 1474
    .line 1475
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1476
    .line 1477
    .line 1478
    invoke-virtual {v0, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1479
    .line 1480
    .line 1481
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1482
    .line 1483
    .line 1484
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1485
    .line 1486
    .line 1487
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1488
    .line 1489
    .line 1490
    move-result-object v0

    .line 1491
    invoke-static {v6, v0}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 1492
    .line 1493
    .line 1494
    :cond_48
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState;

    .line 1495
    .line 1496
    const/4 v1, 0x0

    .line 1497
    invoke-direct {v0, v10, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;Z)V

    .line 1498
    .line 1499
    .line 1500
    goto/16 :goto_1f

    .line 1501
    .line 1502
    :cond_49
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;->PAUSED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 1503
    .line 1504
    sget-object v9, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;->IN_PROGRESS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 1505
    .line 1506
    filled-new-array {v1, v9}, [Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 1507
    .line 1508
    .line 1509
    move-result-object v1

    .line 1510
    invoke-static {v1}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 1511
    .line 1512
    .line 1513
    move-result-object v1

    .line 1514
    invoke-interface {v1, v3}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 1515
    .line 1516
    .line 1517
    move-result v1

    .line 1518
    if-eqz v1, :cond_4a

    .line 1519
    .line 1520
    if-nez v29, :cond_4a

    .line 1521
    .line 1522
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState;

    .line 1523
    .line 1524
    invoke-direct {v0, v10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;)V

    .line 1525
    .line 1526
    .line 1527
    goto/16 :goto_1f

    .line 1528
    .line 1529
    :cond_4a
    invoke-interface {v0, v3}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 1530
    .line 1531
    .line 1532
    move-result v0

    .line 1533
    if-eqz v0, :cond_4f

    .line 1534
    .line 1535
    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    .line 1536
    .line 1537
    .line 1538
    move-result v0

    .line 1539
    if-eqz v0, :cond_4d

    .line 1540
    .line 1541
    const/4 v1, 0x1

    .line 1542
    if-eq v0, v1, :cond_4c

    .line 1543
    .line 1544
    const/4 v1, 0x2

    .line 1545
    if-eq v0, v1, :cond_4c

    .line 1546
    .line 1547
    const/4 v1, 0x3

    .line 1548
    if-eq v0, v1, :cond_4c

    .line 1549
    .line 1550
    const/4 v1, 0x4

    .line 1551
    if-ne v0, v1, :cond_4b

    .line 1552
    .line 1553
    goto :goto_23

    .line 1554
    :cond_4b
    new-instance v0, La8/r0;

    .line 1555
    .line 1556
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 1557
    .line 1558
    .line 1559
    throw v0

    .line 1560
    :cond_4c
    :goto_23
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState;

    .line 1561
    .line 1562
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;->m:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;

    .line 1563
    .line 1564
    invoke-static {v11, v12, v5, v8}, Llp/dd;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;Ls71/h;Z)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;

    .line 1565
    .line 1566
    .line 1567
    move-result-object v1

    .line 1568
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;)V

    .line 1569
    .line 1570
    .line 1571
    goto/16 :goto_1f

    .line 1572
    .line 1573
    :cond_4d
    if-eqz v6, :cond_4e

    .line 1574
    .line 1575
    new-instance v0, Ljava/lang/StringBuilder;

    .line 1576
    .line 1577
    invoke-direct {v0, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1578
    .line 1579
    .line 1580
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1581
    .line 1582
    .line 1583
    invoke-virtual {v0, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1584
    .line 1585
    .line 1586
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1587
    .line 1588
    .line 1589
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1590
    .line 1591
    .line 1592
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1593
    .line 1594
    .line 1595
    move-result-object v0

    .line 1596
    invoke-static {v6, v0}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 1597
    .line 1598
    .line 1599
    :cond_4e
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState;

    .line 1600
    .line 1601
    const/4 v1, 0x0

    .line 1602
    invoke-direct {v0, v10, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;Z)V

    .line 1603
    .line 1604
    .line 1605
    goto/16 :goto_1f

    .line 1606
    .line 1607
    :cond_4f
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;->CUSTOM_DRIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 1608
    .line 1609
    if-eq v3, v0, :cond_52

    .line 1610
    .line 1611
    if-eqz v29, :cond_50

    .line 1612
    .line 1613
    goto :goto_24

    .line 1614
    :cond_50
    if-eqz v6, :cond_51

    .line 1615
    .line 1616
    const-string v0, "PPEStateMachine.createScreenState(): default PPETouchDiagnosisState because no other signals are valid!"

    .line 1617
    .line 1618
    invoke-static {v6, v0}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 1619
    .line 1620
    .line 1621
    :cond_51
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState;

    .line 1622
    .line 1623
    const/4 v1, 0x0

    .line 1624
    invoke-direct {v0, v10, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;Z)V

    .line 1625
    .line 1626
    .line 1627
    goto/16 :goto_1f

    .line 1628
    .line 1629
    :cond_52
    :goto_24
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState;

    .line 1630
    .line 1631
    invoke-direct {v0, v10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;)V

    .line 1632
    .line 1633
    .line 1634
    goto/16 :goto_1f

    .line 1635
    .line 1636
    :goto_25
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->getCurrentState()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 1637
    .line 1638
    .line 1639
    move-result-object v0

    .line 1640
    invoke-static {v0, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1641
    .line 1642
    .line 1643
    goto :goto_27

    .line 1644
    :goto_26
    move-object v7, v4

    .line 1645
    :goto_27
    return-object v7

    .line 1646
    :pswitch_13
    move-object v4, v7

    .line 1647
    move-object/from16 v1, p1

    .line 1648
    .line 1649
    check-cast v1, Ljava/lang/String;

    .line 1650
    .line 1651
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1652
    .line 1653
    .line 1654
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1655
    .line 1656
    check-cast v0, Lr80/f;

    .line 1657
    .line 1658
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1659
    .line 1660
    .line 1661
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 1662
    .line 1663
    .line 1664
    move-result-object v2

    .line 1665
    new-instance v3, Lqh/a;

    .line 1666
    .line 1667
    move-object v5, v4

    .line 1668
    const/4 v4, 0x1

    .line 1669
    invoke-direct {v3, v4, v0, v1, v5}, Lqh/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 1670
    .line 1671
    .line 1672
    const/4 v1, 0x3

    .line 1673
    invoke-static {v2, v5, v5, v3, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1674
    .line 1675
    .line 1676
    return-object v9

    .line 1677
    :pswitch_14
    move-object/from16 v1, p1

    .line 1678
    .line 1679
    check-cast v1, Ljava/lang/String;

    .line 1680
    .line 1681
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1682
    .line 1683
    .line 1684
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1685
    .line 1686
    check-cast v0, Lr60/a0;

    .line 1687
    .line 1688
    invoke-virtual {v0, v1}, Lr60/a0;->h(Ljava/lang/String;)V

    .line 1689
    .line 1690
    .line 1691
    return-object v9

    .line 1692
    :pswitch_15
    move-object/from16 v1, p1

    .line 1693
    .line 1694
    check-cast v1, Ljava/lang/String;

    .line 1695
    .line 1696
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1697
    .line 1698
    .line 1699
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1700
    .line 1701
    check-cast v0, Lr60/x;

    .line 1702
    .line 1703
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1704
    .line 1705
    .line 1706
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 1707
    .line 1708
    .line 1709
    move-result-object v2

    .line 1710
    new-instance v3, Lr60/t;

    .line 1711
    .line 1712
    const/4 v4, 0x0

    .line 1713
    invoke-direct {v3, v0, v1, v4}, Lr60/t;-><init>(Lr60/x;Ljava/lang/String;Lkotlin/coroutines/Continuation;)V

    .line 1714
    .line 1715
    .line 1716
    const/4 v1, 0x3

    .line 1717
    invoke-static {v2, v4, v4, v3, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1718
    .line 1719
    .line 1720
    return-object v9

    .line 1721
    :pswitch_16
    move v1, v6

    .line 1722
    move-object v4, v7

    .line 1723
    move-object/from16 v2, p1

    .line 1724
    .line 1725
    check-cast v2, Ljava/lang/String;

    .line 1726
    .line 1727
    invoke-static {v2, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1728
    .line 1729
    .line 1730
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1731
    .line 1732
    check-cast v0, Lr60/s;

    .line 1733
    .line 1734
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1735
    .line 1736
    .line 1737
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 1738
    .line 1739
    .line 1740
    move-result-object v3

    .line 1741
    new-instance v5, Lnz/g;

    .line 1742
    .line 1743
    const/16 v6, 0x16

    .line 1744
    .line 1745
    invoke-direct {v5, v6, v0, v2, v4}, Lnz/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 1746
    .line 1747
    .line 1748
    invoke-static {v3, v4, v4, v5, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1749
    .line 1750
    .line 1751
    return-object v9

    .line 1752
    :pswitch_17
    move-object/from16 v1, p1

    .line 1753
    .line 1754
    check-cast v1, Ljava/lang/Boolean;

    .line 1755
    .line 1756
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1757
    .line 1758
    .line 1759
    move-result v11

    .line 1760
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1761
    .line 1762
    check-cast v0, Lr60/s;

    .line 1763
    .line 1764
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1765
    .line 1766
    .line 1767
    move-result-object v1

    .line 1768
    move-object v10, v1

    .line 1769
    check-cast v10, Lr60/r;

    .line 1770
    .line 1771
    const/16 v24, 0x0

    .line 1772
    .line 1773
    const/16 v25, 0x7ffe

    .line 1774
    .line 1775
    const/4 v12, 0x0

    .line 1776
    const/4 v13, 0x0

    .line 1777
    const/4 v14, 0x0

    .line 1778
    const/4 v15, 0x0

    .line 1779
    const/16 v16, 0x0

    .line 1780
    .line 1781
    const/16 v17, 0x0

    .line 1782
    .line 1783
    const/16 v18, 0x0

    .line 1784
    .line 1785
    const/16 v19, 0x0

    .line 1786
    .line 1787
    const/16 v20, 0x0

    .line 1788
    .line 1789
    const/16 v21, 0x0

    .line 1790
    .line 1791
    const/16 v22, 0x0

    .line 1792
    .line 1793
    const/16 v23, 0x0

    .line 1794
    .line 1795
    invoke-static/range {v10 .. v25}, Lr60/r;->a(Lr60/r;ZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lr60/r;

    .line 1796
    .line 1797
    .line 1798
    move-result-object v1

    .line 1799
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 1800
    .line 1801
    .line 1802
    return-object v9

    .line 1803
    :pswitch_18
    move-object/from16 v1, p1

    .line 1804
    .line 1805
    check-cast v1, Ljava/net/URI;

    .line 1806
    .line 1807
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1808
    .line 1809
    check-cast v0, Lr60/p;

    .line 1810
    .line 1811
    iget-object v2, v0, Lr60/p;->n:Lp60/f0;

    .line 1812
    .line 1813
    invoke-virtual {v2, v1}, Lp60/f0;->a(Ljava/net/URI;)Lq60/a;

    .line 1814
    .line 1815
    .line 1816
    move-result-object v1

    .line 1817
    sget-object v2, Lq60/a;->d:Lq60/a;

    .line 1818
    .line 1819
    if-ne v1, v2, :cond_53

    .line 1820
    .line 1821
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 1822
    .line 1823
    .line 1824
    move-result-object v1

    .line 1825
    new-instance v2, Lr60/n;

    .line 1826
    .line 1827
    const/4 v4, 0x1

    .line 1828
    const/4 v5, 0x0

    .line 1829
    invoke-direct {v2, v0, v5, v4}, Lr60/n;-><init>(Lr60/p;Lkotlin/coroutines/Continuation;I)V

    .line 1830
    .line 1831
    .line 1832
    const/4 v3, 0x3

    .line 1833
    invoke-static {v1, v5, v5, v2, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1834
    .line 1835
    .line 1836
    :cond_53
    iget-object v1, v0, Lr60/p;->r:Lnn0/g;

    .line 1837
    .line 1838
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 1839
    .line 1840
    .line 1841
    move-result-object v1

    .line 1842
    check-cast v1, Lon0/b;

    .line 1843
    .line 1844
    sget-object v2, Lon0/b;->d:Lon0/b;

    .line 1845
    .line 1846
    if-ne v1, v2, :cond_54

    .line 1847
    .line 1848
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1849
    .line 1850
    .line 1851
    move-result-object v3

    .line 1852
    check-cast v3, Lr60/m;

    .line 1853
    .line 1854
    iget-object v3, v3, Lr60/m;->d:Ljava/util/List;

    .line 1855
    .line 1856
    invoke-interface {v3}, Ljava/util/List;->isEmpty()Z

    .line 1857
    .line 1858
    .line 1859
    move-result v3

    .line 1860
    if-eqz v3, :cond_54

    .line 1861
    .line 1862
    iget-object v0, v0, Lr60/p;->j:Lp60/k;

    .line 1863
    .line 1864
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 1865
    .line 1866
    .line 1867
    goto :goto_28

    .line 1868
    :cond_54
    if-ne v1, v2, :cond_55

    .line 1869
    .line 1870
    iget-object v0, v0, Lr60/p;->i:Lp60/j;

    .line 1871
    .line 1872
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 1873
    .line 1874
    .line 1875
    goto :goto_28

    .line 1876
    :cond_55
    sget-object v2, Lon0/b;->e:Lon0/b;

    .line 1877
    .line 1878
    if-ne v1, v2, :cond_56

    .line 1879
    .line 1880
    iget-object v0, v0, Lr60/p;->s:Lp60/s;

    .line 1881
    .line 1882
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 1883
    .line 1884
    .line 1885
    :cond_56
    :goto_28
    return-object v9

    .line 1886
    :pswitch_19
    move-object/from16 v1, p1

    .line 1887
    .line 1888
    check-cast v1, Ljava/lang/String;

    .line 1889
    .line 1890
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1891
    .line 1892
    .line 1893
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1894
    .line 1895
    check-cast v0, Lr60/l;

    .line 1896
    .line 1897
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1898
    .line 1899
    .line 1900
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1901
    .line 1902
    .line 1903
    move-result-object v2

    .line 1904
    move-object v10, v2

    .line 1905
    check-cast v10, Lr60/i;

    .line 1906
    .line 1907
    invoke-virtual {v0, v1}, Lr60/l;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 1908
    .line 1909
    .line 1910
    move-result-object v18

    .line 1911
    const/16 v25, 0x0

    .line 1912
    .line 1913
    const/16 v26, 0x7f3f

    .line 1914
    .line 1915
    const/4 v11, 0x0

    .line 1916
    const/4 v12, 0x0

    .line 1917
    const/4 v13, 0x0

    .line 1918
    const/4 v14, 0x0

    .line 1919
    const/4 v15, 0x0

    .line 1920
    const/16 v16, 0x0

    .line 1921
    .line 1922
    const/16 v19, 0x0

    .line 1923
    .line 1924
    const/16 v20, 0x0

    .line 1925
    .line 1926
    const/16 v21, 0x0

    .line 1927
    .line 1928
    const/16 v22, 0x0

    .line 1929
    .line 1930
    const/16 v23, 0x0

    .line 1931
    .line 1932
    const/16 v24, 0x0

    .line 1933
    .line 1934
    move-object/from16 v17, v1

    .line 1935
    .line 1936
    invoke-static/range {v10 .. v26}, Lr60/i;->a(Lr60/i;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZLon0/q;Ljava/util/ArrayList;Lql0/g;ZZI)Lr60/i;

    .line 1937
    .line 1938
    .line 1939
    move-result-object v1

    .line 1940
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 1941
    .line 1942
    .line 1943
    invoke-virtual {v0}, Lr60/l;->k()V

    .line 1944
    .line 1945
    .line 1946
    return-object v9

    .line 1947
    :pswitch_1a
    move-object/from16 v1, p1

    .line 1948
    .line 1949
    check-cast v1, Ljava/lang/String;

    .line 1950
    .line 1951
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1952
    .line 1953
    .line 1954
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1955
    .line 1956
    check-cast v0, Lr60/l;

    .line 1957
    .line 1958
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1959
    .line 1960
    .line 1961
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1962
    .line 1963
    .line 1964
    move-result-object v2

    .line 1965
    move-object v10, v2

    .line 1966
    check-cast v10, Lr60/i;

    .line 1967
    .line 1968
    const/16 v25, 0x0

    .line 1969
    .line 1970
    const/16 v26, 0x7fdf

    .line 1971
    .line 1972
    const/4 v11, 0x0

    .line 1973
    const/4 v12, 0x0

    .line 1974
    const/4 v13, 0x0

    .line 1975
    const/4 v14, 0x0

    .line 1976
    const/4 v15, 0x0

    .line 1977
    const/16 v17, 0x0

    .line 1978
    .line 1979
    const/16 v18, 0x0

    .line 1980
    .line 1981
    const/16 v19, 0x0

    .line 1982
    .line 1983
    const/16 v20, 0x0

    .line 1984
    .line 1985
    const/16 v21, 0x0

    .line 1986
    .line 1987
    const/16 v22, 0x0

    .line 1988
    .line 1989
    const/16 v23, 0x0

    .line 1990
    .line 1991
    const/16 v24, 0x0

    .line 1992
    .line 1993
    move-object/from16 v16, v1

    .line 1994
    .line 1995
    invoke-static/range {v10 .. v26}, Lr60/i;->a(Lr60/i;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZLon0/q;Ljava/util/ArrayList;Lql0/g;ZZI)Lr60/i;

    .line 1996
    .line 1997
    .line 1998
    move-result-object v1

    .line 1999
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 2000
    .line 2001
    .line 2002
    invoke-virtual {v0}, Lr60/l;->k()V

    .line 2003
    .line 2004
    .line 2005
    return-object v9

    .line 2006
    :pswitch_1b
    move-object/from16 v14, p1

    .line 2007
    .line 2008
    check-cast v14, Ljava/lang/String;

    .line 2009
    .line 2010
    invoke-static {v14, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2011
    .line 2012
    .line 2013
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 2014
    .line 2015
    check-cast v0, Lr60/l;

    .line 2016
    .line 2017
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2018
    .line 2019
    .line 2020
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 2021
    .line 2022
    .line 2023
    move-result-object v1

    .line 2024
    move-object v10, v1

    .line 2025
    check-cast v10, Lr60/i;

    .line 2026
    .line 2027
    const/16 v25, 0x0

    .line 2028
    .line 2029
    const/16 v26, 0x7ff7

    .line 2030
    .line 2031
    const/4 v11, 0x0

    .line 2032
    const/4 v12, 0x0

    .line 2033
    const/4 v13, 0x0

    .line 2034
    const/4 v15, 0x0

    .line 2035
    const/16 v16, 0x0

    .line 2036
    .line 2037
    const/16 v17, 0x0

    .line 2038
    .line 2039
    const/16 v18, 0x0

    .line 2040
    .line 2041
    const/16 v19, 0x0

    .line 2042
    .line 2043
    const/16 v20, 0x0

    .line 2044
    .line 2045
    const/16 v21, 0x0

    .line 2046
    .line 2047
    const/16 v22, 0x0

    .line 2048
    .line 2049
    const/16 v23, 0x0

    .line 2050
    .line 2051
    const/16 v24, 0x0

    .line 2052
    .line 2053
    invoke-static/range {v10 .. v26}, Lr60/i;->a(Lr60/i;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZLon0/q;Ljava/util/ArrayList;Lql0/g;ZZI)Lr60/i;

    .line 2054
    .line 2055
    .line 2056
    move-result-object v1

    .line 2057
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 2058
    .line 2059
    .line 2060
    invoke-virtual {v0}, Lr60/l;->k()V

    .line 2061
    .line 2062
    .line 2063
    return-object v9

    .line 2064
    :pswitch_1c
    move-object/from16 v15, p1

    .line 2065
    .line 2066
    check-cast v15, Ljava/lang/String;

    .line 2067
    .line 2068
    invoke-static {v15, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2069
    .line 2070
    .line 2071
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 2072
    .line 2073
    check-cast v0, Lr60/l;

    .line 2074
    .line 2075
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2076
    .line 2077
    .line 2078
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 2079
    .line 2080
    .line 2081
    move-result-object v1

    .line 2082
    move-object v10, v1

    .line 2083
    check-cast v10, Lr60/i;

    .line 2084
    .line 2085
    const/16 v25, 0x0

    .line 2086
    .line 2087
    const/16 v26, 0x7fef

    .line 2088
    .line 2089
    const/4 v11, 0x0

    .line 2090
    const/4 v12, 0x0

    .line 2091
    const/4 v13, 0x0

    .line 2092
    const/4 v14, 0x0

    .line 2093
    const/16 v16, 0x0

    .line 2094
    .line 2095
    const/16 v17, 0x0

    .line 2096
    .line 2097
    const/16 v18, 0x0

    .line 2098
    .line 2099
    const/16 v19, 0x0

    .line 2100
    .line 2101
    const/16 v20, 0x0

    .line 2102
    .line 2103
    const/16 v21, 0x0

    .line 2104
    .line 2105
    const/16 v22, 0x0

    .line 2106
    .line 2107
    const/16 v23, 0x0

    .line 2108
    .line 2109
    const/16 v24, 0x0

    .line 2110
    .line 2111
    invoke-static/range {v10 .. v26}, Lr60/i;->a(Lr60/i;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZLon0/q;Ljava/util/ArrayList;Lql0/g;ZZI)Lr60/i;

    .line 2112
    .line 2113
    .line 2114
    move-result-object v1

    .line 2115
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 2116
    .line 2117
    .line 2118
    invoke-virtual {v0}, Lr60/l;->k()V

    .line 2119
    .line 2120
    .line 2121
    return-object v9

    .line 2122
    :pswitch_1d
    move-object/from16 v13, p1

    .line 2123
    .line 2124
    check-cast v13, Ljava/lang/String;

    .line 2125
    .line 2126
    invoke-static {v13, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2127
    .line 2128
    .line 2129
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 2130
    .line 2131
    check-cast v0, Lr60/l;

    .line 2132
    .line 2133
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2134
    .line 2135
    .line 2136
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 2137
    .line 2138
    .line 2139
    move-result-object v1

    .line 2140
    move-object v10, v1

    .line 2141
    check-cast v10, Lr60/i;

    .line 2142
    .line 2143
    const/16 v25, 0x0

    .line 2144
    .line 2145
    const/16 v26, 0x7ffb

    .line 2146
    .line 2147
    const/4 v11, 0x0

    .line 2148
    const/4 v12, 0x0

    .line 2149
    const/4 v14, 0x0

    .line 2150
    const/4 v15, 0x0

    .line 2151
    const/16 v16, 0x0

    .line 2152
    .line 2153
    const/16 v17, 0x0

    .line 2154
    .line 2155
    const/16 v18, 0x0

    .line 2156
    .line 2157
    const/16 v19, 0x0

    .line 2158
    .line 2159
    const/16 v20, 0x0

    .line 2160
    .line 2161
    const/16 v21, 0x0

    .line 2162
    .line 2163
    const/16 v22, 0x0

    .line 2164
    .line 2165
    const/16 v23, 0x0

    .line 2166
    .line 2167
    const/16 v24, 0x0

    .line 2168
    .line 2169
    invoke-static/range {v10 .. v26}, Lr60/i;->a(Lr60/i;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZLon0/q;Ljava/util/ArrayList;Lql0/g;ZZI)Lr60/i;

    .line 2170
    .line 2171
    .line 2172
    move-result-object v1

    .line 2173
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 2174
    .line 2175
    .line 2176
    invoke-virtual {v0}, Lr60/l;->k()V

    .line 2177
    .line 2178
    .line 2179
    return-object v9

    .line 2180
    :pswitch_1e
    move-object/from16 v1, p1

    .line 2181
    .line 2182
    check-cast v1, Ljava/lang/String;

    .line 2183
    .line 2184
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2185
    .line 2186
    .line 2187
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 2188
    .line 2189
    check-cast v0, Lr60/g;

    .line 2190
    .line 2191
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2192
    .line 2193
    .line 2194
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 2195
    .line 2196
    .line 2197
    move-result-object v2

    .line 2198
    move-object v10, v2

    .line 2199
    check-cast v10, Lr60/b;

    .line 2200
    .line 2201
    const/16 v20, 0x0

    .line 2202
    .line 2203
    const/16 v21, 0x33f

    .line 2204
    .line 2205
    const/4 v11, 0x0

    .line 2206
    const/4 v12, 0x0

    .line 2207
    const/4 v13, 0x0

    .line 2208
    const/4 v14, 0x0

    .line 2209
    const/4 v15, 0x0

    .line 2210
    const/16 v16, 0x0

    .line 2211
    .line 2212
    const/16 v18, 0x1

    .line 2213
    .line 2214
    const/16 v19, 0x0

    .line 2215
    .line 2216
    move-object/from16 v17, v1

    .line 2217
    .line 2218
    invoke-static/range {v10 .. v21}, Lr60/b;->a(Lr60/b;Ljava/lang/String;ZLql0/g;ZLjava/lang/String;Ljava/util/List;Ljava/lang/String;ZLon0/a0;Ljava/lang/String;I)Lr60/b;

    .line 2219
    .line 2220
    .line 2221
    move-result-object v1

    .line 2222
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 2223
    .line 2224
    .line 2225
    return-object v9

    .line 2226
    :pswitch_1f
    move-object/from16 v1, p1

    .line 2227
    .line 2228
    check-cast v1, Ljava/lang/String;

    .line 2229
    .line 2230
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2231
    .line 2232
    .line 2233
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 2234
    .line 2235
    check-cast v0, Lr60/g;

    .line 2236
    .line 2237
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2238
    .line 2239
    .line 2240
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 2241
    .line 2242
    .line 2243
    move-result-object v2

    .line 2244
    new-instance v3, Lr60/e;

    .line 2245
    .line 2246
    const/4 v4, 0x1

    .line 2247
    const/4 v5, 0x0

    .line 2248
    invoke-direct {v3, v0, v1, v5, v4}, Lr60/e;-><init>(Lr60/g;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 2249
    .line 2250
    .line 2251
    const/4 v1, 0x3

    .line 2252
    invoke-static {v2, v5, v5, v3, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 2253
    .line 2254
    .line 2255
    return-object v9

    .line 2256
    nop

    .line 2257
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 2258
    .line 2259
    .line 2260
    .line 2261
    .line 2262
    .line 2263
    .line 2264
    .line 2265
    .line 2266
    .line 2267
    .line 2268
    .line 2269
    .line 2270
    .line 2271
    .line 2272
    .line 2273
    .line 2274
    .line 2275
    .line 2276
    .line 2277
    .line 2278
    .line 2279
    .line 2280
    .line 2281
    .line 2282
    .line 2283
    .line 2284
    .line 2285
    .line 2286
    .line 2287
    .line 2288
    .line 2289
    .line 2290
    .line 2291
    .line 2292
    .line 2293
    .line 2294
    .line 2295
    .line 2296
    .line 2297
    .line 2298
    .line 2299
    .line 2300
    .line 2301
    .line 2302
    .line 2303
    .line 2304
    .line 2305
    .line 2306
    .line 2307
    .line 2308
    .line 2309
    .line 2310
    .line 2311
    .line 2312
    .line 2313
    .line 2314
    .line 2315
    .line 2316
    .line 2317
    .line 2318
    .line 2319
    :pswitch_data_1
    .packed-switch 0x1
        :pswitch_12
        :pswitch_12
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_11
        :pswitch_11
        :pswitch_10
        :pswitch_11
        :pswitch_11
        :pswitch_10
        :pswitch_11
        :pswitch_10
        :pswitch_11
        :pswitch_10
        :pswitch_11
        :pswitch_11
        :pswitch_10
        :pswitch_11
    .end packed-switch
.end method
