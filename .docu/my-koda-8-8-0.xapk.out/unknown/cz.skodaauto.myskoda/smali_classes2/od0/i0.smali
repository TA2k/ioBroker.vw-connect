.class public final Lod0/i0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lme0/a;
.implements Lme0/b;


# instance fields
.field public final a:Lti0/a;

.field public final b:Lti0/a;

.field public final c:Lti0/a;

.field public final d:Lti0/a;

.field public final e:Lny/d;

.field public final f:Lwe0/a;

.field public final g:Lez0/c;


# direct methods
.method public constructor <init>(Lti0/a;Lti0/a;Lti0/a;Lti0/a;Lny/d;Lwe0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lod0/i0;->a:Lti0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lod0/i0;->b:Lti0/a;

    .line 7
    .line 8
    iput-object p3, p0, Lod0/i0;->c:Lti0/a;

    .line 9
    .line 10
    iput-object p4, p0, Lod0/i0;->d:Lti0/a;

    .line 11
    .line 12
    iput-object p5, p0, Lod0/i0;->e:Lny/d;

    .line 13
    .line 14
    iput-object p6, p0, Lod0/i0;->f:Lwe0/a;

    .line 15
    .line 16
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    iput-object p1, p0, Lod0/i0;->g:Lez0/c;

    .line 21
    .line 22
    return-void
.end method

.method public static final b(Lod0/i0;Ljava/lang/String;Lrd0/r;Lrx0/c;)Ljava/lang/Object;
    .locals 34

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p3

    .line 4
    .line 5
    instance-of v2, v1, Lod0/g0;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lod0/g0;

    .line 11
    .line 12
    iget v3, v2, Lod0/g0;->k:I

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
    iput v3, v2, Lod0/g0;->k:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lod0/g0;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Lod0/g0;-><init>(Lod0/i0;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Lod0/g0;->i:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lod0/g0;->k:I

    .line 34
    .line 35
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    const-string v7, "<this>"

    .line 38
    .line 39
    const/4 v8, 0x1

    .line 40
    packed-switch v4, :pswitch_data_0

    .line 41
    .line 42
    .line 43
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 46
    .line 47
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw v0

    .line 51
    :pswitch_0
    iget-wide v10, v2, Lod0/g0;->h:J

    .line 52
    .line 53
    iget-object v4, v2, Lod0/g0;->g:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast v4, Lao0/a;

    .line 56
    .line 57
    iget-object v4, v2, Lod0/g0;->f:Ljava/util/Iterator;

    .line 58
    .line 59
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    move-object v12, v4

    .line 63
    move-object/from16 v19, v5

    .line 64
    .line 65
    move v4, v8

    .line 66
    const/4 v1, 0x0

    .line 67
    const/4 v5, 0x0

    .line 68
    goto/16 :goto_10

    .line 69
    .line 70
    :pswitch_1
    iget-wide v10, v2, Lod0/g0;->h:J

    .line 71
    .line 72
    iget-object v4, v2, Lod0/g0;->g:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast v4, Lao0/a;

    .line 75
    .line 76
    iget-object v12, v2, Lod0/g0;->f:Ljava/util/Iterator;

    .line 77
    .line 78
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    move-object/from16 v19, v5

    .line 82
    .line 83
    :goto_1
    move-wide/from16 v23, v10

    .line 84
    .line 85
    goto/16 :goto_d

    .line 86
    .line 87
    :pswitch_2
    iget-wide v10, v2, Lod0/g0;->h:J

    .line 88
    .line 89
    iget-object v4, v2, Lod0/g0;->g:Ljava/lang/Object;

    .line 90
    .line 91
    check-cast v4, Lao0/c;

    .line 92
    .line 93
    iget-object v4, v2, Lod0/g0;->f:Ljava/util/Iterator;

    .line 94
    .line 95
    iget-object v12, v2, Lod0/g0;->e:Lrd0/r;

    .line 96
    .line 97
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    move-object v1, v4

    .line 101
    move-object/from16 v19, v5

    .line 102
    .line 103
    move-object v4, v12

    .line 104
    goto/16 :goto_9

    .line 105
    .line 106
    :pswitch_3
    iget-wide v10, v2, Lod0/g0;->h:J

    .line 107
    .line 108
    iget-object v4, v2, Lod0/g0;->g:Ljava/lang/Object;

    .line 109
    .line 110
    check-cast v4, Lao0/c;

    .line 111
    .line 112
    iget-object v12, v2, Lod0/g0;->f:Ljava/util/Iterator;

    .line 113
    .line 114
    iget-object v13, v2, Lod0/g0;->e:Lrd0/r;

    .line 115
    .line 116
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    move-object/from16 v19, v5

    .line 120
    .line 121
    :goto_2
    move-wide/from16 v23, v10

    .line 122
    .line 123
    goto/16 :goto_a

    .line 124
    .line 125
    :pswitch_4
    iget-object v4, v2, Lod0/g0;->e:Lrd0/r;

    .line 126
    .line 127
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 128
    .line 129
    .line 130
    move-object/from16 v19, v5

    .line 131
    .line 132
    goto/16 :goto_8

    .line 133
    .line 134
    :pswitch_5
    iget-object v4, v2, Lod0/g0;->e:Lrd0/r;

    .line 135
    .line 136
    iget-object v10, v2, Lod0/g0;->d:Ljava/lang/String;

    .line 137
    .line 138
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 139
    .line 140
    .line 141
    move-object v15, v10

    .line 142
    goto :goto_3

    .line 143
    :pswitch_6
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 144
    .line 145
    .line 146
    iget-object v1, v0, Lod0/i0;->a:Lti0/a;

    .line 147
    .line 148
    move-object/from16 v4, p1

    .line 149
    .line 150
    iput-object v4, v2, Lod0/g0;->d:Ljava/lang/String;

    .line 151
    .line 152
    move-object/from16 v10, p2

    .line 153
    .line 154
    iput-object v10, v2, Lod0/g0;->e:Lrd0/r;

    .line 155
    .line 156
    iput v8, v2, Lod0/g0;->k:I

    .line 157
    .line 158
    invoke-interface {v1, v2}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v1

    .line 162
    if-ne v1, v3, :cond_1

    .line 163
    .line 164
    goto/16 :goto_f

    .line 165
    .line 166
    :cond_1
    move-object v15, v4

    .line 167
    move-object v4, v10

    .line 168
    :goto_3
    check-cast v1, Lod0/k;

    .line 169
    .line 170
    const-string v10, "$this$toEntity"

    .line 171
    .line 172
    invoke-static {v4, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 173
    .line 174
    .line 175
    const-string v10, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-vin$0"

    .line 176
    .line 177
    invoke-static {v15, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 178
    .line 179
    .line 180
    new-instance v10, Lod0/l;

    .line 181
    .line 182
    iget-wide v13, v4, Lrd0/r;->a:J

    .line 183
    .line 184
    iget-object v11, v4, Lrd0/r;->b:Ljava/lang/String;

    .line 185
    .line 186
    iget-object v12, v4, Lrd0/r;->c:Lrd0/p;

    .line 187
    .line 188
    iget-object v6, v4, Lrd0/r;->f:Lrd0/s;

    .line 189
    .line 190
    new-instance v8, Lod0/m;

    .line 191
    .line 192
    iget-object v9, v6, Lrd0/s;->a:Lqr0/l;

    .line 193
    .line 194
    if-eqz v9, :cond_2

    .line 195
    .line 196
    iget v9, v9, Lqr0/l;->d:I

    .line 197
    .line 198
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 199
    .line 200
    .line 201
    move-result-object v9

    .line 202
    :goto_4
    move-object/from16 v19, v5

    .line 203
    .line 204
    goto :goto_5

    .line 205
    :cond_2
    const/4 v9, 0x0

    .line 206
    goto :goto_4

    .line 207
    :goto_5
    iget-object v5, v6, Lrd0/s;->b:Lqr0/l;

    .line 208
    .line 209
    if-eqz v5, :cond_3

    .line 210
    .line 211
    iget v5, v5, Lqr0/l;->d:I

    .line 212
    .line 213
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 214
    .line 215
    .line 216
    move-result-object v5

    .line 217
    :goto_6
    move-object/from16 p1, v10

    .line 218
    .line 219
    goto :goto_7

    .line 220
    :cond_3
    const/4 v5, 0x0

    .line 221
    goto :goto_6

    .line 222
    :goto_7
    iget-object v10, v6, Lrd0/s;->c:Ljava/lang/Boolean;

    .line 223
    .line 224
    iget-object v6, v6, Lrd0/s;->d:Ljava/lang/Boolean;

    .line 225
    .line 226
    invoke-direct {v8, v9, v5, v10, v6}, Lod0/m;-><init>(Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Boolean;Ljava/lang/Boolean;)V

    .line 227
    .line 228
    .line 229
    move-object/from16 v16, v11

    .line 230
    .line 231
    move-object/from16 v17, v12

    .line 232
    .line 233
    const-wide/16 v11, 0x0

    .line 234
    .line 235
    move-object/from16 v10, p1

    .line 236
    .line 237
    move-object/from16 v18, v8

    .line 238
    .line 239
    invoke-direct/range {v10 .. v18}, Lod0/l;-><init>(JJLjava/lang/String;Ljava/lang/String;Lrd0/p;Lod0/m;)V

    .line 240
    .line 241
    .line 242
    const/4 v5, 0x0

    .line 243
    iput-object v5, v2, Lod0/g0;->d:Ljava/lang/String;

    .line 244
    .line 245
    iput-object v4, v2, Lod0/g0;->e:Lrd0/r;

    .line 246
    .line 247
    const/4 v5, 0x2

    .line 248
    iput v5, v2, Lod0/g0;->k:I

    .line 249
    .line 250
    iget-object v5, v1, Lod0/k;->a:Lla/u;

    .line 251
    .line 252
    new-instance v6, Ll2/v1;

    .line 253
    .line 254
    const/16 v8, 0x1d

    .line 255
    .line 256
    invoke-direct {v6, v8, v1, v10}, Ll2/v1;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 257
    .line 258
    .line 259
    const/4 v1, 0x0

    .line 260
    const/4 v8, 0x1

    .line 261
    invoke-static {v2, v5, v1, v8, v6}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 262
    .line 263
    .line 264
    move-result-object v5

    .line 265
    if-ne v5, v3, :cond_4

    .line 266
    .line 267
    goto/16 :goto_f

    .line 268
    .line 269
    :cond_4
    move-object v1, v5

    .line 270
    :goto_8
    check-cast v1, Ljava/lang/Number;

    .line 271
    .line 272
    invoke-virtual {v1}, Ljava/lang/Number;->longValue()J

    .line 273
    .line 274
    .line 275
    move-result-wide v5

    .line 276
    iget-object v1, v4, Lrd0/r;->d:Ljava/util/List;

    .line 277
    .line 278
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 279
    .line 280
    .line 281
    move-result-object v1

    .line 282
    move-wide v10, v5

    .line 283
    :goto_9
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 284
    .line 285
    .line 286
    move-result v5

    .line 287
    if-eqz v5, :cond_8

    .line 288
    .line 289
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 290
    .line 291
    .line 292
    move-result-object v5

    .line 293
    check-cast v5, Lao0/c;

    .line 294
    .line 295
    iget-object v6, v0, Lod0/i0;->c:Lti0/a;

    .line 296
    .line 297
    const/4 v8, 0x0

    .line 298
    iput-object v8, v2, Lod0/g0;->d:Ljava/lang/String;

    .line 299
    .line 300
    iput-object v4, v2, Lod0/g0;->e:Lrd0/r;

    .line 301
    .line 302
    iput-object v1, v2, Lod0/g0;->f:Ljava/util/Iterator;

    .line 303
    .line 304
    iput-object v5, v2, Lod0/g0;->g:Ljava/lang/Object;

    .line 305
    .line 306
    iput-wide v10, v2, Lod0/g0;->h:J

    .line 307
    .line 308
    const/4 v8, 0x3

    .line 309
    iput v8, v2, Lod0/g0;->k:I

    .line 310
    .line 311
    invoke-interface {v6, v2}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 312
    .line 313
    .line 314
    move-result-object v6

    .line 315
    if-ne v6, v3, :cond_5

    .line 316
    .line 317
    goto/16 :goto_f

    .line 318
    .line 319
    :cond_5
    move-object v12, v1

    .line 320
    move-object v13, v4

    .line 321
    move-object v4, v5

    .line 322
    move-object v1, v6

    .line 323
    goto/16 :goto_2

    .line 324
    .line 325
    :goto_a
    check-cast v1, Lod0/o;

    .line 326
    .line 327
    invoke-static {v4, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 328
    .line 329
    .line 330
    new-instance v20, Lod0/p;

    .line 331
    .line 332
    iget-wide v5, v4, Lao0/c;->a:J

    .line 333
    .line 334
    iget-boolean v8, v4, Lao0/c;->b:Z

    .line 335
    .line 336
    iget-object v9, v4, Lao0/c;->c:Ljava/time/LocalTime;

    .line 337
    .line 338
    iget-object v10, v4, Lao0/c;->d:Lao0/f;

    .line 339
    .line 340
    invoke-virtual {v10}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 341
    .line 342
    .line 343
    move-result-object v27

    .line 344
    iget-object v10, v4, Lao0/c;->e:Ljava/util/Set;

    .line 345
    .line 346
    move-object/from16 v28, v10

    .line 347
    .line 348
    check-cast v28, Ljava/lang/Iterable;

    .line 349
    .line 350
    new-instance v10, Lod0/g;

    .line 351
    .line 352
    const/4 v11, 0x5

    .line 353
    invoke-direct {v10, v11}, Lod0/g;-><init>(I)V

    .line 354
    .line 355
    .line 356
    const/16 v33, 0x1e

    .line 357
    .line 358
    const-string v29, ","

    .line 359
    .line 360
    const/16 v30, 0x0

    .line 361
    .line 362
    const/16 v31, 0x0

    .line 363
    .line 364
    move-object/from16 v32, v10

    .line 365
    .line 366
    invoke-static/range {v28 .. v33}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 367
    .line 368
    .line 369
    move-result-object v28

    .line 370
    iget-boolean v4, v4, Lao0/c;->f:Z

    .line 371
    .line 372
    move/from16 v29, v4

    .line 373
    .line 374
    move-wide/from16 v21, v5

    .line 375
    .line 376
    move/from16 v25, v8

    .line 377
    .line 378
    move-object/from16 v26, v9

    .line 379
    .line 380
    invoke-direct/range {v20 .. v29}, Lod0/p;-><init>(JJZLjava/time/LocalTime;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 381
    .line 382
    .line 383
    move-object/from16 v4, v20

    .line 384
    .line 385
    move-wide/from16 v10, v23

    .line 386
    .line 387
    const/4 v5, 0x0

    .line 388
    iput-object v5, v2, Lod0/g0;->d:Ljava/lang/String;

    .line 389
    .line 390
    iput-object v13, v2, Lod0/g0;->e:Lrd0/r;

    .line 391
    .line 392
    iput-object v12, v2, Lod0/g0;->f:Ljava/util/Iterator;

    .line 393
    .line 394
    iput-object v5, v2, Lod0/g0;->g:Ljava/lang/Object;

    .line 395
    .line 396
    iput-wide v10, v2, Lod0/g0;->h:J

    .line 397
    .line 398
    const/4 v5, 0x4

    .line 399
    iput v5, v2, Lod0/g0;->k:I

    .line 400
    .line 401
    iget-object v5, v1, Lod0/o;->a:Lla/u;

    .line 402
    .line 403
    new-instance v6, Lod0/n;

    .line 404
    .line 405
    const/4 v8, 0x0

    .line 406
    invoke-direct {v6, v8, v1, v4}, Lod0/n;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 407
    .line 408
    .line 409
    const/4 v1, 0x0

    .line 410
    const/4 v8, 0x1

    .line 411
    invoke-static {v2, v5, v1, v8, v6}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 412
    .line 413
    .line 414
    move-result-object v4

    .line 415
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 416
    .line 417
    if-ne v4, v1, :cond_6

    .line 418
    .line 419
    goto :goto_b

    .line 420
    :cond_6
    move-object/from16 v4, v19

    .line 421
    .line 422
    :goto_b
    if-ne v4, v3, :cond_7

    .line 423
    .line 424
    goto/16 :goto_f

    .line 425
    .line 426
    :cond_7
    move-object v1, v12

    .line 427
    move-object v4, v13

    .line 428
    goto/16 :goto_9

    .line 429
    .line 430
    :cond_8
    iget-object v1, v4, Lrd0/r;->e:Ljava/util/List;

    .line 431
    .line 432
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 433
    .line 434
    .line 435
    move-result-object v1

    .line 436
    :goto_c
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 437
    .line 438
    .line 439
    move-result v4

    .line 440
    if-eqz v4, :cond_c

    .line 441
    .line 442
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 443
    .line 444
    .line 445
    move-result-object v4

    .line 446
    check-cast v4, Lao0/a;

    .line 447
    .line 448
    iget-object v5, v0, Lod0/i0;->b:Lti0/a;

    .line 449
    .line 450
    const/4 v8, 0x0

    .line 451
    iput-object v8, v2, Lod0/g0;->d:Ljava/lang/String;

    .line 452
    .line 453
    iput-object v8, v2, Lod0/g0;->e:Lrd0/r;

    .line 454
    .line 455
    iput-object v1, v2, Lod0/g0;->f:Ljava/util/Iterator;

    .line 456
    .line 457
    iput-object v4, v2, Lod0/g0;->g:Ljava/lang/Object;

    .line 458
    .line 459
    iput-wide v10, v2, Lod0/g0;->h:J

    .line 460
    .line 461
    const/4 v6, 0x5

    .line 462
    iput v6, v2, Lod0/g0;->k:I

    .line 463
    .line 464
    invoke-interface {v5, v2}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 465
    .line 466
    .line 467
    move-result-object v5

    .line 468
    if-ne v5, v3, :cond_9

    .line 469
    .line 470
    goto :goto_f

    .line 471
    :cond_9
    move-object v12, v1

    .line 472
    move-object v1, v5

    .line 473
    goto/16 :goto_1

    .line 474
    .line 475
    :goto_d
    check-cast v1, Lod0/i;

    .line 476
    .line 477
    invoke-static {v4, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 478
    .line 479
    .line 480
    new-instance v20, Lod0/j;

    .line 481
    .line 482
    iget-wide v5, v4, Lao0/a;->a:J

    .line 483
    .line 484
    iget-boolean v8, v4, Lao0/a;->b:Z

    .line 485
    .line 486
    iget-object v9, v4, Lao0/a;->c:Ljava/time/LocalTime;

    .line 487
    .line 488
    iget-object v4, v4, Lao0/a;->d:Ljava/time/LocalTime;

    .line 489
    .line 490
    move-object/from16 v27, v4

    .line 491
    .line 492
    move-wide/from16 v21, v5

    .line 493
    .line 494
    move/from16 v25, v8

    .line 495
    .line 496
    move-object/from16 v26, v9

    .line 497
    .line 498
    invoke-direct/range {v20 .. v27}, Lod0/j;-><init>(JJZLjava/time/LocalTime;Ljava/time/LocalTime;)V

    .line 499
    .line 500
    .line 501
    move-object/from16 v4, v20

    .line 502
    .line 503
    move-wide/from16 v10, v23

    .line 504
    .line 505
    const/4 v5, 0x0

    .line 506
    iput-object v5, v2, Lod0/g0;->d:Ljava/lang/String;

    .line 507
    .line 508
    iput-object v5, v2, Lod0/g0;->e:Lrd0/r;

    .line 509
    .line 510
    iput-object v12, v2, Lod0/g0;->f:Ljava/util/Iterator;

    .line 511
    .line 512
    iput-object v5, v2, Lod0/g0;->g:Ljava/lang/Object;

    .line 513
    .line 514
    iput-wide v10, v2, Lod0/g0;->h:J

    .line 515
    .line 516
    const/4 v6, 0x6

    .line 517
    iput v6, v2, Lod0/g0;->k:I

    .line 518
    .line 519
    iget-object v6, v1, Lod0/i;->a:Lla/u;

    .line 520
    .line 521
    new-instance v8, Ll2/v1;

    .line 522
    .line 523
    const/16 v9, 0x1c

    .line 524
    .line 525
    invoke-direct {v8, v9, v1, v4}, Ll2/v1;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 526
    .line 527
    .line 528
    const/4 v1, 0x0

    .line 529
    const/4 v4, 0x1

    .line 530
    invoke-static {v2, v6, v1, v4, v8}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 531
    .line 532
    .line 533
    move-result-object v6

    .line 534
    sget-object v8, Lqx0/a;->d:Lqx0/a;

    .line 535
    .line 536
    if-ne v6, v8, :cond_a

    .line 537
    .line 538
    goto :goto_e

    .line 539
    :cond_a
    move-object/from16 v6, v19

    .line 540
    .line 541
    :goto_e
    if-ne v6, v3, :cond_b

    .line 542
    .line 543
    :goto_f
    return-object v3

    .line 544
    :cond_b
    :goto_10
    move-object v1, v12

    .line 545
    goto :goto_c

    .line 546
    :cond_c
    return-object v19

    .line 547
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p1, Lod0/c0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lod0/c0;

    .line 7
    .line 8
    iget v1, v0, Lod0/c0;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lod0/c0;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lod0/c0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lod0/c0;-><init>(Lod0/i0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lod0/c0;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lod0/c0;->f:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    const/4 v5, 0x1

    .line 35
    packed-switch v2, :pswitch_data_0

    .line 36
    .line 37
    .line 38
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 39
    .line 40
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 41
    .line 42
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    throw p0

    .line 46
    :pswitch_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    return-object v4

    .line 50
    :pswitch_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    goto/16 :goto_a

    .line 54
    .line 55
    :pswitch_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    goto/16 :goto_9

    .line 59
    .line 60
    :pswitch_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    goto/16 :goto_7

    .line 64
    .line 65
    :pswitch_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    goto :goto_6

    .line 69
    :pswitch_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    goto :goto_4

    .line 73
    :pswitch_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    goto :goto_3

    .line 77
    :pswitch_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    goto :goto_1

    .line 81
    :pswitch_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    iget-object p1, p0, Lod0/i0;->f:Lwe0/a;

    .line 85
    .line 86
    check-cast p1, Lwe0/c;

    .line 87
    .line 88
    invoke-virtual {p1}, Lwe0/c;->a()V

    .line 89
    .line 90
    .line 91
    iput v5, v0, Lod0/c0;->f:I

    .line 92
    .line 93
    iget-object p1, p0, Lod0/i0;->b:Lti0/a;

    .line 94
    .line 95
    invoke-interface {p1, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object p1

    .line 99
    if-ne p1, v1, :cond_1

    .line 100
    .line 101
    goto/16 :goto_c

    .line 102
    .line 103
    :cond_1
    :goto_1
    check-cast p1, Lod0/i;

    .line 104
    .line 105
    const/4 v2, 0x2

    .line 106
    iput v2, v0, Lod0/c0;->f:I

    .line 107
    .line 108
    iget-object p1, p1, Lod0/i;->a:Lla/u;

    .line 109
    .line 110
    new-instance v2, Lod0/g;

    .line 111
    .line 112
    const/4 v6, 0x2

    .line 113
    invoke-direct {v2, v6}, Lod0/g;-><init>(I)V

    .line 114
    .line 115
    .line 116
    invoke-static {v0, p1, v3, v5, v2}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    if-ne p1, v1, :cond_2

    .line 121
    .line 122
    goto :goto_2

    .line 123
    :cond_2
    move-object p1, v4

    .line 124
    :goto_2
    if-ne p1, v1, :cond_3

    .line 125
    .line 126
    goto/16 :goto_c

    .line 127
    .line 128
    :cond_3
    :goto_3
    const/4 p1, 0x3

    .line 129
    iput p1, v0, Lod0/c0;->f:I

    .line 130
    .line 131
    iget-object p1, p0, Lod0/i0;->c:Lti0/a;

    .line 132
    .line 133
    invoke-interface {p1, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object p1

    .line 137
    if-ne p1, v1, :cond_4

    .line 138
    .line 139
    goto :goto_c

    .line 140
    :cond_4
    :goto_4
    check-cast p1, Lod0/o;

    .line 141
    .line 142
    const/4 v2, 0x4

    .line 143
    iput v2, v0, Lod0/c0;->f:I

    .line 144
    .line 145
    iget-object p1, p1, Lod0/o;->a:Lla/u;

    .line 146
    .line 147
    new-instance v2, Lod0/g;

    .line 148
    .line 149
    const/4 v6, 0x4

    .line 150
    invoke-direct {v2, v6}, Lod0/g;-><init>(I)V

    .line 151
    .line 152
    .line 153
    invoke-static {v0, p1, v3, v5, v2}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    move-result-object p1

    .line 157
    if-ne p1, v1, :cond_5

    .line 158
    .line 159
    goto :goto_5

    .line 160
    :cond_5
    move-object p1, v4

    .line 161
    :goto_5
    if-ne p1, v1, :cond_6

    .line 162
    .line 163
    goto :goto_c

    .line 164
    :cond_6
    :goto_6
    const/4 p1, 0x5

    .line 165
    iput p1, v0, Lod0/c0;->f:I

    .line 166
    .line 167
    iget-object p1, p0, Lod0/i0;->a:Lti0/a;

    .line 168
    .line 169
    invoke-interface {p1, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object p1

    .line 173
    if-ne p1, v1, :cond_7

    .line 174
    .line 175
    goto :goto_c

    .line 176
    :cond_7
    :goto_7
    check-cast p1, Lod0/k;

    .line 177
    .line 178
    const/4 v2, 0x6

    .line 179
    iput v2, v0, Lod0/c0;->f:I

    .line 180
    .line 181
    iget-object p1, p1, Lod0/k;->a:Lla/u;

    .line 182
    .line 183
    new-instance v2, Lod0/g;

    .line 184
    .line 185
    const/4 v6, 0x3

    .line 186
    invoke-direct {v2, v6}, Lod0/g;-><init>(I)V

    .line 187
    .line 188
    .line 189
    invoke-static {v0, p1, v3, v5, v2}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object p1

    .line 193
    if-ne p1, v1, :cond_8

    .line 194
    .line 195
    goto :goto_8

    .line 196
    :cond_8
    move-object p1, v4

    .line 197
    :goto_8
    if-ne p1, v1, :cond_9

    .line 198
    .line 199
    goto :goto_c

    .line 200
    :cond_9
    :goto_9
    const/4 p1, 0x7

    .line 201
    iput p1, v0, Lod0/c0;->f:I

    .line 202
    .line 203
    iget-object p0, p0, Lod0/i0;->d:Lti0/a;

    .line 204
    .line 205
    invoke-interface {p0, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object p1

    .line 209
    if-ne p1, v1, :cond_a

    .line 210
    .line 211
    goto :goto_c

    .line 212
    :cond_a
    :goto_a
    check-cast p1, Lod0/q;

    .line 213
    .line 214
    const/16 p0, 0x8

    .line 215
    .line 216
    iput p0, v0, Lod0/c0;->f:I

    .line 217
    .line 218
    iget-object p0, p1, Lod0/q;->a:Lla/u;

    .line 219
    .line 220
    new-instance p1, Lod0/g;

    .line 221
    .line 222
    const/4 v2, 0x6

    .line 223
    invoke-direct {p1, v2}, Lod0/g;-><init>(I)V

    .line 224
    .line 225
    .line 226
    invoke-static {v0, p0, v3, v5, p1}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object p0

    .line 230
    if-ne p0, v1, :cond_b

    .line 231
    .line 232
    goto :goto_b

    .line 233
    :cond_b
    move-object p0, v4

    .line 234
    :goto_b
    if-ne p0, v1, :cond_c

    .line 235
    .line 236
    :goto_c
    return-object v1

    .line 237
    :cond_c
    return-object v4

    .line 238
    nop

    .line 239
    :pswitch_data_0
    .packed-switch 0x0
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
.end method

.method public final c(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p2, Lod0/d0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lod0/d0;

    .line 7
    .line 8
    iget v1, v0, Lod0/d0;->g:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lod0/d0;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lod0/d0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lod0/d0;-><init>(Lod0/i0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lod0/d0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lod0/d0;->g:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x2

    .line 33
    const/4 v5, 0x1

    .line 34
    if-eqz v2, :cond_3

    .line 35
    .line 36
    if-eq v2, v5, :cond_2

    .line 37
    .line 38
    if-ne v2, v4, :cond_1

    .line 39
    .line 40
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    goto :goto_3

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    iget-object p1, v0, Lod0/d0;->d:Ljava/lang/String;

    .line 53
    .line 54
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    iput-object p1, v0, Lod0/d0;->d:Ljava/lang/String;

    .line 62
    .line 63
    iput v5, v0, Lod0/d0;->g:I

    .line 64
    .line 65
    iget-object p0, p0, Lod0/i0;->d:Lti0/a;

    .line 66
    .line 67
    invoke-interface {p0, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object p2

    .line 71
    if-ne p2, v1, :cond_4

    .line 72
    .line 73
    goto :goto_2

    .line 74
    :cond_4
    :goto_1
    check-cast p2, Lod0/q;

    .line 75
    .line 76
    const/4 p0, 0x0

    .line 77
    iput-object p0, v0, Lod0/d0;->d:Ljava/lang/String;

    .line 78
    .line 79
    iput v4, v0, Lod0/d0;->g:I

    .line 80
    .line 81
    iget-object p0, p2, Lod0/q;->a:Lla/u;

    .line 82
    .line 83
    new-instance v2, Lod0/d;

    .line 84
    .line 85
    const/4 v4, 0x2

    .line 86
    invoke-direct {v2, p1, v4, p2}, Lod0/d;-><init>(Ljava/lang/String;ILjava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    invoke-static {v0, p0, v5, v3, v2}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object p2

    .line 93
    if-ne p2, v1, :cond_5

    .line 94
    .line 95
    :goto_2
    return-object v1

    .line 96
    :cond_5
    :goto_3
    if-eqz p2, :cond_6

    .line 97
    .line 98
    move v3, v5

    .line 99
    :cond_6
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    return-object p0
.end method

.method public final d(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lod0/e0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lod0/e0;

    .line 7
    .line 8
    iget v1, v0, Lod0/e0;->g:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lod0/e0;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lod0/e0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lod0/e0;-><init>(Lod0/i0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lod0/e0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lod0/e0;->g:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p1, v0, Lod0/e0;->d:Ljava/lang/String;

    .line 37
    .line 38
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iput-object p1, v0, Lod0/e0;->d:Ljava/lang/String;

    .line 54
    .line 55
    iput v3, v0, Lod0/e0;->g:I

    .line 56
    .line 57
    iget-object p2, p0, Lod0/i0;->d:Lti0/a;

    .line 58
    .line 59
    invoke-interface {p2, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p2

    .line 63
    if-ne p2, v1, :cond_3

    .line 64
    .line 65
    return-object v1

    .line 66
    :cond_3
    :goto_1
    check-cast p2, Lod0/q;

    .line 67
    .line 68
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 69
    .line 70
    .line 71
    const-string v0, "vin"

    .line 72
    .line 73
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    iget-object v0, p2, Lod0/q;->a:Lla/u;

    .line 77
    .line 78
    const-string v1, "charging_profiles"

    .line 79
    .line 80
    filled-new-array {v1}, [Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object v1

    .line 84
    new-instance v2, Lod0/d;

    .line 85
    .line 86
    const/4 v3, 0x4

    .line 87
    invoke-direct {v2, p1, v3, p2}, Lod0/d;-><init>(Ljava/lang/String;ILjava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    const/4 p1, 0x0

    .line 91
    invoke-static {v0, p1, v1, v2}, Ljp/ga;->a(Lla/u;Z[Ljava/lang/String;Lay0/k;)Lna/j;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    new-instance p2, Lrz/k;

    .line 96
    .line 97
    const/16 v0, 0x15

    .line 98
    .line 99
    invoke-direct {p2, p1, v0}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 100
    .line 101
    .line 102
    new-instance p1, Llb0/y;

    .line 103
    .line 104
    const/4 v0, 0x4

    .line 105
    invoke-direct {p1, v0, p2, p0}, Llb0/y;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    return-object p1
.end method
