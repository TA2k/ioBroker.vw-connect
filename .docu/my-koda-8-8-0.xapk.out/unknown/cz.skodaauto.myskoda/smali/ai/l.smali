.class public final Lai/l;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:La50/d;

.field public final e:Lxh/e;

.field public final f:La71/a0;

.field public final g:I

.field public final h:Lai/d;

.field public final i:Ljava/lang/String;

.field public final j:Lyy0/c2;

.field public final k:Lyy0/c2;

.field public final l:Llx0/q;

.field public m:Ljava/lang/Object;


# direct methods
.method public constructor <init>(La50/d;Lx40/j;Lxh/e;Lzb/d;Lag/c;Lag/c;La71/a0;Lai/d;Lxh/e;Lxh/e;Lxh/e;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lai/l;->d:La50/d;

    .line 5
    .line 6
    iput-object p3, p0, Lai/l;->e:Lxh/e;

    .line 7
    .line 8
    iput-object p7, p0, Lai/l;->f:La71/a0;

    .line 9
    .line 10
    const p1, 0x7fffffff

    .line 11
    .line 12
    .line 13
    iput p1, p0, Lai/l;->g:I

    .line 14
    .line 15
    iput-object p8, p0, Lai/l;->h:Lai/d;

    .line 16
    .line 17
    iput-object p12, p0, Lai/l;->i:Ljava/lang/String;

    .line 18
    .line 19
    new-instance p1, Llc/q;

    .line 20
    .line 21
    sget-object p2, Llc/a;->c:Llc/c;

    .line 22
    .line 23
    invoke-direct {p1, p2}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    iput-object p1, p0, Lai/l;->j:Lyy0/c2;

    .line 31
    .line 32
    iput-object p1, p0, Lai/l;->k:Lyy0/c2;

    .line 33
    .line 34
    invoke-static {p0}, Lzb/b;->F(Landroidx/lifecycle/b1;)Llx0/q;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    iput-object p1, p0, Lai/l;->l:Llx0/q;

    .line 39
    .line 40
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    .line 41
    .line 42
    iput-object p1, p0, Lai/l;->m:Ljava/lang/Object;

    .line 43
    .line 44
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    new-instance p2, Lai/j;

    .line 49
    .line 50
    const/4 p3, 0x0

    .line 51
    const/4 p4, 0x0

    .line 52
    invoke-direct {p2, p0, p4, p3}, Lai/j;-><init>(Lai/l;Lkotlin/coroutines/Continuation;I)V

    .line 53
    .line 54
    .line 55
    const/4 p0, 0x3

    .line 56
    invoke-static {p1, p4, p4, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 57
    .line 58
    .line 59
    return-void
.end method

.method public static final a(Lai/l;Lzg/z0;)V
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    move-object/from16 v1, p1

    .line 7
    .line 8
    iget-object v1, v1, Lzg/z0;->a:Ljava/util/List;

    .line 9
    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Ljava/lang/Iterable;

    .line 12
    .line 13
    new-instance v3, Ljava/util/ArrayList;

    .line 14
    .line 15
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 16
    .line 17
    .line 18
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 19
    .line 20
    .line 21
    move-result-object v4

    .line 22
    :cond_0
    :goto_0
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 23
    .line 24
    .line 25
    move-result v5

    .line 26
    if-eqz v5, :cond_1

    .line 27
    .line 28
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v5

    .line 32
    instance-of v6, v5, Lzg/o0;

    .line 33
    .line 34
    if-eqz v6, :cond_0

    .line 35
    .line 36
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_1
    invoke-virtual {v3}, Ljava/util/ArrayList;->isEmpty()Z

    .line 41
    .line 42
    .line 43
    move-result v3

    .line 44
    if-eqz v3, :cond_2

    .line 45
    .line 46
    iget-object v3, v0, Lai/l;->e:Lxh/e;

    .line 47
    .line 48
    sget-object v4, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 49
    .line 50
    invoke-virtual {v3, v4}, Lxh/e;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    :cond_2
    new-instance v3, Ljava/util/ArrayList;

    .line 54
    .line 55
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 56
    .line 57
    .line 58
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 59
    .line 60
    .line 61
    move-result-object v2

    .line 62
    :cond_3
    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 63
    .line 64
    .line 65
    move-result v4

    .line 66
    if-eqz v4, :cond_4

    .line 67
    .line 68
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v4

    .line 72
    instance-of v5, v4, Lzg/o0;

    .line 73
    .line 74
    if-eqz v5, :cond_3

    .line 75
    .line 76
    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    goto :goto_1

    .line 80
    :cond_4
    iput-object v3, v0, Lai/l;->m:Ljava/lang/Object;

    .line 81
    .line 82
    iget-object v2, v0, Lai/l;->h:Lai/d;

    .line 83
    .line 84
    const-string v3, "chargingInfrastructures"

    .line 85
    .line 86
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    const-string v3, "downloadImage"

    .line 90
    .line 91
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    check-cast v1, Ljava/lang/Iterable;

    .line 95
    .line 96
    new-instance v3, Ljava/util/ArrayList;

    .line 97
    .line 98
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 99
    .line 100
    .line 101
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 102
    .line 103
    .line 104
    move-result-object v4

    .line 105
    :cond_5
    :goto_2
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 106
    .line 107
    .line 108
    move-result v5

    .line 109
    if-eqz v5, :cond_6

    .line 110
    .line 111
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v5

    .line 115
    instance-of v6, v5, Lzg/o0;

    .line 116
    .line 117
    if-eqz v6, :cond_5

    .line 118
    .line 119
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    goto :goto_2

    .line 123
    :cond_6
    new-instance v4, Ljava/util/ArrayList;

    .line 124
    .line 125
    const/16 v5, 0xa

    .line 126
    .line 127
    invoke-static {v3, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 128
    .line 129
    .line 130
    move-result v6

    .line 131
    invoke-direct {v4, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 132
    .line 133
    .line 134
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 135
    .line 136
    .line 137
    move-result-object v3

    .line 138
    :goto_3
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 139
    .line 140
    .line 141
    move-result v6

    .line 142
    if-eqz v6, :cond_7

    .line 143
    .line 144
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v6

    .line 148
    check-cast v6, Lzg/o0;

    .line 149
    .line 150
    iget-object v6, v6, Lzg/o0;->b:Lzg/h;

    .line 151
    .line 152
    invoke-virtual {v4, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 153
    .line 154
    .line 155
    goto :goto_3

    .line 156
    :cond_7
    new-instance v3, Ljava/util/ArrayList;

    .line 157
    .line 158
    invoke-static {v4, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 159
    .line 160
    .line 161
    move-result v6

    .line 162
    invoke-direct {v3, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 163
    .line 164
    .line 165
    invoke-virtual {v4}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 166
    .line 167
    .line 168
    move-result-object v4

    .line 169
    :goto_4
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 170
    .line 171
    .line 172
    move-result v6

    .line 173
    if-eqz v6, :cond_11

    .line 174
    .line 175
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object v6

    .line 179
    check-cast v6, Lzg/h;

    .line 180
    .line 181
    iget-object v10, v6, Lzg/h;->i:Ljava/lang/String;

    .line 182
    .line 183
    iget-object v11, v6, Lzg/h;->h:Ljava/lang/String;

    .line 184
    .line 185
    iget-object v9, v6, Lzg/h;->p:Ljava/lang/Boolean;

    .line 186
    .line 187
    sget-object v12, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 188
    .line 189
    invoke-static {v9, v12}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 190
    .line 191
    .line 192
    move-result v12

    .line 193
    iget-object v9, v6, Lzg/h;->e:Lzg/g;

    .line 194
    .line 195
    const-string v13, "<this>"

    .line 196
    .line 197
    invoke-static {v9, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 198
    .line 199
    .line 200
    invoke-virtual {v9}, Ljava/lang/Enum;->ordinal()I

    .line 201
    .line 202
    .line 203
    move-result v13

    .line 204
    packed-switch v13, :pswitch_data_0

    .line 205
    .line 206
    .line 207
    new-instance v0, La8/r0;

    .line 208
    .line 209
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 210
    .line 211
    .line 212
    throw v0

    .line 213
    :pswitch_0
    sget-object v13, Lgh/a;->f:Lgh/a;

    .line 214
    .line 215
    goto :goto_5

    .line 216
    :pswitch_1
    sget-object v13, Lgh/a;->h:Lgh/a;

    .line 217
    .line 218
    goto :goto_5

    .line 219
    :pswitch_2
    sget-object v13, Lgh/a;->g:Lgh/a;

    .line 220
    .line 221
    goto :goto_5

    .line 222
    :pswitch_3
    sget-object v13, Lgh/a;->e:Lgh/a;

    .line 223
    .line 224
    goto :goto_5

    .line 225
    :pswitch_4
    sget-object v13, Lgh/a;->d:Lgh/a;

    .line 226
    .line 227
    :goto_5
    iget-object v14, v6, Lzg/h;->m:Ljava/lang/String;

    .line 228
    .line 229
    const-string v15, ""

    .line 230
    .line 231
    move-object/from16 v16, v14

    .line 232
    .line 233
    if-nez v14, :cond_8

    .line 234
    .line 235
    move-object v14, v15

    .line 236
    :cond_8
    iget-object v7, v6, Lzg/h;->k:Ljava/lang/String;

    .line 237
    .line 238
    if-nez v7, :cond_9

    .line 239
    .line 240
    goto :goto_6

    .line 241
    :cond_9
    move-object v15, v7

    .line 242
    :goto_6
    if-eqz v16, :cond_a

    .line 243
    .line 244
    const/16 v17, 0x1

    .line 245
    .line 246
    goto :goto_7

    .line 247
    :cond_a
    const/16 v17, 0x0

    .line 248
    .line 249
    :goto_7
    if-eqz v7, :cond_b

    .line 250
    .line 251
    const/16 v16, 0x1

    .line 252
    .line 253
    goto :goto_8

    .line 254
    :cond_b
    const/16 v16, 0x0

    .line 255
    .line 256
    :goto_8
    iget-boolean v7, v6, Lzg/h;->v:Z

    .line 257
    .line 258
    sget-object v8, Lzg/g;->e:Lzg/g;

    .line 259
    .line 260
    if-ne v9, v8, :cond_c

    .line 261
    .line 262
    const/16 v18, 0x1

    .line 263
    .line 264
    goto :goto_9

    .line 265
    :cond_c
    const/16 v18, 0x0

    .line 266
    .line 267
    :goto_9
    sget-object v8, Lzg/g;->g:Lzg/g;

    .line 268
    .line 269
    if-ne v9, v8, :cond_d

    .line 270
    .line 271
    const/16 v19, 0x1

    .line 272
    .line 273
    goto :goto_a

    .line 274
    :cond_d
    const/16 v19, 0x0

    .line 275
    .line 276
    :goto_a
    sget-object v8, Lzg/g;->i:Lzg/g;

    .line 277
    .line 278
    if-ne v9, v8, :cond_e

    .line 279
    .line 280
    const/16 v20, 0x1

    .line 281
    .line 282
    goto :goto_b

    .line 283
    :cond_e
    const/16 v20, 0x0

    .line 284
    .line 285
    :goto_b
    sget-object v8, Lzg/g;->f:Lzg/g;

    .line 286
    .line 287
    if-ne v9, v8, :cond_f

    .line 288
    .line 289
    const/16 v21, 0x1

    .line 290
    .line 291
    goto :goto_c

    .line 292
    :cond_f
    const/16 v21, 0x0

    .line 293
    .line 294
    :goto_c
    iget-object v8, v6, Lzg/h;->d:Ljava/util/List;

    .line 295
    .line 296
    check-cast v8, Ljava/lang/Iterable;

    .line 297
    .line 298
    new-instance v9, Ljava/util/ArrayList;

    .line 299
    .line 300
    move-object/from16 v25, v4

    .line 301
    .line 302
    invoke-static {v8, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 303
    .line 304
    .line 305
    move-result v4

    .line 306
    invoke-direct {v9, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 307
    .line 308
    .line 309
    invoke-interface {v8}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 310
    .line 311
    .line 312
    move-result-object v4

    .line 313
    :goto_d
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 314
    .line 315
    .line 316
    move-result v8

    .line 317
    if-eqz v8, :cond_10

    .line 318
    .line 319
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 320
    .line 321
    .line 322
    move-result-object v8

    .line 323
    invoke-virtual {v2, v8}, Lai/d;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 324
    .line 325
    .line 326
    move-result-object v8

    .line 327
    invoke-virtual {v9, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 328
    .line 329
    .line 330
    goto :goto_d

    .line 331
    :cond_10
    iget-object v4, v6, Lzg/h;->f:Ljava/lang/String;

    .line 332
    .line 333
    move-object/from16 v23, v9

    .line 334
    .line 335
    new-instance v9, Lai/b;

    .line 336
    .line 337
    move-object/from16 v22, v4

    .line 338
    .line 339
    move/from16 v24, v7

    .line 340
    .line 341
    invoke-direct/range {v9 .. v24}, Lai/b;-><init>(Ljava/lang/String;Ljava/lang/String;ZLgh/a;Ljava/lang/String;Ljava/lang/String;ZZZZZZLjava/lang/String;Ljava/util/ArrayList;Z)V

    .line 342
    .line 343
    .line 344
    invoke-virtual {v3, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 345
    .line 346
    .line 347
    move-object/from16 v4, v25

    .line 348
    .line 349
    goto/16 :goto_4

    .line 350
    .line 351
    :cond_11
    new-instance v2, Ljava/util/ArrayList;

    .line 352
    .line 353
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 354
    .line 355
    .line 356
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 357
    .line 358
    .line 359
    move-result-object v4

    .line 360
    :cond_12
    :goto_e
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 361
    .line 362
    .line 363
    move-result v5

    .line 364
    if-eqz v5, :cond_13

    .line 365
    .line 366
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 367
    .line 368
    .line 369
    move-result-object v5

    .line 370
    instance-of v6, v5, Lzg/v0;

    .line 371
    .line 372
    if-eqz v6, :cond_12

    .line 373
    .line 374
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 375
    .line 376
    .line 377
    goto :goto_e

    .line 378
    :cond_13
    invoke-static {v2}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 379
    .line 380
    .line 381
    move-result-object v2

    .line 382
    check-cast v2, Lzg/v0;

    .line 383
    .line 384
    instance-of v4, v1, Ljava/util/Collection;

    .line 385
    .line 386
    if-eqz v4, :cond_14

    .line 387
    .line 388
    move-object v4, v1

    .line 389
    check-cast v4, Ljava/util/Collection;

    .line 390
    .line 391
    invoke-interface {v4}, Ljava/util/Collection;->isEmpty()Z

    .line 392
    .line 393
    .line 394
    move-result v4

    .line 395
    if-eqz v4, :cond_14

    .line 396
    .line 397
    goto :goto_f

    .line 398
    :cond_14
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 399
    .line 400
    .line 401
    move-result-object v1

    .line 402
    :cond_15
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 403
    .line 404
    .line 405
    move-result v4

    .line 406
    if-eqz v4, :cond_16

    .line 407
    .line 408
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 409
    .line 410
    .line 411
    move-result-object v4

    .line 412
    check-cast v4, Lzg/w0;

    .line 413
    .line 414
    instance-of v4, v4, Lzg/s0;

    .line 415
    .line 416
    if-eqz v4, :cond_15

    .line 417
    .line 418
    sget-object v1, Lai/g;->d:Lai/g;

    .line 419
    .line 420
    goto :goto_10

    .line 421
    :cond_16
    :goto_f
    if-eqz v2, :cond_17

    .line 422
    .line 423
    invoke-virtual {v3}, Ljava/util/ArrayList;->isEmpty()Z

    .line 424
    .line 425
    .line 426
    move-result v1

    .line 427
    if-nez v1, :cond_17

    .line 428
    .line 429
    sget-object v1, Lai/g;->e:Lai/g;

    .line 430
    .line 431
    goto :goto_10

    .line 432
    :cond_17
    sget-object v1, Lai/g;->f:Lai/g;

    .line 433
    .line 434
    :goto_10
    invoke-static {}, Ljp/k1;->f()Lnx0/c;

    .line 435
    .line 436
    .line 437
    move-result-object v4

    .line 438
    invoke-virtual {v4, v3}, Lnx0/c;->addAll(Ljava/util/Collection;)Z

    .line 439
    .line 440
    .line 441
    const/4 v5, 0x0

    .line 442
    if-eqz v2, :cond_18

    .line 443
    .line 444
    iget-object v2, v2, Lzg/v0;->b:Lzg/h1;

    .line 445
    .line 446
    goto :goto_11

    .line 447
    :cond_18
    move-object v2, v5

    .line 448
    :goto_11
    invoke-static {v3}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 449
    .line 450
    .line 451
    move-result-object v6

    .line 452
    move-object v7, v6

    .line 453
    check-cast v7, Lai/b;

    .line 454
    .line 455
    sget-object v7, Lai/g;->d:Lai/g;

    .line 456
    .line 457
    if-eq v1, v7, :cond_19

    .line 458
    .line 459
    goto :goto_12

    .line 460
    :cond_19
    move-object v6, v5

    .line 461
    :goto_12
    check-cast v6, Lai/b;

    .line 462
    .line 463
    new-instance v7, Lai/a;

    .line 464
    .line 465
    invoke-direct {v7, v2, v6}, Lai/a;-><init>(Lzg/h1;Lai/b;)V

    .line 466
    .line 467
    .line 468
    invoke-virtual {v4, v7}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 469
    .line 470
    .line 471
    invoke-static {v4}, Ljp/k1;->d(Ljava/util/List;)Lnx0/c;

    .line 472
    .line 473
    .line 474
    move-result-object v2

    .line 475
    invoke-virtual {v3}, Ljava/util/ArrayList;->isEmpty()Z

    .line 476
    .line 477
    .line 478
    move-result v4

    .line 479
    if-eqz v4, :cond_1b

    .line 480
    .line 481
    :cond_1a
    const/4 v7, 0x0

    .line 482
    goto :goto_13

    .line 483
    :cond_1b
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 484
    .line 485
    .line 486
    move-result-object v3

    .line 487
    :cond_1c
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 488
    .line 489
    .line 490
    move-result v4

    .line 491
    if-eqz v4, :cond_1a

    .line 492
    .line 493
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 494
    .line 495
    .line 496
    move-result-object v4

    .line 497
    check-cast v4, Lai/b;

    .line 498
    .line 499
    iget-boolean v4, v4, Lai/b;->o:Z

    .line 500
    .line 501
    if-eqz v4, :cond_1c

    .line 502
    .line 503
    const/4 v7, 0x1

    .line 504
    :goto_13
    new-instance v3, Lai/h;

    .line 505
    .line 506
    invoke-direct {v3, v2, v7, v1}, Lai/h;-><init>(Lnx0/c;ZLai/g;)V

    .line 507
    .line 508
    .line 509
    check-cast v2, Ljava/lang/Iterable;

    .line 510
    .line 511
    new-instance v1, Ljava/util/ArrayList;

    .line 512
    .line 513
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 514
    .line 515
    .line 516
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 517
    .line 518
    .line 519
    move-result-object v2

    .line 520
    :cond_1d
    :goto_14
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 521
    .line 522
    .line 523
    move-result v4

    .line 524
    if-eqz v4, :cond_1e

    .line 525
    .line 526
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 527
    .line 528
    .line 529
    move-result-object v4

    .line 530
    instance-of v6, v4, Lai/a;

    .line 531
    .line 532
    if-eqz v6, :cond_1d

    .line 533
    .line 534
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 535
    .line 536
    .line 537
    goto :goto_14

    .line 538
    :cond_1e
    invoke-static {v1}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 539
    .line 540
    .line 541
    move-result-object v1

    .line 542
    check-cast v1, Lai/a;

    .line 543
    .line 544
    iget-object v0, v0, Lai/l;->j:Lyy0/c2;

    .line 545
    .line 546
    new-instance v1, Llc/q;

    .line 547
    .line 548
    invoke-direct {v1, v3}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 549
    .line 550
    .line 551
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 552
    .line 553
    .line 554
    invoke-virtual {v0, v5, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 555
    .line 556
    .line 557
    return-void

    .line 558
    nop

    .line 559
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_2
        :pswitch_3
        :pswitch_1
        :pswitch_0
        :pswitch_4
        :pswitch_3
    .end packed-switch
.end method


# virtual methods
.method public final b()Lzb/k0;
    .locals 0

    .line 1
    iget-object p0, p0, Lai/l;->l:Llx0/q;

    .line 2
    .line 3
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lzb/k0;

    .line 8
    .line 9
    return-object p0
.end method
