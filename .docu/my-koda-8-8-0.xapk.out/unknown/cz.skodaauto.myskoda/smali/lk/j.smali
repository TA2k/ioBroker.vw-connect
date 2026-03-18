.class public final synthetic Llk/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILay0/k;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Llk/j;->d:I

    iput-object p3, p0, Llk/j;->f:Ljava/lang/Object;

    iput-object p2, p0, Llk/j;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 2
    iput p1, p0, Llk/j;->d:I

    iput-object p2, p0, Llk/j;->e:Ljava/lang/Object;

    iput-object p3, p0, Llk/j;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 32

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Llk/j;->d:I

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x1

    .line 7
    const/4 v4, 0x0

    .line 8
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 9
    .line 10
    iget-object v6, v0, Llk/j;->f:Ljava/lang/Object;

    .line 11
    .line 12
    iget-object v0, v0, Llk/j;->e:Ljava/lang/Object;

    .line 13
    .line 14
    packed-switch v1, :pswitch_data_0

    .line 15
    .line 16
    .line 17
    check-cast v0, Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;

    .line 18
    .line 19
    check-cast v6, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;

    .line 20
    .line 21
    invoke-static {v0, v6}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->m(Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    return-object v0

    .line 26
    :pswitch_0
    check-cast v0, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;

    .line 27
    .line 28
    check-cast v6, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;

    .line 29
    .line 30
    invoke-static {v0, v6}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->a(Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    return-object v0

    .line 35
    :pswitch_1
    check-cast v0, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;

    .line 36
    .line 37
    check-cast v6, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;

    .line 38
    .line 39
    invoke-static {v0, v6}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->i(Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    return-object v0

    .line 44
    :pswitch_2
    check-cast v0, Lay0/k;

    .line 45
    .line 46
    check-cast v6, Ln50/a0;

    .line 47
    .line 48
    iget-object v1, v6, Ln50/a0;->e:Lqp0/b0;

    .line 49
    .line 50
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    return-object v5

    .line 54
    :pswitch_3
    check-cast v0, Lay0/k;

    .line 55
    .line 56
    check-cast v6, Ln50/m;

    .line 57
    .line 58
    invoke-interface {v0, v6}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    return-object v5

    .line 62
    :pswitch_4
    check-cast v0, Lay0/k;

    .line 63
    .line 64
    check-cast v6, Ln50/f;

    .line 65
    .line 66
    invoke-interface {v0, v6}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    return-object v5

    .line 70
    :pswitch_5
    check-cast v0, Lu2/g;

    .line 71
    .line 72
    check-cast v6, Lu2/c;

    .line 73
    .line 74
    new-instance v1, Lo1/v0;

    .line 75
    .line 76
    sget-object v2, Lmx0/t;->d:Lmx0/t;

    .line 77
    .line 78
    invoke-direct {v1, v0, v2, v6}, Lo1/v0;-><init>(Lu2/g;Ljava/util/Map;Lu2/c;)V

    .line 79
    .line 80
    .line 81
    return-object v1

    .line 82
    :pswitch_6
    check-cast v0, Lnz/z;

    .line 83
    .line 84
    iget-object v1, v0, Lnz/z;->i:Lij0/a;

    .line 85
    .line 86
    check-cast v6, Lcn0/c;

    .line 87
    .line 88
    iget-object v4, v6, Lcn0/c;->e:Lcn0/a;

    .line 89
    .line 90
    sget-object v7, Lcn0/a;->v:Lcn0/a;

    .line 91
    .line 92
    if-ne v4, v7, :cond_0

    .line 93
    .line 94
    sget v2, Lnz/z;->B:I

    .line 95
    .line 96
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 97
    .line 98
    .line 99
    move-result-object v2

    .line 100
    move-object v6, v2

    .line 101
    check-cast v6, Lnz/s;

    .line 102
    .line 103
    const-string v2, "<this>"

    .line 104
    .line 105
    invoke-static {v6, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    const-string v2, "stringResource"

    .line 109
    .line 110
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    invoke-static {v1}, Ljp/za;->d(Lij0/a;)Lbo0/l;

    .line 114
    .line 115
    .line 116
    move-result-object v19

    .line 117
    const/16 v30, 0x0

    .line 118
    .line 119
    const v31, 0xfff7fff

    .line 120
    .line 121
    .line 122
    const/4 v7, 0x0

    .line 123
    const/4 v8, 0x0

    .line 124
    const/4 v9, 0x0

    .line 125
    const/4 v10, 0x0

    .line 126
    const/4 v11, 0x0

    .line 127
    const/4 v12, 0x0

    .line 128
    const/4 v13, 0x0

    .line 129
    const/4 v14, 0x0

    .line 130
    const/4 v15, 0x0

    .line 131
    const/16 v16, 0x0

    .line 132
    .line 133
    const/16 v17, 0x0

    .line 134
    .line 135
    const/16 v18, 0x0

    .line 136
    .line 137
    const/16 v20, 0x0

    .line 138
    .line 139
    const/16 v21, 0x0

    .line 140
    .line 141
    const/16 v22, 0x0

    .line 142
    .line 143
    const/16 v23, 0x0

    .line 144
    .line 145
    const/16 v24, 0x0

    .line 146
    .line 147
    const/16 v25, 0x0

    .line 148
    .line 149
    const/16 v26, 0x0

    .line 150
    .line 151
    const/16 v27, 0x0

    .line 152
    .line 153
    const/16 v28, 0x0

    .line 154
    .line 155
    const/16 v29, 0x0

    .line 156
    .line 157
    invoke-static/range {v6 .. v31}, Lnz/s;->a(Lnz/s;Ler0/g;Llf0/i;ZZZZZZLjava/lang/String;Ljava/lang/String;Lnz/r;Lnz/q;Lbo0/l;Lnz/p;ZZLjava/lang/String;Lmz/a;Lqr0/q;Lqr0/q;Lmy0/c;ZLmb0/c;ZI)Lnz/s;

    .line 158
    .line 159
    .line 160
    move-result-object v1

    .line 161
    goto :goto_0

    .line 162
    :cond_0
    sget v4, Lnz/z;->B:I

    .line 163
    .line 164
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 165
    .line 166
    .line 167
    move-result-object v4

    .line 168
    check-cast v4, Lnz/s;

    .line 169
    .line 170
    iget-object v6, v6, Lcn0/c;->e:Lcn0/a;

    .line 171
    .line 172
    sget-object v7, Lcn0/a;->s:Lcn0/a;

    .line 173
    .line 174
    if-ne v6, v7, :cond_1

    .line 175
    .line 176
    move v2, v3

    .line 177
    :cond_1
    invoke-static {v4, v1, v2}, Ljp/gb;->i(Lnz/s;Lij0/a;Z)Lnz/s;

    .line 178
    .line 179
    .line 180
    move-result-object v1

    .line 181
    :goto_0
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 182
    .line 183
    .line 184
    return-object v5

    .line 185
    :pswitch_7
    check-cast v0, Lay0/k;

    .line 186
    .line 187
    check-cast v6, Lz9/y;

    .line 188
    .line 189
    iget-object v1, v6, Lz9/y;->b:Lca/g;

    .line 190
    .line 191
    invoke-virtual {v1}, Lca/g;->h()Lz9/u;

    .line 192
    .line 193
    .line 194
    move-result-object v1

    .line 195
    if-eqz v1, :cond_2

    .line 196
    .line 197
    iget-object v1, v1, Lz9/u;->e:Lca/j;

    .line 198
    .line 199
    iget-object v1, v1, Lca/j;->e:Ljava/lang/Object;

    .line 200
    .line 201
    move-object v4, v1

    .line 202
    check-cast v4, Ljava/lang/String;

    .line 203
    .line 204
    :cond_2
    invoke-static {v4}, Lrp/d;->b(Ljava/lang/String;)Lly/b;

    .line 205
    .line 206
    .line 207
    move-result-object v1

    .line 208
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    return-object v5

    .line 212
    :pswitch_8
    move-object v8, v0

    .line 213
    check-cast v8, Lne0/c;

    .line 214
    .line 215
    check-cast v6, Ld01/k0;

    .line 216
    .line 217
    new-instance v7, Ljava/lang/IllegalStateException;

    .line 218
    .line 219
    iget-object v0, v6, Ld01/k0;->a:Ld01/a0;

    .line 220
    .line 221
    new-instance v1, Ljava/lang/StringBuilder;

    .line 222
    .line 223
    const-string v2, "Unable to refresh access token while requesting "

    .line 224
    .line 225
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 226
    .line 227
    .line 228
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 229
    .line 230
    .line 231
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 232
    .line 233
    .line 234
    move-result-object v0

    .line 235
    invoke-direct {v7, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 236
    .line 237
    .line 238
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 239
    .line 240
    .line 241
    move-result-wide v10

    .line 242
    sget-object v0, Lne0/b;->e:Lne0/b;

    .line 243
    .line 244
    iget-object v1, v8, Lne0/c;->e:Lne0/b;

    .line 245
    .line 246
    iget v2, v1, Lne0/b;->d:I

    .line 247
    .line 248
    if-le v2, v3, :cond_3

    .line 249
    .line 250
    move-object v12, v1

    .line 251
    goto :goto_1

    .line 252
    :cond_3
    move-object v12, v0

    .line 253
    :goto_1
    new-instance v6, Lne0/c;

    .line 254
    .line 255
    const/4 v9, 0x0

    .line 256
    invoke-direct/range {v6 .. v12}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;JLne0/b;)V

    .line 257
    .line 258
    .line 259
    return-object v6

    .line 260
    :pswitch_9
    check-cast v0, Lif0/d;

    .line 261
    .line 262
    check-cast v6, Landroidx/work/impl/WorkDatabase;

    .line 263
    .line 264
    invoke-virtual {v0, v6}, Lif0/d;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 265
    .line 266
    .line 267
    move-result-object v0

    .line 268
    return-object v0

    .line 269
    :pswitch_a
    check-cast v0, Lfb/u;

    .line 270
    .line 271
    check-cast v6, Ljava/util/UUID;

    .line 272
    .line 273
    iget-object v1, v0, Lfb/u;->c:Landroidx/work/impl/WorkDatabase;

    .line 274
    .line 275
    const-string v2, "getWorkDatabase(...)"

    .line 276
    .line 277
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 278
    .line 279
    .line 280
    new-instance v2, Lh0/h0;

    .line 281
    .line 282
    const/16 v3, 0x1a

    .line 283
    .line 284
    invoke-direct {v2, v3, v0, v6}, Lh0/h0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 285
    .line 286
    .line 287
    new-instance v3, Lh91/a;

    .line 288
    .line 289
    const/4 v4, 0x2

    .line 290
    invoke-direct {v3, v2, v4}, Lh91/a;-><init>(Ljava/lang/Runnable;I)V

    .line 291
    .line 292
    .line 293
    invoke-virtual {v1, v3}, Lla/u;->p(Lay0/a;)Ljava/lang/Object;

    .line 294
    .line 295
    .line 296
    iget-object v1, v0, Lfb/u;->b:Leb/b;

    .line 297
    .line 298
    iget-object v2, v0, Lfb/u;->c:Landroidx/work/impl/WorkDatabase;

    .line 299
    .line 300
    iget-object v0, v0, Lfb/u;->e:Ljava/util/List;

    .line 301
    .line 302
    invoke-static {v1, v2, v0}, Lfb/i;->b(Leb/b;Landroidx/work/impl/WorkDatabase;Ljava/util/List;)V

    .line 303
    .line 304
    .line 305
    return-object v5

    .line 306
    :pswitch_b
    check-cast v0, Lay0/k;

    .line 307
    .line 308
    check-cast v6, Lma0/e;

    .line 309
    .line 310
    invoke-interface {v0, v6}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 311
    .line 312
    .line 313
    return-object v5

    .line 314
    :pswitch_c
    check-cast v6, Ln71/d;

    .line 315
    .line 316
    check-cast v0, Lay0/k;

    .line 317
    .line 318
    iget-object v1, v6, Ln71/d;->b:Ljava/util/ArrayList;

    .line 319
    .line 320
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 321
    .line 322
    .line 323
    move-result-object v1

    .line 324
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 325
    .line 326
    .line 327
    move-result v2

    .line 328
    if-eqz v2, :cond_4

    .line 329
    .line 330
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 331
    .line 332
    .line 333
    move-result-object v2

    .line 334
    invoke-interface {v0, v2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 335
    .line 336
    .line 337
    goto :goto_2

    .line 338
    :cond_4
    return-object v5

    .line 339
    :pswitch_d
    check-cast v0, Lay0/k;

    .line 340
    .line 341
    check-cast v6, Lm70/y0;

    .line 342
    .line 343
    iget-object v1, v6, Lm70/y0;->a:Ljava/lang/String;

    .line 344
    .line 345
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 346
    .line 347
    .line 348
    return-object v5

    .line 349
    :pswitch_e
    check-cast v0, Lay0/k;

    .line 350
    .line 351
    check-cast v6, Lm70/z0;

    .line 352
    .line 353
    iget-object v1, v6, Lm70/z0;->a:Ljava/lang/String;

    .line 354
    .line 355
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 356
    .line 357
    .line 358
    return-object v5

    .line 359
    :pswitch_f
    check-cast v0, Lay0/k;

    .line 360
    .line 361
    check-cast v6, Ll70/x;

    .line 362
    .line 363
    invoke-interface {v0, v6}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 364
    .line 365
    .line 366
    return-object v5

    .line 367
    :pswitch_10
    check-cast v0, Ll2/b1;

    .line 368
    .line 369
    check-cast v6, Lw3/j2;

    .line 370
    .line 371
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 372
    .line 373
    .line 374
    move-result-object v0

    .line 375
    check-cast v0, Lt4/f;

    .line 376
    .line 377
    if-eqz v0, :cond_5

    .line 378
    .line 379
    iget v0, v0, Lt4/f;->d:F

    .line 380
    .line 381
    check-cast v6, Lw3/r1;

    .line 382
    .line 383
    invoke-virtual {v6}, Lw3/r1;->a()J

    .line 384
    .line 385
    .line 386
    move-result-wide v1

    .line 387
    const-wide v3, 0xffffffffL

    .line 388
    .line 389
    .line 390
    .line 391
    .line 392
    and-long/2addr v1, v3

    .line 393
    long-to-int v1, v1

    .line 394
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 395
    .line 396
    .line 397
    move-result-object v1

    .line 398
    invoke-static {v1}, Lxf0/i0;->N(Ljava/lang/Number;)F

    .line 399
    .line 400
    .line 401
    move-result v1

    .line 402
    sub-float/2addr v1, v0

    .line 403
    invoke-static {v1}, Lxf0/i0;->O(F)I

    .line 404
    .line 405
    .line 406
    move-result v0

    .line 407
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 408
    .line 409
    .line 410
    move-result-object v4

    .line 411
    :cond_5
    return-object v4

    .line 412
    :pswitch_11
    check-cast v0, Lay0/k;

    .line 413
    .line 414
    check-cast v6, Lm70/k;

    .line 415
    .line 416
    iget-object v1, v6, Lm70/k;->a:Ll70/h;

    .line 417
    .line 418
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 419
    .line 420
    .line 421
    return-object v5

    .line 422
    :pswitch_12
    check-cast v0, Lay0/k;

    .line 423
    .line 424
    check-cast v6, Lm70/j;

    .line 425
    .line 426
    iget-object v1, v6, Lm70/j;->a:Ll70/d;

    .line 427
    .line 428
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 429
    .line 430
    .line 431
    return-object v5

    .line 432
    :pswitch_13
    check-cast v0, Lay0/k;

    .line 433
    .line 434
    check-cast v6, Ll70/h;

    .line 435
    .line 436
    invoke-interface {v0, v6}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 437
    .line 438
    .line 439
    return-object v5

    .line 440
    :pswitch_14
    check-cast v6, Lm70/b;

    .line 441
    .line 442
    check-cast v0, Lay0/k;

    .line 443
    .line 444
    invoke-virtual {v6}, Lm70/b;->b()Ll70/d;

    .line 445
    .line 446
    .line 447
    move-result-object v1

    .line 448
    if-eqz v1, :cond_6

    .line 449
    .line 450
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 451
    .line 452
    .line 453
    :cond_6
    return-object v5

    .line 454
    :pswitch_15
    check-cast v0, Ll2/h0;

    .line 455
    .line 456
    check-cast v6, Ln1/v;

    .line 457
    .line 458
    invoke-virtual {v0}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 459
    .line 460
    .line 461
    move-result-object v0

    .line 462
    check-cast v0, Ln1/g;

    .line 463
    .line 464
    new-instance v1, Lbb/g0;

    .line 465
    .line 466
    iget-object v2, v6, Ln1/v;->d:Lm1/o;

    .line 467
    .line 468
    iget-object v2, v2, Lm1/o;->f:Lo1/g0;

    .line 469
    .line 470
    invoke-virtual {v2}, Lo1/g0;->getValue()Ljava/lang/Object;

    .line 471
    .line 472
    .line 473
    move-result-object v2

    .line 474
    check-cast v2, Lgy0/j;

    .line 475
    .line 476
    invoke-direct {v1, v2, v0}, Lbb/g0;-><init>(Lgy0/j;Lo1/y;)V

    .line 477
    .line 478
    .line 479
    new-instance v2, Ln1/h;

    .line 480
    .line 481
    invoke-direct {v2, v6, v0, v1}, Ln1/h;-><init>(Ln1/v;Ln1/g;Lbb/g0;)V

    .line 482
    .line 483
    .line 484
    return-object v2

    .line 485
    :pswitch_16
    check-cast v0, Lay0/k;

    .line 486
    .line 487
    check-cast v6, Lhg/c;

    .line 488
    .line 489
    iget-object v1, v6, Lhg/c;->b:Lhg/j;

    .line 490
    .line 491
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 492
    .line 493
    .line 494
    return-object v5

    .line 495
    :pswitch_17
    check-cast v0, Lmj/k;

    .line 496
    .line 497
    check-cast v6, Lvy0/b0;

    .line 498
    .line 499
    iget-object v1, v0, Lmj/k;->d:Ll20/c;

    .line 500
    .line 501
    invoke-virtual {v1}, Ll20/c;->invoke()Ljava/lang/Object;

    .line 502
    .line 503
    .line 504
    move-result-object v1

    .line 505
    check-cast v1, Lnj/h;

    .line 506
    .line 507
    if-eqz v1, :cond_7

    .line 508
    .line 509
    invoke-virtual {v0, v1}, Lmj/k;->c(Lnj/h;)Lnj/h;

    .line 510
    .line 511
    .line 512
    move-result-object v7

    .line 513
    goto :goto_3

    .line 514
    :cond_7
    move-object v7, v4

    .line 515
    :goto_3
    const-string v8, "Kt"

    .line 516
    .line 517
    const/16 v9, 0x2e

    .line 518
    .line 519
    const/16 v10, 0x24

    .line 520
    .line 521
    if-nez v7, :cond_a

    .line 522
    .line 523
    new-instance v3, Lmj/h;

    .line 524
    .line 525
    invoke-direct {v3, v1, v2}, Lmj/h;-><init>(Lnj/h;I)V

    .line 526
    .line 527
    .line 528
    sget-object v1, Lgi/b;->e:Lgi/b;

    .line 529
    .line 530
    sget-object v2, Lgi/a;->e:Lgi/a;

    .line 531
    .line 532
    instance-of v7, v6, Ljava/lang/String;

    .line 533
    .line 534
    if-eqz v7, :cond_8

    .line 535
    .line 536
    check-cast v6, Ljava/lang/String;

    .line 537
    .line 538
    goto :goto_4

    .line 539
    :cond_8
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 540
    .line 541
    .line 542
    move-result-object v6

    .line 543
    invoke-virtual {v6}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 544
    .line 545
    .line 546
    move-result-object v6

    .line 547
    invoke-static {v6, v10}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 548
    .line 549
    .line 550
    move-result-object v7

    .line 551
    invoke-static {v9, v7, v7}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 552
    .line 553
    .line 554
    move-result-object v7

    .line 555
    invoke-virtual {v7}, Ljava/lang/String;->length()I

    .line 556
    .line 557
    .line 558
    move-result v9

    .line 559
    if-nez v9, :cond_9

    .line 560
    .line 561
    goto :goto_4

    .line 562
    :cond_9
    invoke-static {v7, v8}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 563
    .line 564
    .line 565
    move-result-object v6

    .line 566
    :goto_4
    invoke-static {v6, v2, v1, v4, v3}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 567
    .line 568
    .line 569
    invoke-virtual {v0}, Lmj/k;->b()V

    .line 570
    .line 571
    .line 572
    goto :goto_6

    .line 573
    :cond_a
    new-instance v2, Lmj/h;

    .line 574
    .line 575
    invoke-direct {v2, v1, v3}, Lmj/h;-><init>(Lnj/h;I)V

    .line 576
    .line 577
    .line 578
    sget-object v1, Lgi/b;->e:Lgi/b;

    .line 579
    .line 580
    sget-object v3, Lgi/a;->e:Lgi/a;

    .line 581
    .line 582
    instance-of v11, v6, Ljava/lang/String;

    .line 583
    .line 584
    if-eqz v11, :cond_b

    .line 585
    .line 586
    check-cast v6, Ljava/lang/String;

    .line 587
    .line 588
    goto :goto_5

    .line 589
    :cond_b
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 590
    .line 591
    .line 592
    move-result-object v6

    .line 593
    invoke-virtual {v6}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 594
    .line 595
    .line 596
    move-result-object v6

    .line 597
    invoke-static {v6, v10}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 598
    .line 599
    .line 600
    move-result-object v10

    .line 601
    invoke-static {v9, v10, v10}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 602
    .line 603
    .line 604
    move-result-object v9

    .line 605
    invoke-virtual {v9}, Ljava/lang/String;->length()I

    .line 606
    .line 607
    .line 608
    move-result v10

    .line 609
    if-nez v10, :cond_c

    .line 610
    .line 611
    goto :goto_5

    .line 612
    :cond_c
    invoke-static {v9, v8}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 613
    .line 614
    .line 615
    move-result-object v6

    .line 616
    :goto_5
    invoke-static {v6, v3, v1, v4, v2}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 617
    .line 618
    .line 619
    iget-object v1, v0, Lmj/k;->h:Lyy0/c2;

    .line 620
    .line 621
    new-instance v2, Lri/a;

    .line 622
    .line 623
    iget-object v0, v0, Lmj/k;->g:Lmj/f;

    .line 624
    .line 625
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 626
    .line 627
    .line 628
    invoke-static {v7}, Lmj/f;->a(Lnj/h;)Llj/j;

    .line 629
    .line 630
    .line 631
    move-result-object v0

    .line 632
    invoke-direct {v2, v0}, Lri/a;-><init>(Ljava/lang/Object;)V

    .line 633
    .line 634
    .line 635
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 636
    .line 637
    .line 638
    invoke-virtual {v1, v4, v2}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 639
    .line 640
    .line 641
    :goto_6
    return-object v5

    .line 642
    :pswitch_18
    check-cast v0, Lm70/n;

    .line 643
    .line 644
    check-cast v6, Ll70/h;

    .line 645
    .line 646
    new-instance v1, Llj0/d;

    .line 647
    .line 648
    iget-object v0, v0, Lm70/n;->v:Lij0/a;

    .line 649
    .line 650
    invoke-static {v6}, Li0/d;->d(Ll70/h;)I

    .line 651
    .line 652
    .line 653
    move-result v2

    .line 654
    check-cast v0, Ljj0/f;

    .line 655
    .line 656
    invoke-virtual {v0, v2}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 657
    .line 658
    .line 659
    move-result-object v0

    .line 660
    invoke-direct {v1, v0}, Llj0/d;-><init>(Ljava/lang/String;)V

    .line 661
    .line 662
    .line 663
    return-object v1

    .line 664
    :pswitch_19
    check-cast v0, Ll60/e;

    .line 665
    .line 666
    check-cast v6, Ll2/b1;

    .line 667
    .line 668
    invoke-interface {v6}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 669
    .line 670
    .line 671
    move-result-object v1

    .line 672
    check-cast v1, Ll60/c;

    .line 673
    .line 674
    iget-boolean v1, v1, Ll60/c;->g:Z

    .line 675
    .line 676
    if-eqz v1, :cond_d

    .line 677
    .line 678
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 679
    .line 680
    .line 681
    move-result-object v1

    .line 682
    new-instance v2, Lk31/l;

    .line 683
    .line 684
    const/16 v3, 0xc

    .line 685
    .line 686
    invoke-direct {v2, v0, v4, v3}, Lk31/l;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 687
    .line 688
    .line 689
    const/4 v0, 0x3

    .line 690
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 691
    .line 692
    .line 693
    :cond_d
    return-object v5

    .line 694
    :pswitch_1a
    check-cast v0, Lkotlin/jvm/internal/d0;

    .line 695
    .line 696
    check-cast v6, Llz0/g;

    .line 697
    .line 698
    new-instance v1, Ljava/lang/StringBuilder;

    .line 699
    .line 700
    const-string v2, "Only found "

    .line 701
    .line 702
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 703
    .line 704
    .line 705
    iget v0, v0, Lkotlin/jvm/internal/d0;->d:I

    .line 706
    .line 707
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 708
    .line 709
    .line 710
    const-string v0, " digits in a row, but need to parse "

    .line 711
    .line 712
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 713
    .line 714
    .line 715
    invoke-virtual {v6}, Llz0/g;->b()Ljava/lang/String;

    .line 716
    .line 717
    .line 718
    move-result-object v0

    .line 719
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 720
    .line 721
    .line 722
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 723
    .line 724
    .line 725
    move-result-object v0

    .line 726
    return-object v0

    .line 727
    :pswitch_1b
    check-cast v0, Lly0/n;

    .line 728
    .line 729
    check-cast v6, Ljava/lang/CharSequence;

    .line 730
    .line 731
    const-string v1, "input"

    .line 732
    .line 733
    invoke-static {v6, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 734
    .line 735
    .line 736
    iget-object v0, v0, Lly0/n;->d:Ljava/util/regex/Pattern;

    .line 737
    .line 738
    invoke-virtual {v0, v6}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 739
    .line 740
    .line 741
    move-result-object v0

    .line 742
    const-string v1, "matcher(...)"

    .line 743
    .line 744
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 745
    .line 746
    .line 747
    invoke-static {v0, v2, v6}, Ltm0/d;->c(Ljava/util/regex/Matcher;ILjava/lang/CharSequence;)Lly0/l;

    .line 748
    .line 749
    .line 750
    move-result-object v0

    .line 751
    return-object v0

    .line 752
    :pswitch_1c
    check-cast v0, Lay0/k;

    .line 753
    .line 754
    check-cast v6, Luf/r;

    .line 755
    .line 756
    new-instance v1, Luf/j;

    .line 757
    .line 758
    invoke-direct {v1, v6}, Luf/j;-><init>(Luf/r;)V

    .line 759
    .line 760
    .line 761
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 762
    .line 763
    .line 764
    return-object v5

    .line 765
    :pswitch_data_0
    .packed-switch 0x0
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
        :pswitch_12
        :pswitch_11
        :pswitch_10
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
.end method
