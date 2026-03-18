.class public final synthetic La71/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, La71/u;->d:I

    .line 2
    .line 3
    iput-object p1, p0, La71/u;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, La71/u;->d:I

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x2

    .line 7
    const/4 v4, 0x1

    .line 8
    const/4 v5, 0x3

    .line 9
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    const/4 v7, 0x0

    .line 12
    iget-object v0, v0, La71/u;->e:Ljava/lang/Object;

    .line 13
    .line 14
    packed-switch v1, :pswitch_data_0

    .line 15
    .line 16
    .line 17
    check-cast v0, Lct0/h;

    .line 18
    .line 19
    new-instance v1, Llj0/a;

    .line 20
    .line 21
    iget-object v0, v0, Lct0/h;->h:Lij0/a;

    .line 22
    .line 23
    const v2, 0x7f1203fa

    .line 24
    .line 25
    .line 26
    check-cast v0, Ljj0/f;

    .line 27
    .line 28
    invoke-virtual {v0, v2}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    invoke-direct {v1, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    return-object v1

    .line 36
    :pswitch_0
    check-cast v0, Lci0/h;

    .line 37
    .line 38
    iget-object v0, v0, Lci0/h;->d:Lgb0/p;

    .line 39
    .line 40
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    check-cast v0, Ljava/lang/Boolean;

    .line 45
    .line 46
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 47
    .line 48
    .line 49
    return-object v0

    .line 50
    :pswitch_1
    check-cast v0, Lc81/d;

    .line 51
    .line 52
    iget-object v1, v0, Lc81/d;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;

    .line 53
    .line 54
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->stop()V

    .line 55
    .line 56
    .line 57
    iget-object v1, v0, Lc81/d;->j:Lc81/f;

    .line 58
    .line 59
    if-eqz v1, :cond_0

    .line 60
    .line 61
    iput-object v2, v0, Lc81/d;->j:Lc81/f;

    .line 62
    .line 63
    invoke-virtual {v1}, Lc81/f;->invoke()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    :cond_0
    iput-object v2, v0, Lc81/d;->i:Lc81/e;

    .line 67
    .line 68
    iput-object v2, v0, Lc81/d;->f:Landroidx/lifecycle/c1;

    .line 69
    .line 70
    iput-object v2, v0, Lc81/d;->e:Lt71/a;

    .line 71
    .line 72
    return-object v6

    .line 73
    :pswitch_2
    check-cast v0, Lyq0/n;

    .line 74
    .line 75
    new-instance v1, Lkj0/h;

    .line 76
    .line 77
    sget-object v2, Lc80/u;->a:[I

    .line 78
    .line 79
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 80
    .line 81
    .line 82
    move-result v0

    .line 83
    aget v0, v2, v0

    .line 84
    .line 85
    if-ne v0, v3, :cond_1

    .line 86
    .line 87
    const-string v0, "SPIN - Activate biometrics - Enter SPIN"

    .line 88
    .line 89
    goto :goto_0

    .line 90
    :cond_1
    const-string v0, "SPIN - Enter SPIN - manual"

    .line 91
    .line 92
    :goto_0
    invoke-direct {v1, v0}, Lkj0/h;-><init>(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    return-object v1

    .line 96
    :pswitch_3
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 97
    .line 98
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 99
    .line 100
    .line 101
    move-result-object v0

    .line 102
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 103
    .line 104
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    invoke-interface {v0}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object v0

    .line 112
    const-string v1, "createInterruptionErrorText: on receiving, InterruptionError="

    .line 113
    .line 114
    invoke-static {v1, v0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v0

    .line 118
    return-object v0

    .line 119
    :pswitch_4
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;

    .line 120
    .line 121
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 122
    .line 123
    .line 124
    move-result-object v0

    .line 125
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 126
    .line 127
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 128
    .line 129
    .line 130
    move-result-object v0

    .line 131
    invoke-interface {v0}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 132
    .line 133
    .line 134
    move-result-object v0

    .line 135
    const-string v1, "createParkingFailedErrorText: on receiving, ParkingFailedError="

    .line 136
    .line 137
    invoke-static {v1, v0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 138
    .line 139
    .line 140
    move-result-object v0

    .line 141
    return-object v0

    .line 142
    :pswitch_5
    check-cast v0, Lc2/p;

    .line 143
    .line 144
    new-instance v1, Landroid/view/inputmethod/BaseInputConnection;

    .line 145
    .line 146
    iget-object v0, v0, Lc2/p;->a:Landroid/view/View;

    .line 147
    .line 148
    invoke-direct {v1, v0, v7}, Landroid/view/inputmethod/BaseInputConnection;-><init>(Landroid/view/View;Z)V

    .line 149
    .line 150
    .line 151
    return-object v1

    .line 152
    :pswitch_6
    check-cast v0, Lc2/k;

    .line 153
    .line 154
    iget-object v0, v0, Lc2/k;->e:Ljava/lang/Object;

    .line 155
    .line 156
    check-cast v0, Landroid/view/View;

    .line 157
    .line 158
    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 159
    .line 160
    .line 161
    move-result-object v0

    .line 162
    const-string v1, "input_method"

    .line 163
    .line 164
    invoke-virtual {v0, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object v0

    .line 168
    const-string v1, "null cannot be cast to non-null type android.view.inputmethod.InputMethodManager"

    .line 169
    .line 170
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 171
    .line 172
    .line 173
    check-cast v0, Landroid/view/inputmethod/InputMethodManager;

    .line 174
    .line 175
    return-object v0

    .line 176
    :pswitch_7
    check-cast v0, Lc1/c1;

    .line 177
    .line 178
    iget-object v1, v0, Lc1/c1;->i:Lc1/w1;

    .line 179
    .line 180
    if-eqz v1, :cond_2

    .line 181
    .line 182
    iget-object v1, v1, Lc1/w1;->l:Ll2/h0;

    .line 183
    .line 184
    invoke-virtual {v1}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object v1

    .line 188
    check-cast v1, Ljava/lang/Number;

    .line 189
    .line 190
    invoke-virtual {v1}, Ljava/lang/Number;->longValue()J

    .line 191
    .line 192
    .line 193
    move-result-wide v1

    .line 194
    goto :goto_1

    .line 195
    :cond_2
    const-wide/16 v1, 0x0

    .line 196
    .line 197
    :goto_1
    iput-wide v1, v0, Lc1/c1;->j:J

    .line 198
    .line 199
    return-object v6

    .line 200
    :pswitch_8
    check-cast v0, Lvy0/b0;

    .line 201
    .line 202
    invoke-interface {v0}, Lvy0/b0;->getCoroutineContext()Lpx0/g;

    .line 203
    .line 204
    .line 205
    move-result-object v0

    .line 206
    invoke-static {v0}, Lc1/d;->p(Lpx0/g;)F

    .line 207
    .line 208
    .line 209
    move-result v0

    .line 210
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 211
    .line 212
    .line 213
    move-result-object v0

    .line 214
    return-object v0

    .line 215
    :pswitch_9
    check-cast v0, Lc00/y1;

    .line 216
    .line 217
    new-instance v1, Llj0/a;

    .line 218
    .line 219
    iget-object v0, v0, Lc00/y1;->i:Lij0/a;

    .line 220
    .line 221
    const v2, 0x7f1200ae

    .line 222
    .line 223
    .line 224
    check-cast v0, Ljj0/f;

    .line 225
    .line 226
    invoke-virtual {v0, v2}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 227
    .line 228
    .line 229
    move-result-object v0

    .line 230
    invoke-direct {v1, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 231
    .line 232
    .line 233
    return-object v1

    .line 234
    :pswitch_a
    check-cast v0, Lc00/t1;

    .line 235
    .line 236
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 237
    .line 238
    .line 239
    move-result-object v1

    .line 240
    check-cast v1, Lc00/n1;

    .line 241
    .line 242
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 243
    .line 244
    .line 245
    move-result-object v2

    .line 246
    check-cast v2, Lc00/n1;

    .line 247
    .line 248
    iget-object v2, v2, Lc00/n1;->c:Ljava/util/List;

    .line 249
    .line 250
    check-cast v2, Ljava/lang/Iterable;

    .line 251
    .line 252
    new-instance v3, Ljava/util/ArrayList;

    .line 253
    .line 254
    const/16 v4, 0xa

    .line 255
    .line 256
    invoke-static {v2, v4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 257
    .line 258
    .line 259
    move-result v4

    .line 260
    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 261
    .line 262
    .line 263
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 264
    .line 265
    .line 266
    move-result-object v2

    .line 267
    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 268
    .line 269
    .line 270
    move-result v4

    .line 271
    if-eqz v4, :cond_3

    .line 272
    .line 273
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 274
    .line 275
    .line 276
    move-result-object v4

    .line 277
    check-cast v4, Lc00/m1;

    .line 278
    .line 279
    iget-object v5, v0, Lc00/t1;->i:Lij0/a;

    .line 280
    .line 281
    invoke-static {v4, v5}, Ljp/fc;->h(Lc00/m1;Lij0/a;)Lc00/m1;

    .line 282
    .line 283
    .line 284
    move-result-object v4

    .line 285
    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 286
    .line 287
    .line 288
    goto :goto_2

    .line 289
    :cond_3
    const/16 v2, 0xb

    .line 290
    .line 291
    invoke-static {v1, v7, v3, v2}, Lc00/n1;->a(Lc00/n1;ZLjava/util/List;I)Lc00/n1;

    .line 292
    .line 293
    .line 294
    move-result-object v1

    .line 295
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 296
    .line 297
    .line 298
    return-object v6

    .line 299
    :pswitch_b
    check-cast v0, Lc00/q0;

    .line 300
    .line 301
    new-instance v1, Llj0/a;

    .line 302
    .line 303
    iget-object v0, v0, Lc00/q0;->p:Lij0/a;

    .line 304
    .line 305
    const v2, 0x7f1200c9

    .line 306
    .line 307
    .line 308
    check-cast v0, Ljj0/f;

    .line 309
    .line 310
    invoke-virtual {v0, v2}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 311
    .line 312
    .line 313
    move-result-object v0

    .line 314
    invoke-direct {v1, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 315
    .line 316
    .line 317
    return-object v1

    .line 318
    :pswitch_c
    check-cast v0, Lc00/t;

    .line 319
    .line 320
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 321
    .line 322
    .line 323
    move-result-object v1

    .line 324
    check-cast v1, Lc00/s;

    .line 325
    .line 326
    sget-object v2, Lc00/r;->d:Lc00/r;

    .line 327
    .line 328
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 329
    .line 330
    .line 331
    new-instance v1, Lc00/s;

    .line 332
    .line 333
    invoke-direct {v1, v2}, Lc00/s;-><init>(Lc00/r;)V

    .line 334
    .line 335
    .line 336
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 337
    .line 338
    .line 339
    return-object v6

    .line 340
    :pswitch_d
    check-cast v0, Lc00/h;

    .line 341
    .line 342
    new-instance v1, Llj0/a;

    .line 343
    .line 344
    iget-object v0, v0, Lc00/h;->l:Lij0/a;

    .line 345
    .line 346
    const v2, 0x7f120084

    .line 347
    .line 348
    .line 349
    check-cast v0, Ljj0/f;

    .line 350
    .line 351
    invoke-virtual {v0, v2}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 352
    .line 353
    .line 354
    move-result-object v0

    .line 355
    invoke-direct {v1, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 356
    .line 357
    .line 358
    return-object v1

    .line 359
    :pswitch_e
    check-cast v0, Lc0/a;

    .line 360
    .line 361
    invoke-virtual {v0}, Lc0/a;->a()Le0/b;

    .line 362
    .line 363
    .line 364
    move-result-object v0

    .line 365
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 366
    .line 367
    .line 368
    move-result v0

    .line 369
    if-eqz v0, :cond_6

    .line 370
    .line 371
    if-eq v0, v4, :cond_5

    .line 372
    .line 373
    if-eq v0, v3, :cond_7

    .line 374
    .line 375
    if-ne v0, v5, :cond_4

    .line 376
    .line 377
    move v3, v5

    .line 378
    goto :goto_3

    .line 379
    :cond_4
    new-instance v0, La8/r0;

    .line 380
    .line 381
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 382
    .line 383
    .line 384
    throw v0

    .line 385
    :cond_5
    move v3, v4

    .line 386
    goto :goto_3

    .line 387
    :cond_6
    move v3, v7

    .line 388
    :cond_7
    :goto_3
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 389
    .line 390
    .line 391
    move-result-object v0

    .line 392
    return-object v0

    .line 393
    :pswitch_f
    check-cast v0, Lbz/r;

    .line 394
    .line 395
    new-instance v1, Llj0/a;

    .line 396
    .line 397
    iget-object v0, v0, Lbz/r;->o:Lij0/a;

    .line 398
    .line 399
    const v2, 0x7f120062

    .line 400
    .line 401
    .line 402
    check-cast v0, Ljj0/f;

    .line 403
    .line 404
    invoke-virtual {v0, v2}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 405
    .line 406
    .line 407
    move-result-object v0

    .line 408
    invoke-direct {v1, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 409
    .line 410
    .line 411
    return-object v1

    .line 412
    :pswitch_10
    check-cast v0, Laz/i;

    .line 413
    .line 414
    new-instance v1, Laz/b;

    .line 415
    .line 416
    const-string v2, "<this>"

    .line 417
    .line 418
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 419
    .line 420
    .line 421
    new-instance v2, Ljava/util/LinkedHashSet;

    .line 422
    .line 423
    invoke-direct {v2}, Ljava/util/LinkedHashSet;-><init>()V

    .line 424
    .line 425
    .line 426
    iget v3, v0, Laz/i;->d:I

    .line 427
    .line 428
    invoke-static {v3}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 429
    .line 430
    .line 431
    move-result-object v3

    .line 432
    new-instance v5, Llx0/l;

    .line 433
    .line 434
    const-string v6, "filter_budget"

    .line 435
    .line 436
    invoke-direct {v5, v6, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 437
    .line 438
    .line 439
    invoke-interface {v2, v5}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 440
    .line 441
    .line 442
    iget-object v3, v0, Laz/i;->f:Laz/h;

    .line 443
    .line 444
    iget-object v3, v3, Laz/h;->d:Ljava/lang/String;

    .line 445
    .line 446
    new-instance v5, Llx0/l;

    .line 447
    .line 448
    const-string v6, "filter_companion"

    .line 449
    .line 450
    invoke-direct {v5, v6, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 451
    .line 452
    .line 453
    invoke-interface {v2, v5}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 454
    .line 455
    .line 456
    iget-object v3, v0, Laz/i;->c:Ljava/util/List;

    .line 457
    .line 458
    move-object v8, v3

    .line 459
    check-cast v8, Ljava/lang/Iterable;

    .line 460
    .line 461
    new-instance v12, Lb30/a;

    .line 462
    .line 463
    const/16 v3, 0x14

    .line 464
    .line 465
    invoke-direct {v12, v3}, Lb30/a;-><init>(I)V

    .line 466
    .line 467
    .line 468
    const/16 v13, 0x1e

    .line 469
    .line 470
    const-string v9, ";"

    .line 471
    .line 472
    const/4 v10, 0x0

    .line 473
    const/4 v11, 0x0

    .line 474
    invoke-static/range {v8 .. v13}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 475
    .line 476
    .line 477
    move-result-object v3

    .line 478
    iget-object v5, v0, Laz/i;->e:Ljava/util/List;

    .line 479
    .line 480
    move-object v8, v5

    .line 481
    check-cast v8, Ljava/lang/Iterable;

    .line 482
    .line 483
    new-instance v12, Lb30/a;

    .line 484
    .line 485
    const/16 v5, 0x15

    .line 486
    .line 487
    invoke-direct {v12, v5}, Lb30/a;-><init>(I)V

    .line 488
    .line 489
    .line 490
    const-string v9, ";"

    .line 491
    .line 492
    invoke-static/range {v8 .. v13}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 493
    .line 494
    .line 495
    move-result-object v5

    .line 496
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 497
    .line 498
    .line 499
    move-result v6

    .line 500
    if-lez v6, :cond_8

    .line 501
    .line 502
    new-instance v6, Llx0/l;

    .line 503
    .line 504
    const-string v8, "filter_interests"

    .line 505
    .line 506
    invoke-direct {v6, v8, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 507
    .line 508
    .line 509
    invoke-interface {v2, v6}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 510
    .line 511
    .line 512
    :cond_8
    invoke-virtual {v5}, Ljava/lang/String;->length()I

    .line 513
    .line 514
    .line 515
    move-result v3

    .line 516
    if-lez v3, :cond_9

    .line 517
    .line 518
    new-instance v3, Llx0/l;

    .line 519
    .line 520
    const-string v6, "filter_categories"

    .line 521
    .line 522
    invoke-direct {v3, v6, v5}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 523
    .line 524
    .line 525
    invoke-interface {v2, v3}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 526
    .line 527
    .line 528
    :cond_9
    new-instance v3, Ljava/lang/StringBuilder;

    .line 529
    .line 530
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 531
    .line 532
    .line 533
    iget-boolean v5, v0, Laz/i;->g:Z

    .line 534
    .line 535
    if-eqz v5, :cond_a

    .line 536
    .line 537
    const-string v5, "with_pet;"

    .line 538
    .line 539
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 540
    .line 541
    .line 542
    :cond_a
    iget-boolean v0, v0, Laz/i;->h:Z

    .line 543
    .line 544
    if-eqz v0, :cond_b

    .line 545
    .line 546
    const-string v0, "wheel_chair;"

    .line 547
    .line 548
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 549
    .line 550
    .line 551
    :cond_b
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->length()I

    .line 552
    .line 553
    .line 554
    move-result v0

    .line 555
    if-lez v0, :cond_f

    .line 556
    .line 557
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->length()I

    .line 558
    .line 559
    .line 560
    move-result v0

    .line 561
    sub-int/2addr v0, v4

    .line 562
    if-gez v0, :cond_c

    .line 563
    .line 564
    move v0, v7

    .line 565
    :cond_c
    if-ltz v0, :cond_e

    .line 566
    .line 567
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->length()I

    .line 568
    .line 569
    .line 570
    move-result v4

    .line 571
    if-le v0, v4, :cond_d

    .line 572
    .line 573
    move v0, v4

    .line 574
    :cond_d
    invoke-virtual {v3, v7, v0}, Ljava/lang/StringBuilder;->subSequence(II)Ljava/lang/CharSequence;

    .line 575
    .line 576
    .line 577
    goto :goto_4

    .line 578
    :cond_e
    const-string v1, "Requested character count "

    .line 579
    .line 580
    const-string v2, " is less than zero."

    .line 581
    .line 582
    invoke-static {v1, v0, v2}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 583
    .line 584
    .line 585
    move-result-object v0

    .line 586
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 587
    .line 588
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 589
    .line 590
    .line 591
    move-result-object v0

    .line 592
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 593
    .line 594
    .line 595
    throw v1

    .line 596
    :cond_f
    :goto_4
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->length()I

    .line 597
    .line 598
    .line 599
    move-result v0

    .line 600
    if-lez v0, :cond_10

    .line 601
    .line 602
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 603
    .line 604
    .line 605
    move-result-object v0

    .line 606
    new-instance v3, Llx0/l;

    .line 607
    .line 608
    const-string v4, "filter_toggle"

    .line 609
    .line 610
    invoke-direct {v3, v4, v0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 611
    .line 612
    .line 613
    invoke-interface {v2, v3}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 614
    .line 615
    .line 616
    :cond_10
    invoke-direct {v1, v2}, Laz/b;-><init>(Ljava/util/LinkedHashSet;)V

    .line 617
    .line 618
    .line 619
    return-object v1

    .line 620
    :pswitch_11
    check-cast v0, Lbz/g;

    .line 621
    .line 622
    new-instance v1, Llj0/a;

    .line 623
    .line 624
    iget-object v0, v0, Lbz/g;->l:Lij0/a;

    .line 625
    .line 626
    const v2, 0x7f12004f

    .line 627
    .line 628
    .line 629
    check-cast v0, Ljj0/f;

    .line 630
    .line 631
    invoke-virtual {v0, v2}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 632
    .line 633
    .line 634
    move-result-object v0

    .line 635
    invoke-direct {v1, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 636
    .line 637
    .line 638
    return-object v1

    .line 639
    :pswitch_12
    check-cast v0, Lbz/e;

    .line 640
    .line 641
    new-instance v1, Llj0/a;

    .line 642
    .line 643
    iget-object v0, v0, Lbz/e;->k:Lij0/a;

    .line 644
    .line 645
    const v2, 0x7f120376

    .line 646
    .line 647
    .line 648
    check-cast v0, Ljj0/f;

    .line 649
    .line 650
    invoke-virtual {v0, v2}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 651
    .line 652
    .line 653
    move-result-object v0

    .line 654
    invoke-direct {v1, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 655
    .line 656
    .line 657
    return-object v1

    .line 658
    :pswitch_13
    check-cast v0, Lbo0/r;

    .line 659
    .line 660
    new-instance v1, Llj0/a;

    .line 661
    .line 662
    iget-object v0, v0, Lbo0/r;->j:Lij0/a;

    .line 663
    .line 664
    const v2, 0x7f120093

    .line 665
    .line 666
    .line 667
    check-cast v0, Ljj0/f;

    .line 668
    .line 669
    invoke-virtual {v0, v2}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 670
    .line 671
    .line 672
    move-result-object v0

    .line 673
    invoke-direct {v1, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 674
    .line 675
    .line 676
    return-object v1

    .line 677
    :pswitch_14
    check-cast v0, Lbm/e;

    .line 678
    .line 679
    new-instance v1, Landroid/graphics/BitmapFactory$Options;

    .line 680
    .line 681
    invoke-direct {v1}, Landroid/graphics/BitmapFactory$Options;-><init>()V

    .line 682
    .line 683
    .line 684
    iget-object v6, v0, Lbm/e;->b:Lmm/n;

    .line 685
    .line 686
    new-instance v8, Lbm/b;

    .line 687
    .line 688
    iget-object v9, v0, Lbm/e;->d:Ljava/lang/Object;

    .line 689
    .line 690
    check-cast v9, Lbm/q;

    .line 691
    .line 692
    invoke-interface {v9}, Lbm/q;->p0()Lu01/h;

    .line 693
    .line 694
    .line 695
    move-result-object v9

    .line 696
    invoke-direct {v8, v9, v7}, Lbm/b;-><init>(Lu01/h0;I)V

    .line 697
    .line 698
    .line 699
    invoke-static {v8}, Lu01/b;->c(Lu01/h0;)Lu01/b0;

    .line 700
    .line 701
    .line 702
    move-result-object v9

    .line 703
    iput-boolean v4, v1, Landroid/graphics/BitmapFactory$Options;->inJustDecodeBounds:Z

    .line 704
    .line 705
    invoke-virtual {v9}, Lu01/b0;->b()Lu01/b0;

    .line 706
    .line 707
    .line 708
    move-result-object v10

    .line 709
    new-instance v11, Lcx0/a;

    .line 710
    .line 711
    invoke-direct {v11, v10, v5}, Lcx0/a;-><init>(Ljava/lang/Object;I)V

    .line 712
    .line 713
    .line 714
    invoke-static {v11, v2, v1}, Landroid/graphics/BitmapFactory;->decodeStream(Ljava/io/InputStream;Landroid/graphics/Rect;Landroid/graphics/BitmapFactory$Options;)Landroid/graphics/Bitmap;

    .line 715
    .line 716
    .line 717
    iget-object v10, v8, Lbm/b;->f:Ljava/lang/Object;

    .line 718
    .line 719
    check-cast v10, Ljava/lang/Exception;

    .line 720
    .line 721
    if-nez v10, :cond_38

    .line 722
    .line 723
    iput-boolean v7, v1, Landroid/graphics/BitmapFactory$Options;->inJustDecodeBounds:Z

    .line 724
    .line 725
    sget-object v10, Lbm/o;->a:Landroid/graphics/Paint;

    .line 726
    .line 727
    iget-object v10, v1, Landroid/graphics/BitmapFactory$Options;->outMimeType:Ljava/lang/String;

    .line 728
    .line 729
    iget-object v0, v0, Lbm/e;->e:Ljava/lang/Object;

    .line 730
    .line 731
    check-cast v0, Lbm/n;

    .line 732
    .line 733
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 734
    .line 735
    .line 736
    const-string v0, "image/jpeg"

    .line 737
    .line 738
    if-eqz v10, :cond_12

    .line 739
    .line 740
    invoke-virtual {v10, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 741
    .line 742
    .line 743
    move-result v11

    .line 744
    if-nez v11, :cond_11

    .line 745
    .line 746
    const-string v11, "image/webp"

    .line 747
    .line 748
    invoke-virtual {v10, v11}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 749
    .line 750
    .line 751
    move-result v11

    .line 752
    if-nez v11, :cond_11

    .line 753
    .line 754
    const-string v11, "image/heic"

    .line 755
    .line 756
    invoke-virtual {v10, v11}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 757
    .line 758
    .line 759
    move-result v11

    .line 760
    if-nez v11, :cond_11

    .line 761
    .line 762
    const-string v11, "image/heif"

    .line 763
    .line 764
    invoke-virtual {v10, v11}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 765
    .line 766
    .line 767
    move-result v10

    .line 768
    if-eqz v10, :cond_12

    .line 769
    .line 770
    :cond_11
    move v10, v4

    .line 771
    goto :goto_5

    .line 772
    :cond_12
    move v10, v7

    .line 773
    :goto_5
    if-eqz v10, :cond_14

    .line 774
    .line 775
    new-instance v10, Lv6/g;

    .line 776
    .line 777
    new-instance v11, Lbm/m;

    .line 778
    .line 779
    invoke-virtual {v9}, Lu01/b0;->b()Lu01/b0;

    .line 780
    .line 781
    .line 782
    move-result-object v12

    .line 783
    new-instance v13, Lcx0/a;

    .line 784
    .line 785
    invoke-direct {v13, v12, v5}, Lcx0/a;-><init>(Ljava/lang/Object;I)V

    .line 786
    .line 787
    .line 788
    invoke-direct {v11, v13, v7}, Lbm/m;-><init>(Ljava/io/InputStream;I)V

    .line 789
    .line 790
    .line 791
    invoke-direct {v10, v11}, Lv6/g;-><init>(Ljava/io/InputStream;)V

    .line 792
    .line 793
    .line 794
    new-instance v11, Lbm/l;

    .line 795
    .line 796
    const-string v12, "Orientation"

    .line 797
    .line 798
    invoke-virtual {v10, v4, v12}, Lv6/g;->c(ILjava/lang/String;)I

    .line 799
    .line 800
    .line 801
    move-result v12

    .line 802
    if-eq v12, v3, :cond_13

    .line 803
    .line 804
    const/4 v3, 0x7

    .line 805
    if-eq v12, v3, :cond_13

    .line 806
    .line 807
    const/4 v3, 0x4

    .line 808
    if-eq v12, v3, :cond_13

    .line 809
    .line 810
    const/4 v3, 0x5

    .line 811
    if-eq v12, v3, :cond_13

    .line 812
    .line 813
    move v3, v7

    .line 814
    goto :goto_6

    .line 815
    :cond_13
    move v3, v4

    .line 816
    :goto_6
    invoke-virtual {v10}, Lv6/g;->l()I

    .line 817
    .line 818
    .line 819
    move-result v10

    .line 820
    invoke-direct {v11, v10, v3}, Lbm/l;-><init>(IZ)V

    .line 821
    .line 822
    .line 823
    goto :goto_7

    .line 824
    :cond_14
    sget-object v11, Lbm/l;->c:Lbm/l;

    .line 825
    .line 826
    :goto_7
    iget v3, v11, Lbm/l;->b:I

    .line 827
    .line 828
    iget-boolean v10, v11, Lbm/l;->a:Z

    .line 829
    .line 830
    iget-object v11, v8, Lbm/b;->f:Ljava/lang/Object;

    .line 831
    .line 832
    check-cast v11, Ljava/lang/Exception;

    .line 833
    .line 834
    if-nez v11, :cond_37

    .line 835
    .line 836
    iput-boolean v7, v1, Landroid/graphics/BitmapFactory$Options;->inMutable:Z

    .line 837
    .line 838
    sget-object v11, Lmm/i;->c:Ld8/c;

    .line 839
    .line 840
    invoke-static {v6, v11}, Lyl/m;->e(Lmm/n;Ld8/c;)Ljava/lang/Object;

    .line 841
    .line 842
    .line 843
    move-result-object v12

    .line 844
    check-cast v12, Landroid/graphics/ColorSpace;

    .line 845
    .line 846
    iget-object v13, v6, Lmm/n;->a:Landroid/content/Context;

    .line 847
    .line 848
    if-eqz v12, :cond_15

    .line 849
    .line 850
    invoke-static {v6, v11}, Lyl/m;->e(Lmm/n;Ld8/c;)Ljava/lang/Object;

    .line 851
    .line 852
    .line 853
    move-result-object v11

    .line 854
    check-cast v11, Landroid/graphics/ColorSpace;

    .line 855
    .line 856
    iput-object v11, v1, Landroid/graphics/BitmapFactory$Options;->inPreferredColorSpace:Landroid/graphics/ColorSpace;

    .line 857
    .line 858
    :cond_15
    sget-object v11, Lmm/i;->d:Ld8/c;

    .line 859
    .line 860
    invoke-static {v6, v11}, Lyl/m;->e(Lmm/n;Ld8/c;)Ljava/lang/Object;

    .line 861
    .line 862
    .line 863
    move-result-object v11

    .line 864
    check-cast v11, Ljava/lang/Boolean;

    .line 865
    .line 866
    invoke-virtual {v11}, Ljava/lang/Boolean;->booleanValue()Z

    .line 867
    .line 868
    .line 869
    move-result v11

    .line 870
    iput-boolean v11, v1, Landroid/graphics/BitmapFactory$Options;->inPremultiplied:Z

    .line 871
    .line 872
    sget-object v11, Lmm/i;->b:Ld8/c;

    .line 873
    .line 874
    invoke-static {v6, v11}, Lyl/m;->e(Lmm/n;Ld8/c;)Ljava/lang/Object;

    .line 875
    .line 876
    .line 877
    move-result-object v11

    .line 878
    check-cast v11, Landroid/graphics/Bitmap$Config;

    .line 879
    .line 880
    if-nez v10, :cond_16

    .line 881
    .line 882
    if-lez v3, :cond_18

    .line 883
    .line 884
    :cond_16
    if-eqz v11, :cond_17

    .line 885
    .line 886
    sget-object v12, Landroid/graphics/Bitmap$Config;->HARDWARE:Landroid/graphics/Bitmap$Config;

    .line 887
    .line 888
    if-ne v11, v12, :cond_18

    .line 889
    .line 890
    :cond_17
    sget-object v11, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 891
    .line 892
    :cond_18
    sget-object v12, Lmm/i;->g:Ld8/c;

    .line 893
    .line 894
    invoke-static {v6, v12}, Lyl/m;->e(Lmm/n;Ld8/c;)Ljava/lang/Object;

    .line 895
    .line 896
    .line 897
    move-result-object v12

    .line 898
    check-cast v12, Ljava/lang/Boolean;

    .line 899
    .line 900
    invoke-virtual {v12}, Ljava/lang/Boolean;->booleanValue()Z

    .line 901
    .line 902
    .line 903
    move-result v12

    .line 904
    if-eqz v12, :cond_19

    .line 905
    .line 906
    sget-object v12, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 907
    .line 908
    if-ne v11, v12, :cond_19

    .line 909
    .line 910
    iget-object v12, v1, Landroid/graphics/BitmapFactory$Options;->outMimeType:Ljava/lang/String;

    .line 911
    .line 912
    invoke-static {v12, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 913
    .line 914
    .line 915
    move-result v0

    .line 916
    if-eqz v0, :cond_19

    .line 917
    .line 918
    sget-object v11, Landroid/graphics/Bitmap$Config;->RGB_565:Landroid/graphics/Bitmap$Config;

    .line 919
    .line 920
    :cond_19
    iget-object v0, v1, Landroid/graphics/BitmapFactory$Options;->outConfig:Landroid/graphics/Bitmap$Config;

    .line 921
    .line 922
    sget-object v12, Landroid/graphics/Bitmap$Config;->RGBA_F16:Landroid/graphics/Bitmap$Config;

    .line 923
    .line 924
    if-ne v0, v12, :cond_1a

    .line 925
    .line 926
    sget-object v0, Landroid/graphics/Bitmap$Config;->HARDWARE:Landroid/graphics/Bitmap$Config;

    .line 927
    .line 928
    if-eq v11, v0, :cond_1a

    .line 929
    .line 930
    move-object v11, v12

    .line 931
    :cond_1a
    iput-object v11, v1, Landroid/graphics/BitmapFactory$Options;->inPreferredConfig:Landroid/graphics/Bitmap$Config;

    .line 932
    .line 933
    iget v0, v1, Landroid/graphics/BitmapFactory$Options;->outWidth:I

    .line 934
    .line 935
    const/16 v11, 0x10e

    .line 936
    .line 937
    const/16 v12, 0x5a

    .line 938
    .line 939
    if-lez v0, :cond_29

    .line 940
    .line 941
    iget v14, v1, Landroid/graphics/BitmapFactory$Options;->outHeight:I

    .line 942
    .line 943
    if-gtz v14, :cond_1b

    .line 944
    .line 945
    move/from16 v18, v3

    .line 946
    .line 947
    move v2, v4

    .line 948
    move-object v12, v8

    .line 949
    move-object v3, v9

    .line 950
    goto/16 :goto_10

    .line 951
    .line 952
    :cond_1b
    if-eq v3, v12, :cond_1d

    .line 953
    .line 954
    if-ne v3, v11, :cond_1c

    .line 955
    .line 956
    goto :goto_8

    .line 957
    :cond_1c
    move v15, v0

    .line 958
    goto :goto_9

    .line 959
    :cond_1d
    :goto_8
    move v15, v14

    .line 960
    :goto_9
    if-eq v3, v12, :cond_1f

    .line 961
    .line 962
    if-ne v3, v11, :cond_1e

    .line 963
    .line 964
    goto :goto_a

    .line 965
    :cond_1e
    move v0, v14

    .line 966
    :cond_1f
    :goto_a
    iget-object v14, v6, Lmm/n;->b:Lnm/h;

    .line 967
    .line 968
    iget-object v11, v6, Lmm/n;->c:Lnm/g;

    .line 969
    .line 970
    sget-object v12, Lmm/h;->b:Ld8/c;

    .line 971
    .line 972
    invoke-static {v6, v12}, Lyl/m;->e(Lmm/n;Ld8/c;)Ljava/lang/Object;

    .line 973
    .line 974
    .line 975
    move-result-object v12

    .line 976
    check-cast v12, Lnm/h;

    .line 977
    .line 978
    invoke-static {v15, v0, v14, v11, v12}, Lno/nordicsemi/android/ble/d;->d(IILnm/h;Lnm/g;Lnm/h;)J

    .line 979
    .line 980
    .line 981
    move-result-wide v16

    .line 982
    const/16 v12, 0x20

    .line 983
    .line 984
    move/from16 v18, v3

    .line 985
    .line 986
    shr-long v2, v16, v12

    .line 987
    .line 988
    long-to-int v2, v2

    .line 989
    const-wide v19, 0xffffffffL

    .line 990
    .line 991
    .line 992
    .line 993
    .line 994
    move-object v12, v8

    .line 995
    and-long v7, v16, v19

    .line 996
    .line 997
    long-to-int v7, v7

    .line 998
    div-int v8, v15, v2

    .line 999
    .line 1000
    invoke-static {v8}, Ljava/lang/Integer;->highestOneBit(I)I

    .line 1001
    .line 1002
    .line 1003
    move-result v8

    .line 1004
    div-int v16, v0, v7

    .line 1005
    .line 1006
    invoke-static/range {v16 .. v16}, Ljava/lang/Integer;->highestOneBit(I)I

    .line 1007
    .line 1008
    .line 1009
    move-result v3

    .line 1010
    invoke-virtual {v11}, Ljava/lang/Enum;->ordinal()I

    .line 1011
    .line 1012
    .line 1013
    move-result v14

    .line 1014
    if-eqz v14, :cond_21

    .line 1015
    .line 1016
    if-ne v14, v4, :cond_20

    .line 1017
    .line 1018
    invoke-static {v8, v3}, Ljava/lang/Math;->max(II)I

    .line 1019
    .line 1020
    .line 1021
    move-result v3

    .line 1022
    goto :goto_b

    .line 1023
    :cond_20
    new-instance v0, La8/r0;

    .line 1024
    .line 1025
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 1026
    .line 1027
    .line 1028
    throw v0

    .line 1029
    :cond_21
    invoke-static {v8, v3}, Ljava/lang/Math;->min(II)I

    .line 1030
    .line 1031
    .line 1032
    move-result v3

    .line 1033
    :goto_b
    if-ge v3, v4, :cond_22

    .line 1034
    .line 1035
    move v3, v4

    .line 1036
    :cond_22
    iput v3, v1, Landroid/graphics/BitmapFactory$Options;->inSampleSize:I

    .line 1037
    .line 1038
    int-to-double v14, v15

    .line 1039
    move-object/from16 v19, v6

    .line 1040
    .line 1041
    int-to-double v5, v3

    .line 1042
    div-double/2addr v14, v5

    .line 1043
    move-object v3, v9

    .line 1044
    int-to-double v8, v0

    .line 1045
    div-double/2addr v8, v5

    .line 1046
    int-to-double v5, v2

    .line 1047
    move-wide/from16 v21, v5

    .line 1048
    .line 1049
    int-to-double v4, v7

    .line 1050
    div-double v6, v21, v14

    .line 1051
    .line 1052
    div-double/2addr v4, v8

    .line 1053
    invoke-virtual {v11}, Ljava/lang/Enum;->ordinal()I

    .line 1054
    .line 1055
    .line 1056
    move-result v0

    .line 1057
    if-eqz v0, :cond_24

    .line 1058
    .line 1059
    const/4 v2, 0x1

    .line 1060
    if-ne v0, v2, :cond_23

    .line 1061
    .line 1062
    invoke-static {v6, v7, v4, v5}, Ljava/lang/Math;->min(DD)D

    .line 1063
    .line 1064
    .line 1065
    move-result-wide v4

    .line 1066
    :goto_c
    move-object/from16 v0, v19

    .line 1067
    .line 1068
    goto :goto_d

    .line 1069
    :cond_23
    new-instance v0, La8/r0;

    .line 1070
    .line 1071
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 1072
    .line 1073
    .line 1074
    throw v0

    .line 1075
    :cond_24
    invoke-static {v6, v7, v4, v5}, Ljava/lang/Math;->max(DD)D

    .line 1076
    .line 1077
    .line 1078
    move-result-wide v4

    .line 1079
    goto :goto_c

    .line 1080
    :goto_d
    iget-object v0, v0, Lmm/n;->d:Lnm/d;

    .line 1081
    .line 1082
    sget-object v6, Lnm/d;->e:Lnm/d;

    .line 1083
    .line 1084
    const-wide/high16 v7, 0x3ff0000000000000L    # 1.0

    .line 1085
    .line 1086
    if-ne v0, v6, :cond_25

    .line 1087
    .line 1088
    cmpl-double v0, v4, v7

    .line 1089
    .line 1090
    if-lez v0, :cond_25

    .line 1091
    .line 1092
    move-wide v4, v7

    .line 1093
    :cond_25
    cmpg-double v0, v4, v7

    .line 1094
    .line 1095
    if-nez v0, :cond_26

    .line 1096
    .line 1097
    const/4 v0, 0x1

    .line 1098
    goto :goto_e

    .line 1099
    :cond_26
    const/4 v0, 0x0

    .line 1100
    :goto_e
    xor-int/lit8 v6, v0, 0x1

    .line 1101
    .line 1102
    iput-boolean v6, v1, Landroid/graphics/BitmapFactory$Options;->inScaled:Z

    .line 1103
    .line 1104
    if-nez v0, :cond_27

    .line 1105
    .line 1106
    cmpl-double v0, v4, v7

    .line 1107
    .line 1108
    const v6, 0x7fffffff

    .line 1109
    .line 1110
    .line 1111
    if-lez v0, :cond_28

    .line 1112
    .line 1113
    int-to-double v7, v6

    .line 1114
    div-double/2addr v7, v4

    .line 1115
    invoke-static {v7, v8}, Lcy0/a;->h(D)I

    .line 1116
    .line 1117
    .line 1118
    move-result v0

    .line 1119
    iput v0, v1, Landroid/graphics/BitmapFactory$Options;->inDensity:I

    .line 1120
    .line 1121
    iput v6, v1, Landroid/graphics/BitmapFactory$Options;->inTargetDensity:I

    .line 1122
    .line 1123
    :cond_27
    :goto_f
    const/4 v0, 0x0

    .line 1124
    goto :goto_11

    .line 1125
    :cond_28
    iput v6, v1, Landroid/graphics/BitmapFactory$Options;->inDensity:I

    .line 1126
    .line 1127
    int-to-double v6, v6

    .line 1128
    mul-double/2addr v6, v4

    .line 1129
    invoke-static {v6, v7}, Lcy0/a;->h(D)I

    .line 1130
    .line 1131
    .line 1132
    move-result v0

    .line 1133
    iput v0, v1, Landroid/graphics/BitmapFactory$Options;->inTargetDensity:I

    .line 1134
    .line 1135
    goto :goto_f

    .line 1136
    :cond_29
    move/from16 v18, v3

    .line 1137
    .line 1138
    move-object v12, v8

    .line 1139
    move-object v3, v9

    .line 1140
    move v2, v4

    .line 1141
    :goto_10
    iput v2, v1, Landroid/graphics/BitmapFactory$Options;->inSampleSize:I

    .line 1142
    .line 1143
    const/4 v0, 0x0

    .line 1144
    iput-boolean v0, v1, Landroid/graphics/BitmapFactory$Options;->inScaled:Z

    .line 1145
    .line 1146
    :goto_11
    :try_start_0
    new-instance v4, Lcx0/a;

    .line 1147
    .line 1148
    const/4 v8, 0x3

    .line 1149
    invoke-direct {v4, v3, v8}, Lcx0/a;-><init>(Ljava/lang/Object;I)V

    .line 1150
    .line 1151
    .line 1152
    const/4 v14, 0x0

    .line 1153
    invoke-static {v4, v14, v1}, Landroid/graphics/BitmapFactory;->decodeStream(Ljava/io/InputStream;Landroid/graphics/Rect;Landroid/graphics/BitmapFactory$Options;)Landroid/graphics/Bitmap;

    .line 1154
    .line 1155
    .line 1156
    move-result-object v4
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 1157
    invoke-virtual {v3}, Lu01/b0;->close()V

    .line 1158
    .line 1159
    .line 1160
    iget-object v3, v12, Lbm/b;->f:Ljava/lang/Object;

    .line 1161
    .line 1162
    check-cast v3, Ljava/lang/Exception;

    .line 1163
    .line 1164
    if-nez v3, :cond_36

    .line 1165
    .line 1166
    if-eqz v4, :cond_35

    .line 1167
    .line 1168
    invoke-virtual {v13}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 1169
    .line 1170
    .line 1171
    move-result-object v3

    .line 1172
    invoke-virtual {v3}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 1173
    .line 1174
    .line 1175
    move-result-object v3

    .line 1176
    iget v3, v3, Landroid/util/DisplayMetrics;->densityDpi:I

    .line 1177
    .line 1178
    invoke-virtual {v4, v3}, Landroid/graphics/Bitmap;->setDensity(I)V

    .line 1179
    .line 1180
    .line 1181
    if-nez v10, :cond_2a

    .line 1182
    .line 1183
    if-lez v18, :cond_32

    .line 1184
    .line 1185
    :cond_2a
    new-instance v3, Landroid/graphics/Matrix;

    .line 1186
    .line 1187
    invoke-direct {v3}, Landroid/graphics/Matrix;-><init>()V

    .line 1188
    .line 1189
    .line 1190
    invoke-virtual {v4}, Landroid/graphics/Bitmap;->getWidth()I

    .line 1191
    .line 1192
    .line 1193
    move-result v5

    .line 1194
    int-to-float v5, v5

    .line 1195
    const/high16 v6, 0x40000000    # 2.0f

    .line 1196
    .line 1197
    div-float/2addr v5, v6

    .line 1198
    invoke-virtual {v4}, Landroid/graphics/Bitmap;->getHeight()I

    .line 1199
    .line 1200
    .line 1201
    move-result v7

    .line 1202
    int-to-float v7, v7

    .line 1203
    div-float/2addr v7, v6

    .line 1204
    if-eqz v10, :cond_2b

    .line 1205
    .line 1206
    const/high16 v6, -0x40800000    # -1.0f

    .line 1207
    .line 1208
    const/high16 v8, 0x3f800000    # 1.0f

    .line 1209
    .line 1210
    invoke-virtual {v3, v6, v8, v5, v7}, Landroid/graphics/Matrix;->postScale(FFFF)Z

    .line 1211
    .line 1212
    .line 1213
    :cond_2b
    if-lez v18, :cond_2c

    .line 1214
    .line 1215
    move/from16 v6, v18

    .line 1216
    .line 1217
    int-to-float v8, v6

    .line 1218
    invoke-virtual {v3, v8, v5, v7}, Landroid/graphics/Matrix;->postRotate(FFF)Z

    .line 1219
    .line 1220
    .line 1221
    goto :goto_12

    .line 1222
    :cond_2c
    move/from16 v6, v18

    .line 1223
    .line 1224
    :goto_12
    new-instance v5, Landroid/graphics/RectF;

    .line 1225
    .line 1226
    invoke-virtual {v4}, Landroid/graphics/Bitmap;->getWidth()I

    .line 1227
    .line 1228
    .line 1229
    move-result v7

    .line 1230
    int-to-float v7, v7

    .line 1231
    invoke-virtual {v4}, Landroid/graphics/Bitmap;->getHeight()I

    .line 1232
    .line 1233
    .line 1234
    move-result v8

    .line 1235
    int-to-float v8, v8

    .line 1236
    const/4 v9, 0x0

    .line 1237
    invoke-direct {v5, v9, v9, v7, v8}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 1238
    .line 1239
    .line 1240
    invoke-virtual {v3, v5}, Landroid/graphics/Matrix;->mapRect(Landroid/graphics/RectF;)Z

    .line 1241
    .line 1242
    .line 1243
    iget v7, v5, Landroid/graphics/RectF;->left:F

    .line 1244
    .line 1245
    cmpg-float v8, v7, v9

    .line 1246
    .line 1247
    if-nez v8, :cond_2d

    .line 1248
    .line 1249
    iget v8, v5, Landroid/graphics/RectF;->top:F

    .line 1250
    .line 1251
    cmpg-float v8, v8, v9

    .line 1252
    .line 1253
    if-nez v8, :cond_2d

    .line 1254
    .line 1255
    :goto_13
    const/16 v5, 0x5a

    .line 1256
    .line 1257
    goto :goto_14

    .line 1258
    :cond_2d
    neg-float v7, v7

    .line 1259
    iget v5, v5, Landroid/graphics/RectF;->top:F

    .line 1260
    .line 1261
    neg-float v5, v5

    .line 1262
    invoke-virtual {v3, v7, v5}, Landroid/graphics/Matrix;->postTranslate(FF)Z

    .line 1263
    .line 1264
    .line 1265
    goto :goto_13

    .line 1266
    :goto_14
    if-eq v6, v5, :cond_30

    .line 1267
    .line 1268
    const/16 v5, 0x10e

    .line 1269
    .line 1270
    if-ne v6, v5, :cond_2e

    .line 1271
    .line 1272
    goto :goto_15

    .line 1273
    :cond_2e
    invoke-virtual {v4}, Landroid/graphics/Bitmap;->getWidth()I

    .line 1274
    .line 1275
    .line 1276
    move-result v5

    .line 1277
    invoke-virtual {v4}, Landroid/graphics/Bitmap;->getHeight()I

    .line 1278
    .line 1279
    .line 1280
    move-result v6

    .line 1281
    invoke-virtual {v4}, Landroid/graphics/Bitmap;->getConfig()Landroid/graphics/Bitmap$Config;

    .line 1282
    .line 1283
    .line 1284
    move-result-object v7

    .line 1285
    if-nez v7, :cond_2f

    .line 1286
    .line 1287
    sget-object v7, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 1288
    .line 1289
    :cond_2f
    invoke-static {v5, v6, v7}, Landroid/graphics/Bitmap;->createBitmap(IILandroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;

    .line 1290
    .line 1291
    .line 1292
    move-result-object v5

    .line 1293
    goto :goto_16

    .line 1294
    :cond_30
    :goto_15
    invoke-virtual {v4}, Landroid/graphics/Bitmap;->getHeight()I

    .line 1295
    .line 1296
    .line 1297
    move-result v5

    .line 1298
    invoke-virtual {v4}, Landroid/graphics/Bitmap;->getWidth()I

    .line 1299
    .line 1300
    .line 1301
    move-result v6

    .line 1302
    invoke-virtual {v4}, Landroid/graphics/Bitmap;->getConfig()Landroid/graphics/Bitmap$Config;

    .line 1303
    .line 1304
    .line 1305
    move-result-object v7

    .line 1306
    if-nez v7, :cond_31

    .line 1307
    .line 1308
    sget-object v7, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 1309
    .line 1310
    :cond_31
    invoke-static {v5, v6, v7}, Landroid/graphics/Bitmap;->createBitmap(IILandroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;

    .line 1311
    .line 1312
    .line 1313
    move-result-object v5

    .line 1314
    :goto_16
    new-instance v6, Landroid/graphics/Canvas;

    .line 1315
    .line 1316
    invoke-direct {v6, v5}, Landroid/graphics/Canvas;-><init>(Landroid/graphics/Bitmap;)V

    .line 1317
    .line 1318
    .line 1319
    sget-object v7, Lbm/o;->a:Landroid/graphics/Paint;

    .line 1320
    .line 1321
    invoke-virtual {v6, v4, v3, v7}, Landroid/graphics/Canvas;->drawBitmap(Landroid/graphics/Bitmap;Landroid/graphics/Matrix;Landroid/graphics/Paint;)V

    .line 1322
    .line 1323
    .line 1324
    invoke-virtual {v4}, Landroid/graphics/Bitmap;->recycle()V

    .line 1325
    .line 1326
    .line 1327
    move-object v4, v5

    .line 1328
    :cond_32
    new-instance v3, Lbm/i;

    .line 1329
    .line 1330
    invoke-virtual {v13}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 1331
    .line 1332
    .line 1333
    move-result-object v5

    .line 1334
    new-instance v6, Landroid/graphics/drawable/BitmapDrawable;

    .line 1335
    .line 1336
    invoke-direct {v6, v5, v4}, Landroid/graphics/drawable/BitmapDrawable;-><init>(Landroid/content/res/Resources;Landroid/graphics/Bitmap;)V

    .line 1337
    .line 1338
    .line 1339
    invoke-static {v6}, Lyl/m;->c(Landroid/graphics/drawable/Drawable;)Lyl/j;

    .line 1340
    .line 1341
    .line 1342
    move-result-object v4

    .line 1343
    iget v5, v1, Landroid/graphics/BitmapFactory$Options;->inSampleSize:I

    .line 1344
    .line 1345
    const/4 v2, 0x1

    .line 1346
    if-gt v5, v2, :cond_33

    .line 1347
    .line 1348
    iget-boolean v1, v1, Landroid/graphics/BitmapFactory$Options;->inScaled:Z

    .line 1349
    .line 1350
    if-eqz v1, :cond_34

    .line 1351
    .line 1352
    :cond_33
    move v0, v2

    .line 1353
    :cond_34
    invoke-direct {v3, v4, v0}, Lbm/i;-><init>(Lyl/j;Z)V

    .line 1354
    .line 1355
    .line 1356
    return-object v3

    .line 1357
    :cond_35
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1358
    .line 1359
    const-string v1, "BitmapFactory returned a null bitmap. Often this means BitmapFactory could not decode the image data read from the image source (e.g. network, disk, or memory) as it\'s not encoded as a valid image format."

    .line 1360
    .line 1361
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1362
    .line 1363
    .line 1364
    throw v0

    .line 1365
    :cond_36
    throw v3

    .line 1366
    :catchall_0
    move-exception v0

    .line 1367
    move-object v1, v0

    .line 1368
    :try_start_1
    throw v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 1369
    :catchall_1
    move-exception v0

    .line 1370
    invoke-static {v3, v1}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 1371
    .line 1372
    .line 1373
    throw v0

    .line 1374
    :cond_37
    throw v11

    .line 1375
    :cond_38
    throw v10

    .line 1376
    :pswitch_15
    check-cast v0, Lbf/d;

    .line 1377
    .line 1378
    iget-object v0, v0, Lbf/d;->d:Lay0/a;

    .line 1379
    .line 1380
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 1381
    .line 1382
    .line 1383
    return-object v6

    .line 1384
    :pswitch_16
    check-cast v0, Lba0/v;

    .line 1385
    .line 1386
    new-instance v1, Llj0/a;

    .line 1387
    .line 1388
    iget-object v0, v0, Lba0/v;->n:Lij0/a;

    .line 1389
    .line 1390
    const v2, 0x7f12038c

    .line 1391
    .line 1392
    .line 1393
    check-cast v0, Ljj0/f;

    .line 1394
    .line 1395
    invoke-virtual {v0, v2}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 1396
    .line 1397
    .line 1398
    move-result-object v0

    .line 1399
    invoke-direct {v1, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 1400
    .line 1401
    .line 1402
    return-object v1

    .line 1403
    :pswitch_17
    check-cast v0, Lba0/g;

    .line 1404
    .line 1405
    new-instance v1, Llj0/a;

    .line 1406
    .line 1407
    iget-object v0, v0, Lba0/g;->l:Lij0/a;

    .line 1408
    .line 1409
    const v2, 0x7f120374

    .line 1410
    .line 1411
    .line 1412
    check-cast v0, Ljj0/f;

    .line 1413
    .line 1414
    invoke-virtual {v0, v2}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 1415
    .line 1416
    .line 1417
    move-result-object v0

    .line 1418
    invoke-direct {v1, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 1419
    .line 1420
    .line 1421
    return-object v1

    .line 1422
    :pswitch_18
    check-cast v0, Landroidx/lifecycle/i1;

    .line 1423
    .line 1424
    invoke-static {v0}, Landroidx/lifecycle/v0;->h(Landroidx/lifecycle/i1;)Landroidx/lifecycle/x0;

    .line 1425
    .line 1426
    .line 1427
    move-result-object v0

    .line 1428
    return-object v0

    .line 1429
    :pswitch_19
    check-cast v0, Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;

    .line 1430
    .line 1431
    if-eqz v0, :cond_39

    .line 1432
    .line 1433
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;->getReturnCode()I

    .line 1434
    .line 1435
    .line 1436
    move-result v1

    .line 1437
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1438
    .line 1439
    .line 1440
    move-result-object v1

    .line 1441
    goto :goto_17

    .line 1442
    :cond_39
    const-string v1, "--"

    .line 1443
    .line 1444
    :goto_17
    if-eqz v0, :cond_3a

    .line 1445
    .line 1446
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;->getReasonString()Ljava/lang/String;

    .line 1447
    .line 1448
    .line 1449
    move-result-object v0

    .line 1450
    if-nez v0, :cond_3b

    .line 1451
    .line 1452
    :cond_3a
    const-string v0, ""

    .line 1453
    .line 1454
    :cond_3b
    new-instance v2, Ljava/lang/StringBuilder;

    .line 1455
    .line 1456
    const-string v3, "MQTT client disconnected. Reason: "

    .line 1457
    .line 1458
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1459
    .line 1460
    .line 1461
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1462
    .line 1463
    .line 1464
    const-string v1, " "

    .line 1465
    .line 1466
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1467
    .line 1468
    .line 1469
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1470
    .line 1471
    .line 1472
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1473
    .line 1474
    .line 1475
    move-result-object v0

    .line 1476
    return-object v0

    .line 1477
    :pswitch_1a
    check-cast v0, Lac0/k;

    .line 1478
    .line 1479
    new-instance v1, Ljava/lang/StringBuilder;

    .line 1480
    .line 1481
    const-string v2, "Processing Mqtt subscription action: "

    .line 1482
    .line 1483
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1484
    .line 1485
    .line 1486
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1487
    .line 1488
    .line 1489
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1490
    .line 1491
    .line 1492
    move-result-object v0

    .line 1493
    return-object v0

    .line 1494
    :pswitch_1b
    check-cast v0, Lac0/w;

    .line 1495
    .line 1496
    new-instance v1, Lac0/h;

    .line 1497
    .line 1498
    invoke-direct {v1, v0}, Lac0/h;-><init>(Lac0/w;)V

    .line 1499
    .line 1500
    .line 1501
    return-object v1

    .line 1502
    :pswitch_1c
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveCorrectionViewModel;

    .line 1503
    .line 1504
    invoke-interface {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveCorrectionViewModel;->stopParking()V

    .line 1505
    .line 1506
    .line 1507
    return-object v6

    .line 1508
    nop

    .line 1509
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
