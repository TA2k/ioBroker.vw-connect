.class public final synthetic Ld2/g;
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
    iput p2, p0, Ld2/g;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ld2/g;->e:Ljava/lang/Object;

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
    .locals 12

    .line 1
    iget v0, p0, Ld2/g;->d:I

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    const-string v2, "<this>"

    .line 5
    .line 6
    const/4 v3, 0x1

    .line 7
    const/4 v4, 0x0

    .line 8
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 9
    .line 10
    iget-object p0, p0, Ld2/g;->e:Ljava/lang/Object;

    .line 11
    .line 12
    packed-switch v0, :pswitch_data_0

    .line 13
    .line 14
    .line 15
    check-cast p0, Lg40/u0;

    .line 16
    .line 17
    new-instance v0, Llj0/a;

    .line 18
    .line 19
    invoke-static {p0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    if-eqz p0, :cond_2

    .line 27
    .line 28
    if-eq p0, v3, :cond_1

    .line 29
    .line 30
    const/4 v1, 0x2

    .line 31
    if-ne p0, v1, :cond_0

    .line 32
    .line 33
    const-string p0, "myskodaclub_tab_title_rewards"

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    new-instance p0, La8/r0;

    .line 37
    .line 38
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 39
    .line 40
    .line 41
    throw p0

    .line 42
    :cond_1
    const-string p0, "myskodaclub_tab_title_challenges"

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_2
    const-string p0, "myskodaclub_tab_title_overview"

    .line 46
    .line 47
    :goto_0
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    return-object v0

    .line 51
    :pswitch_0
    check-cast p0, Lh40/p0;

    .line 52
    .line 53
    new-instance v0, Llj0/a;

    .line 54
    .line 55
    iget-object p0, p0, Lh40/p0;->h:Lij0/a;

    .line 56
    .line 57
    const v1, 0x7f120382

    .line 58
    .line 59
    .line 60
    check-cast p0, Ljj0/f;

    .line 61
    .line 62
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    return-object v0

    .line 70
    :pswitch_1
    check-cast p0, Lg40/k;

    .line 71
    .line 72
    new-instance v0, Llj0/a;

    .line 73
    .line 74
    iget-object p0, p0, Lg40/k;->d:Ljava/lang/String;

    .line 75
    .line 76
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    return-object v0

    .line 80
    :pswitch_2
    check-cast p0, Lh40/k;

    .line 81
    .line 82
    new-instance v0, Llj0/a;

    .line 83
    .line 84
    iget-object p0, p0, Lh40/k;->l:Lij0/a;

    .line 85
    .line 86
    const v1, 0x7f120374

    .line 87
    .line 88
    .line 89
    check-cast p0, Ljj0/f;

    .line 90
    .line 91
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    return-object v0

    .line 99
    :pswitch_3
    check-cast p0, Lh2/s9;

    .line 100
    .line 101
    iget-object v0, p0, Lh2/s9;->n:Ll2/j1;

    .line 102
    .line 103
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    check-cast v0, Ljava/lang/Boolean;

    .line 108
    .line 109
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 110
    .line 111
    .line 112
    move-result v0

    .line 113
    if-nez v0, :cond_3

    .line 114
    .line 115
    iget-object p0, p0, Lh2/s9;->b:Lay0/a;

    .line 116
    .line 117
    if-eqz p0, :cond_3

    .line 118
    .line 119
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    :cond_3
    return-object v5

    .line 123
    :pswitch_4
    check-cast p0, Lh2/r8;

    .line 124
    .line 125
    iget-object p0, p0, Lh2/r8;->d:Lc1/j;

    .line 126
    .line 127
    return-object p0

    .line 128
    :pswitch_5
    check-cast p0, Lh2/w5;

    .line 129
    .line 130
    iget-object p0, p0, Lh2/w5;->g:Lay0/a;

    .line 131
    .line 132
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    return-object v5

    .line 136
    :pswitch_6
    check-cast p0, Lh2/m0;

    .line 137
    .line 138
    iget-object p0, p0, Lh2/m0;->a:Lh2/r8;

    .line 139
    .line 140
    iget-object p0, p0, Lh2/r8;->e:Li2/p;

    .line 141
    .line 142
    invoke-virtual {p0}, Li2/p;->f()F

    .line 143
    .line 144
    .line 145
    move-result p0

    .line 146
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 147
    .line 148
    .line 149
    move-result-object p0

    .line 150
    return-object p0

    .line 151
    :pswitch_7
    check-cast p0, Lgn0/i;

    .line 152
    .line 153
    iget-object p0, p0, Lgn0/i;->b:Len0/s;

    .line 154
    .line 155
    iget-object p0, p0, Len0/s;->f:Lwe0/a;

    .line 156
    .line 157
    check-cast p0, Lwe0/c;

    .line 158
    .line 159
    invoke-virtual {p0}, Lwe0/c;->b()Z

    .line 160
    .line 161
    .line 162
    move-result p0

    .line 163
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 164
    .line 165
    .line 166
    move-result-object p0

    .line 167
    return-object p0

    .line 168
    :pswitch_8
    check-cast p0, Lgb0/c0;

    .line 169
    .line 170
    iget-object p0, p0, Lgb0/c0;->d:Ljava/util/ArrayList;

    .line 171
    .line 172
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 173
    .line 174
    .line 175
    move-result p0

    .line 176
    const-string v0, "VehicleSensitiveRepository: "

    .line 177
    .line 178
    invoke-static {p0, v0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 179
    .line 180
    .line 181
    move-result-object p0

    .line 182
    return-object p0

    .line 183
    :pswitch_9
    check-cast p0, Lg70/e;

    .line 184
    .line 185
    new-instance v0, Llj0/b;

    .line 186
    .line 187
    iget-object p0, p0, Lg70/e;->j:Lij0/a;

    .line 188
    .line 189
    const v1, 0x7f120f6f

    .line 190
    .line 191
    .line 192
    check-cast p0, Ljj0/f;

    .line 193
    .line 194
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 195
    .line 196
    .line 197
    move-result-object p0

    .line 198
    const-string v1, "https://availability.skoda-auto.com"

    .line 199
    .line 200
    invoke-direct {v0, p0, v1}, Llj0/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    return-object v0

    .line 204
    :pswitch_a
    check-cast p0, Lg2/a;

    .line 205
    .line 206
    invoke-static {p0}, Lv3/f;->m(Lv3/p;)V

    .line 207
    .line 208
    .line 209
    return-object v5

    .line 210
    :pswitch_b
    check-cast p0, Lg1/p2;

    .line 211
    .line 212
    iget-boolean p0, p0, Lx2/r;->q:Z

    .line 213
    .line 214
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 215
    .line 216
    .line 217
    move-result-object p0

    .line 218
    return-object p0

    .line 219
    :pswitch_c
    check-cast p0, Lxy0/n;

    .line 220
    .line 221
    invoke-interface {p0}, Lxy0/z;->n()Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object p0

    .line 225
    invoke-static {p0}, Lxy0/q;->b(Ljava/lang/Object;)Ljava/lang/Object;

    .line 226
    .line 227
    .line 228
    move-result-object p0

    .line 229
    check-cast p0, Lg1/r1;

    .line 230
    .line 231
    return-object p0

    .line 232
    :pswitch_d
    check-cast p0, Lt4/c;

    .line 233
    .line 234
    const/16 v0, 0x7d

    .line 235
    .line 236
    int-to-float v0, v0

    .line 237
    invoke-interface {p0, v0}, Lt4/c;->w0(F)F

    .line 238
    .line 239
    .line 240
    move-result p0

    .line 241
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 242
    .line 243
    .line 244
    move-result-object p0

    .line 245
    return-object p0

    .line 246
    :pswitch_e
    check-cast p0, Lfr0/h;

    .line 247
    .line 248
    new-instance v0, Llj0/b;

    .line 249
    .line 250
    iget-object p0, p0, Lfr0/h;->i:Lij0/a;

    .line 251
    .line 252
    const v1, 0x7f1201c3

    .line 253
    .line 254
    .line 255
    check-cast p0, Ljj0/f;

    .line 256
    .line 257
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 258
    .line 259
    .line 260
    move-result-object p0

    .line 261
    const-string v1, "myskoda://app/settings/subscriptions"

    .line 262
    .line 263
    invoke-direct {v0, p0, v1}, Llj0/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 264
    .line 265
    .line 266
    return-object v0

    .line 267
    :pswitch_f
    check-cast p0, Lff/g;

    .line 268
    .line 269
    sget-object v0, Lff/d;->a:Lff/d;

    .line 270
    .line 271
    invoke-virtual {p0, v0}, Lff/g;->a(Lff/e;)V

    .line 272
    .line 273
    .line 274
    return-object v5

    .line 275
    :pswitch_10
    check-cast p0, Lfd0/b;

    .line 276
    .line 277
    new-instance v0, Lc/c;

    .line 278
    .line 279
    invoke-direct {v0, p0, v3}, Lc/c;-><init>(Ljava/lang/Object;I)V

    .line 280
    .line 281
    .line 282
    return-object v0

    .line 283
    :pswitch_11
    check-cast p0, Lfb/o;

    .line 284
    .line 285
    sget-object v0, Lnb/a;->a:Ljava/lang/String;

    .line 286
    .line 287
    iget-object v0, p0, Lfb/o;->a:Lfb/u;

    .line 288
    .line 289
    new-instance v1, Ljava/util/HashSet;

    .line 290
    .line 291
    invoke-direct {v1}, Ljava/util/HashSet;-><init>()V

    .line 292
    .line 293
    .line 294
    iget-object v2, p0, Lfb/o;->e:Ljava/util/ArrayList;

    .line 295
    .line 296
    invoke-interface {v1, v2}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    .line 297
    .line 298
    .line 299
    invoke-static {p0}, Lfb/o;->e(Lfb/o;)Ljava/util/HashSet;

    .line 300
    .line 301
    .line 302
    move-result-object v2

    .line 303
    invoke-virtual {v1}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 304
    .line 305
    .line 306
    move-result-object v4

    .line 307
    :cond_4
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 308
    .line 309
    .line 310
    move-result v6

    .line 311
    if-eqz v6, :cond_5

    .line 312
    .line 313
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 314
    .line 315
    .line 316
    move-result-object v6

    .line 317
    check-cast v6, Ljava/lang/String;

    .line 318
    .line 319
    invoke-virtual {v2, v6}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 320
    .line 321
    .line 322
    move-result v6

    .line 323
    if-eqz v6, :cond_4

    .line 324
    .line 325
    goto :goto_1

    .line 326
    :cond_5
    iget-object v2, p0, Lfb/o;->e:Ljava/util/ArrayList;

    .line 327
    .line 328
    invoke-interface {v1, v2}, Ljava/util/Set;->removeAll(Ljava/util/Collection;)Z

    .line 329
    .line 330
    .line 331
    const/4 v3, 0x0

    .line 332
    :goto_1
    if-nez v3, :cond_7

    .line 333
    .line 334
    iget-object v1, v0, Lfb/u;->c:Landroidx/work/impl/WorkDatabase;

    .line 335
    .line 336
    iget-object v2, v0, Lfb/u;->b:Leb/b;

    .line 337
    .line 338
    invoke-virtual {v1}, Lla/u;->c()V

    .line 339
    .line 340
    .line 341
    :try_start_0
    invoke-static {v1, v2, p0}, Lnb/e;->b(Landroidx/work/impl/WorkDatabase;Leb/b;Lfb/o;)V

    .line 342
    .line 343
    .line 344
    invoke-static {p0}, Lnb/a;->a(Lfb/o;)Z

    .line 345
    .line 346
    .line 347
    move-result p0

    .line 348
    invoke-virtual {v1}, Lla/u;->q()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 349
    .line 350
    .line 351
    invoke-virtual {v1}, Lla/u;->g()V

    .line 352
    .line 353
    .line 354
    if-eqz p0, :cond_6

    .line 355
    .line 356
    iget-object p0, v0, Lfb/u;->c:Landroidx/work/impl/WorkDatabase;

    .line 357
    .line 358
    iget-object v0, v0, Lfb/u;->e:Ljava/util/List;

    .line 359
    .line 360
    invoke-static {v2, p0, v0}, Lfb/i;->b(Leb/b;Landroidx/work/impl/WorkDatabase;Ljava/util/List;)V

    .line 361
    .line 362
    .line 363
    :cond_6
    return-object v5

    .line 364
    :catchall_0
    move-exception v0

    .line 365
    move-object p0, v0

    .line 366
    invoke-virtual {v1}, Lla/u;->g()V

    .line 367
    .line 368
    .line 369
    throw p0

    .line 370
    :cond_7
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 371
    .line 372
    new-instance v1, Ljava/lang/StringBuilder;

    .line 373
    .line 374
    const-string v2, "WorkContinuation has cycles ("

    .line 375
    .line 376
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 377
    .line 378
    .line 379
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 380
    .line 381
    .line 382
    const-string p0, ")"

    .line 383
    .line 384
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 385
    .line 386
    .line 387
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 388
    .line 389
    .line 390
    move-result-object p0

    .line 391
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 392
    .line 393
    .line 394
    throw v0

    .line 395
    :pswitch_12
    check-cast p0, Ldv0/e;

    .line 396
    .line 397
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 398
    .line 399
    .line 400
    move-result-object v0

    .line 401
    new-instance v2, Ldv0/b;

    .line 402
    .line 403
    const/4 v3, 0x5

    .line 404
    invoke-direct {v2, p0, v4, v3}, Ldv0/b;-><init>(Ldv0/e;Lkotlin/coroutines/Continuation;I)V

    .line 405
    .line 406
    .line 407
    invoke-static {v0, v4, v4, v2, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 408
    .line 409
    .line 410
    return-object v5

    .line 411
    :pswitch_13
    check-cast p0, Leu0/d;

    .line 412
    .line 413
    iget-object v1, p0, Leu0/d;->a:Landroid/content/Context;

    .line 414
    .line 415
    new-instance v0, Lcq/o;

    .line 416
    .line 417
    sget-object v5, Lko/h;->c:Lko/h;

    .line 418
    .line 419
    sget-object v3, Lbq/g;->a:Lc2/k;

    .line 420
    .line 421
    sget-object v4, Lbq/f;->b:Lbq/f;

    .line 422
    .line 423
    const/4 v2, 0x0

    .line 424
    invoke-direct/range {v0 .. v5}, Lko/i;-><init>(Landroid/content/Context;Lcz/skodaauto/myskoda/app/main/system/MainActivity;Lc2/k;Lko/b;Lko/h;)V

    .line 425
    .line 426
    .line 427
    return-object v0

    .line 428
    :pswitch_14
    check-cast p0, Lei/e;

    .line 429
    .line 430
    iget-object v0, p0, Lei/e;->i:Lyy0/c2;

    .line 431
    .line 432
    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 433
    .line 434
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 435
    .line 436
    .line 437
    invoke-virtual {v0, v4, v2}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 438
    .line 439
    .line 440
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 441
    .line 442
    .line 443
    move-result-object v0

    .line 444
    new-instance v2, La7/k;

    .line 445
    .line 446
    const/16 v6, 0x12

    .line 447
    .line 448
    invoke-direct {v2, p0, v4, v6}, La7/k;-><init>(Landroidx/lifecycle/b1;Lkotlin/coroutines/Continuation;I)V

    .line 449
    .line 450
    .line 451
    invoke-static {v0, v4, v4, v2, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 452
    .line 453
    .line 454
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 455
    .line 456
    .line 457
    move-result-object v0

    .line 458
    new-instance v2, Le60/m;

    .line 459
    .line 460
    invoke-direct {v2, p0, v4, v3}, Le60/m;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 461
    .line 462
    .line 463
    invoke-static {v0, v4, v4, v2, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 464
    .line 465
    .line 466
    return-object v5

    .line 467
    :pswitch_15
    check-cast p0, Le20/g;

    .line 468
    .line 469
    new-instance v0, Llj0/b;

    .line 470
    .line 471
    iget-object p0, p0, Le20/g;->i:Lij0/a;

    .line 472
    .line 473
    const v1, 0x7f12026b

    .line 474
    .line 475
    .line 476
    check-cast p0, Ljj0/f;

    .line 477
    .line 478
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 479
    .line 480
    .line 481
    move-result-object p0

    .line 482
    const-string v1, "https://go.skoda.eu/driving-score"

    .line 483
    .line 484
    invoke-direct {v0, p0, v1}, Llj0/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 485
    .line 486
    .line 487
    return-object v0

    .line 488
    :pswitch_16
    check-cast p0, Le10/d;

    .line 489
    .line 490
    iget-object p0, p0, Le10/d;->a:Le10/c;

    .line 491
    .line 492
    check-cast p0, Lc10/a;

    .line 493
    .line 494
    iget-object p0, p0, Lc10/a;->a:Lwe0/a;

    .line 495
    .line 496
    check-cast p0, Lwe0/c;

    .line 497
    .line 498
    invoke-virtual {p0}, Lwe0/c;->b()Z

    .line 499
    .line 500
    .line 501
    move-result p0

    .line 502
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 503
    .line 504
    .line 505
    move-result-object p0

    .line 506
    return-object p0

    .line 507
    :pswitch_17
    check-cast p0, Le1/o1;

    .line 508
    .line 509
    sget-object v0, Le1/e1;->a:Ll2/e0;

    .line 510
    .line 511
    invoke-static {p0, v0}, Lv3/f;->i(Lv3/l;Ll2/s1;)Ljava/lang/Object;

    .line 512
    .line 513
    .line 514
    move-result-object v0

    .line 515
    check-cast v0, Le1/k;

    .line 516
    .line 517
    iput-object v0, p0, Le1/o1;->E:Le1/k;

    .line 518
    .line 519
    if-eqz v0, :cond_8

    .line 520
    .line 521
    new-instance v6, Le1/j;

    .line 522
    .line 523
    iget-object v7, v0, Le1/k;->a:Landroid/content/Context;

    .line 524
    .line 525
    iget-object v8, v0, Le1/k;->b:Lt4/c;

    .line 526
    .line 527
    iget-wide v9, v0, Le1/k;->c:J

    .line 528
    .line 529
    iget-object v11, v0, Le1/k;->d:Lk1/z0;

    .line 530
    .line 531
    invoke-direct/range {v6 .. v11}, Le1/j;-><init>(Landroid/content/Context;Lt4/c;JLk1/z0;)V

    .line 532
    .line 533
    .line 534
    move-object v4, v6

    .line 535
    :cond_8
    iput-object v4, p0, Le1/o1;->F:Le1/j;

    .line 536
    .line 537
    return-object v5

    .line 538
    :pswitch_18
    check-cast p0, Lrw0/d;

    .line 539
    .line 540
    check-cast p0, Lfw0/h;

    .line 541
    .line 542
    iget v0, p0, Lfw0/h;->a:I

    .line 543
    .line 544
    packed-switch v0, :pswitch_data_1

    .line 545
    .line 546
    .line 547
    iget-object p0, p0, Lfw0/h;->d:Ljava/lang/Object;

    .line 548
    .line 549
    check-cast p0, Ljava/io/InputStream;

    .line 550
    .line 551
    sget-object v0, Lvy0/p0;->a:Lcz0/e;

    .line 552
    .line 553
    sget-object v0, Lcz0/d;->e:Lcz0/d;

    .line 554
    .line 555
    sget-object v1, Ldx0/b;->a:Ldx0/a;

    .line 556
    .line 557
    invoke-static {p0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 558
    .line 559
    .line 560
    const-string v2, "context"

    .line 561
    .line 562
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 563
    .line 564
    .line 565
    const-string v2, "pool"

    .line 566
    .line 567
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 568
    .line 569
    .line 570
    new-instance v1, Lcx0/c;

    .line 571
    .line 572
    new-instance v2, Lnz0/b;

    .line 573
    .line 574
    invoke-direct {v2, p0}, Lnz0/b;-><init>(Ljava/io/InputStream;)V

    .line 575
    .line 576
    .line 577
    invoke-direct {v1, v2, v0}, Lcx0/c;-><init>(Lnz0/b;Lpx0/g;)V

    .line 578
    .line 579
    .line 580
    goto :goto_2

    .line 581
    :pswitch_19
    iget-object p0, p0, Lfw0/h;->d:Ljava/lang/Object;

    .line 582
    .line 583
    move-object v1, p0

    .line 584
    check-cast v1, Lio/ktor/utils/io/t;

    .line 585
    .line 586
    :goto_2
    return-object v1

    .line 587
    :pswitch_1a
    check-cast p0, Ldi/o;

    .line 588
    .line 589
    invoke-static {p0}, Ldi/o;->a(Ldi/o;)V

    .line 590
    .line 591
    .line 592
    return-object v5

    .line 593
    :pswitch_1b
    check-cast p0, Ldf/d;

    .line 594
    .line 595
    iget-object v0, p0, Ldf/d;->e:Li91/i4;

    .line 596
    .line 597
    iget-object p0, p0, Ldf/d;->g:Lyy0/l1;

    .line 598
    .line 599
    invoke-static {p0}, Ldf/d;->a(Lyy0/a2;)Ljava/util/ArrayList;

    .line 600
    .line 601
    .line 602
    move-result-object p0

    .line 603
    invoke-virtual {v0, p0}, Li91/i4;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 604
    .line 605
    .line 606
    return-object v5

    .line 607
    :pswitch_1c
    check-cast p0, Ld2/l;

    .line 608
    .line 609
    iput-object v4, p0, Ld2/l;->C:Ld2/k;

    .line 610
    .line 611
    invoke-static {p0}, Lv3/f;->o(Lv3/x1;)V

    .line 612
    .line 613
    .line 614
    invoke-static {p0}, Lv3/f;->n(Lv3/y;)V

    .line 615
    .line 616
    .line 617
    invoke-static {p0}, Lv3/f;->m(Lv3/p;)V

    .line 618
    .line 619
    .line 620
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 621
    .line 622
    return-object p0

    .line 623
    :pswitch_1d
    check-cast p0, Ld2/i;

    .line 624
    .line 625
    iput-object v4, p0, Ld2/i;->G:Ld2/h;

    .line 626
    .line 627
    invoke-static {p0}, Lv3/f;->o(Lv3/x1;)V

    .line 628
    .line 629
    .line 630
    invoke-static {p0}, Lv3/f;->n(Lv3/y;)V

    .line 631
    .line 632
    .line 633
    invoke-static {p0}, Lv3/f;->m(Lv3/p;)V

    .line 634
    .line 635
    .line 636
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 637
    .line 638
    return-object p0

    .line 639
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
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

    .line 640
    .line 641
    .line 642
    .line 643
    .line 644
    .line 645
    .line 646
    .line 647
    .line 648
    .line 649
    .line 650
    .line 651
    .line 652
    .line 653
    .line 654
    .line 655
    .line 656
    .line 657
    .line 658
    .line 659
    .line 660
    .line 661
    .line 662
    .line 663
    .line 664
    .line 665
    .line 666
    .line 667
    .line 668
    .line 669
    .line 670
    .line 671
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_19
    .end packed-switch
.end method
