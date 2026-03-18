.class public final synthetic Le81/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lez0/c;Lez0/b;)V
    .locals 0

    .line 1
    const/4 p2, 0x3

    iput p2, p0, Le81/w;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Le81/w;->e:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p2, p0, Le81/w;->d:I

    iput-object p1, p0, Le81/w;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget v2, v0, Le81/w;->d:I

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    const-string v4, "it"

    .line 9
    .line 10
    const/4 v5, 0x7

    .line 11
    const-wide v6, 0xffffffffL

    .line 12
    .line 13
    .line 14
    .line 15
    .line 16
    const/16 v8, 0x20

    .line 17
    .line 18
    const/4 v9, 0x0

    .line 19
    const/4 v10, 0x1

    .line 20
    const/4 v11, 0x0

    .line 21
    sget-object v12, Llx0/b0;->a:Llx0/b0;

    .line 22
    .line 23
    iget-object v0, v0, Le81/w;->e:Ljava/lang/Object;

    .line 24
    .line 25
    packed-switch v2, :pswitch_data_0

    .line 26
    .line 27
    .line 28
    check-cast v0, Lv3/j0;

    .line 29
    .line 30
    check-cast v1, Lg3/d;

    .line 31
    .line 32
    const-string v2, "$this$record"

    .line 33
    .line 34
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0}, Lv3/j0;->b()V

    .line 38
    .line 39
    .line 40
    return-object v12

    .line 41
    :pswitch_0
    move-object v3, v0

    .line 42
    check-cast v3, Lh3/c;

    .line 43
    .line 44
    move-object v4, v1

    .line 45
    check-cast v4, Lv3/j0;

    .line 46
    .line 47
    const-string v0, "$this$drawWithContent"

    .line 48
    .line 49
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    new-instance v0, Le81/w;

    .line 53
    .line 54
    const/16 v1, 0x1d

    .line 55
    .line 56
    invoke-direct {v0, v4, v1}, Le81/w;-><init>(Ljava/lang/Object;I)V

    .line 57
    .line 58
    .line 59
    iget-object v1, v4, Lv3/j0;->d:Lg3/b;

    .line 60
    .line 61
    invoke-interface {v1}, Lg3/d;->e()J

    .line 62
    .line 63
    .line 64
    move-result-wide v1

    .line 65
    shr-long v9, v1, v8

    .line 66
    .line 67
    long-to-int v9, v9

    .line 68
    invoke-static {v9}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 69
    .line 70
    .line 71
    move-result v9

    .line 72
    float-to-int v9, v9

    .line 73
    and-long/2addr v1, v6

    .line 74
    long-to-int v1, v1

    .line 75
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 76
    .line 77
    .line 78
    move-result v1

    .line 79
    float-to-int v1, v1

    .line 80
    int-to-long v9, v9

    .line 81
    shl-long v8, v9, v8

    .line 82
    .line 83
    int-to-long v1, v1

    .line 84
    and-long/2addr v1, v6

    .line 85
    or-long v6, v8, v1

    .line 86
    .line 87
    iget-object v1, v4, Lv3/j0;->e:Lv3/p;

    .line 88
    .line 89
    invoke-virtual {v4}, Lv3/j0;->getLayoutDirection()Lt4/m;

    .line 90
    .line 91
    .line 92
    move-result-object v2

    .line 93
    new-instance v8, La3/g;

    .line 94
    .line 95
    invoke-direct {v8, v4, v1, v0, v5}, La3/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 96
    .line 97
    .line 98
    move-object v5, v2

    .line 99
    invoke-virtual/range {v3 .. v8}, Lh3/c;->g(Lt4/c;Lt4/m;JLay0/k;)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v4}, Lv3/j0;->x0()Lgw0/c;

    .line 103
    .line 104
    .line 105
    move-result-object v0

    .line 106
    invoke-virtual {v0}, Lgw0/c;->h()Le3/r;

    .line 107
    .line 108
    .line 109
    move-result-object v0

    .line 110
    invoke-virtual {v4}, Lv3/j0;->x0()Lgw0/c;

    .line 111
    .line 112
    .line 113
    move-result-object v1

    .line 114
    iget-object v1, v1, Lgw0/c;->f:Ljava/lang/Object;

    .line 115
    .line 116
    check-cast v1, Lh3/c;

    .line 117
    .line 118
    invoke-virtual {v3, v0, v1}, Lh3/c;->c(Le3/r;Lh3/c;)V

    .line 119
    .line 120
    .line 121
    return-object v12

    .line 122
    :pswitch_1
    check-cast v0, Ld4/l;

    .line 123
    .line 124
    check-cast v1, Lv3/c2;

    .line 125
    .line 126
    const-string v2, "null cannot be cast to non-null type androidx.compose.material3.internal.ParentSemanticsNode"

    .line 127
    .line 128
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    check-cast v1, Li2/y0;

    .line 132
    .line 133
    iput-boolean v10, v1, Li2/y0;->s:Z

    .line 134
    .line 135
    iget-object v2, v1, Li2/y0;->r:Laa/o;

    .line 136
    .line 137
    invoke-virtual {v2, v0}, Laa/o;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    invoke-static {v1}, Lv3/f;->o(Lv3/x1;)V

    .line 141
    .line 142
    .line 143
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 144
    .line 145
    return-object v0

    .line 146
    :pswitch_2
    check-cast v0, Lh2/yb;

    .line 147
    .line 148
    check-cast v1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 149
    .line 150
    new-instance v1, La2/j;

    .line 151
    .line 152
    invoke-direct {v1, v0, v5}, La2/j;-><init>(Ljava/lang/Object;I)V

    .line 153
    .line 154
    .line 155
    return-object v1

    .line 156
    :pswitch_3
    check-cast v0, Li0/e;

    .line 157
    .line 158
    iget-object v2, v0, Li0/e;->n:Lf3/d;

    .line 159
    .line 160
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 161
    .line 162
    .line 163
    invoke-virtual {v0, v1}, Landroidx/lifecycle/i0;->j(Ljava/lang/Object;)V

    .line 164
    .line 165
    .line 166
    return-object v12

    .line 167
    :pswitch_4
    check-cast v0, Lhu/f0;

    .line 168
    .line 169
    check-cast v1, Lm6/b;

    .line 170
    .line 171
    const-string v2, "ex"

    .line 172
    .line 173
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    const-string v2, "FirebaseSessions"

    .line 177
    .line 178
    const-string v3, "CorruptionException in session data DataStore"

    .line 179
    .line 180
    invoke-static {v2, v3, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 181
    .line 182
    .line 183
    new-instance v1, Lhu/e0;

    .line 184
    .line 185
    iget-object v0, v0, Lhu/f0;->a:Lhu/p0;

    .line 186
    .line 187
    invoke-virtual {v0, v9}, Lhu/p0;->a(Lhu/j0;)Lhu/j0;

    .line 188
    .line 189
    .line 190
    move-result-object v0

    .line 191
    invoke-direct {v1, v0, v9, v9}, Lhu/e0;-><init>(Lhu/j0;Lhu/z0;Ljava/util/Map;)V

    .line 192
    .line 193
    .line 194
    return-object v1

    .line 195
    :pswitch_5
    check-cast v0, Landroid/text/style/StyleSpan;

    .line 196
    .line 197
    check-cast v1, Lgi/c;

    .line 198
    .line 199
    const-string v2, "$this$log"

    .line 200
    .line 201
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 202
    .line 203
    .line 204
    invoke-virtual {v0}, Landroid/text/style/StyleSpan;->getStyle()I

    .line 205
    .line 206
    .line 207
    move-result v0

    .line 208
    const-string v1, "TextResourceCompose, unknown StyleSpan "

    .line 209
    .line 210
    invoke-static {v0, v1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 211
    .line 212
    .line 213
    move-result-object v0

    .line 214
    return-object v0

    .line 215
    :pswitch_6
    move-object v2, v0

    .line 216
    check-cast v2, Lzi/a;

    .line 217
    .line 218
    move-object v0, v1

    .line 219
    check-cast v0, Lhi/a;

    .line 220
    .line 221
    const-string v1, "$this$sdkViewModel"

    .line 222
    .line 223
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 224
    .line 225
    .line 226
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 227
    .line 228
    const-class v3, Lti/c;

    .line 229
    .line 230
    invoke-virtual {v1, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 231
    .line 232
    .line 233
    move-result-object v3

    .line 234
    check-cast v0, Lii/a;

    .line 235
    .line 236
    invoke-virtual {v0, v3}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 237
    .line 238
    .line 239
    move-result-object v3

    .line 240
    move-object v14, v3

    .line 241
    check-cast v14, Lti/c;

    .line 242
    .line 243
    const-class v3, Lfg/c;

    .line 244
    .line 245
    invoke-virtual {v1, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 246
    .line 247
    .line 248
    move-result-object v1

    .line 249
    invoke-virtual {v0, v1}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 250
    .line 251
    .line 252
    move-result-object v0

    .line 253
    check-cast v0, Lfg/c;

    .line 254
    .line 255
    new-instance v1, Lhg/x;

    .line 256
    .line 257
    new-instance v3, Lbq0/i;

    .line 258
    .line 259
    const/16 v4, 0x11

    .line 260
    .line 261
    invoke-direct {v3, v14, v9, v4}, Lbq0/i;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 262
    .line 263
    .line 264
    new-instance v4, Lh40/w3;

    .line 265
    .line 266
    const/16 v5, 0x10

    .line 267
    .line 268
    invoke-direct {v4, v0, v9, v5}, Lh40/w3;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 269
    .line 270
    .line 271
    new-instance v5, Lh90/d;

    .line 272
    .line 273
    const/16 v18, 0x0

    .line 274
    .line 275
    const/16 v19, 0xa

    .line 276
    .line 277
    const/4 v13, 0x0

    .line 278
    const-class v15, Lti/c;

    .line 279
    .line 280
    const-string v16, "onRemoteAuthStartCharging"

    .line 281
    .line 282
    const-string v17, "onRemoteAuthStartCharging()V"

    .line 283
    .line 284
    move-object v12, v5

    .line 285
    invoke-direct/range {v12 .. v19}, Lh90/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 286
    .line 287
    .line 288
    new-instance v15, Lag/c;

    .line 289
    .line 290
    const/16 v21, 0x0

    .line 291
    .line 292
    const/16 v22, 0x14

    .line 293
    .line 294
    const/16 v16, 0x2

    .line 295
    .line 296
    const-class v18, Lfg/c;

    .line 297
    .line 298
    const-string v19, "getOverview"

    .line 299
    .line 300
    const-string v20, "getOverview-gIAlu-s(Lcariad/charging/multicharge/kitten/remoteauthorization/models/RemoteAuthorizationOverviewRequest;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 301
    .line 302
    move-object/from16 v17, v0

    .line 303
    .line 304
    invoke-direct/range {v15 .. v22}, Lag/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 305
    .line 306
    .line 307
    new-instance v7, Lh50/p;

    .line 308
    .line 309
    const/16 v0, 0x15

    .line 310
    .line 311
    invoke-direct {v7, v0}, Lh50/p;-><init>(I)V

    .line 312
    .line 313
    .line 314
    move-object v6, v15

    .line 315
    invoke-direct/range {v1 .. v7}, Lhg/x;-><init>(Lzi/a;Lbq0/i;Lh40/w3;Lh90/d;Lag/c;Lh50/p;)V

    .line 316
    .line 317
    .line 318
    invoke-static {v1}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 319
    .line 320
    .line 321
    move-result-object v0

    .line 322
    new-instance v2, Lhg/v;

    .line 323
    .line 324
    invoke-direct {v2, v1, v9, v11}, Lhg/v;-><init>(Lhg/x;Lkotlin/coroutines/Continuation;I)V

    .line 325
    .line 326
    .line 327
    const/4 v3, 0x3

    .line 328
    invoke-static {v0, v9, v9, v2, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 329
    .line 330
    .line 331
    iget-object v0, v1, Lhg/x;->d:Lzi/a;

    .line 332
    .line 333
    iget-object v0, v0, Lzi/a;->f:Ljava/lang/Long;

    .line 334
    .line 335
    invoke-virtual {v1, v0, v10}, Lhg/x;->f(Ljava/lang/Long;Z)V

    .line 336
    .line 337
    .line 338
    return-object v1

    .line 339
    :pswitch_7
    check-cast v0, Lg70/i;

    .line 340
    .line 341
    check-cast v1, Ljava/lang/String;

    .line 342
    .line 343
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 344
    .line 345
    .line 346
    iget-boolean v0, v0, Lg70/i;->f:Z

    .line 347
    .line 348
    if-nez v0, :cond_4

    .line 349
    .line 350
    sget-object v0, Ltechnology/cariad/cat/genx/QRCode;->Companion:Ltechnology/cariad/cat/genx/QRCode$Companion;

    .line 351
    .line 352
    invoke-virtual {v0, v1}, Ltechnology/cariad/cat/genx/QRCode$Companion;->parseFromString-IoAF18A(Ljava/lang/String;)Ljava/lang/Object;

    .line 353
    .line 354
    .line 355
    move-result-object v2

    .line 356
    instance-of v3, v2, Llx0/n;

    .line 357
    .line 358
    if-eqz v3, :cond_0

    .line 359
    .line 360
    move-object v2, v9

    .line 361
    :cond_0
    check-cast v2, Ltechnology/cariad/cat/genx/QRCode;

    .line 362
    .line 363
    sget-object v3, Landroidx/compose/foundation/layout/b;->a:Landroidx/compose/foundation/layout/b;

    .line 364
    .line 365
    if-eqz v2, :cond_1

    .line 366
    .line 367
    new-instance v4, Lh70/i;

    .line 368
    .line 369
    invoke-direct {v4, v2, v11}, Lh70/i;-><init>(Ltechnology/cariad/cat/genx/QRCode;I)V

    .line 370
    .line 371
    .line 372
    invoke-static {v9, v3, v4}, Llp/nd;->m(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 373
    .line 374
    .line 375
    :cond_1
    invoke-virtual {v0, v1}, Ltechnology/cariad/cat/genx/QRCode$Companion;->parseFromString-IoAF18A(Ljava/lang/String;)Ljava/lang/Object;

    .line 376
    .line 377
    .line 378
    move-result-object v0

    .line 379
    instance-of v1, v0, Llx0/n;

    .line 380
    .line 381
    if-eqz v1, :cond_2

    .line 382
    .line 383
    move-object v0, v9

    .line 384
    :cond_2
    check-cast v0, Ltechnology/cariad/cat/genx/QRCode;

    .line 385
    .line 386
    if-eqz v0, :cond_4

    .line 387
    .line 388
    new-instance v1, Lh70/i;

    .line 389
    .line 390
    invoke-direct {v1, v0, v10}, Lh70/i;-><init>(Ltechnology/cariad/cat/genx/QRCode;I)V

    .line 391
    .line 392
    .line 393
    invoke-static {v9, v3, v1}, Llp/nd;->f(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 394
    .line 395
    .line 396
    sget-object v1, Lh70/m;->b:Lw81/c;

    .line 397
    .line 398
    if-eqz v1, :cond_3

    .line 399
    .line 400
    new-instance v2, Lx41/k1;

    .line 401
    .line 402
    invoke-direct {v2, v0}, Lx41/k1;-><init>(Ltechnology/cariad/cat/genx/QRCode;)V

    .line 403
    .line 404
    .line 405
    invoke-virtual {v1, v2}, Lw81/c;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 406
    .line 407
    .line 408
    :cond_3
    sput-object v9, Lh70/m;->b:Lw81/c;

    .line 409
    .line 410
    :cond_4
    return-object v12

    .line 411
    :pswitch_8
    check-cast v0, Lg4/m0;

    .line 412
    .line 413
    check-cast v1, Lg4/e;

    .line 414
    .line 415
    iget-object v2, v1, Lg4/e;->a:Ljava/lang/Object;

    .line 416
    .line 417
    check-cast v2, Lg4/b;

    .line 418
    .line 419
    instance-of v3, v2, Lg4/m;

    .line 420
    .line 421
    const/16 v4, 0xe

    .line 422
    .line 423
    if-eqz v3, :cond_5

    .line 424
    .line 425
    move-object v3, v2

    .line 426
    check-cast v3, Lg4/m;

    .line 427
    .line 428
    iget-object v5, v3, Lg4/m;->b:Lg4/m0;

    .line 429
    .line 430
    if-nez v5, :cond_5

    .line 431
    .line 432
    iget-object v2, v3, Lg4/m;->a:Ljava/lang/String;

    .line 433
    .line 434
    iget-object v3, v3, Lg4/m;->c:Lxf0/x1;

    .line 435
    .line 436
    new-instance v5, Lg4/m;

    .line 437
    .line 438
    invoke-direct {v5, v2, v0, v3}, Lg4/m;-><init>(Ljava/lang/String;Lg4/m0;Lxf0/x1;)V

    .line 439
    .line 440
    .line 441
    invoke-static {v1, v5, v11, v4}, Lg4/e;->a(Lg4/e;Lg4/b;II)Lg4/e;

    .line 442
    .line 443
    .line 444
    move-result-object v1

    .line 445
    goto :goto_0

    .line 446
    :cond_5
    instance-of v3, v2, Lg4/l;

    .line 447
    .line 448
    if-eqz v3, :cond_6

    .line 449
    .line 450
    check-cast v2, Lg4/l;

    .line 451
    .line 452
    iget-object v3, v2, Lg4/l;->b:Lg4/m0;

    .line 453
    .line 454
    if-nez v3, :cond_6

    .line 455
    .line 456
    iget-object v3, v2, Lg4/l;->a:Ljava/lang/String;

    .line 457
    .line 458
    iget-object v2, v2, Lg4/l;->c:Lxf0/x1;

    .line 459
    .line 460
    new-instance v5, Lg4/l;

    .line 461
    .line 462
    invoke-direct {v5, v3, v0, v2}, Lg4/l;-><init>(Ljava/lang/String;Lg4/m0;Lxf0/x1;)V

    .line 463
    .line 464
    .line 465
    invoke-static {v1, v5, v11, v4}, Lg4/e;->a(Lg4/e;Lg4/b;II)Lg4/e;

    .line 466
    .line 467
    .line 468
    move-result-object v1

    .line 469
    :cond_6
    :goto_0
    return-object v1

    .line 470
    :pswitch_9
    check-cast v0, Lh2/t9;

    .line 471
    .line 472
    check-cast v1, Lh2/b5;

    .line 473
    .line 474
    iget-object v1, v1, Lh2/b5;->a:Ljava/lang/Object;

    .line 475
    .line 476
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 477
    .line 478
    .line 479
    move-result v0

    .line 480
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 481
    .line 482
    .line 483
    move-result-object v0

    .line 484
    return-object v0

    .line 485
    :pswitch_a
    check-cast v0, Lh2/w5;

    .line 486
    .line 487
    check-cast v1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 488
    .line 489
    invoke-virtual {v0}, Landroid/app/Dialog;->show()V

    .line 490
    .line 491
    .line 492
    new-instance v1, La2/j;

    .line 493
    .line 494
    const/4 v2, 0x6

    .line 495
    invoke-direct {v1, v0, v2}, La2/j;-><init>(Ljava/lang/Object;I)V

    .line 496
    .line 497
    .line 498
    return-object v1

    .line 499
    :pswitch_b
    check-cast v0, Lc1/c;

    .line 500
    .line 501
    check-cast v1, Le3/k0;

    .line 502
    .line 503
    invoke-virtual {v0}, Lc1/c;->d()Ljava/lang/Object;

    .line 504
    .line 505
    .line 506
    move-result-object v0

    .line 507
    check-cast v0, Ljava/lang/Number;

    .line 508
    .line 509
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 510
    .line 511
    .line 512
    move-result v0

    .line 513
    invoke-static {v1, v0}, Lh2/j6;->d(Le3/k0;F)F

    .line 514
    .line 515
    .line 516
    move-result v2

    .line 517
    invoke-static {v1, v0}, Lh2/j6;->e(Le3/k0;F)F

    .line 518
    .line 519
    .line 520
    move-result v0

    .line 521
    cmpg-float v3, v0, v3

    .line 522
    .line 523
    if-nez v3, :cond_7

    .line 524
    .line 525
    const/high16 v0, 0x3f800000    # 1.0f

    .line 526
    .line 527
    goto :goto_1

    .line 528
    :cond_7
    div-float v0, v2, v0

    .line 529
    .line 530
    :goto_1
    invoke-virtual {v1, v0}, Le3/k0;->p(F)V

    .line 531
    .line 532
    .line 533
    sget-wide v2, Lh2/j6;->c:J

    .line 534
    .line 535
    invoke-virtual {v1, v2, v3}, Le3/k0;->A(J)V

    .line 536
    .line 537
    .line 538
    return-object v12

    .line 539
    :pswitch_c
    check-cast v0, Lh2/h5;

    .line 540
    .line 541
    check-cast v1, Lb3/d;

    .line 542
    .line 543
    iget-object v2, v0, Lh2/h5;->D:Lc1/c;

    .line 544
    .line 545
    invoke-virtual {v2}, Lc1/c;->d()Ljava/lang/Object;

    .line 546
    .line 547
    .line 548
    move-result-object v2

    .line 549
    check-cast v2, Lt4/f;

    .line 550
    .line 551
    iget v2, v2, Lt4/f;->d:F

    .line 552
    .line 553
    invoke-virtual {v1}, Lb3/d;->a()F

    .line 554
    .line 555
    .line 556
    move-result v4

    .line 557
    mul-float/2addr v4, v2

    .line 558
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 559
    .line 560
    .line 561
    move-result-object v2

    .line 562
    iget-object v5, v0, Lh2/h5;->C:Le3/n0;

    .line 563
    .line 564
    if-nez v5, :cond_8

    .line 565
    .line 566
    sget-object v5, Lh2/i8;->a:Ll2/u2;

    .line 567
    .line 568
    invoke-static {v0, v5}, Lv3/f;->i(Lv3/l;Ll2/s1;)Ljava/lang/Object;

    .line 569
    .line 570
    .line 571
    move-result-object v5

    .line 572
    check-cast v5, Lh2/h8;

    .line 573
    .line 574
    sget-object v9, Lk2/s;->d:Lk2/f0;

    .line 575
    .line 576
    invoke-static {v5, v9}, Lh2/i8;->a(Lh2/h8;Lk2/f0;)Le3/n0;

    .line 577
    .line 578
    .line 579
    move-result-object v5

    .line 580
    :cond_8
    iget-object v9, v1, Lb3/d;->d:Lb3/b;

    .line 581
    .line 582
    invoke-interface {v9}, Lb3/b;->e()J

    .line 583
    .line 584
    .line 585
    move-result-wide v11

    .line 586
    iget-object v9, v1, Lb3/d;->d:Lb3/b;

    .line 587
    .line 588
    invoke-interface {v9}, Lb3/b;->getLayoutDirection()Lt4/m;

    .line 589
    .line 590
    .line 591
    move-result-object v9

    .line 592
    invoke-interface {v5, v11, v12, v9, v1}, Le3/n0;->a(JLt4/m;Lt4/c;)Le3/g0;

    .line 593
    .line 594
    .line 595
    move-result-object v5

    .line 596
    instance-of v9, v5, Le3/e0;

    .line 597
    .line 598
    if-eqz v9, :cond_9

    .line 599
    .line 600
    check-cast v5, Le3/e0;

    .line 601
    .line 602
    iget-object v5, v5, Le3/e0;->a:Ld3/c;

    .line 603
    .line 604
    invoke-static {v2, v5}, Le3/i;->b(Le3/i;Ld3/c;)V

    .line 605
    .line 606
    .line 607
    goto :goto_2

    .line 608
    :cond_9
    instance-of v9, v5, Le3/f0;

    .line 609
    .line 610
    if-eqz v9, :cond_a

    .line 611
    .line 612
    check-cast v5, Le3/f0;

    .line 613
    .line 614
    iget-object v5, v5, Le3/f0;->a:Ld3/d;

    .line 615
    .line 616
    invoke-static {v2, v5}, Le3/i;->c(Le3/i;Ld3/d;)V

    .line 617
    .line 618
    .line 619
    goto :goto_2

    .line 620
    :cond_a
    instance-of v9, v5, Le3/d0;

    .line 621
    .line 622
    if-eqz v9, :cond_b

    .line 623
    .line 624
    check-cast v5, Le3/d0;

    .line 625
    .line 626
    iget-object v5, v5, Le3/d0;->a:Le3/i;

    .line 627
    .line 628
    invoke-static {v2, v5}, Le3/i;->a(Le3/i;Le3/i;)V

    .line 629
    .line 630
    .line 631
    :goto_2
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 632
    .line 633
    .line 634
    move-result-object v5

    .line 635
    new-instance v9, Ld3/c;

    .line 636
    .line 637
    iget-object v11, v1, Lb3/d;->d:Lb3/b;

    .line 638
    .line 639
    invoke-interface {v11}, Lb3/b;->e()J

    .line 640
    .line 641
    .line 642
    move-result-wide v11

    .line 643
    and-long/2addr v11, v6

    .line 644
    long-to-int v11, v11

    .line 645
    invoke-static {v11}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 646
    .line 647
    .line 648
    move-result v11

    .line 649
    sub-float/2addr v11, v4

    .line 650
    iget-object v4, v1, Lb3/d;->d:Lb3/b;

    .line 651
    .line 652
    invoke-interface {v4}, Lb3/b;->e()J

    .line 653
    .line 654
    .line 655
    move-result-wide v12

    .line 656
    shr-long/2addr v12, v8

    .line 657
    long-to-int v4, v12

    .line 658
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 659
    .line 660
    .line 661
    move-result v4

    .line 662
    iget-object v8, v1, Lb3/d;->d:Lb3/b;

    .line 663
    .line 664
    invoke-interface {v8}, Lb3/b;->e()J

    .line 665
    .line 666
    .line 667
    move-result-wide v12

    .line 668
    and-long/2addr v6, v12

    .line 669
    long-to-int v6, v6

    .line 670
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 671
    .line 672
    .line 673
    move-result v6

    .line 674
    invoke-direct {v9, v3, v11, v4, v6}, Ld3/c;-><init>(FFFF)V

    .line 675
    .line 676
    .line 677
    invoke-static {v5, v9}, Le3/i;->b(Le3/i;Ld3/c;)V

    .line 678
    .line 679
    .line 680
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 681
    .line 682
    .line 683
    move-result-object v3

    .line 684
    invoke-virtual {v3, v5, v2, v10}, Le3/i;->i(Le3/i;Le3/i;I)Z

    .line 685
    .line 686
    .line 687
    new-instance v2, Let/g;

    .line 688
    .line 689
    const/16 v4, 0x12

    .line 690
    .line 691
    invoke-direct {v2, v4, v3, v0}, Let/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 692
    .line 693
    .line 694
    invoke-virtual {v1, v2}, Lb3/d;->b(Lay0/k;)Lb3/g;

    .line 695
    .line 696
    .line 697
    move-result-object v0

    .line 698
    return-object v0

    .line 699
    :cond_b
    new-instance v0, La8/r0;

    .line 700
    .line 701
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 702
    .line 703
    .line 704
    throw v0

    .line 705
    :pswitch_d
    check-cast v0, Llx0/l;

    .line 706
    .line 707
    check-cast v1, Ld4/l;

    .line 708
    .line 709
    iget-object v0, v0, Llx0/l;->d:Ljava/lang/Object;

    .line 710
    .line 711
    check-cast v0, Ljava/lang/String;

    .line 712
    .line 713
    invoke-static {v1, v0}, Ld4/x;->d(Ld4/l;Ljava/lang/String;)V

    .line 714
    .line 715
    .line 716
    return-object v12

    .line 717
    :pswitch_e
    check-cast v0, Lg1/u2;

    .line 718
    .line 719
    check-cast v1, Ld3/b;

    .line 720
    .line 721
    iget-object v2, v0, Lg1/u2;->k:Lg1/e2;

    .line 722
    .line 723
    iget-wide v3, v1, Ld3/b;->a:J

    .line 724
    .line 725
    iget v1, v0, Lg1/u2;->j:I

    .line 726
    .line 727
    invoke-virtual {v0, v2, v3, v4, v1}, Lg1/u2;->c(Lg1/e2;JI)J

    .line 728
    .line 729
    .line 730
    move-result-wide v0

    .line 731
    new-instance v2, Ld3/b;

    .line 732
    .line 733
    invoke-direct {v2, v0, v1}, Ld3/b;-><init>(J)V

    .line 734
    .line 735
    .line 736
    return-object v2

    .line 737
    :pswitch_f
    check-cast v0, Lg1/p2;

    .line 738
    .line 739
    check-cast v1, Lt3/y;

    .line 740
    .line 741
    iget-object v0, v0, Lg1/p2;->J:Lg1/y;

    .line 742
    .line 743
    iput-object v1, v0, Lg1/y;->w:Lt3/y;

    .line 744
    .line 745
    iget-boolean v1, v0, Lg1/y;->y:Z

    .line 746
    .line 747
    if-eqz v1, :cond_c

    .line 748
    .line 749
    invoke-virtual {v0}, Lg1/y;->Y0()Ld3/c;

    .line 750
    .line 751
    .line 752
    move-result-object v1

    .line 753
    if-eqz v1, :cond_c

    .line 754
    .line 755
    iget-wide v2, v0, Lg1/y;->z:J

    .line 756
    .line 757
    invoke-virtual {v0, v1, v2, v3}, Lg1/y;->Z0(Ld3/c;J)Z

    .line 758
    .line 759
    .line 760
    move-result v1

    .line 761
    if-nez v1, :cond_c

    .line 762
    .line 763
    iput-boolean v10, v0, Lg1/y;->x:Z

    .line 764
    .line 765
    invoke-virtual {v0}, Lg1/y;->a1()V

    .line 766
    .line 767
    .line 768
    :cond_c
    iput-boolean v11, v0, Lg1/y;->y:Z

    .line 769
    .line 770
    return-object v12

    .line 771
    :pswitch_10
    check-cast v0, Li40/k0;

    .line 772
    .line 773
    check-cast v1, Lp3/t;

    .line 774
    .line 775
    invoke-static {v1, v11}, Lp3/s;->h(Lp3/t;Z)J

    .line 776
    .line 777
    .line 778
    move-result-wide v2

    .line 779
    and-long/2addr v2, v6

    .line 780
    long-to-int v2, v2

    .line 781
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 782
    .line 783
    .line 784
    move-result v2

    .line 785
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 786
    .line 787
    .line 788
    move-result-object v2

    .line 789
    invoke-virtual {v0, v1, v2}, Li40/k0;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 790
    .line 791
    .line 792
    invoke-virtual {v1}, Lp3/t;->a()V

    .line 793
    .line 794
    .line 795
    return-object v12

    .line 796
    :pswitch_11
    check-cast v0, Lal/c;

    .line 797
    .line 798
    check-cast v1, Lp3/t;

    .line 799
    .line 800
    invoke-static {v1, v11}, Lp3/s;->h(Lp3/t;Z)J

    .line 801
    .line 802
    .line 803
    move-result-wide v2

    .line 804
    shr-long/2addr v2, v8

    .line 805
    long-to-int v2, v2

    .line 806
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 807
    .line 808
    .line 809
    move-result v2

    .line 810
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 811
    .line 812
    .line 813
    move-result-object v2

    .line 814
    invoke-virtual {v0, v1, v2}, Lal/c;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 815
    .line 816
    .line 817
    invoke-virtual {v1}, Lp3/t;->a()V

    .line 818
    .line 819
    .line 820
    return-object v12

    .line 821
    :pswitch_12
    check-cast v0, Lvy0/x1;

    .line 822
    .line 823
    check-cast v1, Ljava/lang/Throwable;

    .line 824
    .line 825
    invoke-virtual {v0, v9}, Lvy0/p1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 826
    .line 827
    .line 828
    return-object v12

    .line 829
    :pswitch_13
    check-cast v0, Lkw0/c;

    .line 830
    .line 831
    check-cast v1, Ljava/lang/Throwable;

    .line 832
    .line 833
    iget-object v0, v0, Lkw0/c;->e:Lvy0/z1;

    .line 834
    .line 835
    const-string v2, "null cannot be cast to non-null type kotlinx.coroutines.CompletableJob"

    .line 836
    .line 837
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 838
    .line 839
    .line 840
    if-nez v1, :cond_d

    .line 841
    .line 842
    invoke-virtual {v0}, Lvy0/k1;->l0()Z

    .line 843
    .line 844
    .line 845
    goto :goto_3

    .line 846
    :cond_d
    new-instance v2, Lvy0/u;

    .line 847
    .line 848
    invoke-direct {v2, v1, v11}, Lvy0/u;-><init>(Ljava/lang/Throwable;Z)V

    .line 849
    .line 850
    .line 851
    invoke-virtual {v0, v2}, Lvy0/p1;->W(Ljava/lang/Object;)Z

    .line 852
    .line 853
    .line 854
    :goto_3
    return-object v12

    .line 855
    :pswitch_14
    check-cast v0, Lvy0/r0;

    .line 856
    .line 857
    check-cast v1, Ljava/lang/Throwable;

    .line 858
    .line 859
    invoke-interface {v0}, Lvy0/r0;->dispose()V

    .line 860
    .line 861
    .line 862
    return-object v12

    .line 863
    :pswitch_15
    check-cast v0, Lvy0/z1;

    .line 864
    .line 865
    check-cast v1, Ljava/lang/Throwable;

    .line 866
    .line 867
    sget-object v2, Lfw0/f0;->a:Lt21/b;

    .line 868
    .line 869
    if-eqz v1, :cond_e

    .line 870
    .line 871
    new-instance v3, Ljava/lang/StringBuilder;

    .line 872
    .line 873
    const-string v4, "Cancelling request because engine Job failed with error: "

    .line 874
    .line 875
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 876
    .line 877
    .line 878
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 879
    .line 880
    .line 881
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 882
    .line 883
    .line 884
    move-result-object v3

    .line 885
    invoke-interface {v2, v3}, Lt21/b;->h(Ljava/lang/String;)V

    .line 886
    .line 887
    .line 888
    const-string v2, "Engine failed"

    .line 889
    .line 890
    invoke-static {v2, v1}, Lvy0/e0;->a(Ljava/lang/String;Ljava/lang/Throwable;)Ljava/util/concurrent/CancellationException;

    .line 891
    .line 892
    .line 893
    move-result-object v1

    .line 894
    invoke-virtual {v0, v1}, Lvy0/p1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 895
    .line 896
    .line 897
    goto :goto_4

    .line 898
    :cond_e
    const-string v1, "Cancelling request because engine Job completed"

    .line 899
    .line 900
    invoke-interface {v2, v1}, Lt21/b;->h(Ljava/lang/String;)V

    .line 901
    .line 902
    .line 903
    invoke-virtual {v0}, Lvy0/k1;->l0()Z

    .line 904
    .line 905
    .line 906
    :goto_4
    return-object v12

    .line 907
    :pswitch_16
    check-cast v0, Lvy0/k1;

    .line 908
    .line 909
    check-cast v1, Ljava/lang/Throwable;

    .line 910
    .line 911
    invoke-virtual {v0}, Lvy0/k1;->l0()Z

    .line 912
    .line 913
    .line 914
    return-object v12

    .line 915
    :pswitch_17
    check-cast v0, Lf31/m;

    .line 916
    .line 917
    check-cast v1, Le31/m3;

    .line 918
    .line 919
    const-string v2, "response"

    .line 920
    .line 921
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 922
    .line 923
    .line 924
    new-instance v2, Li31/d0;

    .line 925
    .line 926
    iget-object v3, v1, Le31/m3;->a:Le31/f3;

    .line 927
    .line 928
    iget-object v3, v3, Le31/f3;->c:Ljava/lang/String;

    .line 929
    .line 930
    iget-object v4, v1, Le31/m3;->f:Ljava/lang/String;

    .line 931
    .line 932
    iget-object v1, v1, Le31/m3;->k:Ljava/lang/Boolean;

    .line 933
    .line 934
    if-eqz v1, :cond_f

    .line 935
    .line 936
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 937
    .line 938
    .line 939
    move-result v11

    .line 940
    :cond_f
    invoke-direct {v2, v3, v4, v11}, Li31/d0;-><init>(Ljava/lang/String;Ljava/lang/String;Z)V

    .line 941
    .line 942
    .line 943
    iget-object v0, v0, Lf31/m;->a:Lb31/a;

    .line 944
    .line 945
    invoke-virtual {v0, v2}, Lb31/a;->a(Ljava/lang/Object;)V

    .line 946
    .line 947
    .line 948
    return-object v2

    .line 949
    :pswitch_18
    check-cast v0, Lf01/g;

    .line 950
    .line 951
    check-cast v1, Ljava/io/IOException;

    .line 952
    .line 953
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 954
    .line 955
    .line 956
    sget-object v1, Le01/g;->a:Ljava/util/TimeZone;

    .line 957
    .line 958
    iput-boolean v10, v0, Lf01/g;->n:Z

    .line 959
    .line 960
    return-object v12

    .line 961
    :pswitch_19
    check-cast v0, Lez0/c;

    .line 962
    .line 963
    check-cast v1, Ljava/lang/Throwable;

    .line 964
    .line 965
    invoke-virtual {v0, v9}, Lez0/c;->d(Ljava/lang/Object;)V

    .line 966
    .line 967
    .line 968
    return-object v12

    .line 969
    :pswitch_1a
    check-cast v0, Lkw/d;

    .line 970
    .line 971
    check-cast v1, Lpw/g;

    .line 972
    .line 973
    if-eqz v1, :cond_16

    .line 974
    .line 975
    iget-wide v1, v1, Lpw/g;->a:J

    .line 976
    .line 977
    iget-object v0, v0, Lkw/d;->t:Ljava/util/TreeMap;

    .line 978
    .line 979
    invoke-virtual {v0}, Ljava/util/TreeMap;->values()Ljava/util/Collection;

    .line 980
    .line 981
    .line 982
    move-result-object v0

    .line 983
    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 984
    .line 985
    .line 986
    move-result-object v0

    .line 987
    const/high16 v3, 0x7f800000    # Float.POSITIVE_INFINITY

    .line 988
    .line 989
    :goto_5
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 990
    .line 991
    .line 992
    move-result v4

    .line 993
    if-eqz v4, :cond_16

    .line 994
    .line 995
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 996
    .line 997
    .line 998
    move-result-object v4

    .line 999
    check-cast v4, Ljava/util/List;

    .line 1000
    .line 1001
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 1002
    .line 1003
    .line 1004
    check-cast v4, Ljava/lang/Iterable;

    .line 1005
    .line 1006
    new-instance v5, Ljava/util/LinkedHashMap;

    .line 1007
    .line 1008
    invoke-direct {v5}, Ljava/util/LinkedHashMap;-><init>()V

    .line 1009
    .line 1010
    .line 1011
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 1012
    .line 1013
    .line 1014
    move-result-object v4

    .line 1015
    :goto_6
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 1016
    .line 1017
    .line 1018
    move-result v6

    .line 1019
    if-eqz v6, :cond_11

    .line 1020
    .line 1021
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1022
    .line 1023
    .line 1024
    move-result-object v6

    .line 1025
    move-object v7, v6

    .line 1026
    check-cast v7, Low/e;

    .line 1027
    .line 1028
    shr-long v9, v1, v8

    .line 1029
    .line 1030
    long-to-int v9, v9

    .line 1031
    invoke-static {v9}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 1032
    .line 1033
    .line 1034
    move-result v9

    .line 1035
    iget v7, v7, Low/e;->b:F

    .line 1036
    .line 1037
    sub-float/2addr v9, v7

    .line 1038
    invoke-static {v9}, Ljava/lang/Math;->abs(F)F

    .line 1039
    .line 1040
    .line 1041
    move-result v7

    .line 1042
    invoke-static {v7}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1043
    .line 1044
    .line 1045
    move-result-object v7

    .line 1046
    invoke-virtual {v5, v7}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1047
    .line 1048
    .line 1049
    move-result-object v9

    .line 1050
    if-nez v9, :cond_10

    .line 1051
    .line 1052
    new-instance v9, Ljava/util/ArrayList;

    .line 1053
    .line 1054
    invoke-direct {v9}, Ljava/util/ArrayList;-><init>()V

    .line 1055
    .line 1056
    .line 1057
    invoke-interface {v5, v7, v9}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1058
    .line 1059
    .line 1060
    :cond_10
    check-cast v9, Ljava/util/List;

    .line 1061
    .line 1062
    invoke-interface {v9, v6}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1063
    .line 1064
    .line 1065
    goto :goto_6

    .line 1066
    :cond_11
    invoke-virtual {v5}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 1067
    .line 1068
    .line 1069
    move-result-object v4

    .line 1070
    check-cast v4, Ljava/lang/Iterable;

    .line 1071
    .line 1072
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 1073
    .line 1074
    .line 1075
    move-result-object v4

    .line 1076
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 1077
    .line 1078
    .line 1079
    move-result v5

    .line 1080
    if-eqz v5, :cond_15

    .line 1081
    .line 1082
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1083
    .line 1084
    .line 1085
    move-result-object v5

    .line 1086
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 1087
    .line 1088
    .line 1089
    move-result v6

    .line 1090
    if-nez v6, :cond_12

    .line 1091
    .line 1092
    goto :goto_7

    .line 1093
    :cond_12
    move-object v6, v5

    .line 1094
    check-cast v6, Ljava/util/Map$Entry;

    .line 1095
    .line 1096
    invoke-interface {v6}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 1097
    .line 1098
    .line 1099
    move-result-object v6

    .line 1100
    check-cast v6, Ljava/lang/Number;

    .line 1101
    .line 1102
    invoke-virtual {v6}, Ljava/lang/Number;->floatValue()F

    .line 1103
    .line 1104
    .line 1105
    move-result v6

    .line 1106
    :cond_13
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1107
    .line 1108
    .line 1109
    move-result-object v7

    .line 1110
    move-object v9, v7

    .line 1111
    check-cast v9, Ljava/util/Map$Entry;

    .line 1112
    .line 1113
    invoke-interface {v9}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 1114
    .line 1115
    .line 1116
    move-result-object v9

    .line 1117
    check-cast v9, Ljava/lang/Number;

    .line 1118
    .line 1119
    invoke-virtual {v9}, Ljava/lang/Number;->floatValue()F

    .line 1120
    .line 1121
    .line 1122
    move-result v9

    .line 1123
    invoke-static {v6, v9}, Ljava/lang/Float;->compare(FF)I

    .line 1124
    .line 1125
    .line 1126
    move-result v10

    .line 1127
    if-lez v10, :cond_14

    .line 1128
    .line 1129
    move-object v5, v7

    .line 1130
    move v6, v9

    .line 1131
    :cond_14
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 1132
    .line 1133
    .line 1134
    move-result v7

    .line 1135
    if-nez v7, :cond_13

    .line 1136
    .line 1137
    :goto_7
    check-cast v5, Ljava/util/Map$Entry;

    .line 1138
    .line 1139
    invoke-interface {v5}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 1140
    .line 1141
    .line 1142
    move-result-object v4

    .line 1143
    check-cast v4, Ljava/lang/Number;

    .line 1144
    .line 1145
    invoke-virtual {v4}, Ljava/lang/Number;->floatValue()F

    .line 1146
    .line 1147
    .line 1148
    move-result v4

    .line 1149
    invoke-interface {v5}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 1150
    .line 1151
    .line 1152
    move-result-object v5

    .line 1153
    check-cast v5, Ljava/util/List;

    .line 1154
    .line 1155
    cmpl-float v3, v4, v3

    .line 1156
    .line 1157
    if-gtz v3, :cond_16

    .line 1158
    .line 1159
    move v3, v4

    .line 1160
    goto/16 :goto_5

    .line 1161
    .line 1162
    :cond_15
    new-instance v0, Ljava/util/NoSuchElementException;

    .line 1163
    .line 1164
    invoke-direct {v0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 1165
    .line 1166
    .line 1167
    throw v0

    .line 1168
    :cond_16
    return-object v12

    .line 1169
    :pswitch_1b
    check-cast v0, Let/h;

    .line 1170
    .line 1171
    check-cast v1, Lq6/b;

    .line 1172
    .line 1173
    sget-object v2, Let/h;->c:Lq6/e;

    .line 1174
    .line 1175
    invoke-virtual {v1}, Lq6/b;->a()Ljava/util/Map;

    .line 1176
    .line 1177
    .line 1178
    move-result-object v3

    .line 1179
    invoke-interface {v3}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 1180
    .line 1181
    .line 1182
    move-result-object v3

    .line 1183
    invoke-interface {v3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 1184
    .line 1185
    .line 1186
    move-result-object v3

    .line 1187
    const-wide/16 v4, 0x0

    .line 1188
    .line 1189
    move-wide v6, v4

    .line 1190
    :cond_17
    :goto_8
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 1191
    .line 1192
    .line 1193
    move-result v8

    .line 1194
    if-eqz v8, :cond_1a

    .line 1195
    .line 1196
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1197
    .line 1198
    .line 1199
    move-result-object v8

    .line 1200
    check-cast v8, Ljava/util/Map$Entry;

    .line 1201
    .line 1202
    invoke-interface {v8}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 1203
    .line 1204
    .line 1205
    move-result-object v12

    .line 1206
    instance-of v12, v12, Ljava/util/Set;

    .line 1207
    .line 1208
    if-eqz v12, :cond_17

    .line 1209
    .line 1210
    invoke-interface {v8}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 1211
    .line 1212
    .line 1213
    move-result-object v12

    .line 1214
    check-cast v12, Lq6/e;

    .line 1215
    .line 1216
    invoke-interface {v8}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 1217
    .line 1218
    .line 1219
    move-result-object v8

    .line 1220
    check-cast v8, Ljava/util/Set;

    .line 1221
    .line 1222
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 1223
    .line 1224
    .line 1225
    move-result-wide v13

    .line 1226
    invoke-virtual {v0, v13, v14}, Let/h;->b(J)Ljava/lang/String;

    .line 1227
    .line 1228
    .line 1229
    move-result-object v13

    .line 1230
    invoke-interface {v8, v13}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 1231
    .line 1232
    .line 1233
    move-result v8

    .line 1234
    if-eqz v8, :cond_19

    .line 1235
    .line 1236
    filled-new-array {v13}, [Ljava/lang/Object;

    .line 1237
    .line 1238
    .line 1239
    move-result-object v8

    .line 1240
    new-instance v13, Ljava/util/HashSet;

    .line 1241
    .line 1242
    invoke-direct {v13, v10}, Ljava/util/HashSet;-><init>(I)V

    .line 1243
    .line 1244
    .line 1245
    aget-object v8, v8, v11

    .line 1246
    .line 1247
    invoke-static {v8}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1248
    .line 1249
    .line 1250
    invoke-virtual {v13, v8}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 1251
    .line 1252
    .line 1253
    move-result v14

    .line 1254
    if-eqz v14, :cond_18

    .line 1255
    .line 1256
    invoke-static {v13}, Ljava/util/Collections;->unmodifiableSet(Ljava/util/Set;)Ljava/util/Set;

    .line 1257
    .line 1258
    .line 1259
    move-result-object v8

    .line 1260
    invoke-virtual {v1, v12, v8}, Lq6/b;->e(Lq6/e;Ljava/lang/Object;)V

    .line 1261
    .line 1262
    .line 1263
    const-wide/16 v12, 0x1

    .line 1264
    .line 1265
    add-long/2addr v6, v12

    .line 1266
    goto :goto_8

    .line 1267
    :cond_18
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 1268
    .line 1269
    const-string v1, "duplicate element: "

    .line 1270
    .line 1271
    invoke-static {v8, v1}, Lkx/a;->i(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;

    .line 1272
    .line 1273
    .line 1274
    move-result-object v1

    .line 1275
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 1276
    .line 1277
    .line 1278
    throw v0

    .line 1279
    :cond_19
    invoke-virtual {v1, v12}, Lq6/b;->d(Lq6/e;)V

    .line 1280
    .line 1281
    .line 1282
    goto :goto_8

    .line 1283
    :cond_1a
    cmp-long v0, v6, v4

    .line 1284
    .line 1285
    if-nez v0, :cond_1b

    .line 1286
    .line 1287
    invoke-virtual {v1, v2}, Lq6/b;->d(Lq6/e;)V

    .line 1288
    .line 1289
    .line 1290
    goto :goto_9

    .line 1291
    :cond_1b
    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1292
    .line 1293
    .line 1294
    move-result-object v0

    .line 1295
    invoke-virtual {v1, v2, v0}, Lq6/b;->e(Lq6/e;Ljava/lang/Object;)V

    .line 1296
    .line 1297
    .line 1298
    :goto_9
    return-object v9

    .line 1299
    :pswitch_1c
    check-cast v0, Le81/x;

    .line 1300
    .line 1301
    check-cast v1, Ls71/q;

    .line 1302
    .line 1303
    invoke-static {v0, v1}, Le81/x;->a(Le81/x;Ls71/q;)V

    .line 1304
    .line 1305
    .line 1306
    return-object v12

    .line 1307
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
