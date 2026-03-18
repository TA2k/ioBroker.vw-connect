.class public final Laa/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll2/j0;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;

.field public final synthetic c:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Laa/t;->a:I

    .line 2
    .line 3
    iput-object p2, p0, Laa/t;->b:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Laa/t;->c:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final dispose()V
    .locals 5

    .line 1
    iget v0, p0, Laa/t;->a:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x0

    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Laa/t;->b:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Ljc/a;

    .line 11
    .line 12
    iget-object p0, p0, Laa/t;->c:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Lzb/q;

    .line 15
    .line 16
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    iget-object v0, v0, Ljc/a;->a:Ljava/util/ArrayList;

    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    :cond_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 26
    .line 27
    .line 28
    move-result v3

    .line 29
    if-eqz v3, :cond_1

    .line 30
    .line 31
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v3

    .line 35
    move-object v4, v3

    .line 36
    check-cast v4, Lzb/q;

    .line 37
    .line 38
    invoke-static {v4, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v4

    .line 42
    if-eqz v4, :cond_0

    .line 43
    .line 44
    move-object v2, v3

    .line 45
    :cond_1
    check-cast v2, Lzb/q;

    .line 46
    .line 47
    if-eqz v2, :cond_2

    .line 48
    .line 49
    invoke-virtual {v2}, Landroid/app/Dialog;->dismiss()V

    .line 50
    .line 51
    .line 52
    iget-object p0, v2, Lzb/q;->h:Lzb/n;

    .line 53
    .line 54
    invoke-virtual {p0}, Lw3/a;->d()V

    .line 55
    .line 56
    .line 57
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    :cond_2
    return-void

    .line 61
    :pswitch_0
    iget-object v0, p0, Laa/t;->b:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast v0, Landroid/content/Context;

    .line 64
    .line 65
    invoke-virtual {v0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    iget-object p0, p0, Laa/t;->c:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast p0, Lw3/k0;

    .line 72
    .line 73
    invoke-virtual {v0, p0}, Landroid/content/Context;->unregisterComponentCallbacks(Landroid/content/ComponentCallbacks;)V

    .line 74
    .line 75
    .line 76
    return-void

    .line 77
    :pswitch_1
    iget-object v0, p0, Laa/t;->b:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast v0, Landroid/content/Context;

    .line 80
    .line 81
    invoke-virtual {v0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    iget-object p0, p0, Laa/t;->c:Ljava/lang/Object;

    .line 86
    .line 87
    check-cast p0, Lw3/j0;

    .line 88
    .line 89
    invoke-virtual {v0, p0}, Landroid/content/Context;->unregisterComponentCallbacks(Landroid/content/ComponentCallbacks;)V

    .line 90
    .line 91
    .line 92
    return-void

    .line 93
    :pswitch_2
    iget-object v0, p0, Laa/t;->b:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast v0, Lt1/k1;

    .line 96
    .line 97
    iget-object v0, v0, Lt1/k1;->c:Lv2/o;

    .line 98
    .line 99
    iget-object p0, p0, Laa/t;->c:Ljava/lang/Object;

    .line 100
    .line 101
    check-cast p0, Lay0/k;

    .line 102
    .line 103
    invoke-virtual {v0, p0}, Lv2/o;->remove(Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    return-void

    .line 107
    :pswitch_3
    iget-object v0, p0, Laa/t;->b:Ljava/lang/Object;

    .line 108
    .line 109
    check-cast v0, Ll2/b1;

    .line 110
    .line 111
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v1

    .line 115
    check-cast v1, Li1/n;

    .line 116
    .line 117
    if-eqz v1, :cond_4

    .line 118
    .line 119
    new-instance v3, Li1/m;

    .line 120
    .line 121
    invoke-direct {v3, v1}, Li1/m;-><init>(Li1/n;)V

    .line 122
    .line 123
    .line 124
    iget-object p0, p0, Laa/t;->c:Ljava/lang/Object;

    .line 125
    .line 126
    check-cast p0, Li1/l;

    .line 127
    .line 128
    if-eqz p0, :cond_3

    .line 129
    .line 130
    invoke-virtual {p0, v3}, Li1/l;->b(Li1/k;)V

    .line 131
    .line 132
    .line 133
    :cond_3
    invoke-interface {v0, v2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    :cond_4
    return-void

    .line 137
    :pswitch_4
    iget-object v0, p0, Laa/t;->b:Ljava/lang/Object;

    .line 138
    .line 139
    check-cast v0, Ll2/b1;

    .line 140
    .line 141
    invoke-static {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;->access$SetupWindow$lambda$1(Ll2/b1;)Landroid/view/Window;

    .line 142
    .line 143
    .line 144
    move-result-object v0

    .line 145
    if-eqz v0, :cond_5

    .line 146
    .line 147
    iget-object p0, p0, Laa/t;->c:Ljava/lang/Object;

    .line 148
    .line 149
    check-cast p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;

    .line 150
    .line 151
    invoke-virtual {p0, v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;->tearDownWindowCallbacks(Landroid/view/Window;)V

    .line 152
    .line 153
    .line 154
    :cond_5
    return-void

    .line 155
    :pswitch_5
    iget-object v0, p0, Laa/t;->b:Ljava/lang/Object;

    .line 156
    .line 157
    check-cast v0, Landroidx/compose/runtime/DisposableEffectScope;

    .line 158
    .line 159
    new-instance v1, Lep0/f;

    .line 160
    .line 161
    iget-object p0, p0, Laa/t;->c:Ljava/lang/Object;

    .line 162
    .line 163
    check-cast p0, Lx61/a;

    .line 164
    .line 165
    const/16 v2, 0xa

    .line 166
    .line 167
    invoke-direct {v1, p0, v2}, Lep0/f;-><init>(Ljava/lang/Object;I)V

    .line 168
    .line 169
    .line 170
    invoke-static {v0, v1}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 171
    .line 172
    .line 173
    return-void

    .line 174
    :pswitch_6
    iget-object v0, p0, Laa/t;->b:Ljava/lang/Object;

    .line 175
    .line 176
    check-cast v0, Lo1/v0;

    .line 177
    .line 178
    iget-object v0, v0, Lo1/v0;->f:Landroidx/collection/r0;

    .line 179
    .line 180
    iget-object p0, p0, Laa/t;->c:Ljava/lang/Object;

    .line 181
    .line 182
    invoke-virtual {v0, p0}, Landroidx/collection/r0;->k(Ljava/lang/Object;)V

    .line 183
    .line 184
    .line 185
    return-void

    .line 186
    :pswitch_7
    iget-object v0, p0, Laa/t;->b:Ljava/lang/Object;

    .line 187
    .line 188
    check-cast v0, Lz9/y;

    .line 189
    .line 190
    iget-object p0, p0, Laa/t;->c:Ljava/lang/Object;

    .line 191
    .line 192
    check-cast p0, Lny/b0;

    .line 193
    .line 194
    iget-object v0, v0, Lz9/y;->b:Lca/g;

    .line 195
    .line 196
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 197
    .line 198
    .line 199
    iget-object v0, v0, Lca/g;->p:Ljava/util/ArrayList;

    .line 200
    .line 201
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 202
    .line 203
    .line 204
    return-void

    .line 205
    :pswitch_8
    iget-object v0, p0, Laa/t;->b:Ljava/lang/Object;

    .line 206
    .line 207
    check-cast v0, Lz9/y;

    .line 208
    .line 209
    iget-object p0, p0, Laa/t;->c:Ljava/lang/Object;

    .line 210
    .line 211
    check-cast p0, Lny/b0;

    .line 212
    .line 213
    iget-object v0, v0, Lz9/y;->b:Lca/g;

    .line 214
    .line 215
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 216
    .line 217
    .line 218
    iget-object v0, v0, Lca/g;->p:Ljava/util/ArrayList;

    .line 219
    .line 220
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 221
    .line 222
    .line 223
    return-void

    .line 224
    :pswitch_9
    iget-object v0, p0, Laa/t;->b:Ljava/lang/Object;

    .line 225
    .line 226
    check-cast v0, Lkn/c0;

    .line 227
    .line 228
    iget-object v3, v0, Lkn/c0;->b:Ll2/j1;

    .line 229
    .line 230
    sget-object v4, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 231
    .line 232
    invoke-virtual {v3, v4}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 233
    .line 234
    .line 235
    iget-object v3, v0, Lkn/c0;->c:Ll2/g1;

    .line 236
    .line 237
    invoke-virtual {v3, v1}, Ll2/g1;->p(I)V

    .line 238
    .line 239
    .line 240
    iget-object p0, p0, Laa/t;->c:Ljava/lang/Object;

    .line 241
    .line 242
    check-cast p0, Lvy0/b0;

    .line 243
    .line 244
    new-instance v1, Lkn/d;

    .line 245
    .line 246
    const/4 v3, 0x2

    .line 247
    invoke-direct {v1, v0, v2, v3}, Lkn/d;-><init>(Lkn/c0;Lkotlin/coroutines/Continuation;I)V

    .line 248
    .line 249
    .line 250
    const/4 v0, 0x3

    .line 251
    invoke-static {p0, v2, v2, v1, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 252
    .line 253
    .line 254
    return-void

    .line 255
    :pswitch_a
    iget-object v0, p0, Laa/t;->b:Ljava/lang/Object;

    .line 256
    .line 257
    check-cast v0, Lkn/c0;

    .line 258
    .line 259
    iget-object v0, v0, Lkn/c0;->c:Ll2/g1;

    .line 260
    .line 261
    invoke-virtual {v0, v1}, Ll2/g1;->p(I)V

    .line 262
    .line 263
    .line 264
    iget-object p0, p0, Laa/t;->c:Ljava/lang/Object;

    .line 265
    .line 266
    check-cast p0, Lkn/k0;

    .line 267
    .line 268
    invoke-virtual {p0}, Landroid/app/Dialog;->dismiss()V

    .line 269
    .line 270
    .line 271
    iget-object p0, p0, Lkn/k0;->j:Lkn/n0;

    .line 272
    .line 273
    invoke-virtual {p0}, Lw3/a;->d()V

    .line 274
    .line 275
    .line 276
    return-void

    .line 277
    :pswitch_b
    iget-object v0, p0, Laa/t;->b:Ljava/lang/Object;

    .line 278
    .line 279
    check-cast v0, Lk1/r1;

    .line 280
    .line 281
    iget-object p0, p0, Laa/t;->c:Ljava/lang/Object;

    .line 282
    .line 283
    check-cast p0, Landroid/view/View;

    .line 284
    .line 285
    iget v1, v0, Lk1/r1;->t:I

    .line 286
    .line 287
    add-int/lit8 v1, v1, -0x1

    .line 288
    .line 289
    iput v1, v0, Lk1/r1;->t:I

    .line 290
    .line 291
    if-nez v1, :cond_6

    .line 292
    .line 293
    sget-object v1, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 294
    .line 295
    invoke-static {p0, v2}, Ld6/k0;->j(Landroid/view/View;Ld6/s;)V

    .line 296
    .line 297
    .line 298
    invoke-static {p0, v2}, Ld6/r0;->k(Landroid/view/View;Landroidx/datastore/preferences/protobuf/k;)V

    .line 299
    .line 300
    .line 301
    iget-object v0, v0, Lk1/r1;->u:Lk1/m0;

    .line 302
    .line 303
    invoke-virtual {p0, v0}, Landroid/view/View;->removeOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    .line 304
    .line 305
    .line 306
    :cond_6
    return-void

    .line 307
    :pswitch_c
    iget-object v0, p0, Laa/t;->b:Ljava/lang/Object;

    .line 308
    .line 309
    check-cast v0, Landroidx/compose/runtime/DisposableEffectScope;

    .line 310
    .line 311
    sget-object v1, Lio0/i;->d:Lio0/i;

    .line 312
    .line 313
    invoke-static {v0, v1}, Llp/nd;->l(Ljava/lang/Object;Lay0/a;)V

    .line 314
    .line 315
    .line 316
    iget-object p0, p0, Laa/t;->c:Ljava/lang/Object;

    .line 317
    .line 318
    check-cast p0, Landroidx/media3/exoplayer/ExoPlayer;

    .line 319
    .line 320
    check-cast p0, La8/i0;

    .line 321
    .line 322
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 323
    .line 324
    .line 325
    invoke-virtual {p0, v2}, La8/i0;->G0(La8/o;)V

    .line 326
    .line 327
    .line 328
    new-instance v0, Lv7/c;

    .line 329
    .line 330
    sget-object v1, Lhr/x0;->h:Lhr/x0;

    .line 331
    .line 332
    iget-object v2, p0, La8/i0;->y1:La8/i1;

    .line 333
    .line 334
    iget-wide v2, v2, La8/i1;->s:J

    .line 335
    .line 336
    invoke-direct {v0, v1}, Lv7/c;-><init>(Ljava/util/List;)V

    .line 337
    .line 338
    .line 339
    iput-object v0, p0, La8/i0;->s1:Lv7/c;

    .line 340
    .line 341
    invoke-virtual {p0}, La8/i0;->x0()V

    .line 342
    .line 343
    .line 344
    return-void

    .line 345
    :pswitch_d
    iget-object v0, p0, Laa/t;->b:Ljava/lang/Object;

    .line 346
    .line 347
    check-cast v0, Lc1/w1;

    .line 348
    .line 349
    iget-object p0, p0, Laa/t;->c:Ljava/lang/Object;

    .line 350
    .line 351
    check-cast p0, Lc1/t1;

    .line 352
    .line 353
    iget-object v0, v0, Lc1/w1;->i:Lv2/o;

    .line 354
    .line 355
    invoke-virtual {v0, p0}, Lv2/o;->remove(Ljava/lang/Object;)Z

    .line 356
    .line 357
    .line 358
    return-void

    .line 359
    :pswitch_e
    iget-object v0, p0, Laa/t;->b:Ljava/lang/Object;

    .line 360
    .line 361
    check-cast v0, Lc1/w1;

    .line 362
    .line 363
    iget-object p0, p0, Laa/t;->c:Ljava/lang/Object;

    .line 364
    .line 365
    check-cast p0, Lc1/q1;

    .line 366
    .line 367
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 368
    .line 369
    .line 370
    iget-object p0, p0, Lc1/q1;->b:Ll2/j1;

    .line 371
    .line 372
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 373
    .line 374
    .line 375
    move-result-object p0

    .line 376
    check-cast p0, Lc1/p1;

    .line 377
    .line 378
    if-eqz p0, :cond_7

    .line 379
    .line 380
    iget-object p0, p0, Lc1/p1;->d:Lc1/t1;

    .line 381
    .line 382
    iget-object v0, v0, Lc1/w1;->i:Lv2/o;

    .line 383
    .line 384
    invoke-virtual {v0, p0}, Lv2/o;->remove(Ljava/lang/Object;)Z

    .line 385
    .line 386
    .line 387
    :cond_7
    return-void

    .line 388
    :pswitch_f
    iget-object v0, p0, Laa/t;->b:Ljava/lang/Object;

    .line 389
    .line 390
    check-cast v0, Lc1/w1;

    .line 391
    .line 392
    iget-object p0, p0, Laa/t;->c:Ljava/lang/Object;

    .line 393
    .line 394
    check-cast p0, Lc1/w1;

    .line 395
    .line 396
    iget-object v0, v0, Lc1/w1;->j:Lv2/o;

    .line 397
    .line 398
    invoke-virtual {v0, p0}, Lv2/o;->remove(Ljava/lang/Object;)Z

    .line 399
    .line 400
    .line 401
    return-void

    .line 402
    :pswitch_10
    iget-object v0, p0, Laa/t;->b:Ljava/lang/Object;

    .line 403
    .line 404
    check-cast v0, Lc1/i0;

    .line 405
    .line 406
    iget-object p0, p0, Laa/t;->c:Ljava/lang/Object;

    .line 407
    .line 408
    check-cast p0, Lc1/g0;

    .line 409
    .line 410
    iget-object v0, v0, Lc1/i0;->a:Ln2/b;

    .line 411
    .line 412
    invoke-virtual {v0, p0}, Ln2/b;->l(Ljava/lang/Object;)Z

    .line 413
    .line 414
    .line 415
    return-void

    .line 416
    :pswitch_11
    iget-object v0, p0, Laa/t;->b:Ljava/lang/Object;

    .line 417
    .line 418
    check-cast v0, Ll2/t2;

    .line 419
    .line 420
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 421
    .line 422
    .line 423
    move-result-object v0

    .line 424
    check-cast v0, Ljava/util/List;

    .line 425
    .line 426
    check-cast v0, Ljava/lang/Iterable;

    .line 427
    .line 428
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 429
    .line 430
    .line 431
    move-result-object v0

    .line 432
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 433
    .line 434
    .line 435
    move-result v1

    .line 436
    if-eqz v1, :cond_8

    .line 437
    .line 438
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 439
    .line 440
    .line 441
    move-result-object v1

    .line 442
    check-cast v1, Lz9/k;

    .line 443
    .line 444
    iget-object v2, p0, Laa/t;->c:Ljava/lang/Object;

    .line 445
    .line 446
    check-cast v2, Laa/i;

    .line 447
    .line 448
    invoke-virtual {v2}, Lz9/j0;->b()Lz9/m;

    .line 449
    .line 450
    .line 451
    move-result-object v2

    .line 452
    invoke-virtual {v2, v1}, Lz9/m;->c(Lz9/k;)V

    .line 453
    .line 454
    .line 455
    goto :goto_0

    .line 456
    :cond_8
    return-void

    .line 457
    :pswitch_12
    iget-object v0, p0, Laa/t;->b:Ljava/lang/Object;

    .line 458
    .line 459
    check-cast v0, Lz9/k;

    .line 460
    .line 461
    iget-object v0, v0, Lz9/k;->k:Lca/c;

    .line 462
    .line 463
    iget-object v0, v0, Lca/c;->j:Landroidx/lifecycle/z;

    .line 464
    .line 465
    iget-object p0, p0, Laa/t;->c:Ljava/lang/Object;

    .line 466
    .line 467
    check-cast p0, Laa/n;

    .line 468
    .line 469
    invoke-virtual {v0, p0}, Landroidx/lifecycle/z;->d(Landroidx/lifecycle/w;)V

    .line 470
    .line 471
    .line 472
    return-void

    .line 473
    :pswitch_data_0
    .packed-switch 0x0
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
