.class public final synthetic Let/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Let/g;->d:I

    iput-object p2, p0, Let/g;->e:Ljava/lang/Object;

    iput-object p3, p0, Let/g;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lh2/nb;Lc1/t1;Ll2/b1;)V
    .locals 0

    .line 2
    const/16 p1, 0x1b

    iput p1, p0, Let/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Let/g;->e:Ljava/lang/Object;

    iput-object p3, p0, Let/g;->f:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Lay0/a;)V
    .locals 1

    .line 3
    const/16 v0, 0x14

    iput v0, p0, Let/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Let/g;->f:Ljava/lang/Object;

    iput-object p2, p0, Let/g;->e:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lb71/o;Lw3/b2;)V
    .locals 0

    .line 4
    const/16 p1, 0x10

    iput p1, p0, Let/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p5, p0, Let/g;->e:Ljava/lang/Object;

    iput-object p6, p0, Let/g;->f:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 33

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Let/g;->d:I

    .line 4
    .line 5
    const/high16 v2, -0x40800000    # -1.0f

    .line 6
    .line 7
    const/16 v3, 0x17

    .line 8
    .line 9
    const/4 v4, 0x3

    .line 10
    const/4 v5, 0x5

    .line 11
    const/4 v6, 0x2

    .line 12
    const/high16 v7, 0x3f800000    # 1.0f

    .line 13
    .line 14
    const/4 v8, 0x0

    .line 15
    const/4 v9, 0x0

    .line 16
    const-wide v10, 0xffffffffL

    .line 17
    .line 18
    .line 19
    .line 20
    .line 21
    const/16 v12, 0x20

    .line 22
    .line 23
    const/4 v14, 0x0

    .line 24
    packed-switch v1, :pswitch_data_0

    .line 25
    .line 26
    .line 27
    iget-object v1, v0, Let/g;->e:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast v1, Le3/g0;

    .line 30
    .line 31
    iget-object v0, v0, Let/g;->f:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast v0, Lh2/gb;

    .line 34
    .line 35
    move-object/from16 v2, p1

    .line 36
    .line 37
    check-cast v2, Lg3/d;

    .line 38
    .line 39
    invoke-virtual {v0}, Lh2/gb;->a()J

    .line 40
    .line 41
    .line 42
    move-result-wide v3

    .line 43
    invoke-static {v2, v1, v3, v4}, Le3/j0;->o(Lg3/d;Le3/g0;J)V

    .line 44
    .line 45
    .line 46
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 47
    .line 48
    return-object v0

    .line 49
    :pswitch_0
    iget-object v1, v0, Let/g;->e:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast v1, Le3/n0;

    .line 52
    .line 53
    iget-object v0, v0, Let/g;->f:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast v0, Lh2/gb;

    .line 56
    .line 57
    move-object/from16 v2, p1

    .line 58
    .line 59
    check-cast v2, Lb3/d;

    .line 60
    .line 61
    iget-object v3, v2, Lb3/d;->d:Lb3/b;

    .line 62
    .line 63
    invoke-interface {v3}, Lb3/b;->e()J

    .line 64
    .line 65
    .line 66
    move-result-wide v3

    .line 67
    iget-object v6, v2, Lb3/d;->d:Lb3/b;

    .line 68
    .line 69
    invoke-interface {v6}, Lb3/b;->getLayoutDirection()Lt4/m;

    .line 70
    .line 71
    .line 72
    move-result-object v6

    .line 73
    invoke-interface {v1, v3, v4, v6, v2}, Le3/n0;->a(JLt4/m;Lt4/c;)Le3/g0;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    new-instance v3, Let/g;

    .line 78
    .line 79
    const/16 v4, 0x1d

    .line 80
    .line 81
    invoke-direct {v3, v4, v1, v0}, Let/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    new-instance v0, Law/o;

    .line 85
    .line 86
    invoke-direct {v0, v5, v3}, Law/o;-><init>(ILay0/k;)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {v2, v0}, Lb3/d;->b(Lay0/k;)Lb3/g;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    return-object v0

    .line 94
    :pswitch_1
    iget-object v1, v0, Let/g;->e:Ljava/lang/Object;

    .line 95
    .line 96
    check-cast v1, Ll2/t2;

    .line 97
    .line 98
    iget-object v0, v0, Let/g;->f:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast v0, Ll2/b1;

    .line 101
    .line 102
    move-object/from16 v2, p1

    .line 103
    .line 104
    check-cast v2, Ld3/e;

    .line 105
    .line 106
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v1

    .line 110
    check-cast v1, Ljava/lang/Number;

    .line 111
    .line 112
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 113
    .line 114
    .line 115
    move-result v1

    .line 116
    iget-wide v3, v2, Ld3/e;->a:J

    .line 117
    .line 118
    shr-long/2addr v3, v12

    .line 119
    long-to-int v3, v3

    .line 120
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 121
    .line 122
    .line 123
    move-result v3

    .line 124
    mul-float/2addr v3, v1

    .line 125
    iget-wide v4, v2, Ld3/e;->a:J

    .line 126
    .line 127
    and-long/2addr v4, v10

    .line 128
    long-to-int v2, v4

    .line 129
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 130
    .line 131
    .line 132
    move-result v2

    .line 133
    mul-float/2addr v2, v1

    .line 134
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v1

    .line 138
    check-cast v1, Ld3/e;

    .line 139
    .line 140
    iget-wide v4, v1, Ld3/e;->a:J

    .line 141
    .line 142
    shr-long/2addr v4, v12

    .line 143
    long-to-int v1, v4

    .line 144
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 145
    .line 146
    .line 147
    move-result v1

    .line 148
    cmpg-float v1, v1, v3

    .line 149
    .line 150
    if-nez v1, :cond_0

    .line 151
    .line 152
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v1

    .line 156
    check-cast v1, Ld3/e;

    .line 157
    .line 158
    iget-wide v4, v1, Ld3/e;->a:J

    .line 159
    .line 160
    and-long/2addr v4, v10

    .line 161
    long-to-int v1, v4

    .line 162
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 163
    .line 164
    .line 165
    move-result v1

    .line 166
    cmpg-float v1, v1, v2

    .line 167
    .line 168
    if-nez v1, :cond_0

    .line 169
    .line 170
    goto :goto_0

    .line 171
    :cond_0
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 172
    .line 173
    .line 174
    move-result v1

    .line 175
    int-to-long v3, v1

    .line 176
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 177
    .line 178
    .line 179
    move-result v1

    .line 180
    int-to-long v1, v1

    .line 181
    shl-long/2addr v3, v12

    .line 182
    and-long/2addr v1, v10

    .line 183
    or-long/2addr v1, v3

    .line 184
    new-instance v3, Ld3/e;

    .line 185
    .line 186
    invoke-direct {v3, v1, v2}, Ld3/e;-><init>(J)V

    .line 187
    .line 188
    .line 189
    invoke-interface {v0, v3}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 190
    .line 191
    .line 192
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 193
    .line 194
    return-object v0

    .line 195
    :pswitch_2
    iget-object v1, v0, Let/g;->e:Ljava/lang/Object;

    .line 196
    .line 197
    check-cast v1, Lvy0/b0;

    .line 198
    .line 199
    iget-object v0, v0, Let/g;->f:Ljava/lang/Object;

    .line 200
    .line 201
    check-cast v0, Lh2/yb;

    .line 202
    .line 203
    move-object/from16 v2, p1

    .line 204
    .line 205
    check-cast v2, Lc3/t;

    .line 206
    .line 207
    new-instance v3, Lh40/w3;

    .line 208
    .line 209
    const/16 v5, 0x16

    .line 210
    .line 211
    invoke-direct {v3, v5, v2, v0, v14}, Lh40/w3;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 212
    .line 213
    .line 214
    invoke-static {v1, v14, v14, v3, v4}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 215
    .line 216
    .line 217
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 218
    .line 219
    return-object v0

    .line 220
    :pswitch_3
    iget-object v1, v0, Let/g;->e:Ljava/lang/Object;

    .line 221
    .line 222
    check-cast v1, Li2/t0;

    .line 223
    .line 224
    iget-object v0, v0, Let/g;->f:Ljava/lang/Object;

    .line 225
    .line 226
    check-cast v0, Landroid/view/accessibility/AccessibilityManager;

    .line 227
    .line 228
    move-object/from16 v2, p1

    .line 229
    .line 230
    check-cast v2, Landroidx/lifecycle/p;

    .line 231
    .line 232
    sget-object v3, Landroidx/lifecycle/p;->ON_RESUME:Landroidx/lifecycle/p;

    .line 233
    .line 234
    if-ne v2, v3, :cond_2

    .line 235
    .line 236
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 237
    .line 238
    .line 239
    invoke-virtual {v0}, Landroid/view/accessibility/AccessibilityManager;->isEnabled()Z

    .line 240
    .line 241
    .line 242
    move-result v2

    .line 243
    iget-object v3, v1, Li2/t0;->f:Ll2/j1;

    .line 244
    .line 245
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 246
    .line 247
    .line 248
    move-result-object v2

    .line 249
    invoke-virtual {v3, v2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 250
    .line 251
    .line 252
    invoke-virtual {v0, v1}, Landroid/view/accessibility/AccessibilityManager;->addAccessibilityStateChangeListener(Landroid/view/accessibility/AccessibilityManager$AccessibilityStateChangeListener;)Z

    .line 253
    .line 254
    .line 255
    iget-object v2, v1, Li2/t0;->g:Li2/s0;

    .line 256
    .line 257
    if-eqz v2, :cond_1

    .line 258
    .line 259
    invoke-virtual {v0}, Landroid/view/accessibility/AccessibilityManager;->isTouchExplorationEnabled()Z

    .line 260
    .line 261
    .line 262
    move-result v3

    .line 263
    iget-object v4, v2, Li2/s0;->a:Ll2/j1;

    .line 264
    .line 265
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 266
    .line 267
    .line 268
    move-result-object v3

    .line 269
    invoke-virtual {v4, v3}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 270
    .line 271
    .line 272
    invoke-virtual {v0, v2}, Landroid/view/accessibility/AccessibilityManager;->addTouchExplorationStateChangeListener(Landroid/view/accessibility/AccessibilityManager$TouchExplorationStateChangeListener;)Z

    .line 273
    .line 274
    .line 275
    :cond_1
    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 276
    .line 277
    const/16 v3, 0x21

    .line 278
    .line 279
    if-lt v2, v3, :cond_2

    .line 280
    .line 281
    iget-object v1, v1, Li2/t0;->h:Li2/r0;

    .line 282
    .line 283
    if-eqz v1, :cond_2

    .line 284
    .line 285
    invoke-static {v0}, Li2/t0;->a(Landroid/view/accessibility/AccessibilityManager;)Z

    .line 286
    .line 287
    .line 288
    move-result v2

    .line 289
    iget-object v3, v1, Li2/r0;->a:Ll2/j1;

    .line 290
    .line 291
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 292
    .line 293
    .line 294
    move-result-object v2

    .line 295
    invoke-virtual {v3, v2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 296
    .line 297
    .line 298
    invoke-static {v0}, Li2/t0;->b(Landroid/view/accessibility/AccessibilityManager;)Z

    .line 299
    .line 300
    .line 301
    move-result v2

    .line 302
    iget-object v3, v1, Li2/r0;->b:Ll2/j1;

    .line 303
    .line 304
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 305
    .line 306
    .line 307
    move-result-object v2

    .line 308
    invoke-virtual {v3, v2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 309
    .line 310
    .line 311
    invoke-static {v1}, Li2/p0;->g(Ljava/lang/Object;)Landroid/view/accessibility/AccessibilityManager$AccessibilityServicesStateChangeListener;

    .line 312
    .line 313
    .line 314
    move-result-object v1

    .line 315
    invoke-static {v0, v1}, Li2/q0;->a(Landroid/view/accessibility/AccessibilityManager;Landroid/view/accessibility/AccessibilityManager$AccessibilityServicesStateChangeListener;)V

    .line 316
    .line 317
    .line 318
    :cond_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 319
    .line 320
    return-object v0

    .line 321
    :pswitch_4
    iget-object v1, v0, Let/g;->e:Ljava/lang/Object;

    .line 322
    .line 323
    check-cast v1, Ll2/t2;

    .line 324
    .line 325
    iget-object v0, v0, Let/g;->f:Ljava/lang/Object;

    .line 326
    .line 327
    check-cast v0, Lay0/k;

    .line 328
    .line 329
    move-object/from16 v2, p1

    .line 330
    .line 331
    check-cast v2, Ld3/b;

    .line 332
    .line 333
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 334
    .line 335
    .line 336
    move-result-object v1

    .line 337
    check-cast v1, Lg4/l0;

    .line 338
    .line 339
    if-eqz v1, :cond_3

    .line 340
    .line 341
    iget-object v3, v1, Lg4/l0;->a:Lg4/k0;

    .line 342
    .line 343
    iget-object v3, v3, Lg4/k0;->a:Lg4/g;

    .line 344
    .line 345
    iget-wide v4, v2, Ld3/b;->a:J

    .line 346
    .line 347
    iget-object v1, v1, Lg4/l0;->b:Lg4/o;

    .line 348
    .line 349
    invoke-virtual {v1, v4, v5}, Lg4/o;->g(J)I

    .line 350
    .line 351
    .line 352
    move-result v1

    .line 353
    const-string v2, "URL_RESOURCE"

    .line 354
    .line 355
    invoke-virtual {v3, v1, v1, v2}, Lg4/g;->b(IILjava/lang/String;)Ljava/util/List;

    .line 356
    .line 357
    .line 358
    move-result-object v1

    .line 359
    invoke-static {v1}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 360
    .line 361
    .line 362
    move-result-object v1

    .line 363
    check-cast v1, Lg4/e;

    .line 364
    .line 365
    if-eqz v1, :cond_3

    .line 366
    .line 367
    iget-object v1, v1, Lg4/e;->a:Ljava/lang/Object;

    .line 368
    .line 369
    check-cast v1, Ljava/lang/String;

    .line 370
    .line 371
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 372
    .line 373
    .line 374
    :cond_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 375
    .line 376
    return-object v0

    .line 377
    :pswitch_5
    iget-object v1, v0, Let/g;->e:Ljava/lang/Object;

    .line 378
    .line 379
    check-cast v1, Lb81/a;

    .line 380
    .line 381
    iget-object v0, v0, Let/g;->f:Ljava/lang/Object;

    .line 382
    .line 383
    check-cast v0, Ljava/lang/String;

    .line 384
    .line 385
    move-object/from16 v2, p1

    .line 386
    .line 387
    check-cast v2, Lkw0/c;

    .line 388
    .line 389
    const-string v3, "$this$catRequest"

    .line 390
    .line 391
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 392
    .line 393
    .line 394
    sget-object v3, Low0/v;->h:Low0/v;

    .line 395
    .line 396
    invoke-static {v3}, Ljp/m1;->k(Ljava/lang/Object;)Ljava/util/Set;

    .line 397
    .line 398
    .line 399
    move-result-object v3

    .line 400
    invoke-static {v2, v3}, Lkp/i7;->a(Lkw0/c;Ljava/util/Set;)V

    .line 401
    .line 402
    .line 403
    sget-object v3, Low0/s;->c:Low0/s;

    .line 404
    .line 405
    invoke-virtual {v2, v3}, Lkw0/c;->b(Low0/s;)V

    .line 406
    .line 407
    .line 408
    iget-object v1, v1, Lb81/a;->f:Ljava/lang/Object;

    .line 409
    .line 410
    check-cast v1, Ly41/g;

    .line 411
    .line 412
    iget-object v1, v1, Ly41/g;->a:Ljava/lang/String;

    .line 413
    .line 414
    new-instance v3, Ljava/lang/StringBuilder;

    .line 415
    .line 416
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 417
    .line 418
    .line 419
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 420
    .line 421
    .line 422
    const-string v1, "/user/v1/mobiledevicekeys/"

    .line 423
    .line 424
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 425
    .line 426
    .line 427
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 428
    .line 429
    .line 430
    const-string v0, "/pairing/unpair"

    .line 431
    .line 432
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 433
    .line 434
    .line 435
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 436
    .line 437
    .line 438
    move-result-object v0

    .line 439
    invoke-static {v2, v0}, Lkw0/d;->a(Lkw0/c;Ljava/lang/String;)V

    .line 440
    .line 441
    .line 442
    sget-object v0, Low0/b;->a:Low0/e;

    .line 443
    .line 444
    invoke-static {v2, v0}, Ljp/pc;->d(Lkw0/c;Low0/e;)V

    .line 445
    .line 446
    .line 447
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 448
    .line 449
    return-object v0

    .line 450
    :pswitch_6
    iget-object v1, v0, Let/g;->e:Ljava/lang/Object;

    .line 451
    .line 452
    check-cast v1, Lh2/u7;

    .line 453
    .line 454
    iget-object v0, v0, Let/g;->f:Ljava/lang/Object;

    .line 455
    .line 456
    check-cast v0, Lkotlin/jvm/internal/b0;

    .line 457
    .line 458
    move-object/from16 v2, p1

    .line 459
    .line 460
    check-cast v2, Lp3/t;

    .line 461
    .line 462
    invoke-static {v2, v9}, Lp3/s;->h(Lp3/t;Z)J

    .line 463
    .line 464
    .line 465
    move-result-wide v2

    .line 466
    shr-long/2addr v2, v12

    .line 467
    long-to-int v2, v2

    .line 468
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 469
    .line 470
    .line 471
    move-result v2

    .line 472
    iget-boolean v0, v0, Lkotlin/jvm/internal/b0;->d:Z

    .line 473
    .line 474
    iget-object v3, v1, Lh2/u7;->p:Ll2/j1;

    .line 475
    .line 476
    invoke-virtual {v3}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 477
    .line 478
    .line 479
    move-result-object v3

    .line 480
    check-cast v3, Ljava/lang/Boolean;

    .line 481
    .line 482
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 483
    .line 484
    .line 485
    move-result v3

    .line 486
    if-eqz v3, :cond_4

    .line 487
    .line 488
    neg-float v2, v2

    .line 489
    :cond_4
    invoke-virtual {v1, v2, v0}, Lh2/u7;->e(FZ)V

    .line 490
    .line 491
    .line 492
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 493
    .line 494
    return-object v0

    .line 495
    :pswitch_7
    iget-object v1, v0, Let/g;->e:Ljava/lang/Object;

    .line 496
    .line 497
    check-cast v1, Li2/x0;

    .line 498
    .line 499
    iget-object v0, v0, Let/g;->f:Ljava/lang/Object;

    .line 500
    .line 501
    check-cast v0, Lk1/q1;

    .line 502
    .line 503
    move-object/from16 v2, p1

    .line 504
    .line 505
    check-cast v2, Lk1/q1;

    .line 506
    .line 507
    new-instance v3, Lk1/z;

    .line 508
    .line 509
    invoke-direct {v3, v0, v2}, Lk1/z;-><init>(Lk1/q1;Lk1/q1;)V

    .line 510
    .line 511
    .line 512
    iget-object v0, v1, Li2/x0;->a:Ll2/j1;

    .line 513
    .line 514
    invoke-virtual {v0, v3}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 515
    .line 516
    .line 517
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 518
    .line 519
    return-object v0

    .line 520
    :pswitch_8
    iget-object v1, v0, Let/g;->f:Ljava/lang/Object;

    .line 521
    .line 522
    check-cast v1, Ljava/lang/String;

    .line 523
    .line 524
    iget-object v0, v0, Let/g;->e:Ljava/lang/Object;

    .line 525
    .line 526
    check-cast v0, Lay0/a;

    .line 527
    .line 528
    move-object/from16 v2, p1

    .line 529
    .line 530
    check-cast v2, Ld4/l;

    .line 531
    .line 532
    sget-object v4, Ld4/x;->a:[Lhy0/z;

    .line 533
    .line 534
    sget-object v4, Ld4/v;->s:Ld4/z;

    .line 535
    .line 536
    sget-object v5, Ld4/x;->a:[Lhy0/z;

    .line 537
    .line 538
    const/16 v6, 0xa

    .line 539
    .line 540
    aget-object v5, v5, v6

    .line 541
    .line 542
    invoke-static {v7}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 543
    .line 544
    .line 545
    move-result-object v5

    .line 546
    invoke-virtual {v4, v2, v5}, Ld4/z;->a(Ld4/l;Ljava/lang/Object;)V

    .line 547
    .line 548
    .line 549
    invoke-static {v2, v1}, Ld4/x;->d(Ld4/l;Ljava/lang/String;)V

    .line 550
    .line 551
    .line 552
    new-instance v1, Lb71/i;

    .line 553
    .line 554
    invoke-direct {v1, v0, v3}, Lb71/i;-><init>(Lay0/a;I)V

    .line 555
    .line 556
    .line 557
    sget-object v0, Ld4/k;->b:Ld4/z;

    .line 558
    .line 559
    new-instance v3, Ld4/a;

    .line 560
    .line 561
    invoke-direct {v3, v14, v1}, Ld4/a;-><init>(Ljava/lang/String;Llx0/e;)V

    .line 562
    .line 563
    .line 564
    invoke-virtual {v2, v0, v3}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 565
    .line 566
    .line 567
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 568
    .line 569
    return-object v0

    .line 570
    :pswitch_9
    iget-object v1, v0, Let/g;->e:Ljava/lang/Object;

    .line 571
    .line 572
    check-cast v1, Lh2/r8;

    .line 573
    .line 574
    iget-object v0, v0, Let/g;->f:Ljava/lang/Object;

    .line 575
    .line 576
    check-cast v0, Lc1/c;

    .line 577
    .line 578
    move-object/from16 v2, p1

    .line 579
    .line 580
    check-cast v2, Le3/k0;

    .line 581
    .line 582
    iget-object v1, v1, Lh2/r8;->e:Li2/p;

    .line 583
    .line 584
    iget-object v1, v1, Li2/p;->j:Ll2/f1;

    .line 585
    .line 586
    invoke-virtual {v1}, Ll2/f1;->o()F

    .line 587
    .line 588
    .line 589
    move-result v1

    .line 590
    iget-wide v3, v2, Le3/k0;->t:J

    .line 591
    .line 592
    and-long/2addr v3, v10

    .line 593
    long-to-int v3, v3

    .line 594
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 595
    .line 596
    .line 597
    move-result v3

    .line 598
    invoke-static {v1}, Ljava/lang/Float;->isNaN(F)Z

    .line 599
    .line 600
    .line 601
    move-result v4

    .line 602
    if-nez v4, :cond_6

    .line 603
    .line 604
    invoke-static {v3}, Ljava/lang/Float;->isNaN(F)Z

    .line 605
    .line 606
    .line 607
    move-result v4

    .line 608
    if-nez v4, :cond_6

    .line 609
    .line 610
    cmpg-float v4, v3, v8

    .line 611
    .line 612
    if-nez v4, :cond_5

    .line 613
    .line 614
    goto :goto_1

    .line 615
    :cond_5
    invoke-virtual {v0}, Lc1/c;->d()Ljava/lang/Object;

    .line 616
    .line 617
    .line 618
    move-result-object v0

    .line 619
    check-cast v0, Ljava/lang/Number;

    .line 620
    .line 621
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 622
    .line 623
    .line 624
    move-result v0

    .line 625
    invoke-static {v2, v0}, Lh2/j6;->d(Le3/k0;F)F

    .line 626
    .line 627
    .line 628
    move-result v4

    .line 629
    invoke-virtual {v2, v4}, Le3/k0;->l(F)V

    .line 630
    .line 631
    .line 632
    invoke-static {v2, v0}, Lh2/j6;->e(Le3/k0;F)F

    .line 633
    .line 634
    .line 635
    move-result v0

    .line 636
    invoke-virtual {v2, v0}, Le3/k0;->p(F)V

    .line 637
    .line 638
    .line 639
    add-float/2addr v1, v3

    .line 640
    div-float/2addr v1, v3

    .line 641
    const/high16 v0, 0x3f000000    # 0.5f

    .line 642
    .line 643
    invoke-static {v0, v1}, Le3/j0;->i(FF)J

    .line 644
    .line 645
    .line 646
    move-result-wide v0

    .line 647
    invoke-virtual {v2, v0, v1}, Le3/k0;->A(J)V

    .line 648
    .line 649
    .line 650
    :cond_6
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 651
    .line 652
    return-object v0

    .line 653
    :pswitch_a
    iget-object v1, v0, Let/g;->e:Ljava/lang/Object;

    .line 654
    .line 655
    move-object v3, v1

    .line 656
    check-cast v3, Le3/i;

    .line 657
    .line 658
    iget-object v0, v0, Let/g;->f:Ljava/lang/Object;

    .line 659
    .line 660
    check-cast v0, Lh2/h5;

    .line 661
    .line 662
    move-object/from16 v2, p1

    .line 663
    .line 664
    check-cast v2, Lv3/j0;

    .line 665
    .line 666
    invoke-virtual {v2}, Lv3/j0;->b()V

    .line 667
    .line 668
    .line 669
    new-instance v4, Le3/p0;

    .line 670
    .line 671
    iget-object v0, v0, Lh2/h5;->B:Lc1/c;

    .line 672
    .line 673
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 674
    .line 675
    .line 676
    invoke-virtual {v0}, Lc1/c;->d()Ljava/lang/Object;

    .line 677
    .line 678
    .line 679
    move-result-object v0

    .line 680
    check-cast v0, Le3/s;

    .line 681
    .line 682
    iget-wide v0, v0, Le3/s;->a:J

    .line 683
    .line 684
    invoke-direct {v4, v0, v1}, Le3/p0;-><init>(J)V

    .line 685
    .line 686
    .line 687
    const/4 v6, 0x0

    .line 688
    const/16 v7, 0x3c

    .line 689
    .line 690
    const/4 v5, 0x0

    .line 691
    invoke-static/range {v2 .. v7}, Lg3/d;->q0(Lg3/d;Le3/i;Le3/p;FLg3/h;I)V

    .line 692
    .line 693
    .line 694
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 695
    .line 696
    return-object v0

    .line 697
    :pswitch_b
    iget-object v1, v0, Let/g;->e:Ljava/lang/Object;

    .line 698
    .line 699
    check-cast v1, Landroid/view/View;

    .line 700
    .line 701
    iget-object v0, v0, Let/g;->f:Ljava/lang/Object;

    .line 702
    .line 703
    check-cast v0, Lay0/a;

    .line 704
    .line 705
    move-object/from16 v2, p1

    .line 706
    .line 707
    check-cast v2, Landroidx/compose/runtime/DisposableEffectScope;

    .line 708
    .line 709
    new-instance v2, Lh2/a5;

    .line 710
    .line 711
    invoke-direct {v2, v1, v0}, Lh2/a5;-><init>(Landroid/view/View;Lay0/a;)V

    .line 712
    .line 713
    .line 714
    new-instance v0, La2/j;

    .line 715
    .line 716
    invoke-direct {v0, v2, v5}, La2/j;-><init>(Ljava/lang/Object;I)V

    .line 717
    .line 718
    .line 719
    return-object v0

    .line 720
    :pswitch_c
    iget-object v1, v0, Let/g;->e:Ljava/lang/Object;

    .line 721
    .line 722
    check-cast v1, Lb71/o;

    .line 723
    .line 724
    iget-object v0, v0, Let/g;->f:Ljava/lang/Object;

    .line 725
    .line 726
    check-cast v0, Lw3/b2;

    .line 727
    .line 728
    move-object/from16 v2, p1

    .line 729
    .line 730
    check-cast v2, Ld4/l;

    .line 731
    .line 732
    const/4 v4, 0x6

    .line 733
    invoke-static {v2, v4}, Ld4/x;->i(Ld4/l;I)V

    .line 734
    .line 735
    .line 736
    new-instance v4, Ld90/w;

    .line 737
    .line 738
    invoke-direct {v4, v3, v1, v0}, Ld90/w;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 739
    .line 740
    .line 741
    sget-object v0, Ld4/k;->b:Ld4/z;

    .line 742
    .line 743
    new-instance v1, Ld4/a;

    .line 744
    .line 745
    invoke-direct {v1, v14, v4}, Ld4/a;-><init>(Ljava/lang/String;Llx0/e;)V

    .line 746
    .line 747
    .line 748
    invoke-virtual {v2, v0, v1}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 749
    .line 750
    .line 751
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 752
    .line 753
    return-object v0

    .line 754
    :pswitch_d
    iget-object v1, v0, Let/g;->e:Ljava/lang/Object;

    .line 755
    .line 756
    check-cast v1, Lh2/f8;

    .line 757
    .line 758
    iget-object v0, v0, Let/g;->f:Ljava/lang/Object;

    .line 759
    .line 760
    check-cast v0, Lh2/z1;

    .line 761
    .line 762
    move-object/from16 v14, p1

    .line 763
    .line 764
    check-cast v14, Lv3/j0;

    .line 765
    .line 766
    iget-wide v2, v0, Lh2/z1;->v:J

    .line 767
    .line 768
    sget-object v0, Lh2/f4;->a:Lk1/a1;

    .line 769
    .line 770
    sget v0, Lh2/m3;->a:F

    .line 771
    .line 772
    invoke-virtual {v14, v0}, Lv3/j0;->w0(F)F

    .line 773
    .line 774
    .line 775
    move-result v4

    .line 776
    invoke-virtual {v14, v0}, Lv3/j0;->w0(F)F

    .line 777
    .line 778
    .line 779
    move-result v0

    .line 780
    sget v5, Lk2/m;->k:F

    .line 781
    .line 782
    invoke-virtual {v14, v5}, Lv3/j0;->w0(F)F

    .line 783
    .line 784
    .line 785
    move-result v5

    .line 786
    sub-float v7, v0, v5

    .line 787
    .line 788
    int-to-float v6, v6

    .line 789
    div-float/2addr v7, v6

    .line 790
    iget-object v15, v14, Lv3/j0;->d:Lg3/b;

    .line 791
    .line 792
    invoke-interface {v15}, Lg3/d;->e()J

    .line 793
    .line 794
    .line 795
    move-result-wide v16

    .line 796
    move-wide/from16 v25, v10

    .line 797
    .line 798
    shr-long v10, v16, v12

    .line 799
    .line 800
    long-to-int v10, v10

    .line 801
    invoke-static {v10}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 802
    .line 803
    .line 804
    move-result v10

    .line 805
    const/4 v11, 0x7

    .line 806
    int-to-float v11, v11

    .line 807
    mul-float v16, v11, v4

    .line 808
    .line 809
    sub-float v10, v10, v16

    .line 810
    .line 811
    div-float/2addr v10, v11

    .line 812
    move/from16 v27, v12

    .line 813
    .line 814
    const/4 v11, 0x1

    .line 815
    iget-wide v12, v1, Lh2/f8;->a:J

    .line 816
    .line 817
    move/from16 v28, v11

    .line 818
    .line 819
    move-wide/from16 v16, v12

    .line 820
    .line 821
    shr-long v11, v16, v27

    .line 822
    .line 823
    long-to-int v11, v11

    .line 824
    and-long v12, v16, v25

    .line 825
    .line 826
    long-to-int v12, v12

    .line 827
    move/from16 v29, v8

    .line 828
    .line 829
    iget-wide v8, v1, Lh2/f8;->b:J

    .line 830
    .line 831
    move-object/from16 p0, v14

    .line 832
    .line 833
    shr-long v13, v8, v27

    .line 834
    .line 835
    long-to-int v13, v13

    .line 836
    and-long v8, v8, v25

    .line 837
    .line 838
    long-to-int v8, v8

    .line 839
    int-to-float v9, v11

    .line 840
    add-float v11, v4, v10

    .line 841
    .line 842
    mul-float/2addr v9, v11

    .line 843
    iget-boolean v14, v1, Lh2/f8;->c:Z

    .line 844
    .line 845
    if-eqz v14, :cond_7

    .line 846
    .line 847
    div-float v14, v4, v6

    .line 848
    .line 849
    goto :goto_2

    .line 850
    :cond_7
    move/from16 v14, v29

    .line 851
    .line 852
    :goto_2
    add-float/2addr v9, v14

    .line 853
    div-float/2addr v10, v6

    .line 854
    add-float/2addr v9, v10

    .line 855
    int-to-float v14, v12

    .line 856
    mul-float/2addr v14, v0

    .line 857
    add-float v30, v14, v7

    .line 858
    .line 859
    int-to-float v13, v13

    .line 860
    mul-float/2addr v13, v11

    .line 861
    iget-boolean v1, v1, Lh2/f8;->d:Z

    .line 862
    .line 863
    if-eqz v1, :cond_8

    .line 864
    .line 865
    div-float/2addr v4, v6

    .line 866
    :cond_8
    add-float/2addr v13, v4

    .line 867
    add-float/2addr v13, v10

    .line 868
    int-to-float v1, v8

    .line 869
    mul-float/2addr v1, v0

    .line 870
    add-float/2addr v1, v7

    .line 871
    invoke-virtual/range {p0 .. p0}, Lv3/j0;->getLayoutDirection()Lt4/m;

    .line 872
    .line 873
    .line 874
    move-result-object v4

    .line 875
    sget-object v6, Lt4/m;->e:Lt4/m;

    .line 876
    .line 877
    if-ne v4, v6, :cond_9

    .line 878
    .line 879
    move/from16 v4, v28

    .line 880
    .line 881
    goto :goto_3

    .line 882
    :cond_9
    const/4 v4, 0x0

    .line 883
    :goto_3
    if-eqz v4, :cond_a

    .line 884
    .line 885
    invoke-interface {v15}, Lg3/d;->e()J

    .line 886
    .line 887
    .line 888
    move-result-wide v6

    .line 889
    shr-long v6, v6, v27

    .line 890
    .line 891
    long-to-int v6, v6

    .line 892
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 893
    .line 894
    .line 895
    move-result v6

    .line 896
    sub-float v9, v6, v9

    .line 897
    .line 898
    invoke-interface {v15}, Lg3/d;->e()J

    .line 899
    .line 900
    .line 901
    move-result-wide v6

    .line 902
    shr-long v6, v6, v27

    .line 903
    .line 904
    long-to-int v6, v6

    .line 905
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 906
    .line 907
    .line 908
    move-result v6

    .line 909
    sub-float v13, v6, v13

    .line 910
    .line 911
    :cond_a
    invoke-static {v9}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 912
    .line 913
    .line 914
    move-result v6

    .line 915
    int-to-long v6, v6

    .line 916
    invoke-static/range {v30 .. v30}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 917
    .line 918
    .line 919
    move-result v10

    .line 920
    int-to-long v10, v10

    .line 921
    shl-long v6, v6, v27

    .line 922
    .line 923
    and-long v10, v10, v25

    .line 924
    .line 925
    or-long v17, v6, v10

    .line 926
    .line 927
    if-ne v12, v8, :cond_b

    .line 928
    .line 929
    sub-float v6, v13, v9

    .line 930
    .line 931
    goto :goto_4

    .line 932
    :cond_b
    if-eqz v4, :cond_c

    .line 933
    .line 934
    neg-float v6, v9

    .line 935
    goto :goto_4

    .line 936
    :cond_c
    invoke-interface {v15}, Lg3/d;->e()J

    .line 937
    .line 938
    .line 939
    move-result-wide v6

    .line 940
    shr-long v6, v6, v27

    .line 941
    .line 942
    long-to-int v6, v6

    .line 943
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 944
    .line 945
    .line 946
    move-result v6

    .line 947
    sub-float/2addr v6, v9

    .line 948
    :goto_4
    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 949
    .line 950
    .line 951
    move-result v6

    .line 952
    int-to-long v6, v6

    .line 953
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 954
    .line 955
    .line 956
    move-result v9

    .line 957
    int-to-long v9, v9

    .line 958
    shl-long v6, v6, v27

    .line 959
    .line 960
    and-long v9, v9, v25

    .line 961
    .line 962
    or-long v19, v6, v9

    .line 963
    .line 964
    const/16 v23, 0x0

    .line 965
    .line 966
    const/16 v24, 0x78

    .line 967
    .line 968
    const/16 v21, 0x0

    .line 969
    .line 970
    const/16 v22, 0x0

    .line 971
    .line 972
    move-wide/from16 v31, v2

    .line 973
    .line 974
    move-object v2, v15

    .line 975
    move-wide/from16 v15, v31

    .line 976
    .line 977
    move-object/from16 v14, p0

    .line 978
    .line 979
    invoke-static/range {v14 .. v24}, Lg3/d;->r0(Lg3/d;JJJFLg3/h;Le3/m;I)V

    .line 980
    .line 981
    .line 982
    if-eq v12, v8, :cond_10

    .line 983
    .line 984
    sub-int/2addr v8, v12

    .line 985
    add-int/lit8 v8, v8, -0x1

    .line 986
    .line 987
    :goto_5
    if-lez v8, :cond_d

    .line 988
    .line 989
    int-to-float v3, v8

    .line 990
    mul-float/2addr v3, v0

    .line 991
    add-float v3, v3, v30

    .line 992
    .line 993
    invoke-static/range {v29 .. v29}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 994
    .line 995
    .line 996
    move-result v6

    .line 997
    int-to-long v6, v6

    .line 998
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 999
    .line 1000
    .line 1001
    move-result v3

    .line 1002
    int-to-long v9, v3

    .line 1003
    shl-long v6, v6, v27

    .line 1004
    .line 1005
    and-long v9, v9, v25

    .line 1006
    .line 1007
    or-long v17, v6, v9

    .line 1008
    .line 1009
    invoke-interface {v2}, Lg3/d;->e()J

    .line 1010
    .line 1011
    .line 1012
    move-result-wide v6

    .line 1013
    shr-long v6, v6, v27

    .line 1014
    .line 1015
    long-to-int v3, v6

    .line 1016
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 1017
    .line 1018
    .line 1019
    move-result v3

    .line 1020
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 1021
    .line 1022
    .line 1023
    move-result v3

    .line 1024
    int-to-long v6, v3

    .line 1025
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 1026
    .line 1027
    .line 1028
    move-result v3

    .line 1029
    int-to-long v9, v3

    .line 1030
    shl-long v6, v6, v27

    .line 1031
    .line 1032
    and-long v9, v9, v25

    .line 1033
    .line 1034
    or-long v19, v6, v9

    .line 1035
    .line 1036
    const/16 v23, 0x0

    .line 1037
    .line 1038
    const/16 v24, 0x78

    .line 1039
    .line 1040
    const/16 v21, 0x0

    .line 1041
    .line 1042
    const/16 v22, 0x0

    .line 1043
    .line 1044
    invoke-static/range {v14 .. v24}, Lg3/d;->r0(Lg3/d;JJJFLg3/h;Le3/m;I)V

    .line 1045
    .line 1046
    .line 1047
    add-int/lit8 v8, v8, -0x1

    .line 1048
    .line 1049
    goto :goto_5

    .line 1050
    :cond_d
    invoke-virtual {v14}, Lv3/j0;->getLayoutDirection()Lt4/m;

    .line 1051
    .line 1052
    .line 1053
    move-result-object v0

    .line 1054
    sget-object v3, Lt4/m;->d:Lt4/m;

    .line 1055
    .line 1056
    if-ne v0, v3, :cond_e

    .line 1057
    .line 1058
    move/from16 v8, v29

    .line 1059
    .line 1060
    goto :goto_6

    .line 1061
    :cond_e
    invoke-interface {v2}, Lg3/d;->e()J

    .line 1062
    .line 1063
    .line 1064
    move-result-wide v6

    .line 1065
    shr-long v6, v6, v27

    .line 1066
    .line 1067
    long-to-int v0, v6

    .line 1068
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 1069
    .line 1070
    .line 1071
    move-result v8

    .line 1072
    :goto_6
    invoke-static {v8}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 1073
    .line 1074
    .line 1075
    move-result v0

    .line 1076
    int-to-long v6, v0

    .line 1077
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 1078
    .line 1079
    .line 1080
    move-result v0

    .line 1081
    int-to-long v0, v0

    .line 1082
    shl-long v6, v6, v27

    .line 1083
    .line 1084
    and-long v0, v0, v25

    .line 1085
    .line 1086
    or-long v17, v6, v0

    .line 1087
    .line 1088
    if-eqz v4, :cond_f

    .line 1089
    .line 1090
    invoke-interface {v2}, Lg3/d;->e()J

    .line 1091
    .line 1092
    .line 1093
    move-result-wide v0

    .line 1094
    shr-long v0, v0, v27

    .line 1095
    .line 1096
    long-to-int v0, v0

    .line 1097
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 1098
    .line 1099
    .line 1100
    move-result v0

    .line 1101
    sub-float/2addr v13, v0

    .line 1102
    :cond_f
    invoke-static {v13}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 1103
    .line 1104
    .line 1105
    move-result v0

    .line 1106
    int-to-long v0, v0

    .line 1107
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 1108
    .line 1109
    .line 1110
    move-result v2

    .line 1111
    int-to-long v2, v2

    .line 1112
    shl-long v0, v0, v27

    .line 1113
    .line 1114
    and-long v2, v2, v25

    .line 1115
    .line 1116
    or-long v19, v0, v2

    .line 1117
    .line 1118
    const/16 v23, 0x0

    .line 1119
    .line 1120
    const/16 v24, 0x78

    .line 1121
    .line 1122
    const/16 v21, 0x0

    .line 1123
    .line 1124
    const/16 v22, 0x0

    .line 1125
    .line 1126
    invoke-static/range {v14 .. v24}, Lg3/d;->r0(Lg3/d;JJJFLg3/h;Le3/m;I)V

    .line 1127
    .line 1128
    .line 1129
    :cond_10
    invoke-virtual {v14}, Lv3/j0;->b()V

    .line 1130
    .line 1131
    .line 1132
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1133
    .line 1134
    return-object v0

    .line 1135
    :pswitch_e
    iget-object v1, v0, Let/g;->e:Ljava/lang/Object;

    .line 1136
    .line 1137
    check-cast v1, Lvy0/b0;

    .line 1138
    .line 1139
    iget-object v0, v0, Let/g;->f:Ljava/lang/Object;

    .line 1140
    .line 1141
    check-cast v0, Lh2/r8;

    .line 1142
    .line 1143
    move-object/from16 v2, p1

    .line 1144
    .line 1145
    check-cast v2, Ljava/lang/Float;

    .line 1146
    .line 1147
    invoke-virtual {v2}, Ljava/lang/Float;->floatValue()F

    .line 1148
    .line 1149
    .line 1150
    move-result v2

    .line 1151
    new-instance v3, Lh2/l0;

    .line 1152
    .line 1153
    const/4 v13, 0x0

    .line 1154
    invoke-direct {v3, v0, v2, v14, v13}, Lh2/l0;-><init>(Lh2/r8;FLkotlin/coroutines/Continuation;I)V

    .line 1155
    .line 1156
    .line 1157
    invoke-static {v1, v14, v14, v3, v4}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1158
    .line 1159
    .line 1160
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1161
    .line 1162
    return-object v0

    .line 1163
    :pswitch_f
    iget-object v1, v0, Let/g;->e:Ljava/lang/Object;

    .line 1164
    .line 1165
    check-cast v1, Lgp0/c;

    .line 1166
    .line 1167
    iget-object v0, v0, Let/g;->f:Ljava/lang/Object;

    .line 1168
    .line 1169
    check-cast v0, Lgp0/d;

    .line 1170
    .line 1171
    move-object/from16 v2, p1

    .line 1172
    .line 1173
    check-cast v2, Lua/a;

    .line 1174
    .line 1175
    const-string v3, "_connection"

    .line 1176
    .line 1177
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1178
    .line 1179
    .line 1180
    iget-object v1, v1, Lgp0/c;->b:Las0/h;

    .line 1181
    .line 1182
    invoke-virtual {v1, v2, v0}, Llp/ef;->e(Lua/a;Ljava/lang/Object;)V

    .line 1183
    .line 1184
    .line 1185
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1186
    .line 1187
    return-object v0

    .line 1188
    :pswitch_10
    iget-object v1, v0, Let/g;->e:Ljava/lang/Object;

    .line 1189
    .line 1190
    check-cast v1, Lgp0/a;

    .line 1191
    .line 1192
    iget-object v0, v0, Let/g;->f:Ljava/lang/Object;

    .line 1193
    .line 1194
    check-cast v0, Lua/a;

    .line 1195
    .line 1196
    move-object/from16 v2, p1

    .line 1197
    .line 1198
    check-cast v2, Landroidx/collection/u;

    .line 1199
    .line 1200
    const-string v3, "_tmpMap"

    .line 1201
    .line 1202
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1203
    .line 1204
    .line 1205
    invoke-virtual {v1, v0, v2}, Lgp0/a;->b(Lua/a;Landroidx/collection/u;)V

    .line 1206
    .line 1207
    .line 1208
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1209
    .line 1210
    return-object v0

    .line 1211
    :pswitch_11
    iget-object v1, v0, Let/g;->e:Ljava/lang/Object;

    .line 1212
    .line 1213
    check-cast v1, Lgp0/a;

    .line 1214
    .line 1215
    iget-object v0, v0, Let/g;->f:Ljava/lang/Object;

    .line 1216
    .line 1217
    check-cast v0, Lgp0/b;

    .line 1218
    .line 1219
    move-object/from16 v2, p1

    .line 1220
    .line 1221
    check-cast v2, Lua/a;

    .line 1222
    .line 1223
    const-string v3, "_connection"

    .line 1224
    .line 1225
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1226
    .line 1227
    .line 1228
    iget-object v1, v1, Lgp0/a;->b:Las0/h;

    .line 1229
    .line 1230
    invoke-virtual {v1, v2, v0}, Llp/ef;->g(Lua/a;Ljava/lang/Object;)J

    .line 1231
    .line 1232
    .line 1233
    move-result-wide v0

    .line 1234
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1235
    .line 1236
    .line 1237
    move-result-object v0

    .line 1238
    return-object v0

    .line 1239
    :pswitch_12
    const/16 v28, 0x1

    .line 1240
    .line 1241
    iget-object v1, v0, Let/g;->e:Ljava/lang/Object;

    .line 1242
    .line 1243
    check-cast v1, Lzi/a;

    .line 1244
    .line 1245
    iget-object v0, v0, Let/g;->f:Ljava/lang/Object;

    .line 1246
    .line 1247
    check-cast v0, Lz9/y;

    .line 1248
    .line 1249
    move-object/from16 v2, p1

    .line 1250
    .line 1251
    check-cast v2, Lz9/w;

    .line 1252
    .line 1253
    const-string v3, "$this$NavHost"

    .line 1254
    .line 1255
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1256
    .line 1257
    .line 1258
    const-string v3, "REMOTE_START_ROUTE"

    .line 1259
    .line 1260
    new-instance v4, Lgg/a;

    .line 1261
    .line 1262
    const/4 v13, 0x0

    .line 1263
    invoke-direct {v4, v1, v0, v13}, Lgg/a;-><init>(Lzi/a;Lz9/y;I)V

    .line 1264
    .line 1265
    .line 1266
    new-instance v9, Lt2/b;

    .line 1267
    .line 1268
    const v5, -0x54c92d3e

    .line 1269
    .line 1270
    .line 1271
    move/from16 v11, v28

    .line 1272
    .line 1273
    invoke-direct {v9, v4, v11, v5}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 1274
    .line 1275
    .line 1276
    const/16 v10, 0xfe

    .line 1277
    .line 1278
    const/4 v4, 0x0

    .line 1279
    const/4 v5, 0x0

    .line 1280
    const/4 v6, 0x0

    .line 1281
    const/4 v7, 0x0

    .line 1282
    const/4 v8, 0x0

    .line 1283
    invoke-static/range {v2 .. v10}, Ljp/r0;->b(Lz9/w;Ljava/lang/String;Ljava/util/List;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lt2/b;I)V

    .line 1284
    .line 1285
    .line 1286
    const-string v3, "REMOTE_STOP_ROUTE"

    .line 1287
    .line 1288
    new-instance v4, Lgg/a;

    .line 1289
    .line 1290
    invoke-direct {v4, v1, v0, v11}, Lgg/a;-><init>(Lzi/a;Lz9/y;I)V

    .line 1291
    .line 1292
    .line 1293
    new-instance v9, Lt2/b;

    .line 1294
    .line 1295
    const v0, 0x1cf41039

    .line 1296
    .line 1297
    .line 1298
    invoke-direct {v9, v4, v11, v0}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 1299
    .line 1300
    .line 1301
    const/4 v4, 0x0

    .line 1302
    invoke-static/range {v2 .. v10}, Ljp/r0;->b(Lz9/w;Ljava/lang/String;Ljava/util/List;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lt2/b;I)V

    .line 1303
    .line 1304
    .line 1305
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1306
    .line 1307
    return-object v0

    .line 1308
    :pswitch_13
    move/from16 v29, v8

    .line 1309
    .line 1310
    iget-object v1, v0, Let/g;->e:Ljava/lang/Object;

    .line 1311
    .line 1312
    check-cast v1, Lg1/l3;

    .line 1313
    .line 1314
    iget-object v0, v0, Let/g;->f:Ljava/lang/Object;

    .line 1315
    .line 1316
    check-cast v0, Lay0/k;

    .line 1317
    .line 1318
    move-object/from16 v2, p1

    .line 1319
    .line 1320
    check-cast v2, Ljava/lang/Long;

    .line 1321
    .line 1322
    invoke-virtual {v2}, Ljava/lang/Long;->longValue()J

    .line 1323
    .line 1324
    .line 1325
    iget v2, v1, Lg1/l3;->e:F

    .line 1326
    .line 1327
    move/from16 v3, v29

    .line 1328
    .line 1329
    iput v3, v1, Lg1/l3;->e:F

    .line 1330
    .line 1331
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1332
    .line 1333
    .line 1334
    move-result-object v1

    .line 1335
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1336
    .line 1337
    .line 1338
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1339
    .line 1340
    return-object v0

    .line 1341
    :pswitch_14
    iget-object v1, v0, Let/g;->e:Ljava/lang/Object;

    .line 1342
    .line 1343
    check-cast v1, Lg1/t2;

    .line 1344
    .line 1345
    iget-object v0, v0, Let/g;->f:Ljava/lang/Object;

    .line 1346
    .line 1347
    check-cast v0, Lg1/u2;

    .line 1348
    .line 1349
    move-object/from16 v2, p1

    .line 1350
    .line 1351
    check-cast v2, Lg1/h0;

    .line 1352
    .line 1353
    iget-wide v2, v2, Lg1/h0;->a:J

    .line 1354
    .line 1355
    iget-object v0, v0, Lg1/u2;->d:Lg1/w1;

    .line 1356
    .line 1357
    sget-object v4, Lg1/w1;->e:Lg1/w1;

    .line 1358
    .line 1359
    if-ne v0, v4, :cond_11

    .line 1360
    .line 1361
    const/4 v0, 0x0

    .line 1362
    const/4 v11, 0x1

    .line 1363
    invoke-static {v2, v3, v11, v0}, Ld3/b;->a(JIF)J

    .line 1364
    .line 1365
    .line 1366
    move-result-wide v2

    .line 1367
    goto :goto_7

    .line 1368
    :cond_11
    const/4 v0, 0x0

    .line 1369
    const/4 v11, 0x1

    .line 1370
    invoke-static {v2, v3, v6, v0}, Ld3/b;->a(JIF)J

    .line 1371
    .line 1372
    .line 1373
    move-result-wide v2

    .line 1374
    :goto_7
    invoke-virtual {v1, v11, v2, v3}, Lg1/t2;->a(IJ)J

    .line 1375
    .line 1376
    .line 1377
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1378
    .line 1379
    return-object v0

    .line 1380
    :pswitch_15
    move-wide/from16 v25, v10

    .line 1381
    .line 1382
    move/from16 v27, v12

    .line 1383
    .line 1384
    iget-object v1, v0, Let/g;->e:Ljava/lang/Object;

    .line 1385
    .line 1386
    check-cast v1, Lg1/a0;

    .line 1387
    .line 1388
    iget-object v0, v0, Let/g;->f:Ljava/lang/Object;

    .line 1389
    .line 1390
    check-cast v0, Lg1/h1;

    .line 1391
    .line 1392
    move-object/from16 v3, p1

    .line 1393
    .line 1394
    check-cast v3, Lg1/h0;

    .line 1395
    .line 1396
    iget-wide v3, v3, Lg1/h0;->a:J

    .line 1397
    .line 1398
    iget-boolean v5, v0, Lg1/h1;->H:Z

    .line 1399
    .line 1400
    if-eqz v5, :cond_12

    .line 1401
    .line 1402
    invoke-static {v3, v4, v2}, Ld3/b;->i(JF)J

    .line 1403
    .line 1404
    .line 1405
    move-result-wide v2

    .line 1406
    goto :goto_8

    .line 1407
    :cond_12
    invoke-static {v3, v4, v7}, Ld3/b;->i(JF)J

    .line 1408
    .line 1409
    .line 1410
    move-result-wide v2

    .line 1411
    :goto_8
    iget-object v0, v0, Lg1/h1;->D:Lg1/w1;

    .line 1412
    .line 1413
    sget-object v4, Lg1/f1;->a:Lg1/e1;

    .line 1414
    .line 1415
    sget-object v4, Lg1/w1;->d:Lg1/w1;

    .line 1416
    .line 1417
    if-ne v0, v4, :cond_13

    .line 1418
    .line 1419
    and-long v2, v2, v25

    .line 1420
    .line 1421
    :goto_9
    long-to-int v0, v2

    .line 1422
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 1423
    .line 1424
    .line 1425
    move-result v0

    .line 1426
    goto :goto_a

    .line 1427
    :cond_13
    shr-long v2, v2, v27

    .line 1428
    .line 1429
    goto :goto_9

    .line 1430
    :goto_a
    iget v2, v1, Lg1/a0;->a:I

    .line 1431
    .line 1432
    packed-switch v2, :pswitch_data_1

    .line 1433
    .line 1434
    .line 1435
    iget-object v1, v1, Lg1/a0;->b:Ljava/lang/Object;

    .line 1436
    .line 1437
    check-cast v1, Li2/p;

    .line 1438
    .line 1439
    iget-object v2, v1, Li2/p;->n:Li2/n;

    .line 1440
    .line 1441
    invoke-virtual {v1, v0}, Li2/p;->e(F)F

    .line 1442
    .line 1443
    .line 1444
    move-result v0

    .line 1445
    invoke-static {v2, v0}, Li2/n;->a(Li2/n;F)V

    .line 1446
    .line 1447
    .line 1448
    goto :goto_b

    .line 1449
    :pswitch_16
    iget-object v1, v1, Lg1/a0;->b:Ljava/lang/Object;

    .line 1450
    .line 1451
    check-cast v1, Lh2/s9;

    .line 1452
    .line 1453
    invoke-virtual {v1, v0}, Lh2/s9;->b(F)V

    .line 1454
    .line 1455
    .line 1456
    goto :goto_b

    .line 1457
    :pswitch_17
    iget-object v1, v1, Lg1/a0;->b:Ljava/lang/Object;

    .line 1458
    .line 1459
    check-cast v1, Lg1/b0;

    .line 1460
    .line 1461
    iget-object v1, v1, Lg1/b0;->a:La2/g;

    .line 1462
    .line 1463
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1464
    .line 1465
    .line 1466
    move-result-object v0

    .line 1467
    invoke-virtual {v1, v0}, La2/g;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1468
    .line 1469
    .line 1470
    :goto_b
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1471
    .line 1472
    return-object v0

    .line 1473
    :pswitch_18
    iget-object v1, v0, Let/g;->e:Ljava/lang/Object;

    .line 1474
    .line 1475
    check-cast v1, Lg1/r;

    .line 1476
    .line 1477
    iget-object v0, v0, Let/g;->f:Ljava/lang/Object;

    .line 1478
    .line 1479
    check-cast v0, Lg1/x;

    .line 1480
    .line 1481
    move-object/from16 v2, p1

    .line 1482
    .line 1483
    check-cast v2, Ljava/lang/Throwable;

    .line 1484
    .line 1485
    iget-object v1, v1, Lg1/r;->a:Ln2/b;

    .line 1486
    .line 1487
    invoke-virtual {v1, v0}, Ln2/b;->l(Ljava/lang/Object;)Z

    .line 1488
    .line 1489
    .line 1490
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1491
    .line 1492
    return-object v0

    .line 1493
    :pswitch_19
    move-wide/from16 v25, v10

    .line 1494
    .line 1495
    move/from16 v27, v12

    .line 1496
    .line 1497
    iget-object v1, v0, Let/g;->e:Ljava/lang/Object;

    .line 1498
    .line 1499
    check-cast v1, Lg1/m;

    .line 1500
    .line 1501
    iget-object v0, v0, Let/g;->f:Ljava/lang/Object;

    .line 1502
    .line 1503
    check-cast v0, Lg1/p;

    .line 1504
    .line 1505
    move-object/from16 v3, p1

    .line 1506
    .line 1507
    check-cast v3, Lg1/h0;

    .line 1508
    .line 1509
    iget-wide v3, v3, Lg1/h0;->a:J

    .line 1510
    .line 1511
    invoke-virtual {v1}, Lg1/m;->k1()Z

    .line 1512
    .line 1513
    .line 1514
    move-result v5

    .line 1515
    if-eqz v5, :cond_14

    .line 1516
    .line 1517
    invoke-static {v3, v4, v2}, Ld3/b;->i(JF)J

    .line 1518
    .line 1519
    .line 1520
    move-result-wide v2

    .line 1521
    goto :goto_c

    .line 1522
    :cond_14
    invoke-static {v3, v4, v7}, Ld3/b;->i(JF)J

    .line 1523
    .line 1524
    .line 1525
    move-result-wide v2

    .line 1526
    :goto_c
    iget-object v4, v1, Lg1/m;->D:Lg1/w1;

    .line 1527
    .line 1528
    sget-object v5, Lg1/w1;->d:Lg1/w1;

    .line 1529
    .line 1530
    if-ne v4, v5, :cond_15

    .line 1531
    .line 1532
    and-long v2, v2, v25

    .line 1533
    .line 1534
    :goto_d
    long-to-int v2, v2

    .line 1535
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 1536
    .line 1537
    .line 1538
    move-result v2

    .line 1539
    goto :goto_e

    .line 1540
    :cond_15
    shr-long v2, v2, v27

    .line 1541
    .line 1542
    goto :goto_d

    .line 1543
    :goto_e
    iget-object v1, v1, Lg1/m;->C:Lg1/q;

    .line 1544
    .line 1545
    invoke-virtual {v1, v2}, Lg1/q;->j(F)F

    .line 1546
    .line 1547
    .line 1548
    move-result v1

    .line 1549
    invoke-static {v0, v1}, Lg1/p;->b(Lg1/p;F)V

    .line 1550
    .line 1551
    .line 1552
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1553
    .line 1554
    return-object v0

    .line 1555
    :pswitch_1a
    iget-object v1, v0, Let/g;->e:Ljava/lang/Object;

    .line 1556
    .line 1557
    check-cast v1, Lhc/a;

    .line 1558
    .line 1559
    iget-object v0, v0, Let/g;->f:Ljava/lang/Object;

    .line 1560
    .line 1561
    check-cast v0, Lay0/k;

    .line 1562
    .line 1563
    move-object/from16 v2, p1

    .line 1564
    .line 1565
    check-cast v2, Lm1/f;

    .line 1566
    .line 1567
    const-string v3, "$this$LazyColumn"

    .line 1568
    .line 1569
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1570
    .line 1571
    .line 1572
    iget-object v1, v1, Lhc/a;->d:Ljava/util/ArrayList;

    .line 1573
    .line 1574
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 1575
    .line 1576
    .line 1577
    move-result v3

    .line 1578
    new-instance v4, Lal/n;

    .line 1579
    .line 1580
    invoke-direct {v4, v1, v6}, Lal/n;-><init>(Ljava/util/ArrayList;I)V

    .line 1581
    .line 1582
    .line 1583
    new-instance v5, Lca0/g;

    .line 1584
    .line 1585
    const/4 v11, 0x1

    .line 1586
    invoke-direct {v5, v1, v0, v11}, Lca0/g;-><init>(Ljava/util/ArrayList;Lay0/k;I)V

    .line 1587
    .line 1588
    .line 1589
    new-instance v0, Lt2/b;

    .line 1590
    .line 1591
    const v1, 0x799532c4

    .line 1592
    .line 1593
    .line 1594
    invoke-direct {v0, v5, v11, v1}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 1595
    .line 1596
    .line 1597
    invoke-virtual {v2, v3, v14, v4, v0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 1598
    .line 1599
    .line 1600
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1601
    .line 1602
    return-object v0

    .line 1603
    :pswitch_1b
    iget-object v1, v0, Let/g;->e:Ljava/lang/Object;

    .line 1604
    .line 1605
    check-cast v1, Lai/a;

    .line 1606
    .line 1607
    iget-object v0, v0, Let/g;->f:Ljava/lang/Object;

    .line 1608
    .line 1609
    check-cast v0, Lyj/b;

    .line 1610
    .line 1611
    move-object/from16 v2, p1

    .line 1612
    .line 1613
    check-cast v2, Lhi/a;

    .line 1614
    .line 1615
    const-string v3, "$this$sdkViewModel"

    .line 1616
    .line 1617
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1618
    .line 1619
    .line 1620
    const-class v3, Ldh/u;

    .line 1621
    .line 1622
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1623
    .line 1624
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1625
    .line 1626
    .line 1627
    move-result-object v3

    .line 1628
    check-cast v2, Lii/a;

    .line 1629
    .line 1630
    invoke-virtual {v2, v3}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 1631
    .line 1632
    .line 1633
    move-result-object v2

    .line 1634
    check-cast v2, Ldh/u;

    .line 1635
    .line 1636
    new-instance v3, Lfi/c;

    .line 1637
    .line 1638
    new-instance v4, La2/c;

    .line 1639
    .line 1640
    const/16 v5, 0xb

    .line 1641
    .line 1642
    invoke-direct {v4, v5, v2, v1, v14}, La2/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 1643
    .line 1644
    .line 1645
    invoke-direct {v3, v1, v4, v0}, Lfi/c;-><init>(Lai/a;La2/c;Lyj/b;)V

    .line 1646
    .line 1647
    .line 1648
    return-object v3

    .line 1649
    :pswitch_1c
    iget-object v1, v0, Let/g;->e:Ljava/lang/Object;

    .line 1650
    .line 1651
    check-cast v1, Le51/e;

    .line 1652
    .line 1653
    iget-object v0, v0, Let/g;->f:Ljava/lang/Object;

    .line 1654
    .line 1655
    check-cast v0, Ljava/lang/String;

    .line 1656
    .line 1657
    move-object/from16 v2, p1

    .line 1658
    .line 1659
    check-cast v2, Lkw0/c;

    .line 1660
    .line 1661
    const-string v3, "$this$catRequest"

    .line 1662
    .line 1663
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1664
    .line 1665
    .line 1666
    sget-object v3, Low0/v;->f:Low0/v;

    .line 1667
    .line 1668
    invoke-static {v3}, Ljp/m1;->k(Ljava/lang/Object;)Ljava/util/Set;

    .line 1669
    .line 1670
    .line 1671
    move-result-object v3

    .line 1672
    invoke-static {v2, v3}, Lkp/i7;->a(Lkw0/c;Ljava/util/Set;)V

    .line 1673
    .line 1674
    .line 1675
    sget-object v3, Low0/s;->b:Low0/s;

    .line 1676
    .line 1677
    invoke-virtual {v2, v3}, Lkw0/c;->b(Low0/s;)V

    .line 1678
    .line 1679
    .line 1680
    iget-object v1, v1, Le51/e;->b:Ly41/g;

    .line 1681
    .line 1682
    iget-object v1, v1, Ly41/g;->a:Ljava/lang/String;

    .line 1683
    .line 1684
    new-instance v3, Ljava/lang/StringBuilder;

    .line 1685
    .line 1686
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 1687
    .line 1688
    .line 1689
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1690
    .line 1691
    .line 1692
    const-string v1, "/user/v1/mobiledevicekeys/"

    .line 1693
    .line 1694
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1695
    .line 1696
    .line 1697
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1698
    .line 1699
    .line 1700
    const-string v0, "/status"

    .line 1701
    .line 1702
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1703
    .line 1704
    .line 1705
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1706
    .line 1707
    .line 1708
    move-result-object v0

    .line 1709
    invoke-static {v2, v0}, Lkw0/d;->a(Lkw0/c;Ljava/lang/String;)V

    .line 1710
    .line 1711
    .line 1712
    sget-object v0, Low0/b;->a:Low0/e;

    .line 1713
    .line 1714
    invoke-static {v2, v0}, Ljp/pc;->d(Lkw0/c;Low0/e;)V

    .line 1715
    .line 1716
    .line 1717
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1718
    .line 1719
    return-object v0

    .line 1720
    :pswitch_1d
    iget-object v1, v0, Let/g;->e:Ljava/lang/Object;

    .line 1721
    .line 1722
    check-cast v1, Lf01/g;

    .line 1723
    .line 1724
    iget-object v0, v0, Let/g;->f:Ljava/lang/Object;

    .line 1725
    .line 1726
    check-cast v0, La8/b;

    .line 1727
    .line 1728
    move-object/from16 v2, p1

    .line 1729
    .line 1730
    check-cast v2, Ljava/io/IOException;

    .line 1731
    .line 1732
    const-string v3, "it"

    .line 1733
    .line 1734
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1735
    .line 1736
    .line 1737
    monitor-enter v1

    .line 1738
    :try_start_0
    invoke-virtual {v0}, La8/b;->g()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 1739
    .line 1740
    .line 1741
    monitor-exit v1

    .line 1742
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1743
    .line 1744
    return-object v0

    .line 1745
    :catchall_0
    move-exception v0

    .line 1746
    monitor-exit v1

    .line 1747
    throw v0

    .line 1748
    :pswitch_1e
    iget-object v1, v0, Let/g;->e:Ljava/lang/Object;

    .line 1749
    .line 1750
    check-cast v1, Let/h;

    .line 1751
    .line 1752
    iget-object v0, v0, Let/g;->f:Ljava/lang/Object;

    .line 1753
    .line 1754
    check-cast v0, Ljava/lang/String;

    .line 1755
    .line 1756
    move-object/from16 v2, p1

    .line 1757
    .line 1758
    check-cast v2, Lq6/b;

    .line 1759
    .line 1760
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1761
    .line 1762
    .line 1763
    sget-object v3, Let/h;->d:Lq6/e;

    .line 1764
    .line 1765
    invoke-virtual {v2, v3, v0}, Lq6/b;->e(Lq6/e;Ljava/lang/Object;)V

    .line 1766
    .line 1767
    .line 1768
    invoke-virtual {v1, v2, v0}, Let/h;->d(Lq6/b;Ljava/lang/String;)V

    .line 1769
    .line 1770
    .line 1771
    return-object v14

    .line 1772
    nop

    .line 1773
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
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

    .line 1774
    .line 1775
    .line 1776
    .line 1777
    .line 1778
    .line 1779
    .line 1780
    .line 1781
    .line 1782
    .line 1783
    .line 1784
    .line 1785
    .line 1786
    .line 1787
    .line 1788
    .line 1789
    .line 1790
    .line 1791
    .line 1792
    .line 1793
    .line 1794
    .line 1795
    .line 1796
    .line 1797
    .line 1798
    .line 1799
    .line 1800
    .line 1801
    .line 1802
    .line 1803
    .line 1804
    .line 1805
    .line 1806
    .line 1807
    .line 1808
    .line 1809
    .line 1810
    .line 1811
    .line 1812
    .line 1813
    .line 1814
    .line 1815
    .line 1816
    .line 1817
    .line 1818
    .line 1819
    .line 1820
    .line 1821
    .line 1822
    .line 1823
    .line 1824
    .line 1825
    .line 1826
    .line 1827
    .line 1828
    .line 1829
    .line 1830
    .line 1831
    .line 1832
    .line 1833
    .line 1834
    .line 1835
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_17
        :pswitch_16
    .end packed-switch
.end method
