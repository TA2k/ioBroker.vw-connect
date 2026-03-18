.class public final synthetic Ly1/i;
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
    iput p2, p0, Ly1/i;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ly1/i;->e:Ljava/lang/Object;

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
    .locals 8

    .line 1
    iget v0, p0, Ly1/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ly1/i;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lzb/v0;

    .line 9
    .line 10
    new-instance v0, Lz70/e0;

    .line 11
    .line 12
    const/16 v1, 0xd

    .line 13
    .line 14
    invoke-direct {v0, v1}, Lz70/e0;-><init>(I)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0, v0}, Lzb/v0;->g(Lay0/k;)V

    .line 18
    .line 19
    .line 20
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 21
    .line 22
    return-object p0

    .line 23
    :pswitch_0
    iget-object p0, p0, Ly1/i;->e:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast p0, Lr7/a;

    .line 26
    .line 27
    new-instance v0, Lzb/k0;

    .line 28
    .line 29
    invoke-direct {v0, p0}, Lzb/k0;-><init>(Lr7/a;)V

    .line 30
    .line 31
    .line 32
    return-object v0

    .line 33
    :pswitch_1
    iget-object p0, p0, Ly1/i;->e:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast p0, Lb/j0;

    .line 36
    .line 37
    invoke-interface {p0}, Lb/j0;->getOnBackPressedDispatcher()Lb/h0;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-virtual {p0}, Lb/h0;->c()V

    .line 42
    .line 43
    .line 44
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 45
    .line 46
    return-object p0

    .line 47
    :pswitch_2
    iget-object p0, p0, Ly1/i;->e:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast p0, Lzb/f;

    .line 50
    .line 51
    iget-object p0, p0, Lzb/f;->c:Lay0/a;

    .line 52
    .line 53
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 57
    .line 58
    return-object p0

    .line 59
    :pswitch_3
    iget-object p0, p0, Ly1/i;->e:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast p0, Lz9/k;

    .line 62
    .line 63
    iget-object p0, p0, Lz9/k;->k:Lca/c;

    .line 64
    .line 65
    iget-boolean v0, p0, Lca/c;->i:Z

    .line 66
    .line 67
    if-eqz v0, :cond_2

    .line 68
    .line 69
    iget-object v0, p0, Lca/c;->j:Landroidx/lifecycle/z;

    .line 70
    .line 71
    iget-object v0, v0, Landroidx/lifecycle/z;->d:Landroidx/lifecycle/q;

    .line 72
    .line 73
    sget-object v1, Landroidx/lifecycle/q;->d:Landroidx/lifecycle/q;

    .line 74
    .line 75
    if-eq v0, v1, :cond_1

    .line 76
    .line 77
    iget-object v0, p0, Lca/c;->a:Lz9/k;

    .line 78
    .line 79
    iget-object p0, p0, Lca/c;->m:Llx0/q;

    .line 80
    .line 81
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    check-cast p0, Landroidx/lifecycle/e1;

    .line 86
    .line 87
    const/4 v1, 0x4

    .line 88
    invoke-static {v0, p0, v1}, Lst/b;->d(Landroidx/lifecycle/i1;Landroidx/lifecycle/e1;I)Landroidx/lifecycle/g1;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    const-class v0, Lca/b;

    .line 93
    .line 94
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 95
    .line 96
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 101
    .line 102
    .line 103
    const-string v1, "modelClass"

    .line 104
    .line 105
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    iget-object p0, p0, Landroidx/lifecycle/g1;->a:Ljava/lang/Object;

    .line 109
    .line 110
    check-cast p0, Lcom/google/firebase/messaging/w;

    .line 111
    .line 112
    invoke-interface {v0}, Lhy0/d;->getQualifiedName()Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object v1

    .line 116
    if-eqz v1, :cond_0

    .line 117
    .line 118
    const-string v2, "androidx.lifecycle.ViewModelProvider.DefaultKey:"

    .line 119
    .line 120
    invoke-virtual {v2, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object v1

    .line 124
    invoke-virtual {p0, v0, v1}, Lcom/google/firebase/messaging/w;->l(Lhy0/d;Ljava/lang/String;)Landroidx/lifecycle/b1;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    check-cast p0, Lca/b;

    .line 129
    .line 130
    iget-object p0, p0, Lca/b;->d:Landroidx/lifecycle/s0;

    .line 131
    .line 132
    return-object p0

    .line 133
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 134
    .line 135
    const-string v0, "Local and anonymous classes can not be ViewModels"

    .line 136
    .line 137
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 138
    .line 139
    .line 140
    throw p0

    .line 141
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 142
    .line 143
    const-string v0, "You cannot access the NavBackStackEntry\'s SavedStateHandle after the NavBackStackEntry is destroyed."

    .line 144
    .line 145
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    throw p0

    .line 149
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 150
    .line 151
    const-string v0, "You cannot access the NavBackStackEntry\'s SavedStateHandle until it is added to the NavController\'s back stack (i.e., the Lifecycle of the NavBackStackEntry reaches the CREATED state)."

    .line 152
    .line 153
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 154
    .line 155
    .line 156
    throw p0

    .line 157
    :pswitch_4
    iget-object p0, p0, Ly1/i;->e:Ljava/lang/Object;

    .line 158
    .line 159
    check-cast p0, Lz1/f;

    .line 160
    .line 161
    iget-boolean v0, p0, Lx2/r;->q:Z

    .line 162
    .line 163
    if-eqz v0, :cond_3

    .line 164
    .line 165
    invoke-static {p0}, Lev/a;->e(Lv3/m;)Lw1/c;

    .line 166
    .line 167
    .line 168
    move-result-object p0

    .line 169
    goto :goto_0

    .line 170
    :cond_3
    sget-object p0, Lw1/c;->b:Lw1/c;

    .line 171
    .line 172
    :goto_0
    return-object p0

    .line 173
    :pswitch_5
    iget-object p0, p0, Ly1/i;->e:Ljava/lang/Object;

    .line 174
    .line 175
    check-cast p0, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationStatus;

    .line 176
    .line 177
    invoke-interface {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationStatus;->getStatus()I

    .line 178
    .line 179
    .line 180
    move-result p0

    .line 181
    const/4 v0, 0x1

    .line 182
    if-ne p0, v0, :cond_4

    .line 183
    .line 184
    const-string p0, "Marketing Cloud init was successful"

    .line 185
    .line 186
    goto :goto_1

    .line 187
    :cond_4
    const-string p0, "Marketing Cloud failed to initialize"

    .line 188
    .line 189
    :goto_1
    return-object p0

    .line 190
    :pswitch_6
    iget-object p0, p0, Ly1/i;->e:Ljava/lang/Object;

    .line 191
    .line 192
    check-cast p0, Lcom/google/firebase/messaging/v;

    .line 193
    .line 194
    new-instance v0, Ljava/lang/StringBuilder;

    .line 195
    .line 196
    const-string v1, "Message received: "

    .line 197
    .line 198
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 199
    .line 200
    .line 201
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 202
    .line 203
    .line 204
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 205
    .line 206
    .line 207
    move-result-object p0

    .line 208
    return-object p0

    .line 209
    :pswitch_7
    const-class v0, Landroid/app/ActivityManager;

    .line 210
    .line 211
    iget-object p0, p0, Ly1/i;->e:Ljava/lang/Object;

    .line 212
    .line 213
    check-cast p0, Lcom/google/android/material/datepicker/d;

    .line 214
    .line 215
    iget-object p0, p0, Lcom/google/android/material/datepicker/d;->a:Ljava/lang/Object;

    .line 216
    .line 217
    check-cast p0, Landroid/content/Context;

    .line 218
    .line 219
    const-wide v1, 0x3fc999999999999aL    # 0.2

    .line 220
    .line 221
    .line 222
    .line 223
    .line 224
    :try_start_0
    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object v3

    .line 228
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 229
    .line 230
    .line 231
    check-cast v3, Landroid/app/ActivityManager;

    .line 232
    .line 233
    invoke-virtual {v3}, Landroid/app/ActivityManager;->isLowRamDevice()Z

    .line 234
    .line 235
    .line 236
    move-result v3
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 237
    if-eqz v3, :cond_5

    .line 238
    .line 239
    const-wide v1, 0x3fc3333333333333L    # 0.15

    .line 240
    .line 241
    .line 242
    .line 243
    .line 244
    :catch_0
    :cond_5
    const-wide/16 v3, 0x0

    .line 245
    .line 246
    cmpg-double v3, v3, v1

    .line 247
    .line 248
    if-gtz v3, :cond_8

    .line 249
    .line 250
    const-wide/high16 v3, 0x3ff0000000000000L    # 1.0

    .line 251
    .line 252
    cmpg-double v3, v1, v3

    .line 253
    .line 254
    if-gtz v3, :cond_8

    .line 255
    .line 256
    new-instance v3, Lhm/g;

    .line 257
    .line 258
    const/4 v4, 0x0

    .line 259
    invoke-direct {v3, v4}, Lhm/g;-><init>(I)V

    .line 260
    .line 261
    .line 262
    :try_start_1
    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    .line 263
    .line 264
    .line 265
    move-result-object v0

    .line 266
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 267
    .line 268
    .line 269
    check-cast v0, Landroid/app/ActivityManager;

    .line 270
    .line 271
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;

    .line 272
    .line 273
    .line 274
    move-result-object p0

    .line 275
    iget p0, p0, Landroid/content/pm/ApplicationInfo;->flags:I

    .line 276
    .line 277
    const/high16 v4, 0x100000

    .line 278
    .line 279
    and-int/2addr p0, v4

    .line 280
    if-eqz p0, :cond_6

    .line 281
    .line 282
    invoke-virtual {v0}, Landroid/app/ActivityManager;->getLargeMemoryClass()I

    .line 283
    .line 284
    .line 285
    move-result p0

    .line 286
    goto :goto_2

    .line 287
    :cond_6
    invoke-virtual {v0}, Landroid/app/ActivityManager;->getMemoryClass()I

    .line 288
    .line 289
    .line 290
    move-result p0
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 291
    goto :goto_2

    .line 292
    :catch_1
    const/16 p0, 0x100

    .line 293
    .line 294
    :goto_2
    int-to-long v4, p0

    .line 295
    const-wide/32 v6, 0x100000

    .line 296
    .line 297
    .line 298
    mul-long/2addr v4, v6

    .line 299
    long-to-double v4, v4

    .line 300
    mul-double/2addr v1, v4

    .line 301
    double-to-long v0, v1

    .line 302
    new-instance p0, Lh6/j;

    .line 303
    .line 304
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 305
    .line 306
    .line 307
    iput-wide v0, p0, Lh6/j;->d:J

    .line 308
    .line 309
    iput-object v3, p0, Lh6/j;->e:Ljava/lang/Object;

    .line 310
    .line 311
    new-instance v2, Lc1/i2;

    .line 312
    .line 313
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 314
    .line 315
    .line 316
    iput-object p0, v2, Lc1/i2;->g:Ljava/lang/Object;

    .line 317
    .line 318
    new-instance v4, Ljava/util/LinkedHashMap;

    .line 319
    .line 320
    const/4 v5, 0x0

    .line 321
    const/high16 v6, 0x3f400000    # 0.75f

    .line 322
    .line 323
    const/4 v7, 0x1

    .line 324
    invoke-direct {v4, v5, v6, v7}, Ljava/util/LinkedHashMap;-><init>(IFZ)V

    .line 325
    .line 326
    .line 327
    iput-object v4, v2, Lc1/i2;->f:Ljava/lang/Object;

    .line 328
    .line 329
    iput-wide v0, v2, Lc1/i2;->d:J

    .line 330
    .line 331
    const-wide/16 v4, 0x0

    .line 332
    .line 333
    cmp-long v0, v0, v4

    .line 334
    .line 335
    if-lez v0, :cond_7

    .line 336
    .line 337
    iput-object v2, p0, Lh6/j;->f:Ljava/lang/Object;

    .line 338
    .line 339
    new-instance v0, Lhm/d;

    .line 340
    .line 341
    invoke-direct {v0, p0, v3}, Lhm/d;-><init>(Lh6/j;Lhm/g;)V

    .line 342
    .line 343
    .line 344
    return-object v0

    .line 345
    :cond_7
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 346
    .line 347
    const-string v0, "maxSize <= 0"

    .line 348
    .line 349
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 350
    .line 351
    .line 352
    throw p0

    .line 353
    :cond_8
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 354
    .line 355
    const-string v0, "percent must be in the range [0.0, 1.0]."

    .line 356
    .line 357
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 358
    .line 359
    .line 360
    throw p0

    .line 361
    :pswitch_8
    iget-object p0, p0, Ly1/i;->e:Ljava/lang/Object;

    .line 362
    .line 363
    check-cast p0, Llx0/l;

    .line 364
    .line 365
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 366
    .line 367
    .line 368
    move-result-object p0

    .line 369
    return-object p0

    .line 370
    :pswitch_9
    iget-object p0, p0, Ly1/i;->e:Ljava/lang/Object;

    .line 371
    .line 372
    check-cast p0, Lye/f;

    .line 373
    .line 374
    sget-object v0, Lye/c;->a:Lye/c;

    .line 375
    .line 376
    invoke-virtual {p0, v0}, Lye/f;->a(Lye/d;)V

    .line 377
    .line 378
    .line 379
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 380
    .line 381
    return-object p0

    .line 382
    :pswitch_a
    iget-object p0, p0, Ly1/i;->e:Ljava/lang/Object;

    .line 383
    .line 384
    check-cast p0, Lyd/u;

    .line 385
    .line 386
    sget-object v0, Lyd/d;->a:Lyd/d;

    .line 387
    .line 388
    invoke-virtual {p0, v0}, Lyd/u;->a(Lyd/k;)V

    .line 389
    .line 390
    .line 391
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 392
    .line 393
    return-object p0

    .line 394
    :pswitch_b
    iget-object p0, p0, Ly1/i;->e:Ljava/lang/Object;

    .line 395
    .line 396
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;

    .line 397
    .line 398
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;)Llx0/b0;

    .line 399
    .line 400
    .line 401
    move-result-object p0

    .line 402
    return-object p0

    .line 403
    :pswitch_c
    iget-object p0, p0, Ly1/i;->e:Ljava/lang/Object;

    .line 404
    .line 405
    check-cast p0, Ly70/y1;

    .line 406
    .line 407
    new-instance v0, Llj0/a;

    .line 408
    .line 409
    iget-object p0, p0, Ly70/y1;->i:Lij0/a;

    .line 410
    .line 411
    const v1, 0x7f120374

    .line 412
    .line 413
    .line 414
    check-cast p0, Ljj0/f;

    .line 415
    .line 416
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 417
    .line 418
    .line 419
    move-result-object p0

    .line 420
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 421
    .line 422
    .line 423
    return-object v0

    .line 424
    :pswitch_d
    iget-object p0, p0, Ly1/i;->e:Ljava/lang/Object;

    .line 425
    .line 426
    check-cast p0, Ly70/f;

    .line 427
    .line 428
    new-instance v0, Llj0/a;

    .line 429
    .line 430
    iget-object p0, p0, Ly70/f;->m:Lij0/a;

    .line 431
    .line 432
    const v1, 0x7f120374

    .line 433
    .line 434
    .line 435
    check-cast p0, Ljj0/f;

    .line 436
    .line 437
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 438
    .line 439
    .line 440
    move-result-object p0

    .line 441
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 442
    .line 443
    .line 444
    return-object v0

    .line 445
    :pswitch_e
    iget-object p0, p0, Ly1/i;->e:Ljava/lang/Object;

    .line 446
    .line 447
    check-cast p0, Lx20/c;

    .line 448
    .line 449
    return-object p0

    .line 450
    :pswitch_f
    iget-object p0, p0, Ly1/i;->e:Ljava/lang/Object;

    .line 451
    .line 452
    check-cast p0, Landroid/app/RemoteAction;

    .line 453
    .line 454
    invoke-virtual {p0}, Landroid/app/RemoteAction;->getActionIntent()Landroid/app/PendingIntent;

    .line 455
    .line 456
    .line 457
    move-result-object p0

    .line 458
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 459
    .line 460
    const/16 v1, 0x22

    .line 461
    .line 462
    if-lt v0, v1, :cond_9

    .line 463
    .line 464
    :try_start_2
    invoke-static {}, Landroid/app/ActivityOptions;->makeBasic()Landroid/app/ActivityOptions;

    .line 465
    .line 466
    .line 467
    move-result-object v0

    .line 468
    invoke-static {v0}, Lt51/b;->b(Landroid/app/ActivityOptions;)Landroid/app/ActivityOptions;

    .line 469
    .line 470
    .line 471
    move-result-object v0

    .line 472
    invoke-virtual {v0}, Landroid/app/ActivityOptions;->toBundle()Landroid/os/Bundle;

    .line 473
    .line 474
    .line 475
    move-result-object v0

    .line 476
    invoke-static {p0, v0}, Lt51/b;->p(Landroid/app/PendingIntent;Landroid/os/Bundle;)V
    :try_end_2
    .catch Landroid/app/PendingIntent$CanceledException; {:try_start_2 .. :try_end_2} :catch_2

    .line 477
    .line 478
    .line 479
    goto :goto_3

    .line 480
    :catch_2
    move-exception v0

    .line 481
    new-instance v1, Ljava/lang/StringBuilder;

    .line 482
    .line 483
    const-string v2, "error sending pendingIntent: "

    .line 484
    .line 485
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 486
    .line 487
    .line 488
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 489
    .line 490
    .line 491
    const-string p0, " error: "

    .line 492
    .line 493
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 494
    .line 495
    .line 496
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 497
    .line 498
    .line 499
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 500
    .line 501
    .line 502
    move-result-object p0

    .line 503
    const-string v0, "TextClassification"

    .line 504
    .line 505
    invoke-static {v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 506
    .line 507
    .line 508
    goto :goto_3

    .line 509
    :cond_9
    invoke-virtual {p0}, Landroid/app/PendingIntent;->send()V

    .line 510
    .line 511
    .line 512
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 513
    .line 514
    return-object p0

    .line 515
    :pswitch_10
    iget-object p0, p0, Ly1/i;->e:Ljava/lang/Object;

    .line 516
    .line 517
    check-cast p0, Lw1/g;

    .line 518
    .line 519
    invoke-interface {p0}, Lw1/g;->close()V

    .line 520
    .line 521
    .line 522
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 523
    .line 524
    return-object p0

    .line 525
    :pswitch_data_0
    .packed-switch 0x0
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
