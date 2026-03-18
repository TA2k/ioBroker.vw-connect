.class public final Lfd0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Landroid/content/pm/PackageManager;

.field public final b:Lzc0/b;

.field public c:Le/c;

.field public d:Ljava/lang/String;

.field public final e:Llx0/q;


# direct methods
.method public constructor <init>(Landroid/content/pm/PackageManager;Lzc0/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lfd0/b;->a:Landroid/content/pm/PackageManager;

    .line 5
    .line 6
    iput-object p2, p0, Lfd0/b;->b:Lzc0/b;

    .line 7
    .line 8
    new-instance p1, Ld2/g;

    .line 9
    .line 10
    const/16 p2, 0xc

    .line 11
    .line 12
    invoke-direct {p1, p0, p2}, Ld2/g;-><init>(Ljava/lang/Object;I)V

    .line 13
    .line 14
    .line 15
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    iput-object p1, p0, Lfd0/b;->e:Llx0/q;

    .line 20
    .line 21
    return-void
.end method

.method public static final a(Lfd0/b;Lcz/skodaauto/myskoda/app/main/system/MainActivity;Lzc0/d;)V
    .locals 10

    .line 1
    iget-object v0, p0, Lfd0/b;->a:Landroid/content/pm/PackageManager;

    .line 2
    .line 3
    iget-boolean v1, p2, Lzc0/d;->e:Z

    .line 4
    .line 5
    const-string v2, "android.intent.action.VIEW"

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    if-eqz v1, :cond_2

    .line 9
    .line 10
    new-instance p1, Landroid/content/Intent;

    .line 11
    .line 12
    invoke-direct {p1, v2}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p1, v0}, Landroid/content/Intent;->resolveActivity(Landroid/content/pm/PackageManager;)Landroid/content/ComponentName;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    move-object p1, v3

    .line 23
    :goto_0
    if-eqz p1, :cond_1

    .line 24
    .line 25
    goto/16 :goto_b

    .line 26
    .line 27
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 28
    .line 29
    const-string p1, "Unable to determine browser package."

    .line 30
    .line 31
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw p0

    .line 35
    :cond_2
    iget-object v1, p0, Lfd0/b;->d:Ljava/lang/String;

    .line 36
    .line 37
    const/4 v4, 0x2

    .line 38
    const/4 v5, 0x0

    .line 39
    const/4 v6, 0x1

    .line 40
    if-nez v1, :cond_12

    .line 41
    .line 42
    new-instance v1, Landroid/content/Intent;

    .line 43
    .line 44
    invoke-direct {v1}, Landroid/content/Intent;-><init>()V

    .line 45
    .line 46
    .line 47
    invoke-virtual {v1, v2}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    const-string v2, "android.intent.category.BROWSABLE"

    .line 52
    .line 53
    invoke-virtual {v1, v2}, Landroid/content/Intent;->addCategory(Ljava/lang/String;)Landroid/content/Intent;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    const-string v2, "http"

    .line 58
    .line 59
    const-string v7, ""

    .line 60
    .line 61
    invoke-static {v2, v7, v3}, Landroid/net/Uri;->fromParts(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/net/Uri;

    .line 62
    .line 63
    .line 64
    move-result-object v2

    .line 65
    invoke-virtual {v1, v2}, Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    const-string v2, "setData(...)"

    .line 70
    .line 71
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    invoke-static {v0, v1, v5}, Lkp/x7;->b(Landroid/content/pm/PackageManager;Landroid/content/Intent;I)Ljava/util/List;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    check-cast v2, Ljava/lang/Iterable;

    .line 79
    .line 80
    new-instance v7, Ljava/util/ArrayList;

    .line 81
    .line 82
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 83
    .line 84
    .line 85
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 86
    .line 87
    .line 88
    move-result-object v2

    .line 89
    :cond_3
    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 90
    .line 91
    .line 92
    move-result v8

    .line 93
    if-eqz v8, :cond_4

    .line 94
    .line 95
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v8

    .line 99
    move-object v9, v8

    .line 100
    check-cast v9, Landroid/content/pm/ResolveInfo;

    .line 101
    .line 102
    invoke-virtual {p0, v9}, Lfd0/b;->b(Landroid/content/pm/ResolveInfo;)Z

    .line 103
    .line 104
    .line 105
    move-result v9

    .line 106
    if-eqz v9, :cond_3

    .line 107
    .line 108
    invoke-virtual {v7, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    goto :goto_1

    .line 112
    :cond_4
    new-instance v2, Ljava/util/ArrayList;

    .line 113
    .line 114
    const/16 v8, 0xa

    .line 115
    .line 116
    invoke-static {v7, v8}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 117
    .line 118
    .line 119
    move-result v9

    .line 120
    invoke-direct {v2, v9}, Ljava/util/ArrayList;-><init>(I)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {v7}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 124
    .line 125
    .line 126
    move-result-object v7

    .line 127
    :goto_2
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 128
    .line 129
    .line 130
    move-result v9

    .line 131
    if-eqz v9, :cond_5

    .line 132
    .line 133
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object v9

    .line 137
    check-cast v9, Landroid/content/pm/ResolveInfo;

    .line 138
    .line 139
    iget-object v9, v9, Landroid/content/pm/ResolveInfo;->activityInfo:Landroid/content/pm/ActivityInfo;

    .line 140
    .line 141
    iget-object v9, v9, Landroid/content/pm/ActivityInfo;->packageName:Ljava/lang/String;

    .line 142
    .line 143
    invoke-virtual {v2, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 144
    .line 145
    .line 146
    goto :goto_2

    .line 147
    :cond_5
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 148
    .line 149
    .line 150
    move-result v7

    .line 151
    if-eqz v7, :cond_8

    .line 152
    .line 153
    const/high16 v2, 0x20000

    .line 154
    .line 155
    invoke-static {v0, v1, v2}, Lkp/x7;->b(Landroid/content/pm/PackageManager;Landroid/content/Intent;I)Ljava/util/List;

    .line 156
    .line 157
    .line 158
    move-result-object v0

    .line 159
    check-cast v0, Ljava/lang/Iterable;

    .line 160
    .line 161
    new-instance v1, Ljava/util/ArrayList;

    .line 162
    .line 163
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 164
    .line 165
    .line 166
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 167
    .line 168
    .line 169
    move-result-object v0

    .line 170
    :cond_6
    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 171
    .line 172
    .line 173
    move-result v2

    .line 174
    if-eqz v2, :cond_7

    .line 175
    .line 176
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object v2

    .line 180
    move-object v7, v2

    .line 181
    check-cast v7, Landroid/content/pm/ResolveInfo;

    .line 182
    .line 183
    invoke-virtual {p0, v7}, Lfd0/b;->b(Landroid/content/pm/ResolveInfo;)Z

    .line 184
    .line 185
    .line 186
    move-result v7

    .line 187
    if-eqz v7, :cond_6

    .line 188
    .line 189
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 190
    .line 191
    .line 192
    goto :goto_3

    .line 193
    :cond_7
    new-instance v2, Ljava/util/ArrayList;

    .line 194
    .line 195
    invoke-static {v1, v8}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 196
    .line 197
    .line 198
    move-result v0

    .line 199
    invoke-direct {v2, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 200
    .line 201
    .line 202
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 203
    .line 204
    .line 205
    move-result-object v0

    .line 206
    :goto_4
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 207
    .line 208
    .line 209
    move-result v1

    .line 210
    if-eqz v1, :cond_8

    .line 211
    .line 212
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object v1

    .line 216
    check-cast v1, Landroid/content/pm/ResolveInfo;

    .line 217
    .line 218
    iget-object v1, v1, Landroid/content/pm/ResolveInfo;->activityInfo:Landroid/content/pm/ActivityInfo;

    .line 219
    .line 220
    iget-object v1, v1, Landroid/content/pm/ActivityInfo;->packageName:Ljava/lang/String;

    .line 221
    .line 222
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 223
    .line 224
    .line 225
    goto :goto_4

    .line 226
    :cond_8
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 227
    .line 228
    .line 229
    move-result v0

    .line 230
    if-ne v0, v6, :cond_9

    .line 231
    .line 232
    invoke-static {v2}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    move-result-object v0

    .line 236
    check-cast v0, Ljava/lang/String;

    .line 237
    .line 238
    :goto_5
    move-object v1, v0

    .line 239
    goto/16 :goto_9

    .line 240
    .line 241
    :cond_9
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 242
    .line 243
    .line 244
    move-result v0

    .line 245
    if-le v0, v6, :cond_11

    .line 246
    .line 247
    new-instance v0, Ljava/util/ArrayList;

    .line 248
    .line 249
    invoke-static {v2, v8}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 250
    .line 251
    .line 252
    move-result v1

    .line 253
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 254
    .line 255
    .line 256
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 257
    .line 258
    .line 259
    move-result-object v1

    .line 260
    :goto_6
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 261
    .line 262
    .line 263
    move-result v2

    .line 264
    if-eqz v2, :cond_10

    .line 265
    .line 266
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 267
    .line 268
    .line 269
    move-result-object v2

    .line 270
    check-cast v2, Ljava/lang/String;

    .line 271
    .line 272
    const-string v7, "packageName"

    .line 273
    .line 274
    invoke-static {v2, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 275
    .line 276
    .line 277
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 278
    .line 279
    .line 280
    move-result v7

    .line 281
    const v8, 0xf493ae6

    .line 282
    .line 283
    .line 284
    if-eq v7, v8, :cond_e

    .line 285
    .line 286
    const v8, 0x263106eb

    .line 287
    .line 288
    .line 289
    if-eq v7, v8, :cond_c

    .line 290
    .line 291
    const v8, 0x3b8380d1

    .line 292
    .line 293
    .line 294
    if-eq v7, v8, :cond_a

    .line 295
    .line 296
    goto :goto_7

    .line 297
    :cond_a
    const-string v7, "org.mozilla.firefox"

    .line 298
    .line 299
    invoke-virtual {v2, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 300
    .line 301
    .line 302
    move-result v8

    .line 303
    if-nez v8, :cond_b

    .line 304
    .line 305
    goto :goto_7

    .line 306
    :cond_b
    new-instance v2, Lfd0/a;

    .line 307
    .line 308
    invoke-direct {v2, v7, v6}, Lfd0/a;-><init>(Ljava/lang/String;I)V

    .line 309
    .line 310
    .line 311
    goto :goto_8

    .line 312
    :cond_c
    const-string v7, "com.sec.android.app.sbrowser"

    .line 313
    .line 314
    invoke-virtual {v2, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 315
    .line 316
    .line 317
    move-result v8

    .line 318
    if-nez v8, :cond_d

    .line 319
    .line 320
    goto :goto_7

    .line 321
    :cond_d
    new-instance v2, Lfd0/a;

    .line 322
    .line 323
    invoke-direct {v2, v7, v4}, Lfd0/a;-><init>(Ljava/lang/String;I)V

    .line 324
    .line 325
    .line 326
    goto :goto_8

    .line 327
    :cond_e
    const-string v7, "com.android.chrome"

    .line 328
    .line 329
    invoke-virtual {v2, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 330
    .line 331
    .line 332
    move-result v8

    .line 333
    if-eqz v8, :cond_f

    .line 334
    .line 335
    new-instance v2, Lfd0/a;

    .line 336
    .line 337
    const/4 v8, 0x3

    .line 338
    invoke-direct {v2, v7, v8}, Lfd0/a;-><init>(Ljava/lang/String;I)V

    .line 339
    .line 340
    .line 341
    goto :goto_8

    .line 342
    :cond_f
    :goto_7
    new-instance v7, Lfd0/a;

    .line 343
    .line 344
    invoke-direct {v7, v2, v5}, Lfd0/a;-><init>(Ljava/lang/String;I)V

    .line 345
    .line 346
    .line 347
    move-object v2, v7

    .line 348
    :goto_8
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 349
    .line 350
    .line 351
    goto :goto_6

    .line 352
    :cond_10
    new-instance v1, La5/f;

    .line 353
    .line 354
    const/4 v2, 0x7

    .line 355
    invoke-direct {v1, v2}, La5/f;-><init>(I)V

    .line 356
    .line 357
    .line 358
    invoke-static {v0, v1}, Lmx0/q;->p0(Ljava/lang/Iterable;Ljava/util/Comparator;)Ljava/util/List;

    .line 359
    .line 360
    .line 361
    move-result-object v0

    .line 362
    invoke-static {v0}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 363
    .line 364
    .line 365
    move-result-object v0

    .line 366
    check-cast v0, Lfd0/a;

    .line 367
    .line 368
    iget-object v0, v0, Lfd0/a;->a:Ljava/lang/String;

    .line 369
    .line 370
    goto/16 :goto_5

    .line 371
    .line 372
    :cond_11
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 373
    .line 374
    const-string p1, "Unable to determine CustomTabs package."

    .line 375
    .line 376
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 377
    .line 378
    .line 379
    throw p0

    .line 380
    :cond_12
    :goto_9
    iput-object v1, p0, Lfd0/b;->d:Ljava/lang/String;

    .line 381
    .line 382
    if-eqz v1, :cond_18

    .line 383
    .line 384
    new-instance v0, Lvv0/d;

    .line 385
    .line 386
    invoke-direct {v0}, Lvv0/d;-><init>()V

    .line 387
    .line 388
    .line 389
    iget-object v2, v0, Lvv0/d;->b:Ljava/lang/Object;

    .line 390
    .line 391
    check-cast v2, Landroid/content/Intent;

    .line 392
    .line 393
    iget-boolean v7, p2, Lzc0/d;->b:Z

    .line 394
    .line 395
    if-nez v7, :cond_13

    .line 396
    .line 397
    invoke-static {p1, v5, v5}, Landroid/app/ActivityOptions;->makeCustomAnimation(Landroid/content/Context;II)Landroid/app/ActivityOptions;

    .line 398
    .line 399
    .line 400
    move-result-object v7

    .line 401
    invoke-virtual {v7}, Landroid/app/ActivityOptions;->toBundle()Landroid/os/Bundle;

    .line 402
    .line 403
    .line 404
    move-result-object v7

    .line 405
    const-string v8, "android.support.customtabs.extra.EXIT_ANIMATION_BUNDLE"

    .line 406
    .line 407
    invoke-virtual {v2, v8, v7}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Bundle;)Landroid/content/Intent;

    .line 408
    .line 409
    .line 410
    :cond_13
    iget-boolean v7, p2, Lzc0/d;->c:Z

    .line 411
    .line 412
    if-nez v7, :cond_14

    .line 413
    .line 414
    invoke-static {p1, v5, v5}, Landroid/app/ActivityOptions;->makeCustomAnimation(Landroid/content/Context;II)Landroid/app/ActivityOptions;

    .line 415
    .line 416
    .line 417
    move-result-object p1

    .line 418
    iput-object p1, v0, Lvv0/d;->d:Ljava/lang/Object;

    .line 419
    .line 420
    :cond_14
    sget p1, Lh/n;->e:I

    .line 421
    .line 422
    if-eq p1, v6, :cond_15

    .line 423
    .line 424
    if-eq p1, v4, :cond_16

    .line 425
    .line 426
    move v4, v5

    .line 427
    goto :goto_a

    .line 428
    :cond_15
    move v4, v6

    .line 429
    :cond_16
    :goto_a
    const-string p1, "androidx.browser.customtabs.extra.COLOR_SCHEME"

    .line 430
    .line 431
    invoke-virtual {v2, p1, v4}, Landroid/content/Intent;->putExtra(Ljava/lang/String;I)Landroid/content/Intent;

    .line 432
    .line 433
    .line 434
    invoke-virtual {v0}, Lvv0/d;->c()Lc2/k;

    .line 435
    .line 436
    .line 437
    move-result-object p1

    .line 438
    iget-object p1, p1, Lc2/k;->e:Ljava/lang/Object;

    .line 439
    .line 440
    check-cast p1, Landroid/content/Intent;

    .line 441
    .line 442
    const-string v0, "intent"

    .line 443
    .line 444
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 445
    .line 446
    .line 447
    invoke-virtual {p1, v1}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;

    .line 448
    .line 449
    .line 450
    :goto_b
    iget-object p2, p2, Lzc0/d;->a:Ljava/net/URL;

    .line 451
    .line 452
    invoke-virtual {p2}, Ljava/net/URL;->toExternalForm()Ljava/lang/String;

    .line 453
    .line 454
    .line 455
    move-result-object p2

    .line 456
    const-string v0, "toExternalForm(...)"

    .line 457
    .line 458
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 459
    .line 460
    .line 461
    invoke-static {p2}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 462
    .line 463
    .line 464
    move-result-object p2

    .line 465
    invoke-virtual {p1, p2}, Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;

    .line 466
    .line 467
    .line 468
    iget-object p0, p0, Lfd0/b;->c:Le/c;

    .line 469
    .line 470
    if-eqz p0, :cond_17

    .line 471
    .line 472
    invoke-virtual {p0, p1}, Le/c;->a(Ljava/lang/Object;)V

    .line 473
    .line 474
    .line 475
    return-void

    .line 476
    :cond_17
    const-string p0, "resultLauncher"

    .line 477
    .line 478
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 479
    .line 480
    .line 481
    throw v3

    .line 482
    :cond_18
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 483
    .line 484
    const-string p1, "Required value was null."

    .line 485
    .line 486
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 487
    .line 488
    .line 489
    throw p0
.end method


# virtual methods
.method public final b(Landroid/content/pm/ResolveInfo;)Z
    .locals 5

    .line 1
    new-instance v0, Landroid/content/Intent;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/content/Intent;-><init>()V

    .line 4
    .line 5
    .line 6
    const-string v1, "android.support.customtabs.action.CustomTabsService"

    .line 7
    .line 8
    invoke-virtual {v0, v1}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    .line 9
    .line 10
    .line 11
    iget-object p1, p1, Landroid/content/pm/ResolveInfo;->activityInfo:Landroid/content/pm/ActivityInfo;

    .line 12
    .line 13
    iget-object p1, p1, Landroid/content/pm/ActivityInfo;->packageName:Ljava/lang/String;

    .line 14
    .line 15
    invoke-virtual {v0, p1}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;

    .line 16
    .line 17
    .line 18
    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 19
    .line 20
    const/16 v1, 0x21

    .line 21
    .line 22
    iget-object p0, p0, Lfd0/b;->a:Landroid/content/pm/PackageManager;

    .line 23
    .line 24
    const/4 v2, 0x0

    .line 25
    if-lt p1, v1, :cond_0

    .line 26
    .line 27
    int-to-long v3, v2

    .line 28
    invoke-static {v3, v4}, Lb/s;->c(J)Landroid/content/pm/PackageManager$ResolveInfoFlags;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    invoke-static {p0, v0, p1}, Lb/s;->d(Landroid/content/pm/PackageManager;Landroid/content/Intent;Landroid/content/pm/PackageManager$ResolveInfoFlags;)Landroid/content/pm/ResolveInfo;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    invoke-virtual {p0, v0, v2}, Landroid/content/pm/PackageManager;->resolveService(Landroid/content/Intent;I)Landroid/content/pm/ResolveInfo;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    :goto_0
    if-eqz p0, :cond_1

    .line 42
    .line 43
    const/4 p0, 0x1

    .line 44
    return p0

    .line 45
    :cond_1
    return v2
.end method
