.class public final Ldm/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ldm/g;


# instance fields
.field public final synthetic a:I

.field public final b:Lyl/t;

.field public final c:Lmm/n;


# direct methods
.method public synthetic constructor <init>(Lyl/t;Lmm/n;I)V
    .locals 0

    .line 1
    iput p3, p0, Ldm/b;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Ldm/b;->b:Lyl/t;

    .line 4
    .line 5
    iput-object p2, p0, Ldm/b;->c:Lmm/n;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget p1, p0, Ldm/b;->a:I

    .line 2
    .line 3
    const-string v0, "toLowerCase(...)"

    .line 4
    .line 5
    const/16 v1, 0x2e

    .line 6
    .line 7
    const/16 v2, 0x1c

    .line 8
    .line 9
    const/4 v3, -0x1

    .line 10
    const/4 v4, 0x6

    .line 11
    const-string v5, "substring(...)"

    .line 12
    .line 13
    const-string v6, ""

    .line 14
    .line 15
    const/4 v7, 0x2

    .line 16
    const/4 v8, 0x0

    .line 17
    const/4 v9, 0x0

    .line 18
    const/4 v10, 0x1

    .line 19
    iget-object v11, p0, Ldm/b;->b:Lyl/t;

    .line 20
    .line 21
    iget-object p0, p0, Ldm/b;->c:Lmm/n;

    .line 22
    .line 23
    packed-switch p1, :pswitch_data_0

    .line 24
    .line 25
    .line 26
    iget-object p1, v11, Lyl/t;->d:Ljava/lang/String;

    .line 27
    .line 28
    const-string v0, "Invalid android.resource URI: "

    .line 29
    .line 30
    if-eqz p1, :cond_d

    .line 31
    .line 32
    invoke-static {p1}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    if-nez v1, :cond_0

    .line 37
    .line 38
    move-object v9, p1

    .line 39
    :cond_0
    if-eqz v9, :cond_d

    .line 40
    .line 41
    invoke-static {v11}, Lyl/m;->g(Lyl/t;)Ljava/util/List;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    invoke-static {p1}, Lmx0/q;->U(Ljava/util/List;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    check-cast p1, Ljava/lang/String;

    .line 50
    .line 51
    if-eqz p1, :cond_c

    .line 52
    .line 53
    invoke-static {p1}, Lly0/w;->y(Ljava/lang/String;)Ljava/lang/Integer;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    if-eqz p1, :cond_c

    .line 58
    .line 59
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 60
    .line 61
    .line 62
    move-result p1

    .line 63
    iget-object v0, p0, Lmm/n;->a:Landroid/content/Context;

    .line 64
    .line 65
    invoke-virtual {v0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    invoke-virtual {v9, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result v1

    .line 73
    if-eqz v1, :cond_1

    .line 74
    .line 75
    invoke-virtual {v0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    goto :goto_0

    .line 80
    :cond_1
    invoke-virtual {v0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 81
    .line 82
    .line 83
    move-result-object v1

    .line 84
    invoke-virtual {v1, v9}, Landroid/content/pm/PackageManager;->getResourcesForApplication(Ljava/lang/String;)Landroid/content/res/Resources;

    .line 85
    .line 86
    .line 87
    move-result-object v1

    .line 88
    :goto_0
    new-instance v2, Landroid/util/TypedValue;

    .line 89
    .line 90
    invoke-direct {v2}, Landroid/util/TypedValue;-><init>()V

    .line 91
    .line 92
    .line 93
    invoke-virtual {v1, p1, v2, v10}, Landroid/content/res/Resources;->getValue(ILandroid/util/TypedValue;Z)V

    .line 94
    .line 95
    .line 96
    iget-object v2, v2, Landroid/util/TypedValue;->string:Ljava/lang/CharSequence;

    .line 97
    .line 98
    invoke-virtual {v2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object v2

    .line 102
    invoke-static {v2}, Lkp/j8;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object v2

    .line 106
    const-string v3, "text/xml"

    .line 107
    .line 108
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    move-result v3

    .line 112
    if-eqz v3, :cond_b

    .line 113
    .line 114
    invoke-virtual {v0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v2

    .line 118
    invoke-virtual {v9, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 119
    .line 120
    .line 121
    move-result v2

    .line 122
    const-string v3, "Invalid resource ID: "

    .line 123
    .line 124
    if-eqz v2, :cond_3

    .line 125
    .line 126
    invoke-static {v0, p1}, Llp/g1;->b(Landroid/content/Context;I)Landroid/graphics/drawable/Drawable;

    .line 127
    .line 128
    .line 129
    move-result-object v1

    .line 130
    if-eqz v1, :cond_2

    .line 131
    .line 132
    goto :goto_2

    .line 133
    :cond_2
    invoke-static {p1, v3}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 138
    .line 139
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 144
    .line 145
    .line 146
    throw p1

    .line 147
    :cond_3
    invoke-virtual {v1, p1}, Landroid/content/res/Resources;->getXml(I)Landroid/content/res/XmlResourceParser;

    .line 148
    .line 149
    .line 150
    move-result-object v2

    .line 151
    invoke-interface {v2}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    .line 152
    .line 153
    .line 154
    move-result v4

    .line 155
    :goto_1
    if-eq v4, v7, :cond_4

    .line 156
    .line 157
    if-eq v4, v10, :cond_4

    .line 158
    .line 159
    invoke-interface {v2}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    .line 160
    .line 161
    .line 162
    move-result v4

    .line 163
    goto :goto_1

    .line 164
    :cond_4
    if-ne v4, v7, :cond_a

    .line 165
    .line 166
    invoke-virtual {v0}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 167
    .line 168
    .line 169
    move-result-object v2

    .line 170
    sget-object v4, Lp5/j;->a:Ljava/lang/ThreadLocal;

    .line 171
    .line 172
    invoke-virtual {v1, p1, v2}, Landroid/content/res/Resources;->getDrawable(ILandroid/content/res/Resources$Theme;)Landroid/graphics/drawable/Drawable;

    .line 173
    .line 174
    .line 175
    move-result-object v1

    .line 176
    if-eqz v1, :cond_9

    .line 177
    .line 178
    :goto_2
    sget-object p1, Lsm/i;->a:[Landroid/graphics/Bitmap$Config;

    .line 179
    .line 180
    instance-of p1, v1, Landroid/graphics/drawable/VectorDrawable;

    .line 181
    .line 182
    if-nez p1, :cond_6

    .line 183
    .line 184
    instance-of p1, v1, Lcb/p;

    .line 185
    .line 186
    if-eqz p1, :cond_5

    .line 187
    .line 188
    goto :goto_3

    .line 189
    :cond_5
    move p1, v8

    .line 190
    goto :goto_4

    .line 191
    :cond_6
    :goto_3
    move p1, v10

    .line 192
    :goto_4
    new-instance v2, Ldm/h;

    .line 193
    .line 194
    if-eqz p1, :cond_8

    .line 195
    .line 196
    sget-object v3, Lmm/i;->b:Ld8/c;

    .line 197
    .line 198
    invoke-static {p0, v3}, Lyl/m;->e(Lmm/n;Ld8/c;)Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v3

    .line 202
    check-cast v3, Landroid/graphics/Bitmap$Config;

    .line 203
    .line 204
    iget-object v4, p0, Lmm/n;->b:Lnm/h;

    .line 205
    .line 206
    iget-object v5, p0, Lmm/n;->c:Lnm/g;

    .line 207
    .line 208
    iget-object p0, p0, Lmm/n;->d:Lnm/d;

    .line 209
    .line 210
    sget-object v6, Lnm/d;->e:Lnm/d;

    .line 211
    .line 212
    if-ne p0, v6, :cond_7

    .line 213
    .line 214
    move v8, v10

    .line 215
    :cond_7
    invoke-static {v1, v3, v4, v5, v8}, Lsm/b;->a(Landroid/graphics/drawable/Drawable;Landroid/graphics/Bitmap$Config;Lnm/h;Lnm/g;Z)Landroid/graphics/Bitmap;

    .line 216
    .line 217
    .line 218
    move-result-object p0

    .line 219
    invoke-virtual {v0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 220
    .line 221
    .line 222
    move-result-object v0

    .line 223
    new-instance v1, Landroid/graphics/drawable/BitmapDrawable;

    .line 224
    .line 225
    invoke-direct {v1, v0, p0}, Landroid/graphics/drawable/BitmapDrawable;-><init>(Landroid/content/res/Resources;Landroid/graphics/Bitmap;)V

    .line 226
    .line 227
    .line 228
    :cond_8
    invoke-static {v1}, Lyl/m;->c(Landroid/graphics/drawable/Drawable;)Lyl/j;

    .line 229
    .line 230
    .line 231
    move-result-object p0

    .line 232
    sget-object v0, Lbm/h;->f:Lbm/h;

    .line 233
    .line 234
    invoke-direct {v2, p0, p1, v0}, Ldm/h;-><init>(Lyl/j;ZLbm/h;)V

    .line 235
    .line 236
    .line 237
    goto :goto_5

    .line 238
    :cond_9
    invoke-static {p1, v3}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 239
    .line 240
    .line 241
    move-result-object p0

    .line 242
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 243
    .line 244
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 245
    .line 246
    .line 247
    move-result-object p0

    .line 248
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 249
    .line 250
    .line 251
    throw p1

    .line 252
    :cond_a
    new-instance p0, Lorg/xmlpull/v1/XmlPullParserException;

    .line 253
    .line 254
    const-string p1, "No start tag found."

    .line 255
    .line 256
    invoke-direct {p0, p1}, Lorg/xmlpull/v1/XmlPullParserException;-><init>(Ljava/lang/String;)V

    .line 257
    .line 258
    .line 259
    throw p0

    .line 260
    :cond_b
    new-instance v0, Landroid/util/TypedValue;

    .line 261
    .line 262
    invoke-direct {v0}, Landroid/util/TypedValue;-><init>()V

    .line 263
    .line 264
    .line 265
    invoke-virtual {v1, p1, v0}, Landroid/content/res/Resources;->openRawResource(ILandroid/util/TypedValue;)Ljava/io/InputStream;

    .line 266
    .line 267
    .line 268
    move-result-object v0

    .line 269
    new-instance v1, Ldm/i;

    .line 270
    .line 271
    invoke-static {v0}, Lu01/b;->g(Ljava/io/InputStream;)Lu01/s;

    .line 272
    .line 273
    .line 274
    move-result-object v0

    .line 275
    invoke-static {v0}, Lu01/b;->c(Lu01/h0;)Lu01/b0;

    .line 276
    .line 277
    .line 278
    move-result-object v0

    .line 279
    iget-object p0, p0, Lmm/n;->f:Lu01/k;

    .line 280
    .line 281
    new-instance v3, Lbm/r;

    .line 282
    .line 283
    invoke-direct {v3, v9, p1}, Lbm/r;-><init>(Ljava/lang/String;I)V

    .line 284
    .line 285
    .line 286
    new-instance p1, Lbm/s;

    .line 287
    .line 288
    invoke-direct {p1, v0, p0, v3}, Lbm/s;-><init>(Lu01/h;Lu01/k;Ljp/ua;)V

    .line 289
    .line 290
    .line 291
    sget-object p0, Lbm/h;->f:Lbm/h;

    .line 292
    .line 293
    invoke-direct {v1, p1, v2, p0}, Ldm/i;-><init>(Lbm/q;Ljava/lang/String;Lbm/h;)V

    .line 294
    .line 295
    .line 296
    move-object v2, v1

    .line 297
    :goto_5
    return-object v2

    .line 298
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 299
    .line 300
    new-instance p1, Ljava/lang/StringBuilder;

    .line 301
    .line 302
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 303
    .line 304
    .line 305
    invoke-virtual {p1, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 306
    .line 307
    .line 308
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 309
    .line 310
    .line 311
    move-result-object p1

    .line 312
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 313
    .line 314
    .line 315
    throw p0

    .line 316
    :cond_d
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 317
    .line 318
    new-instance p1, Ljava/lang/StringBuilder;

    .line 319
    .line 320
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 321
    .line 322
    .line 323
    invoke-virtual {p1, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 324
    .line 325
    .line 326
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 327
    .line 328
    .line 329
    move-result-object p1

    .line 330
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 331
    .line 332
    .line 333
    throw p0

    .line 334
    :pswitch_0
    iget-object p1, v11, Lyl/t;->e:Ljava/lang/String;

    .line 335
    .line 336
    if-nez p1, :cond_e

    .line 337
    .line 338
    move-object p1, v6

    .line 339
    :cond_e
    const/16 v7, 0x21

    .line 340
    .line 341
    invoke-static {p1, v7, v8, v4}, Lly0/p;->J(Ljava/lang/CharSequence;CII)I

    .line 342
    .line 343
    .line 344
    move-result v4

    .line 345
    if-eq v4, v3, :cond_11

    .line 346
    .line 347
    sget-object v3, Lu01/y;->e:Ljava/lang/String;

    .line 348
    .line 349
    invoke-virtual {p1, v8, v4}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 350
    .line 351
    .line 352
    move-result-object v3

    .line 353
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 354
    .line 355
    .line 356
    invoke-static {v3}, Lrb0/a;->a(Ljava/lang/String;)Lu01/y;

    .line 357
    .line 358
    .line 359
    move-result-object v3

    .line 360
    add-int/2addr v4, v10

    .line 361
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 362
    .line 363
    .line 364
    move-result v7

    .line 365
    invoke-virtual {p1, v4, v7}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 366
    .line 367
    .line 368
    move-result-object p1

    .line 369
    invoke-static {p1, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 370
    .line 371
    .line 372
    invoke-static {p1}, Lrb0/a;->a(Ljava/lang/String;)Lu01/y;

    .line 373
    .line 374
    .line 375
    move-result-object p1

    .line 376
    new-instance v4, Ldm/i;

    .line 377
    .line 378
    iget-object p0, p0, Lmm/n;->f:Lu01/k;

    .line 379
    .line 380
    const-string v5, "<this>"

    .line 381
    .line 382
    invoke-static {p0, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 383
    .line 384
    .line 385
    new-instance v5, Luu/r;

    .line 386
    .line 387
    const/16 v7, 0x16

    .line 388
    .line 389
    invoke-direct {v5, v7}, Luu/r;-><init>(I)V

    .line 390
    .line 391
    .line 392
    invoke-static {v3, p0, v5}, Lv01/b;->e(Lu01/y;Lu01/k;Lay0/k;)Lu01/k0;

    .line 393
    .line 394
    .line 395
    move-result-object p0

    .line 396
    invoke-static {p1, p0, v9, v9, v2}, Ljp/va;->a(Lu01/y;Lu01/k;Ljava/lang/String;Lcm/f;I)Lbm/p;

    .line 397
    .line 398
    .line 399
    move-result-object p0

    .line 400
    invoke-virtual {p1}, Lu01/y;->b()Ljava/lang/String;

    .line 401
    .line 402
    .line 403
    move-result-object p1

    .line 404
    invoke-static {v1, p1, v6}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 405
    .line 406
    .line 407
    move-result-object p1

    .line 408
    invoke-static {p1}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 409
    .line 410
    .line 411
    move-result v1

    .line 412
    if-eqz v1, :cond_f

    .line 413
    .line 414
    goto :goto_6

    .line 415
    :cond_f
    sget-object v1, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 416
    .line 417
    invoke-virtual {p1, v1}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 418
    .line 419
    .line 420
    move-result-object p1

    .line 421
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 422
    .line 423
    .line 424
    sget-object v0, Lsm/f;->a:Lnx0/f;

    .line 425
    .line 426
    invoke-virtual {v0, p1}, Lnx0/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 427
    .line 428
    .line 429
    move-result-object v0

    .line 430
    move-object v9, v0

    .line 431
    check-cast v9, Ljava/lang/String;

    .line 432
    .line 433
    if-nez v9, :cond_10

    .line 434
    .line 435
    invoke-static {}, Landroid/webkit/MimeTypeMap;->getSingleton()Landroid/webkit/MimeTypeMap;

    .line 436
    .line 437
    .line 438
    move-result-object v0

    .line 439
    invoke-virtual {v0, p1}, Landroid/webkit/MimeTypeMap;->getMimeTypeFromExtension(Ljava/lang/String;)Ljava/lang/String;

    .line 440
    .line 441
    .line 442
    move-result-object v9

    .line 443
    :cond_10
    :goto_6
    sget-object p1, Lbm/h;->f:Lbm/h;

    .line 444
    .line 445
    invoke-direct {v4, p0, v9, p1}, Ldm/i;-><init>(Lbm/q;Ljava/lang/String;Lbm/h;)V

    .line 446
    .line 447
    .line 448
    return-object v4

    .line 449
    :cond_11
    new-instance p0, Ljava/lang/StringBuilder;

    .line 450
    .line 451
    const-string p1, "Invalid jar:file URI: "

    .line 452
    .line 453
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 454
    .line 455
    .line 456
    invoke-virtual {p0, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 457
    .line 458
    .line 459
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 460
    .line 461
    .line 462
    move-result-object p0

    .line 463
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 464
    .line 465
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 466
    .line 467
    .line 468
    move-result-object p0

    .line 469
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 470
    .line 471
    .line 472
    throw p1

    .line 473
    :pswitch_1
    sget-object p1, Lu01/y;->e:Ljava/lang/String;

    .line 474
    .line 475
    invoke-static {v11}, Lyl/m;->f(Lyl/t;)Ljava/lang/String;

    .line 476
    .line 477
    .line 478
    move-result-object p1

    .line 479
    if-eqz p1, :cond_14

    .line 480
    .line 481
    invoke-static {p1}, Lrb0/a;->a(Ljava/lang/String;)Lu01/y;

    .line 482
    .line 483
    .line 484
    move-result-object p1

    .line 485
    new-instance v3, Ldm/i;

    .line 486
    .line 487
    iget-object p0, p0, Lmm/n;->f:Lu01/k;

    .line 488
    .line 489
    invoke-static {p1, p0, v9, v9, v2}, Ljp/va;->a(Lu01/y;Lu01/k;Ljava/lang/String;Lcm/f;I)Lbm/p;

    .line 490
    .line 491
    .line 492
    move-result-object p0

    .line 493
    invoke-virtual {p1}, Lu01/y;->b()Ljava/lang/String;

    .line 494
    .line 495
    .line 496
    move-result-object p1

    .line 497
    invoke-static {v1, p1, v6}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 498
    .line 499
    .line 500
    move-result-object p1

    .line 501
    invoke-static {p1}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 502
    .line 503
    .line 504
    move-result v1

    .line 505
    if-eqz v1, :cond_12

    .line 506
    .line 507
    goto :goto_7

    .line 508
    :cond_12
    sget-object v1, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 509
    .line 510
    invoke-virtual {p1, v1}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 511
    .line 512
    .line 513
    move-result-object p1

    .line 514
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 515
    .line 516
    .line 517
    sget-object v0, Lsm/f;->a:Lnx0/f;

    .line 518
    .line 519
    invoke-virtual {v0, p1}, Lnx0/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 520
    .line 521
    .line 522
    move-result-object v0

    .line 523
    move-object v9, v0

    .line 524
    check-cast v9, Ljava/lang/String;

    .line 525
    .line 526
    if-nez v9, :cond_13

    .line 527
    .line 528
    invoke-static {}, Landroid/webkit/MimeTypeMap;->getSingleton()Landroid/webkit/MimeTypeMap;

    .line 529
    .line 530
    .line 531
    move-result-object v0

    .line 532
    invoke-virtual {v0, p1}, Landroid/webkit/MimeTypeMap;->getMimeTypeFromExtension(Ljava/lang/String;)Ljava/lang/String;

    .line 533
    .line 534
    .line 535
    move-result-object v9

    .line 536
    :cond_13
    :goto_7
    sget-object p1, Lbm/h;->f:Lbm/h;

    .line 537
    .line 538
    invoke-direct {v3, p0, v9, p1}, Ldm/i;-><init>(Lbm/q;Ljava/lang/String;Lbm/h;)V

    .line 539
    .line 540
    .line 541
    return-object v3

    .line 542
    :cond_14
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 543
    .line 544
    const-string p1, "filePath == null"

    .line 545
    .line 546
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 547
    .line 548
    .line 549
    throw p0

    .line 550
    :pswitch_2
    iget-object p1, v11, Lyl/t;->a:Ljava/lang/String;

    .line 551
    .line 552
    iget-object v0, v11, Lyl/t;->a:Ljava/lang/String;

    .line 553
    .line 554
    const-string v1, ";base64,"

    .line 555
    .line 556
    invoke-static {p1, v1, v8, v8, v4}, Lly0/p;->K(Ljava/lang/CharSequence;Ljava/lang/String;IZI)I

    .line 557
    .line 558
    .line 559
    move-result p1

    .line 560
    const-string v1, "invalid data uri: "

    .line 561
    .line 562
    if-eq p1, v3, :cond_16

    .line 563
    .line 564
    const/16 v2, 0x3a

    .line 565
    .line 566
    invoke-static {v0, v2, v8, v4}, Lly0/p;->J(Ljava/lang/CharSequence;CII)I

    .line 567
    .line 568
    .line 569
    move-result v2

    .line 570
    if-eq v2, v3, :cond_15

    .line 571
    .line 572
    add-int/2addr v2, v10

    .line 573
    invoke-virtual {v0, v2, p1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 574
    .line 575
    .line 576
    move-result-object v1

    .line 577
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 578
    .line 579
    .line 580
    sget-object v2, Lxx0/c;->e:Lxx0/a;

    .line 581
    .line 582
    add-int/lit8 p1, p1, 0x8

    .line 583
    .line 584
    const/4 v3, 0x4

    .line 585
    invoke-static {v2, v0, p1, v3}, Lxx0/c;->a(Lxx0/c;Ljava/lang/CharSequence;II)[B

    .line 586
    .line 587
    .line 588
    move-result-object p1

    .line 589
    new-instance v0, Lu01/f;

    .line 590
    .line 591
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 592
    .line 593
    .line 594
    invoke-virtual {v0, p1}, Lu01/f;->write([B)V

    .line 595
    .line 596
    .line 597
    iget-object p0, p0, Lmm/n;->f:Lu01/k;

    .line 598
    .line 599
    new-instance p1, Lbm/s;

    .line 600
    .line 601
    invoke-direct {p1, v0, p0, v9}, Lbm/s;-><init>(Lu01/h;Lu01/k;Ljp/ua;)V

    .line 602
    .line 603
    .line 604
    sget-object p0, Lbm/h;->e:Lbm/h;

    .line 605
    .line 606
    new-instance v0, Ldm/i;

    .line 607
    .line 608
    invoke-direct {v0, p1, v1, p0}, Ldm/i;-><init>(Lbm/q;Ljava/lang/String;Lbm/h;)V

    .line 609
    .line 610
    .line 611
    return-object v0

    .line 612
    :cond_15
    new-instance p0, Ljava/lang/StringBuilder;

    .line 613
    .line 614
    invoke-direct {p0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 615
    .line 616
    .line 617
    invoke-virtual {p0, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 618
    .line 619
    .line 620
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 621
    .line 622
    .line 623
    move-result-object p0

    .line 624
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 625
    .line 626
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 627
    .line 628
    .line 629
    move-result-object p0

    .line 630
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 631
    .line 632
    .line 633
    throw p1

    .line 634
    :cond_16
    new-instance p0, Ljava/lang/StringBuilder;

    .line 635
    .line 636
    invoke-direct {p0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 637
    .line 638
    .line 639
    invoke-virtual {p0, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 640
    .line 641
    .line 642
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 643
    .line 644
    .line 645
    move-result-object p0

    .line 646
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 647
    .line 648
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 649
    .line 650
    .line 651
    move-result-object p0

    .line 652
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 653
    .line 654
    .line 655
    throw p1

    .line 656
    :pswitch_3
    iget-object p1, v11, Lyl/t;->a:Ljava/lang/String;

    .line 657
    .line 658
    invoke-static {p1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 659
    .line 660
    .line 661
    move-result-object p1

    .line 662
    iget-object v0, p0, Lmm/n;->a:Landroid/content/Context;

    .line 663
    .line 664
    invoke-virtual {v0}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    .line 665
    .line 666
    .line 667
    move-result-object v0

    .line 668
    iget-object v1, v11, Lyl/t;->d:Ljava/lang/String;

    .line 669
    .line 670
    const-string v2, "com.android.contacts"

    .line 671
    .line 672
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 673
    .line 674
    .line 675
    move-result v2

    .line 676
    const-string v3, "r"

    .line 677
    .line 678
    const-string v4, "\'."

    .line 679
    .line 680
    if-eqz v2, :cond_18

    .line 681
    .line 682
    invoke-static {v11}, Lyl/m;->g(Lyl/t;)Ljava/util/List;

    .line 683
    .line 684
    .line 685
    move-result-object v2

    .line 686
    invoke-static {v2}, Lmx0/q;->U(Ljava/util/List;)Ljava/lang/Object;

    .line 687
    .line 688
    .line 689
    move-result-object v2

    .line 690
    const-string v5, "display_photo"

    .line 691
    .line 692
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 693
    .line 694
    .line 695
    move-result v2

    .line 696
    if-eqz v2, :cond_18

    .line 697
    .line 698
    invoke-virtual {v0, p1, v3}, Landroid/content/ContentResolver;->openAssetFileDescriptor(Landroid/net/Uri;Ljava/lang/String;)Landroid/content/res/AssetFileDescriptor;

    .line 699
    .line 700
    .line 701
    move-result-object v1

    .line 702
    if-eqz v1, :cond_17

    .line 703
    .line 704
    goto/16 :goto_c

    .line 705
    .line 706
    :cond_17
    new-instance p0, Ljava/lang/StringBuilder;

    .line 707
    .line 708
    const-string v0, "Unable to find a contact photo associated with \'"

    .line 709
    .line 710
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 711
    .line 712
    .line 713
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 714
    .line 715
    .line 716
    invoke-virtual {p0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 717
    .line 718
    .line 719
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 720
    .line 721
    .line 722
    move-result-object p0

    .line 723
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 724
    .line 725
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 726
    .line 727
    .line 728
    move-result-object p0

    .line 729
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 730
    .line 731
    .line 732
    throw p1

    .line 733
    :cond_18
    const-string v2, "media"

    .line 734
    .line 735
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 736
    .line 737
    .line 738
    move-result v1

    .line 739
    if-nez v1, :cond_19

    .line 740
    .line 741
    goto/16 :goto_b

    .line 742
    .line 743
    :cond_19
    invoke-static {v11}, Lyl/m;->g(Lyl/t;)Ljava/util/List;

    .line 744
    .line 745
    .line 746
    move-result-object v1

    .line 747
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 748
    .line 749
    .line 750
    move-result v2

    .line 751
    const/4 v5, 0x3

    .line 752
    if-lt v2, v5, :cond_1e

    .line 753
    .line 754
    add-int/lit8 v5, v2, -0x3

    .line 755
    .line 756
    invoke-interface {v1, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 757
    .line 758
    .line 759
    move-result-object v5

    .line 760
    const-string v6, "audio"

    .line 761
    .line 762
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 763
    .line 764
    .line 765
    move-result v5

    .line 766
    if-eqz v5, :cond_1e

    .line 767
    .line 768
    sub-int/2addr v2, v7

    .line 769
    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 770
    .line 771
    .line 772
    move-result-object v1

    .line 773
    const-string v2, "albums"

    .line 774
    .line 775
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 776
    .line 777
    .line 778
    move-result v1

    .line 779
    if-eqz v1, :cond_1e

    .line 780
    .line 781
    iget-object v1, p0, Lmm/n;->b:Lnm/h;

    .line 782
    .line 783
    iget-object v2, v1, Lnm/h;->a:Lnm/c;

    .line 784
    .line 785
    instance-of v3, v2, Lnm/a;

    .line 786
    .line 787
    if-eqz v3, :cond_1a

    .line 788
    .line 789
    check-cast v2, Lnm/a;

    .line 790
    .line 791
    goto :goto_8

    .line 792
    :cond_1a
    move-object v2, v9

    .line 793
    :goto_8
    if-eqz v2, :cond_1c

    .line 794
    .line 795
    iget v2, v2, Lnm/a;->a:I

    .line 796
    .line 797
    iget-object v1, v1, Lnm/h;->b:Lnm/c;

    .line 798
    .line 799
    instance-of v3, v1, Lnm/a;

    .line 800
    .line 801
    if-eqz v3, :cond_1b

    .line 802
    .line 803
    check-cast v1, Lnm/a;

    .line 804
    .line 805
    goto :goto_9

    .line 806
    :cond_1b
    move-object v1, v9

    .line 807
    :goto_9
    if-eqz v1, :cond_1c

    .line 808
    .line 809
    iget v1, v1, Lnm/a;->a:I

    .line 810
    .line 811
    new-instance v3, Landroid/os/Bundle;

    .line 812
    .line 813
    invoke-direct {v3, v10}, Landroid/os/Bundle;-><init>(I)V

    .line 814
    .line 815
    .line 816
    new-instance v5, Landroid/graphics/Point;

    .line 817
    .line 818
    invoke-direct {v5, v2, v1}, Landroid/graphics/Point;-><init>(II)V

    .line 819
    .line 820
    .line 821
    const-string v1, "android.content.extra.SIZE"

    .line 822
    .line 823
    invoke-virtual {v3, v1, v5}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 824
    .line 825
    .line 826
    goto :goto_a

    .line 827
    :cond_1c
    move-object v3, v9

    .line 828
    :goto_a
    const-string v1, "image/*"

    .line 829
    .line 830
    invoke-virtual {v0, p1, v1, v3, v9}, Landroid/content/ContentResolver;->openTypedAssetFile(Landroid/net/Uri;Ljava/lang/String;Landroid/os/Bundle;Landroid/os/CancellationSignal;)Landroid/content/res/AssetFileDescriptor;

    .line 831
    .line 832
    .line 833
    move-result-object v1

    .line 834
    if-eqz v1, :cond_1d

    .line 835
    .line 836
    goto :goto_c

    .line 837
    :cond_1d
    new-instance p0, Ljava/lang/StringBuilder;

    .line 838
    .line 839
    const-string v0, "Unable to find a music thumbnail associated with \'"

    .line 840
    .line 841
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 842
    .line 843
    .line 844
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 845
    .line 846
    .line 847
    invoke-virtual {p0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 848
    .line 849
    .line 850
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 851
    .line 852
    .line 853
    move-result-object p0

    .line 854
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 855
    .line 856
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 857
    .line 858
    .line 859
    move-result-object p0

    .line 860
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 861
    .line 862
    .line 863
    throw p1

    .line 864
    :cond_1e
    :goto_b
    invoke-virtual {v0, p1, v3}, Landroid/content/ContentResolver;->openAssetFileDescriptor(Landroid/net/Uri;Ljava/lang/String;)Landroid/content/res/AssetFileDescriptor;

    .line 865
    .line 866
    .line 867
    move-result-object v1

    .line 868
    if-eqz v1, :cond_1f

    .line 869
    .line 870
    :goto_c
    new-instance v2, Ldm/i;

    .line 871
    .line 872
    invoke-virtual {v1}, Landroid/content/res/AssetFileDescriptor;->createInputStream()Ljava/io/FileInputStream;

    .line 873
    .line 874
    .line 875
    move-result-object v3

    .line 876
    invoke-static {v3}, Lu01/b;->g(Ljava/io/InputStream;)Lu01/s;

    .line 877
    .line 878
    .line 879
    move-result-object v3

    .line 880
    invoke-static {v3}, Lu01/b;->c(Lu01/h0;)Lu01/b0;

    .line 881
    .line 882
    .line 883
    move-result-object v3

    .line 884
    iget-object p0, p0, Lmm/n;->f:Lu01/k;

    .line 885
    .line 886
    new-instance v4, Lbm/g;

    .line 887
    .line 888
    invoke-direct {v4, v1}, Lbm/g;-><init>(Landroid/content/res/AssetFileDescriptor;)V

    .line 889
    .line 890
    .line 891
    new-instance v1, Lbm/s;

    .line 892
    .line 893
    invoke-direct {v1, v3, p0, v4}, Lbm/s;-><init>(Lu01/h;Lu01/k;Ljp/ua;)V

    .line 894
    .line 895
    .line 896
    invoke-virtual {v0, p1}, Landroid/content/ContentResolver;->getType(Landroid/net/Uri;)Ljava/lang/String;

    .line 897
    .line 898
    .line 899
    move-result-object p0

    .line 900
    sget-object p1, Lbm/h;->f:Lbm/h;

    .line 901
    .line 902
    invoke-direct {v2, v1, p0, p1}, Ldm/i;-><init>(Lbm/q;Ljava/lang/String;Lbm/h;)V

    .line 903
    .line 904
    .line 905
    return-object v2

    .line 906
    :cond_1f
    new-instance p0, Ljava/lang/StringBuilder;

    .line 907
    .line 908
    const-string v0, "Unable to open \'"

    .line 909
    .line 910
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 911
    .line 912
    .line 913
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 914
    .line 915
    .line 916
    invoke-virtual {p0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 917
    .line 918
    .line 919
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 920
    .line 921
    .line 922
    move-result-object p0

    .line 923
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 924
    .line 925
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 926
    .line 927
    .line 928
    move-result-object p0

    .line 929
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 930
    .line 931
    .line 932
    throw p1

    .line 933
    :pswitch_4
    invoke-static {v11}, Lyl/m;->g(Lyl/t;)Ljava/util/List;

    .line 934
    .line 935
    .line 936
    move-result-object p1

    .line 937
    check-cast p1, Ljava/lang/Iterable;

    .line 938
    .line 939
    invoke-static {p1, v10}, Lmx0/q;->D(Ljava/lang/Iterable;I)Ljava/util/List;

    .line 940
    .line 941
    .line 942
    move-result-object p1

    .line 943
    move-object v0, p1

    .line 944
    check-cast v0, Ljava/lang/Iterable;

    .line 945
    .line 946
    const/4 v4, 0x0

    .line 947
    const/16 v5, 0x3e

    .line 948
    .line 949
    const-string v1, "/"

    .line 950
    .line 951
    const/4 v2, 0x0

    .line 952
    const/4 v3, 0x0

    .line 953
    invoke-static/range {v0 .. v5}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 954
    .line 955
    .line 956
    move-result-object p1

    .line 957
    new-instance v0, Ldm/i;

    .line 958
    .line 959
    iget-object v1, p0, Lmm/n;->a:Landroid/content/Context;

    .line 960
    .line 961
    invoke-virtual {v1}, Landroid/content/Context;->getAssets()Landroid/content/res/AssetManager;

    .line 962
    .line 963
    .line 964
    move-result-object v1

    .line 965
    invoke-virtual {v1, p1}, Landroid/content/res/AssetManager;->open(Ljava/lang/String;)Ljava/io/InputStream;

    .line 966
    .line 967
    .line 968
    move-result-object v1

    .line 969
    invoke-static {v1}, Lu01/b;->g(Ljava/io/InputStream;)Lu01/s;

    .line 970
    .line 971
    .line 972
    move-result-object v1

    .line 973
    invoke-static {v1}, Lu01/b;->c(Lu01/h0;)Lu01/b0;

    .line 974
    .line 975
    .line 976
    move-result-object v1

    .line 977
    iget-object p0, p0, Lmm/n;->f:Lu01/k;

    .line 978
    .line 979
    new-instance v2, Lbm/a;

    .line 980
    .line 981
    invoke-direct {v2, p1}, Lbm/a;-><init>(Ljava/lang/String;)V

    .line 982
    .line 983
    .line 984
    new-instance v3, Lbm/s;

    .line 985
    .line 986
    invoke-direct {v3, v1, p0, v2}, Lbm/s;-><init>(Lu01/h;Lu01/k;Ljp/ua;)V

    .line 987
    .line 988
    .line 989
    invoke-static {p1}, Lkp/j8;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 990
    .line 991
    .line 992
    move-result-object p0

    .line 993
    sget-object p1, Lbm/h;->f:Lbm/h;

    .line 994
    .line 995
    invoke-direct {v0, v3, p0, p1}, Ldm/i;-><init>(Lbm/q;Ljava/lang/String;Lbm/h;)V

    .line 996
    .line 997
    .line 998
    return-object v0

    .line 999
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
