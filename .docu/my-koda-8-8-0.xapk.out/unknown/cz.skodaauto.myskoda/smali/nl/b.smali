.class public final Lnl/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lnl/g;


# instance fields
.field public final synthetic a:I

.field public final b:Landroid/net/Uri;

.field public final c:Ltl/l;


# direct methods
.method public synthetic constructor <init>(Landroid/net/Uri;Ltl/l;I)V
    .locals 0

    .line 1
    iput p3, p0, Lnl/b;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lnl/b;->b:Landroid/net/Uri;

    .line 4
    .line 5
    iput-object p2, p0, Lnl/b;->c:Ltl/l;

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
    .locals 10

    .line 1
    iget p1, p0, Lnl/b;->a:I

    .line 2
    .line 3
    const/4 v0, 0x2

    .line 4
    const/4 v1, 0x0

    .line 5
    iget-object v2, p0, Lnl/b;->b:Landroid/net/Uri;

    .line 6
    .line 7
    iget-object p0, p0, Lnl/b;->c:Ltl/l;

    .line 8
    .line 9
    const/4 v3, 0x1

    .line 10
    packed-switch p1, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    invoke-virtual {v2}, Landroid/net/Uri;->getAuthority()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    const-string v4, "Invalid android.resource URI: "

    .line 18
    .line 19
    if-eqz p1, :cond_c

    .line 20
    .line 21
    invoke-static {p1}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 22
    .line 23
    .line 24
    move-result v5

    .line 25
    if-nez v5, :cond_0

    .line 26
    .line 27
    move-object v1, p1

    .line 28
    :cond_0
    if-eqz v1, :cond_c

    .line 29
    .line 30
    invoke-virtual {v2}, Landroid/net/Uri;->getPathSegments()Ljava/util/List;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    invoke-static {p1}, Lmx0/q;->U(Ljava/util/List;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    check-cast p1, Ljava/lang/String;

    .line 39
    .line 40
    if-eqz p1, :cond_b

    .line 41
    .line 42
    invoke-static {p1}, Lly0/w;->y(Ljava/lang/String;)Ljava/lang/Integer;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    if-eqz p1, :cond_b

    .line 47
    .line 48
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 49
    .line 50
    .line 51
    move-result p1

    .line 52
    iget-object v2, p0, Ltl/l;->a:Landroid/content/Context;

    .line 53
    .line 54
    invoke-virtual {v2}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v4

    .line 58
    invoke-virtual {v1, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    move-result v4

    .line 62
    if-eqz v4, :cond_1

    .line 63
    .line 64
    invoke-virtual {v2}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 65
    .line 66
    .line 67
    move-result-object v4

    .line 68
    goto :goto_0

    .line 69
    :cond_1
    invoke-virtual {v2}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 70
    .line 71
    .line 72
    move-result-object v4

    .line 73
    invoke-virtual {v4, v1}, Landroid/content/pm/PackageManager;->getResourcesForApplication(Ljava/lang/String;)Landroid/content/res/Resources;

    .line 74
    .line 75
    .line 76
    move-result-object v4

    .line 77
    :goto_0
    new-instance v5, Landroid/util/TypedValue;

    .line 78
    .line 79
    invoke-direct {v5}, Landroid/util/TypedValue;-><init>()V

    .line 80
    .line 81
    .line 82
    invoke-virtual {v4, p1, v5, v3}, Landroid/content/res/Resources;->getValue(ILandroid/util/TypedValue;Z)V

    .line 83
    .line 84
    .line 85
    iget-object v5, v5, Landroid/util/TypedValue;->string:Ljava/lang/CharSequence;

    .line 86
    .line 87
    const/16 v6, 0x2f

    .line 88
    .line 89
    const/4 v7, 0x6

    .line 90
    const/4 v8, 0x0

    .line 91
    invoke-static {v5, v6, v8, v7}, Lly0/p;->O(Ljava/lang/CharSequence;CII)I

    .line 92
    .line 93
    .line 94
    move-result v6

    .line 95
    invoke-interface {v5}, Ljava/lang/CharSequence;->length()I

    .line 96
    .line 97
    .line 98
    move-result v7

    .line 99
    invoke-interface {v5, v6, v7}, Ljava/lang/CharSequence;->subSequence(II)Ljava/lang/CharSequence;

    .line 100
    .line 101
    .line 102
    move-result-object v5

    .line 103
    invoke-virtual {v5}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object v5

    .line 107
    invoke-static {}, Landroid/webkit/MimeTypeMap;->getSingleton()Landroid/webkit/MimeTypeMap;

    .line 108
    .line 109
    .line 110
    move-result-object v6

    .line 111
    invoke-static {v6, v5}, Lxl/c;->b(Landroid/webkit/MimeTypeMap;Ljava/lang/String;)Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object v5

    .line 115
    const-string v6, "text/xml"

    .line 116
    .line 117
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    move-result v6

    .line 121
    if-eqz v6, :cond_a

    .line 122
    .line 123
    invoke-virtual {v2}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object v5

    .line 127
    invoke-virtual {v1, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    move-result v1

    .line 131
    const-string v5, "Invalid resource ID: "

    .line 132
    .line 133
    if-eqz v1, :cond_3

    .line 134
    .line 135
    invoke-static {v2, p1}, Llp/g1;->b(Landroid/content/Context;I)Landroid/graphics/drawable/Drawable;

    .line 136
    .line 137
    .line 138
    move-result-object v0

    .line 139
    if-eqz v0, :cond_2

    .line 140
    .line 141
    goto :goto_2

    .line 142
    :cond_2
    invoke-static {p1, v5}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 143
    .line 144
    .line 145
    move-result-object p0

    .line 146
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 147
    .line 148
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    throw p1

    .line 156
    :cond_3
    invoke-virtual {v4, p1}, Landroid/content/res/Resources;->getXml(I)Landroid/content/res/XmlResourceParser;

    .line 157
    .line 158
    .line 159
    move-result-object v1

    .line 160
    invoke-interface {v1}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    .line 161
    .line 162
    .line 163
    move-result v6

    .line 164
    :goto_1
    if-eq v6, v0, :cond_4

    .line 165
    .line 166
    if-eq v6, v3, :cond_4

    .line 167
    .line 168
    invoke-interface {v1}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    .line 169
    .line 170
    .line 171
    move-result v6

    .line 172
    goto :goto_1

    .line 173
    :cond_4
    if-ne v6, v0, :cond_9

    .line 174
    .line 175
    invoke-virtual {v2}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 176
    .line 177
    .line 178
    move-result-object v0

    .line 179
    sget-object v1, Lp5/j;->a:Ljava/lang/ThreadLocal;

    .line 180
    .line 181
    invoke-virtual {v4, p1, v0}, Landroid/content/res/Resources;->getDrawable(ILandroid/content/res/Resources$Theme;)Landroid/graphics/drawable/Drawable;

    .line 182
    .line 183
    .line 184
    move-result-object v0

    .line 185
    if-eqz v0, :cond_8

    .line 186
    .line 187
    :goto_2
    instance-of p1, v0, Landroid/graphics/drawable/VectorDrawable;

    .line 188
    .line 189
    if-nez p1, :cond_6

    .line 190
    .line 191
    instance-of p1, v0, Lcb/p;

    .line 192
    .line 193
    if-eqz p1, :cond_5

    .line 194
    .line 195
    goto :goto_3

    .line 196
    :cond_5
    move v3, v8

    .line 197
    :cond_6
    :goto_3
    new-instance p1, Lnl/d;

    .line 198
    .line 199
    if-eqz v3, :cond_7

    .line 200
    .line 201
    iget-object v1, p0, Ltl/l;->b:Landroid/graphics/Bitmap$Config;

    .line 202
    .line 203
    iget-object v4, p0, Ltl/l;->d:Lul/g;

    .line 204
    .line 205
    iget-object v5, p0, Ltl/l;->e:Lul/f;

    .line 206
    .line 207
    iget-boolean p0, p0, Ltl/l;->f:Z

    .line 208
    .line 209
    invoke-static {v0, v1, v4, v5, p0}, Llp/cf;->a(Landroid/graphics/drawable/Drawable;Landroid/graphics/Bitmap$Config;Lul/g;Lul/f;Z)Landroid/graphics/Bitmap;

    .line 210
    .line 211
    .line 212
    move-result-object p0

    .line 213
    invoke-virtual {v2}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 214
    .line 215
    .line 216
    move-result-object v0

    .line 217
    new-instance v1, Landroid/graphics/drawable/BitmapDrawable;

    .line 218
    .line 219
    invoke-direct {v1, v0, p0}, Landroid/graphics/drawable/BitmapDrawable;-><init>(Landroid/content/res/Resources;Landroid/graphics/Bitmap;)V

    .line 220
    .line 221
    .line 222
    move-object v0, v1

    .line 223
    :cond_7
    sget-object p0, Lkl/e;->f:Lkl/e;

    .line 224
    .line 225
    invoke-direct {p1, v0, v3, p0}, Lnl/d;-><init>(Landroid/graphics/drawable/Drawable;ZLkl/e;)V

    .line 226
    .line 227
    .line 228
    goto :goto_4

    .line 229
    :cond_8
    invoke-static {p1, v5}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 230
    .line 231
    .line 232
    move-result-object p0

    .line 233
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 234
    .line 235
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 236
    .line 237
    .line 238
    move-result-object p0

    .line 239
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 240
    .line 241
    .line 242
    throw p1

    .line 243
    :cond_9
    new-instance p0, Lorg/xmlpull/v1/XmlPullParserException;

    .line 244
    .line 245
    const-string p1, "No start tag found."

    .line 246
    .line 247
    invoke-direct {p0, p1}, Lorg/xmlpull/v1/XmlPullParserException;-><init>(Ljava/lang/String;)V

    .line 248
    .line 249
    .line 250
    throw p0

    .line 251
    :cond_a
    new-instance p0, Landroid/util/TypedValue;

    .line 252
    .line 253
    invoke-direct {p0}, Landroid/util/TypedValue;-><init>()V

    .line 254
    .line 255
    .line 256
    invoke-virtual {v4, p1, p0}, Landroid/content/res/Resources;->openRawResource(ILandroid/util/TypedValue;)Ljava/io/InputStream;

    .line 257
    .line 258
    .line 259
    move-result-object p1

    .line 260
    new-instance v0, Lnl/m;

    .line 261
    .line 262
    invoke-static {p1}, Lu01/b;->g(Ljava/io/InputStream;)Lu01/s;

    .line 263
    .line 264
    .line 265
    move-result-object p1

    .line 266
    invoke-static {p1}, Lu01/b;->c(Lu01/h0;)Lu01/b0;

    .line 267
    .line 268
    .line 269
    move-result-object p1

    .line 270
    new-instance v1, Lkl/n;

    .line 271
    .line 272
    iget p0, p0, Landroid/util/TypedValue;->density:I

    .line 273
    .line 274
    invoke-direct {v1, p0}, Lkl/n;-><init>(I)V

    .line 275
    .line 276
    .line 277
    new-instance p0, Lkl/o;

    .line 278
    .line 279
    new-instance v4, Lkl/m;

    .line 280
    .line 281
    invoke-direct {v4, v2, v3}, Lkl/m;-><init>(Landroid/content/Context;I)V

    .line 282
    .line 283
    .line 284
    invoke-direct {p0, p1, v4, v1}, Lkl/o;-><init>(Lu01/h;Lay0/a;Llp/qd;)V

    .line 285
    .line 286
    .line 287
    sget-object p1, Lkl/e;->f:Lkl/e;

    .line 288
    .line 289
    invoke-direct {v0, p0, v5, p1}, Lnl/m;-><init>(Lkl/l;Ljava/lang/String;Lkl/e;)V

    .line 290
    .line 291
    .line 292
    move-object p1, v0

    .line 293
    :goto_4
    return-object p1

    .line 294
    :cond_b
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 295
    .line 296
    new-instance p1, Ljava/lang/StringBuilder;

    .line 297
    .line 298
    invoke-direct {p1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 299
    .line 300
    .line 301
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 302
    .line 303
    .line 304
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 305
    .line 306
    .line 307
    move-result-object p1

    .line 308
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 309
    .line 310
    .line 311
    throw p0

    .line 312
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 313
    .line 314
    new-instance p1, Ljava/lang/StringBuilder;

    .line 315
    .line 316
    invoke-direct {p1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 317
    .line 318
    .line 319
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 320
    .line 321
    .line 322
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 323
    .line 324
    .line 325
    move-result-object p1

    .line 326
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 327
    .line 328
    .line 329
    throw p0

    .line 330
    :pswitch_0
    iget-object p1, p0, Ltl/l;->a:Landroid/content/Context;

    .line 331
    .line 332
    invoke-virtual {p1}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    .line 333
    .line 334
    .line 335
    move-result-object p1

    .line 336
    invoke-virtual {v2}, Landroid/net/Uri;->getAuthority()Ljava/lang/String;

    .line 337
    .line 338
    .line 339
    move-result-object v4

    .line 340
    const-string v5, "com.android.contacts"

    .line 341
    .line 342
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 343
    .line 344
    .line 345
    move-result v4

    .line 346
    const-string v5, "\'."

    .line 347
    .line 348
    if-eqz v4, :cond_f

    .line 349
    .line 350
    invoke-virtual {v2}, Landroid/net/Uri;->getLastPathSegment()Ljava/lang/String;

    .line 351
    .line 352
    .line 353
    move-result-object v4

    .line 354
    const-string v6, "display_photo"

    .line 355
    .line 356
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 357
    .line 358
    .line 359
    move-result v4

    .line 360
    if-eqz v4, :cond_f

    .line 361
    .line 362
    const-string v0, "r"

    .line 363
    .line 364
    invoke-virtual {p1, v2, v0}, Landroid/content/ContentResolver;->openAssetFileDescriptor(Landroid/net/Uri;Ljava/lang/String;)Landroid/content/res/AssetFileDescriptor;

    .line 365
    .line 366
    .line 367
    move-result-object v0

    .line 368
    if-eqz v0, :cond_d

    .line 369
    .line 370
    invoke-virtual {v0}, Landroid/content/res/AssetFileDescriptor;->createInputStream()Ljava/io/FileInputStream;

    .line 371
    .line 372
    .line 373
    move-result-object v1

    .line 374
    :cond_d
    if-eqz v1, :cond_e

    .line 375
    .line 376
    goto/16 :goto_9

    .line 377
    .line 378
    :cond_e
    new-instance p0, Ljava/lang/StringBuilder;

    .line 379
    .line 380
    const-string p1, "Unable to find a contact photo associated with \'"

    .line 381
    .line 382
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 383
    .line 384
    .line 385
    invoke-virtual {p0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 386
    .line 387
    .line 388
    invoke-virtual {p0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 389
    .line 390
    .line 391
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 392
    .line 393
    .line 394
    move-result-object p0

    .line 395
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 396
    .line 397
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 398
    .line 399
    .line 400
    move-result-object p0

    .line 401
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 402
    .line 403
    .line 404
    throw p1

    .line 405
    :cond_f
    invoke-virtual {v2}, Landroid/net/Uri;->getAuthority()Ljava/lang/String;

    .line 406
    .line 407
    .line 408
    move-result-object v4

    .line 409
    const-string v6, "media"

    .line 410
    .line 411
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 412
    .line 413
    .line 414
    move-result v4

    .line 415
    if-nez v4, :cond_10

    .line 416
    .line 417
    goto/16 :goto_8

    .line 418
    .line 419
    :cond_10
    invoke-virtual {v2}, Landroid/net/Uri;->getPathSegments()Ljava/util/List;

    .line 420
    .line 421
    .line 422
    move-result-object v4

    .line 423
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 424
    .line 425
    .line 426
    move-result v6

    .line 427
    const/4 v7, 0x3

    .line 428
    if-lt v6, v7, :cond_16

    .line 429
    .line 430
    add-int/lit8 v7, v6, -0x3

    .line 431
    .line 432
    invoke-interface {v4, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 433
    .line 434
    .line 435
    move-result-object v7

    .line 436
    const-string v8, "audio"

    .line 437
    .line 438
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 439
    .line 440
    .line 441
    move-result v7

    .line 442
    if-eqz v7, :cond_16

    .line 443
    .line 444
    sub-int/2addr v6, v0

    .line 445
    invoke-interface {v4, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 446
    .line 447
    .line 448
    move-result-object v0

    .line 449
    const-string v4, "albums"

    .line 450
    .line 451
    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 452
    .line 453
    .line 454
    move-result v0

    .line 455
    if-eqz v0, :cond_16

    .line 456
    .line 457
    iget-object v0, p0, Ltl/l;->d:Lul/g;

    .line 458
    .line 459
    iget-object v4, v0, Lul/g;->a:Llp/u1;

    .line 460
    .line 461
    instance-of v6, v4, Lul/a;

    .line 462
    .line 463
    if-eqz v6, :cond_11

    .line 464
    .line 465
    check-cast v4, Lul/a;

    .line 466
    .line 467
    goto :goto_5

    .line 468
    :cond_11
    move-object v4, v1

    .line 469
    :goto_5
    if-eqz v4, :cond_13

    .line 470
    .line 471
    iget v4, v4, Lul/a;->a:I

    .line 472
    .line 473
    iget-object v0, v0, Lul/g;->b:Llp/u1;

    .line 474
    .line 475
    instance-of v6, v0, Lul/a;

    .line 476
    .line 477
    if-eqz v6, :cond_12

    .line 478
    .line 479
    check-cast v0, Lul/a;

    .line 480
    .line 481
    goto :goto_6

    .line 482
    :cond_12
    move-object v0, v1

    .line 483
    :goto_6
    if-eqz v0, :cond_13

    .line 484
    .line 485
    iget v0, v0, Lul/a;->a:I

    .line 486
    .line 487
    new-instance v6, Landroid/os/Bundle;

    .line 488
    .line 489
    invoke-direct {v6, v3}, Landroid/os/Bundle;-><init>(I)V

    .line 490
    .line 491
    .line 492
    new-instance v7, Landroid/graphics/Point;

    .line 493
    .line 494
    invoke-direct {v7, v4, v0}, Landroid/graphics/Point;-><init>(II)V

    .line 495
    .line 496
    .line 497
    const-string v0, "android.content.extra.SIZE"

    .line 498
    .line 499
    invoke-virtual {v6, v0, v7}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 500
    .line 501
    .line 502
    goto :goto_7

    .line 503
    :cond_13
    move-object v6, v1

    .line 504
    :goto_7
    const-string v0, "image/*"

    .line 505
    .line 506
    invoke-virtual {p1, v2, v0, v6, v1}, Landroid/content/ContentResolver;->openTypedAssetFile(Landroid/net/Uri;Ljava/lang/String;Landroid/os/Bundle;Landroid/os/CancellationSignal;)Landroid/content/res/AssetFileDescriptor;

    .line 507
    .line 508
    .line 509
    move-result-object v0

    .line 510
    if-eqz v0, :cond_14

    .line 511
    .line 512
    invoke-virtual {v0}, Landroid/content/res/AssetFileDescriptor;->createInputStream()Ljava/io/FileInputStream;

    .line 513
    .line 514
    .line 515
    move-result-object v1

    .line 516
    :cond_14
    if-eqz v1, :cond_15

    .line 517
    .line 518
    goto :goto_9

    .line 519
    :cond_15
    new-instance p0, Ljava/lang/StringBuilder;

    .line 520
    .line 521
    const-string p1, "Unable to find a music thumbnail associated with \'"

    .line 522
    .line 523
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 524
    .line 525
    .line 526
    invoke-virtual {p0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 527
    .line 528
    .line 529
    invoke-virtual {p0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 530
    .line 531
    .line 532
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 533
    .line 534
    .line 535
    move-result-object p0

    .line 536
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 537
    .line 538
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 539
    .line 540
    .line 541
    move-result-object p0

    .line 542
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 543
    .line 544
    .line 545
    throw p1

    .line 546
    :cond_16
    :goto_8
    invoke-virtual {p1, v2}, Landroid/content/ContentResolver;->openInputStream(Landroid/net/Uri;)Ljava/io/InputStream;

    .line 547
    .line 548
    .line 549
    move-result-object v1

    .line 550
    if-eqz v1, :cond_17

    .line 551
    .line 552
    :goto_9
    new-instance v0, Lnl/m;

    .line 553
    .line 554
    invoke-static {v1}, Lu01/b;->g(Ljava/io/InputStream;)Lu01/s;

    .line 555
    .line 556
    .line 557
    move-result-object v1

    .line 558
    invoke-static {v1}, Lu01/b;->c(Lu01/h0;)Lu01/b0;

    .line 559
    .line 560
    .line 561
    move-result-object v1

    .line 562
    iget-object p0, p0, Ltl/l;->a:Landroid/content/Context;

    .line 563
    .line 564
    new-instance v4, Lkl/a;

    .line 565
    .line 566
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 567
    .line 568
    .line 569
    new-instance v5, Lkl/o;

    .line 570
    .line 571
    new-instance v6, Lkl/m;

    .line 572
    .line 573
    invoke-direct {v6, p0, v3}, Lkl/m;-><init>(Landroid/content/Context;I)V

    .line 574
    .line 575
    .line 576
    invoke-direct {v5, v1, v6, v4}, Lkl/o;-><init>(Lu01/h;Lay0/a;Llp/qd;)V

    .line 577
    .line 578
    .line 579
    invoke-virtual {p1, v2}, Landroid/content/ContentResolver;->getType(Landroid/net/Uri;)Ljava/lang/String;

    .line 580
    .line 581
    .line 582
    move-result-object p0

    .line 583
    sget-object p1, Lkl/e;->f:Lkl/e;

    .line 584
    .line 585
    invoke-direct {v0, v5, p0, p1}, Lnl/m;-><init>(Lkl/l;Ljava/lang/String;Lkl/e;)V

    .line 586
    .line 587
    .line 588
    return-object v0

    .line 589
    :cond_17
    new-instance p0, Ljava/lang/StringBuilder;

    .line 590
    .line 591
    const-string p1, "Unable to open \'"

    .line 592
    .line 593
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 594
    .line 595
    .line 596
    invoke-virtual {p0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 597
    .line 598
    .line 599
    invoke-virtual {p0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 600
    .line 601
    .line 602
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 603
    .line 604
    .line 605
    move-result-object p0

    .line 606
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 607
    .line 608
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 609
    .line 610
    .line 611
    move-result-object p0

    .line 612
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 613
    .line 614
    .line 615
    throw p1

    .line 616
    :pswitch_1
    invoke-virtual {v2}, Landroid/net/Uri;->getPathSegments()Ljava/util/List;

    .line 617
    .line 618
    .line 619
    move-result-object p1

    .line 620
    check-cast p1, Ljava/lang/Iterable;

    .line 621
    .line 622
    invoke-static {p1, v3}, Lmx0/q;->D(Ljava/lang/Iterable;I)Ljava/util/List;

    .line 623
    .line 624
    .line 625
    move-result-object p1

    .line 626
    move-object v4, p1

    .line 627
    check-cast v4, Ljava/lang/Iterable;

    .line 628
    .line 629
    const/4 v8, 0x0

    .line 630
    const/16 v9, 0x3e

    .line 631
    .line 632
    const-string v5, "/"

    .line 633
    .line 634
    const/4 v6, 0x0

    .line 635
    const/4 v7, 0x0

    .line 636
    invoke-static/range {v4 .. v9}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 637
    .line 638
    .line 639
    move-result-object p1

    .line 640
    new-instance v0, Lnl/m;

    .line 641
    .line 642
    iget-object v1, p0, Ltl/l;->a:Landroid/content/Context;

    .line 643
    .line 644
    invoke-virtual {v1}, Landroid/content/Context;->getAssets()Landroid/content/res/AssetManager;

    .line 645
    .line 646
    .line 647
    move-result-object v1

    .line 648
    invoke-virtual {v1, p1}, Landroid/content/res/AssetManager;->open(Ljava/lang/String;)Ljava/io/InputStream;

    .line 649
    .line 650
    .line 651
    move-result-object v1

    .line 652
    invoke-static {v1}, Lu01/b;->g(Ljava/io/InputStream;)Lu01/s;

    .line 653
    .line 654
    .line 655
    move-result-object v1

    .line 656
    invoke-static {v1}, Lu01/b;->c(Lu01/h0;)Lu01/b0;

    .line 657
    .line 658
    .line 659
    move-result-object v1

    .line 660
    iget-object p0, p0, Ltl/l;->a:Landroid/content/Context;

    .line 661
    .line 662
    new-instance v2, Lkl/a;

    .line 663
    .line 664
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 665
    .line 666
    .line 667
    new-instance v4, Lkl/o;

    .line 668
    .line 669
    new-instance v5, Lkl/m;

    .line 670
    .line 671
    invoke-direct {v5, p0, v3}, Lkl/m;-><init>(Landroid/content/Context;I)V

    .line 672
    .line 673
    .line 674
    invoke-direct {v4, v1, v5, v2}, Lkl/o;-><init>(Lu01/h;Lay0/a;Llp/qd;)V

    .line 675
    .line 676
    .line 677
    invoke-static {}, Landroid/webkit/MimeTypeMap;->getSingleton()Landroid/webkit/MimeTypeMap;

    .line 678
    .line 679
    .line 680
    move-result-object p0

    .line 681
    invoke-static {p0, p1}, Lxl/c;->b(Landroid/webkit/MimeTypeMap;Ljava/lang/String;)Ljava/lang/String;

    .line 682
    .line 683
    .line 684
    move-result-object p0

    .line 685
    sget-object p1, Lkl/e;->f:Lkl/e;

    .line 686
    .line 687
    invoke-direct {v0, v4, p0, p1}, Lnl/m;-><init>(Lkl/l;Ljava/lang/String;Lkl/e;)V

    .line 688
    .line 689
    .line 690
    return-object v0

    .line 691
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
