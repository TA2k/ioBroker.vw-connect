.class public final Lw3/x0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lw3/w0;
.implements Lpx0/f;
.implements Lk4/k;


# static fields
.field public static final e:Lw3/x0;

.field public static final f:Lw3/x0;

.field public static final synthetic g:Lw3/x0;

.field public static final h:Lw3/l2;


# instance fields
.field public final synthetic d:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lw3/x0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lw3/x0;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lw3/x0;->e:Lw3/x0;

    .line 8
    .line 9
    new-instance v0, Lw3/x0;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Lw3/x0;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lw3/x0;->f:Lw3/x0;

    .line 16
    .line 17
    new-instance v0, Lw3/x0;

    .line 18
    .line 19
    const/4 v1, 0x2

    .line 20
    invoke-direct {v0, v1}, Lw3/x0;-><init>(I)V

    .line 21
    .line 22
    .line 23
    sput-object v0, Lw3/x0;->g:Lw3/x0;

    .line 24
    .line 25
    new-instance v0, Lw3/l2;

    .line 26
    .line 27
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 28
    .line 29
    .line 30
    sput-object v0, Lw3/x0;->h:Lw3/l2;

    .line 31
    .line 32
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lw3/x0;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public a(Landroid/app/Activity;)Landroid/graphics/Rect;
    .locals 9

    .line 1
    iget p0, p0, Lw3/x0;->d:I

    .line 2
    .line 3
    const-string v0, "null cannot be cast to non-null type android.graphics.Rect"

    .line 4
    .line 5
    const-string v1, "getBounds"

    .line 6
    .line 7
    const/4 v2, 0x1

    .line 8
    const-string v3, "windowConfiguration"

    .line 9
    .line 10
    const-class v4, Landroid/content/res/Configuration;

    .line 11
    .line 12
    const/4 v5, 0x0

    .line 13
    packed-switch p0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-virtual {p0}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    :try_start_0
    invoke-virtual {v4, v3}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    invoke-virtual {v3, v2}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {v3, p0}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    invoke-virtual {v2, v1, v5}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    new-instance v2, Landroid/graphics/Rect;

    .line 44
    .line 45
    invoke-virtual {v1, p0, v5}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    check-cast p0, Landroid/graphics/Rect;

    .line 53
    .line 54
    invoke-direct {v2, p0}, Landroid/graphics/Rect;-><init>(Landroid/graphics/Rect;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 55
    .line 56
    .line 57
    goto :goto_1

    .line 58
    :catch_0
    move-exception p0

    .line 59
    instance-of v0, p0, Ljava/lang/NoSuchFieldException;

    .line 60
    .line 61
    if-nez v0, :cond_1

    .line 62
    .line 63
    instance-of v0, p0, Ljava/lang/NoSuchMethodException;

    .line 64
    .line 65
    if-nez v0, :cond_1

    .line 66
    .line 67
    instance-of v0, p0, Ljava/lang/IllegalAccessException;

    .line 68
    .line 69
    if-nez v0, :cond_1

    .line 70
    .line 71
    instance-of v0, p0, Ljava/lang/reflect/InvocationTargetException;

    .line 72
    .line 73
    if-eqz v0, :cond_0

    .line 74
    .line 75
    goto :goto_0

    .line 76
    :cond_0
    throw p0

    .line 77
    :cond_1
    :goto_0
    sget-object p0, Lw3/x0;->e:Lw3/x0;

    .line 78
    .line 79
    invoke-virtual {p0, p1}, Lw3/x0;->a(Landroid/app/Activity;)Landroid/graphics/Rect;

    .line 80
    .line 81
    .line 82
    move-result-object v2

    .line 83
    :goto_1
    return-object v2

    .line 84
    :pswitch_0
    new-instance p0, Landroid/graphics/Rect;

    .line 85
    .line 86
    invoke-direct {p0}, Landroid/graphics/Rect;-><init>()V

    .line 87
    .line 88
    .line 89
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 90
    .line 91
    .line 92
    move-result-object v6

    .line 93
    invoke-virtual {v6}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 94
    .line 95
    .line 96
    move-result-object v6

    .line 97
    :try_start_1
    invoke-virtual {v4, v3}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 98
    .line 99
    .line 100
    move-result-object v3

    .line 101
    invoke-virtual {v3, v2}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {v3, v6}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v3

    .line 108
    invoke-virtual {p1}, Landroid/app/Activity;->isInMultiWindowMode()Z

    .line 109
    .line 110
    .line 111
    move-result v4

    .line 112
    if-eqz v4, :cond_2

    .line 113
    .line 114
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 115
    .line 116
    .line 117
    move-result-object v4

    .line 118
    invoke-virtual {v4, v1, v5}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 119
    .line 120
    .line 121
    move-result-object v1

    .line 122
    invoke-virtual {v1, v3, v5}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object v1

    .line 126
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 127
    .line 128
    .line 129
    check-cast v1, Landroid/graphics/Rect;

    .line 130
    .line 131
    invoke-virtual {p0, v1}, Landroid/graphics/Rect;->set(Landroid/graphics/Rect;)V

    .line 132
    .line 133
    .line 134
    goto :goto_4

    .line 135
    :catch_1
    move-exception v0

    .line 136
    goto :goto_2

    .line 137
    :cond_2
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 138
    .line 139
    .line 140
    move-result-object v1

    .line 141
    const-string v4, "getAppBounds"

    .line 142
    .line 143
    invoke-virtual {v1, v4, v5}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 144
    .line 145
    .line 146
    move-result-object v1

    .line 147
    invoke-virtual {v1, v3, v5}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object v1

    .line 151
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 152
    .line 153
    .line 154
    check-cast v1, Landroid/graphics/Rect;

    .line 155
    .line 156
    invoke-virtual {p0, v1}, Landroid/graphics/Rect;->set(Landroid/graphics/Rect;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 157
    .line 158
    .line 159
    goto :goto_4

    .line 160
    :goto_2
    instance-of v1, v0, Ljava/lang/NoSuchFieldException;

    .line 161
    .line 162
    if-nez v1, :cond_4

    .line 163
    .line 164
    instance-of v1, v0, Ljava/lang/NoSuchMethodException;

    .line 165
    .line 166
    if-nez v1, :cond_4

    .line 167
    .line 168
    instance-of v1, v0, Ljava/lang/IllegalAccessException;

    .line 169
    .line 170
    if-nez v1, :cond_4

    .line 171
    .line 172
    instance-of v1, v0, Ljava/lang/reflect/InvocationTargetException;

    .line 173
    .line 174
    if-eqz v1, :cond_3

    .line 175
    .line 176
    goto :goto_3

    .line 177
    :cond_3
    throw v0

    .line 178
    :cond_4
    :goto_3
    invoke-virtual {p1}, Landroid/app/Activity;->getWindowManager()Landroid/view/WindowManager;

    .line 179
    .line 180
    .line 181
    move-result-object v0

    .line 182
    invoke-interface {v0}, Landroid/view/WindowManager;->getDefaultDisplay()Landroid/view/Display;

    .line 183
    .line 184
    .line 185
    move-result-object v0

    .line 186
    invoke-virtual {v0, p0}, Landroid/view/Display;->getRectSize(Landroid/graphics/Rect;)V

    .line 187
    .line 188
    .line 189
    :goto_4
    invoke-virtual {p1}, Landroid/app/Activity;->getWindowManager()Landroid/view/WindowManager;

    .line 190
    .line 191
    .line 192
    move-result-object v0

    .line 193
    invoke-interface {v0}, Landroid/view/WindowManager;->getDefaultDisplay()Landroid/view/Display;

    .line 194
    .line 195
    .line 196
    move-result-object v0

    .line 197
    new-instance v1, Landroid/graphics/Point;

    .line 198
    .line 199
    invoke-direct {v1}, Landroid/graphics/Point;-><init>()V

    .line 200
    .line 201
    .line 202
    invoke-virtual {v0, v1}, Landroid/view/Display;->getRealSize(Landroid/graphics/Point;)V

    .line 203
    .line 204
    .line 205
    invoke-virtual {p1}, Landroid/app/Activity;->isInMultiWindowMode()Z

    .line 206
    .line 207
    .line 208
    move-result v3

    .line 209
    const/4 v4, 0x0

    .line 210
    if-nez v3, :cond_8

    .line 211
    .line 212
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 213
    .line 214
    .line 215
    move-result-object v3

    .line 216
    const-string v6, "dimen"

    .line 217
    .line 218
    const-string v7, "android"

    .line 219
    .line 220
    const-string v8, "navigation_bar_height"

    .line 221
    .line 222
    invoke-virtual {v3, v8, v6, v7}, Landroid/content/res/Resources;->getIdentifier(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I

    .line 223
    .line 224
    .line 225
    move-result v6

    .line 226
    if-lez v6, :cond_5

    .line 227
    .line 228
    invoke-virtual {v3, v6}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    .line 229
    .line 230
    .line 231
    move-result v3

    .line 232
    goto :goto_5

    .line 233
    :cond_5
    move v3, v4

    .line 234
    :goto_5
    iget v6, p0, Landroid/graphics/Rect;->bottom:I

    .line 235
    .line 236
    add-int/2addr v6, v3

    .line 237
    iget v7, v1, Landroid/graphics/Point;->y:I

    .line 238
    .line 239
    if-ne v6, v7, :cond_6

    .line 240
    .line 241
    iput v6, p0, Landroid/graphics/Rect;->bottom:I

    .line 242
    .line 243
    goto :goto_6

    .line 244
    :cond_6
    iget v6, p0, Landroid/graphics/Rect;->right:I

    .line 245
    .line 246
    add-int/2addr v6, v3

    .line 247
    iget v7, v1, Landroid/graphics/Point;->x:I

    .line 248
    .line 249
    if-ne v6, v7, :cond_7

    .line 250
    .line 251
    iput v6, p0, Landroid/graphics/Rect;->right:I

    .line 252
    .line 253
    goto :goto_6

    .line 254
    :cond_7
    iget v6, p0, Landroid/graphics/Rect;->left:I

    .line 255
    .line 256
    if-ne v6, v3, :cond_8

    .line 257
    .line 258
    iput v4, p0, Landroid/graphics/Rect;->left:I

    .line 259
    .line 260
    :cond_8
    :goto_6
    invoke-virtual {p0}, Landroid/graphics/Rect;->width()I

    .line 261
    .line 262
    .line 263
    move-result v3

    .line 264
    iget v6, v1, Landroid/graphics/Point;->x:I

    .line 265
    .line 266
    if-lt v3, v6, :cond_9

    .line 267
    .line 268
    invoke-virtual {p0}, Landroid/graphics/Rect;->height()I

    .line 269
    .line 270
    .line 271
    move-result v3

    .line 272
    iget v6, v1, Landroid/graphics/Point;->y:I

    .line 273
    .line 274
    if-ge v3, v6, :cond_f

    .line 275
    .line 276
    :cond_9
    invoke-virtual {p1}, Landroid/app/Activity;->isInMultiWindowMode()Z

    .line 277
    .line 278
    .line 279
    move-result p1

    .line 280
    if-nez p1, :cond_f

    .line 281
    .line 282
    :try_start_2
    const-string p1, "android.view.DisplayInfo"

    .line 283
    .line 284
    invoke-static {p1}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 285
    .line 286
    .line 287
    move-result-object p1

    .line 288
    invoke-virtual {p1, v5}, Ljava/lang/Class;->getConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 289
    .line 290
    .line 291
    move-result-object p1

    .line 292
    invoke-virtual {p1, v2}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 293
    .line 294
    .line 295
    invoke-virtual {p1, v5}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 296
    .line 297
    .line 298
    move-result-object p1

    .line 299
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 300
    .line 301
    .line 302
    move-result-object v3

    .line 303
    const-string v6, "getDisplayInfo"

    .line 304
    .line 305
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 306
    .line 307
    .line 308
    move-result-object v7

    .line 309
    filled-new-array {v7}, [Ljava/lang/Class;

    .line 310
    .line 311
    .line 312
    move-result-object v7

    .line 313
    invoke-virtual {v3, v6, v7}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 314
    .line 315
    .line 316
    move-result-object v3

    .line 317
    invoke-virtual {v3, v2}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 318
    .line 319
    .line 320
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 321
    .line 322
    .line 323
    move-result-object v6

    .line 324
    invoke-virtual {v3, v0, v6}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 325
    .line 326
    .line 327
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 328
    .line 329
    .line 330
    move-result-object v0

    .line 331
    const-string v3, "displayCutout"

    .line 332
    .line 333
    invoke-virtual {v0, v3}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 334
    .line 335
    .line 336
    move-result-object v0

    .line 337
    invoke-virtual {v0, v2}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 338
    .line 339
    .line 340
    invoke-virtual {v0, p1}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 341
    .line 342
    .line 343
    move-result-object p1

    .line 344
    instance-of v0, p1, Landroid/view/DisplayCutout;

    .line 345
    .line 346
    if-eqz v0, :cond_b

    .line 347
    .line 348
    check-cast p1, Landroid/view/DisplayCutout;
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_2

    .line 349
    .line 350
    move-object v5, p1

    .line 351
    goto :goto_7

    .line 352
    :catch_2
    move-exception p1

    .line 353
    instance-of v0, p1, Ljava/lang/ClassNotFoundException;

    .line 354
    .line 355
    if-nez v0, :cond_b

    .line 356
    .line 357
    instance-of v0, p1, Ljava/lang/NoSuchMethodException;

    .line 358
    .line 359
    if-nez v0, :cond_b

    .line 360
    .line 361
    instance-of v0, p1, Ljava/lang/NoSuchFieldException;

    .line 362
    .line 363
    if-nez v0, :cond_b

    .line 364
    .line 365
    instance-of v0, p1, Ljava/lang/IllegalAccessException;

    .line 366
    .line 367
    if-nez v0, :cond_b

    .line 368
    .line 369
    instance-of v0, p1, Ljava/lang/reflect/InvocationTargetException;

    .line 370
    .line 371
    if-nez v0, :cond_b

    .line 372
    .line 373
    instance-of v0, p1, Ljava/lang/InstantiationException;

    .line 374
    .line 375
    if-eqz v0, :cond_a

    .line 376
    .line 377
    goto :goto_7

    .line 378
    :cond_a
    throw p1

    .line 379
    :cond_b
    :goto_7
    if-eqz v5, :cond_f

    .line 380
    .line 381
    iget p1, p0, Landroid/graphics/Rect;->left:I

    .line 382
    .line 383
    invoke-virtual {v5}, Landroid/view/DisplayCutout;->getSafeInsetLeft()I

    .line 384
    .line 385
    .line 386
    move-result v0

    .line 387
    if-ne p1, v0, :cond_c

    .line 388
    .line 389
    iput v4, p0, Landroid/graphics/Rect;->left:I

    .line 390
    .line 391
    :cond_c
    iget p1, v1, Landroid/graphics/Point;->x:I

    .line 392
    .line 393
    iget v0, p0, Landroid/graphics/Rect;->right:I

    .line 394
    .line 395
    sub-int/2addr p1, v0

    .line 396
    invoke-virtual {v5}, Landroid/view/DisplayCutout;->getSafeInsetRight()I

    .line 397
    .line 398
    .line 399
    move-result v0

    .line 400
    if-ne p1, v0, :cond_d

    .line 401
    .line 402
    iget p1, p0, Landroid/graphics/Rect;->right:I

    .line 403
    .line 404
    invoke-virtual {v5}, Landroid/view/DisplayCutout;->getSafeInsetRight()I

    .line 405
    .line 406
    .line 407
    move-result v0

    .line 408
    add-int/2addr v0, p1

    .line 409
    iput v0, p0, Landroid/graphics/Rect;->right:I

    .line 410
    .line 411
    :cond_d
    iget p1, p0, Landroid/graphics/Rect;->top:I

    .line 412
    .line 413
    invoke-virtual {v5}, Landroid/view/DisplayCutout;->getSafeInsetTop()I

    .line 414
    .line 415
    .line 416
    move-result v0

    .line 417
    if-ne p1, v0, :cond_e

    .line 418
    .line 419
    iput v4, p0, Landroid/graphics/Rect;->top:I

    .line 420
    .line 421
    :cond_e
    iget p1, v1, Landroid/graphics/Point;->y:I

    .line 422
    .line 423
    iget v0, p0, Landroid/graphics/Rect;->bottom:I

    .line 424
    .line 425
    sub-int/2addr p1, v0

    .line 426
    invoke-virtual {v5}, Landroid/view/DisplayCutout;->getSafeInsetBottom()I

    .line 427
    .line 428
    .line 429
    move-result v0

    .line 430
    if-ne p1, v0, :cond_f

    .line 431
    .line 432
    iget p1, p0, Landroid/graphics/Rect;->bottom:I

    .line 433
    .line 434
    invoke-virtual {v5}, Landroid/view/DisplayCutout;->getSafeInsetBottom()I

    .line 435
    .line 436
    .line 437
    move-result v0

    .line 438
    add-int/2addr v0, p1

    .line 439
    iput v0, p0, Landroid/graphics/Rect;->bottom:I

    .line 440
    .line 441
    :cond_f
    return-object p0

    .line 442
    nop

    .line 443
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
