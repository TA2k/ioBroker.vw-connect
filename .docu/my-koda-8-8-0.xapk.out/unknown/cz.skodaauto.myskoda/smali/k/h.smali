.class public final Lk/h;
.super Landroid/view/MenuInflater;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final e:[Ljava/lang/Class;

.field public static final f:[Ljava/lang/Class;


# instance fields
.field public final a:[Ljava/lang/Object;

.field public final b:[Ljava/lang/Object;

.field public final c:Landroid/content/Context;

.field public d:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-class v0, Landroid/content/Context;

    .line 2
    .line 3
    filled-new-array {v0}, [Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lk/h;->e:[Ljava/lang/Class;

    .line 8
    .line 9
    sput-object v0, Lk/h;->f:[Ljava/lang/Class;

    .line 10
    .line 11
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Landroid/view/MenuInflater;-><init>(Landroid/content/Context;)V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk/h;->c:Landroid/content/Context;

    .line 5
    .line 6
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    iput-object p1, p0, Lk/h;->a:[Ljava/lang/Object;

    .line 11
    .line 12
    iput-object p1, p0, Lk/h;->b:[Ljava/lang/Object;

    .line 13
    .line 14
    return-void
.end method

.method public static a(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    instance-of v0, p0, Landroid/app/Activity;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    instance-of v0, p0, Landroid/content/ContextWrapper;

    .line 7
    .line 8
    if-eqz v0, :cond_1

    .line 9
    .line 10
    check-cast p0, Landroid/content/ContextWrapper;

    .line 11
    .line 12
    invoke-virtual {p0}, Landroid/content/ContextWrapper;->getBaseContext()Landroid/content/Context;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    invoke-static {p0}, Lk/h;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    :cond_1
    return-object p0
.end method


# virtual methods
.method public final b(Lorg/xmlpull/v1/XmlPullParser;Landroid/util/AttributeSet;Landroid/view/Menu;)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    new-instance v2, Lk/g;

    .line 6
    .line 7
    move-object/from16 v3, p3

    .line 8
    .line 9
    invoke-direct {v2, v0, v3}, Lk/g;-><init>(Lk/h;Landroid/view/Menu;)V

    .line 10
    .line 11
    .line 12
    invoke-interface/range {p1 .. p1}, Lorg/xmlpull/v1/XmlPullParser;->getEventType()I

    .line 13
    .line 14
    .line 15
    move-result v3

    .line 16
    :goto_0
    const-string v4, "menu"

    .line 17
    .line 18
    const/4 v5, 0x2

    .line 19
    const/4 v6, 0x1

    .line 20
    if-ne v3, v5, :cond_1

    .line 21
    .line 22
    invoke-interface/range {p1 .. p1}, Lorg/xmlpull/v1/XmlPullParser;->getName()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v3

    .line 26
    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v7

    .line 30
    if-eqz v7, :cond_0

    .line 31
    .line 32
    invoke-interface/range {p1 .. p1}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    goto :goto_1

    .line 37
    :cond_0
    new-instance v0, Ljava/lang/RuntimeException;

    .line 38
    .line 39
    const-string v1, "Expecting menu, got "

    .line 40
    .line 41
    invoke-virtual {v1, v3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    invoke-direct {v0, v1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw v0

    .line 49
    :cond_1
    invoke-interface/range {p1 .. p1}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    if-ne v3, v6, :cond_17

    .line 54
    .line 55
    :goto_1
    const/4 v7, 0x0

    .line 56
    move v9, v7

    .line 57
    move v10, v9

    .line 58
    const/4 v11, 0x0

    .line 59
    :goto_2
    if-nez v9, :cond_16

    .line 60
    .line 61
    if-eq v3, v6, :cond_15

    .line 62
    .line 63
    const-string v12, "item"

    .line 64
    .line 65
    const-string v13, "group"

    .line 66
    .line 67
    const/4 v14, 0x3

    .line 68
    if-eq v3, v5, :cond_8

    .line 69
    .line 70
    if-eq v3, v14, :cond_3

    .line 71
    .line 72
    :cond_2
    :goto_3
    move-object/from16 v8, p1

    .line 73
    .line 74
    goto/16 :goto_4

    .line 75
    .line 76
    :cond_3
    invoke-interface/range {p1 .. p1}, Lorg/xmlpull/v1/XmlPullParser;->getName()Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object v3

    .line 80
    if-eqz v10, :cond_4

    .line 81
    .line 82
    invoke-virtual {v3, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    move-result v14

    .line 86
    if-eqz v14, :cond_4

    .line 87
    .line 88
    move-object/from16 v8, p1

    .line 89
    .line 90
    move v10, v7

    .line 91
    const/4 v5, 0x0

    .line 92
    const/4 v11, 0x0

    .line 93
    goto/16 :goto_c

    .line 94
    .line 95
    :cond_4
    invoke-virtual {v3, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    move-result v13

    .line 99
    if-eqz v13, :cond_5

    .line 100
    .line 101
    iput v7, v2, Lk/g;->b:I

    .line 102
    .line 103
    iput v7, v2, Lk/g;->c:I

    .line 104
    .line 105
    iput v7, v2, Lk/g;->d:I

    .line 106
    .line 107
    iput v7, v2, Lk/g;->e:I

    .line 108
    .line 109
    iput-boolean v6, v2, Lk/g;->f:Z

    .line 110
    .line 111
    iput-boolean v6, v2, Lk/g;->g:Z

    .line 112
    .line 113
    goto :goto_3

    .line 114
    :cond_5
    invoke-virtual {v3, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 115
    .line 116
    .line 117
    move-result v12

    .line 118
    if-eqz v12, :cond_7

    .line 119
    .line 120
    iget-boolean v3, v2, Lk/g;->h:Z

    .line 121
    .line 122
    if-nez v3, :cond_2

    .line 123
    .line 124
    iget-object v3, v2, Lk/g;->z:Ll/o;

    .line 125
    .line 126
    if-eqz v3, :cond_6

    .line 127
    .line 128
    iget-object v3, v3, Ll/o;->b:Landroid/view/ActionProvider;

    .line 129
    .line 130
    invoke-virtual {v3}, Landroid/view/ActionProvider;->hasSubMenu()Z

    .line 131
    .line 132
    .line 133
    move-result v3

    .line 134
    if-eqz v3, :cond_6

    .line 135
    .line 136
    iput-boolean v6, v2, Lk/g;->h:Z

    .line 137
    .line 138
    iget v3, v2, Lk/g;->b:I

    .line 139
    .line 140
    iget v12, v2, Lk/g;->i:I

    .line 141
    .line 142
    iget v13, v2, Lk/g;->j:I

    .line 143
    .line 144
    iget-object v14, v2, Lk/g;->k:Ljava/lang/CharSequence;

    .line 145
    .line 146
    iget-object v15, v2, Lk/g;->a:Landroid/view/Menu;

    .line 147
    .line 148
    invoke-interface {v15, v3, v12, v13, v14}, Landroid/view/Menu;->addSubMenu(IIILjava/lang/CharSequence;)Landroid/view/SubMenu;

    .line 149
    .line 150
    .line 151
    move-result-object v3

    .line 152
    invoke-interface {v3}, Landroid/view/SubMenu;->getItem()Landroid/view/MenuItem;

    .line 153
    .line 154
    .line 155
    move-result-object v3

    .line 156
    invoke-virtual {v2, v3}, Lk/g;->b(Landroid/view/MenuItem;)V

    .line 157
    .line 158
    .line 159
    goto :goto_3

    .line 160
    :cond_6
    iput-boolean v6, v2, Lk/g;->h:Z

    .line 161
    .line 162
    iget v3, v2, Lk/g;->b:I

    .line 163
    .line 164
    iget v12, v2, Lk/g;->i:I

    .line 165
    .line 166
    iget v13, v2, Lk/g;->j:I

    .line 167
    .line 168
    iget-object v14, v2, Lk/g;->k:Ljava/lang/CharSequence;

    .line 169
    .line 170
    iget-object v15, v2, Lk/g;->a:Landroid/view/Menu;

    .line 171
    .line 172
    invoke-interface {v15, v3, v12, v13, v14}, Landroid/view/Menu;->add(IIILjava/lang/CharSequence;)Landroid/view/MenuItem;

    .line 173
    .line 174
    .line 175
    move-result-object v3

    .line 176
    invoke-virtual {v2, v3}, Lk/g;->b(Landroid/view/MenuItem;)V

    .line 177
    .line 178
    .line 179
    goto :goto_3

    .line 180
    :cond_7
    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 181
    .line 182
    .line 183
    move-result v3

    .line 184
    if-eqz v3, :cond_2

    .line 185
    .line 186
    move-object/from16 v8, p1

    .line 187
    .line 188
    move v9, v6

    .line 189
    :goto_4
    const/4 v5, 0x0

    .line 190
    goto/16 :goto_c

    .line 191
    .line 192
    :cond_8
    if-eqz v10, :cond_9

    .line 193
    .line 194
    goto :goto_3

    .line 195
    :cond_9
    invoke-interface/range {p1 .. p1}, Lorg/xmlpull/v1/XmlPullParser;->getName()Ljava/lang/String;

    .line 196
    .line 197
    .line 198
    move-result-object v3

    .line 199
    invoke-virtual {v3, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 200
    .line 201
    .line 202
    move-result v13

    .line 203
    iget-object v15, v0, Lk/h;->c:Landroid/content/Context;

    .line 204
    .line 205
    const/4 v8, 0x5

    .line 206
    const/4 v5, 0x4

    .line 207
    if-eqz v13, :cond_a

    .line 208
    .line 209
    sget-object v3, Lg/a;->p:[I

    .line 210
    .line 211
    invoke-virtual {v15, v1, v3}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    .line 212
    .line 213
    .line 214
    move-result-object v3

    .line 215
    invoke-virtual {v3, v6, v7}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 216
    .line 217
    .line 218
    move-result v12

    .line 219
    iput v12, v2, Lk/g;->b:I

    .line 220
    .line 221
    invoke-virtual {v3, v14, v7}, Landroid/content/res/TypedArray;->getInt(II)I

    .line 222
    .line 223
    .line 224
    move-result v12

    .line 225
    iput v12, v2, Lk/g;->c:I

    .line 226
    .line 227
    invoke-virtual {v3, v5, v7}, Landroid/content/res/TypedArray;->getInt(II)I

    .line 228
    .line 229
    .line 230
    move-result v5

    .line 231
    iput v5, v2, Lk/g;->d:I

    .line 232
    .line 233
    invoke-virtual {v3, v8, v7}, Landroid/content/res/TypedArray;->getInt(II)I

    .line 234
    .line 235
    .line 236
    move-result v5

    .line 237
    iput v5, v2, Lk/g;->e:I

    .line 238
    .line 239
    const/4 v5, 0x2

    .line 240
    invoke-virtual {v3, v5, v6}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    .line 241
    .line 242
    .line 243
    move-result v8

    .line 244
    iput-boolean v8, v2, Lk/g;->f:Z

    .line 245
    .line 246
    invoke-virtual {v3, v7, v6}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    .line 247
    .line 248
    .line 249
    move-result v5

    .line 250
    iput-boolean v5, v2, Lk/g;->g:Z

    .line 251
    .line 252
    invoke-virtual {v3}, Landroid/content/res/TypedArray;->recycle()V

    .line 253
    .line 254
    .line 255
    goto/16 :goto_3

    .line 256
    .line 257
    :cond_a
    invoke-virtual {v3, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 258
    .line 259
    .line 260
    move-result v12

    .line 261
    if-eqz v12, :cond_13

    .line 262
    .line 263
    sget-object v3, Lg/a;->q:[I

    .line 264
    .line 265
    invoke-static {v15, v1, v3}, Lil/g;->Q(Landroid/content/Context;Landroid/util/AttributeSet;[I)Lil/g;

    .line 266
    .line 267
    .line 268
    move-result-object v3

    .line 269
    iget-object v12, v3, Lil/g;->f:Ljava/lang/Object;

    .line 270
    .line 271
    check-cast v12, Landroid/content/res/TypedArray;

    .line 272
    .line 273
    const/4 v13, 0x2

    .line 274
    invoke-virtual {v12, v13, v7}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 275
    .line 276
    .line 277
    move-result v15

    .line 278
    iput v15, v2, Lk/g;->i:I

    .line 279
    .line 280
    iget v15, v2, Lk/g;->c:I

    .line 281
    .line 282
    invoke-virtual {v12, v8, v15}, Landroid/content/res/TypedArray;->getInt(II)I

    .line 283
    .line 284
    .line 285
    move-result v8

    .line 286
    const/4 v15, 0x6

    .line 287
    iget v13, v2, Lk/g;->d:I

    .line 288
    .line 289
    invoke-virtual {v12, v15, v13}, Landroid/content/res/TypedArray;->getInt(II)I

    .line 290
    .line 291
    .line 292
    move-result v13

    .line 293
    const/high16 v15, -0x10000

    .line 294
    .line 295
    and-int/2addr v8, v15

    .line 296
    const v15, 0xffff

    .line 297
    .line 298
    .line 299
    and-int/2addr v13, v15

    .line 300
    or-int/2addr v8, v13

    .line 301
    iput v8, v2, Lk/g;->j:I

    .line 302
    .line 303
    const/4 v8, 0x7

    .line 304
    invoke-virtual {v12, v8}, Landroid/content/res/TypedArray;->getText(I)Ljava/lang/CharSequence;

    .line 305
    .line 306
    .line 307
    move-result-object v8

    .line 308
    iput-object v8, v2, Lk/g;->k:Ljava/lang/CharSequence;

    .line 309
    .line 310
    const/16 v8, 0x8

    .line 311
    .line 312
    invoke-virtual {v12, v8}, Landroid/content/res/TypedArray;->getText(I)Ljava/lang/CharSequence;

    .line 313
    .line 314
    .line 315
    move-result-object v8

    .line 316
    iput-object v8, v2, Lk/g;->l:Ljava/lang/CharSequence;

    .line 317
    .line 318
    invoke-virtual {v12, v7, v7}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 319
    .line 320
    .line 321
    move-result v8

    .line 322
    iput v8, v2, Lk/g;->m:I

    .line 323
    .line 324
    const/16 v8, 0x9

    .line 325
    .line 326
    invoke-virtual {v12, v8}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    .line 327
    .line 328
    .line 329
    move-result-object v8

    .line 330
    if-nez v8, :cond_b

    .line 331
    .line 332
    move v8, v7

    .line 333
    goto :goto_5

    .line 334
    :cond_b
    invoke-virtual {v8, v7}, Ljava/lang/String;->charAt(I)C

    .line 335
    .line 336
    .line 337
    move-result v8

    .line 338
    :goto_5
    iput-char v8, v2, Lk/g;->n:C

    .line 339
    .line 340
    const/16 v8, 0x10

    .line 341
    .line 342
    const/16 v13, 0x1000

    .line 343
    .line 344
    invoke-virtual {v12, v8, v13}, Landroid/content/res/TypedArray;->getInt(II)I

    .line 345
    .line 346
    .line 347
    move-result v8

    .line 348
    iput v8, v2, Lk/g;->o:I

    .line 349
    .line 350
    const/16 v8, 0xa

    .line 351
    .line 352
    invoke-virtual {v12, v8}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    .line 353
    .line 354
    .line 355
    move-result-object v8

    .line 356
    if-nez v8, :cond_c

    .line 357
    .line 358
    move v8, v7

    .line 359
    goto :goto_6

    .line 360
    :cond_c
    invoke-virtual {v8, v7}, Ljava/lang/String;->charAt(I)C

    .line 361
    .line 362
    .line 363
    move-result v8

    .line 364
    :goto_6
    iput-char v8, v2, Lk/g;->p:C

    .line 365
    .line 366
    const/16 v8, 0x14

    .line 367
    .line 368
    invoke-virtual {v12, v8, v13}, Landroid/content/res/TypedArray;->getInt(II)I

    .line 369
    .line 370
    .line 371
    move-result v8

    .line 372
    iput v8, v2, Lk/g;->q:I

    .line 373
    .line 374
    const/16 v8, 0xb

    .line 375
    .line 376
    invoke-virtual {v12, v8}, Landroid/content/res/TypedArray;->hasValue(I)Z

    .line 377
    .line 378
    .line 379
    move-result v13

    .line 380
    if-eqz v13, :cond_d

    .line 381
    .line 382
    invoke-virtual {v12, v8, v7}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    .line 383
    .line 384
    .line 385
    move-result v8

    .line 386
    iput v8, v2, Lk/g;->r:I

    .line 387
    .line 388
    goto :goto_7

    .line 389
    :cond_d
    iget v8, v2, Lk/g;->e:I

    .line 390
    .line 391
    iput v8, v2, Lk/g;->r:I

    .line 392
    .line 393
    :goto_7
    invoke-virtual {v12, v14, v7}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    .line 394
    .line 395
    .line 396
    move-result v8

    .line 397
    iput-boolean v8, v2, Lk/g;->s:Z

    .line 398
    .line 399
    iget-boolean v8, v2, Lk/g;->f:Z

    .line 400
    .line 401
    invoke-virtual {v12, v5, v8}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    .line 402
    .line 403
    .line 404
    move-result v5

    .line 405
    iput-boolean v5, v2, Lk/g;->t:Z

    .line 406
    .line 407
    iget-boolean v5, v2, Lk/g;->g:Z

    .line 408
    .line 409
    invoke-virtual {v12, v6, v5}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    .line 410
    .line 411
    .line 412
    move-result v5

    .line 413
    iput-boolean v5, v2, Lk/g;->u:Z

    .line 414
    .line 415
    const/16 v5, 0x15

    .line 416
    .line 417
    const/4 v8, -0x1

    .line 418
    invoke-virtual {v12, v5, v8}, Landroid/content/res/TypedArray;->getInt(II)I

    .line 419
    .line 420
    .line 421
    move-result v5

    .line 422
    iput v5, v2, Lk/g;->v:I

    .line 423
    .line 424
    const/16 v5, 0xc

    .line 425
    .line 426
    invoke-virtual {v12, v5}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    .line 427
    .line 428
    .line 429
    move-result-object v5

    .line 430
    iput-object v5, v2, Lk/g;->y:Ljava/lang/String;

    .line 431
    .line 432
    const/16 v5, 0xd

    .line 433
    .line 434
    invoke-virtual {v12, v5, v7}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 435
    .line 436
    .line 437
    move-result v5

    .line 438
    iput v5, v2, Lk/g;->w:I

    .line 439
    .line 440
    const/16 v5, 0xf

    .line 441
    .line 442
    invoke-virtual {v12, v5}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    .line 443
    .line 444
    .line 445
    move-result-object v5

    .line 446
    iput-object v5, v2, Lk/g;->x:Ljava/lang/String;

    .line 447
    .line 448
    const/16 v5, 0xe

    .line 449
    .line 450
    invoke-virtual {v12, v5}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    .line 451
    .line 452
    .line 453
    move-result-object v5

    .line 454
    if-eqz v5, :cond_e

    .line 455
    .line 456
    move v13, v6

    .line 457
    goto :goto_8

    .line 458
    :cond_e
    move v13, v7

    .line 459
    :goto_8
    if-eqz v13, :cond_f

    .line 460
    .line 461
    iget v14, v2, Lk/g;->w:I

    .line 462
    .line 463
    if-nez v14, :cond_f

    .line 464
    .line 465
    iget-object v14, v2, Lk/g;->x:Ljava/lang/String;

    .line 466
    .line 467
    if-nez v14, :cond_f

    .line 468
    .line 469
    sget-object v13, Lk/h;->f:[Ljava/lang/Class;

    .line 470
    .line 471
    iget-object v14, v0, Lk/h;->b:[Ljava/lang/Object;

    .line 472
    .line 473
    invoke-virtual {v2, v5, v13, v14}, Lk/g;->a(Ljava/lang/String;[Ljava/lang/Class;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 474
    .line 475
    .line 476
    move-result-object v5

    .line 477
    check-cast v5, Ll/o;

    .line 478
    .line 479
    iput-object v5, v2, Lk/g;->z:Ll/o;

    .line 480
    .line 481
    goto :goto_9

    .line 482
    :cond_f
    if-eqz v13, :cond_10

    .line 483
    .line 484
    const-string v5, "SupportMenuInflater"

    .line 485
    .line 486
    const-string v13, "Ignoring attribute \'actionProviderClass\'. Action view already specified."

    .line 487
    .line 488
    invoke-static {v5, v13}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 489
    .line 490
    .line 491
    :cond_10
    const/4 v5, 0x0

    .line 492
    iput-object v5, v2, Lk/g;->z:Ll/o;

    .line 493
    .line 494
    :goto_9
    const/16 v5, 0x11

    .line 495
    .line 496
    invoke-virtual {v12, v5}, Landroid/content/res/TypedArray;->getText(I)Ljava/lang/CharSequence;

    .line 497
    .line 498
    .line 499
    move-result-object v5

    .line 500
    iput-object v5, v2, Lk/g;->A:Ljava/lang/CharSequence;

    .line 501
    .line 502
    const/16 v5, 0x16

    .line 503
    .line 504
    invoke-virtual {v12, v5}, Landroid/content/res/TypedArray;->getText(I)Ljava/lang/CharSequence;

    .line 505
    .line 506
    .line 507
    move-result-object v5

    .line 508
    iput-object v5, v2, Lk/g;->B:Ljava/lang/CharSequence;

    .line 509
    .line 510
    const/16 v5, 0x13

    .line 511
    .line 512
    invoke-virtual {v12, v5}, Landroid/content/res/TypedArray;->hasValue(I)Z

    .line 513
    .line 514
    .line 515
    move-result v13

    .line 516
    if-eqz v13, :cond_11

    .line 517
    .line 518
    invoke-virtual {v12, v5, v8}, Landroid/content/res/TypedArray;->getInt(II)I

    .line 519
    .line 520
    .line 521
    move-result v5

    .line 522
    iget-object v8, v2, Lk/g;->D:Landroid/graphics/PorterDuff$Mode;

    .line 523
    .line 524
    invoke-static {v5, v8}, Lm/g1;->b(ILandroid/graphics/PorterDuff$Mode;)Landroid/graphics/PorterDuff$Mode;

    .line 525
    .line 526
    .line 527
    move-result-object v5

    .line 528
    iput-object v5, v2, Lk/g;->D:Landroid/graphics/PorterDuff$Mode;

    .line 529
    .line 530
    const/4 v5, 0x0

    .line 531
    goto :goto_a

    .line 532
    :cond_11
    const/4 v5, 0x0

    .line 533
    iput-object v5, v2, Lk/g;->D:Landroid/graphics/PorterDuff$Mode;

    .line 534
    .line 535
    :goto_a
    const/16 v8, 0x12

    .line 536
    .line 537
    invoke-virtual {v12, v8}, Landroid/content/res/TypedArray;->hasValue(I)Z

    .line 538
    .line 539
    .line 540
    move-result v12

    .line 541
    if-eqz v12, :cond_12

    .line 542
    .line 543
    invoke-virtual {v3, v8}, Lil/g;->y(I)Landroid/content/res/ColorStateList;

    .line 544
    .line 545
    .line 546
    move-result-object v8

    .line 547
    iput-object v8, v2, Lk/g;->C:Landroid/content/res/ColorStateList;

    .line 548
    .line 549
    goto :goto_b

    .line 550
    :cond_12
    iput-object v5, v2, Lk/g;->C:Landroid/content/res/ColorStateList;

    .line 551
    .line 552
    :goto_b
    invoke-virtual {v3}, Lil/g;->U()V

    .line 553
    .line 554
    .line 555
    iput-boolean v7, v2, Lk/g;->h:Z

    .line 556
    .line 557
    move-object/from16 v8, p1

    .line 558
    .line 559
    goto :goto_c

    .line 560
    :cond_13
    const/4 v5, 0x0

    .line 561
    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 562
    .line 563
    .line 564
    move-result v8

    .line 565
    if-eqz v8, :cond_14

    .line 566
    .line 567
    iput-boolean v6, v2, Lk/g;->h:Z

    .line 568
    .line 569
    iget v3, v2, Lk/g;->b:I

    .line 570
    .line 571
    iget v8, v2, Lk/g;->i:I

    .line 572
    .line 573
    iget v12, v2, Lk/g;->j:I

    .line 574
    .line 575
    iget-object v13, v2, Lk/g;->k:Ljava/lang/CharSequence;

    .line 576
    .line 577
    iget-object v14, v2, Lk/g;->a:Landroid/view/Menu;

    .line 578
    .line 579
    invoke-interface {v14, v3, v8, v12, v13}, Landroid/view/Menu;->addSubMenu(IIILjava/lang/CharSequence;)Landroid/view/SubMenu;

    .line 580
    .line 581
    .line 582
    move-result-object v3

    .line 583
    invoke-interface {v3}, Landroid/view/SubMenu;->getItem()Landroid/view/MenuItem;

    .line 584
    .line 585
    .line 586
    move-result-object v8

    .line 587
    invoke-virtual {v2, v8}, Lk/g;->b(Landroid/view/MenuItem;)V

    .line 588
    .line 589
    .line 590
    move-object/from16 v8, p1

    .line 591
    .line 592
    invoke-virtual {v0, v8, v1, v3}, Lk/h;->b(Lorg/xmlpull/v1/XmlPullParser;Landroid/util/AttributeSet;Landroid/view/Menu;)V

    .line 593
    .line 594
    .line 595
    goto :goto_c

    .line 596
    :cond_14
    move-object/from16 v8, p1

    .line 597
    .line 598
    move-object v11, v3

    .line 599
    move v10, v6

    .line 600
    :goto_c
    invoke-interface {v8}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    .line 601
    .line 602
    .line 603
    move-result v3

    .line 604
    const/4 v5, 0x2

    .line 605
    goto/16 :goto_2

    .line 606
    .line 607
    :cond_15
    new-instance v0, Ljava/lang/RuntimeException;

    .line 608
    .line 609
    const-string v1, "Unexpected end of document"

    .line 610
    .line 611
    invoke-direct {v0, v1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 612
    .line 613
    .line 614
    throw v0

    .line 615
    :cond_16
    return-void

    .line 616
    :cond_17
    move-object/from16 v8, p1

    .line 617
    .line 618
    goto/16 :goto_0
.end method

.method public final inflate(ILandroid/view/Menu;)V
    .locals 5

    .line 1
    const-string v0, "Error inflating menu XML"

    .line 2
    .line 3
    instance-of v1, p2, Ll/l;

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    invoke-super {p0, p1, p2}, Landroid/view/MenuInflater;->inflate(ILandroid/view/Menu;)V

    .line 8
    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    const/4 v1, 0x0

    .line 12
    const/4 v2, 0x0

    .line 13
    :try_start_0
    iget-object v3, p0, Lk/h;->c:Landroid/content/Context;

    .line 14
    .line 15
    invoke-virtual {v3}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 16
    .line 17
    .line 18
    move-result-object v3

    .line 19
    invoke-virtual {v3, p1}, Landroid/content/res/Resources;->getLayout(I)Landroid/content/res/XmlResourceParser;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    invoke-static {v1}, Landroid/util/Xml;->asAttributeSet(Lorg/xmlpull/v1/XmlPullParser;)Landroid/util/AttributeSet;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    instance-of v3, p2, Ll/l;

    .line 28
    .line 29
    if-eqz v3, :cond_1

    .line 30
    .line 31
    move-object v3, p2

    .line 32
    check-cast v3, Ll/l;

    .line 33
    .line 34
    iget-boolean v4, v3, Ll/l;->p:Z

    .line 35
    .line 36
    if-nez v4, :cond_1

    .line 37
    .line 38
    invoke-virtual {v3}, Ll/l;->w()V

    .line 39
    .line 40
    .line 41
    const/4 v2, 0x1

    .line 42
    goto :goto_0

    .line 43
    :catchall_0
    move-exception p0

    .line 44
    goto :goto_3

    .line 45
    :catch_0
    move-exception p0

    .line 46
    goto :goto_1

    .line 47
    :catch_1
    move-exception p0

    .line 48
    goto :goto_2

    .line 49
    :cond_1
    :goto_0
    invoke-virtual {p0, v1, p1, p2}, Lk/h;->b(Lorg/xmlpull/v1/XmlPullParser;Landroid/util/AttributeSet;Landroid/view/Menu;)V
    :try_end_0
    .catch Lorg/xmlpull/v1/XmlPullParserException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 50
    .line 51
    .line 52
    if-eqz v2, :cond_2

    .line 53
    .line 54
    check-cast p2, Ll/l;

    .line 55
    .line 56
    invoke-virtual {p2}, Ll/l;->v()V

    .line 57
    .line 58
    .line 59
    :cond_2
    invoke-interface {v1}, Landroid/content/res/XmlResourceParser;->close()V

    .line 60
    .line 61
    .line 62
    return-void

    .line 63
    :goto_1
    :try_start_1
    new-instance p1, Landroid/view/InflateException;

    .line 64
    .line 65
    invoke-direct {p1, v0, p0}, Landroid/view/InflateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 66
    .line 67
    .line 68
    throw p1

    .line 69
    :goto_2
    new-instance p1, Landroid/view/InflateException;

    .line 70
    .line 71
    invoke-direct {p1, v0, p0}, Landroid/view/InflateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 72
    .line 73
    .line 74
    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 75
    :goto_3
    if-eqz v2, :cond_3

    .line 76
    .line 77
    check-cast p2, Ll/l;

    .line 78
    .line 79
    invoke-virtual {p2}, Ll/l;->v()V

    .line 80
    .line 81
    .line 82
    :cond_3
    if-eqz v1, :cond_4

    .line 83
    .line 84
    invoke-interface {v1}, Landroid/content/res/XmlResourceParser;->close()V

    .line 85
    .line 86
    .line 87
    :cond_4
    throw p0
.end method
