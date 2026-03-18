.class public abstract Ljq/d;
.super Landroid/widget/LinearLayout;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Ljava/util/ArrayList;

.field public final e:Ljava/util/ArrayList;

.field public final f:Lh6/e;

.field public final g:Ld4/a0;

.field public h:[Ljava/lang/Integer;

.field public i:Lwq/w;

.field public j:Lwq/x;

.field public k:I

.field public l:Lwq/z;

.field public m:Z


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 12

    .line 1
    const v0, 0x7f13049b

    .line 2
    .line 3
    .line 4
    const v4, 0x7f040375

    .line 5
    .line 6
    .line 7
    invoke-static {p1, p2, v4, v0}, Lbr/a;->a(Landroid/content/Context;Landroid/util/AttributeSet;II)Landroid/content/Context;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    invoke-direct {p0, p1, p2, v4}, Landroid/widget/LinearLayout;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    .line 12
    .line 13
    .line 14
    new-instance p1, Ljava/util/ArrayList;

    .line 15
    .line 16
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Ljq/d;->d:Ljava/util/ArrayList;

    .line 20
    .line 21
    new-instance p1, Ljava/util/ArrayList;

    .line 22
    .line 23
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 24
    .line 25
    .line 26
    iput-object p1, p0, Ljq/d;->e:Ljava/util/ArrayList;

    .line 27
    .line 28
    new-instance p1, Lh6/e;

    .line 29
    .line 30
    move-object v0, p0

    .line 31
    check-cast v0, Lcom/google/android/material/button/MaterialButtonToggleGroup;

    .line 32
    .line 33
    const/16 v1, 0x8

    .line 34
    .line 35
    invoke-direct {p1, v0, v1}, Lh6/e;-><init>(Ljava/lang/Object;I)V

    .line 36
    .line 37
    .line 38
    iput-object p1, p0, Ljq/d;->f:Lh6/e;

    .line 39
    .line 40
    new-instance p1, Ld4/a0;

    .line 41
    .line 42
    const/4 v1, 0x3

    .line 43
    invoke-direct {p1, v0, v1}, Ld4/a0;-><init>(Ljava/lang/Object;I)V

    .line 44
    .line 45
    .line 46
    iput-object p1, p0, Ljq/d;->g:Ld4/a0;

    .line 47
    .line 48
    const/4 p1, 0x1

    .line 49
    iput-boolean p1, p0, Ljq/d;->m:Z

    .line 50
    .line 51
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    const/4 v7, 0x0

    .line 56
    new-array v6, v7, [I

    .line 57
    .line 58
    sget-object v3, Ldq/a;->k:[I

    .line 59
    .line 60
    const v5, 0x7f13049b

    .line 61
    .line 62
    .line 63
    move-object v2, p2

    .line 64
    invoke-static/range {v1 .. v6}, Lrq/k;->e(Landroid/content/Context;Landroid/util/AttributeSet;[III[I)Landroid/content/res/TypedArray;

    .line 65
    .line 66
    .line 67
    move-result-object p2

    .line 68
    const/4 v2, 0x2

    .line 69
    invoke-virtual {p2, v2}, Landroid/content/res/TypedArray;->hasValue(I)Z

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    const-string v3, "No start tag found"

    .line 74
    .line 75
    const-string v4, "selector"

    .line 76
    .line 77
    const-string v5, "xml"

    .line 78
    .line 79
    const/4 v6, 0x0

    .line 80
    if-eqz v0, :cond_6

    .line 81
    .line 82
    invoke-virtual {p2, v2, v7}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 83
    .line 84
    .line 85
    move-result v0

    .line 86
    if-nez v0, :cond_0

    .line 87
    .line 88
    :catch_0
    :goto_0
    move-object v0, v6

    .line 89
    goto :goto_5

    .line 90
    :cond_0
    invoke-virtual {v1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 91
    .line 92
    .line 93
    move-result-object v8

    .line 94
    invoke-virtual {v8, v0}, Landroid/content/res/Resources;->getResourceTypeName(I)Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object v8

    .line 98
    invoke-virtual {v8, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 99
    .line 100
    .line 101
    move-result v8

    .line 102
    if-nez v8, :cond_1

    .line 103
    .line 104
    goto :goto_0

    .line 105
    :cond_1
    :try_start_0
    invoke-virtual {v1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 106
    .line 107
    .line 108
    move-result-object v8

    .line 109
    invoke-virtual {v8, v0}, Landroid/content/res/Resources;->getXml(I)Landroid/content/res/XmlResourceParser;

    .line 110
    .line 111
    .line 112
    move-result-object v8
    :try_end_0
    .catch Lorg/xmlpull/v1/XmlPullParserException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Landroid/content/res/Resources$NotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 113
    :try_start_1
    new-instance v0, Lwq/z;

    .line 114
    .line 115
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 116
    .line 117
    .line 118
    const/16 v9, 0xa

    .line 119
    .line 120
    new-array v10, v9, [[I

    .line 121
    .line 122
    iput-object v10, v0, Lwq/z;->c:[[I

    .line 123
    .line 124
    new-array v9, v9, [Lt1/j0;

    .line 125
    .line 126
    iput-object v9, v0, Lwq/z;->d:[Lt1/j0;

    .line 127
    .line 128
    invoke-static {v8}, Landroid/util/Xml;->asAttributeSet(Lorg/xmlpull/v1/XmlPullParser;)Landroid/util/AttributeSet;

    .line 129
    .line 130
    .line 131
    move-result-object v9

    .line 132
    :goto_1
    invoke-interface {v8}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    .line 133
    .line 134
    .line 135
    move-result v10

    .line 136
    if-eq v10, v2, :cond_2

    .line 137
    .line 138
    if-eq v10, p1, :cond_2

    .line 139
    .line 140
    goto :goto_1

    .line 141
    :cond_2
    if-ne v10, v2, :cond_4

    .line 142
    .line 143
    invoke-interface {v8}, Lorg/xmlpull/v1/XmlPullParser;->getName()Ljava/lang/String;

    .line 144
    .line 145
    .line 146
    move-result-object v10

    .line 147
    invoke-virtual {v10, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 148
    .line 149
    .line 150
    move-result v10

    .line 151
    if-eqz v10, :cond_3

    .line 152
    .line 153
    invoke-virtual {v1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 154
    .line 155
    .line 156
    move-result-object v10

    .line 157
    invoke-virtual {v0, v1, v8, v9, v10}, Lwq/z;->a(Landroid/content/Context;Landroid/content/res/XmlResourceParser;Landroid/util/AttributeSet;Landroid/content/res/Resources$Theme;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 158
    .line 159
    .line 160
    goto :goto_2

    .line 161
    :catchall_0
    move-exception v0

    .line 162
    move-object v9, v0

    .line 163
    goto :goto_3

    .line 164
    :cond_3
    :goto_2
    :try_start_2
    invoke-interface {v8}, Landroid/content/res/XmlResourceParser;->close()V
    :try_end_2
    .catch Lorg/xmlpull/v1/XmlPullParserException; {:try_start_2 .. :try_end_2} :catch_0
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0
    .catch Landroid/content/res/Resources$NotFoundException; {:try_start_2 .. :try_end_2} :catch_0

    .line 165
    .line 166
    .line 167
    goto :goto_5

    .line 168
    :cond_4
    :try_start_3
    new-instance v0, Lorg/xmlpull/v1/XmlPullParserException;

    .line 169
    .line 170
    invoke-direct {v0, v3}, Lorg/xmlpull/v1/XmlPullParserException;-><init>(Ljava/lang/String;)V

    .line 171
    .line 172
    .line 173
    throw v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 174
    :goto_3
    if-eqz v8, :cond_5

    .line 175
    .line 176
    :try_start_4
    invoke-interface {v8}, Landroid/content/res/XmlResourceParser;->close()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 177
    .line 178
    .line 179
    goto :goto_4

    .line 180
    :catchall_1
    move-exception v0

    .line 181
    :try_start_5
    invoke-virtual {v9, v0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 182
    .line 183
    .line 184
    :cond_5
    :goto_4
    throw v9
    :try_end_5
    .catch Lorg/xmlpull/v1/XmlPullParserException; {:try_start_5 .. :try_end_5} :catch_0
    .catch Ljava/io/IOException; {:try_start_5 .. :try_end_5} :catch_0
    .catch Landroid/content/res/Resources$NotFoundException; {:try_start_5 .. :try_end_5} :catch_0

    .line 185
    :goto_5
    iput-object v0, p0, Ljq/d;->l:Lwq/z;

    .line 186
    .line 187
    :cond_6
    const/4 v0, 0x4

    .line 188
    invoke-virtual {p2, v0}, Landroid/content/res/TypedArray;->hasValue(I)Z

    .line 189
    .line 190
    .line 191
    move-result v8

    .line 192
    if-eqz v8, :cond_8

    .line 193
    .line 194
    invoke-static {v1, p2, v0}, Lwq/x;->b(Landroid/content/Context;Landroid/content/res/TypedArray;I)Lwq/x;

    .line 195
    .line 196
    .line 197
    move-result-object v8

    .line 198
    iput-object v8, p0, Ljq/d;->j:Lwq/x;

    .line 199
    .line 200
    if-nez v8, :cond_8

    .line 201
    .line 202
    new-instance v8, Ld01/z;

    .line 203
    .line 204
    invoke-virtual {p2, v0, v7}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 205
    .line 206
    .line 207
    move-result v0

    .line 208
    const/4 v9, 0x5

    .line 209
    invoke-virtual {p2, v9, v7}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 210
    .line 211
    .line 212
    move-result v9

    .line 213
    new-instance v10, Lwq/a;

    .line 214
    .line 215
    int-to-float v11, v7

    .line 216
    invoke-direct {v10, v11}, Lwq/a;-><init>(F)V

    .line 217
    .line 218
    .line 219
    invoke-static {v1, v0, v9, v10}, Lwq/m;->a(Landroid/content/Context;IILwq/a;)Lwq/l;

    .line 220
    .line 221
    .line 222
    move-result-object v0

    .line 223
    invoke-virtual {v0}, Lwq/l;->a()Lwq/m;

    .line 224
    .line 225
    .line 226
    move-result-object v0

    .line 227
    invoke-direct {v8, v0}, Ld01/z;-><init>(Lwq/m;)V

    .line 228
    .line 229
    .line 230
    iget v0, v8, Ld01/z;->b:I

    .line 231
    .line 232
    if-nez v0, :cond_7

    .line 233
    .line 234
    goto :goto_6

    .line 235
    :cond_7
    new-instance v6, Lwq/x;

    .line 236
    .line 237
    invoke-direct {v6, v8}, Lwq/x;-><init>(Ld01/z;)V

    .line 238
    .line 239
    .line 240
    :goto_6
    iput-object v6, p0, Ljq/d;->j:Lwq/x;

    .line 241
    .line 242
    :cond_8
    const/4 v0, 0x3

    .line 243
    invoke-virtual {p2, v0}, Landroid/content/res/TypedArray;->hasValue(I)Z

    .line 244
    .line 245
    .line 246
    move-result v6

    .line 247
    if-eqz v6, :cond_f

    .line 248
    .line 249
    new-instance v6, Lwq/a;

    .line 250
    .line 251
    const/4 v8, 0x0

    .line 252
    invoke-direct {v6, v8}, Lwq/a;-><init>(F)V

    .line 253
    .line 254
    .line 255
    invoke-virtual {p2, v0, v7}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 256
    .line 257
    .line 258
    move-result v8

    .line 259
    if-nez v8, :cond_9

    .line 260
    .line 261
    invoke-static {p2, v0, v6}, Lwq/m;->c(Landroid/content/res/TypedArray;ILwq/d;)Lwq/d;

    .line 262
    .line 263
    .line 264
    move-result-object v0

    .line 265
    invoke-static {v0}, Lwq/w;->b(Lwq/d;)Lwq/w;

    .line 266
    .line 267
    .line 268
    move-result-object v0

    .line 269
    goto :goto_b

    .line 270
    :cond_9
    invoke-virtual {v1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 271
    .line 272
    .line 273
    move-result-object v9

    .line 274
    invoke-virtual {v9, v8}, Landroid/content/res/Resources;->getResourceTypeName(I)Ljava/lang/String;

    .line 275
    .line 276
    .line 277
    move-result-object v9

    .line 278
    invoke-virtual {v9, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 279
    .line 280
    .line 281
    move-result v5

    .line 282
    if-nez v5, :cond_a

    .line 283
    .line 284
    invoke-static {p2, v0, v6}, Lwq/m;->c(Landroid/content/res/TypedArray;ILwq/d;)Lwq/d;

    .line 285
    .line 286
    .line 287
    move-result-object v0

    .line 288
    invoke-static {v0}, Lwq/w;->b(Lwq/d;)Lwq/w;

    .line 289
    .line 290
    .line 291
    move-result-object v0

    .line 292
    goto :goto_b

    .line 293
    :cond_a
    :try_start_6
    invoke-virtual {v1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 294
    .line 295
    .line 296
    move-result-object v0

    .line 297
    invoke-virtual {v0, v8}, Landroid/content/res/Resources;->getXml(I)Landroid/content/res/XmlResourceParser;

    .line 298
    .line 299
    .line 300
    move-result-object v5
    :try_end_6
    .catch Lorg/xmlpull/v1/XmlPullParserException; {:try_start_6 .. :try_end_6} :catch_1
    .catch Ljava/io/IOException; {:try_start_6 .. :try_end_6} :catch_1
    .catch Landroid/content/res/Resources$NotFoundException; {:try_start_6 .. :try_end_6} :catch_1

    .line 301
    :try_start_7
    new-instance v0, Lwq/w;

    .line 302
    .line 303
    invoke-direct {v0}, Lwq/w;-><init>()V

    .line 304
    .line 305
    .line 306
    invoke-static {v5}, Landroid/util/Xml;->asAttributeSet(Lorg/xmlpull/v1/XmlPullParser;)Landroid/util/AttributeSet;

    .line 307
    .line 308
    .line 309
    move-result-object v8

    .line 310
    :goto_7
    invoke-interface {v5}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    .line 311
    .line 312
    .line 313
    move-result v9

    .line 314
    if-eq v9, v2, :cond_b

    .line 315
    .line 316
    if-eq v9, p1, :cond_b

    .line 317
    .line 318
    goto :goto_7

    .line 319
    :cond_b
    if-ne v9, v2, :cond_d

    .line 320
    .line 321
    invoke-interface {v5}, Lorg/xmlpull/v1/XmlPullParser;->getName()Ljava/lang/String;

    .line 322
    .line 323
    .line 324
    move-result-object v2

    .line 325
    invoke-virtual {v2, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 326
    .line 327
    .line 328
    move-result v2

    .line 329
    if-eqz v2, :cond_c

    .line 330
    .line 331
    invoke-virtual {v1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 332
    .line 333
    .line 334
    move-result-object v2

    .line 335
    invoke-virtual {v0, v1, v5, v8, v2}, Lwq/w;->d(Landroid/content/Context;Landroid/content/res/XmlResourceParser;Landroid/util/AttributeSet;Landroid/content/res/Resources$Theme;)V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_2

    .line 336
    .line 337
    .line 338
    goto :goto_8

    .line 339
    :catchall_2
    move-exception v0

    .line 340
    move-object v1, v0

    .line 341
    goto :goto_9

    .line 342
    :cond_c
    :goto_8
    :try_start_8
    invoke-interface {v5}, Landroid/content/res/XmlResourceParser;->close()V
    :try_end_8
    .catch Lorg/xmlpull/v1/XmlPullParserException; {:try_start_8 .. :try_end_8} :catch_1
    .catch Ljava/io/IOException; {:try_start_8 .. :try_end_8} :catch_1
    .catch Landroid/content/res/Resources$NotFoundException; {:try_start_8 .. :try_end_8} :catch_1

    .line 343
    .line 344
    .line 345
    goto :goto_b

    .line 346
    :cond_d
    :try_start_9
    new-instance v0, Lorg/xmlpull/v1/XmlPullParserException;

    .line 347
    .line 348
    invoke-direct {v0, v3}, Lorg/xmlpull/v1/XmlPullParserException;-><init>(Ljava/lang/String;)V

    .line 349
    .line 350
    .line 351
    throw v0
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_2

    .line 352
    :goto_9
    if-eqz v5, :cond_e

    .line 353
    .line 354
    :try_start_a
    invoke-interface {v5}, Landroid/content/res/XmlResourceParser;->close()V
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_3

    .line 355
    .line 356
    .line 357
    goto :goto_a

    .line 358
    :catchall_3
    move-exception v0

    .line 359
    :try_start_b
    invoke-virtual {v1, v0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 360
    .line 361
    .line 362
    :cond_e
    :goto_a
    throw v1
    :try_end_b
    .catch Lorg/xmlpull/v1/XmlPullParserException; {:try_start_b .. :try_end_b} :catch_1
    .catch Ljava/io/IOException; {:try_start_b .. :try_end_b} :catch_1
    .catch Landroid/content/res/Resources$NotFoundException; {:try_start_b .. :try_end_b} :catch_1

    .line 363
    :catch_1
    invoke-static {v6}, Lwq/w;->b(Lwq/d;)Lwq/w;

    .line 364
    .line 365
    .line 366
    move-result-object v0

    .line 367
    :goto_b
    iput-object v0, p0, Ljq/d;->i:Lwq/w;

    .line 368
    .line 369
    :cond_f
    invoke-virtual {p2, p1, v7}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    .line 370
    .line 371
    .line 372
    move-result v0

    .line 373
    iput v0, p0, Ljq/d;->k:I

    .line 374
    .line 375
    invoke-virtual {p0, p1}, Landroid/view/ViewGroup;->setChildrenDrawingOrderEnabled(Z)V

    .line 376
    .line 377
    .line 378
    invoke-virtual {p2, v7, p1}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    .line 379
    .line 380
    .line 381
    move-result p1

    .line 382
    invoke-virtual {p0, p1}, Ljq/d;->setEnabled(Z)V

    .line 383
    .line 384
    .line 385
    invoke-virtual {p2}, Landroid/content/res/TypedArray;->recycle()V

    .line 386
    .line 387
    .line 388
    return-void
.end method

.method private getFirstVisibleChildIndex()I
    .locals 3

    .line 1
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    :goto_0
    if-ge v1, v0, :cond_1

    .line 7
    .line 8
    invoke-virtual {p0, v1}, Ljq/d;->c(I)Z

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    if-eqz v2, :cond_0

    .line 13
    .line 14
    return v1

    .line 15
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_1
    const/4 p0, -0x1

    .line 19
    return p0
.end method

.method private getLastVisibleChildIndex()I
    .locals 2

    .line 1
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    add-int/lit8 v0, v0, -0x1

    .line 6
    .line 7
    :goto_0
    if-ltz v0, :cond_1

    .line 8
    .line 9
    invoke-virtual {p0, v0}, Ljq/d;->c(I)Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    return v0

    .line 16
    :cond_0
    add-int/lit8 v0, v0, -0x1

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_1
    const/4 p0, -0x1

    .line 20
    return p0
.end method

.method private setGeneratedIdIfNeeded(Lcom/google/android/material/button/MaterialButton;)V
    .locals 1

    .line 1
    invoke-virtual {p1}, Landroid/view/View;->getId()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    const/4 v0, -0x1

    .line 6
    if-ne p0, v0, :cond_0

    .line 7
    .line 8
    invoke-static {}, Landroid/view/View;->generateViewId()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    invoke-virtual {p1, p0}, Landroid/view/View;->setId(I)V

    .line 13
    .line 14
    .line 15
    :cond_0
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 9

    .line 1
    invoke-direct {p0}, Ljq/d;->getFirstVisibleChildIndex()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, -0x1

    .line 6
    if-ne v0, v1, :cond_0

    .line 7
    .line 8
    goto/16 :goto_4

    .line 9
    .line 10
    :cond_0
    add-int/lit8 v2, v0, 0x1

    .line 11
    .line 12
    :goto_0
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 13
    .line 14
    .line 15
    move-result v3

    .line 16
    const/4 v4, 0x1

    .line 17
    const/4 v5, 0x0

    .line 18
    if-ge v2, v3, :cond_4

    .line 19
    .line 20
    invoke-virtual {p0, v2}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    check-cast v3, Lcom/google/android/material/button/MaterialButton;

    .line 25
    .line 26
    add-int/lit8 v6, v2, -0x1

    .line 27
    .line 28
    invoke-virtual {p0, v6}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 29
    .line 30
    .line 31
    move-result-object v6

    .line 32
    check-cast v6, Lcom/google/android/material/button/MaterialButton;

    .line 33
    .line 34
    iget v7, p0, Ljq/d;->k:I

    .line 35
    .line 36
    if-gtz v7, :cond_1

    .line 37
    .line 38
    invoke-virtual {v3}, Lcom/google/android/material/button/MaterialButton;->getStrokeWidth()I

    .line 39
    .line 40
    .line 41
    move-result v7

    .line 42
    invoke-virtual {v6}, Lcom/google/android/material/button/MaterialButton;->getStrokeWidth()I

    .line 43
    .line 44
    .line 45
    move-result v8

    .line 46
    invoke-static {v7, v8}, Ljava/lang/Math;->min(II)I

    .line 47
    .line 48
    .line 49
    move-result v7

    .line 50
    invoke-virtual {v3, v4}, Lcom/google/android/material/button/MaterialButton;->setShouldDrawSurfaceColorStroke(Z)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {v6, v4}, Lcom/google/android/material/button/MaterialButton;->setShouldDrawSurfaceColorStroke(Z)V

    .line 54
    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_1
    invoke-virtual {v3, v5}, Lcom/google/android/material/button/MaterialButton;->setShouldDrawSurfaceColorStroke(Z)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v6, v5}, Lcom/google/android/material/button/MaterialButton;->setShouldDrawSurfaceColorStroke(Z)V

    .line 61
    .line 62
    .line 63
    move v7, v5

    .line 64
    :goto_1
    invoke-virtual {v3}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 65
    .line 66
    .line 67
    move-result-object v4

    .line 68
    instance-of v6, v4, Landroid/widget/LinearLayout$LayoutParams;

    .line 69
    .line 70
    if-eqz v6, :cond_2

    .line 71
    .line 72
    check-cast v4, Landroid/widget/LinearLayout$LayoutParams;

    .line 73
    .line 74
    goto :goto_2

    .line 75
    :cond_2
    new-instance v6, Landroid/widget/LinearLayout$LayoutParams;

    .line 76
    .line 77
    iget v8, v4, Landroid/view/ViewGroup$LayoutParams;->width:I

    .line 78
    .line 79
    iget v4, v4, Landroid/view/ViewGroup$LayoutParams;->height:I

    .line 80
    .line 81
    invoke-direct {v6, v8, v4}, Landroid/widget/LinearLayout$LayoutParams;-><init>(II)V

    .line 82
    .line 83
    .line 84
    move-object v4, v6

    .line 85
    :goto_2
    invoke-virtual {p0}, Landroid/widget/LinearLayout;->getOrientation()I

    .line 86
    .line 87
    .line 88
    move-result v6

    .line 89
    if-nez v6, :cond_3

    .line 90
    .line 91
    invoke-virtual {v4, v5}, Landroid/view/ViewGroup$MarginLayoutParams;->setMarginEnd(I)V

    .line 92
    .line 93
    .line 94
    iget v6, p0, Ljq/d;->k:I

    .line 95
    .line 96
    sub-int/2addr v6, v7

    .line 97
    invoke-virtual {v4, v6}, Landroid/view/ViewGroup$MarginLayoutParams;->setMarginStart(I)V

    .line 98
    .line 99
    .line 100
    iput v5, v4, Landroid/widget/LinearLayout$LayoutParams;->topMargin:I

    .line 101
    .line 102
    goto :goto_3

    .line 103
    :cond_3
    iput v5, v4, Landroid/widget/LinearLayout$LayoutParams;->bottomMargin:I

    .line 104
    .line 105
    iget v6, p0, Ljq/d;->k:I

    .line 106
    .line 107
    sub-int/2addr v6, v7

    .line 108
    iput v6, v4, Landroid/widget/LinearLayout$LayoutParams;->topMargin:I

    .line 109
    .line 110
    invoke-virtual {v4, v5}, Landroid/view/ViewGroup$MarginLayoutParams;->setMarginStart(I)V

    .line 111
    .line 112
    .line 113
    :goto_3
    invoke-virtual {v3, v4}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 114
    .line 115
    .line 116
    add-int/lit8 v2, v2, 0x1

    .line 117
    .line 118
    goto :goto_0

    .line 119
    :cond_4
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 120
    .line 121
    .line 122
    move-result v2

    .line 123
    if-eqz v2, :cond_7

    .line 124
    .line 125
    if-ne v0, v1, :cond_5

    .line 126
    .line 127
    goto :goto_4

    .line 128
    :cond_5
    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 129
    .line 130
    .line 131
    move-result-object v0

    .line 132
    check-cast v0, Lcom/google/android/material/button/MaterialButton;

    .line 133
    .line 134
    invoke-virtual {v0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 135
    .line 136
    .line 137
    move-result-object v0

    .line 138
    check-cast v0, Landroid/widget/LinearLayout$LayoutParams;

    .line 139
    .line 140
    invoke-virtual {p0}, Landroid/widget/LinearLayout;->getOrientation()I

    .line 141
    .line 142
    .line 143
    move-result p0

    .line 144
    if-ne p0, v4, :cond_6

    .line 145
    .line 146
    iput v5, v0, Landroid/widget/LinearLayout$LayoutParams;->topMargin:I

    .line 147
    .line 148
    iput v5, v0, Landroid/widget/LinearLayout$LayoutParams;->bottomMargin:I

    .line 149
    .line 150
    return-void

    .line 151
    :cond_6
    invoke-virtual {v0, v5}, Landroid/view/ViewGroup$MarginLayoutParams;->setMarginEnd(I)V

    .line 152
    .line 153
    .line 154
    invoke-virtual {v0, v5}, Landroid/view/ViewGroup$MarginLayoutParams;->setMarginStart(I)V

    .line 155
    .line 156
    .line 157
    iput v5, v0, Landroid/widget/LinearLayout$LayoutParams;->leftMargin:I

    .line 158
    .line 159
    iput v5, v0, Landroid/widget/LinearLayout$LayoutParams;->rightMargin:I

    .line 160
    .line 161
    :cond_7
    :goto_4
    return-void
.end method

.method public addView(Landroid/view/View;ILandroid/view/ViewGroup$LayoutParams;)V
    .locals 1

    .line 1
    instance-of v0, p1, Lcom/google/android/material/button/MaterialButton;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const-string p0, "MButtonGroup"

    .line 6
    .line 7
    const-string p1, "Child views must be of type MaterialButton."

    .line 8
    .line 9
    invoke-static {p0, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    invoke-virtual {p0}, Ljq/d;->d()V

    .line 14
    .line 15
    .line 16
    const/4 v0, 0x1

    .line 17
    iput-boolean v0, p0, Ljq/d;->m:Z

    .line 18
    .line 19
    invoke-super {p0, p1, p2, p3}, Landroid/view/ViewGroup;->addView(Landroid/view/View;ILandroid/view/ViewGroup$LayoutParams;)V

    .line 20
    .line 21
    .line 22
    check-cast p1, Lcom/google/android/material/button/MaterialButton;

    .line 23
    .line 24
    invoke-direct {p0, p1}, Ljq/d;->setGeneratedIdIfNeeded(Lcom/google/android/material/button/MaterialButton;)V

    .line 25
    .line 26
    .line 27
    iget-object p2, p0, Ljq/d;->f:Lh6/e;

    .line 28
    .line 29
    invoke-virtual {p1, p2}, Lcom/google/android/material/button/MaterialButton;->setOnPressedChangeListenerInternal(Ljq/b;)V

    .line 30
    .line 31
    .line 32
    iget-object p2, p0, Ljq/d;->d:Ljava/util/ArrayList;

    .line 33
    .line 34
    invoke-virtual {p1}, Lcom/google/android/material/button/MaterialButton;->getShapeAppearanceModel()Lwq/m;

    .line 35
    .line 36
    .line 37
    move-result-object p3

    .line 38
    invoke-virtual {p2, p3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    iget-object p2, p0, Ljq/d;->e:Ljava/util/ArrayList;

    .line 42
    .line 43
    invoke-virtual {p1}, Lcom/google/android/material/button/MaterialButton;->getStateListShapeAppearanceModel()Lwq/x;

    .line 44
    .line 45
    .line 46
    move-result-object p3

    .line 47
    invoke-virtual {p2, p3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    invoke-virtual {p0}, Landroid/view/View;->isEnabled()Z

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    invoke-virtual {p1, p0}, Landroid/view/View;->setEnabled(Z)V

    .line 55
    .line 56
    .line 57
    return-void
.end method

.method public final b()V
    .locals 12

    .line 1
    iget-object v0, p0, Ljq/d;->l:Lwq/z;

    .line 2
    .line 3
    if-eqz v0, :cond_12

    .line 4
    .line 5
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    goto/16 :goto_10

    .line 12
    .line 13
    :cond_0
    invoke-direct {p0}, Ljq/d;->getFirstVisibleChildIndex()I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    invoke-direct {p0}, Ljq/d;->getLastVisibleChildIndex()I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    const v2, 0x7fffffff

    .line 22
    .line 23
    .line 24
    move v3, v0

    .line 25
    :goto_0
    if-gt v3, v1, :cond_e

    .line 26
    .line 27
    invoke-virtual {p0, v3}, Ljq/d;->c(I)Z

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    if-nez v4, :cond_1

    .line 32
    .line 33
    goto/16 :goto_b

    .line 34
    .line 35
    :cond_1
    invoke-virtual {p0, v3}, Ljq/d;->c(I)Z

    .line 36
    .line 37
    .line 38
    move-result v4

    .line 39
    const/4 v5, 0x0

    .line 40
    if-eqz v4, :cond_c

    .line 41
    .line 42
    iget-object v4, p0, Ljq/d;->l:Lwq/z;

    .line 43
    .line 44
    if-nez v4, :cond_2

    .line 45
    .line 46
    goto/16 :goto_a

    .line 47
    .line 48
    :cond_2
    invoke-virtual {p0, v3}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 49
    .line 50
    .line 51
    move-result-object v4

    .line 52
    check-cast v4, Lcom/google/android/material/button/MaterialButton;

    .line 53
    .line 54
    iget-object v6, p0, Ljq/d;->l:Lwq/z;

    .line 55
    .line 56
    invoke-virtual {v4}, Landroid/view/View;->getWidth()I

    .line 57
    .line 58
    .line 59
    move-result v4

    .line 60
    neg-int v7, v4

    .line 61
    move v8, v5

    .line 62
    :goto_1
    iget v9, v6, Lwq/z;->a:I

    .line 63
    .line 64
    if-ge v8, v9, :cond_5

    .line 65
    .line 66
    iget-object v9, v6, Lwq/z;->d:[Lt1/j0;

    .line 67
    .line 68
    aget-object v9, v9, v8

    .line 69
    .line 70
    iget-object v9, v9, Lt1/j0;->e:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast v9, Lwq/y;

    .line 73
    .line 74
    iget v10, v9, Lwq/y;->a:I

    .line 75
    .line 76
    iget v9, v9, Lwq/y;->b:F

    .line 77
    .line 78
    const/4 v11, 0x2

    .line 79
    if-ne v10, v11, :cond_3

    .line 80
    .line 81
    int-to-float v7, v7

    .line 82
    invoke-static {v7, v9}, Ljava/lang/Math;->max(FF)F

    .line 83
    .line 84
    .line 85
    move-result v7

    .line 86
    :goto_2
    float-to-int v7, v7

    .line 87
    goto :goto_3

    .line 88
    :cond_3
    const/4 v11, 0x1

    .line 89
    if-ne v10, v11, :cond_4

    .line 90
    .line 91
    int-to-float v7, v7

    .line 92
    int-to-float v10, v4

    .line 93
    mul-float/2addr v10, v9

    .line 94
    invoke-static {v7, v10}, Ljava/lang/Math;->max(FF)F

    .line 95
    .line 96
    .line 97
    move-result v7

    .line 98
    goto :goto_2

    .line 99
    :cond_4
    :goto_3
    add-int/lit8 v8, v8, 0x1

    .line 100
    .line 101
    goto :goto_1

    .line 102
    :cond_5
    invoke-static {v5, v7}, Ljava/lang/Math;->max(II)I

    .line 103
    .line 104
    .line 105
    move-result v4

    .line 106
    add-int/lit8 v6, v3, -0x1

    .line 107
    .line 108
    :goto_4
    const/4 v7, 0x0

    .line 109
    if-ltz v6, :cond_7

    .line 110
    .line 111
    invoke-virtual {p0, v6}, Ljq/d;->c(I)Z

    .line 112
    .line 113
    .line 114
    move-result v8

    .line 115
    if-eqz v8, :cond_6

    .line 116
    .line 117
    invoke-virtual {p0, v6}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 118
    .line 119
    .line 120
    move-result-object v6

    .line 121
    check-cast v6, Lcom/google/android/material/button/MaterialButton;

    .line 122
    .line 123
    goto :goto_5

    .line 124
    :cond_6
    add-int/lit8 v6, v6, -0x1

    .line 125
    .line 126
    goto :goto_4

    .line 127
    :cond_7
    move-object v6, v7

    .line 128
    :goto_5
    if-nez v6, :cond_8

    .line 129
    .line 130
    move v6, v5

    .line 131
    goto :goto_6

    .line 132
    :cond_8
    invoke-virtual {v6}, Lcom/google/android/material/button/MaterialButton;->getAllowedWidthDecrease()I

    .line 133
    .line 134
    .line 135
    move-result v6

    .line 136
    :goto_6
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 137
    .line 138
    .line 139
    move-result v8

    .line 140
    add-int/lit8 v9, v3, 0x1

    .line 141
    .line 142
    :goto_7
    if-ge v9, v8, :cond_a

    .line 143
    .line 144
    invoke-virtual {p0, v9}, Ljq/d;->c(I)Z

    .line 145
    .line 146
    .line 147
    move-result v10

    .line 148
    if-eqz v10, :cond_9

    .line 149
    .line 150
    invoke-virtual {p0, v9}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 151
    .line 152
    .line 153
    move-result-object v7

    .line 154
    check-cast v7, Lcom/google/android/material/button/MaterialButton;

    .line 155
    .line 156
    goto :goto_8

    .line 157
    :cond_9
    add-int/lit8 v9, v9, 0x1

    .line 158
    .line 159
    goto :goto_7

    .line 160
    :cond_a
    :goto_8
    if-nez v7, :cond_b

    .line 161
    .line 162
    goto :goto_9

    .line 163
    :cond_b
    invoke-virtual {v7}, Lcom/google/android/material/button/MaterialButton;->getAllowedWidthDecrease()I

    .line 164
    .line 165
    .line 166
    move-result v5

    .line 167
    :goto_9
    add-int/2addr v6, v5

    .line 168
    invoke-static {v4, v6}, Ljava/lang/Math;->min(II)I

    .line 169
    .line 170
    .line 171
    move-result v5

    .line 172
    :cond_c
    :goto_a
    if-eq v3, v0, :cond_d

    .line 173
    .line 174
    if-eq v3, v1, :cond_d

    .line 175
    .line 176
    div-int/lit8 v5, v5, 0x2

    .line 177
    .line 178
    :cond_d
    invoke-static {v2, v5}, Ljava/lang/Math;->min(II)I

    .line 179
    .line 180
    .line 181
    move-result v2

    .line 182
    :goto_b
    add-int/lit8 v3, v3, 0x1

    .line 183
    .line 184
    goto/16 :goto_0

    .line 185
    .line 186
    :cond_e
    move v3, v0

    .line 187
    :goto_c
    if-gt v3, v1, :cond_12

    .line 188
    .line 189
    invoke-virtual {p0, v3}, Ljq/d;->c(I)Z

    .line 190
    .line 191
    .line 192
    move-result v4

    .line 193
    if-nez v4, :cond_f

    .line 194
    .line 195
    goto :goto_f

    .line 196
    :cond_f
    invoke-virtual {p0, v3}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 197
    .line 198
    .line 199
    move-result-object v4

    .line 200
    check-cast v4, Lcom/google/android/material/button/MaterialButton;

    .line 201
    .line 202
    iget-object v5, p0, Ljq/d;->l:Lwq/z;

    .line 203
    .line 204
    invoke-virtual {v4, v5}, Lcom/google/android/material/button/MaterialButton;->setSizeChange(Lwq/z;)V

    .line 205
    .line 206
    .line 207
    invoke-virtual {p0, v3}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 208
    .line 209
    .line 210
    move-result-object v4

    .line 211
    check-cast v4, Lcom/google/android/material/button/MaterialButton;

    .line 212
    .line 213
    if-eq v3, v0, :cond_11

    .line 214
    .line 215
    if-ne v3, v1, :cond_10

    .line 216
    .line 217
    goto :goto_d

    .line 218
    :cond_10
    mul-int/lit8 v5, v2, 0x2

    .line 219
    .line 220
    goto :goto_e

    .line 221
    :cond_11
    :goto_d
    move v5, v2

    .line 222
    :goto_e
    invoke-virtual {v4, v5}, Lcom/google/android/material/button/MaterialButton;->setWidthChangeMax(I)V

    .line 223
    .line 224
    .line 225
    :goto_f
    add-int/lit8 v3, v3, 0x1

    .line 226
    .line 227
    goto :goto_c

    .line 228
    :cond_12
    :goto_10
    return-void
.end method

.method public final c(I)Z
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Landroid/view/View;->getVisibility()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    const/16 p1, 0x8

    .line 10
    .line 11
    if-eq p0, p1, :cond_0

    .line 12
    .line 13
    const/4 p0, 0x1

    .line 14
    return p0

    .line 15
    :cond_0
    const/4 p0, 0x0

    .line 16
    return p0
.end method

.method public final d()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    :goto_0
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 3
    .line 4
    .line 5
    move-result v1

    .line 6
    if-ge v0, v1, :cond_1

    .line 7
    .line 8
    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    check-cast v1, Lcom/google/android/material/button/MaterialButton;

    .line 13
    .line 14
    iget-object v2, v1, Lcom/google/android/material/button/MaterialButton;->y:Landroid/widget/LinearLayout$LayoutParams;

    .line 15
    .line 16
    if-eqz v2, :cond_0

    .line 17
    .line 18
    invoke-virtual {v1, v2}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 19
    .line 20
    .line 21
    const/4 v2, 0x0

    .line 22
    iput-object v2, v1, Lcom/google/android/material/button/MaterialButton;->y:Landroid/widget/LinearLayout$LayoutParams;

    .line 23
    .line 24
    const/high16 v2, -0x40800000    # -1.0f

    .line 25
    .line 26
    iput v2, v1, Lcom/google/android/material/button/MaterialButton;->v:F

    .line 27
    .line 28
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_1
    return-void
.end method

.method public final dispatchDraw(Landroid/graphics/Canvas;)V
    .locals 6

    .line 1
    new-instance v0, Ljava/util/TreeMap;

    .line 2
    .line 3
    iget-object v1, p0, Ljq/d;->g:Ld4/a0;

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/util/TreeMap;-><init>(Ljava/util/Comparator;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    const/4 v2, 0x0

    .line 13
    move v3, v2

    .line 14
    :goto_0
    if-ge v3, v1, :cond_0

    .line 15
    .line 16
    invoke-virtual {p0, v3}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 17
    .line 18
    .line 19
    move-result-object v4

    .line 20
    check-cast v4, Lcom/google/android/material/button/MaterialButton;

    .line 21
    .line 22
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 23
    .line 24
    .line 25
    move-result-object v5

    .line 26
    invoke-virtual {v0, v4, v5}, Ljava/util/TreeMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    add-int/lit8 v3, v3, 0x1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    invoke-virtual {v0}, Ljava/util/TreeMap;->values()Ljava/util/Collection;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    new-array v1, v2, [Ljava/lang/Integer;

    .line 37
    .line 38
    invoke-interface {v0, v1}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    check-cast v0, [Ljava/lang/Integer;

    .line 43
    .line 44
    iput-object v0, p0, Ljq/d;->h:[Ljava/lang/Integer;

    .line 45
    .line 46
    invoke-super {p0, p1}, Landroid/view/View;->dispatchDraw(Landroid/graphics/Canvas;)V

    .line 47
    .line 48
    .line 49
    return-void
.end method

.method public final e()V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Ljq/d;->i:Lwq/w;

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    iget-object v1, v0, Ljq/d;->j:Lwq/x;

    .line 8
    .line 9
    if-eqz v1, :cond_15

    .line 10
    .line 11
    :cond_0
    iget-boolean v1, v0, Ljq/d;->m:Z

    .line 12
    .line 13
    if-nez v1, :cond_1

    .line 14
    .line 15
    goto/16 :goto_c

    .line 16
    .line 17
    :cond_1
    const/4 v1, 0x0

    .line 18
    iput-boolean v1, v0, Ljq/d;->m:Z

    .line 19
    .line 20
    invoke-virtual {v0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    invoke-direct {v0}, Ljq/d;->getFirstVisibleChildIndex()I

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    invoke-direct {v0}, Ljq/d;->getLastVisibleChildIndex()I

    .line 29
    .line 30
    .line 31
    move-result v4

    .line 32
    move v5, v1

    .line 33
    :goto_0
    if-ge v5, v2, :cond_15

    .line 34
    .line 35
    invoke-virtual {v0, v5}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 36
    .line 37
    .line 38
    move-result-object v6

    .line 39
    check-cast v6, Lcom/google/android/material/button/MaterialButton;

    .line 40
    .line 41
    invoke-virtual {v6}, Landroid/view/View;->getVisibility()I

    .line 42
    .line 43
    .line 44
    move-result v7

    .line 45
    const/16 v8, 0x8

    .line 46
    .line 47
    if-ne v7, v8, :cond_2

    .line 48
    .line 49
    goto/16 :goto_b

    .line 50
    .line 51
    :cond_2
    if-ne v5, v3, :cond_3

    .line 52
    .line 53
    const/4 v8, 0x1

    .line 54
    goto :goto_1

    .line 55
    :cond_3
    move v8, v1

    .line 56
    :goto_1
    if-ne v5, v4, :cond_4

    .line 57
    .line 58
    const/4 v9, 0x1

    .line 59
    goto :goto_2

    .line 60
    :cond_4
    move v9, v1

    .line 61
    :goto_2
    iget-object v10, v0, Ljq/d;->j:Lwq/x;

    .line 62
    .line 63
    if-eqz v10, :cond_5

    .line 64
    .line 65
    if-nez v8, :cond_6

    .line 66
    .line 67
    if-eqz v9, :cond_5

    .line 68
    .line 69
    goto :goto_3

    .line 70
    :cond_5
    iget-object v10, v0, Ljq/d;->e:Ljava/util/ArrayList;

    .line 71
    .line 72
    invoke-virtual {v10, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v10

    .line 76
    check-cast v10, Lwq/x;

    .line 77
    .line 78
    :cond_6
    :goto_3
    if-nez v10, :cond_7

    .line 79
    .line 80
    new-instance v10, Ld01/z;

    .line 81
    .line 82
    iget-object v11, v0, Ljq/d;->d:Ljava/util/ArrayList;

    .line 83
    .line 84
    invoke-virtual {v11, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v11

    .line 88
    check-cast v11, Lwq/m;

    .line 89
    .line 90
    invoke-direct {v10, v11}, Ld01/z;-><init>(Lwq/m;)V

    .line 91
    .line 92
    .line 93
    goto :goto_4

    .line 94
    :cond_7
    new-instance v11, Ld01/z;

    .line 95
    .line 96
    const/4 v12, 0x1

    .line 97
    invoke-direct {v11, v12}, Ld01/z;-><init>(I)V

    .line 98
    .line 99
    .line 100
    iget v12, v10, Lwq/x;->a:I

    .line 101
    .line 102
    iput v12, v11, Ld01/z;->b:I

    .line 103
    .line 104
    iget-object v13, v10, Lwq/x;->b:Lwq/m;

    .line 105
    .line 106
    iput-object v13, v11, Ld01/z;->c:Ljava/lang/Object;

    .line 107
    .line 108
    iget-object v13, v10, Lwq/x;->c:[[I

    .line 109
    .line 110
    array-length v14, v13

    .line 111
    new-array v14, v14, [[I

    .line 112
    .line 113
    iput-object v14, v11, Ld01/z;->d:Ljava/io/Serializable;

    .line 114
    .line 115
    iget-object v15, v10, Lwq/x;->d:[Lwq/m;

    .line 116
    .line 117
    array-length v7, v15

    .line 118
    new-array v7, v7, [Lwq/m;

    .line 119
    .line 120
    iput-object v7, v11, Ld01/z;->e:Ljava/io/Serializable;

    .line 121
    .line 122
    invoke-static {v13, v1, v14, v1, v12}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 123
    .line 124
    .line 125
    iget-object v7, v11, Ld01/z;->e:Ljava/io/Serializable;

    .line 126
    .line 127
    check-cast v7, [Lwq/m;

    .line 128
    .line 129
    iget v12, v11, Ld01/z;->b:I

    .line 130
    .line 131
    invoke-static {v15, v1, v7, v1, v12}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 132
    .line 133
    .line 134
    iget-object v7, v10, Lwq/x;->e:Lwq/w;

    .line 135
    .line 136
    iput-object v7, v11, Ld01/z;->f:Ljava/lang/Object;

    .line 137
    .line 138
    iget-object v7, v10, Lwq/x;->f:Lwq/w;

    .line 139
    .line 140
    iput-object v7, v11, Ld01/z;->g:Ljava/lang/Object;

    .line 141
    .line 142
    iget-object v7, v10, Lwq/x;->g:Lwq/w;

    .line 143
    .line 144
    iput-object v7, v11, Ld01/z;->h:Ljava/lang/Object;

    .line 145
    .line 146
    iget-object v7, v10, Lwq/x;->h:Lwq/w;

    .line 147
    .line 148
    iput-object v7, v11, Ld01/z;->i:Ljava/lang/Object;

    .line 149
    .line 150
    move-object v10, v11

    .line 151
    :goto_4
    invoke-virtual {v0}, Landroid/widget/LinearLayout;->getOrientation()I

    .line 152
    .line 153
    .line 154
    move-result v7

    .line 155
    if-nez v7, :cond_8

    .line 156
    .line 157
    const/4 v7, 0x1

    .line 158
    goto :goto_5

    .line 159
    :cond_8
    move v7, v1

    .line 160
    :goto_5
    invoke-virtual {v0}, Landroid/view/View;->getLayoutDirection()I

    .line 161
    .line 162
    .line 163
    move-result v11

    .line 164
    const/4 v12, 0x1

    .line 165
    if-ne v11, v12, :cond_9

    .line 166
    .line 167
    const/4 v12, 0x1

    .line 168
    goto :goto_6

    .line 169
    :cond_9
    move v12, v1

    .line 170
    :goto_6
    if-eqz v7, :cond_c

    .line 171
    .line 172
    if-eqz v8, :cond_a

    .line 173
    .line 174
    const/4 v7, 0x5

    .line 175
    goto :goto_7

    .line 176
    :cond_a
    move v7, v1

    .line 177
    :goto_7
    if-eqz v9, :cond_b

    .line 178
    .line 179
    or-int/lit8 v7, v7, 0xa

    .line 180
    .line 181
    :cond_b
    if-eqz v12, :cond_e

    .line 182
    .line 183
    and-int/lit8 v8, v7, 0x5

    .line 184
    .line 185
    and-int/lit8 v7, v7, 0xa

    .line 186
    .line 187
    const/16 v16, 0x1

    .line 188
    .line 189
    shl-int/lit8 v8, v8, 0x1

    .line 190
    .line 191
    shr-int/lit8 v7, v7, 0x1

    .line 192
    .line 193
    or-int/2addr v7, v8

    .line 194
    goto :goto_9

    .line 195
    :cond_c
    if-eqz v8, :cond_d

    .line 196
    .line 197
    const/4 v7, 0x3

    .line 198
    goto :goto_8

    .line 199
    :cond_d
    move v7, v1

    .line 200
    :goto_8
    if-eqz v9, :cond_e

    .line 201
    .line 202
    or-int/lit8 v7, v7, 0xc

    .line 203
    .line 204
    :cond_e
    :goto_9
    not-int v7, v7

    .line 205
    iget-object v8, v0, Ljq/d;->i:Lwq/w;

    .line 206
    .line 207
    or-int/lit8 v9, v7, 0x1

    .line 208
    .line 209
    if-ne v9, v7, :cond_f

    .line 210
    .line 211
    iput-object v8, v10, Ld01/z;->f:Ljava/lang/Object;

    .line 212
    .line 213
    :cond_f
    or-int/lit8 v9, v7, 0x2

    .line 214
    .line 215
    if-ne v9, v7, :cond_10

    .line 216
    .line 217
    iput-object v8, v10, Ld01/z;->g:Ljava/lang/Object;

    .line 218
    .line 219
    :cond_10
    or-int/lit8 v9, v7, 0x4

    .line 220
    .line 221
    if-ne v9, v7, :cond_11

    .line 222
    .line 223
    iput-object v8, v10, Ld01/z;->h:Ljava/lang/Object;

    .line 224
    .line 225
    :cond_11
    or-int/lit8 v9, v7, 0x8

    .line 226
    .line 227
    if-ne v9, v7, :cond_12

    .line 228
    .line 229
    iput-object v8, v10, Ld01/z;->i:Ljava/lang/Object;

    .line 230
    .line 231
    :cond_12
    iget v7, v10, Ld01/z;->b:I

    .line 232
    .line 233
    if-nez v7, :cond_13

    .line 234
    .line 235
    const/4 v7, 0x0

    .line 236
    goto :goto_a

    .line 237
    :cond_13
    new-instance v7, Lwq/x;

    .line 238
    .line 239
    invoke-direct {v7, v10}, Lwq/x;-><init>(Ld01/z;)V

    .line 240
    .line 241
    .line 242
    :goto_a
    invoke-virtual {v7}, Lwq/x;->d()Z

    .line 243
    .line 244
    .line 245
    move-result v8

    .line 246
    if-eqz v8, :cond_14

    .line 247
    .line 248
    invoke-virtual {v6, v7}, Lcom/google/android/material/button/MaterialButton;->setStateListShapeAppearanceModel(Lwq/x;)V

    .line 249
    .line 250
    .line 251
    goto :goto_b

    .line 252
    :cond_14
    invoke-virtual {v7}, Lwq/x;->c()Lwq/m;

    .line 253
    .line 254
    .line 255
    move-result-object v7

    .line 256
    invoke-virtual {v6, v7}, Lcom/google/android/material/button/MaterialButton;->setShapeAppearanceModel(Lwq/m;)V

    .line 257
    .line 258
    .line 259
    :goto_b
    add-int/lit8 v5, v5, 0x1

    .line 260
    .line 261
    goto/16 :goto_0

    .line 262
    .line 263
    :cond_15
    :goto_c
    return-void
.end method

.method public getButtonSizeChange()Lwq/z;
    .locals 0

    .line 1
    iget-object p0, p0, Ljq/d;->l:Lwq/z;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getChildDrawingOrder(II)I
    .locals 0

    .line 1
    iget-object p0, p0, Ljq/d;->h:[Ljava/lang/Integer;

    .line 2
    .line 3
    if-eqz p0, :cond_1

    .line 4
    .line 5
    array-length p1, p0

    .line 6
    if-lt p2, p1, :cond_0

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    aget-object p0, p0, p2

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0

    .line 16
    :cond_1
    :goto_0
    const-string p0, "MButtonGroup"

    .line 17
    .line 18
    const-string p1, "Child order wasn\'t updated"

    .line 19
    .line 20
    invoke-static {p0, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 21
    .line 22
    .line 23
    return p2
.end method

.method public getInnerCornerSize()Lwq/d;
    .locals 0

    .line 1
    iget-object p0, p0, Ljq/d;->i:Lwq/w;

    .line 2
    .line 3
    iget-object p0, p0, Lwq/w;->b:Lwq/d;

    .line 4
    .line 5
    return-object p0
.end method

.method public getInnerCornerSizeStateList()Lwq/w;
    .locals 0

    .line 1
    iget-object p0, p0, Ljq/d;->i:Lwq/w;

    .line 2
    .line 3
    return-object p0
.end method

.method public getShapeAppearance()Lwq/m;
    .locals 0

    .line 1
    iget-object p0, p0, Ljq/d;->j:Lwq/x;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return-object p0

    .line 7
    :cond_0
    invoke-virtual {p0}, Lwq/x;->c()Lwq/m;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public getSpacing()I
    .locals 0

    .line 1
    iget p0, p0, Ljq/d;->k:I

    .line 2
    .line 3
    return p0
.end method

.method public getStateListShapeAppearance()Lwq/x;
    .locals 0

    .line 1
    iget-object p0, p0, Ljq/d;->j:Lwq/x;

    .line 2
    .line 3
    return-object p0
.end method

.method public final onLayout(ZIIII)V
    .locals 0

    .line 1
    invoke-super/range {p0 .. p5}, Landroid/widget/LinearLayout;->onLayout(ZIIII)V

    .line 2
    .line 3
    .line 4
    if-eqz p1, :cond_0

    .line 5
    .line 6
    invoke-virtual {p0}, Ljq/d;->d()V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0}, Ljq/d;->b()V

    .line 10
    .line 11
    .line 12
    :cond_0
    return-void
.end method

.method public final onMeasure(II)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Ljq/d;->e()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Ljq/d;->a()V

    .line 5
    .line 6
    .line 7
    invoke-super {p0, p1, p2}, Landroid/widget/LinearLayout;->onMeasure(II)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final onViewRemoved(Landroid/view/View;)V
    .locals 2

    .line 1
    invoke-super {p0, p1}, Landroid/view/ViewGroup;->onViewRemoved(Landroid/view/View;)V

    .line 2
    .line 3
    .line 4
    instance-of v0, p1, Lcom/google/android/material/button/MaterialButton;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    move-object v0, p1

    .line 9
    check-cast v0, Lcom/google/android/material/button/MaterialButton;

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    invoke-virtual {v0, v1}, Lcom/google/android/material/button/MaterialButton;->setOnPressedChangeListenerInternal(Ljq/b;)V

    .line 13
    .line 14
    .line 15
    :cond_0
    invoke-virtual {p0, p1}, Landroid/view/ViewGroup;->indexOfChild(Landroid/view/View;)I

    .line 16
    .line 17
    .line 18
    move-result p1

    .line 19
    if-ltz p1, :cond_1

    .line 20
    .line 21
    iget-object v0, p0, Ljq/d;->d:Ljava/util/ArrayList;

    .line 22
    .line 23
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    iget-object v0, p0, Ljq/d;->e:Ljava/util/ArrayList;

    .line 27
    .line 28
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    :cond_1
    const/4 p1, 0x1

    .line 32
    iput-boolean p1, p0, Ljq/d;->m:Z

    .line 33
    .line 34
    invoke-virtual {p0}, Ljq/d;->e()V

    .line 35
    .line 36
    .line 37
    invoke-virtual {p0}, Ljq/d;->d()V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p0}, Ljq/d;->a()V

    .line 41
    .line 42
    .line 43
    return-void
.end method

.method public setButtonSizeChange(Lwq/z;)V
    .locals 1

    .line 1
    iget-object v0, p0, Ljq/d;->l:Lwq/z;

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-object p1, p0, Ljq/d;->l:Lwq/z;

    .line 6
    .line 7
    invoke-virtual {p0}, Ljq/d;->b()V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Landroid/view/View;->requestLayout()V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0}, Landroid/view/View;->invalidate()V

    .line 14
    .line 15
    .line 16
    :cond_0
    return-void
.end method

.method public setEnabled(Z)V
    .locals 2

    .line 1
    invoke-super {p0, p1}, Landroid/view/View;->setEnabled(Z)V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    :goto_0
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-ge v0, v1, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    check-cast v1, Lcom/google/android/material/button/MaterialButton;

    .line 16
    .line 17
    invoke-virtual {v1, p1}, Landroid/view/View;->setEnabled(Z)V

    .line 18
    .line 19
    .line 20
    add-int/lit8 v0, v0, 0x1

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    return-void
.end method

.method public setInnerCornerSize(Lwq/d;)V
    .locals 0

    .line 1
    invoke-static {p1}, Lwq/w;->b(Lwq/d;)Lwq/w;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iput-object p1, p0, Ljq/d;->i:Lwq/w;

    .line 6
    .line 7
    const/4 p1, 0x1

    .line 8
    iput-boolean p1, p0, Ljq/d;->m:Z

    .line 9
    .line 10
    invoke-virtual {p0}, Ljq/d;->e()V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0}, Landroid/view/View;->invalidate()V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public setInnerCornerSizeStateList(Lwq/w;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ljq/d;->i:Lwq/w;

    .line 2
    .line 3
    const/4 p1, 0x1

    .line 4
    iput-boolean p1, p0, Ljq/d;->m:Z

    .line 5
    .line 6
    invoke-virtual {p0}, Ljq/d;->e()V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0}, Landroid/view/View;->invalidate()V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public setOrientation(I)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Landroid/widget/LinearLayout;->getOrientation()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eq v0, p1, :cond_0

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    iput-boolean v0, p0, Ljq/d;->m:Z

    .line 9
    .line 10
    :cond_0
    invoke-super {p0, p1}, Landroid/widget/LinearLayout;->setOrientation(I)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public setShapeAppearance(Lwq/m;)V
    .locals 1

    .line 1
    new-instance v0, Ld01/z;

    .line 2
    .line 3
    invoke-direct {v0, p1}, Ld01/z;-><init>(Lwq/m;)V

    .line 4
    .line 5
    .line 6
    iget p1, v0, Ld01/z;->b:I

    .line 7
    .line 8
    if-nez p1, :cond_0

    .line 9
    .line 10
    const/4 p1, 0x0

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    new-instance p1, Lwq/x;

    .line 13
    .line 14
    invoke-direct {p1, v0}, Lwq/x;-><init>(Ld01/z;)V

    .line 15
    .line 16
    .line 17
    :goto_0
    iput-object p1, p0, Ljq/d;->j:Lwq/x;

    .line 18
    .line 19
    const/4 p1, 0x1

    .line 20
    iput-boolean p1, p0, Ljq/d;->m:Z

    .line 21
    .line 22
    invoke-virtual {p0}, Ljq/d;->e()V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0}, Landroid/view/View;->invalidate()V

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public setSpacing(I)V
    .locals 0

    .line 1
    iput p1, p0, Ljq/d;->k:I

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/view/View;->invalidate()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Landroid/view/View;->requestLayout()V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public setStateListShapeAppearance(Lwq/x;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ljq/d;->j:Lwq/x;

    .line 2
    .line 3
    const/4 p1, 0x1

    .line 4
    iput-boolean p1, p0, Ljq/d;->m:Z

    .line 5
    .line 6
    invoke-virtual {p0}, Ljq/d;->e()V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0}, Landroid/view/View;->invalidate()V

    .line 10
    .line 11
    .line 12
    return-void
.end method
