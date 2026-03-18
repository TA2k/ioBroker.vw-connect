.class public abstract Ls5/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lpy/a;

.field public static final b:Landroidx/collection/w;

.field public static c:Landroid/graphics/Paint;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-string v0, "TypefaceCompat static init"

    .line 2
    .line 3
    invoke-static {v0}, Ljp/x0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 11
    .line 12
    const/16 v1, 0x1f

    .line 13
    .line 14
    if-lt v0, v1, :cond_0

    .line 15
    .line 16
    new-instance v0, Ls5/f;

    .line 17
    .line 18
    invoke-direct {v0}, Lpy/a;-><init>()V

    .line 19
    .line 20
    .line 21
    sput-object v0, Ls5/e;->a:Lpy/a;

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v0, Lpy/a;

    .line 25
    .line 26
    invoke-direct {v0}, Lpy/a;-><init>()V

    .line 27
    .line 28
    .line 29
    sput-object v0, Ls5/e;->a:Lpy/a;

    .line 30
    .line 31
    :goto_0
    new-instance v0, Landroidx/collection/w;

    .line 32
    .line 33
    const/16 v1, 0x10

    .line 34
    .line 35
    invoke-direct {v0, v1}, Landroidx/collection/w;-><init>(I)V

    .line 36
    .line 37
    .line 38
    sput-object v0, Ls5/e;->b:Landroidx/collection/w;

    .line 39
    .line 40
    const/4 v0, 0x0

    .line 41
    sput-object v0, Ls5/e;->c:Landroid/graphics/Paint;

    .line 42
    .line 43
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 44
    .line 45
    .line 46
    return-void
.end method

.method public static a(Landroid/content/Context;[Lz5/g;I)Landroid/graphics/Typeface;
    .locals 2

    .line 1
    const-string v0, "TypefaceCompat.createFromFontInfo"

    .line 2
    .line 3
    invoke-static {v0}, Ljp/x0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    :try_start_0
    sget-object v0, Ls5/e;->a:Lpy/a;

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    .line 16
    .line 17
    .line 18
    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    const/4 v1, 0x0

    .line 20
    :try_start_1
    invoke-virtual {v0, p1, p0}, Lpy/a;->p([Lz5/g;Landroid/content/ContentResolver;)Landroid/graphics/fonts/FontFamily;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    if-nez p0, :cond_0

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    new-instance p1, Landroid/graphics/Typeface$CustomFallbackBuilder;

    .line 28
    .line 29
    invoke-direct {p1, p0}, Landroid/graphics/Typeface$CustomFallbackBuilder;-><init>(Landroid/graphics/fonts/FontFamily;)V

    .line 30
    .line 31
    .line 32
    invoke-static {p0, p2}, Lpy/a;->n(Landroid/graphics/fonts/FontFamily;I)Landroid/graphics/fonts/Font;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-virtual {p0}, Landroid/graphics/fonts/Font;->getStyle()Landroid/graphics/fonts/FontStyle;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    invoke-virtual {p1, p0}, Landroid/graphics/Typeface$CustomFallbackBuilder;->setStyle(Landroid/graphics/fonts/FontStyle;)Landroid/graphics/Typeface$CustomFallbackBuilder;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    invoke-virtual {p0}, Landroid/graphics/Typeface$CustomFallbackBuilder;->build()Landroid/graphics/Typeface;

    .line 45
    .line 46
    .line 47
    move-result-object v1
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 48
    goto :goto_0

    .line 49
    :catch_0
    move-exception p0

    .line 50
    :try_start_2
    const-string p1, "TypefaceCompatApi29Impl"

    .line 51
    .line 52
    const-string p2, "Font load failed"

    .line 53
    .line 54
    invoke-static {p1, p2, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 55
    .line 56
    .line 57
    :goto_0
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 58
    .line 59
    .line 60
    return-object v1

    .line 61
    :catchall_0
    move-exception p0

    .line 62
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 63
    .line 64
    .line 65
    throw p0
.end method

.method public static b(Landroid/content/Context;Lp5/d;Landroid/content/res/Resources;ILjava/lang/String;IILp5/b;Z)Landroid/graphics/Typeface;
    .locals 17

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    move/from16 v4, p6

    .line 4
    .line 5
    move-object/from16 v1, p7

    .line 6
    .line 7
    instance-of v2, v0, Lp5/g;

    .line 8
    .line 9
    const/4 v3, 0x6

    .line 10
    const/4 v6, -0x3

    .line 11
    const/4 v7, 0x0

    .line 12
    const/4 v5, 0x0

    .line 13
    if-eqz v2, :cond_16

    .line 14
    .line 15
    check-cast v0, Lp5/g;

    .line 16
    .line 17
    const-string v2, "TypefaceCompat"

    .line 18
    .line 19
    iget-object v8, v0, Lp5/g;->d:Ljava/lang/String;

    .line 20
    .line 21
    invoke-static {v8}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 22
    .line 23
    .line 24
    move-result v9

    .line 25
    const/4 v10, 0x1

    .line 26
    if-nez v9, :cond_0

    .line 27
    .line 28
    invoke-static {v8}, Ls5/e;->e(Ljava/lang/String;)Landroid/graphics/Typeface;

    .line 29
    .line 30
    .line 31
    move-result-object v8

    .line 32
    if-eqz v8, :cond_0

    .line 33
    .line 34
    goto/16 :goto_6

    .line 35
    .line 36
    :cond_0
    iget-object v8, v0, Lp5/g;->a:Ljava/util/ArrayList;

    .line 37
    .line 38
    invoke-virtual {v8}, Ljava/util/ArrayList;->size()I

    .line 39
    .line 40
    .line 41
    move-result v9

    .line 42
    if-ne v9, v10, :cond_1

    .line 43
    .line 44
    invoke-virtual {v8, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    check-cast v2, Lz5/c;

    .line 49
    .line 50
    iget-object v2, v2, Lz5/c;->e:Ljava/lang/String;

    .line 51
    .line 52
    invoke-static {v2}, Ls5/e;->e(Ljava/lang/String;)Landroid/graphics/Typeface;

    .line 53
    .line 54
    .line 55
    move-result-object v8

    .line 56
    goto/16 :goto_6

    .line 57
    .line 58
    :cond_1
    sget v9, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 59
    .line 60
    const/16 v11, 0x1f

    .line 61
    .line 62
    if-ge v9, v11, :cond_2

    .line 63
    .line 64
    :goto_0
    move-object v8, v7

    .line 65
    goto/16 :goto_6

    .line 66
    .line 67
    :cond_2
    move v9, v5

    .line 68
    :goto_1
    invoke-virtual {v8}, Ljava/util/ArrayList;->size()I

    .line 69
    .line 70
    .line 71
    move-result v11

    .line 72
    if-ge v9, v11, :cond_4

    .line 73
    .line 74
    invoke-virtual {v8, v9}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v11

    .line 78
    check-cast v11, Lz5/c;

    .line 79
    .line 80
    iget-object v11, v11, Lz5/c;->e:Ljava/lang/String;

    .line 81
    .line 82
    invoke-static {v11}, Ls5/e;->e(Ljava/lang/String;)Landroid/graphics/Typeface;

    .line 83
    .line 84
    .line 85
    move-result-object v11

    .line 86
    if-nez v11, :cond_3

    .line 87
    .line 88
    goto :goto_0

    .line 89
    :cond_3
    add-int/lit8 v9, v9, 0x1

    .line 90
    .line 91
    goto :goto_1

    .line 92
    :cond_4
    move v9, v5

    .line 93
    move-object v11, v7

    .line 94
    :goto_2
    invoke-virtual {v8}, Ljava/util/ArrayList;->size()I

    .line 95
    .line 96
    .line 97
    move-result v12

    .line 98
    if-ge v9, v12, :cond_9

    .line 99
    .line 100
    invoke-virtual {v8, v9}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v12

    .line 104
    check-cast v12, Lz5/c;

    .line 105
    .line 106
    invoke-virtual {v8}, Ljava/util/ArrayList;->size()I

    .line 107
    .line 108
    .line 109
    move-result v13

    .line 110
    sub-int/2addr v13, v10

    .line 111
    if-ne v9, v13, :cond_5

    .line 112
    .line 113
    iget-object v13, v12, Lz5/c;->f:Ljava/lang/String;

    .line 114
    .line 115
    invoke-static {v13}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 116
    .line 117
    .line 118
    move-result v13

    .line 119
    if-eqz v13, :cond_5

    .line 120
    .line 121
    iget-object v2, v12, Lz5/c;->e:Ljava/lang/String;

    .line 122
    .line 123
    invoke-virtual {v11, v2}, Landroid/graphics/Typeface$CustomFallbackBuilder;->setSystemFallback(Ljava/lang/String;)Landroid/graphics/Typeface$CustomFallbackBuilder;

    .line 124
    .line 125
    .line 126
    goto :goto_5

    .line 127
    :cond_5
    iget-object v13, v12, Lz5/c;->e:Ljava/lang/String;

    .line 128
    .line 129
    iget-object v14, v12, Lz5/c;->f:Ljava/lang/String;

    .line 130
    .line 131
    invoke-static {v13}, Ls5/e;->e(Ljava/lang/String;)Landroid/graphics/Typeface;

    .line 132
    .line 133
    .line 134
    move-result-object v13

    .line 135
    invoke-static {v13}, Ls5/e;->f(Landroid/graphics/Typeface;)Landroid/graphics/fonts/Font;

    .line 136
    .line 137
    .line 138
    move-result-object v13

    .line 139
    if-nez v13, :cond_6

    .line 140
    .line 141
    new-instance v8, Ljava/lang/StringBuilder;

    .line 142
    .line 143
    const-string v9, "Unable identify the primary font for "

    .line 144
    .line 145
    invoke-direct {v8, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    iget-object v9, v12, Lz5/c;->e:Ljava/lang/String;

    .line 149
    .line 150
    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 151
    .line 152
    .line 153
    const-string v9, ". Falling back to provider font."

    .line 154
    .line 155
    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 156
    .line 157
    .line 158
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 159
    .line 160
    .line 161
    move-result-object v8

    .line 162
    invoke-static {v2, v8}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 163
    .line 164
    .line 165
    goto :goto_0

    .line 166
    :cond_6
    invoke-static {v14}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 167
    .line 168
    .line 169
    move-result v12

    .line 170
    if-eqz v12, :cond_7

    .line 171
    .line 172
    :try_start_0
    new-instance v12, Landroid/graphics/fonts/FontFamily$Builder;

    .line 173
    .line 174
    new-instance v15, Landroid/graphics/fonts/Font$Builder;

    .line 175
    .line 176
    invoke-static {v13}, Lh4/b;->e(Landroid/graphics/fonts/Font;)Landroid/graphics/fonts/Font$Builder;

    .line 177
    .line 178
    .line 179
    move-result-object v13

    .line 180
    invoke-virtual {v13, v14}, Landroid/graphics/fonts/Font$Builder;->setFontVariationSettings(Ljava/lang/String;)Landroid/graphics/fonts/Font$Builder;

    .line 181
    .line 182
    .line 183
    move-result-object v13

    .line 184
    invoke-virtual {v13}, Landroid/graphics/fonts/Font$Builder;->build()Landroid/graphics/fonts/Font;

    .line 185
    .line 186
    .line 187
    move-result-object v13

    .line 188
    invoke-direct {v12, v13}, Landroid/graphics/fonts/FontFamily$Builder;-><init>(Landroid/graphics/fonts/Font;)V

    .line 189
    .line 190
    .line 191
    invoke-virtual {v12}, Landroid/graphics/fonts/FontFamily$Builder;->build()Landroid/graphics/fonts/FontFamily;

    .line 192
    .line 193
    .line 194
    move-result-object v12
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 195
    goto :goto_3

    .line 196
    :catch_0
    const-string v8, "Failed to clone Font instance. Fall back to provider font."

    .line 197
    .line 198
    invoke-static {v2, v8}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 199
    .line 200
    .line 201
    goto/16 :goto_0

    .line 202
    .line 203
    :cond_7
    new-instance v12, Landroid/graphics/fonts/FontFamily$Builder;

    .line 204
    .line 205
    invoke-direct {v12, v13}, Landroid/graphics/fonts/FontFamily$Builder;-><init>(Landroid/graphics/fonts/Font;)V

    .line 206
    .line 207
    .line 208
    invoke-virtual {v12}, Landroid/graphics/fonts/FontFamily$Builder;->build()Landroid/graphics/fonts/FontFamily;

    .line 209
    .line 210
    .line 211
    move-result-object v12

    .line 212
    :goto_3
    if-nez v11, :cond_8

    .line 213
    .line 214
    new-instance v11, Landroid/graphics/Typeface$CustomFallbackBuilder;

    .line 215
    .line 216
    invoke-direct {v11, v12}, Landroid/graphics/Typeface$CustomFallbackBuilder;-><init>(Landroid/graphics/fonts/FontFamily;)V

    .line 217
    .line 218
    .line 219
    goto :goto_4

    .line 220
    :cond_8
    invoke-virtual {v11, v12}, Landroid/graphics/Typeface$CustomFallbackBuilder;->addCustomFallback(Landroid/graphics/fonts/FontFamily;)Landroid/graphics/Typeface$CustomFallbackBuilder;

    .line 221
    .line 222
    .line 223
    :goto_4
    add-int/lit8 v9, v9, 0x1

    .line 224
    .line 225
    goto/16 :goto_2

    .line 226
    .line 227
    :cond_9
    :goto_5
    invoke-virtual {v11}, Landroid/graphics/Typeface$CustomFallbackBuilder;->build()Landroid/graphics/Typeface;

    .line 228
    .line 229
    .line 230
    move-result-object v8

    .line 231
    :goto_6
    if-eqz v8, :cond_b

    .line 232
    .line 233
    if-eqz v1, :cond_a

    .line 234
    .line 235
    new-instance v0, Landroid/os/Handler;

    .line 236
    .line 237
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 238
    .line 239
    .line 240
    move-result-object v2

    .line 241
    invoke-direct {v0, v2}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 242
    .line 243
    .line 244
    new-instance v2, Lno/nordicsemi/android/ble/o0;

    .line 245
    .line 246
    invoke-direct {v2, v3, v1, v8}, Lno/nordicsemi/android/ble/o0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 247
    .line 248
    .line 249
    invoke-virtual {v0, v2}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 250
    .line 251
    .line 252
    :cond_a
    sget-object v0, Ls5/e;->b:Landroidx/collection/w;

    .line 253
    .line 254
    invoke-static/range {p2 .. p6}, Ls5/e;->d(Landroid/content/res/Resources;ILjava/lang/String;II)Ljava/lang/String;

    .line 255
    .line 256
    .line 257
    move-result-object v1

    .line 258
    invoke-virtual {v0, v1, v8}, Landroidx/collection/w;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 259
    .line 260
    .line 261
    return-object v8

    .line 262
    :cond_b
    if-eqz p8, :cond_d

    .line 263
    .line 264
    iget v2, v0, Lp5/g;->c:I

    .line 265
    .line 266
    if-nez v2, :cond_c

    .line 267
    .line 268
    :goto_7
    move v2, v10

    .line 269
    goto :goto_8

    .line 270
    :cond_c
    move v2, v5

    .line 271
    goto :goto_8

    .line 272
    :cond_d
    if-nez v1, :cond_c

    .line 273
    .line 274
    goto :goto_7

    .line 275
    :goto_8
    const/4 v3, -0x1

    .line 276
    if-eqz p8, :cond_e

    .line 277
    .line 278
    iget v8, v0, Lp5/g;->b:I

    .line 279
    .line 280
    goto :goto_9

    .line 281
    :cond_e
    move v8, v3

    .line 282
    :goto_9
    new-instance v9, Landroid/os/Handler;

    .line 283
    .line 284
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 285
    .line 286
    .line 287
    move-result-object v11

    .line 288
    invoke-direct {v9, v11}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 289
    .line 290
    .line 291
    new-instance v11, Lj1/a;

    .line 292
    .line 293
    const/16 v12, 0x1c

    .line 294
    .line 295
    invoke-direct {v11, v12, v5}, Lj1/a;-><init>(IZ)V

    .line 296
    .line 297
    .line 298
    iput-object v1, v11, Lj1/a;->e:Ljava/lang/Object;

    .line 299
    .line 300
    iget-object v0, v0, Lp5/g;->a:Ljava/util/ArrayList;

    .line 301
    .line 302
    new-instance v12, Lyn/i;

    .line 303
    .line 304
    new-instance v1, Lq/q;

    .line 305
    .line 306
    invoke-direct {v1, v9}, Lq/q;-><init>(Landroid/os/Handler;)V

    .line 307
    .line 308
    .line 309
    invoke-direct {v12, v11, v1}, Lyn/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 310
    .line 311
    .line 312
    const/16 v9, 0x1a

    .line 313
    .line 314
    if-eqz v2, :cond_12

    .line 315
    .line 316
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 317
    .line 318
    .line 319
    move-result v2

    .line 320
    if-gt v2, v10, :cond_11

    .line 321
    .line 322
    invoke-virtual {v0, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 323
    .line 324
    .line 325
    move-result-object v0

    .line 326
    check-cast v0, Lz5/c;

    .line 327
    .line 328
    sget-object v2, Lz5/f;->a:Landroidx/collection/w;

    .line 329
    .line 330
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 331
    .line 332
    .line 333
    move-result-object v2

    .line 334
    new-instance v13, Ljava/util/ArrayList;

    .line 335
    .line 336
    invoke-direct {v13, v10}, Ljava/util/ArrayList;-><init>(I)V

    .line 337
    .line 338
    .line 339
    aget-object v2, v2, v5

    .line 340
    .line 341
    invoke-static {v2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 342
    .line 343
    .line 344
    invoke-virtual {v13, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 345
    .line 346
    .line 347
    invoke-static {v13}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 348
    .line 349
    .line 350
    move-result-object v2

    .line 351
    invoke-static {v4, v2}, Lz5/f;->a(ILjava/util/List;)Ljava/lang/String;

    .line 352
    .line 353
    .line 354
    move-result-object v2

    .line 355
    sget-object v13, Lz5/f;->a:Landroidx/collection/w;

    .line 356
    .line 357
    invoke-virtual {v13, v2}, Landroidx/collection/w;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 358
    .line 359
    .line 360
    move-result-object v13

    .line 361
    check-cast v13, Landroid/graphics/Typeface;

    .line 362
    .line 363
    if-eqz v13, :cond_f

    .line 364
    .line 365
    new-instance v0, Llr/b;

    .line 366
    .line 367
    invoke-direct {v0, v9, v11, v13}, Llr/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 368
    .line 369
    .line 370
    invoke-virtual {v1, v0}, Lq/q;->execute(Ljava/lang/Runnable;)V

    .line 371
    .line 372
    .line 373
    move-object v7, v13

    .line 374
    goto/16 :goto_d

    .line 375
    .line 376
    :cond_f
    if-ne v8, v3, :cond_10

    .line 377
    .line 378
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 379
    .line 380
    .line 381
    move-result-object v0

    .line 382
    new-instance v1, Ljava/util/ArrayList;

    .line 383
    .line 384
    invoke-direct {v1, v10}, Ljava/util/ArrayList;-><init>(I)V

    .line 385
    .line 386
    .line 387
    aget-object v0, v0, v5

    .line 388
    .line 389
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 390
    .line 391
    .line 392
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 393
    .line 394
    .line 395
    invoke-static {v1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 396
    .line 397
    .line 398
    move-result-object v0

    .line 399
    move-object/from16 v1, p0

    .line 400
    .line 401
    invoke-static {v2, v1, v0, v4}, Lz5/f;->b(Ljava/lang/String;Landroid/content/Context;Ljava/util/List;I)Lz5/e;

    .line 402
    .line 403
    .line 404
    move-result-object v0

    .line 405
    invoke-virtual {v12, v0}, Lyn/i;->a(Lz5/e;)V

    .line 406
    .line 407
    .line 408
    iget-object v7, v0, Lz5/e;->a:Landroid/graphics/Typeface;

    .line 409
    .line 410
    goto/16 :goto_d

    .line 411
    .line 412
    :cond_10
    move-object/from16 v1, p0

    .line 413
    .line 414
    move-object v3, v0

    .line 415
    new-instance v0, Lz5/d;

    .line 416
    .line 417
    const/4 v5, 0x0

    .line 418
    move-object/from16 v16, v2

    .line 419
    .line 420
    move-object v2, v1

    .line 421
    move-object/from16 v1, v16

    .line 422
    .line 423
    invoke-direct/range {v0 .. v5}, Lz5/d;-><init>(Ljava/lang/String;Landroid/content/Context;Ljava/lang/Object;II)V

    .line 424
    .line 425
    .line 426
    :try_start_1
    sget-object v1, Lz5/f;->b:Ljava/util/concurrent/ThreadPoolExecutor;

    .line 427
    .line 428
    invoke-interface {v1, v0}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/util/concurrent/Callable;)Ljava/util/concurrent/Future;

    .line 429
    .line 430
    .line 431
    move-result-object v0
    :try_end_1
    .catch Ljava/lang/InterruptedException; {:try_start_1 .. :try_end_1} :catch_4

    .line 432
    int-to-long v1, v8

    .line 433
    :try_start_2
    sget-object v3, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 434
    .line 435
    invoke-interface {v0, v1, v2, v3}, Ljava/util/concurrent/Future;->get(JLjava/util/concurrent/TimeUnit;)Ljava/lang/Object;

    .line 436
    .line 437
    .line 438
    move-result-object v0
    :try_end_2
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_2 .. :try_end_2} :catch_2
    .catch Ljava/lang/InterruptedException; {:try_start_2 .. :try_end_2} :catch_1
    .catch Ljava/util/concurrent/TimeoutException; {:try_start_2 .. :try_end_2} :catch_3

    .line 439
    :try_start_3
    check-cast v0, Lz5/e;

    .line 440
    .line 441
    invoke-virtual {v12, v0}, Lyn/i;->a(Lz5/e;)V

    .line 442
    .line 443
    .line 444
    iget-object v7, v0, Lz5/e;->a:Landroid/graphics/Typeface;

    .line 445
    .line 446
    goto/16 :goto_d

    .line 447
    .line 448
    :catch_1
    move-exception v0

    .line 449
    goto :goto_a

    .line 450
    :catch_2
    move-exception v0

    .line 451
    goto :goto_b

    .line 452
    :catch_3
    new-instance v0, Ljava/lang/InterruptedException;

    .line 453
    .line 454
    const-string v1, "timeout"

    .line 455
    .line 456
    invoke-direct {v0, v1}, Ljava/lang/InterruptedException;-><init>(Ljava/lang/String;)V

    .line 457
    .line 458
    .line 459
    throw v0

    .line 460
    :goto_a
    throw v0

    .line 461
    :goto_b
    new-instance v1, Ljava/lang/RuntimeException;

    .line 462
    .line 463
    invoke-direct {v1, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 464
    .line 465
    .line 466
    throw v1
    :try_end_3
    .catch Ljava/lang/InterruptedException; {:try_start_3 .. :try_end_3} :catch_4

    .line 467
    :catch_4
    iget-object v0, v12, Lyn/i;->e:Ljava/lang/Object;

    .line 468
    .line 469
    check-cast v0, Lq/q;

    .line 470
    .line 471
    iget-object v1, v12, Lyn/i;->d:Ljava/lang/Object;

    .line 472
    .line 473
    check-cast v1, Lj1/a;

    .line 474
    .line 475
    new-instance v2, Lcom/google/android/material/datepicker/n;

    .line 476
    .line 477
    const/4 v3, 0x4

    .line 478
    invoke-direct {v2, v1, v6, v3}, Lcom/google/android/material/datepicker/n;-><init>(Ljava/lang/Object;II)V

    .line 479
    .line 480
    .line 481
    invoke-virtual {v0, v2}, Lq/q;->execute(Ljava/lang/Runnable;)V

    .line 482
    .line 483
    .line 484
    goto/16 :goto_d

    .line 485
    .line 486
    :cond_11
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 487
    .line 488
    const-string v1, "Fallbacks with blocking fetches are not supported for performance reasons"

    .line 489
    .line 490
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 491
    .line 492
    .line 493
    throw v0

    .line 494
    :cond_12
    invoke-static {v4, v0}, Lz5/f;->a(ILjava/util/List;)Ljava/lang/String;

    .line 495
    .line 496
    .line 497
    move-result-object v2

    .line 498
    sget-object v3, Lz5/f;->a:Landroidx/collection/w;

    .line 499
    .line 500
    invoke-virtual {v3, v2}, Landroidx/collection/w;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 501
    .line 502
    .line 503
    move-result-object v3

    .line 504
    check-cast v3, Landroid/graphics/Typeface;

    .line 505
    .line 506
    if-eqz v3, :cond_13

    .line 507
    .line 508
    new-instance v0, Llr/b;

    .line 509
    .line 510
    invoke-direct {v0, v9, v11, v3}, Llr/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 511
    .line 512
    .line 513
    invoke-virtual {v1, v0}, Lq/q;->execute(Ljava/lang/Runnable;)V

    .line 514
    .line 515
    .line 516
    move-object v7, v3

    .line 517
    goto :goto_d

    .line 518
    :cond_13
    new-instance v1, Lp0/d;

    .line 519
    .line 520
    invoke-direct {v1, v12, v10}, Lp0/d;-><init>(Ljava/lang/Object;I)V

    .line 521
    .line 522
    .line 523
    sget-object v8, Lz5/f;->c:Ljava/lang/Object;

    .line 524
    .line 525
    monitor-enter v8

    .line 526
    :try_start_4
    sget-object v3, Lz5/f;->d:Landroidx/collection/a1;

    .line 527
    .line 528
    invoke-virtual {v3, v2}, Landroidx/collection/a1;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 529
    .line 530
    .line 531
    move-result-object v5

    .line 532
    check-cast v5, Ljava/util/ArrayList;

    .line 533
    .line 534
    if-eqz v5, :cond_14

    .line 535
    .line 536
    invoke-virtual {v5, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 537
    .line 538
    .line 539
    monitor-exit v8

    .line 540
    goto :goto_d

    .line 541
    :catchall_0
    move-exception v0

    .line 542
    goto :goto_e

    .line 543
    :cond_14
    new-instance v5, Ljava/util/ArrayList;

    .line 544
    .line 545
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 546
    .line 547
    .line 548
    invoke-virtual {v5, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 549
    .line 550
    .line 551
    invoke-virtual {v3, v2, v5}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 552
    .line 553
    .line 554
    monitor-exit v8
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 555
    move-object v3, v0

    .line 556
    new-instance v0, Lz5/d;

    .line 557
    .line 558
    const/4 v5, 0x1

    .line 559
    move-object v1, v2

    .line 560
    move-object/from16 v2, p0

    .line 561
    .line 562
    invoke-direct/range {v0 .. v5}, Lz5/d;-><init>(Ljava/lang/String;Landroid/content/Context;Ljava/lang/Object;II)V

    .line 563
    .line 564
    .line 565
    sget-object v2, Lz5/f;->b:Ljava/util/concurrent/ThreadPoolExecutor;

    .line 566
    .line 567
    new-instance v3, Lp0/d;

    .line 568
    .line 569
    const/4 v5, 0x2

    .line 570
    invoke-direct {v3, v1, v5}, Lp0/d;-><init>(Ljava/lang/Object;I)V

    .line 571
    .line 572
    .line 573
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 574
    .line 575
    .line 576
    move-result-object v1

    .line 577
    if-nez v1, :cond_15

    .line 578
    .line 579
    new-instance v1, Landroid/os/Handler;

    .line 580
    .line 581
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 582
    .line 583
    .line 584
    move-result-object v5

    .line 585
    invoke-direct {v1, v5}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 586
    .line 587
    .line 588
    goto :goto_c

    .line 589
    :cond_15
    new-instance v1, Landroid/os/Handler;

    .line 590
    .line 591
    invoke-direct {v1}, Landroid/os/Handler;-><init>()V

    .line 592
    .line 593
    .line 594
    :goto_c
    new-instance v5, Lio/i;

    .line 595
    .line 596
    invoke-direct {v5}, Lio/i;-><init>()V

    .line 597
    .line 598
    .line 599
    iput-object v0, v5, Lio/i;->e:Ljava/lang/Object;

    .line 600
    .line 601
    iput-object v3, v5, Lio/i;->f:Ljava/lang/Object;

    .line 602
    .line 603
    iput-object v1, v5, Lio/i;->g:Ljava/lang/Object;

    .line 604
    .line 605
    invoke-virtual {v2, v5}, Ljava/util/concurrent/ThreadPoolExecutor;->execute(Ljava/lang/Runnable;)V

    .line 606
    .line 607
    .line 608
    :goto_d
    move-object/from16 v12, p2

    .line 609
    .line 610
    goto/16 :goto_13

    .line 611
    .line 612
    :goto_e
    :try_start_5
    monitor-exit v8
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 613
    throw v0

    .line 614
    :cond_16
    sget-object v2, Ls5/e;->a:Lpy/a;

    .line 615
    .line 616
    check-cast v0, Lp5/e;

    .line 617
    .line 618
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 619
    .line 620
    .line 621
    :try_start_6
    iget-object v0, v0, Lp5/e;->a:[Lp5/f;

    .line 622
    .line 623
    array-length v2, v0

    .line 624
    move-object v8, v7

    .line 625
    :goto_f
    if-ge v5, v2, :cond_18

    .line 626
    .line 627
    aget-object v9, v0, v5
    :try_end_6
    .catch Ljava/lang/Exception; {:try_start_6 .. :try_end_6} :catch_6

    .line 628
    .line 629
    :try_start_7
    new-instance v10, Landroid/graphics/fonts/Font$Builder;

    .line 630
    .line 631
    iget v11, v9, Lp5/f;->e:I
    :try_end_7
    .catch Ljava/io/IOException; {:try_start_7 .. :try_end_7} :catch_7
    .catch Ljava/lang/Exception; {:try_start_7 .. :try_end_7} :catch_6

    .line 632
    .line 633
    move-object/from16 v12, p2

    .line 634
    .line 635
    :try_start_8
    invoke-direct {v10, v12, v11}, Landroid/graphics/fonts/Font$Builder;-><init>(Landroid/content/res/Resources;I)V

    .line 636
    .line 637
    .line 638
    iget v11, v9, Lp5/f;->a:I

    .line 639
    .line 640
    invoke-virtual {v10, v11}, Landroid/graphics/fonts/Font$Builder;->setWeight(I)Landroid/graphics/fonts/Font$Builder;

    .line 641
    .line 642
    .line 643
    move-result-object v10

    .line 644
    iget-boolean v11, v9, Lp5/f;->b:Z

    .line 645
    .line 646
    invoke-virtual {v10, v11}, Landroid/graphics/fonts/Font$Builder;->setSlant(I)Landroid/graphics/fonts/Font$Builder;

    .line 647
    .line 648
    .line 649
    move-result-object v10

    .line 650
    iget v11, v9, Lp5/f;->d:I

    .line 651
    .line 652
    invoke-virtual {v10, v11}, Landroid/graphics/fonts/Font$Builder;->setTtcIndex(I)Landroid/graphics/fonts/Font$Builder;

    .line 653
    .line 654
    .line 655
    move-result-object v10

    .line 656
    iget-object v9, v9, Lp5/f;->c:Ljava/lang/String;

    .line 657
    .line 658
    invoke-virtual {v10, v9}, Landroid/graphics/fonts/Font$Builder;->setFontVariationSettings(Ljava/lang/String;)Landroid/graphics/fonts/Font$Builder;

    .line 659
    .line 660
    .line 661
    move-result-object v9

    .line 662
    invoke-virtual {v9}, Landroid/graphics/fonts/Font$Builder;->build()Landroid/graphics/fonts/Font;

    .line 663
    .line 664
    .line 665
    move-result-object v9

    .line 666
    if-nez v8, :cond_17

    .line 667
    .line 668
    new-instance v10, Landroid/graphics/fonts/FontFamily$Builder;

    .line 669
    .line 670
    invoke-direct {v10, v9}, Landroid/graphics/fonts/FontFamily$Builder;-><init>(Landroid/graphics/fonts/Font;)V

    .line 671
    .line 672
    .line 673
    move-object v8, v10

    .line 674
    goto :goto_10

    .line 675
    :catch_5
    move-exception v0

    .line 676
    goto :goto_11

    .line 677
    :cond_17
    invoke-virtual {v8, v9}, Landroid/graphics/fonts/FontFamily$Builder;->addFont(Landroid/graphics/fonts/Font;)Landroid/graphics/fonts/FontFamily$Builder;
    :try_end_8
    .catch Ljava/io/IOException; {:try_start_8 .. :try_end_8} :catch_8
    .catch Ljava/lang/Exception; {:try_start_8 .. :try_end_8} :catch_5

    .line 678
    .line 679
    .line 680
    goto :goto_10

    .line 681
    :catch_6
    move-exception v0

    .line 682
    move-object/from16 v12, p2

    .line 683
    .line 684
    goto :goto_11

    .line 685
    :catch_7
    move-object/from16 v12, p2

    .line 686
    .line 687
    :catch_8
    :goto_10
    add-int/lit8 v5, v5, 0x1

    .line 688
    .line 689
    goto :goto_f

    .line 690
    :cond_18
    move-object/from16 v12, p2

    .line 691
    .line 692
    if-nez v8, :cond_19

    .line 693
    .line 694
    goto :goto_12

    .line 695
    :cond_19
    :try_start_9
    invoke-virtual {v8}, Landroid/graphics/fonts/FontFamily$Builder;->build()Landroid/graphics/fonts/FontFamily;

    .line 696
    .line 697
    .line 698
    move-result-object v0

    .line 699
    new-instance v2, Landroid/graphics/Typeface$CustomFallbackBuilder;

    .line 700
    .line 701
    invoke-direct {v2, v0}, Landroid/graphics/Typeface$CustomFallbackBuilder;-><init>(Landroid/graphics/fonts/FontFamily;)V

    .line 702
    .line 703
    .line 704
    invoke-static {v0, v4}, Lpy/a;->n(Landroid/graphics/fonts/FontFamily;I)Landroid/graphics/fonts/Font;

    .line 705
    .line 706
    .line 707
    move-result-object v0

    .line 708
    invoke-virtual {v0}, Landroid/graphics/fonts/Font;->getStyle()Landroid/graphics/fonts/FontStyle;

    .line 709
    .line 710
    .line 711
    move-result-object v0

    .line 712
    invoke-virtual {v2, v0}, Landroid/graphics/Typeface$CustomFallbackBuilder;->setStyle(Landroid/graphics/fonts/FontStyle;)Landroid/graphics/Typeface$CustomFallbackBuilder;

    .line 713
    .line 714
    .line 715
    move-result-object v0

    .line 716
    invoke-virtual {v0}, Landroid/graphics/Typeface$CustomFallbackBuilder;->build()Landroid/graphics/Typeface;

    .line 717
    .line 718
    .line 719
    move-result-object v7
    :try_end_9
    .catch Ljava/lang/Exception; {:try_start_9 .. :try_end_9} :catch_5

    .line 720
    goto :goto_12

    .line 721
    :goto_11
    const-string v2, "TypefaceCompatApi29Impl"

    .line 722
    .line 723
    const-string v5, "Font load failed"

    .line 724
    .line 725
    invoke-static {v2, v5, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 726
    .line 727
    .line 728
    :goto_12
    if-eqz v1, :cond_1b

    .line 729
    .line 730
    if-eqz v7, :cond_1a

    .line 731
    .line 732
    new-instance v0, Landroid/os/Handler;

    .line 733
    .line 734
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 735
    .line 736
    .line 737
    move-result-object v2

    .line 738
    invoke-direct {v0, v2}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 739
    .line 740
    .line 741
    new-instance v2, Lno/nordicsemi/android/ble/o0;

    .line 742
    .line 743
    invoke-direct {v2, v3, v1, v7}, Lno/nordicsemi/android/ble/o0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 744
    .line 745
    .line 746
    invoke-virtual {v0, v2}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 747
    .line 748
    .line 749
    goto :goto_13

    .line 750
    :cond_1a
    invoke-virtual {v1, v6}, Lp5/b;->a(I)V

    .line 751
    .line 752
    .line 753
    :cond_1b
    :goto_13
    if-eqz v7, :cond_1c

    .line 754
    .line 755
    sget-object v0, Ls5/e;->b:Landroidx/collection/w;

    .line 756
    .line 757
    invoke-static/range {p2 .. p6}, Ls5/e;->d(Landroid/content/res/Resources;ILjava/lang/String;II)Ljava/lang/String;

    .line 758
    .line 759
    .line 760
    move-result-object v1

    .line 761
    invoke-virtual {v0, v1, v7}, Landroidx/collection/w;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 762
    .line 763
    .line 764
    :cond_1c
    return-object v7
.end method

.method public static c(Landroid/content/res/Resources;ILjava/lang/String;II)Landroid/graphics/Typeface;
    .locals 3

    .line 1
    sget-object v0, Ls5/e;->a:Lpy/a;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    :try_start_0
    new-instance v0, Landroid/graphics/fonts/Font$Builder;

    .line 7
    .line 8
    invoke-direct {v0, p0, p1}, Landroid/graphics/fonts/Font$Builder;-><init>(Landroid/content/res/Resources;I)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Landroid/graphics/fonts/Font$Builder;->build()Landroid/graphics/fonts/Font;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    new-instance v1, Landroid/graphics/fonts/FontFamily$Builder;

    .line 16
    .line 17
    invoke-direct {v1, v0}, Landroid/graphics/fonts/FontFamily$Builder;-><init>(Landroid/graphics/fonts/Font;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1}, Landroid/graphics/fonts/FontFamily$Builder;->build()Landroid/graphics/fonts/FontFamily;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    new-instance v2, Landroid/graphics/Typeface$CustomFallbackBuilder;

    .line 25
    .line 26
    invoke-direct {v2, v1}, Landroid/graphics/Typeface$CustomFallbackBuilder;-><init>(Landroid/graphics/fonts/FontFamily;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0}, Landroid/graphics/fonts/Font;->getStyle()Landroid/graphics/fonts/FontStyle;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    invoke-virtual {v2, v0}, Landroid/graphics/Typeface$CustomFallbackBuilder;->setStyle(Landroid/graphics/fonts/FontStyle;)Landroid/graphics/Typeface$CustomFallbackBuilder;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    invoke-virtual {v0}, Landroid/graphics/Typeface$CustomFallbackBuilder;->build()Landroid/graphics/Typeface;

    .line 38
    .line 39
    .line 40
    move-result-object v0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 41
    goto :goto_0

    .line 42
    :catch_0
    move-exception v0

    .line 43
    const-string v1, "TypefaceCompatApi29Impl"

    .line 44
    .line 45
    const-string v2, "Font load failed"

    .line 46
    .line 47
    invoke-static {v1, v2, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 48
    .line 49
    .line 50
    const/4 v0, 0x0

    .line 51
    :goto_0
    if-eqz v0, :cond_0

    .line 52
    .line 53
    invoke-static {p0, p1, p2, p3, p4}, Ls5/e;->d(Landroid/content/res/Resources;ILjava/lang/String;II)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    sget-object p1, Ls5/e;->b:Landroidx/collection/w;

    .line 58
    .line 59
    invoke-virtual {p1, p0, v0}, Landroidx/collection/w;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    :cond_0
    return-object v0
.end method

.method public static d(Landroid/content/res/Resources;ILjava/lang/String;II)Ljava/lang/String;
    .locals 1

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p1}, Landroid/content/res/Resources;->getResourcePackageName(I)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const/16 p0, 0x2d

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    invoke-virtual {v0, p4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0
.end method

.method public static e(Ljava/lang/String;)Landroid/graphics/Typeface;
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p0, :cond_1

    .line 3
    .line 4
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    const/4 v1, 0x0

    .line 12
    invoke-static {p0, v1}, Landroid/graphics/Typeface;->create(Ljava/lang/String;I)Landroid/graphics/Typeface;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    sget-object v2, Landroid/graphics/Typeface;->DEFAULT:Landroid/graphics/Typeface;

    .line 17
    .line 18
    invoke-static {v2, v1}, Landroid/graphics/Typeface;->create(Landroid/graphics/Typeface;I)Landroid/graphics/Typeface;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    if-eqz p0, :cond_1

    .line 23
    .line 24
    invoke-virtual {p0, v1}, Landroid/graphics/Typeface;->equals(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-nez v1, :cond_1

    .line 29
    .line 30
    return-object p0

    .line 31
    :cond_1
    :goto_0
    return-object v0
.end method

.method public static f(Landroid/graphics/Typeface;)Landroid/graphics/fonts/Font;
    .locals 2

    .line 1
    sget-object v0, Ls5/e;->c:Landroid/graphics/Paint;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Landroid/graphics/Paint;

    .line 6
    .line 7
    invoke-direct {v0}, Landroid/graphics/Paint;-><init>()V

    .line 8
    .line 9
    .line 10
    sput-object v0, Ls5/e;->c:Landroid/graphics/Paint;

    .line 11
    .line 12
    :cond_0
    sget-object v0, Ls5/e;->c:Landroid/graphics/Paint;

    .line 13
    .line 14
    const/high16 v1, 0x41200000    # 10.0f

    .line 15
    .line 16
    invoke-virtual {v0, v1}, Landroid/graphics/Paint;->setTextSize(F)V

    .line 17
    .line 18
    .line 19
    sget-object v0, Ls5/e;->c:Landroid/graphics/Paint;

    .line 20
    .line 21
    invoke-virtual {v0, p0}, Landroid/graphics/Paint;->setTypeface(Landroid/graphics/Typeface;)Landroid/graphics/Typeface;

    .line 22
    .line 23
    .line 24
    sget-object p0, Ls5/e;->c:Landroid/graphics/Paint;

    .line 25
    .line 26
    invoke-static {p0}, Lh4/b;->g(Landroid/graphics/Paint;)Landroid/graphics/text/PositionedGlyphs;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    invoke-static {p0}, Lh4/b;->b(Landroid/graphics/text/PositionedGlyphs;)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-nez v0, :cond_1

    .line 35
    .line 36
    const/4 p0, 0x0

    .line 37
    return-object p0

    .line 38
    :cond_1
    invoke-static {p0}, Lh4/b;->f(Landroid/graphics/text/PositionedGlyphs;)Landroid/graphics/fonts/Font;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0
.end method
