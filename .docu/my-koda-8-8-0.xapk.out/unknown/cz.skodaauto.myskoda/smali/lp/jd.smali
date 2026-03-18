.class public abstract Llp/jd;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Le3/f;Ljava/lang/String;Lx2/s;Lx2/e;Lt3/k;Lkc/i;Ll2/o;II)V
    .locals 16

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v6, p5

    .line 4
    .line 5
    move/from16 v7, p7

    .line 6
    .line 7
    const-string v0, "bitmap"

    .line 8
    .line 9
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    move-object/from16 v13, p6

    .line 13
    .line 14
    check-cast v13, Ll2/t;

    .line 15
    .line 16
    const v0, 0x4d9cca20    # 3.2881152E8f

    .line 17
    .line 18
    .line 19
    invoke-virtual {v13, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 20
    .line 21
    .line 22
    and-int/lit8 v0, v7, 0x6

    .line 23
    .line 24
    if-nez v0, :cond_1

    .line 25
    .line 26
    invoke-virtual {v13, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-eqz v0, :cond_0

    .line 31
    .line 32
    const/4 v0, 0x4

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    const/4 v0, 0x2

    .line 35
    :goto_0
    or-int/2addr v0, v7

    .line 36
    goto :goto_1

    .line 37
    :cond_1
    move v0, v7

    .line 38
    :goto_1
    and-int/lit8 v2, v7, 0x30

    .line 39
    .line 40
    move-object/from16 v9, p1

    .line 41
    .line 42
    if-nez v2, :cond_3

    .line 43
    .line 44
    invoke-virtual {v13, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    if-eqz v2, :cond_2

    .line 49
    .line 50
    const/16 v2, 0x20

    .line 51
    .line 52
    goto :goto_2

    .line 53
    :cond_2
    const/16 v2, 0x10

    .line 54
    .line 55
    :goto_2
    or-int/2addr v0, v2

    .line 56
    :cond_3
    and-int/lit16 v2, v7, 0x180

    .line 57
    .line 58
    move-object/from16 v10, p2

    .line 59
    .line 60
    if-nez v2, :cond_5

    .line 61
    .line 62
    invoke-virtual {v13, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result v2

    .line 66
    if-eqz v2, :cond_4

    .line 67
    .line 68
    const/16 v2, 0x100

    .line 69
    .line 70
    goto :goto_3

    .line 71
    :cond_4
    const/16 v2, 0x80

    .line 72
    .line 73
    :goto_3
    or-int/2addr v0, v2

    .line 74
    :cond_5
    and-int/lit8 v2, p8, 0x8

    .line 75
    .line 76
    if-eqz v2, :cond_7

    .line 77
    .line 78
    or-int/lit16 v0, v0, 0xc00

    .line 79
    .line 80
    :cond_6
    move-object/from16 v3, p3

    .line 81
    .line 82
    goto :goto_5

    .line 83
    :cond_7
    and-int/lit16 v3, v7, 0xc00

    .line 84
    .line 85
    if-nez v3, :cond_6

    .line 86
    .line 87
    move-object/from16 v3, p3

    .line 88
    .line 89
    invoke-virtual {v13, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result v4

    .line 93
    if-eqz v4, :cond_8

    .line 94
    .line 95
    const/16 v4, 0x800

    .line 96
    .line 97
    goto :goto_4

    .line 98
    :cond_8
    const/16 v4, 0x400

    .line 99
    .line 100
    :goto_4
    or-int/2addr v0, v4

    .line 101
    :goto_5
    and-int/lit16 v4, v7, 0x6000

    .line 102
    .line 103
    move-object/from16 v12, p4

    .line 104
    .line 105
    if-nez v4, :cond_a

    .line 106
    .line 107
    invoke-virtual {v13, v12}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    move-result v4

    .line 111
    if-eqz v4, :cond_9

    .line 112
    .line 113
    const/16 v4, 0x4000

    .line 114
    .line 115
    goto :goto_6

    .line 116
    :cond_9
    const/16 v4, 0x2000

    .line 117
    .line 118
    :goto_6
    or-int/2addr v0, v4

    .line 119
    :cond_a
    const/high16 v4, 0x30000

    .line 120
    .line 121
    and-int/2addr v4, v7

    .line 122
    if-nez v4, :cond_d

    .line 123
    .line 124
    const/high16 v4, 0x40000

    .line 125
    .line 126
    and-int/2addr v4, v7

    .line 127
    if-nez v4, :cond_b

    .line 128
    .line 129
    invoke-virtual {v13, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 130
    .line 131
    .line 132
    move-result v4

    .line 133
    goto :goto_7

    .line 134
    :cond_b
    invoke-virtual {v13, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 135
    .line 136
    .line 137
    move-result v4

    .line 138
    :goto_7
    if-eqz v4, :cond_c

    .line 139
    .line 140
    const/high16 v4, 0x20000

    .line 141
    .line 142
    goto :goto_8

    .line 143
    :cond_c
    const/high16 v4, 0x10000

    .line 144
    .line 145
    :goto_8
    or-int/2addr v0, v4

    .line 146
    :cond_d
    const v4, 0x12493

    .line 147
    .line 148
    .line 149
    and-int/2addr v4, v0

    .line 150
    const v5, 0x12492

    .line 151
    .line 152
    .line 153
    const/4 v8, 0x0

    .line 154
    if-eq v4, v5, :cond_e

    .line 155
    .line 156
    const/4 v4, 0x1

    .line 157
    goto :goto_9

    .line 158
    :cond_e
    move v4, v8

    .line 159
    :goto_9
    and-int/lit8 v5, v0, 0x1

    .line 160
    .line 161
    invoke-virtual {v13, v5, v4}, Ll2/t;->O(IZ)Z

    .line 162
    .line 163
    .line 164
    move-result v4

    .line 165
    if-eqz v4, :cond_13

    .line 166
    .line 167
    if-eqz v2, :cond_f

    .line 168
    .line 169
    sget-object v2, Lx2/c;->h:Lx2/j;

    .line 170
    .line 171
    move-object v11, v2

    .line 172
    goto :goto_a

    .line 173
    :cond_f
    move-object v11, v3

    .line 174
    :goto_a
    sget-object v2, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 175
    .line 176
    invoke-virtual {v13, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object v2

    .line 180
    check-cast v2, Landroid/content/Context;

    .line 181
    .line 182
    invoke-virtual {v2}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 183
    .line 184
    .line 185
    move-result-object v2

    .line 186
    invoke-virtual {v2}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 187
    .line 188
    .line 189
    move-result-object v2

    .line 190
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 191
    .line 192
    .line 193
    instance-of v3, v6, Lkc/f;

    .line 194
    .line 195
    if-eqz v3, :cond_10

    .line 196
    .line 197
    invoke-static {v1}, Le3/j0;->k(Le3/f;)Landroid/graphics/Bitmap;

    .line 198
    .line 199
    .line 200
    move-result-object v3

    .line 201
    const/high16 v4, 0x41700000    # 15.0f

    .line 202
    .line 203
    invoke-static {v3, v4, v8, v2}, Llp/jd;->b(Landroid/graphics/Bitmap;FILandroid/util/DisplayMetrics;)Landroid/graphics/Bitmap;

    .line 204
    .line 205
    .line 206
    move-result-object v2

    .line 207
    new-instance v3, Le3/f;

    .line 208
    .line 209
    invoke-direct {v3, v2}, Le3/f;-><init>(Landroid/graphics/Bitmap;)V

    .line 210
    .line 211
    .line 212
    :goto_b
    move-object v8, v3

    .line 213
    goto :goto_c

    .line 214
    :cond_10
    instance-of v3, v6, Lkc/h;

    .line 215
    .line 216
    if-eqz v3, :cond_11

    .line 217
    .line 218
    invoke-static {v1}, Le3/j0;->k(Le3/f;)Landroid/graphics/Bitmap;

    .line 219
    .line 220
    .line 221
    move-result-object v3

    .line 222
    move-object v4, v6

    .line 223
    check-cast v4, Lkc/h;

    .line 224
    .line 225
    iget v4, v4, Lkc/h;->a:F

    .line 226
    .line 227
    const v5, -0x777778

    .line 228
    .line 229
    .line 230
    invoke-static {v3, v4, v5, v2}, Llp/jd;->b(Landroid/graphics/Bitmap;FILandroid/util/DisplayMetrics;)Landroid/graphics/Bitmap;

    .line 231
    .line 232
    .line 233
    move-result-object v2

    .line 234
    new-instance v3, Le3/f;

    .line 235
    .line 236
    invoke-direct {v3, v2}, Le3/f;-><init>(Landroid/graphics/Bitmap;)V

    .line 237
    .line 238
    .line 239
    goto :goto_b

    .line 240
    :cond_11
    sget-object v2, Lkc/g;->a:Lkc/g;

    .line 241
    .line 242
    invoke-static {v6, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 243
    .line 244
    .line 245
    move-result v2

    .line 246
    if-eqz v2, :cond_12

    .line 247
    .line 248
    move-object v8, v1

    .line 249
    :goto_c
    const v2, 0xfff0

    .line 250
    .line 251
    .line 252
    and-int v14, v0, v2

    .line 253
    .line 254
    const/16 v15, 0xe0

    .line 255
    .line 256
    invoke-static/range {v8 .. v15}, Lkp/m;->c(Le3/f;Ljava/lang/String;Lx2/s;Lx2/e;Lt3/k;Ll2/o;II)V

    .line 257
    .line 258
    .line 259
    move-object v4, v11

    .line 260
    goto :goto_d

    .line 261
    :cond_12
    new-instance v0, La8/r0;

    .line 262
    .line 263
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 264
    .line 265
    .line 266
    throw v0

    .line 267
    :cond_13
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 268
    .line 269
    .line 270
    move-object v4, v3

    .line 271
    :goto_d
    invoke-virtual {v13}, Ll2/t;->s()Ll2/u1;

    .line 272
    .line 273
    .line 274
    move-result-object v9

    .line 275
    if-eqz v9, :cond_14

    .line 276
    .line 277
    new-instance v0, Lh2/z0;

    .line 278
    .line 279
    move-object/from16 v2, p1

    .line 280
    .line 281
    move-object/from16 v3, p2

    .line 282
    .line 283
    move-object/from16 v5, p4

    .line 284
    .line 285
    move/from16 v8, p8

    .line 286
    .line 287
    invoke-direct/range {v0 .. v8}, Lh2/z0;-><init>(Le3/f;Ljava/lang/String;Lx2/s;Lx2/e;Lt3/k;Lkc/i;II)V

    .line 288
    .line 289
    .line 290
    iput-object v0, v9, Ll2/u1;->d:Lay0/n;

    .line 291
    .line 292
    :cond_14
    return-void
.end method

.method public static final b(Landroid/graphics/Bitmap;FILandroid/util/DisplayMetrics;)Landroid/graphics/Bitmap;
    .locals 4

    .line 1
    const/4 v0, 0x2

    .line 2
    new-array v0, v0, [I

    .line 3
    .line 4
    new-instance v1, Landroid/graphics/Paint;

    .line 5
    .line 6
    invoke-direct {v1}, Landroid/graphics/Paint;-><init>()V

    .line 7
    .line 8
    .line 9
    new-instance v2, Landroid/graphics/BlurMaskFilter;

    .line 10
    .line 11
    iget p3, p3, Landroid/util/DisplayMetrics;->density:F

    .line 12
    .line 13
    mul-float/2addr p3, p1

    .line 14
    sget-object p1, Landroid/graphics/BlurMaskFilter$Blur;->NORMAL:Landroid/graphics/BlurMaskFilter$Blur;

    .line 15
    .line 16
    invoke-direct {v2, p3, p1}, Landroid/graphics/BlurMaskFilter;-><init>(FLandroid/graphics/BlurMaskFilter$Blur;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v1, v2}, Landroid/graphics/Paint;->setMaskFilter(Landroid/graphics/MaskFilter;)Landroid/graphics/MaskFilter;

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0, v1, v0}, Landroid/graphics/Bitmap;->extractAlpha(Landroid/graphics/Paint;[I)Landroid/graphics/Bitmap;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    const-string p3, "extractAlpha(...)"

    .line 27
    .line 28
    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p1}, Landroid/graphics/Bitmap;->getWidth()I

    .line 32
    .line 33
    .line 34
    move-result p3

    .line 35
    invoke-virtual {p1}, Landroid/graphics/Bitmap;->getHeight()I

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    sget-object v2, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 40
    .line 41
    invoke-static {p3, v1, v2}, Landroid/graphics/Bitmap;->createBitmap(IILandroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;

    .line 42
    .line 43
    .line 44
    move-result-object p3

    .line 45
    const-string v1, "createBitmap(...)"

    .line 46
    .line 47
    invoke-static {p3, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    new-instance v1, Landroid/graphics/Canvas;

    .line 51
    .line 52
    invoke-direct {v1, p3}, Landroid/graphics/Canvas;-><init>(Landroid/graphics/Bitmap;)V

    .line 53
    .line 54
    .line 55
    sget-object v2, Landroid/graphics/PorterDuff$Mode;->CLEAR:Landroid/graphics/PorterDuff$Mode;

    .line 56
    .line 57
    const/4 v3, 0x0

    .line 58
    invoke-virtual {v1, v3, v2}, Landroid/graphics/Canvas;->drawColor(ILandroid/graphics/PorterDuff$Mode;)V

    .line 59
    .line 60
    .line 61
    new-instance v2, Landroid/graphics/Paint;

    .line 62
    .line 63
    invoke-direct {v2}, Landroid/graphics/Paint;-><init>()V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v2, p2}, Landroid/graphics/Paint;->setColor(I)V

    .line 67
    .line 68
    .line 69
    const/4 p2, 0x0

    .line 70
    invoke-virtual {v1, p1, p2, p2, v2}, Landroid/graphics/Canvas;->drawBitmap(Landroid/graphics/Bitmap;FFLandroid/graphics/Paint;)V

    .line 71
    .line 72
    .line 73
    aget v2, v0, v3

    .line 74
    .line 75
    int-to-float v2, v2

    .line 76
    sub-float v2, p2, v2

    .line 77
    .line 78
    const/4 v3, 0x1

    .line 79
    aget v0, v0, v3

    .line 80
    .line 81
    int-to-float v0, v0

    .line 82
    sub-float/2addr p2, v0

    .line 83
    const/4 v0, 0x0

    .line 84
    invoke-virtual {v1, p0, v2, p2, v0}, Landroid/graphics/Canvas;->drawBitmap(Landroid/graphics/Bitmap;FFLandroid/graphics/Paint;)V

    .line 85
    .line 86
    .line 87
    invoke-virtual {p1}, Landroid/graphics/Bitmap;->recycle()V

    .line 88
    .line 89
    .line 90
    return-object p3
.end method

.method public static final c(Lvk0/y;Lij0/a;)Lwk0/j0;
    .locals 9

    .line 1
    const-string v0, "stringResource"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lwk0/j0;

    .line 7
    .line 8
    iget-object v2, p0, Lvk0/y;->a:Ljava/lang/String;

    .line 9
    .line 10
    iget-object v0, p0, Lvk0/y;->f:Lvk0/w;

    .line 11
    .line 12
    iget-object v3, v0, Lvk0/w;->c:Ljava/net/URL;

    .line 13
    .line 14
    invoke-static {v3}, Ljp/sf;->h(Ljava/net/URL;)Landroid/net/Uri;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    iget-object v0, v0, Lvk0/w;->b:Ljava/lang/String;

    .line 19
    .line 20
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    check-cast p1, Ljj0/f;

    .line 25
    .line 26
    const v4, 0x7f120675

    .line 27
    .line 28
    .line 29
    invoke-virtual {p1, v4, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v4

    .line 33
    iget-object v5, p0, Lvk0/y;->c:Ljava/lang/String;

    .line 34
    .line 35
    iget-object p1, p0, Lvk0/y;->e:Ljava/time/OffsetDateTime;

    .line 36
    .line 37
    invoke-static {p1}, Lvo/a;->g(Ljava/time/OffsetDateTime;)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v6

    .line 41
    iget-object p1, p0, Lvk0/y;->g:Ljava/net/URL;

    .line 42
    .line 43
    invoke-static {p1}, Ljp/sf;->h(Ljava/net/URL;)Landroid/net/Uri;

    .line 44
    .line 45
    .line 46
    move-result-object v7

    .line 47
    iget-object p0, p0, Lvk0/y;->b:Lvk0/x;

    .line 48
    .line 49
    sget-object p1, Lvk0/x;->f:Lvk0/x;

    .line 50
    .line 51
    if-ne p0, p1, :cond_0

    .line 52
    .line 53
    const/4 p0, 0x1

    .line 54
    :goto_0
    move v8, p0

    .line 55
    goto :goto_1

    .line 56
    :cond_0
    const/4 p0, 0x0

    .line 57
    goto :goto_0

    .line 58
    :goto_1
    invoke-direct/range {v1 .. v8}, Lwk0/j0;-><init>(Ljava/lang/String;Landroid/net/Uri;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/net/Uri;Z)V

    .line 59
    .line 60
    .line 61
    return-object v1
.end method
