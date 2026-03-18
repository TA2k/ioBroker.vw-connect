.class public final Lbb/f;
.super Lbb/x;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final H:[Ljava/lang/String;

.field public static final I:Lbb/b;

.field public static final J:Lbb/b;

.field public static final K:Lbb/b;

.field public static final L:Lbb/b;

.field public static final M:Lbb/b;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    const-string v0, "android:changeBounds:windowX"

    .line 2
    .line 3
    const-string v1, "android:changeBounds:windowY"

    .line 4
    .line 5
    const-string v2, "android:changeBounds:bounds"

    .line 6
    .line 7
    const-string v3, "android:changeBounds:clip"

    .line 8
    .line 9
    const-string v4, "android:changeBounds:parent"

    .line 10
    .line 11
    filled-new-array {v2, v3, v4, v0, v1}, [Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lbb/f;->H:[Ljava/lang/String;

    .line 16
    .line 17
    new-instance v0, Lbb/b;

    .line 18
    .line 19
    const/4 v1, 0x0

    .line 20
    const-string v2, "topLeft"

    .line 21
    .line 22
    const-class v3, Landroid/graphics/PointF;

    .line 23
    .line 24
    invoke-direct {v0, v1, v2, v3}, Lbb/b;-><init>(ILjava/lang/String;Ljava/lang/Class;)V

    .line 25
    .line 26
    .line 27
    sput-object v0, Lbb/f;->I:Lbb/b;

    .line 28
    .line 29
    new-instance v0, Lbb/b;

    .line 30
    .line 31
    const/4 v1, 0x1

    .line 32
    const-string v4, "bottomRight"

    .line 33
    .line 34
    invoke-direct {v0, v1, v4, v3}, Lbb/b;-><init>(ILjava/lang/String;Ljava/lang/Class;)V

    .line 35
    .line 36
    .line 37
    sput-object v0, Lbb/f;->J:Lbb/b;

    .line 38
    .line 39
    new-instance v0, Lbb/b;

    .line 40
    .line 41
    const/4 v1, 0x2

    .line 42
    invoke-direct {v0, v1, v4, v3}, Lbb/b;-><init>(ILjava/lang/String;Ljava/lang/Class;)V

    .line 43
    .line 44
    .line 45
    sput-object v0, Lbb/f;->K:Lbb/b;

    .line 46
    .line 47
    new-instance v0, Lbb/b;

    .line 48
    .line 49
    const/4 v1, 0x3

    .line 50
    invoke-direct {v0, v1, v2, v3}, Lbb/b;-><init>(ILjava/lang/String;Ljava/lang/Class;)V

    .line 51
    .line 52
    .line 53
    sput-object v0, Lbb/f;->L:Lbb/b;

    .line 54
    .line 55
    new-instance v0, Lbb/b;

    .line 56
    .line 57
    const-string v1, "position"

    .line 58
    .line 59
    const/4 v2, 0x4

    .line 60
    invoke-direct {v0, v2, v1, v3}, Lbb/b;-><init>(ILjava/lang/String;Ljava/lang/Class;)V

    .line 61
    .line 62
    .line 63
    sput-object v0, Lbb/f;->M:Lbb/b;

    .line 64
    .line 65
    return-void
.end method

.method public static O(Lbb/f0;)V
    .locals 6

    .line 1
    iget-object v0, p0, Lbb/f0;->b:Landroid/view/View;

    .line 2
    .line 3
    iget-object p0, p0, Lbb/f0;->a:Ljava/util/HashMap;

    .line 4
    .line 5
    invoke-virtual {v0}, Landroid/view/View;->isLaidOut()Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-nez v1, :cond_1

    .line 10
    .line 11
    invoke-virtual {v0}, Landroid/view/View;->getWidth()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-nez v1, :cond_1

    .line 16
    .line 17
    invoke-virtual {v0}, Landroid/view/View;->getHeight()I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    return-void

    .line 25
    :cond_1
    :goto_0
    new-instance v1, Landroid/graphics/Rect;

    .line 26
    .line 27
    invoke-virtual {v0}, Landroid/view/View;->getLeft()I

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    invoke-virtual {v0}, Landroid/view/View;->getTop()I

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    invoke-virtual {v0}, Landroid/view/View;->getRight()I

    .line 36
    .line 37
    .line 38
    move-result v4

    .line 39
    invoke-virtual {v0}, Landroid/view/View;->getBottom()I

    .line 40
    .line 41
    .line 42
    move-result v5

    .line 43
    invoke-direct {v1, v2, v3, v4, v5}, Landroid/graphics/Rect;-><init>(IIII)V

    .line 44
    .line 45
    .line 46
    const-string v2, "android:changeBounds:bounds"

    .line 47
    .line 48
    invoke-virtual {p0, v2, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    const-string v1, "android:changeBounds:parent"

    .line 52
    .line 53
    invoke-virtual {v0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    invoke-virtual {p0, v1, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    return-void
.end method


# virtual methods
.method public final d(Lbb/f0;)V
    .locals 0

    .line 1
    invoke-static {p1}, Lbb/f;->O(Lbb/f0;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final h(Lbb/f0;)V
    .locals 0

    .line 1
    invoke-static {p1}, Lbb/f;->O(Lbb/f0;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final l(Landroid/view/ViewGroup;Lbb/f0;Lbb/f0;)Landroid/animation/Animator;
    .locals 18

    .line 1
    move-object/from16 v1, p2

    .line 2
    .line 3
    move-object/from16 v2, p3

    .line 4
    .line 5
    if-eqz v1, :cond_11

    .line 6
    .line 7
    iget-object v1, v1, Lbb/f0;->a:Ljava/util/HashMap;

    .line 8
    .line 9
    if-nez v2, :cond_0

    .line 10
    .line 11
    goto/16 :goto_5

    .line 12
    .line 13
    :cond_0
    iget-object v3, v2, Lbb/f0;->a:Ljava/util/HashMap;

    .line 14
    .line 15
    const-string v4, "android:changeBounds:parent"

    .line 16
    .line 17
    invoke-virtual {v1, v4}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v5

    .line 21
    check-cast v5, Landroid/view/ViewGroup;

    .line 22
    .line 23
    invoke-virtual {v3, v4}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v4

    .line 27
    check-cast v4, Landroid/view/ViewGroup;

    .line 28
    .line 29
    if-eqz v5, :cond_11

    .line 30
    .line 31
    if-nez v4, :cond_1

    .line 32
    .line 33
    goto/16 :goto_5

    .line 34
    .line 35
    :cond_1
    iget-object v2, v2, Lbb/f0;->b:Landroid/view/View;

    .line 36
    .line 37
    const-string v4, "android:changeBounds:bounds"

    .line 38
    .line 39
    invoke-virtual {v1, v4}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v5

    .line 43
    check-cast v5, Landroid/graphics/Rect;

    .line 44
    .line 45
    invoke-virtual {v3, v4}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v4

    .line 49
    check-cast v4, Landroid/graphics/Rect;

    .line 50
    .line 51
    iget v6, v5, Landroid/graphics/Rect;->left:I

    .line 52
    .line 53
    iget v7, v4, Landroid/graphics/Rect;->left:I

    .line 54
    .line 55
    iget v8, v5, Landroid/graphics/Rect;->top:I

    .line 56
    .line 57
    iget v9, v4, Landroid/graphics/Rect;->top:I

    .line 58
    .line 59
    iget v10, v5, Landroid/graphics/Rect;->right:I

    .line 60
    .line 61
    iget v11, v4, Landroid/graphics/Rect;->right:I

    .line 62
    .line 63
    iget v5, v5, Landroid/graphics/Rect;->bottom:I

    .line 64
    .line 65
    iget v4, v4, Landroid/graphics/Rect;->bottom:I

    .line 66
    .line 67
    sub-int v12, v10, v6

    .line 68
    .line 69
    sub-int v13, v5, v8

    .line 70
    .line 71
    sub-int v14, v11, v7

    .line 72
    .line 73
    sub-int v15, v4, v9

    .line 74
    .line 75
    const-string v0, "android:changeBounds:clip"

    .line 76
    .line 77
    invoke-virtual {v1, v0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v1

    .line 81
    check-cast v1, Landroid/graphics/Rect;

    .line 82
    .line 83
    invoke-virtual {v3, v0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    check-cast v0, Landroid/graphics/Rect;

    .line 88
    .line 89
    const/16 p1, 0x0

    .line 90
    .line 91
    const/4 v3, 0x1

    .line 92
    if-eqz v12, :cond_2

    .line 93
    .line 94
    if-nez v13, :cond_3

    .line 95
    .line 96
    :cond_2
    if-eqz v14, :cond_7

    .line 97
    .line 98
    if-eqz v15, :cond_7

    .line 99
    .line 100
    :cond_3
    if-ne v6, v7, :cond_5

    .line 101
    .line 102
    if-eq v8, v9, :cond_4

    .line 103
    .line 104
    goto :goto_0

    .line 105
    :cond_4
    move/from16 v16, p1

    .line 106
    .line 107
    goto :goto_1

    .line 108
    :cond_5
    :goto_0
    move/from16 v16, v3

    .line 109
    .line 110
    :goto_1
    if-ne v10, v11, :cond_6

    .line 111
    .line 112
    if-eq v5, v4, :cond_8

    .line 113
    .line 114
    :cond_6
    add-int/lit8 v16, v16, 0x1

    .line 115
    .line 116
    goto :goto_2

    .line 117
    :cond_7
    move/from16 v16, p1

    .line 118
    .line 119
    :cond_8
    :goto_2
    if-eqz v1, :cond_9

    .line 120
    .line 121
    invoke-virtual {v1, v0}, Landroid/graphics/Rect;->equals(Ljava/lang/Object;)Z

    .line 122
    .line 123
    .line 124
    move-result v17

    .line 125
    if-eqz v17, :cond_a

    .line 126
    .line 127
    :cond_9
    if-nez v1, :cond_b

    .line 128
    .line 129
    if-eqz v0, :cond_b

    .line 130
    .line 131
    :cond_a
    add-int/lit8 v16, v16, 0x1

    .line 132
    .line 133
    :cond_b
    move/from16 v0, v16

    .line 134
    .line 135
    if-lez v0, :cond_11

    .line 136
    .line 137
    sget-object v1, Lbb/i0;->a:Lbb/b;

    .line 138
    .line 139
    invoke-virtual {v2, v6, v8, v10, v5}, Landroid/view/View;->setLeftTopRightBottom(IIII)V

    .line 140
    .line 141
    .line 142
    const/4 v1, 0x2

    .line 143
    if-ne v0, v1, :cond_d

    .line 144
    .line 145
    if-ne v12, v14, :cond_c

    .line 146
    .line 147
    if-ne v13, v15, :cond_c

    .line 148
    .line 149
    move-object/from16 v0, p0

    .line 150
    .line 151
    iget-object v1, v0, Lbb/x;->z:Lgv/a;

    .line 152
    .line 153
    int-to-float v4, v6

    .line 154
    int-to-float v5, v8

    .line 155
    int-to-float v6, v7

    .line 156
    int-to-float v7, v9

    .line 157
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 158
    .line 159
    .line 160
    invoke-static {v4, v5, v6, v7}, Lgv/a;->i(FFFF)Landroid/graphics/Path;

    .line 161
    .line 162
    .line 163
    move-result-object v1

    .line 164
    sget-object v4, Lbb/f;->M:Lbb/b;

    .line 165
    .line 166
    invoke-static {v2, v4, v1}, Lbb/o;->a(Ljava/lang/Object;Landroid/util/Property;Landroid/graphics/Path;)Landroid/animation/ObjectAnimator;

    .line 167
    .line 168
    .line 169
    move-result-object v1

    .line 170
    goto/16 :goto_4

    .line 171
    .line 172
    :cond_c
    move-object/from16 v0, p0

    .line 173
    .line 174
    new-instance v12, Lbb/e;

    .line 175
    .line 176
    invoke-direct {v12, v2}, Lbb/e;-><init>(Landroid/view/View;)V

    .line 177
    .line 178
    .line 179
    iget-object v13, v0, Lbb/x;->z:Lgv/a;

    .line 180
    .line 181
    int-to-float v6, v6

    .line 182
    int-to-float v8, v8

    .line 183
    int-to-float v7, v7

    .line 184
    int-to-float v9, v9

    .line 185
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 186
    .line 187
    .line 188
    invoke-static {v6, v8, v7, v9}, Lgv/a;->i(FFFF)Landroid/graphics/Path;

    .line 189
    .line 190
    .line 191
    move-result-object v6

    .line 192
    sget-object v7, Lbb/f;->I:Lbb/b;

    .line 193
    .line 194
    invoke-static {v12, v7, v6}, Lbb/o;->a(Ljava/lang/Object;Landroid/util/Property;Landroid/graphics/Path;)Landroid/animation/ObjectAnimator;

    .line 195
    .line 196
    .line 197
    move-result-object v6

    .line 198
    iget-object v7, v0, Lbb/x;->z:Lgv/a;

    .line 199
    .line 200
    int-to-float v8, v10

    .line 201
    int-to-float v5, v5

    .line 202
    int-to-float v9, v11

    .line 203
    int-to-float v4, v4

    .line 204
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 205
    .line 206
    .line 207
    invoke-static {v8, v5, v9, v4}, Lgv/a;->i(FFFF)Landroid/graphics/Path;

    .line 208
    .line 209
    .line 210
    move-result-object v4

    .line 211
    sget-object v5, Lbb/f;->J:Lbb/b;

    .line 212
    .line 213
    invoke-static {v12, v5, v4}, Lbb/o;->a(Ljava/lang/Object;Landroid/util/Property;Landroid/graphics/Path;)Landroid/animation/ObjectAnimator;

    .line 214
    .line 215
    .line 216
    move-result-object v4

    .line 217
    new-instance v5, Landroid/animation/AnimatorSet;

    .line 218
    .line 219
    invoke-direct {v5}, Landroid/animation/AnimatorSet;-><init>()V

    .line 220
    .line 221
    .line 222
    new-array v1, v1, [Landroid/animation/Animator;

    .line 223
    .line 224
    aput-object v6, v1, p1

    .line 225
    .line 226
    aput-object v4, v1, v3

    .line 227
    .line 228
    invoke-virtual {v5, v1}, Landroid/animation/AnimatorSet;->playTogether([Landroid/animation/Animator;)V

    .line 229
    .line 230
    .line 231
    new-instance v1, Lbb/c;

    .line 232
    .line 233
    invoke-direct {v1, v12}, Lbb/c;-><init>(Lbb/e;)V

    .line 234
    .line 235
    .line 236
    invoke-virtual {v5, v1}, Landroid/animation/Animator;->addListener(Landroid/animation/Animator$AnimatorListener;)V

    .line 237
    .line 238
    .line 239
    move-object v1, v5

    .line 240
    goto :goto_4

    .line 241
    :cond_d
    move-object/from16 v0, p0

    .line 242
    .line 243
    if-ne v6, v7, :cond_f

    .line 244
    .line 245
    if-eq v8, v9, :cond_e

    .line 246
    .line 247
    goto :goto_3

    .line 248
    :cond_e
    iget-object v1, v0, Lbb/x;->z:Lgv/a;

    .line 249
    .line 250
    int-to-float v6, v10

    .line 251
    int-to-float v5, v5

    .line 252
    int-to-float v7, v11

    .line 253
    int-to-float v4, v4

    .line 254
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 255
    .line 256
    .line 257
    invoke-static {v6, v5, v7, v4}, Lgv/a;->i(FFFF)Landroid/graphics/Path;

    .line 258
    .line 259
    .line 260
    move-result-object v1

    .line 261
    sget-object v4, Lbb/f;->K:Lbb/b;

    .line 262
    .line 263
    invoke-static {v2, v4, v1}, Lbb/o;->a(Ljava/lang/Object;Landroid/util/Property;Landroid/graphics/Path;)Landroid/animation/ObjectAnimator;

    .line 264
    .line 265
    .line 266
    move-result-object v1

    .line 267
    goto :goto_4

    .line 268
    :cond_f
    :goto_3
    iget-object v1, v0, Lbb/x;->z:Lgv/a;

    .line 269
    .line 270
    int-to-float v4, v6

    .line 271
    int-to-float v5, v8

    .line 272
    int-to-float v6, v7

    .line 273
    int-to-float v7, v9

    .line 274
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 275
    .line 276
    .line 277
    invoke-static {v4, v5, v6, v7}, Lgv/a;->i(FFFF)Landroid/graphics/Path;

    .line 278
    .line 279
    .line 280
    move-result-object v1

    .line 281
    sget-object v4, Lbb/f;->L:Lbb/b;

    .line 282
    .line 283
    invoke-static {v2, v4, v1}, Lbb/o;->a(Ljava/lang/Object;Landroid/util/Property;Landroid/graphics/Path;)Landroid/animation/ObjectAnimator;

    .line 284
    .line 285
    .line 286
    move-result-object v1

    .line 287
    :goto_4
    invoke-virtual {v2}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 288
    .line 289
    .line 290
    move-result-object v4

    .line 291
    instance-of v4, v4, Landroid/view/ViewGroup;

    .line 292
    .line 293
    if-eqz v4, :cond_10

    .line 294
    .line 295
    invoke-virtual {v2}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 296
    .line 297
    .line 298
    move-result-object v2

    .line 299
    check-cast v2, Landroid/view/ViewGroup;

    .line 300
    .line 301
    invoke-static {v2, v3}, Lbb/h0;->b(Landroid/view/ViewGroup;Z)V

    .line 302
    .line 303
    .line 304
    invoke-virtual {v0}, Lbb/x;->p()Lbb/x;

    .line 305
    .line 306
    .line 307
    move-result-object v0

    .line 308
    new-instance v3, Lbb/d;

    .line 309
    .line 310
    invoke-direct {v3, v2}, Lbb/d;-><init>(Landroid/view/ViewGroup;)V

    .line 311
    .line 312
    .line 313
    invoke-virtual {v0, v3}, Lbb/x;->a(Lbb/v;)V

    .line 314
    .line 315
    .line 316
    :cond_10
    return-object v1

    .line 317
    :cond_11
    :goto_5
    const/4 v0, 0x0

    .line 318
    return-object v0
.end method

.method public final r()[Ljava/lang/String;
    .locals 0

    .line 1
    sget-object p0, Lbb/f;->H:[Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final u()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method
