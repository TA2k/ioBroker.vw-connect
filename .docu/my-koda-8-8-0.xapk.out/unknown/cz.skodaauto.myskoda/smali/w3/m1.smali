.class public final Lw3/m1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final f:Ley0/b;


# instance fields
.field public final a:Landroid/graphics/Rect;

.field public final b:Landroid/graphics/Rect;

.field public final c:Landroid/graphics/Rect;

.field public final d:Lw3/l1;

.field public final e:Ljava/util/ArrayList;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ley0/b;

    .line 2
    .line 3
    const/16 v1, 0xa

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ley0/b;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lw3/m1;->f:Ley0/b;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Landroid/graphics/Rect;

    .line 5
    .line 6
    invoke-direct {v0}, Landroid/graphics/Rect;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lw3/m1;->a:Landroid/graphics/Rect;

    .line 10
    .line 11
    new-instance v0, Landroid/graphics/Rect;

    .line 12
    .line 13
    invoke-direct {v0}, Landroid/graphics/Rect;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lw3/m1;->b:Landroid/graphics/Rect;

    .line 17
    .line 18
    new-instance v0, Landroid/graphics/Rect;

    .line 19
    .line 20
    invoke-direct {v0}, Landroid/graphics/Rect;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Lw3/m1;->c:Landroid/graphics/Rect;

    .line 24
    .line 25
    new-instance v0, Lw3/l1;

    .line 26
    .line 27
    new-instance v1, Lt0/c;

    .line 28
    .line 29
    const/16 v2, 0x11

    .line 30
    .line 31
    invoke-direct {v1, p0, v2}, Lt0/c;-><init>(Ljava/lang/Object;I)V

    .line 32
    .line 33
    .line 34
    invoke-direct {v0, v1}, Lw3/l1;-><init>(Lt0/c;)V

    .line 35
    .line 36
    .line 37
    iput-object v0, p0, Lw3/m1;->d:Lw3/l1;

    .line 38
    .line 39
    new-instance v0, Ljava/util/ArrayList;

    .line 40
    .line 41
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 42
    .line 43
    .line 44
    iput-object v0, p0, Lw3/m1;->e:Ljava/util/ArrayList;

    .line 45
    .line 46
    return-void
.end method

.method public static d(Landroid/view/ViewGroup;Landroid/graphics/Rect;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->getScrollY()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    add-int/2addr v1, v0

    .line 10
    invoke-virtual {p0}, Landroid/view/View;->getScrollX()I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    add-int/2addr p0, v0

    .line 19
    invoke-virtual {p1, p0, v1, p0, v1}, Landroid/graphics/Rect;->set(IIII)V

    .line 20
    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final a(ILandroid/graphics/Rect;Landroid/view/View;Landroid/view/ViewGroup;Ljava/util/ArrayList;)Landroid/view/View;
    .locals 11

    .line 1
    const/16 v0, 0x82

    .line 2
    .line 3
    const/16 v1, 0x42

    .line 4
    .line 5
    const/16 v2, 0x21

    .line 6
    .line 7
    const/16 v5, 0x11

    .line 8
    .line 9
    const/4 v6, 0x2

    .line 10
    const/4 v7, 0x1

    .line 11
    iget-object v8, p0, Lw3/m1;->a:Landroid/graphics/Rect;

    .line 12
    .line 13
    if-eqz p3, :cond_0

    .line 14
    .line 15
    invoke-virtual {p3, v8}, Landroid/view/View;->getFocusedRect(Landroid/graphics/Rect;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p4, p3, v8}, Landroid/view/ViewGroup;->offsetDescendantRectToMyCoords(Landroid/view/View;Landroid/graphics/Rect;)V

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    if-eqz p2, :cond_1

    .line 23
    .line 24
    invoke-virtual {v8, p2}, Landroid/graphics/Rect;->set(Landroid/graphics/Rect;)V

    .line 25
    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_1
    if-eq p1, v7, :cond_6

    .line 29
    .line 30
    if-eq p1, v6, :cond_4

    .line 31
    .line 32
    if-eq p1, v5, :cond_3

    .line 33
    .line 34
    if-eq p1, v2, :cond_3

    .line 35
    .line 36
    if-eq p1, v1, :cond_2

    .line 37
    .line 38
    if-eq p1, v0, :cond_2

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_2
    invoke-virtual {p4}, Landroid/view/View;->getScrollY()I

    .line 42
    .line 43
    .line 44
    move-result p2

    .line 45
    invoke-virtual {p4}, Landroid/view/View;->getScrollX()I

    .line 46
    .line 47
    .line 48
    move-result v9

    .line 49
    invoke-virtual {v8, v9, p2, v9, p2}, Landroid/graphics/Rect;->set(IIII)V

    .line 50
    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_3
    invoke-static {p4, v8}, Lw3/m1;->d(Landroid/view/ViewGroup;Landroid/graphics/Rect;)V

    .line 54
    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_4
    invoke-virtual {p4}, Landroid/view/View;->getLayoutDirection()I

    .line 58
    .line 59
    .line 60
    move-result p2

    .line 61
    if-ne p2, v7, :cond_5

    .line 62
    .line 63
    invoke-static {p4, v8}, Lw3/m1;->d(Landroid/view/ViewGroup;Landroid/graphics/Rect;)V

    .line 64
    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_5
    invoke-virtual {p4}, Landroid/view/View;->getScrollY()I

    .line 68
    .line 69
    .line 70
    move-result p2

    .line 71
    invoke-virtual {p4}, Landroid/view/View;->getScrollX()I

    .line 72
    .line 73
    .line 74
    move-result v9

    .line 75
    invoke-virtual {v8, v9, p2, v9, p2}, Landroid/graphics/Rect;->set(IIII)V

    .line 76
    .line 77
    .line 78
    goto :goto_0

    .line 79
    :cond_6
    invoke-virtual {p4}, Landroid/view/View;->getLayoutDirection()I

    .line 80
    .line 81
    .line 82
    move-result p2

    .line 83
    if-ne p2, v7, :cond_7

    .line 84
    .line 85
    invoke-virtual {p4}, Landroid/view/View;->getScrollY()I

    .line 86
    .line 87
    .line 88
    move-result p2

    .line 89
    invoke-virtual {p4}, Landroid/view/View;->getScrollX()I

    .line 90
    .line 91
    .line 92
    move-result v9

    .line 93
    invoke-virtual {v8, v9, p2, v9, p2}, Landroid/graphics/Rect;->set(IIII)V

    .line 94
    .line 95
    .line 96
    goto :goto_0

    .line 97
    :cond_7
    invoke-static {p4, v8}, Lw3/m1;->d(Landroid/view/ViewGroup;Landroid/graphics/Rect;)V

    .line 98
    .line 99
    .line 100
    :goto_0
    if-eq p1, v7, :cond_a

    .line 101
    .line 102
    if-eq p1, v6, :cond_a

    .line 103
    .line 104
    if-eq p1, v5, :cond_8

    .line 105
    .line 106
    if-eq p1, v2, :cond_8

    .line 107
    .line 108
    if-eq p1, v1, :cond_8

    .line 109
    .line 110
    if-ne p1, v0, :cond_9

    .line 111
    .line 112
    :cond_8
    move-object v0, p0

    .line 113
    move v1, p1

    .line 114
    move-object v3, p3

    .line 115
    move-object v4, p4

    .line 116
    move-object/from16 v5, p5

    .line 117
    .line 118
    move-object v2, v8

    .line 119
    goto :goto_1

    .line 120
    :cond_9
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 121
    .line 122
    const-string p2, "Unknown direction: "

    .line 123
    .line 124
    invoke-static {p1, p2}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object p1

    .line 128
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    throw p0

    .line 132
    :goto_1
    invoke-virtual/range {v0 .. v5}, Lw3/m1;->c(ILandroid/graphics/Rect;Landroid/view/View;Landroid/view/ViewGroup;Ljava/util/ArrayList;)Landroid/view/View;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    return-object p0

    .line 137
    :cond_a
    move-object/from16 v8, p5

    .line 138
    .line 139
    iget-object v9, p0, Lw3/m1;->d:Lw3/l1;

    .line 140
    .line 141
    :try_start_0
    invoke-virtual {v9, v8, p4}, Lw3/l1;->a(Ljava/util/ArrayList;Landroid/view/ViewGroup;)V

    .line 142
    .line 143
    .line 144
    invoke-static {v8, v9}, Ljava/util/Collections;->sort(Ljava/util/List;Ljava/util/Comparator;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 145
    .line 146
    .line 147
    iget-object v10, v9, Lw3/l1;->f:Landroidx/collection/q0;

    .line 148
    .line 149
    invoke-virtual {v10}, Landroidx/collection/q0;->a()V

    .line 150
    .line 151
    .line 152
    iget-object v10, v9, Lw3/l1;->e:Landroidx/collection/r0;

    .line 153
    .line 154
    invoke-virtual {v10}, Landroidx/collection/r0;->b()V

    .line 155
    .line 156
    .line 157
    iget-object v10, v9, Lw3/l1;->g:Landroidx/collection/h0;

    .line 158
    .line 159
    invoke-virtual {v10}, Landroidx/collection/h0;->a()V

    .line 160
    .line 161
    .line 162
    iget-object v9, v9, Lw3/l1;->d:Landroidx/collection/q0;

    .line 163
    .line 164
    invoke-virtual {v9}, Landroidx/collection/q0;->a()V

    .line 165
    .line 166
    .line 167
    invoke-virtual {v8}, Ljava/util/ArrayList;->size()I

    .line 168
    .line 169
    .line 170
    move-result v9

    .line 171
    const/4 v10, 0x0

    .line 172
    if-ge v9, v6, :cond_b

    .line 173
    .line 174
    return-object v10

    .line 175
    :cond_b
    if-eq p1, v7, :cond_10

    .line 176
    .line 177
    if-eq p1, v6, :cond_d

    .line 178
    .line 179
    if-eq p1, v5, :cond_c

    .line 180
    .line 181
    if-eq p1, v2, :cond_c

    .line 182
    .line 183
    if-eq p1, v1, :cond_c

    .line 184
    .line 185
    if-eq p1, v0, :cond_c

    .line 186
    .line 187
    move-object v5, v8

    .line 188
    goto :goto_2

    .line 189
    :cond_c
    iget-object v2, p0, Lw3/m1;->a:Landroid/graphics/Rect;

    .line 190
    .line 191
    move-object v0, p0

    .line 192
    move v1, p1

    .line 193
    move-object v3, p3

    .line 194
    move-object v4, p4

    .line 195
    move-object v5, v8

    .line 196
    invoke-virtual/range {v0 .. v5}, Lw3/m1;->c(ILandroid/graphics/Rect;Landroid/view/View;Landroid/view/ViewGroup;Ljava/util/ArrayList;)Landroid/view/View;

    .line 197
    .line 198
    .line 199
    move-result-object v10

    .line 200
    goto :goto_2

    .line 201
    :cond_d
    move-object v5, v8

    .line 202
    if-ge v9, v6, :cond_e

    .line 203
    .line 204
    goto :goto_2

    .line 205
    :cond_e
    if-eqz p3, :cond_f

    .line 206
    .line 207
    invoke-virtual {v5, p3}, Ljava/util/ArrayList;->lastIndexOf(Ljava/lang/Object;)I

    .line 208
    .line 209
    .line 210
    move-result p0

    .line 211
    if-ltz p0, :cond_f

    .line 212
    .line 213
    add-int/2addr p0, v7

    .line 214
    if-ge p0, v9, :cond_f

    .line 215
    .line 216
    invoke-virtual {v5, p0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 217
    .line 218
    .line 219
    move-result-object p0

    .line 220
    move-object v10, p0

    .line 221
    check-cast v10, Landroid/view/View;

    .line 222
    .line 223
    goto :goto_2

    .line 224
    :cond_f
    const/4 p0, 0x0

    .line 225
    invoke-virtual {v5, p0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 226
    .line 227
    .line 228
    move-result-object p0

    .line 229
    move-object v10, p0

    .line 230
    check-cast v10, Landroid/view/View;

    .line 231
    .line 232
    goto :goto_2

    .line 233
    :cond_10
    move-object v5, v8

    .line 234
    if-ge v9, v6, :cond_11

    .line 235
    .line 236
    goto :goto_2

    .line 237
    :cond_11
    if-eqz p3, :cond_12

    .line 238
    .line 239
    invoke-virtual {v5, p3}, Ljava/util/ArrayList;->indexOf(Ljava/lang/Object;)I

    .line 240
    .line 241
    .line 242
    move-result p0

    .line 243
    if-lez p0, :cond_12

    .line 244
    .line 245
    sub-int/2addr p0, v7

    .line 246
    invoke-virtual {v5, p0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 247
    .line 248
    .line 249
    move-result-object p0

    .line 250
    move-object v10, p0

    .line 251
    check-cast v10, Landroid/view/View;

    .line 252
    .line 253
    goto :goto_2

    .line 254
    :cond_12
    add-int/lit8 p0, v9, -0x1

    .line 255
    .line 256
    invoke-virtual {v5, p0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 257
    .line 258
    .line 259
    move-result-object p0

    .line 260
    move-object v10, p0

    .line 261
    check-cast v10, Landroid/view/View;

    .line 262
    .line 263
    :goto_2
    if-nez v10, :cond_13

    .line 264
    .line 265
    sub-int/2addr v9, v7

    .line 266
    invoke-virtual {v5, v9}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 267
    .line 268
    .line 269
    move-result-object p0

    .line 270
    check-cast p0, Landroid/view/View;

    .line 271
    .line 272
    return-object p0

    .line 273
    :cond_13
    return-object v10

    .line 274
    :catchall_0
    move-exception v0

    .line 275
    move-object p0, v0

    .line 276
    iget-object p1, v9, Lw3/l1;->f:Landroidx/collection/q0;

    .line 277
    .line 278
    invoke-virtual {p1}, Landroidx/collection/q0;->a()V

    .line 279
    .line 280
    .line 281
    iget-object p1, v9, Lw3/l1;->e:Landroidx/collection/r0;

    .line 282
    .line 283
    invoke-virtual {p1}, Landroidx/collection/r0;->b()V

    .line 284
    .line 285
    .line 286
    iget-object p1, v9, Lw3/l1;->g:Landroidx/collection/h0;

    .line 287
    .line 288
    invoke-virtual {p1}, Landroidx/collection/h0;->a()V

    .line 289
    .line 290
    .line 291
    iget-object p1, v9, Lw3/l1;->d:Landroidx/collection/q0;

    .line 292
    .line 293
    invoke-virtual {p1}, Landroidx/collection/q0;->a()V

    .line 294
    .line 295
    .line 296
    throw p0
.end method

.method public final b(ILandroid/view/View;Landroid/view/ViewGroup;)Landroid/view/View;
    .locals 9

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p2, :cond_4

    .line 3
    .line 4
    if-ne p2, p3, :cond_0

    .line 5
    .line 6
    goto :goto_1

    .line 7
    :cond_0
    invoke-virtual {p2}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    move-object v2, v0

    .line 12
    :goto_0
    instance-of v3, v1, Landroid/view/ViewGroup;

    .line 13
    .line 14
    if-eqz v3, :cond_4

    .line 15
    .line 16
    if-ne v1, p3, :cond_2

    .line 17
    .line 18
    if-nez v2, :cond_1

    .line 19
    .line 20
    goto :goto_1

    .line 21
    :cond_1
    move-object v7, v2

    .line 22
    goto :goto_2

    .line 23
    :cond_2
    check-cast v1, Landroid/view/ViewGroup;

    .line 24
    .line 25
    invoke-virtual {v1}, Landroid/view/ViewGroup;->getTouchscreenBlocksFocus()Z

    .line 26
    .line 27
    .line 28
    move-result v3

    .line 29
    if-eqz v3, :cond_3

    .line 30
    .line 31
    invoke-virtual {p2}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 32
    .line 33
    .line 34
    move-result-object v3

    .line 35
    invoke-virtual {v3}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    const-string v4, "android.hardware.touchscreen"

    .line 40
    .line 41
    invoke-virtual {v3, v4}, Landroid/content/pm/PackageManager;->hasSystemFeature(Ljava/lang/String;)Z

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    if-eqz v3, :cond_3

    .line 46
    .line 47
    move-object v2, v1

    .line 48
    :cond_3
    invoke-virtual {v1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    goto :goto_0

    .line 53
    :cond_4
    :goto_1
    move-object v7, p3

    .line 54
    :goto_2
    invoke-static {p2, v7, p1}, Lw3/h0;->j(Landroid/view/View;Landroid/view/View;I)Landroid/view/View;

    .line 55
    .line 56
    .line 57
    move-result-object p3

    .line 58
    const/4 v1, 0x1

    .line 59
    move v2, v1

    .line 60
    move-object v1, p3

    .line 61
    :goto_3
    if-eqz p3, :cond_9

    .line 62
    .line 63
    invoke-virtual {p3}, Landroid/view/View;->isFocusable()Z

    .line 64
    .line 65
    .line 66
    move-result v3

    .line 67
    if-eqz v3, :cond_6

    .line 68
    .line 69
    invoke-virtual {p3}, Landroid/view/View;->getVisibility()I

    .line 70
    .line 71
    .line 72
    move-result v3

    .line 73
    if-nez v3, :cond_6

    .line 74
    .line 75
    invoke-virtual {p3}, Landroid/view/View;->isInTouchMode()Z

    .line 76
    .line 77
    .line 78
    move-result v3

    .line 79
    if-eqz v3, :cond_5

    .line 80
    .line 81
    invoke-virtual {p3}, Landroid/view/View;->isFocusableInTouchMode()Z

    .line 82
    .line 83
    .line 84
    move-result v3

    .line 85
    if-eqz v3, :cond_6

    .line 86
    .line 87
    :cond_5
    move-object v0, p3

    .line 88
    goto :goto_5

    .line 89
    :cond_6
    invoke-static {p3, v7, p1}, Lw3/h0;->j(Landroid/view/View;Landroid/view/View;I)Landroid/view/View;

    .line 90
    .line 91
    .line 92
    move-result-object p3

    .line 93
    xor-int/lit8 v3, v2, 0x1

    .line 94
    .line 95
    if-nez v2, :cond_8

    .line 96
    .line 97
    if-eqz v1, :cond_7

    .line 98
    .line 99
    invoke-static {v1, v7, p1}, Lw3/h0;->j(Landroid/view/View;Landroid/view/View;I)Landroid/view/View;

    .line 100
    .line 101
    .line 102
    move-result-object v1

    .line 103
    goto :goto_4

    .line 104
    :cond_7
    move-object v1, v0

    .line 105
    :goto_4
    if-ne v1, p3, :cond_8

    .line 106
    .line 107
    goto :goto_5

    .line 108
    :cond_8
    move v2, v3

    .line 109
    goto :goto_3

    .line 110
    :cond_9
    :goto_5
    if-eqz v0, :cond_a

    .line 111
    .line 112
    return-object v0

    .line 113
    :cond_a
    iget-object v8, p0, Lw3/m1;->e:Ljava/util/ArrayList;

    .line 114
    .line 115
    :try_start_0
    invoke-virtual {v8}, Ljava/util/ArrayList;->clear()V

    .line 116
    .line 117
    .line 118
    invoke-virtual {v7}, Landroid/view/View;->isInTouchMode()Z

    .line 119
    .line 120
    .line 121
    move-result p3

    .line 122
    invoke-virtual {v7, v8, p1, p3}, Landroid/view/View;->addFocusables(Ljava/util/ArrayList;II)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {v8}, Ljava/util/ArrayList;->isEmpty()Z

    .line 126
    .line 127
    .line 128
    move-result p3

    .line 129
    if-nez p3, :cond_b

    .line 130
    .line 131
    const/4 v5, 0x0

    .line 132
    move-object v3, p0

    .line 133
    move v4, p1

    .line 134
    move-object v6, p2

    .line 135
    invoke-virtual/range {v3 .. v8}, Lw3/m1;->a(ILandroid/graphics/Rect;Landroid/view/View;Landroid/view/ViewGroup;Ljava/util/ArrayList;)Landroid/view/View;

    .line 136
    .line 137
    .line 138
    move-result-object v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 139
    goto :goto_6

    .line 140
    :catchall_0
    move-exception v0

    .line 141
    move-object p0, v0

    .line 142
    goto :goto_7

    .line 143
    :cond_b
    :goto_6
    invoke-virtual {v8}, Ljava/util/ArrayList;->clear()V

    .line 144
    .line 145
    .line 146
    return-object v0

    .line 147
    :goto_7
    invoke-virtual {v8}, Ljava/util/ArrayList;->clear()V

    .line 148
    .line 149
    .line 150
    throw p0
.end method

.method public final c(ILandroid/graphics/Rect;Landroid/view/View;Landroid/view/ViewGroup;Ljava/util/ArrayList;)Landroid/view/View;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p4

    .line 6
    .line 7
    iget-object v3, v0, Lw3/m1;->b:Landroid/graphics/Rect;

    .line 8
    .line 9
    move-object/from16 v4, p2

    .line 10
    .line 11
    invoke-virtual {v3, v4}, Landroid/graphics/Rect;->set(Landroid/graphics/Rect;)V

    .line 12
    .line 13
    .line 14
    const/16 v5, 0x11

    .line 15
    .line 16
    const/4 v6, 0x0

    .line 17
    const/4 v7, 0x1

    .line 18
    if-eq v1, v5, :cond_3

    .line 19
    .line 20
    const/16 v5, 0x21

    .line 21
    .line 22
    if-eq v1, v5, :cond_2

    .line 23
    .line 24
    const/16 v5, 0x42

    .line 25
    .line 26
    if-eq v1, v5, :cond_1

    .line 27
    .line 28
    const/16 v5, 0x82

    .line 29
    .line 30
    if-eq v1, v5, :cond_0

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    invoke-virtual {v4}, Landroid/graphics/Rect;->height()I

    .line 34
    .line 35
    .line 36
    move-result v5

    .line 37
    neg-int v5, v5

    .line 38
    sub-int/2addr v5, v7

    .line 39
    invoke-virtual {v3, v6, v5}, Landroid/graphics/Rect;->offset(II)V

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_1
    invoke-virtual {v4}, Landroid/graphics/Rect;->width()I

    .line 44
    .line 45
    .line 46
    move-result v5

    .line 47
    neg-int v5, v5

    .line 48
    sub-int/2addr v5, v7

    .line 49
    invoke-virtual {v3, v5, v6}, Landroid/graphics/Rect;->offset(II)V

    .line 50
    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_2
    invoke-virtual {v4}, Landroid/graphics/Rect;->height()I

    .line 54
    .line 55
    .line 56
    move-result v5

    .line 57
    add-int/2addr v5, v7

    .line 58
    invoke-virtual {v3, v6, v5}, Landroid/graphics/Rect;->offset(II)V

    .line 59
    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_3
    invoke-virtual {v4}, Landroid/graphics/Rect;->width()I

    .line 63
    .line 64
    .line 65
    move-result v5

    .line 66
    add-int/2addr v5, v7

    .line 67
    invoke-virtual {v3, v5, v6}, Landroid/graphics/Rect;->offset(II)V

    .line 68
    .line 69
    .line 70
    :goto_0
    invoke-interface/range {p5 .. p5}, Ljava/util/Collection;->size()I

    .line 71
    .line 72
    .line 73
    move-result v5

    .line 74
    const/4 v8, 0x0

    .line 75
    :goto_1
    if-ge v6, v5, :cond_6

    .line 76
    .line 77
    move-object/from16 v9, p5

    .line 78
    .line 79
    invoke-interface {v9, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v10

    .line 83
    check-cast v10, Landroid/view/View;

    .line 84
    .line 85
    move-object/from16 v11, p3

    .line 86
    .line 87
    invoke-static {v10, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    move-result v12

    .line 91
    if-nez v12, :cond_5

    .line 92
    .line 93
    invoke-static {v10, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    move-result v12

    .line 97
    if-nez v12, :cond_5

    .line 98
    .line 99
    iget-object v12, v0, Lw3/m1;->c:Landroid/graphics/Rect;

    .line 100
    .line 101
    invoke-virtual {v10, v12}, Landroid/view/View;->getFocusedRect(Landroid/graphics/Rect;)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {v2, v10, v12}, Landroid/view/ViewGroup;->offsetDescendantRectToMyCoords(Landroid/view/View;Landroid/graphics/Rect;)V

    .line 105
    .line 106
    .line 107
    invoke-static {v12}, Le3/j0;->B(Landroid/graphics/Rect;)Ld3/c;

    .line 108
    .line 109
    .line 110
    move-result-object v13

    .line 111
    invoke-static {v3}, Le3/j0;->B(Landroid/graphics/Rect;)Ld3/c;

    .line 112
    .line 113
    .line 114
    move-result-object v14

    .line 115
    invoke-static {v4}, Le3/j0;->B(Landroid/graphics/Rect;)Ld3/c;

    .line 116
    .line 117
    .line 118
    move-result-object v15

    .line 119
    invoke-static {v1}, Lc3/f;->D(I)Lc3/d;

    .line 120
    .line 121
    .line 122
    move-result-object v7

    .line 123
    if-eqz v7, :cond_4

    .line 124
    .line 125
    iget v7, v7, Lc3/d;->a:I

    .line 126
    .line 127
    goto :goto_2

    .line 128
    :cond_4
    const/4 v7, 0x1

    .line 129
    :goto_2
    invoke-static {v13, v14, v15, v7}, Lc3/f;->o(Ld3/c;Ld3/c;Ld3/c;I)Z

    .line 130
    .line 131
    .line 132
    move-result v7

    .line 133
    if-eqz v7, :cond_5

    .line 134
    .line 135
    invoke-virtual {v3, v12}, Landroid/graphics/Rect;->set(Landroid/graphics/Rect;)V

    .line 136
    .line 137
    .line 138
    move-object v8, v10

    .line 139
    :cond_5
    add-int/lit8 v6, v6, 0x1

    .line 140
    .line 141
    const/4 v7, 0x1

    .line 142
    goto :goto_1

    .line 143
    :cond_6
    return-object v8
.end method
