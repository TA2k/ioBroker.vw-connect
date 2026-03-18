.class public final Lg4/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Landroidx/lifecycle/c1;

.field public final b:I

.field public final c:Z

.field public final d:F

.field public final e:F

.field public final f:I

.field public final g:Ljava/util/ArrayList;

.field public final h:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>(Landroidx/lifecycle/c1;JII)V
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    iput-object v1, v0, Lg4/o;->a:Landroidx/lifecycle/c1;

    .line 9
    .line 10
    move/from16 v2, p4

    .line 11
    .line 12
    iput v2, v0, Lg4/o;->b:I

    .line 13
    .line 14
    invoke-static/range {p2 .. p3}, Lt4/a;->j(J)I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    if-nez v2, :cond_0

    .line 19
    .line 20
    invoke-static/range {p2 .. p3}, Lt4/a;->i(J)I

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-nez v2, :cond_0

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const-string v2, "Setting Constraints.minWidth and Constraints.minHeight is not supported, these should be the default zero values instead."

    .line 28
    .line 29
    invoke-static {v2}, Lm4/a;->a(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    :goto_0
    new-instance v2, Ljava/util/ArrayList;

    .line 33
    .line 34
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 35
    .line 36
    .line 37
    iget-object v1, v1, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast v1, Ljava/util/ArrayList;

    .line 40
    .line 41
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    const/4 v5, 0x0

    .line 46
    move v12, v5

    .line 47
    const/4 v5, 0x0

    .line 48
    const/4 v10, 0x0

    .line 49
    :goto_1
    if-ge v5, v3, :cond_6

    .line 50
    .line 51
    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v6

    .line 55
    check-cast v6, Lg4/r;

    .line 56
    .line 57
    iget-object v14, v6, Lg4/r;->a:Lo4/c;

    .line 58
    .line 59
    invoke-static/range {p2 .. p3}, Lt4/a;->h(J)I

    .line 60
    .line 61
    .line 62
    move-result v7

    .line 63
    invoke-static/range {p2 .. p3}, Lt4/a;->c(J)Z

    .line 64
    .line 65
    .line 66
    move-result v8

    .line 67
    if-eqz v8, :cond_1

    .line 68
    .line 69
    invoke-static/range {p2 .. p3}, Lt4/a;->g(J)I

    .line 70
    .line 71
    .line 72
    move-result v8

    .line 73
    move/from16 p4, v5

    .line 74
    .line 75
    float-to-double v4, v12

    .line 76
    invoke-static {v4, v5}, Ljava/lang/Math;->ceil(D)D

    .line 77
    .line 78
    .line 79
    move-result-wide v4

    .line 80
    double-to-float v4, v4

    .line 81
    float-to-int v4, v4

    .line 82
    sub-int/2addr v8, v4

    .line 83
    if-gez v8, :cond_2

    .line 84
    .line 85
    const/4 v8, 0x0

    .line 86
    goto :goto_2

    .line 87
    :cond_1
    move/from16 p4, v5

    .line 88
    .line 89
    invoke-static/range {p2 .. p3}, Lt4/a;->g(J)I

    .line 90
    .line 91
    .line 92
    move-result v8

    .line 93
    :cond_2
    :goto_2
    const/4 v4, 0x5

    .line 94
    invoke-static {v7, v8, v4}, Lt4/b;->b(III)J

    .line 95
    .line 96
    .line 97
    move-result-wide v17

    .line 98
    iget v4, v0, Lg4/o;->b:I

    .line 99
    .line 100
    sub-int v15, v4, v10

    .line 101
    .line 102
    new-instance v13, Lg4/a;

    .line 103
    .line 104
    move/from16 v16, p5

    .line 105
    .line 106
    invoke-direct/range {v13 .. v18}, Lg4/a;-><init>(Lo4/c;IIJ)V

    .line 107
    .line 108
    .line 109
    invoke-virtual {v13}, Lg4/a;->b()F

    .line 110
    .line 111
    .line 112
    move-result v4

    .line 113
    add-float/2addr v4, v12

    .line 114
    iget-object v5, v13, Lg4/a;->d:Lh4/j;

    .line 115
    .line 116
    iget v7, v5, Lh4/j;->g:I

    .line 117
    .line 118
    add-int v11, v10, v7

    .line 119
    .line 120
    new-instance v7, Lg4/q;

    .line 121
    .line 122
    iget v8, v6, Lg4/r;->b:I

    .line 123
    .line 124
    iget v9, v6, Lg4/r;->c:I

    .line 125
    .line 126
    move-object v6, v7

    .line 127
    move-object v7, v13

    .line 128
    move v13, v4

    .line 129
    invoke-direct/range {v6 .. v13}, Lg4/q;-><init>(Lg4/a;IIIIFF)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v2, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    iget-boolean v4, v5, Lh4/j;->d:Z

    .line 136
    .line 137
    if-nez v4, :cond_5

    .line 138
    .line 139
    iget v4, v0, Lg4/o;->b:I

    .line 140
    .line 141
    if-ne v11, v4, :cond_3

    .line 142
    .line 143
    iget-object v4, v0, Lg4/o;->a:Landroidx/lifecycle/c1;

    .line 144
    .line 145
    iget-object v4, v4, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 146
    .line 147
    check-cast v4, Ljava/util/ArrayList;

    .line 148
    .line 149
    invoke-static {v4}, Ljp/k1;->h(Ljava/util/List;)I

    .line 150
    .line 151
    .line 152
    move-result v4

    .line 153
    move/from16 v5, p4

    .line 154
    .line 155
    if-eq v5, v4, :cond_4

    .line 156
    .line 157
    goto :goto_3

    .line 158
    :cond_3
    move/from16 v5, p4

    .line 159
    .line 160
    :cond_4
    add-int/lit8 v5, v5, 0x1

    .line 161
    .line 162
    move v10, v11

    .line 163
    move v12, v13

    .line 164
    goto :goto_1

    .line 165
    :cond_5
    :goto_3
    const/4 v1, 0x1

    .line 166
    move v10, v11

    .line 167
    move v12, v13

    .line 168
    goto :goto_4

    .line 169
    :cond_6
    const/4 v1, 0x0

    .line 170
    :goto_4
    iput v12, v0, Lg4/o;->e:F

    .line 171
    .line 172
    iput v10, v0, Lg4/o;->f:I

    .line 173
    .line 174
    iput-boolean v1, v0, Lg4/o;->c:Z

    .line 175
    .line 176
    iput-object v2, v0, Lg4/o;->h:Ljava/util/ArrayList;

    .line 177
    .line 178
    invoke-static/range {p2 .. p3}, Lt4/a;->h(J)I

    .line 179
    .line 180
    .line 181
    move-result v1

    .line 182
    int-to-float v1, v1

    .line 183
    iput v1, v0, Lg4/o;->d:F

    .line 184
    .line 185
    new-instance v1, Ljava/util/ArrayList;

    .line 186
    .line 187
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 188
    .line 189
    .line 190
    move-result v3

    .line 191
    invoke-direct {v1, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 192
    .line 193
    .line 194
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 195
    .line 196
    .line 197
    move-result v3

    .line 198
    const/4 v4, 0x0

    .line 199
    :goto_5
    const/4 v5, 0x0

    .line 200
    if-ge v4, v3, :cond_9

    .line 201
    .line 202
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 203
    .line 204
    .line 205
    move-result-object v6

    .line 206
    check-cast v6, Lg4/q;

    .line 207
    .line 208
    iget-object v7, v6, Lg4/q;->a:Lg4/a;

    .line 209
    .line 210
    iget-object v7, v7, Lg4/a;->f:Ljava/lang/Object;

    .line 211
    .line 212
    new-instance v8, Ljava/util/ArrayList;

    .line 213
    .line 214
    invoke-interface {v7}, Ljava/util/List;->size()I

    .line 215
    .line 216
    .line 217
    move-result v9

    .line 218
    invoke-direct {v8, v9}, Ljava/util/ArrayList;-><init>(I)V

    .line 219
    .line 220
    .line 221
    move-object v9, v7

    .line 222
    check-cast v9, Ljava/util/Collection;

    .line 223
    .line 224
    invoke-interface {v9}, Ljava/util/Collection;->size()I

    .line 225
    .line 226
    .line 227
    move-result v9

    .line 228
    const/4 v10, 0x0

    .line 229
    :goto_6
    if-ge v10, v9, :cond_8

    .line 230
    .line 231
    invoke-interface {v7, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    move-result-object v11

    .line 235
    check-cast v11, Ld3/c;

    .line 236
    .line 237
    if-eqz v11, :cond_7

    .line 238
    .line 239
    invoke-virtual {v6, v11}, Lg4/q;->a(Ld3/c;)Ld3/c;

    .line 240
    .line 241
    .line 242
    move-result-object v11

    .line 243
    goto :goto_7

    .line 244
    :cond_7
    move-object v11, v5

    .line 245
    :goto_7
    invoke-virtual {v8, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 246
    .line 247
    .line 248
    add-int/lit8 v10, v10, 0x1

    .line 249
    .line 250
    goto :goto_6

    .line 251
    :cond_8
    invoke-static {v8, v1}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 252
    .line 253
    .line 254
    add-int/lit8 v4, v4, 0x1

    .line 255
    .line 256
    goto :goto_5

    .line 257
    :cond_9
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 258
    .line 259
    .line 260
    move-result v2

    .line 261
    iget-object v3, v0, Lg4/o;->a:Landroidx/lifecycle/c1;

    .line 262
    .line 263
    iget-object v3, v3, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 264
    .line 265
    check-cast v3, Ljava/util/List;

    .line 266
    .line 267
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 268
    .line 269
    .line 270
    move-result v3

    .line 271
    if-ge v2, v3, :cond_b

    .line 272
    .line 273
    iget-object v2, v0, Lg4/o;->a:Landroidx/lifecycle/c1;

    .line 274
    .line 275
    iget-object v2, v2, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 276
    .line 277
    check-cast v2, Ljava/util/List;

    .line 278
    .line 279
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 280
    .line 281
    .line 282
    move-result v2

    .line 283
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 284
    .line 285
    .line 286
    move-result v3

    .line 287
    sub-int/2addr v2, v3

    .line 288
    new-instance v3, Ljava/util/ArrayList;

    .line 289
    .line 290
    invoke-direct {v3, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 291
    .line 292
    .line 293
    const/4 v4, 0x0

    .line 294
    :goto_8
    if-ge v4, v2, :cond_a

    .line 295
    .line 296
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 297
    .line 298
    .line 299
    add-int/lit8 v4, v4, 0x1

    .line 300
    .line 301
    goto :goto_8

    .line 302
    :cond_a
    invoke-static {v3, v1}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 303
    .line 304
    .line 305
    move-result-object v1

    .line 306
    :cond_b
    iput-object v1, v0, Lg4/o;->g:Ljava/util/ArrayList;

    .line 307
    .line 308
    return-void
.end method

.method public static i(Lg4/o;Le3/r;JLe3/m0;Lr4/l;Lg3/e;)V
    .locals 10

    .line 1
    invoke-interface {p1}, Le3/r;->o()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lg4/o;->h:Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    const/4 v1, 0x0

    .line 11
    :goto_0
    if-ge v1, v0, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    check-cast v2, Lg4/q;

    .line 18
    .line 19
    iget-object v3, v2, Lg4/q;->a:Lg4/a;

    .line 20
    .line 21
    move-object v4, p1

    .line 22
    move-wide v5, p2

    .line 23
    move-object v7, p4

    .line 24
    move-object v8, p5

    .line 25
    move-object/from16 v9, p6

    .line 26
    .line 27
    invoke-virtual/range {v3 .. v9}, Lg4/a;->f(Le3/r;JLe3/m0;Lr4/l;Lg3/e;)V

    .line 28
    .line 29
    .line 30
    iget-object v2, v2, Lg4/q;->a:Lg4/a;

    .line 31
    .line 32
    invoke-virtual {v2}, Lg4/a;->b()F

    .line 33
    .line 34
    .line 35
    move-result v2

    .line 36
    const/4 v3, 0x0

    .line 37
    invoke-interface {p1, v3, v2}, Le3/r;->h(FF)V

    .line 38
    .line 39
    .line 40
    add-int/lit8 v1, v1, 0x1

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_0
    invoke-interface {p1}, Le3/r;->i()V

    .line 44
    .line 45
    .line 46
    return-void
.end method

.method public static j(Lg4/o;Le3/r;Le3/p;FLe3/m0;Lr4/l;Lg3/e;)V
    .locals 9

    .line 1
    invoke-interface {p1}, Le3/r;->o()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lg4/o;->h:Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    const/4 v2, 0x1

    .line 11
    if-gt v1, v2, :cond_0

    .line 12
    .line 13
    invoke-static/range {p0 .. p6}, Lo4/i;->a(Lg4/o;Le3/r;Le3/p;FLe3/m0;Lr4/l;Lg3/e;)V

    .line 14
    .line 15
    .line 16
    goto/16 :goto_2

    .line 17
    .line 18
    :cond_0
    instance-of v1, p2, Le3/p0;

    .line 19
    .line 20
    if-eqz v1, :cond_1

    .line 21
    .line 22
    invoke-static/range {p0 .. p6}, Lo4/i;->a(Lg4/o;Le3/r;Le3/p;FLe3/m0;Lr4/l;Lg3/e;)V

    .line 23
    .line 24
    .line 25
    goto/16 :goto_2

    .line 26
    .line 27
    :cond_1
    instance-of p0, p2, Le3/l0;

    .line 28
    .line 29
    if-eqz p0, :cond_4

    .line 30
    .line 31
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    const/4 v1, 0x0

    .line 36
    const/4 v2, 0x0

    .line 37
    move v3, v1

    .line 38
    move v4, v2

    .line 39
    move v5, v4

    .line 40
    :goto_0
    if-ge v3, p0, :cond_2

    .line 41
    .line 42
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v6

    .line 46
    check-cast v6, Lg4/q;

    .line 47
    .line 48
    iget-object v7, v6, Lg4/q;->a:Lg4/a;

    .line 49
    .line 50
    invoke-virtual {v7}, Lg4/a;->b()F

    .line 51
    .line 52
    .line 53
    move-result v7

    .line 54
    add-float/2addr v5, v7

    .line 55
    iget-object v6, v6, Lg4/q;->a:Lg4/a;

    .line 56
    .line 57
    invoke-virtual {v6}, Lg4/a;->d()F

    .line 58
    .line 59
    .line 60
    move-result v6

    .line 61
    invoke-static {v4, v6}, Ljava/lang/Math;->max(FF)F

    .line 62
    .line 63
    .line 64
    move-result v4

    .line 65
    add-int/lit8 v3, v3, 0x1

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_2
    check-cast p2, Le3/l0;

    .line 69
    .line 70
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 71
    .line 72
    .line 73
    move-result p0

    .line 74
    int-to-long v3, p0

    .line 75
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 76
    .line 77
    .line 78
    move-result p0

    .line 79
    int-to-long v5, p0

    .line 80
    const/16 p0, 0x20

    .line 81
    .line 82
    shl-long/2addr v3, p0

    .line 83
    const-wide v7, 0xffffffffL

    .line 84
    .line 85
    .line 86
    .line 87
    .line 88
    and-long/2addr v5, v7

    .line 89
    or-long/2addr v3, v5

    .line 90
    invoke-virtual {p2, v3, v4}, Le3/l0;->b(J)Landroid/graphics/Shader;

    .line 91
    .line 92
    .line 93
    move-result-object v3

    .line 94
    new-instance v4, Landroid/graphics/Matrix;

    .line 95
    .line 96
    invoke-direct {v4}, Landroid/graphics/Matrix;-><init>()V

    .line 97
    .line 98
    .line 99
    invoke-virtual {v3, v4}, Landroid/graphics/Shader;->getLocalMatrix(Landroid/graphics/Matrix;)Z

    .line 100
    .line 101
    .line 102
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 103
    .line 104
    .line 105
    move-result v5

    .line 106
    :goto_1
    if-ge v1, v5, :cond_3

    .line 107
    .line 108
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    check-cast p0, Lg4/q;

    .line 113
    .line 114
    iget-object p0, p0, Lg4/q;->a:Lg4/a;

    .line 115
    .line 116
    new-instance p2, Le3/q;

    .line 117
    .line 118
    invoke-direct {p2, v3}, Le3/q;-><init>(Landroid/graphics/Shader;)V

    .line 119
    .line 120
    .line 121
    invoke-virtual/range {p0 .. p6}, Lg4/a;->g(Le3/r;Le3/p;FLe3/m0;Lr4/l;Lg3/e;)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {p0}, Lg4/a;->b()F

    .line 125
    .line 126
    .line 127
    move-result p2

    .line 128
    invoke-interface {p1, v2, p2}, Le3/r;->h(FF)V

    .line 129
    .line 130
    .line 131
    invoke-virtual {p0}, Lg4/a;->b()F

    .line 132
    .line 133
    .line 134
    move-result p0

    .line 135
    neg-float p0, p0

    .line 136
    invoke-virtual {v4, v2, p0}, Landroid/graphics/Matrix;->setTranslate(FF)V

    .line 137
    .line 138
    .line 139
    invoke-virtual {v3, v4}, Landroid/graphics/Shader;->setLocalMatrix(Landroid/graphics/Matrix;)V

    .line 140
    .line 141
    .line 142
    add-int/lit8 v1, v1, 0x1

    .line 143
    .line 144
    goto :goto_1

    .line 145
    :cond_3
    :goto_2
    invoke-interface {p1}, Le3/r;->i()V

    .line 146
    .line 147
    .line 148
    return-void

    .line 149
    :cond_4
    new-instance p0, La8/r0;

    .line 150
    .line 151
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 152
    .line 153
    .line 154
    throw p0
.end method


# virtual methods
.method public final a(J[F)V
    .locals 7

    .line 1
    invoke-static {p1, p2}, Lg4/o0;->f(J)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p0, v0}, Lg4/o;->k(I)V

    .line 6
    .line 7
    .line 8
    invoke-static {p1, p2}, Lg4/o0;->e(J)I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    invoke-virtual {p0, v0}, Lg4/o;->l(I)V

    .line 13
    .line 14
    .line 15
    new-instance v5, Lkotlin/jvm/internal/d0;

    .line 16
    .line 17
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 18
    .line 19
    .line 20
    const/4 v0, 0x0

    .line 21
    iput v0, v5, Lkotlin/jvm/internal/d0;->d:I

    .line 22
    .line 23
    new-instance v6, Lkotlin/jvm/internal/c0;

    .line 24
    .line 25
    invoke-direct {v6}, Ljava/lang/Object;-><init>()V

    .line 26
    .line 27
    .line 28
    new-instance v1, Le1/r;

    .line 29
    .line 30
    move-wide v2, p1

    .line 31
    move-object v4, p3

    .line 32
    invoke-direct/range {v1 .. v6}, Le1/r;-><init>(J[FLkotlin/jvm/internal/d0;Lkotlin/jvm/internal/c0;)V

    .line 33
    .line 34
    .line 35
    iget-object p0, p0, Lg4/o;->h:Ljava/util/ArrayList;

    .line 36
    .line 37
    invoke-static {p0, v2, v3, v1}, Lg4/f0;->g(Ljava/util/ArrayList;JLay0/k;)V

    .line 38
    .line 39
    .line 40
    return-void
.end method

.method public final b(I)F
    .locals 2

    .line 1
    invoke-virtual {p0, p1}, Lg4/o;->m(I)V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lg4/o;->h:Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-static {p1, p0}, Lg4/f0;->e(ILjava/util/List;)I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lg4/q;

    .line 15
    .line 16
    iget-object v0, p0, Lg4/q;->a:Lg4/a;

    .line 17
    .line 18
    iget v1, p0, Lg4/q;->d:I

    .line 19
    .line 20
    sub-int/2addr p1, v1

    .line 21
    iget-object v0, v0, Lg4/a;->d:Lh4/j;

    .line 22
    .line 23
    invoke-virtual {v0, p1}, Lh4/j;->e(I)F

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    iget p0, p0, Lg4/q;->f:F

    .line 28
    .line 29
    add-float/2addr p1, p0

    .line 30
    return p1
.end method

.method public final c(IZ)I
    .locals 3

    .line 1
    invoke-virtual {p0, p1}, Lg4/o;->m(I)V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lg4/o;->h:Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-static {p1, p0}, Lg4/f0;->e(ILjava/util/List;)I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lg4/q;

    .line 15
    .line 16
    iget-object v0, p0, Lg4/q;->a:Lg4/a;

    .line 17
    .line 18
    iget v1, p0, Lg4/q;->d:I

    .line 19
    .line 20
    sub-int/2addr p1, v1

    .line 21
    iget-object v0, v0, Lg4/a;->d:Lh4/j;

    .line 22
    .line 23
    if-eqz p2, :cond_1

    .line 24
    .line 25
    iget-object p2, v0, Lh4/j;->f:Landroid/text/Layout;

    .line 26
    .line 27
    sget-object v1, Lh4/k;->a:Lh4/i;

    .line 28
    .line 29
    invoke-virtual {p2, p1}, Landroid/text/Layout;->getEllipsisCount(I)I

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-lez v1, :cond_0

    .line 34
    .line 35
    iget-object v1, v0, Lh4/j;->b:Landroid/text/TextUtils$TruncateAt;

    .line 36
    .line 37
    sget-object v2, Landroid/text/TextUtils$TruncateAt;->END:Landroid/text/TextUtils$TruncateAt;

    .line 38
    .line 39
    if-ne v1, v2, :cond_0

    .line 40
    .line 41
    invoke-virtual {p2, p1}, Landroid/text/Layout;->getLineStart(I)I

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    invoke-virtual {p2, p1}, Landroid/text/Layout;->getEllipsisStart(I)I

    .line 46
    .line 47
    .line 48
    move-result p1

    .line 49
    add-int/2addr p1, v0

    .line 50
    goto :goto_0

    .line 51
    :cond_0
    invoke-virtual {v0}, Lh4/j;->c()Landroidx/lifecycle/c1;

    .line 52
    .line 53
    .line 54
    move-result-object p2

    .line 55
    iget-object v0, p2, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast v0, Landroid/text/Layout;

    .line 58
    .line 59
    invoke-virtual {v0, p1}, Landroid/text/Layout;->getLineEnd(I)I

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    invoke-virtual {v0, p1}, Landroid/text/Layout;->getLineStart(I)I

    .line 64
    .line 65
    .line 66
    move-result p1

    .line 67
    invoke-virtual {p2, v1, p1}, Landroidx/lifecycle/c1;->B(II)I

    .line 68
    .line 69
    .line 70
    move-result p1

    .line 71
    goto :goto_0

    .line 72
    :cond_1
    invoke-virtual {v0, p1}, Lh4/j;->f(I)I

    .line 73
    .line 74
    .line 75
    move-result p1

    .line 76
    :goto_0
    iget p0, p0, Lg4/q;->b:I

    .line 77
    .line 78
    add-int/2addr p1, p0

    .line 79
    return p1
.end method

.method public final d(I)I
    .locals 1

    .line 1
    iget-object v0, p0, Lg4/o;->a:Landroidx/lifecycle/c1;

    .line 2
    .line 3
    iget-object v0, v0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v0, Lg4/g;

    .line 6
    .line 7
    iget-object v0, v0, Lg4/g;->e:Ljava/lang/String;

    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    iget-object p0, p0, Lg4/o;->h:Ljava/util/ArrayList;

    .line 14
    .line 15
    if-lt p1, v0, :cond_0

    .line 16
    .line 17
    invoke-static {p0}, Ljp/k1;->h(Ljava/util/List;)I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    if-gez p1, :cond_1

    .line 23
    .line 24
    const/4 v0, 0x0

    .line 25
    goto :goto_0

    .line 26
    :cond_1
    invoke-static {p1, p0}, Lg4/f0;->d(ILjava/util/List;)I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    :goto_0
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    check-cast p0, Lg4/q;

    .line 35
    .line 36
    iget-object v0, p0, Lg4/q;->a:Lg4/a;

    .line 37
    .line 38
    invoke-virtual {p0, p1}, Lg4/q;->d(I)I

    .line 39
    .line 40
    .line 41
    move-result p1

    .line 42
    iget-object v0, v0, Lg4/a;->d:Lh4/j;

    .line 43
    .line 44
    iget-object v0, v0, Lh4/j;->f:Landroid/text/Layout;

    .line 45
    .line 46
    invoke-virtual {v0, p1}, Landroid/text/Layout;->getLineForOffset(I)I

    .line 47
    .line 48
    .line 49
    move-result p1

    .line 50
    iget p0, p0, Lg4/q;->d:I

    .line 51
    .line 52
    add-int/2addr p1, p0

    .line 53
    return p1
.end method

.method public final e(F)I
    .locals 2

    .line 1
    iget-object p0, p0, Lg4/o;->h:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-static {p0, p1}, Lg4/f0;->f(Ljava/util/ArrayList;F)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    check-cast p0, Lg4/q;

    .line 12
    .line 13
    iget v0, p0, Lg4/q;->c:I

    .line 14
    .line 15
    iget v1, p0, Lg4/q;->b:I

    .line 16
    .line 17
    sub-int/2addr v0, v1

    .line 18
    iget v1, p0, Lg4/q;->d:I

    .line 19
    .line 20
    if-nez v0, :cond_0

    .line 21
    .line 22
    return v1

    .line 23
    :cond_0
    iget-object v0, p0, Lg4/q;->a:Lg4/a;

    .line 24
    .line 25
    iget p0, p0, Lg4/q;->f:F

    .line 26
    .line 27
    sub-float/2addr p1, p0

    .line 28
    iget-object p0, v0, Lg4/a;->d:Lh4/j;

    .line 29
    .line 30
    float-to-int p1, p1

    .line 31
    iget-object v0, p0, Lh4/j;->f:Landroid/text/Layout;

    .line 32
    .line 33
    iget p0, p0, Lh4/j;->h:I

    .line 34
    .line 35
    sub-int/2addr p1, p0

    .line 36
    invoke-virtual {v0, p1}, Landroid/text/Layout;->getLineForVertical(I)I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    add-int/2addr p0, v1

    .line 41
    return p0
.end method

.method public final f(I)F
    .locals 2

    .line 1
    invoke-virtual {p0, p1}, Lg4/o;->m(I)V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lg4/o;->h:Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-static {p1, p0}, Lg4/f0;->e(ILjava/util/List;)I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lg4/q;

    .line 15
    .line 16
    iget-object v0, p0, Lg4/q;->a:Lg4/a;

    .line 17
    .line 18
    iget v1, p0, Lg4/q;->d:I

    .line 19
    .line 20
    sub-int/2addr p1, v1

    .line 21
    iget-object v0, v0, Lg4/a;->d:Lh4/j;

    .line 22
    .line 23
    invoke-virtual {v0, p1}, Lh4/j;->g(I)F

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    iget p0, p0, Lg4/q;->f:F

    .line 28
    .line 29
    add-float/2addr p1, p0

    .line 30
    return p1
.end method

.method public final g(J)I
    .locals 8

    .line 1
    const-wide v0, 0xffffffffL

    .line 2
    .line 3
    .line 4
    .line 5
    .line 6
    and-long v2, p1, v0

    .line 7
    .line 8
    long-to-int v2, v2

    .line 9
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 10
    .line 11
    .line 12
    move-result v3

    .line 13
    iget-object p0, p0, Lg4/o;->h:Ljava/util/ArrayList;

    .line 14
    .line 15
    invoke-static {p0, v3}, Lg4/f0;->f(Ljava/util/ArrayList;F)I

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    invoke-virtual {p0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    check-cast p0, Lg4/q;

    .line 24
    .line 25
    iget v3, p0, Lg4/q;->c:I

    .line 26
    .line 27
    iget v4, p0, Lg4/q;->b:I

    .line 28
    .line 29
    sub-int/2addr v3, v4

    .line 30
    if-nez v3, :cond_0

    .line 31
    .line 32
    return v4

    .line 33
    :cond_0
    iget-object v3, p0, Lg4/q;->a:Lg4/a;

    .line 34
    .line 35
    const/16 v5, 0x20

    .line 36
    .line 37
    shr-long/2addr p1, v5

    .line 38
    long-to-int p1, p1

    .line 39
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 40
    .line 41
    .line 42
    move-result p1

    .line 43
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 44
    .line 45
    .line 46
    move-result p2

    .line 47
    iget p0, p0, Lg4/q;->f:F

    .line 48
    .line 49
    sub-float/2addr p2, p0

    .line 50
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    int-to-long p0, p0

    .line 55
    invoke-static {p2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 56
    .line 57
    .line 58
    move-result p2

    .line 59
    int-to-long v6, p2

    .line 60
    shl-long/2addr p0, v5

    .line 61
    and-long/2addr v6, v0

    .line 62
    or-long/2addr p0, v6

    .line 63
    iget-object p2, v3, Lg4/a;->d:Lh4/j;

    .line 64
    .line 65
    and-long/2addr v0, p0

    .line 66
    long-to-int v0, v0

    .line 67
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    float-to-int v0, v0

    .line 72
    iget-object v1, p2, Lh4/j;->f:Landroid/text/Layout;

    .line 73
    .line 74
    iget v2, p2, Lh4/j;->h:I

    .line 75
    .line 76
    sub-int/2addr v0, v2

    .line 77
    invoke-virtual {v1, v0}, Landroid/text/Layout;->getLineForVertical(I)I

    .line 78
    .line 79
    .line 80
    move-result v0

    .line 81
    shr-long/2addr p0, v5

    .line 82
    long-to-int p0, p0

    .line 83
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 84
    .line 85
    .line 86
    move-result p0

    .line 87
    iget-object p1, p2, Lh4/j;->f:Landroid/text/Layout;

    .line 88
    .line 89
    const/4 v1, -0x1

    .line 90
    int-to-float v1, v1

    .line 91
    invoke-virtual {p2, v0}, Lh4/j;->b(I)F

    .line 92
    .line 93
    .line 94
    move-result p2

    .line 95
    mul-float/2addr p2, v1

    .line 96
    add-float/2addr p2, p0

    .line 97
    invoke-virtual {p1, v0, p2}, Landroid/text/Layout;->getOffsetForHorizontal(IF)I

    .line 98
    .line 99
    .line 100
    move-result p0

    .line 101
    add-int/2addr p0, v4

    .line 102
    return p0
.end method

.method public final h(Ld3/c;ILf3/d;)J
    .locals 10

    .line 1
    iget v0, p1, Ld3/c;->b:F

    .line 2
    .line 3
    iget-object p0, p0, Lg4/o;->h:Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-static {p0, v0}, Lg4/f0;->f(Ljava/util/ArrayList;F)I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    check-cast v1, Lg4/q;

    .line 14
    .line 15
    iget v1, v1, Lg4/q;->g:F

    .line 16
    .line 17
    iget v2, p1, Ld3/c;->d:F

    .line 18
    .line 19
    cmpl-float v1, v1, v2

    .line 20
    .line 21
    const/4 v3, 0x1

    .line 22
    if-gez v1, :cond_5

    .line 23
    .line 24
    invoke-static {p0}, Ljp/k1;->h(Ljava/util/List;)I

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-ne v0, v1, :cond_0

    .line 29
    .line 30
    goto :goto_2

    .line 31
    :cond_0
    invoke-static {p0, v2}, Lg4/f0;->f(Ljava/util/ArrayList;F)I

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    sget-wide v4, Lg4/o0;->b:J

    .line 36
    .line 37
    :goto_0
    sget-wide v6, Lg4/o0;->b:J

    .line 38
    .line 39
    invoke-static {v4, v5, v6, v7}, Lg4/o0;->b(JJ)Z

    .line 40
    .line 41
    .line 42
    move-result v2

    .line 43
    if-eqz v2, :cond_1

    .line 44
    .line 45
    if-gt v0, v1, :cond_1

    .line 46
    .line 47
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v2

    .line 51
    check-cast v2, Lg4/q;

    .line 52
    .line 53
    iget-object v4, v2, Lg4/q;->a:Lg4/a;

    .line 54
    .line 55
    invoke-virtual {v2, p1}, Lg4/q;->c(Ld3/c;)Ld3/c;

    .line 56
    .line 57
    .line 58
    move-result-object v5

    .line 59
    invoke-virtual {v4, v5, p2, p3}, Lg4/a;->c(Ld3/c;ILf3/d;)J

    .line 60
    .line 61
    .line 62
    move-result-wide v4

    .line 63
    invoke-virtual {v2, v4, v5, v3}, Lg4/q;->b(JZ)J

    .line 64
    .line 65
    .line 66
    move-result-wide v4

    .line 67
    add-int/lit8 v0, v0, 0x1

    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_1
    invoke-static {v4, v5, v6, v7}, Lg4/o0;->b(JJ)Z

    .line 71
    .line 72
    .line 73
    move-result v2

    .line 74
    if-eqz v2, :cond_2

    .line 75
    .line 76
    return-wide v6

    .line 77
    :cond_2
    :goto_1
    sget-wide v8, Lg4/o0;->b:J

    .line 78
    .line 79
    invoke-static {v6, v7, v8, v9}, Lg4/o0;->b(JJ)Z

    .line 80
    .line 81
    .line 82
    move-result v2

    .line 83
    if-eqz v2, :cond_3

    .line 84
    .line 85
    if-gt v0, v1, :cond_3

    .line 86
    .line 87
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v2

    .line 91
    check-cast v2, Lg4/q;

    .line 92
    .line 93
    iget-object v6, v2, Lg4/q;->a:Lg4/a;

    .line 94
    .line 95
    invoke-virtual {v2, p1}, Lg4/q;->c(Ld3/c;)Ld3/c;

    .line 96
    .line 97
    .line 98
    move-result-object v7

    .line 99
    invoke-virtual {v6, v7, p2, p3}, Lg4/a;->c(Ld3/c;ILf3/d;)J

    .line 100
    .line 101
    .line 102
    move-result-wide v6

    .line 103
    invoke-virtual {v2, v6, v7, v3}, Lg4/q;->b(JZ)J

    .line 104
    .line 105
    .line 106
    move-result-wide v6

    .line 107
    add-int/lit8 v1, v1, -0x1

    .line 108
    .line 109
    goto :goto_1

    .line 110
    :cond_3
    invoke-static {v6, v7, v8, v9}, Lg4/o0;->b(JJ)Z

    .line 111
    .line 112
    .line 113
    move-result p0

    .line 114
    if-eqz p0, :cond_4

    .line 115
    .line 116
    return-wide v4

    .line 117
    :cond_4
    const/16 p0, 0x20

    .line 118
    .line 119
    shr-long p0, v4, p0

    .line 120
    .line 121
    long-to-int p0, p0

    .line 122
    const-wide p1, 0xffffffffL

    .line 123
    .line 124
    .line 125
    .line 126
    .line 127
    and-long/2addr p1, v6

    .line 128
    long-to-int p1, p1

    .line 129
    invoke-static {p0, p1}, Lg4/f0;->b(II)J

    .line 130
    .line 131
    .line 132
    move-result-wide p0

    .line 133
    return-wide p0

    .line 134
    :cond_5
    :goto_2
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    check-cast p0, Lg4/q;

    .line 139
    .line 140
    iget-object v0, p0, Lg4/q;->a:Lg4/a;

    .line 141
    .line 142
    invoke-virtual {p0, p1}, Lg4/q;->c(Ld3/c;)Ld3/c;

    .line 143
    .line 144
    .line 145
    move-result-object p1

    .line 146
    invoke-virtual {v0, p1, p2, p3}, Lg4/a;->c(Ld3/c;ILf3/d;)J

    .line 147
    .line 148
    .line 149
    move-result-wide p1

    .line 150
    invoke-virtual {p0, p1, p2, v3}, Lg4/q;->b(JZ)J

    .line 151
    .line 152
    .line 153
    move-result-wide p0

    .line 154
    return-wide p0
.end method

.method public final k(I)V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object p0, p0, Lg4/o;->a:Landroidx/lifecycle/c1;

    .line 3
    .line 4
    if-ltz p1, :cond_0

    .line 5
    .line 6
    iget-object v1, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v1, Lg4/g;

    .line 9
    .line 10
    iget-object v1, v1, Lg4/g;->e:Ljava/lang/String;

    .line 11
    .line 12
    invoke-interface {v1}, Ljava/lang/CharSequence;->length()I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-ge p1, v1, :cond_0

    .line 17
    .line 18
    const/4 v0, 0x1

    .line 19
    :cond_0
    if-nez v0, :cond_1

    .line 20
    .line 21
    const-string v0, "offset("

    .line 22
    .line 23
    const-string v1, ") is out of bounds [0, "

    .line 24
    .line 25
    invoke-static {v0, p1, v1}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    iget-object p0, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast p0, Lg4/g;

    .line 32
    .line 33
    iget-object p0, p0, Lg4/g;->e:Ljava/lang/String;

    .line 34
    .line 35
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 36
    .line 37
    .line 38
    move-result p0

    .line 39
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const/16 p0, 0x29

    .line 43
    .line 44
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    invoke-static {p0}, Lm4/a;->a(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    :cond_1
    return-void
.end method

.method public final l(I)V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object p0, p0, Lg4/o;->a:Landroidx/lifecycle/c1;

    .line 3
    .line 4
    if-ltz p1, :cond_0

    .line 5
    .line 6
    iget-object v1, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v1, Lg4/g;

    .line 9
    .line 10
    iget-object v1, v1, Lg4/g;->e:Ljava/lang/String;

    .line 11
    .line 12
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-gt p1, v1, :cond_0

    .line 17
    .line 18
    const/4 v0, 0x1

    .line 19
    :cond_0
    if-nez v0, :cond_1

    .line 20
    .line 21
    const-string v0, "offset("

    .line 22
    .line 23
    const-string v1, ") is out of bounds [0, "

    .line 24
    .line 25
    invoke-static {v0, p1, v1}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    iget-object p0, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast p0, Lg4/g;

    .line 32
    .line 33
    iget-object p0, p0, Lg4/g;->e:Ljava/lang/String;

    .line 34
    .line 35
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 36
    .line 37
    .line 38
    move-result p0

    .line 39
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const/16 p0, 0x5d

    .line 43
    .line 44
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    invoke-static {p0}, Lm4/a;->a(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    :cond_1
    return-void
.end method

.method public final m(I)V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    iget p0, p0, Lg4/o;->f:I

    .line 3
    .line 4
    if-ltz p1, :cond_0

    .line 5
    .line 6
    if-ge p1, p0, :cond_0

    .line 7
    .line 8
    const/4 v0, 0x1

    .line 9
    :cond_0
    if-nez v0, :cond_1

    .line 10
    .line 11
    new-instance v0, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    const-string v1, "lineIndex("

    .line 14
    .line 15
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    const-string p1, ") is out of bounds [0, "

    .line 22
    .line 23
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const/16 p0, 0x29

    .line 30
    .line 31
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    invoke-static {p0}, Lm4/a;->a(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    :cond_1
    return-void
.end method
