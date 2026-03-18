.class public final Lnw/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkw/e;


# instance fields
.field public final a:Ld3/a;

.field public final b:Lnw/f;

.field public final c:F

.field public final d:Lmw/c;

.field public final e:Lrw/a;

.field public final f:Lgv/a;

.field public final g:Ljava/util/LinkedHashMap;

.field public final h:Landroid/graphics/Path;

.field public final i:Landroid/graphics/Canvas;

.field public final j:Lfv/b;

.field public final k:Ljava/util/LinkedHashMap;


# direct methods
.method static constructor <clinit>()V
    .locals 0

    .line 1
    return-void
.end method

.method public constructor <init>(Lnw/f;Lmw/c;Lrw/a;Lgv/a;)V
    .locals 2

    .line 1
    const-string v0, "drawingModelKey"

    .line 2
    .line 3
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    new-instance v0, Ld3/a;

    .line 10
    .line 11
    const/4 v1, 0x2

    .line 12
    invoke-direct {v0, v1}, Ld3/a;-><init>(I)V

    .line 13
    .line 14
    .line 15
    iput-object v0, p0, Lnw/g;->a:Ld3/a;

    .line 16
    .line 17
    iput-object p1, p0, Lnw/g;->b:Lnw/f;

    .line 18
    .line 19
    const/high16 p1, 0x42000000    # 32.0f

    .line 20
    .line 21
    iput p1, p0, Lnw/g;->c:F

    .line 22
    .line 23
    iput-object p2, p0, Lnw/g;->d:Lmw/c;

    .line 24
    .line 25
    iput-object p3, p0, Lnw/g;->e:Lrw/a;

    .line 26
    .line 27
    iput-object p4, p0, Lnw/g;->f:Lgv/a;

    .line 28
    .line 29
    new-instance p1, Ljava/util/LinkedHashMap;

    .line 30
    .line 31
    invoke-direct {p1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 32
    .line 33
    .line 34
    iput-object p1, p0, Lnw/g;->g:Ljava/util/LinkedHashMap;

    .line 35
    .line 36
    new-instance p2, Landroid/graphics/Path;

    .line 37
    .line 38
    invoke-direct {p2}, Landroid/graphics/Path;-><init>()V

    .line 39
    .line 40
    .line 41
    iput-object p2, p0, Lnw/g;->h:Landroid/graphics/Path;

    .line 42
    .line 43
    new-instance p2, Landroid/graphics/Canvas;

    .line 44
    .line 45
    invoke-direct {p2}, Landroid/graphics/Canvas;-><init>()V

    .line 46
    .line 47
    .line 48
    iput-object p2, p0, Lnw/g;->i:Landroid/graphics/Canvas;

    .line 49
    .line 50
    new-instance p2, Lfv/b;

    .line 51
    .line 52
    const/16 p3, 0xd

    .line 53
    .line 54
    invoke-direct {p2, p3}, Lfv/b;-><init>(I)V

    .line 55
    .line 56
    .line 57
    iput-object p2, p0, Lnw/g;->j:Lfv/b;

    .line 58
    .line 59
    iput-object p1, p0, Lnw/g;->k:Ljava/util/LinkedHashMap;

    .line 60
    .line 61
    return-void
.end method


# virtual methods
.method public final a(Lkw/g;Lkw/i;Ljava/lang/Object;Ld3/a;)V
    .locals 4

    .line 1
    check-cast p3, Lmw/j;

    .line 2
    .line 3
    const-string v0, "context"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v0, "horizontalDimensions"

    .line 9
    .line 10
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    const-string p2, "model"

    .line 14
    .line 15
    invoke-static {p3, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    const-string p2, "insets"

    .line 19
    .line 20
    invoke-static {p4, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iget-object p2, p3, Lmw/j;->b:Ljava/util/ArrayList;

    .line 24
    .line 25
    invoke-virtual {p2}, Ljava/util/ArrayList;->size()I

    .line 26
    .line 27
    .line 28
    move-result p2

    .line 29
    const/4 v0, 0x0

    .line 30
    invoke-static {v0, p2}, Lkp/r9;->m(II)Lgy0/j;

    .line 31
    .line 32
    .line 33
    move-result-object p2

    .line 34
    new-instance v0, Ljava/util/ArrayList;

    .line 35
    .line 36
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p2}, Lgy0/h;->iterator()Ljava/util/Iterator;

    .line 40
    .line 41
    .line 42
    move-result-object p2

    .line 43
    :cond_0
    :goto_0
    move-object v1, p2

    .line 44
    check-cast v1, Lgy0/i;

    .line 45
    .line 46
    iget-boolean v1, v1, Lgy0/i;->f:Z

    .line 47
    .line 48
    if-eqz v1, :cond_1

    .line 49
    .line 50
    move-object v1, p2

    .line 51
    check-cast v1, Lmx0/w;

    .line 52
    .line 53
    invoke-virtual {v1}, Lmx0/w;->nextInt()I

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    iget-object v2, p3, Lmw/j;->h:Lrw/b;

    .line 58
    .line 59
    iget-object v3, p0, Lnw/g;->b:Lnw/f;

    .line 60
    .line 61
    invoke-virtual {v3, v1, v2}, Lnw/f;->a(ILrw/b;)Lnw/e;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    if-eqz v1, :cond_0

    .line 66
    .line 67
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_1
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 76
    .line 77
    .line 78
    move-result p2

    .line 79
    if-eqz p2, :cond_3

    .line 80
    .line 81
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p2

    .line 85
    check-cast p2, Lnw/e;

    .line 86
    .line 87
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 88
    .line 89
    .line 90
    const/high16 p2, 0x40000000    # 2.0f

    .line 91
    .line 92
    const/4 p3, 0x0

    .line 93
    invoke-static {p2, p3}, Ljava/lang/Math;->max(FF)F

    .line 94
    .line 95
    .line 96
    move-result v0

    .line 97
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 98
    .line 99
    .line 100
    move-result v1

    .line 101
    if-eqz v1, :cond_2

    .line 102
    .line 103
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v1

    .line 107
    check-cast v1, Lnw/e;

    .line 108
    .line 109
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 110
    .line 111
    .line 112
    invoke-static {p2, p3}, Ljava/lang/Math;->max(FF)F

    .line 113
    .line 114
    .line 115
    move-result v1

    .line 116
    invoke-static {v0, v1}, Ljava/lang/Math;->max(FF)F

    .line 117
    .line 118
    .line 119
    move-result v0

    .line 120
    goto :goto_1

    .line 121
    :cond_2
    const/4 p0, 0x2

    .line 122
    int-to-float p0, p0

    .line 123
    div-float/2addr v0, p0

    .line 124
    invoke-interface {p1, v0}, Lpw/f;->c(F)F

    .line 125
    .line 126
    .line 127
    move-result p0

    .line 128
    const/4 p1, 0x5

    .line 129
    invoke-static {p4, p0, p0, p1}, Ld3/a;->a(Ld3/a;FFI)V

    .line 130
    .line 131
    .line 132
    return-void

    .line 133
    :cond_3
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 134
    .line 135
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 136
    .line 137
    .line 138
    throw p0
.end method

.method public final b(Lkw/g;FLjava/lang/Object;Ld3/a;)V
    .locals 0

    .line 1
    check-cast p3, Lmw/j;

    .line 2
    .line 3
    const-string p0, "context"

    .line 4
    .line 5
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string p0, "model"

    .line 9
    .line 10
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    const-string p0, "insets"

    .line 14
    .line 15
    invoke-static {p4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public final c(Lc1/h2;Ljava/util/List;FLjava/util/Map;Lay0/q;)V
    .locals 27

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    move-object/from16 v2, p4

    .line 6
    .line 7
    const-string v3, "<this>"

    .line 8
    .line 9
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iget-object v3, v0, Lc1/h2;->e:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v3, Lkw/i;

    .line 15
    .line 16
    const-string v4, "series"

    .line 17
    .line 18
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    iget-object v4, v0, Lc1/h2;->b:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v4, Lkw/g;

    .line 24
    .line 25
    invoke-interface {v4}, Lkw/g;->j()Lmw/b;

    .line 26
    .line 27
    .line 28
    move-result-object v5

    .line 29
    invoke-interface {v5}, Lmw/b;->c()D

    .line 30
    .line 31
    .line 32
    move-result-wide v5

    .line 33
    invoke-interface {v4}, Lkw/g;->j()Lmw/b;

    .line 34
    .line 35
    .line 36
    move-result-object v7

    .line 37
    invoke-interface {v7}, Lmw/b;->a()D

    .line 38
    .line 39
    .line 40
    move-result-wide v7

    .line 41
    invoke-interface {v4}, Lkw/g;->j()Lmw/b;

    .line 42
    .line 43
    .line 44
    move-result-object v9

    .line 45
    invoke-interface {v9}, Lmw/b;->b()D

    .line 46
    .line 47
    .line 48
    move-result-wide v9

    .line 49
    iget-object v0, v0, Lc1/h2;->c:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast v0, Landroid/graphics/RectF;

    .line 52
    .line 53
    invoke-interface {v4}, Lpw/f;->e()Z

    .line 54
    .line 55
    .line 56
    move-result v11

    .line 57
    invoke-static {v0, v11}, Ljp/ae;->a(Landroid/graphics/RectF;Z)F

    .line 58
    .line 59
    .line 60
    move-result v11

    .line 61
    invoke-interface {v4}, Lpw/f;->h()F

    .line 62
    .line 63
    .line 64
    move-result v12

    .line 65
    invoke-virtual {v0}, Landroid/graphics/RectF;->width()F

    .line 66
    .line 67
    .line 68
    move-result v13

    .line 69
    mul-float/2addr v13, v12

    .line 70
    add-float/2addr v13, v11

    .line 71
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 72
    .line 73
    .line 74
    move-result-object v12

    .line 75
    const/4 v15, 0x0

    .line 76
    const/16 v16, 0x0

    .line 77
    .line 78
    :goto_0
    invoke-interface {v12}, Ljava/util/Iterator;->hasNext()Z

    .line 79
    .line 80
    .line 81
    move-result v17

    .line 82
    if-eqz v17, :cond_1

    .line 83
    .line 84
    invoke-interface {v12}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v17

    .line 88
    move-object/from16 v14, v17

    .line 89
    .line 90
    check-cast v14, Lmw/i;

    .line 91
    .line 92
    move-object/from16 v17, v4

    .line 93
    .line 94
    move-wide/from16 v18, v5

    .line 95
    .line 96
    iget-wide v4, v14, Lmw/i;->a:D

    .line 97
    .line 98
    cmpg-double v6, v4, v18

    .line 99
    .line 100
    if-gez v6, :cond_0

    .line 101
    .line 102
    add-int/lit8 v15, v15, 0x1

    .line 103
    .line 104
    goto :goto_1

    .line 105
    :cond_0
    cmpl-double v4, v4, v7

    .line 106
    .line 107
    if-gtz v4, :cond_2

    .line 108
    .line 109
    :goto_1
    add-int/lit8 v16, v16, 0x1

    .line 110
    .line 111
    move-object/from16 v4, v17

    .line 112
    .line 113
    move-wide/from16 v5, v18

    .line 114
    .line 115
    goto :goto_0

    .line 116
    :cond_1
    move-object/from16 v17, v4

    .line 117
    .line 118
    move-wide/from16 v18, v5

    .line 119
    .line 120
    :cond_2
    const/4 v4, 0x1

    .line 121
    sub-int/2addr v15, v4

    .line 122
    if-gez v15, :cond_3

    .line 123
    .line 124
    const/4 v14, 0x0

    .line 125
    goto :goto_2

    .line 126
    :cond_3
    move v14, v15

    .line 127
    :goto_2
    add-int/lit8 v5, v16, 0x1

    .line 128
    .line 129
    invoke-static {v1}, Ljp/k1;->h(Ljava/util/List;)I

    .line 130
    .line 131
    .line 132
    move-result v6

    .line 133
    if-le v5, v6, :cond_4

    .line 134
    .line 135
    move v5, v6

    .line 136
    :cond_4
    new-instance v6, Lgy0/j;

    .line 137
    .line 138
    invoke-direct {v6, v14, v5, v4}, Lgy0/h;-><init>(III)V

    .line 139
    .line 140
    .line 141
    invoke-virtual {v6}, Lgy0/h;->iterator()Ljava/util/Iterator;

    .line 142
    .line 143
    .line 144
    move-result-object v5

    .line 145
    const/4 v6, 0x0

    .line 146
    move-object v7, v6

    .line 147
    move-object/from16 v24, v7

    .line 148
    .line 149
    :goto_3
    move-object v8, v5

    .line 150
    check-cast v8, Lgy0/i;

    .line 151
    .line 152
    iget-boolean v8, v8, Lgy0/i;->f:Z

    .line 153
    .line 154
    if-eqz v8, :cond_e

    .line 155
    .line 156
    move-object v8, v5

    .line 157
    check-cast v8, Lmx0/w;

    .line 158
    .line 159
    invoke-virtual {v8}, Lmx0/w;->nextInt()I

    .line 160
    .line 161
    .line 162
    move-result v8

    .line 163
    invoke-interface {v1, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object v12

    .line 167
    add-int/2addr v8, v4

    .line 168
    invoke-static {v8, v1}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 169
    .line 170
    .line 171
    move-result-object v8

    .line 172
    check-cast v8, Lmw/i;

    .line 173
    .line 174
    check-cast v12, Lmw/i;

    .line 175
    .line 176
    if-eqz v7, :cond_5

    .line 177
    .line 178
    invoke-virtual {v7}, Ljava/lang/Float;->floatValue()F

    .line 179
    .line 180
    .line 181
    move-result v7

    .line 182
    goto :goto_4

    .line 183
    :cond_5
    invoke-interface/range {v17 .. v17}, Lpw/f;->h()F

    .line 184
    .line 185
    .line 186
    move-result v7

    .line 187
    iget v14, v3, Lkw/i;->a:F

    .line 188
    .line 189
    mul-float/2addr v7, v14

    .line 190
    iget-wide v14, v12, Lmw/i;->a:D

    .line 191
    .line 192
    sub-double v14, v14, v18

    .line 193
    .line 194
    div-double/2addr v14, v9

    .line 195
    double-to-float v14, v14

    .line 196
    mul-float/2addr v7, v14

    .line 197
    add-float v7, v7, p3

    .line 198
    .line 199
    :goto_4
    if-eqz v8, :cond_6

    .line 200
    .line 201
    invoke-interface/range {v17 .. v17}, Lpw/f;->h()F

    .line 202
    .line 203
    .line 204
    move-result v14

    .line 205
    iget v15, v3, Lkw/i;->a:F

    .line 206
    .line 207
    mul-float/2addr v14, v15

    .line 208
    move-object/from16 p1, v5

    .line 209
    .line 210
    iget-wide v4, v8, Lmw/i;->a:D

    .line 211
    .line 212
    sub-double v4, v4, v18

    .line 213
    .line 214
    div-double/2addr v4, v9

    .line 215
    double-to-float v4, v4

    .line 216
    mul-float/2addr v14, v4

    .line 217
    add-float v14, v14, p3

    .line 218
    .line 219
    invoke-static {v14}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 220
    .line 221
    .line 222
    move-result-object v4

    .line 223
    move-object/from16 v25, v4

    .line 224
    .line 225
    goto :goto_5

    .line 226
    :cond_6
    move-object/from16 p1, v5

    .line 227
    .line 228
    move-object/from16 v25, v6

    .line 229
    .line 230
    :goto_5
    invoke-static {v7}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 231
    .line 232
    .line 233
    move-result-object v4

    .line 234
    if-eqz v25, :cond_a

    .line 235
    .line 236
    invoke-interface/range {v17 .. v17}, Lpw/f;->e()Z

    .line 237
    .line 238
    .line 239
    move-result v5

    .line 240
    if-eqz v5, :cond_7

    .line 241
    .line 242
    cmpg-float v5, v7, v11

    .line 243
    .line 244
    if-ltz v5, :cond_8

    .line 245
    .line 246
    :cond_7
    invoke-interface/range {v17 .. v17}, Lpw/f;->e()Z

    .line 247
    .line 248
    .line 249
    move-result v5

    .line 250
    if-nez v5, :cond_a

    .line 251
    .line 252
    cmpl-float v5, v7, v11

    .line 253
    .line 254
    if-lez v5, :cond_a

    .line 255
    .line 256
    :cond_8
    invoke-interface/range {v17 .. v17}, Lpw/f;->e()Z

    .line 257
    .line 258
    .line 259
    move-result v5

    .line 260
    if-eqz v5, :cond_9

    .line 261
    .line 262
    invoke-virtual/range {v25 .. v25}, Ljava/lang/Float;->floatValue()F

    .line 263
    .line 264
    .line 265
    move-result v5

    .line 266
    cmpg-float v5, v5, v11

    .line 267
    .line 268
    if-ltz v5, :cond_d

    .line 269
    .line 270
    :cond_9
    invoke-interface/range {v17 .. v17}, Lpw/f;->e()Z

    .line 271
    .line 272
    .line 273
    move-result v5

    .line 274
    if-nez v5, :cond_a

    .line 275
    .line 276
    invoke-virtual/range {v25 .. v25}, Ljava/lang/Float;->floatValue()F

    .line 277
    .line 278
    .line 279
    move-result v5

    .line 280
    cmpl-float v5, v5, v11

    .line 281
    .line 282
    if-lez v5, :cond_a

    .line 283
    .line 284
    goto :goto_6

    .line 285
    :cond_a
    invoke-static {v7}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 286
    .line 287
    .line 288
    move-result-object v22

    .line 289
    invoke-interface/range {v17 .. v17}, Lkw/g;->j()Lmw/b;

    .line 290
    .line 291
    .line 292
    move-result-object v5

    .line 293
    invoke-interface {v5, v6}, Lmw/b;->e(Llw/e;)Lmw/k;

    .line 294
    .line 295
    .line 296
    move-result-object v5

    .line 297
    iget v8, v0, Landroid/graphics/RectF;->bottom:F

    .line 298
    .line 299
    if-eqz v2, :cond_b

    .line 300
    .line 301
    iget-wide v14, v12, Lmw/i;->a:D

    .line 302
    .line 303
    invoke-static {v14, v15}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 304
    .line 305
    .line 306
    move-result-object v14

    .line 307
    invoke-interface {v2, v14}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 308
    .line 309
    .line 310
    move-result-object v14

    .line 311
    check-cast v14, Lmw/f;

    .line 312
    .line 313
    :cond_b
    iget-wide v14, v12, Lmw/i;->b:D

    .line 314
    .line 315
    move/from16 v26, v7

    .line 316
    .line 317
    iget-wide v6, v5, Lmw/k;->a:D

    .line 318
    .line 319
    sub-double/2addr v14, v6

    .line 320
    invoke-virtual {v5}, Lmw/k;->a()D

    .line 321
    .line 322
    .line 323
    move-result-wide v5

    .line 324
    div-double/2addr v14, v5

    .line 325
    double-to-float v5, v14

    .line 326
    invoke-virtual {v0}, Landroid/graphics/RectF;->height()F

    .line 327
    .line 328
    .line 329
    move-result v6

    .line 330
    mul-float/2addr v6, v5

    .line 331
    sub-float/2addr v8, v6

    .line 332
    invoke-static {v8}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 333
    .line 334
    .line 335
    move-result-object v23

    .line 336
    move-object/from16 v20, p5

    .line 337
    .line 338
    move-object/from16 v21, v12

    .line 339
    .line 340
    invoke-interface/range {v20 .. v25}, Lay0/q;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 341
    .line 342
    .line 343
    invoke-interface/range {v17 .. v17}, Lpw/f;->e()Z

    .line 344
    .line 345
    .line 346
    move-result v5

    .line 347
    if-eqz v5, :cond_c

    .line 348
    .line 349
    cmpl-float v5, v26, v13

    .line 350
    .line 351
    if-gtz v5, :cond_e

    .line 352
    .line 353
    :cond_c
    invoke-interface/range {v17 .. v17}, Lpw/f;->e()Z

    .line 354
    .line 355
    .line 356
    move-result v5

    .line 357
    if-nez v5, :cond_d

    .line 358
    .line 359
    cmpg-float v5, v26, v13

    .line 360
    .line 361
    if-gez v5, :cond_d

    .line 362
    .line 363
    goto :goto_7

    .line 364
    :cond_d
    :goto_6
    move-object/from16 v5, p1

    .line 365
    .line 366
    move-object/from16 v24, v4

    .line 367
    .line 368
    move-object/from16 v7, v25

    .line 369
    .line 370
    const/4 v4, 0x1

    .line 371
    const/4 v6, 0x0

    .line 372
    goto/16 :goto_3

    .line 373
    .line 374
    :cond_e
    :goto_7
    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-eq p0, p1, :cond_1

    .line 2
    .line 3
    instance-of v0, p1, Lnw/g;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    check-cast p1, Lnw/g;

    .line 8
    .line 9
    iget-object v0, p1, Lnw/g;->b:Lnw/f;

    .line 10
    .line 11
    iget-object v1, p0, Lnw/g;->b:Lnw/f;

    .line 12
    .line 13
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    iget v0, p0, Lnw/g;->c:F

    .line 20
    .line 21
    iget v1, p1, Lnw/g;->c:F

    .line 22
    .line 23
    cmpg-float v0, v0, v1

    .line 24
    .line 25
    if-nez v0, :cond_0

    .line 26
    .line 27
    iget-object v0, p0, Lnw/g;->d:Lmw/c;

    .line 28
    .line 29
    iget-object v1, p1, Lnw/g;->d:Lmw/c;

    .line 30
    .line 31
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    if-eqz v0, :cond_0

    .line 36
    .line 37
    iget-object p0, p0, Lnw/g;->e:Lrw/a;

    .line 38
    .line 39
    iget-object p1, p1, Lnw/g;->e:Lrw/a;

    .line 40
    .line 41
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    if-eqz p0, :cond_0

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_0
    const/4 p0, 0x0

    .line 49
    return p0

    .line 50
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 51
    return p0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget v0, p0, Lnw/g;->c:F

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/4 v1, 0x0

    .line 8
    iget-object v2, p0, Lnw/g;->e:Lrw/a;

    .line 9
    .line 10
    iget-object v3, p0, Lnw/g;->b:Lnw/f;

    .line 11
    .line 12
    iget-object p0, p0, Lnw/g;->d:Lmw/c;

    .line 13
    .line 14
    filled-new-array {v3, v0, p0, v1, v2}, [Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-static {p0}, Ljava/util/Objects;->hash([Ljava/lang/Object;)I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    return p0
.end method
