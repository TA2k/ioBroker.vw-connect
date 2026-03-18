.class public final Llw/m;
.super Llw/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final i:Llw/a;

.field public final j:Lc1/l2;


# direct methods
.method static constructor <clinit>()V
    .locals 0

    .line 1
    return-void
.end method

.method public constructor <init>(Lqw/a;Lqw/e;Lmw/e;Lqw/a;Lqw/a;Lc1/l2;Llw/h;)V
    .locals 7

    .line 1
    move-object v0, p0

    .line 2
    move-object v1, p1

    .line 3
    move-object v2, p2

    .line 4
    move-object v3, p3

    .line 5
    move-object v4, p4

    .line 6
    move-object v5, p5

    .line 7
    move-object v6, p7

    .line 8
    invoke-direct/range {v0 .. v6}, Llw/i;-><init>(Lqw/a;Lqw/e;Lmw/e;Lqw/a;Lqw/a;Llw/h;)V

    .line 9
    .line 10
    .line 11
    sget-object p0, Llw/a;->a:Llw/a;

    .line 12
    .line 13
    iput-object p0, v0, Llw/m;->i:Llw/a;

    .line 14
    .line 15
    iput-object p6, v0, Llw/m;->j:Lc1/l2;

    .line 16
    .line 17
    return-void
.end method

.method public static o(Lkw/g;Lkw/i;)Lgy0/d;
    .locals 6

    .line 1
    const-string v0, "horizontalDimensions"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Lkw/g;->j()Lmw/b;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-interface {v0}, Lmw/b;->c()D

    .line 11
    .line 12
    .line 13
    move-result-wide v0

    .line 14
    invoke-virtual {p1}, Lkw/i;->d()F

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    iget v3, p1, Lkw/i;->a:F

    .line 19
    .line 20
    div-float/2addr v2, v3

    .line 21
    float-to-double v2, v2

    .line 22
    invoke-interface {p0}, Lkw/g;->j()Lmw/b;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    invoke-interface {v4}, Lmw/b;->b()D

    .line 27
    .line 28
    .line 29
    move-result-wide v4

    .line 30
    mul-double/2addr v4, v2

    .line 31
    sub-double/2addr v0, v4

    .line 32
    invoke-interface {p0}, Lkw/g;->j()Lmw/b;

    .line 33
    .line 34
    .line 35
    move-result-object v2

    .line 36
    invoke-interface {v2}, Lmw/b;->a()D

    .line 37
    .line 38
    .line 39
    move-result-wide v2

    .line 40
    iget v4, p1, Lkw/i;->c:F

    .line 41
    .line 42
    iget v5, p1, Lkw/i;->e:F

    .line 43
    .line 44
    add-float/2addr v4, v5

    .line 45
    iget p1, p1, Lkw/i;->a:F

    .line 46
    .line 47
    div-float/2addr v4, p1

    .line 48
    float-to-double v4, v4

    .line 49
    invoke-interface {p0}, Lkw/g;->j()Lmw/b;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    invoke-interface {p0}, Lmw/b;->b()D

    .line 54
    .line 55
    .line 56
    move-result-wide p0

    .line 57
    mul-double/2addr p0, v4

    .line 58
    add-double/2addr p0, v2

    .line 59
    new-instance v2, Lgy0/d;

    .line 60
    .line 61
    invoke-direct {v2, v0, v1, p0, p1}, Lgy0/d;-><init>(DD)V

    .line 62
    .line 63
    .line 64
    return-object v2
.end method


# virtual methods
.method public final a(Lkw/g;Lkw/i;Ljava/lang/Object;Ld3/a;)V
    .locals 14

    .line 1
    move-object/from16 v6, p2

    .line 2
    .line 3
    move-object/from16 v7, p4

    .line 4
    .line 5
    move-object/from16 v0, p3

    .line 6
    .line 7
    check-cast v0, Lmw/a;

    .line 8
    .line 9
    const-string v2, "horizontalDimensions"

    .line 10
    .line 11
    invoke-static {v6, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    const-string v2, "model"

    .line 15
    .line 16
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    const-string v0, "insets"

    .line 20
    .line 21
    invoke-static {v7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    invoke-static/range {p1 .. p2}, Llw/m;->o(Lkw/g;Lkw/i;)Lgy0/d;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    invoke-virtual {p0, p1, v6, v0}, Llw/m;->p(Lkw/g;Lkw/i;Lgy0/d;)F

    .line 29
    .line 30
    .line 31
    invoke-static/range {p1 .. p2}, Llw/m;->o(Lkw/g;Lkw/i;)Lgy0/d;

    .line 32
    .line 33
    .line 34
    iget-object v8, p0, Llw/i;->f:Llw/h;

    .line 35
    .line 36
    instance-of v0, v8, Llw/h;

    .line 37
    .line 38
    if-eqz v0, :cond_8

    .line 39
    .line 40
    iget-object v9, p0, Llw/m;->j:Lc1/l2;

    .line 41
    .line 42
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 43
    .line 44
    .line 45
    invoke-interface {p1}, Lkw/g;->j()Lmw/b;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    invoke-static {v0}, Lo01/g;->a(Lmw/b;)Lnx0/c;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    const/4 v2, 0x0

    .line 54
    invoke-virtual {v0, v2}, Lnx0/c;->listIterator(I)Ljava/util/ListIterator;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    move-object v10, v0

    .line 59
    check-cast v10, Lnx0/a;

    .line 60
    .line 61
    invoke-virtual {v10}, Lnx0/a;->hasNext()Z

    .line 62
    .line 63
    .line 64
    move-result v0

    .line 65
    if-eqz v0, :cond_7

    .line 66
    .line 67
    invoke-virtual {v10}, Lnx0/a;->next()Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    check-cast v0, Ljava/lang/Number;

    .line 72
    .line 73
    invoke-virtual {v0}, Ljava/lang/Number;->doubleValue()D

    .line 74
    .line 75
    .line 76
    move-result-wide v2

    .line 77
    iget-object v11, p0, Llw/i;->c:Lmw/e;

    .line 78
    .line 79
    const/4 v12, 0x0

    .line 80
    invoke-static {v11, p1, v2, v3, v12}, Ljp/j1;->a(Lmw/e;Lkw/g;DLlw/e;)Ljava/lang/CharSequence;

    .line 81
    .line 82
    .line 83
    move-result-object v2

    .line 84
    const/4 v4, 0x0

    .line 85
    const/16 v5, 0xc

    .line 86
    .line 87
    iget-object v0, p0, Llw/i;->b:Lqw/e;

    .line 88
    .line 89
    const/4 v3, 0x0

    .line 90
    move-object v1, p1

    .line 91
    invoke-static/range {v0 .. v5}, Lqw/e;->c(Lqw/e;Lpw/f;Ljava/lang/CharSequence;IFI)F

    .line 92
    .line 93
    .line 94
    move-result v2

    .line 95
    move v13, v2

    .line 96
    :goto_0
    invoke-virtual {v10}, Lnx0/a;->hasNext()Z

    .line 97
    .line 98
    .line 99
    move-result v2

    .line 100
    if-eqz v2, :cond_0

    .line 101
    .line 102
    invoke-virtual {v10}, Lnx0/a;->next()Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v2

    .line 106
    check-cast v2, Ljava/lang/Number;

    .line 107
    .line 108
    invoke-virtual {v2}, Ljava/lang/Number;->doubleValue()D

    .line 109
    .line 110
    .line 111
    move-result-wide v2

    .line 112
    invoke-static {v11, p1, v2, v3, v12}, Ljp/j1;->a(Lmw/e;Lkw/g;DLlw/e;)Ljava/lang/CharSequence;

    .line 113
    .line 114
    .line 115
    move-result-object v2

    .line 116
    const/4 v4, 0x0

    .line 117
    const/16 v5, 0xc

    .line 118
    .line 119
    const/4 v3, 0x0

    .line 120
    move-object v1, p1

    .line 121
    invoke-static/range {v0 .. v5}, Lqw/e;->c(Lqw/e;Lpw/f;Ljava/lang/CharSequence;IFI)F

    .line 122
    .line 123
    .line 124
    move-result v2

    .line 125
    invoke-static {v13, v2}, Ljava/lang/Math;->max(FF)F

    .line 126
    .line 127
    .line 128
    move-result v13

    .line 129
    goto :goto_0

    .line 130
    :cond_0
    const/4 v0, 0x0

    .line 131
    add-float/2addr v13, v0

    .line 132
    iget-object v2, p0, Llw/m;->i:Llw/a;

    .line 133
    .line 134
    sget-object v3, Llw/a;->a:Llw/a;

    .line 135
    .line 136
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    move-result v4

    .line 140
    if-eqz v4, :cond_1

    .line 141
    .line 142
    invoke-virtual/range {p0 .. p1}, Llw/i;->f(Lpw/f;)F

    .line 143
    .line 144
    .line 145
    move-result v4

    .line 146
    goto :goto_1

    .line 147
    :cond_1
    move v4, v0

    .line 148
    :goto_1
    add-float/2addr v13, v4

    .line 149
    invoke-virtual/range {p0 .. p1}, Llw/i;->h(Lkw/g;)F

    .line 150
    .line 151
    .line 152
    move-result v4

    .line 153
    add-float/2addr v4, v13

    .line 154
    invoke-interface {p1}, Lpw/f;->f()Landroid/graphics/RectF;

    .line 155
    .line 156
    .line 157
    move-result-object v5

    .line 158
    invoke-virtual {v5}, Landroid/graphics/RectF;->height()F

    .line 159
    .line 160
    .line 161
    move-result v5

    .line 162
    const/high16 v10, 0x40400000    # 3.0f

    .line 163
    .line 164
    div-float/2addr v5, v10

    .line 165
    cmpl-float v10, v4, v5

    .line 166
    .line 167
    if-lez v10, :cond_2

    .line 168
    .line 169
    move v4, v5

    .line 170
    :cond_2
    iget v5, v8, Llw/h;->a:F

    .line 171
    .line 172
    invoke-interface {p1, v5}, Lpw/f;->c(F)F

    .line 173
    .line 174
    .line 175
    move-result v5

    .line 176
    const v8, 0x7f7fffff    # Float.MAX_VALUE

    .line 177
    .line 178
    .line 179
    invoke-interface {p1, v8}, Lpw/f;->c(F)F

    .line 180
    .line 181
    .line 182
    move-result v8

    .line 183
    invoke-static {v4, v5, v8}, Lkp/r9;->d(FFF)F

    .line 184
    .line 185
    .line 186
    move-result v4

    .line 187
    invoke-virtual/range {p0 .. p1}, Llw/i;->i(Lkw/g;)F

    .line 188
    .line 189
    .line 190
    move-result v5

    .line 191
    invoke-virtual {v9, p1, v6, v5}, Lc1/l2;->g(Lkw/g;Lkw/i;F)F

    .line 192
    .line 193
    .line 194
    move-result v5

    .line 195
    invoke-virtual/range {p0 .. p1}, Llw/i;->i(Lkw/g;)F

    .line 196
    .line 197
    .line 198
    move-result p0

    .line 199
    invoke-virtual {v9, p1, v6, p0}, Lc1/l2;->f(Lkw/g;Lkw/i;F)F

    .line 200
    .line 201
    .line 202
    move-result p0

    .line 203
    iget v1, v7, Ld3/a;->b:F

    .line 204
    .line 205
    cmpg-float v6, v1, v5

    .line 206
    .line 207
    if-gez v6, :cond_3

    .line 208
    .line 209
    goto :goto_2

    .line 210
    :cond_3
    move v5, v1

    .line 211
    :goto_2
    iput v5, v7, Ld3/a;->b:F

    .line 212
    .line 213
    iget v1, v7, Ld3/a;->d:F

    .line 214
    .line 215
    cmpg-float v5, v1, p0

    .line 216
    .line 217
    if-gez v5, :cond_4

    .line 218
    .line 219
    goto :goto_3

    .line 220
    :cond_4
    move p0, v1

    .line 221
    :goto_3
    iput p0, v7, Ld3/a;->d:F

    .line 222
    .line 223
    sget-object p0, Llw/b;->a:Llw/b;

    .line 224
    .line 225
    invoke-static {v2, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 226
    .line 227
    .line 228
    move-result p0

    .line 229
    if-eqz p0, :cond_5

    .line 230
    .line 231
    const/16 p0, 0xd

    .line 232
    .line 233
    invoke-static {v7, v4, v0, p0}, Ld3/a;->a(Ld3/a;FFI)V

    .line 234
    .line 235
    .line 236
    return-void

    .line 237
    :cond_5
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 238
    .line 239
    .line 240
    move-result p0

    .line 241
    if-eqz p0, :cond_6

    .line 242
    .line 243
    const/4 p0, 0x7

    .line 244
    invoke-static {v7, v0, v4, p0}, Ld3/a;->a(Ld3/a;FFI)V

    .line 245
    .line 246
    .line 247
    :cond_6
    return-void

    .line 248
    :cond_7
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 249
    .line 250
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 251
    .line 252
    .line 253
    throw p0

    .line 254
    :cond_8
    new-instance p0, La8/r0;

    .line 255
    .line 256
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 257
    .line 258
    .line 259
    throw p0
.end method

.method public final c(Lc1/h2;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final d(Lc1/h2;)V
    .locals 50

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    iget v1, v2, Lc1/h2;->a:F

    .line 6
    .line 7
    iget-object v3, v2, Lc1/h2;->c:Ljava/lang/Object;

    .line 8
    .line 9
    move-object v12, v3

    .line 10
    check-cast v12, Landroid/graphics/RectF;

    .line 11
    .line 12
    iget-object v3, v2, Lc1/h2;->b:Ljava/lang/Object;

    .line 13
    .line 14
    move-object v13, v3

    .line 15
    check-cast v13, Lkw/g;

    .line 16
    .line 17
    iget-object v3, v2, Lc1/h2;->e:Ljava/lang/Object;

    .line 18
    .line 19
    move-object v14, v3

    .line 20
    check-cast v14, Lkw/i;

    .line 21
    .line 22
    iget-object v3, v2, Lc1/h2;->d:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v3, Landroid/graphics/Canvas;

    .line 25
    .line 26
    invoke-virtual {v3}, Landroid/graphics/Canvas;->save()I

    .line 27
    .line 28
    .line 29
    move-result v15

    .line 30
    iget-object v3, v0, Llw/m;->i:Llw/a;

    .line 31
    .line 32
    sget-object v4, Llw/b;->a:Llw/b;

    .line 33
    .line 34
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v5

    .line 38
    iget-object v6, v0, Llw/i;->h:Landroid/graphics/RectF;

    .line 39
    .line 40
    if-eqz v5, :cond_0

    .line 41
    .line 42
    iget v5, v6, Landroid/graphics/RectF;->bottom:F

    .line 43
    .line 44
    invoke-virtual/range {p0 .. p1}, Llw/i;->f(Lpw/f;)F

    .line 45
    .line 46
    .line 47
    move-result v7

    .line 48
    sub-float/2addr v5, v7

    .line 49
    invoke-virtual/range {p0 .. p1}, Llw/i;->h(Lkw/g;)F

    .line 50
    .line 51
    .line 52
    move-result v7

    .line 53
    sub-float/2addr v5, v7

    .line 54
    goto :goto_0

    .line 55
    :cond_0
    iget v5, v6, Landroid/graphics/RectF;->top:F

    .line 56
    .line 57
    :goto_0
    invoke-virtual/range {p0 .. p1}, Llw/i;->f(Lpw/f;)F

    .line 58
    .line 59
    .line 60
    move-result v7

    .line 61
    add-float/2addr v7, v5

    .line 62
    invoke-virtual/range {p0 .. p1}, Llw/i;->h(Lkw/g;)F

    .line 63
    .line 64
    .line 65
    move-result v8

    .line 66
    add-float/2addr v8, v7

    .line 67
    invoke-static {v2, v14}, Llw/m;->o(Lkw/g;Lkw/i;)Lgy0/d;

    .line 68
    .line 69
    .line 70
    move-result-object v7

    .line 71
    iget-wide v9, v7, Lgy0/d;->e:D

    .line 72
    .line 73
    move-wide/from16 v16, v9

    .line 74
    .line 75
    iget-wide v10, v7, Lgy0/d;->d:D

    .line 76
    .line 77
    invoke-virtual {v0, v2, v14, v7}, Llw/m;->p(Lkw/g;Lkw/i;Lgy0/d;)F

    .line 78
    .line 79
    .line 80
    move-result v7

    .line 81
    iget-object v9, v2, Lc1/h2;->d:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast v9, Landroid/graphics/Canvas;

    .line 84
    .line 85
    move/from16 v18, v1

    .line 86
    .line 87
    iget v1, v6, Landroid/graphics/RectF;->left:F

    .line 88
    .line 89
    move/from16 v19, v1

    .line 90
    .line 91
    invoke-virtual/range {p0 .. p1}, Llw/i;->i(Lkw/g;)F

    .line 92
    .line 93
    .line 94
    move-result v1

    .line 95
    move-wide/from16 v20, v10

    .line 96
    .line 97
    iget-object v10, v0, Llw/m;->j:Lc1/l2;

    .line 98
    .line 99
    invoke-virtual {v10, v2, v14, v1}, Lc1/l2;->g(Lkw/g;Lkw/i;F)F

    .line 100
    .line 101
    .line 102
    move-result v1

    .line 103
    sub-float v1, v19, v1

    .line 104
    .line 105
    iget v11, v6, Landroid/graphics/RectF;->top:F

    .line 106
    .line 107
    move/from16 v19, v5

    .line 108
    .line 109
    iget v5, v12, Landroid/graphics/RectF;->top:F

    .line 110
    .line 111
    invoke-static {v11, v5}, Ljava/lang/Math;->min(FF)F

    .line 112
    .line 113
    .line 114
    move-result v5

    .line 115
    iget v11, v6, Landroid/graphics/RectF;->right:F

    .line 116
    .line 117
    move/from16 v22, v7

    .line 118
    .line 119
    invoke-virtual/range {p0 .. p1}, Llw/i;->i(Lkw/g;)F

    .line 120
    .line 121
    .line 122
    move-result v7

    .line 123
    invoke-virtual {v10, v2, v14, v7}, Lc1/l2;->f(Lkw/g;Lkw/i;F)F

    .line 124
    .line 125
    .line 126
    move-result v7

    .line 127
    add-float/2addr v7, v11

    .line 128
    iget v11, v6, Landroid/graphics/RectF;->bottom:F

    .line 129
    .line 130
    move/from16 v23, v8

    .line 131
    .line 132
    iget v8, v12, Landroid/graphics/RectF;->bottom:F

    .line 133
    .line 134
    invoke-static {v11, v8}, Ljava/lang/Math;->max(FF)F

    .line 135
    .line 136
    .line 137
    move-result v8

    .line 138
    invoke-virtual {v9, v1, v5, v7, v8}, Landroid/graphics/Canvas;->clipRect(FFFF)Z

    .line 139
    .line 140
    .line 141
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 142
    .line 143
    .line 144
    move-result v1

    .line 145
    if-eqz v1, :cond_1

    .line 146
    .line 147
    move/from16 v5, v19

    .line 148
    .line 149
    goto :goto_1

    .line 150
    :cond_1
    move/from16 v5, v23

    .line 151
    .line 152
    :goto_1
    invoke-interface {v13}, Lpw/f;->e()Z

    .line 153
    .line 154
    .line 155
    move-result v1

    .line 156
    invoke-static {v6, v1}, Ljp/ae;->a(Landroid/graphics/RectF;Z)F

    .line 157
    .line 158
    .line 159
    move-result v1

    .line 160
    sub-float v1, v1, v18

    .line 161
    .line 162
    invoke-virtual {v14}, Lkw/i;->d()F

    .line 163
    .line 164
    .line 165
    move-result v7

    .line 166
    invoke-interface {v13}, Lpw/f;->h()F

    .line 167
    .line 168
    .line 169
    move-result v8

    .line 170
    mul-float/2addr v8, v7

    .line 171
    add-float v24, v8, v1

    .line 172
    .line 173
    iget v1, v14, Lkw/i;->a:F

    .line 174
    .line 175
    div-float v1, v18, v1

    .line 176
    .line 177
    float-to-double v7, v1

    .line 178
    invoke-interface {v13}, Lkw/g;->j()Lmw/b;

    .line 179
    .line 180
    .line 181
    move-result-object v1

    .line 182
    invoke-interface {v1}, Lmw/b;->b()D

    .line 183
    .line 184
    .line 185
    move-result-wide v25

    .line 186
    mul-double v25, v25, v7

    .line 187
    .line 188
    invoke-interface {v13}, Lpw/f;->h()F

    .line 189
    .line 190
    .line 191
    move-result v1

    .line 192
    float-to-double v7, v1

    .line 193
    mul-double v25, v25, v7

    .line 194
    .line 195
    add-double v25, v25, v20

    .line 196
    .line 197
    invoke-virtual {v6}, Landroid/graphics/RectF;->width()F

    .line 198
    .line 199
    .line 200
    move-result v1

    .line 201
    iget v7, v14, Lkw/i;->a:F

    .line 202
    .line 203
    div-float/2addr v1, v7

    .line 204
    float-to-double v7, v1

    .line 205
    invoke-interface {v13}, Lkw/g;->j()Lmw/b;

    .line 206
    .line 207
    .line 208
    move-result-object v1

    .line 209
    invoke-interface {v1}, Lmw/b;->b()D

    .line 210
    .line 211
    .line 212
    move-result-wide v27

    .line 213
    mul-double v27, v27, v7

    .line 214
    .line 215
    add-double v27, v27, v25

    .line 216
    .line 217
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 218
    .line 219
    .line 220
    iget v1, v10, Lc1/l2;->e:I

    .line 221
    .line 222
    const/16 v18, 0x0

    .line 223
    .line 224
    cmpg-float v7, v22, v18

    .line 225
    .line 226
    if-nez v7, :cond_2

    .line 227
    .line 228
    const/4 v7, 0x1

    .line 229
    goto :goto_2

    .line 230
    :cond_2
    iget v7, v14, Lkw/i;->a:F

    .line 231
    .line 232
    int-to-float v9, v1

    .line 233
    mul-float/2addr v7, v9

    .line 234
    div-float v7, v22, v7

    .line 235
    .line 236
    float-to-double v8, v7

    .line 237
    invoke-static {v8, v9}, Ljava/lang/Math;->ceil(D)D

    .line 238
    .line 239
    .line 240
    move-result-wide v7

    .line 241
    double-to-float v7, v7

    .line 242
    float-to-int v7, v7

    .line 243
    :goto_2
    mul-int/2addr v1, v7

    .line 244
    invoke-interface {v13}, Lkw/g;->j()Lmw/b;

    .line 245
    .line 246
    .line 247
    move-result-object v7

    .line 248
    invoke-interface {v7}, Lmw/b;->c()D

    .line 249
    .line 250
    .line 251
    move-result-wide v7

    .line 252
    sub-double v7, v25, v7

    .line 253
    .line 254
    invoke-interface {v13}, Lkw/g;->j()Lmw/b;

    .line 255
    .line 256
    .line 257
    move-result-object v9

    .line 258
    invoke-interface {v9}, Lmw/b;->b()D

    .line 259
    .line 260
    .line 261
    move-result-wide v29

    .line 262
    div-double v7, v7, v29

    .line 263
    .line 264
    const/4 v9, 0x0

    .line 265
    move-object/from16 v22, v12

    .line 266
    .line 267
    int-to-double v11, v9

    .line 268
    sub-double/2addr v7, v11

    .line 269
    int-to-double v11, v1

    .line 270
    rem-double/2addr v7, v11

    .line 271
    sub-double v7, v11, v7

    .line 272
    .line 273
    rem-double/2addr v7, v11

    .line 274
    invoke-interface {v13}, Lkw/g;->j()Lmw/b;

    .line 275
    .line 276
    .line 277
    move-result-object v11

    .line 278
    invoke-interface {v11}, Lmw/b;->b()D

    .line 279
    .line 280
    .line 281
    move-result-wide v11

    .line 282
    mul-double/2addr v11, v7

    .line 283
    add-double v11, v11, v25

    .line 284
    .line 285
    invoke-interface {v13}, Lkw/g;->j()Lmw/b;

    .line 286
    .line 287
    .line 288
    move-result-object v7

    .line 289
    invoke-interface {v7}, Lmw/b;->c()D

    .line 290
    .line 291
    .line 292
    move-result-wide v7

    .line 293
    invoke-interface {v13}, Lkw/g;->j()Lmw/b;

    .line 294
    .line 295
    .line 296
    move-result-object v25

    .line 297
    invoke-interface/range {v25 .. v25}, Lmw/b;->b()D

    .line 298
    .line 299
    .line 300
    move-result-wide v25

    .line 301
    rem-double v7, v7, v25

    .line 302
    .line 303
    move-object/from16 v25, v6

    .line 304
    .line 305
    new-instance v6, Ljava/util/ArrayList;

    .line 306
    .line 307
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 308
    .line 309
    .line 310
    const/16 v26, -0x2

    .line 311
    .line 312
    move/from16 v30, v9

    .line 313
    .line 314
    :goto_3
    add-int/lit8 v31, v26, 0x1

    .line 315
    .line 316
    mul-int v9, v26, v1

    .line 317
    .line 318
    move-wide/from16 v33, v7

    .line 319
    .line 320
    int-to-double v7, v9

    .line 321
    invoke-interface {v13}, Lkw/g;->j()Lmw/b;

    .line 322
    .line 323
    .line 324
    move-result-object v9

    .line 325
    invoke-interface {v9}, Lmw/b;->b()D

    .line 326
    .line 327
    .line 328
    move-result-wide v35

    .line 329
    mul-double v35, v35, v7

    .line 330
    .line 331
    add-double v35, v35, v11

    .line 332
    .line 333
    invoke-interface {v13}, Lkw/g;->j()Lmw/b;

    .line 334
    .line 335
    .line 336
    move-result-object v7

    .line 337
    invoke-interface {v7}, Lmw/b;->b()D

    .line 338
    .line 339
    .line 340
    move-result-wide v7

    .line 341
    sub-double v35, v35, v33

    .line 342
    .line 343
    invoke-interface {v13}, Lkw/g;->j()Lmw/b;

    .line 344
    .line 345
    .line 346
    move-result-object v9

    .line 347
    invoke-interface {v9}, Lmw/b;->b()D

    .line 348
    .line 349
    .line 350
    move-result-wide v37

    .line 351
    div-double v35, v35, v37

    .line 352
    .line 353
    invoke-static/range {v35 .. v36}, Ljava/lang/Math;->abs(D)D

    .line 354
    .line 355
    .line 356
    move-result-wide v37

    .line 357
    invoke-static/range {v35 .. v36}, Ljava/lang/Math;->signum(D)D

    .line 358
    .line 359
    .line 360
    move-result-wide v35

    .line 361
    move-wide/from16 v39, v7

    .line 362
    .line 363
    const/4 v9, 0x1

    .line 364
    int-to-double v7, v9

    .line 365
    rem-double v7, v37, v7

    .line 366
    .line 367
    const-wide/high16 v41, 0x3fe0000000000000L    # 0.5

    .line 368
    .line 369
    cmpl-double v7, v7, v41

    .line 370
    .line 371
    if-ltz v7, :cond_3

    .line 372
    .line 373
    invoke-static/range {v37 .. v38}, Ljava/lang/Math;->ceil(D)D

    .line 374
    .line 375
    .line 376
    move-result-wide v7

    .line 377
    goto :goto_4

    .line 378
    :cond_3
    invoke-static/range {v37 .. v38}, Ljava/lang/Math;->floor(D)D

    .line 379
    .line 380
    .line 381
    move-result-wide v7

    .line 382
    :goto_4
    mul-double v35, v35, v7

    .line 383
    .line 384
    mul-double v35, v35, v39

    .line 385
    .line 386
    add-double v35, v35, v33

    .line 387
    .line 388
    invoke-interface {v13}, Lkw/g;->j()Lmw/b;

    .line 389
    .line 390
    .line 391
    move-result-object v7

    .line 392
    invoke-interface {v7}, Lmw/b;->c()D

    .line 393
    .line 394
    .line 395
    move-result-wide v7

    .line 396
    cmpg-double v7, v35, v7

    .line 397
    .line 398
    if-ltz v7, :cond_4

    .line 399
    .line 400
    invoke-static/range {v20 .. v21}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 401
    .line 402
    .line 403
    move-result-object v7

    .line 404
    invoke-virtual {v7}, Ljava/lang/Number;->doubleValue()D

    .line 405
    .line 406
    .line 407
    move-result-wide v7

    .line 408
    cmpg-double v7, v35, v7

    .line 409
    .line 410
    if-nez v7, :cond_5

    .line 411
    .line 412
    :cond_4
    move-wide/from16 v46, v20

    .line 413
    .line 414
    move-object/from16 v21, v10

    .line 415
    .line 416
    move-object/from16 v10, v25

    .line 417
    .line 418
    move-wide/from16 v25, v46

    .line 419
    .line 420
    move-object v8, v4

    .line 421
    move-wide/from16 v46, v16

    .line 422
    .line 423
    move-object/from16 v17, v6

    .line 424
    .line 425
    move-object/from16 v16, v13

    .line 426
    .line 427
    move-object/from16 v6, v22

    .line 428
    .line 429
    move/from16 v13, v23

    .line 430
    .line 431
    move-wide/from16 v22, v11

    .line 432
    .line 433
    move-object v11, v14

    .line 434
    move/from16 v12, v19

    .line 435
    .line 436
    move-wide/from16 v19, v46

    .line 437
    .line 438
    goto/16 :goto_12

    .line 439
    .line 440
    :cond_5
    invoke-interface {v13}, Lkw/g;->j()Lmw/b;

    .line 441
    .line 442
    .line 443
    move-result-object v7

    .line 444
    invoke-interface {v7}, Lmw/b;->a()D

    .line 445
    .line 446
    .line 447
    move-result-wide v7

    .line 448
    cmpl-double v7, v35, v7

    .line 449
    .line 450
    if-gtz v7, :cond_8

    .line 451
    .line 452
    invoke-static/range {v16 .. v17}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 453
    .line 454
    .line 455
    move-result-object v7

    .line 456
    invoke-virtual {v7}, Ljava/lang/Number;->doubleValue()D

    .line 457
    .line 458
    .line 459
    move-result-wide v7

    .line 460
    cmpg-double v7, v35, v7

    .line 461
    .line 462
    if-nez v7, :cond_6

    .line 463
    .line 464
    goto :goto_5

    .line 465
    :cond_6
    invoke-static/range {v35 .. v36}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 466
    .line 467
    .line 468
    move-result-object v7

    .line 469
    invoke-virtual {v6, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 470
    .line 471
    .line 472
    cmpl-double v7, v35, v27

    .line 473
    .line 474
    if-lez v7, :cond_4

    .line 475
    .line 476
    if-eqz v30, :cond_7

    .line 477
    .line 478
    goto :goto_5

    .line 479
    :cond_7
    move/from16 v30, v9

    .line 480
    .line 481
    move/from16 v26, v31

    .line 482
    .line 483
    move-wide/from16 v7, v33

    .line 484
    .line 485
    const/4 v9, 0x0

    .line 486
    goto/16 :goto_3

    .line 487
    .line 488
    :cond_8
    :goto_5
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 489
    .line 490
    .line 491
    invoke-virtual {v6}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 492
    .line 493
    .line 494
    move-result-object v12

    .line 495
    const/4 v9, 0x0

    .line 496
    :goto_6
    invoke-interface {v12}, Ljava/util/Iterator;->hasNext()Z

    .line 497
    .line 498
    .line 499
    move-result v1

    .line 500
    if-eqz v1, :cond_11

    .line 501
    .line 502
    invoke-interface {v12}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 503
    .line 504
    .line 505
    move-result-object v1

    .line 506
    add-int/lit8 v11, v9, 0x1

    .line 507
    .line 508
    if-ltz v9, :cond_10

    .line 509
    .line 510
    check-cast v1, Ljava/lang/Number;

    .line 511
    .line 512
    move-object/from16 v26, v10

    .line 513
    .line 514
    move/from16 v27, v11

    .line 515
    .line 516
    invoke-virtual {v1}, Ljava/lang/Number;->doubleValue()D

    .line 517
    .line 518
    .line 519
    move-result-wide v10

    .line 520
    invoke-interface {v13}, Lkw/g;->j()Lmw/b;

    .line 521
    .line 522
    .line 523
    move-result-object v1

    .line 524
    invoke-interface {v1}, Lmw/b;->c()D

    .line 525
    .line 526
    .line 527
    move-result-wide v28

    .line 528
    sub-double v28, v10, v28

    .line 529
    .line 530
    invoke-interface {v13}, Lkw/g;->j()Lmw/b;

    .line 531
    .line 532
    .line 533
    move-result-object v1

    .line 534
    invoke-interface {v1}, Lmw/b;->b()D

    .line 535
    .line 536
    .line 537
    move-result-wide v30

    .line 538
    div-double v7, v28, v30

    .line 539
    .line 540
    double-to-float v7, v7

    .line 541
    iget v8, v14, Lkw/i;->a:F

    .line 542
    .line 543
    mul-float/2addr v7, v8

    .line 544
    invoke-interface {v13}, Lpw/f;->h()F

    .line 545
    .line 546
    .line 547
    move-result v8

    .line 548
    mul-float/2addr v8, v7

    .line 549
    add-float v8, v8, v24

    .line 550
    .line 551
    add-int/lit8 v9, v9, -0x1

    .line 552
    .line 553
    invoke-static {v9, v6}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 554
    .line 555
    .line 556
    move-result-object v7

    .line 557
    check-cast v7, Ljava/lang/Double;

    .line 558
    .line 559
    if-eqz v7, :cond_9

    .line 560
    .line 561
    invoke-virtual {v7}, Ljava/lang/Double;->doubleValue()D

    .line 562
    .line 563
    .line 564
    move-result-wide v28

    .line 565
    const/4 v7, 0x2

    .line 566
    :goto_7
    move/from16 v1, v27

    .line 567
    .line 568
    goto :goto_8

    .line 569
    :cond_9
    const/4 v7, 0x2

    .line 570
    int-to-double v1, v7

    .line 571
    mul-double v1, v1, v20

    .line 572
    .line 573
    sub-double v28, v1, v10

    .line 574
    .line 575
    goto :goto_7

    .line 576
    :goto_8
    invoke-static {v1, v6}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 577
    .line 578
    .line 579
    move-result-object v2

    .line 580
    check-cast v2, Ljava/lang/Double;

    .line 581
    .line 582
    if-eqz v2, :cond_a

    .line 583
    .line 584
    invoke-virtual {v2}, Ljava/lang/Double;->doubleValue()D

    .line 585
    .line 586
    .line 587
    move-result-wide v30

    .line 588
    move-wide/from16 v46, v30

    .line 589
    .line 590
    move-wide/from16 v30, v10

    .line 591
    .line 592
    move-wide/from16 v9, v46

    .line 593
    .line 594
    :goto_9
    move-object v7, v3

    .line 595
    goto :goto_a

    .line 596
    :cond_a
    move-wide/from16 v30, v10

    .line 597
    .line 598
    int-to-double v9, v7

    .line 599
    mul-double v9, v9, v16

    .line 600
    .line 601
    sub-double v9, v9, v30

    .line 602
    .line 603
    goto :goto_9

    .line 604
    :goto_a
    sub-double v2, v30, v28

    .line 605
    .line 606
    sub-double v9, v9, v30

    .line 607
    .line 608
    invoke-static {v2, v3, v9, v10}, Ljava/lang/Math;->min(DD)D

    .line 609
    .line 610
    .line 611
    move-result-wide v2

    .line 612
    invoke-interface {v13}, Lkw/g;->j()Lmw/b;

    .line 613
    .line 614
    .line 615
    move-result-object v9

    .line 616
    invoke-interface {v9}, Lmw/b;->b()D

    .line 617
    .line 618
    .line 619
    move-result-wide v9

    .line 620
    div-double/2addr v2, v9

    .line 621
    iget v9, v14, Lkw/i;->a:F

    .line 622
    .line 623
    float-to-double v9, v9

    .line 624
    mul-double/2addr v2, v9

    .line 625
    invoke-static {v2, v3}, Ljava/lang/Math;->ceil(D)D

    .line 626
    .line 627
    .line 628
    move-result-wide v2

    .line 629
    double-to-int v2, v2

    .line 630
    iget-object v3, v0, Llw/i;->c:Lmw/e;

    .line 631
    .line 632
    move-object/from16 v9, p1

    .line 633
    .line 634
    move/from16 v27, v1

    .line 635
    .line 636
    move-wide/from16 v10, v30

    .line 637
    .line 638
    const/4 v1, 0x0

    .line 639
    invoke-static {v3, v9, v10, v11, v1}, Ljp/j1;->a(Lmw/e;Lkw/g;DLlw/e;)Ljava/lang/CharSequence;

    .line 640
    .line 641
    .line 642
    move-result-object v3

    .line 643
    const-string v1, "<this>"

    .line 644
    .line 645
    invoke-static {v7, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 646
    .line 647
    .line 648
    invoke-virtual {v7, v4}, Llw/a;->equals(Ljava/lang/Object;)Z

    .line 649
    .line 650
    .line 651
    move-result v1

    .line 652
    if-eqz v1, :cond_b

    .line 653
    .line 654
    sget-object v1, Lpw/i;->d:Lpw/i;

    .line 655
    .line 656
    goto :goto_b

    .line 657
    :cond_b
    sget-object v1, Llw/a;->a:Llw/a;

    .line 658
    .line 659
    invoke-virtual {v7, v1}, Llw/a;->equals(Ljava/lang/Object;)Z

    .line 660
    .line 661
    .line 662
    move-result v1

    .line 663
    if-eqz v1, :cond_f

    .line 664
    .line 665
    sget-object v1, Lpw/i;->f:Lpw/i;

    .line 666
    .line 667
    :goto_b
    invoke-virtual/range {v25 .. v25}, Landroid/graphics/RectF;->height()F

    .line 668
    .line 669
    .line 670
    move-result v28

    .line 671
    invoke-virtual/range {p0 .. p1}, Llw/i;->h(Lkw/g;)F

    .line 672
    .line 673
    .line 674
    move-result v29

    .line 675
    sub-float v28, v28, v29

    .line 676
    .line 677
    invoke-virtual/range {p0 .. p1}, Llw/i;->f(Lpw/f;)F

    .line 678
    .line 679
    .line 680
    move-result v29

    .line 681
    move-object/from16 v30, v1

    .line 682
    .line 683
    move/from16 v31, v2

    .line 684
    .line 685
    const/4 v1, 0x2

    .line 686
    int-to-float v2, v1

    .line 687
    div-float v29, v29, v2

    .line 688
    .line 689
    sub-float v2, v28, v29

    .line 690
    .line 691
    float-to-int v2, v2

    .line 692
    move-wide/from16 v28, v10

    .line 693
    .line 694
    const/4 v10, 0x0

    .line 695
    const/16 v11, 0x10

    .line 696
    .line 697
    move/from16 v32, v1

    .line 698
    .line 699
    iget-object v1, v0, Llw/i;->b:Lqw/e;

    .line 700
    .line 701
    move-object/from16 v33, v6

    .line 702
    .line 703
    const/4 v6, 0x0

    .line 704
    move-object/from16 v34, v9

    .line 705
    .line 706
    move v9, v2

    .line 707
    move-object/from16 v2, v34

    .line 708
    .line 709
    move-object/from16 v45, v4

    .line 710
    .line 711
    move-object/from16 v44, v7

    .line 712
    .line 713
    move v4, v8

    .line 714
    move-object/from16 v34, v12

    .line 715
    .line 716
    move/from16 v12, v19

    .line 717
    .line 718
    move-object/from16 v43, v25

    .line 719
    .line 720
    move-object/from16 v7, v30

    .line 721
    .line 722
    move/from16 v8, v31

    .line 723
    .line 724
    move-wide/from16 v30, v28

    .line 725
    .line 726
    move-wide/from16 v46, v16

    .line 727
    .line 728
    move-object/from16 v16, v13

    .line 729
    .line 730
    move/from16 v13, v23

    .line 731
    .line 732
    move-object/from16 v17, v33

    .line 733
    .line 734
    move-object/from16 v23, v14

    .line 735
    .line 736
    move/from16 v14, v32

    .line 737
    .line 738
    move-wide/from16 v48, v20

    .line 739
    .line 740
    move-object/from16 v21, v26

    .line 741
    .line 742
    move-wide/from16 v19, v46

    .line 743
    .line 744
    move-wide/from16 v25, v48

    .line 745
    .line 746
    invoke-static/range {v1 .. v11}, Lqw/e;->a(Lqw/e;Lc1/h2;Ljava/lang/CharSequence;FFLpw/e;Lpw/i;IIFI)V

    .line 747
    .line 748
    .line 749
    iget-object v1, v0, Llw/i;->d:Lqw/a;

    .line 750
    .line 751
    if-eqz v1, :cond_e

    .line 752
    .line 753
    invoke-virtual/range {v21 .. v21}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 754
    .line 755
    .line 756
    cmpg-double v3, v30, v25

    .line 757
    .line 758
    if-nez v3, :cond_c

    .line 759
    .line 760
    invoke-virtual/range {p0 .. p1}, Llw/i;->i(Lkw/g;)F

    .line 761
    .line 762
    .line 763
    move-result v3

    .line 764
    int-to-float v6, v14

    .line 765
    div-float/2addr v3, v6

    .line 766
    neg-float v3, v3

    .line 767
    goto :goto_c

    .line 768
    :cond_c
    cmpg-double v3, v30, v19

    .line 769
    .line 770
    if-nez v3, :cond_d

    .line 771
    .line 772
    invoke-virtual/range {p0 .. p1}, Llw/i;->i(Lkw/g;)F

    .line 773
    .line 774
    .line 775
    move-result v3

    .line 776
    int-to-float v6, v14

    .line 777
    div-float/2addr v3, v6

    .line 778
    goto :goto_c

    .line 779
    :cond_d
    move/from16 v3, v18

    .line 780
    .line 781
    :goto_c
    invoke-interface/range {v16 .. v16}, Lpw/f;->h()F

    .line 782
    .line 783
    .line 784
    move-result v6

    .line 785
    mul-float/2addr v6, v3

    .line 786
    add-float/2addr v6, v4

    .line 787
    invoke-static {v1, v2, v12, v13, v6}, Lqw/a;->c(Lqw/a;Lc1/h2;FFF)V

    .line 788
    .line 789
    .line 790
    :cond_e
    move-object/from16 v6, v17

    .line 791
    .line 792
    move-object/from16 v10, v21

    .line 793
    .line 794
    move-object/from16 v14, v23

    .line 795
    .line 796
    move/from16 v9, v27

    .line 797
    .line 798
    move-object/from16 v3, v44

    .line 799
    .line 800
    move-object/from16 v4, v45

    .line 801
    .line 802
    move/from16 v23, v13

    .line 803
    .line 804
    move-object/from16 v13, v16

    .line 805
    .line 806
    move-wide/from16 v16, v19

    .line 807
    .line 808
    move-wide/from16 v20, v25

    .line 809
    .line 810
    move-object/from16 v25, v43

    .line 811
    .line 812
    move/from16 v19, v12

    .line 813
    .line 814
    move-object/from16 v12, v34

    .line 815
    .line 816
    goto/16 :goto_6

    .line 817
    .line 818
    :cond_f
    new-instance v0, La8/r0;

    .line 819
    .line 820
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 821
    .line 822
    .line 823
    throw v0

    .line 824
    :cond_10
    invoke-static {}, Ljp/k1;->r()V

    .line 825
    .line 826
    .line 827
    const/4 v1, 0x0

    .line 828
    throw v1

    .line 829
    :cond_11
    move-object/from16 v44, v3

    .line 830
    .line 831
    move-object/from16 v45, v4

    .line 832
    .line 833
    move-object/from16 v23, v14

    .line 834
    .line 835
    move-object/from16 v43, v25

    .line 836
    .line 837
    const/4 v1, 0x0

    .line 838
    const/4 v14, 0x2

    .line 839
    move-wide/from16 v25, v20

    .line 840
    .line 841
    move-object/from16 v21, v10

    .line 842
    .line 843
    move-wide/from16 v19, v16

    .line 844
    .line 845
    move-object/from16 v17, v6

    .line 846
    .line 847
    move-object/from16 v16, v13

    .line 848
    .line 849
    invoke-virtual/range {v21 .. v21}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 850
    .line 851
    .line 852
    invoke-virtual/range {p0 .. p1}, Llw/i;->i(Lkw/g;)F

    .line 853
    .line 854
    .line 855
    move-result v3

    .line 856
    iget-object v4, v0, Llw/i;->a:Lqw/a;

    .line 857
    .line 858
    move-object/from16 v6, v22

    .line 859
    .line 860
    if-eqz v4, :cond_13

    .line 861
    .line 862
    iget v5, v6, Landroid/graphics/RectF;->left:F

    .line 863
    .line 864
    sub-float/2addr v5, v3

    .line 865
    iget v7, v6, Landroid/graphics/RectF;->right:F

    .line 866
    .line 867
    add-float/2addr v7, v3

    .line 868
    move-object/from16 v3, v44

    .line 869
    .line 870
    move-object/from16 v8, v45

    .line 871
    .line 872
    invoke-static {v3, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 873
    .line 874
    .line 875
    move-result v3

    .line 876
    if-eqz v3, :cond_12

    .line 877
    .line 878
    move-object/from16 v10, v43

    .line 879
    .line 880
    iget v3, v10, Landroid/graphics/RectF;->bottom:F

    .line 881
    .line 882
    invoke-virtual/range {p0 .. p1}, Llw/i;->f(Lpw/f;)F

    .line 883
    .line 884
    .line 885
    move-result v8

    .line 886
    int-to-float v9, v14

    .line 887
    div-float/2addr v8, v9

    .line 888
    sub-float/2addr v3, v8

    .line 889
    goto :goto_d

    .line 890
    :cond_12
    move-object/from16 v10, v43

    .line 891
    .line 892
    iget v3, v10, Landroid/graphics/RectF;->top:F

    .line 893
    .line 894
    invoke-virtual/range {p0 .. p1}, Llw/i;->f(Lpw/f;)F

    .line 895
    .line 896
    .line 897
    move-result v8

    .line 898
    int-to-float v9, v14

    .line 899
    div-float/2addr v8, v9

    .line 900
    add-float/2addr v3, v8

    .line 901
    :goto_d
    invoke-static {v4, v2, v5, v7, v3}, Lqw/a;->b(Lqw/a;Lc1/h2;FFF)V

    .line 902
    .line 903
    .line 904
    :cond_13
    if-ltz v15, :cond_14

    .line 905
    .line 906
    iget-object v3, v2, Lc1/h2;->d:Ljava/lang/Object;

    .line 907
    .line 908
    check-cast v3, Landroid/graphics/Canvas;

    .line 909
    .line 910
    invoke-virtual {v3, v15}, Landroid/graphics/Canvas;->restoreToCount(I)V

    .line 911
    .line 912
    .line 913
    :cond_14
    iget-object v9, v0, Llw/i;->e:Lqw/a;

    .line 914
    .line 915
    if-nez v9, :cond_15

    .line 916
    .line 917
    goto/16 :goto_11

    .line 918
    .line 919
    :cond_15
    iget-object v0, v2, Lc1/h2;->d:Ljava/lang/Object;

    .line 920
    .line 921
    check-cast v0, Landroid/graphics/Canvas;

    .line 922
    .line 923
    invoke-virtual {v0}, Landroid/graphics/Canvas;->save()I

    .line 924
    .line 925
    .line 926
    move-result v0

    .line 927
    iget-object v3, v2, Lc1/h2;->d:Ljava/lang/Object;

    .line 928
    .line 929
    check-cast v3, Landroid/graphics/Canvas;

    .line 930
    .line 931
    invoke-virtual {v3, v6}, Landroid/graphics/Canvas;->clipRect(Landroid/graphics/RectF;)Z

    .line 932
    .line 933
    .line 934
    invoke-virtual/range {v17 .. v17}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 935
    .line 936
    .line 937
    move-result-object v3

    .line 938
    :goto_e
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 939
    .line 940
    .line 941
    move-result v4

    .line 942
    if-eqz v4, :cond_19

    .line 943
    .line 944
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 945
    .line 946
    .line 947
    move-result-object v4

    .line 948
    check-cast v4, Ljava/lang/Number;

    .line 949
    .line 950
    invoke-virtual {v4}, Ljava/lang/Number;->doubleValue()D

    .line 951
    .line 952
    .line 953
    move-result-wide v4

    .line 954
    invoke-interface/range {v16 .. v16}, Lkw/g;->j()Lmw/b;

    .line 955
    .line 956
    .line 957
    move-result-object v7

    .line 958
    invoke-interface {v7}, Lmw/b;->c()D

    .line 959
    .line 960
    .line 961
    move-result-wide v7

    .line 962
    sub-double v7, v4, v7

    .line 963
    .line 964
    invoke-interface/range {v16 .. v16}, Lkw/g;->j()Lmw/b;

    .line 965
    .line 966
    .line 967
    move-result-object v10

    .line 968
    invoke-interface {v10}, Lmw/b;->b()D

    .line 969
    .line 970
    .line 971
    move-result-wide v10

    .line 972
    div-double/2addr v7, v10

    .line 973
    double-to-float v7, v7

    .line 974
    move-object/from16 v11, v23

    .line 975
    .line 976
    iget v8, v11, Lkw/i;->a:F

    .line 977
    .line 978
    mul-float/2addr v7, v8

    .line 979
    invoke-interface/range {v16 .. v16}, Lpw/f;->h()F

    .line 980
    .line 981
    .line 982
    move-result v8

    .line 983
    mul-float/2addr v8, v7

    .line 984
    add-float v8, v8, v24

    .line 985
    .line 986
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 987
    .line 988
    .line 989
    move-result-object v4

    .line 990
    invoke-static/range {v25 .. v26}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 991
    .line 992
    .line 993
    move-result-object v5

    .line 994
    invoke-virtual {v4, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 995
    .line 996
    .line 997
    move-result v5

    .line 998
    if-nez v5, :cond_17

    .line 999
    .line 1000
    invoke-static/range {v19 .. v20}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 1001
    .line 1002
    .line 1003
    move-result-object v5

    .line 1004
    invoke-virtual {v4, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 1005
    .line 1006
    .line 1007
    move-result v4

    .line 1008
    if-eqz v4, :cond_16

    .line 1009
    .line 1010
    goto :goto_f

    .line 1011
    :cond_16
    move-object v4, v9

    .line 1012
    goto :goto_10

    .line 1013
    :cond_17
    :goto_f
    move-object v4, v1

    .line 1014
    :goto_10
    if-eqz v4, :cond_18

    .line 1015
    .line 1016
    iget v5, v6, Landroid/graphics/RectF;->top:F

    .line 1017
    .line 1018
    iget v7, v6, Landroid/graphics/RectF;->bottom:F

    .line 1019
    .line 1020
    invoke-static {v4, v2, v5, v7, v8}, Lqw/a;->c(Lqw/a;Lc1/h2;FFF)V

    .line 1021
    .line 1022
    .line 1023
    :cond_18
    move-object/from16 v23, v11

    .line 1024
    .line 1025
    goto :goto_e

    .line 1026
    :cond_19
    if-ltz v0, :cond_1a

    .line 1027
    .line 1028
    iget-object v1, v2, Lc1/h2;->d:Ljava/lang/Object;

    .line 1029
    .line 1030
    check-cast v1, Landroid/graphics/Canvas;

    .line 1031
    .line 1032
    invoke-virtual {v1, v0}, Landroid/graphics/Canvas;->restoreToCount(I)V

    .line 1033
    .line 1034
    .line 1035
    :cond_1a
    :goto_11
    return-void

    .line 1036
    :goto_12
    move-object v4, v8

    .line 1037
    move-object v14, v11

    .line 1038
    move-wide/from16 v7, v33

    .line 1039
    .line 1040
    const/4 v9, 0x0

    .line 1041
    move-wide/from16 v46, v22

    .line 1042
    .line 1043
    move-object/from16 v22, v6

    .line 1044
    .line 1045
    move/from16 v23, v13

    .line 1046
    .line 1047
    move-object/from16 v13, v16

    .line 1048
    .line 1049
    move-object/from16 v6, v17

    .line 1050
    .line 1051
    move-wide/from16 v16, v19

    .line 1052
    .line 1053
    move/from16 v19, v12

    .line 1054
    .line 1055
    move-wide/from16 v11, v46

    .line 1056
    .line 1057
    move-wide/from16 v46, v25

    .line 1058
    .line 1059
    move-object/from16 v25, v10

    .line 1060
    .line 1061
    move-object/from16 v10, v21

    .line 1062
    .line 1063
    move-wide/from16 v20, v46

    .line 1064
    .line 1065
    move/from16 v26, v31

    .line 1066
    .line 1067
    goto/16 :goto_3
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    invoke-super {p0, p1}, Llw/i;->equals(Ljava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    instance-of v0, p1, Llw/m;

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    check-cast p1, Llw/m;

    .line 12
    .line 13
    iget-object p1, p1, Llw/m;->j:Lc1/l2;

    .line 14
    .line 15
    iget-object p0, p0, Llw/m;->j:Lc1/l2;

    .line 16
    .line 17
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-eqz p0, :cond_0

    .line 22
    .line 23
    const/4 p0, 0x1

    .line 24
    return p0

    .line 25
    :cond_0
    const/4 p0, 0x0

    .line 26
    return p0
.end method

.method public final g()Llw/f;
    .locals 0

    .line 1
    iget-object p0, p0, Llw/m;->i:Llw/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    invoke-super {p0}, Llw/i;->hashCode()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    mul-int/lit8 v0, v0, 0x1f

    .line 6
    .line 7
    iget-object p0, p0, Llw/m;->j:Lc1/l2;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    add-int/2addr p0, v0

    .line 14
    return p0
.end method

.method public final m(Lkw/g;Lkw/i;)V
    .locals 15

    .line 1
    move-object/from16 v1, p1

    .line 2
    .line 3
    move-object/from16 v6, p2

    .line 4
    .line 5
    const-string v0, "horizontalDimensions"

    .line 6
    .line 7
    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-interface {v1}, Lkw/g;->j()Lmw/b;

    .line 11
    .line 12
    .line 13
    move-result-object v7

    .line 14
    invoke-static/range {p1 .. p2}, Llw/m;->o(Lkw/g;Lkw/i;)Lgy0/d;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-virtual {p0, v1, v6, v0}, Llw/m;->p(Lkw/g;Lkw/i;Lgy0/d;)F

    .line 19
    .line 20
    .line 21
    iget-object v0, p0, Llw/m;->j:Lc1/l2;

    .line 22
    .line 23
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 24
    .line 25
    .line 26
    invoke-interface {v1}, Lkw/g;->j()Lmw/b;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    invoke-interface {v2}, Lmw/b;->c()D

    .line 31
    .line 32
    .line 33
    move-result-wide v2

    .line 34
    const/4 v4, 0x0

    .line 35
    int-to-double v8, v4

    .line 36
    invoke-interface {v1}, Lkw/g;->j()Lmw/b;

    .line 37
    .line 38
    .line 39
    move-result-object v5

    .line 40
    invoke-interface {v5}, Lmw/b;->b()D

    .line 41
    .line 42
    .line 43
    move-result-wide v10

    .line 44
    mul-double/2addr v10, v8

    .line 45
    add-double/2addr v10, v2

    .line 46
    invoke-static {v10, v11}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 47
    .line 48
    .line 49
    move-result-object v8

    .line 50
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 51
    .line 52
    .line 53
    invoke-interface {v1}, Lkw/g;->j()Lmw/b;

    .line 54
    .line 55
    .line 56
    move-result-object v2

    .line 57
    invoke-interface {v2}, Lmw/b;->a()D

    .line 58
    .line 59
    .line 60
    move-result-wide v9

    .line 61
    invoke-interface {v2}, Lmw/b;->d()D

    .line 62
    .line 63
    .line 64
    move-result-wide v11

    .line 65
    invoke-interface {v2}, Lmw/b;->b()D

    .line 66
    .line 67
    .line 68
    move-result-wide v13

    .line 69
    int-to-double v3, v4

    .line 70
    mul-double/2addr v13, v3

    .line 71
    sub-double/2addr v11, v13

    .line 72
    invoke-interface {v2}, Lmw/b;->b()D

    .line 73
    .line 74
    .line 75
    move-result-wide v2

    .line 76
    iget v0, v0, Lc1/l2;->e:I

    .line 77
    .line 78
    int-to-double v4, v0

    .line 79
    mul-double/2addr v2, v4

    .line 80
    rem-double/2addr v11, v2

    .line 81
    sub-double/2addr v9, v11

    .line 82
    invoke-static {v9, v10}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 83
    .line 84
    .line 85
    move-result-object v9

    .line 86
    invoke-virtual {v8}, Ljava/lang/Double;->doubleValue()D

    .line 87
    .line 88
    .line 89
    move-result-wide v2

    .line 90
    iget-object v10, p0, Llw/i;->c:Lmw/e;

    .line 91
    .line 92
    const/4 v11, 0x0

    .line 93
    invoke-static {v10, v1, v2, v3, v11}, Ljp/j1;->a(Lmw/e;Lkw/g;DLlw/e;)Ljava/lang/CharSequence;

    .line 94
    .line 95
    .line 96
    move-result-object v2

    .line 97
    const/4 v4, 0x0

    .line 98
    const/16 v5, 0xc

    .line 99
    .line 100
    iget-object v0, p0, Llw/i;->b:Lqw/e;

    .line 101
    .line 102
    const/4 v3, 0x0

    .line 103
    invoke-static/range {v0 .. v5}, Lqw/e;->f(Lqw/e;Lkw/g;Ljava/lang/CharSequence;IFI)F

    .line 104
    .line 105
    .line 106
    move-result p0

    .line 107
    const/4 v12, 0x2

    .line 108
    int-to-float v2, v12

    .line 109
    div-float/2addr p0, v2

    .line 110
    invoke-interface {v1}, Lkw/g;->d()Z

    .line 111
    .line 112
    .line 113
    move-result v2

    .line 114
    if-nez v2, :cond_0

    .line 115
    .line 116
    invoke-virtual {v8}, Ljava/lang/Double;->doubleValue()D

    .line 117
    .line 118
    .line 119
    move-result-wide v2

    .line 120
    invoke-interface {v7}, Lmw/b;->c()D

    .line 121
    .line 122
    .line 123
    move-result-wide v4

    .line 124
    sub-double/2addr v2, v4

    .line 125
    double-to-float v2, v2

    .line 126
    iget v3, v6, Lkw/i;->a:F

    .line 127
    .line 128
    mul-float/2addr v2, v3

    .line 129
    sub-float/2addr p0, v2

    .line 130
    :cond_0
    const/16 v2, 0x17

    .line 131
    .line 132
    const/4 v8, 0x0

    .line 133
    invoke-static {v6, p0, v8, v2}, Lkw/i;->b(Lkw/i;FFI)V

    .line 134
    .line 135
    .line 136
    invoke-virtual {v9}, Ljava/lang/Double;->doubleValue()D

    .line 137
    .line 138
    .line 139
    move-result-wide v2

    .line 140
    invoke-static {v10, v1, v2, v3, v11}, Ljp/j1;->a(Lmw/e;Lkw/g;DLlw/e;)Ljava/lang/CharSequence;

    .line 141
    .line 142
    .line 143
    move-result-object v2

    .line 144
    const/4 v4, 0x0

    .line 145
    const/16 v5, 0xc

    .line 146
    .line 147
    const/4 v3, 0x0

    .line 148
    invoke-static/range {v0 .. v5}, Lqw/e;->f(Lqw/e;Lkw/g;Ljava/lang/CharSequence;IFI)F

    .line 149
    .line 150
    .line 151
    move-result p0

    .line 152
    int-to-float v0, v12

    .line 153
    div-float/2addr p0, v0

    .line 154
    invoke-interface/range {p1 .. p1}, Lkw/g;->d()Z

    .line 155
    .line 156
    .line 157
    move-result v0

    .line 158
    if-nez v0, :cond_1

    .line 159
    .line 160
    invoke-interface {v7}, Lmw/b;->a()D

    .line 161
    .line 162
    .line 163
    move-result-wide v0

    .line 164
    invoke-virtual {v9}, Ljava/lang/Double;->doubleValue()D

    .line 165
    .line 166
    .line 167
    move-result-wide v2

    .line 168
    sub-double/2addr v0, v2

    .line 169
    iget v2, v6, Lkw/i;->a:F

    .line 170
    .line 171
    float-to-double v2, v2

    .line 172
    mul-double/2addr v0, v2

    .line 173
    double-to-float v0, v0

    .line 174
    sub-float/2addr p0, v0

    .line 175
    :cond_1
    const/16 v0, 0xf

    .line 176
    .line 177
    invoke-static {v6, v8, p0, v0}, Lkw/i;->b(Lkw/i;FFI)V

    .line 178
    .line 179
    .line 180
    return-void
.end method

.method public final p(Lkw/g;Lkw/i;Lgy0/d;)F
    .locals 10

    .line 1
    const-string v2, "horizontalDimensions"

    .line 2
    .line 3
    invoke-static {p2, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v2, p0, Llw/m;->j:Lc1/l2;

    .line 7
    .line 8
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    invoke-interface {p1}, Lkw/g;->j()Lmw/b;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    invoke-static {v2}, Lo01/g;->a(Lmw/b;)Lnx0/c;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    check-cast v2, Ljava/lang/Iterable;

    .line 20
    .line 21
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 22
    .line 23
    .line 24
    move-result-object v6

    .line 25
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    const/4 v7, 0x0

    .line 30
    if-nez v2, :cond_0

    .line 31
    .line 32
    goto :goto_1

    .line 33
    :cond_0
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v2

    .line 37
    check-cast v2, Ljava/lang/Number;

    .line 38
    .line 39
    invoke-virtual {v2}, Ljava/lang/Number;->doubleValue()D

    .line 40
    .line 41
    .line 42
    move-result-wide v2

    .line 43
    iget-object v8, p0, Llw/i;->c:Lmw/e;

    .line 44
    .line 45
    invoke-static {v8, p1, v2, v3, v7}, Ljp/j1;->a(Lmw/e;Lkw/g;DLlw/e;)Ljava/lang/CharSequence;

    .line 46
    .line 47
    .line 48
    move-result-object v2

    .line 49
    const/4 v4, 0x0

    .line 50
    const/16 v5, 0xc

    .line 51
    .line 52
    iget-object v0, p0, Llw/i;->b:Lqw/e;

    .line 53
    .line 54
    const/4 v3, 0x0

    .line 55
    move-object v1, p1

    .line 56
    invoke-static/range {v0 .. v5}, Lqw/e;->f(Lqw/e;Lkw/g;Ljava/lang/CharSequence;IFI)F

    .line 57
    .line 58
    .line 59
    move-result v2

    .line 60
    move v9, v2

    .line 61
    :goto_0
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    if-eqz v2, :cond_1

    .line 66
    .line 67
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v2

    .line 71
    check-cast v2, Ljava/lang/Number;

    .line 72
    .line 73
    invoke-virtual {v2}, Ljava/lang/Number;->doubleValue()D

    .line 74
    .line 75
    .line 76
    move-result-wide v2

    .line 77
    invoke-static {v8, p1, v2, v3, v7}, Ljp/j1;->a(Lmw/e;Lkw/g;DLlw/e;)Ljava/lang/CharSequence;

    .line 78
    .line 79
    .line 80
    move-result-object v2

    .line 81
    const/4 v4, 0x0

    .line 82
    const/16 v5, 0xc

    .line 83
    .line 84
    const/4 v3, 0x0

    .line 85
    move-object v1, p1

    .line 86
    invoke-static/range {v0 .. v5}, Lqw/e;->f(Lqw/e;Lkw/g;Ljava/lang/CharSequence;IFI)F

    .line 87
    .line 88
    .line 89
    move-result v2

    .line 90
    invoke-static {v9, v2}, Ljava/lang/Math;->max(FF)F

    .line 91
    .line 92
    .line 93
    move-result v9

    .line 94
    goto :goto_0

    .line 95
    :cond_1
    invoke-static {v9}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 96
    .line 97
    .line 98
    move-result-object v7

    .line 99
    :goto_1
    if-eqz v7, :cond_2

    .line 100
    .line 101
    invoke-virtual {v7}, Ljava/lang/Float;->floatValue()F

    .line 102
    .line 103
    .line 104
    move-result v0

    .line 105
    return v0

    .line 106
    :cond_2
    const/4 v0, 0x0

    .line 107
    return v0
.end method
