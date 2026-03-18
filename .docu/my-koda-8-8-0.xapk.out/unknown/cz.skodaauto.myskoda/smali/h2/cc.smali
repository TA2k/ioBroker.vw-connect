.class public final Lh2/cc;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/q0;


# instance fields
.field public final a:Li2/l0;

.field public final b:Lk1/i;

.field public final c:F


# direct methods
.method public constructor <init>(Li2/l0;Lk1/i;F)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/cc;->a:Li2/l0;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/cc;->b:Lk1/i;

    .line 7
    .line 8
    iput p3, p0, Lh2/cc;->c:F

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Lt3/t;Ljava/util/List;I)I
    .locals 2

    .line 1
    move-object p0, p2

    .line 2
    check-cast p0, Ljava/util/Collection;

    .line 3
    .line 4
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 5
    .line 6
    .line 7
    move-result p0

    .line 8
    const/4 p1, 0x0

    .line 9
    move v0, p1

    .line 10
    :goto_0
    if-ge p1, p0, :cond_0

    .line 11
    .line 12
    invoke-interface {p2, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    check-cast v1, Lt3/p0;

    .line 17
    .line 18
    invoke-interface {v1, p3}, Lt3/p0;->G(I)I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    add-int/2addr v0, v1

    .line 23
    add-int/lit8 p1, p1, 0x1

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    return v0
.end method

.method public final b(Lt3/s0;Ljava/util/List;J)Lt3/r0;
    .locals 20

    .line 1
    move-object/from16 v8, p0

    .line 2
    .line 3
    move-object/from16 v7, p1

    .line 4
    .line 5
    move-object/from16 v0, p2

    .line 6
    .line 7
    move-object v1, v0

    .line 8
    check-cast v1, Ljava/util/Collection;

    .line 9
    .line 10
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    const/4 v2, 0x0

    .line 15
    move v3, v2

    .line 16
    :goto_0
    const-string v4, "Collection contains no element matching the predicate."

    .line 17
    .line 18
    if-ge v3, v1, :cond_b

    .line 19
    .line 20
    invoke-interface {v0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v5

    .line 24
    check-cast v5, Lt3/p0;

    .line 25
    .line 26
    invoke-static {v5}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v6

    .line 30
    const-string v9, "navigationIcon"

    .line 31
    .line 32
    invoke-static {v6, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v6

    .line 36
    if-eqz v6, :cond_a

    .line 37
    .line 38
    const/4 v14, 0x0

    .line 39
    const/16 v15, 0xe

    .line 40
    .line 41
    const/4 v11, 0x0

    .line 42
    const/4 v12, 0x0

    .line 43
    const/4 v13, 0x0

    .line 44
    move-wide/from16 v9, p3

    .line 45
    .line 46
    invoke-static/range {v9 .. v15}, Lt4/a;->a(JIIIII)J

    .line 47
    .line 48
    .line 49
    move-result-wide v11

    .line 50
    invoke-interface {v5, v11, v12}, Lt3/p0;->L(J)Lt3/e1;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    move-object v3, v0

    .line 55
    check-cast v3, Ljava/util/Collection;

    .line 56
    .line 57
    invoke-interface {v3}, Ljava/util/Collection;->size()I

    .line 58
    .line 59
    .line 60
    move-result v5

    .line 61
    move v6, v2

    .line 62
    :goto_1
    if-ge v6, v5, :cond_9

    .line 63
    .line 64
    invoke-interface {v0, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v9

    .line 68
    check-cast v9, Lt3/p0;

    .line 69
    .line 70
    invoke-static {v9}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v10

    .line 74
    const-string v11, "actionIcons"

    .line 75
    .line 76
    invoke-static {v10, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result v10

    .line 80
    if-eqz v10, :cond_8

    .line 81
    .line 82
    const/16 v18, 0x0

    .line 83
    .line 84
    const/16 v19, 0xe

    .line 85
    .line 86
    const/4 v15, 0x0

    .line 87
    const/16 v16, 0x0

    .line 88
    .line 89
    const/16 v17, 0x0

    .line 90
    .line 91
    move-wide/from16 v13, p3

    .line 92
    .line 93
    invoke-static/range {v13 .. v19}, Lt4/a;->a(JIIIII)J

    .line 94
    .line 95
    .line 96
    move-result-wide v5

    .line 97
    invoke-interface {v9, v5, v6}, Lt3/p0;->L(J)Lt3/e1;

    .line 98
    .line 99
    .line 100
    move-result-object v5

    .line 101
    invoke-static/range {p3 .. p4}, Lt4/a;->h(J)I

    .line 102
    .line 103
    .line 104
    move-result v6

    .line 105
    const v9, 0x7fffffff

    .line 106
    .line 107
    .line 108
    if-ne v6, v9, :cond_1

    .line 109
    .line 110
    invoke-static/range {p3 .. p4}, Lt4/a;->h(J)I

    .line 111
    .line 112
    .line 113
    move-result v6

    .line 114
    :cond_0
    :goto_2
    move/from16 v16, v6

    .line 115
    .line 116
    goto :goto_3

    .line 117
    :cond_1
    invoke-static/range {p3 .. p4}, Lt4/a;->h(J)I

    .line 118
    .line 119
    .line 120
    move-result v6

    .line 121
    iget v10, v1, Lt3/e1;->d:I

    .line 122
    .line 123
    sub-int/2addr v6, v10

    .line 124
    iget v10, v5, Lt3/e1;->d:I

    .line 125
    .line 126
    sub-int/2addr v6, v10

    .line 127
    if-gez v6, :cond_0

    .line 128
    .line 129
    move v6, v2

    .line 130
    goto :goto_2

    .line 131
    :goto_3
    invoke-interface {v3}, Ljava/util/Collection;->size()I

    .line 132
    .line 133
    .line 134
    move-result v3

    .line 135
    move v6, v2

    .line 136
    :goto_4
    if-ge v6, v3, :cond_7

    .line 137
    .line 138
    invoke-interface {v0, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object v10

    .line 142
    check-cast v10, Lt3/p0;

    .line 143
    .line 144
    invoke-static {v10}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v11

    .line 148
    const-string v12, "title"

    .line 149
    .line 150
    invoke-static {v11, v12}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 151
    .line 152
    .line 153
    move-result v11

    .line 154
    if-eqz v11, :cond_6

    .line 155
    .line 156
    const/16 v18, 0x0

    .line 157
    .line 158
    const/16 v19, 0xc

    .line 159
    .line 160
    const/4 v15, 0x0

    .line 161
    const/16 v17, 0x0

    .line 162
    .line 163
    move-wide/from16 v13, p3

    .line 164
    .line 165
    invoke-static/range {v13 .. v19}, Lt4/a;->a(JIIIII)J

    .line 166
    .line 167
    .line 168
    move-result-wide v3

    .line 169
    invoke-interface {v10, v3, v4}, Lt3/p0;->L(J)Lt3/e1;

    .line 170
    .line 171
    .line 172
    move-result-object v3

    .line 173
    sget-object v0, Lt3/d;->b:Lt3/o;

    .line 174
    .line 175
    invoke-virtual {v3, v0}, Lt3/e1;->a0(Lt3/a;)I

    .line 176
    .line 177
    .line 178
    move-result v4

    .line 179
    const/high16 v6, -0x80000000

    .line 180
    .line 181
    if-eq v4, v6, :cond_2

    .line 182
    .line 183
    invoke-virtual {v3, v0}, Lt3/e1;->a0(Lt3/a;)I

    .line 184
    .line 185
    .line 186
    move-result v0

    .line 187
    goto :goto_5

    .line 188
    :cond_2
    move v0, v2

    .line 189
    :goto_5
    iget-object v4, v8, Lh2/cc;->a:Li2/l0;

    .line 190
    .line 191
    invoke-interface {v4}, Li2/l0;->invoke()F

    .line 192
    .line 193
    .line 194
    move-result v4

    .line 195
    invoke-static {v4}, Ljava/lang/Float;->isNaN(F)Z

    .line 196
    .line 197
    .line 198
    move-result v6

    .line 199
    if-eqz v6, :cond_3

    .line 200
    .line 201
    move v4, v2

    .line 202
    goto :goto_6

    .line 203
    :cond_3
    invoke-static {v4}, Lcy0/a;->i(F)I

    .line 204
    .line 205
    .line 206
    move-result v4

    .line 207
    :goto_6
    iget v6, v8, Lh2/cc;->c:F

    .line 208
    .line 209
    invoke-interface {v7, v6}, Lt4/c;->Q(F)I

    .line 210
    .line 211
    .line 212
    move-result v6

    .line 213
    iget v10, v3, Lt3/e1;->e:I

    .line 214
    .line 215
    invoke-static {v6, v10}, Ljava/lang/Math;->max(II)I

    .line 216
    .line 217
    .line 218
    move-result v10

    .line 219
    invoke-static/range {p3 .. p4}, Lt4/a;->g(J)I

    .line 220
    .line 221
    .line 222
    move-result v6

    .line 223
    if-ne v6, v9, :cond_4

    .line 224
    .line 225
    move v2, v10

    .line 226
    goto :goto_7

    .line 227
    :cond_4
    add-int/2addr v4, v10

    .line 228
    if-gez v4, :cond_5

    .line 229
    .line 230
    goto :goto_7

    .line 231
    :cond_5
    move v2, v4

    .line 232
    :goto_7
    invoke-static/range {p3 .. p4}, Lt4/a;->h(J)I

    .line 233
    .line 234
    .line 235
    move-result v11

    .line 236
    move v9, v0

    .line 237
    new-instance v0, Lh2/bc;

    .line 238
    .line 239
    move-object v4, v5

    .line 240
    move-wide/from16 v5, p3

    .line 241
    .line 242
    invoke-direct/range {v0 .. v10}, Lh2/bc;-><init>(Lt3/e1;ILt3/e1;Lt3/e1;JLt3/s0;Lh2/cc;II)V

    .line 243
    .line 244
    .line 245
    sget-object v1, Lmx0/t;->d:Lmx0/t;

    .line 246
    .line 247
    invoke-interface {v7, v11, v2, v1, v0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 248
    .line 249
    .line 250
    move-result-object v0

    .line 251
    return-object v0

    .line 252
    :cond_6
    add-int/lit8 v6, v6, 0x1

    .line 253
    .line 254
    move-object/from16 v8, p0

    .line 255
    .line 256
    goto :goto_4

    .line 257
    :cond_7
    invoke-static {v4}, Lf2/m0;->c(Ljava/lang/String;)La8/r0;

    .line 258
    .line 259
    .line 260
    move-result-object v0

    .line 261
    throw v0

    .line 262
    :cond_8
    add-int/lit8 v6, v6, 0x1

    .line 263
    .line 264
    move-object/from16 v8, p0

    .line 265
    .line 266
    goto/16 :goto_1

    .line 267
    .line 268
    :cond_9
    invoke-static {v4}, Lf2/m0;->c(Ljava/lang/String;)La8/r0;

    .line 269
    .line 270
    .line 271
    move-result-object v0

    .line 272
    throw v0

    .line 273
    :cond_a
    add-int/lit8 v3, v3, 0x1

    .line 274
    .line 275
    move-object/from16 v8, p0

    .line 276
    .line 277
    goto/16 :goto_0

    .line 278
    .line 279
    :cond_b
    invoke-static {v4}, Lf2/m0;->c(Ljava/lang/String;)La8/r0;

    .line 280
    .line 281
    .line 282
    move-result-object v0

    .line 283
    throw v0
.end method

.method public final c(Lt3/t;Ljava/util/List;I)I
    .locals 5

    .line 1
    iget p0, p0, Lh2/cc;->c:F

    .line 2
    .line 3
    invoke-interface {p1, p0}, Lt4/c;->Q(F)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    invoke-interface {p2}, Ljava/util/List;->isEmpty()Z

    .line 8
    .line 9
    .line 10
    move-result p1

    .line 11
    const/4 v0, 0x0

    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    const/4 p1, 0x0

    .line 15
    goto :goto_1

    .line 16
    :cond_0
    invoke-interface {p2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    check-cast p1, Lt3/p0;

    .line 21
    .line 22
    invoke-interface {p1, p3}, Lt3/p0;->c(I)I

    .line 23
    .line 24
    .line 25
    move-result p1

    .line 26
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    invoke-static {p2}, Ljp/k1;->h(Ljava/util/List;)I

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    const/4 v2, 0x1

    .line 35
    if-gt v2, v1, :cond_2

    .line 36
    .line 37
    :goto_0
    invoke-interface {p2, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    check-cast v3, Lt3/p0;

    .line 42
    .line 43
    invoke-interface {v3, p3}, Lt3/p0;->c(I)I

    .line 44
    .line 45
    .line 46
    move-result v3

    .line 47
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 48
    .line 49
    .line 50
    move-result-object v3

    .line 51
    invoke-virtual {v3, p1}, Ljava/lang/Integer;->compareTo(Ljava/lang/Object;)I

    .line 52
    .line 53
    .line 54
    move-result v4

    .line 55
    if-lez v4, :cond_1

    .line 56
    .line 57
    move-object p1, v3

    .line 58
    :cond_1
    if-eq v2, v1, :cond_2

    .line 59
    .line 60
    add-int/lit8 v2, v2, 0x1

    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_2
    :goto_1
    if-eqz p1, :cond_3

    .line 64
    .line 65
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    :cond_3
    invoke-static {p0, v0}, Ljava/lang/Math;->max(II)I

    .line 70
    .line 71
    .line 72
    move-result p0

    .line 73
    return p0
.end method

.method public final d(Lt3/t;Ljava/util/List;I)I
    .locals 5

    .line 1
    iget p0, p0, Lh2/cc;->c:F

    .line 2
    .line 3
    invoke-interface {p1, p0}, Lt4/c;->Q(F)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    invoke-interface {p2}, Ljava/util/List;->isEmpty()Z

    .line 8
    .line 9
    .line 10
    move-result p1

    .line 11
    const/4 v0, 0x0

    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    const/4 p1, 0x0

    .line 15
    goto :goto_1

    .line 16
    :cond_0
    invoke-interface {p2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    check-cast p1, Lt3/p0;

    .line 21
    .line 22
    invoke-interface {p1, p3}, Lt3/p0;->A(I)I

    .line 23
    .line 24
    .line 25
    move-result p1

    .line 26
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    invoke-static {p2}, Ljp/k1;->h(Ljava/util/List;)I

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    const/4 v2, 0x1

    .line 35
    if-gt v2, v1, :cond_2

    .line 36
    .line 37
    :goto_0
    invoke-interface {p2, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    check-cast v3, Lt3/p0;

    .line 42
    .line 43
    invoke-interface {v3, p3}, Lt3/p0;->A(I)I

    .line 44
    .line 45
    .line 46
    move-result v3

    .line 47
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 48
    .line 49
    .line 50
    move-result-object v3

    .line 51
    invoke-virtual {v3, p1}, Ljava/lang/Integer;->compareTo(Ljava/lang/Object;)I

    .line 52
    .line 53
    .line 54
    move-result v4

    .line 55
    if-lez v4, :cond_1

    .line 56
    .line 57
    move-object p1, v3

    .line 58
    :cond_1
    if-eq v2, v1, :cond_2

    .line 59
    .line 60
    add-int/lit8 v2, v2, 0x1

    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_2
    :goto_1
    if-eqz p1, :cond_3

    .line 64
    .line 65
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    :cond_3
    invoke-static {p0, v0}, Ljava/lang/Math;->max(II)I

    .line 70
    .line 71
    .line 72
    move-result p0

    .line 73
    return p0
.end method

.method public final e(Lt3/t;Ljava/util/List;I)I
    .locals 2

    .line 1
    move-object p0, p2

    .line 2
    check-cast p0, Ljava/util/Collection;

    .line 3
    .line 4
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 5
    .line 6
    .line 7
    move-result p0

    .line 8
    const/4 p1, 0x0

    .line 9
    move v0, p1

    .line 10
    :goto_0
    if-ge p1, p0, :cond_0

    .line 11
    .line 12
    invoke-interface {p2, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    check-cast v1, Lt3/p0;

    .line 17
    .line 18
    invoke-interface {v1, p3}, Lt3/p0;->J(I)I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    add-int/2addr v0, v1

    .line 23
    add-int/lit8 p1, p1, 0x1

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    return v0
.end method
