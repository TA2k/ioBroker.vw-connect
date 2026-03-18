.class public final Landroidx/compose/foundation/lazy/layout/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Landroidx/collection/q0;

.field public b:Lbb/g0;

.field public c:I

.field public final d:Landroidx/collection/r0;

.field public final e:Ljava/util/ArrayList;

.field public final f:Ljava/util/ArrayList;

.field public final g:Ljava/util/ArrayList;

.field public final h:Ljava/util/ArrayList;

.field public final i:Ljava/util/ArrayList;

.field public j:Lo1/v;

.field public final k:Lx2/s;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Landroidx/collection/y0;->a:[J

    .line 5
    .line 6
    new-instance v0, Landroidx/collection/q0;

    .line 7
    .line 8
    invoke-direct {v0}, Landroidx/collection/q0;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Landroidx/compose/foundation/lazy/layout/b;->a:Landroidx/collection/q0;

    .line 12
    .line 13
    sget-object v0, Landroidx/collection/z0;->a:Landroidx/collection/r0;

    .line 14
    .line 15
    new-instance v0, Landroidx/collection/r0;

    .line 16
    .line 17
    invoke-direct {v0}, Landroidx/collection/r0;-><init>()V

    .line 18
    .line 19
    .line 20
    iput-object v0, p0, Landroidx/compose/foundation/lazy/layout/b;->d:Landroidx/collection/r0;

    .line 21
    .line 22
    new-instance v0, Ljava/util/ArrayList;

    .line 23
    .line 24
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 25
    .line 26
    .line 27
    iput-object v0, p0, Landroidx/compose/foundation/lazy/layout/b;->e:Ljava/util/ArrayList;

    .line 28
    .line 29
    new-instance v0, Ljava/util/ArrayList;

    .line 30
    .line 31
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 32
    .line 33
    .line 34
    iput-object v0, p0, Landroidx/compose/foundation/lazy/layout/b;->f:Ljava/util/ArrayList;

    .line 35
    .line 36
    new-instance v0, Ljava/util/ArrayList;

    .line 37
    .line 38
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 39
    .line 40
    .line 41
    iput-object v0, p0, Landroidx/compose/foundation/lazy/layout/b;->g:Ljava/util/ArrayList;

    .line 42
    .line 43
    new-instance v0, Ljava/util/ArrayList;

    .line 44
    .line 45
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 46
    .line 47
    .line 48
    iput-object v0, p0, Landroidx/compose/foundation/lazy/layout/b;->h:Ljava/util/ArrayList;

    .line 49
    .line 50
    new-instance v0, Ljava/util/ArrayList;

    .line 51
    .line 52
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 53
    .line 54
    .line 55
    iput-object v0, p0, Landroidx/compose/foundation/lazy/layout/b;->i:Ljava/util/ArrayList;

    .line 56
    .line 57
    new-instance v0, Landroidx/compose/foundation/lazy/layout/LazyLayoutItemAnimator$DisplayingDisappearingItemsElement;

    .line 58
    .line 59
    invoke-direct {v0, p0}, Landroidx/compose/foundation/lazy/layout/LazyLayoutItemAnimator$DisplayingDisappearingItemsElement;-><init>(Landroidx/compose/foundation/lazy/layout/b;)V

    .line 60
    .line 61
    .line 62
    iput-object v0, p0, Landroidx/compose/foundation/lazy/layout/b;->k:Lx2/s;

    .line 63
    .line 64
    return-void
.end method

.method public static c(Lo1/e0;ILo1/w;)V
    .locals 10

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-interface {p0, v0}, Lo1/e0;->j(I)J

    .line 3
    .line 4
    .line 5
    move-result-wide v1

    .line 6
    invoke-interface {p0}, Lo1/e0;->f()Z

    .line 7
    .line 8
    .line 9
    move-result v3

    .line 10
    if-eqz v3, :cond_0

    .line 11
    .line 12
    const/4 v3, 0x1

    .line 13
    invoke-static {v1, v2, v0, p1, v3}, Lt4/j;->a(JIII)J

    .line 14
    .line 15
    .line 16
    move-result-wide v3

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 v3, 0x2

    .line 19
    invoke-static {v1, v2, p1, v0, v3}, Lt4/j;->a(JIII)J

    .line 20
    .line 21
    .line 22
    move-result-wide v3

    .line 23
    :goto_0
    iget-object p1, p2, Lo1/w;->a:[Lo1/t;

    .line 24
    .line 25
    array-length p2, p1

    .line 26
    move v5, v0

    .line 27
    :goto_1
    if-ge v0, p2, :cond_2

    .line 28
    .line 29
    aget-object v6, p1, v0

    .line 30
    .line 31
    add-int/lit8 v7, v5, 0x1

    .line 32
    .line 33
    if-eqz v6, :cond_1

    .line 34
    .line 35
    invoke-interface {p0, v5}, Lo1/e0;->j(I)J

    .line 36
    .line 37
    .line 38
    move-result-wide v8

    .line 39
    invoke-static {v8, v9, v1, v2}, Lt4/j;->c(JJ)J

    .line 40
    .line 41
    .line 42
    move-result-wide v8

    .line 43
    invoke-static {v3, v4, v8, v9}, Lt4/j;->d(JJ)J

    .line 44
    .line 45
    .line 46
    move-result-wide v8

    .line 47
    iput-wide v8, v6, Lo1/t;->l:J

    .line 48
    .line 49
    :cond_1
    add-int/lit8 v0, v0, 0x1

    .line 50
    .line 51
    move v5, v7

    .line 52
    goto :goto_1

    .line 53
    :cond_2
    return-void
.end method

.method public static h([ILo1/e0;)I
    .locals 5

    .line 1
    invoke-interface {p1}, Lo1/e0;->k()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-interface {p1}, Lo1/e0;->d()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    add-int/2addr v1, v0

    .line 10
    const/4 v2, 0x0

    .line 11
    :goto_0
    if-ge v0, v1, :cond_0

    .line 12
    .line 13
    aget v3, p0, v0

    .line 14
    .line 15
    invoke-interface {p1}, Lo1/e0;->g()I

    .line 16
    .line 17
    .line 18
    move-result v4

    .line 19
    add-int/2addr v4, v3

    .line 20
    aput v4, p0, v0

    .line 21
    .line 22
    invoke-static {v2, v4}, Ljava/lang/Math;->max(II)I

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    add-int/lit8 v0, v0, 0x1

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    return v2
.end method


# virtual methods
.method public final a(ILjava/lang/Object;)Lo1/t;
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/compose/foundation/lazy/layout/b;->a:Landroidx/collection/q0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lo1/w;

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Lo1/w;->a:[Lo1/t;

    .line 12
    .line 13
    aget-object p0, p0, p1

    .line 14
    .line 15
    return-object p0

    .line 16
    :cond_0
    const/4 p0, 0x0

    .line 17
    return-object p0
.end method

.method public final b()J
    .locals 12

    .line 1
    iget-object p0, p0, Landroidx/compose/foundation/lazy/layout/b;->i:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const-wide/16 v1, 0x0

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    :goto_0
    if-ge v3, v0, :cond_1

    .line 11
    .line 12
    invoke-virtual {p0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v4

    .line 16
    check-cast v4, Lo1/t;

    .line 17
    .line 18
    iget-object v5, v4, Lo1/t;->n:Lh3/c;

    .line 19
    .line 20
    if-eqz v5, :cond_0

    .line 21
    .line 22
    const/16 v6, 0x20

    .line 23
    .line 24
    shr-long v7, v1, v6

    .line 25
    .line 26
    long-to-int v7, v7

    .line 27
    iget-wide v8, v4, Lo1/t;->l:J

    .line 28
    .line 29
    shr-long/2addr v8, v6

    .line 30
    long-to-int v8, v8

    .line 31
    iget-wide v9, v5, Lh3/c;->u:J

    .line 32
    .line 33
    shr-long/2addr v9, v6

    .line 34
    long-to-int v9, v9

    .line 35
    add-int/2addr v8, v9

    .line 36
    invoke-static {v7, v8}, Ljava/lang/Math;->max(II)I

    .line 37
    .line 38
    .line 39
    move-result v7

    .line 40
    const-wide v8, 0xffffffffL

    .line 41
    .line 42
    .line 43
    .line 44
    .line 45
    and-long/2addr v1, v8

    .line 46
    long-to-int v1, v1

    .line 47
    iget-wide v10, v4, Lo1/t;->l:J

    .line 48
    .line 49
    and-long/2addr v10, v8

    .line 50
    long-to-int v2, v10

    .line 51
    iget-wide v4, v5, Lh3/c;->u:J

    .line 52
    .line 53
    and-long/2addr v4, v8

    .line 54
    long-to-int v4, v4

    .line 55
    add-int/2addr v2, v4

    .line 56
    invoke-static {v1, v2}, Ljava/lang/Math;->max(II)I

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    int-to-long v4, v7

    .line 61
    shl-long/2addr v4, v6

    .line 62
    int-to-long v1, v1

    .line 63
    and-long/2addr v1, v8

    .line 64
    or-long/2addr v1, v4

    .line 65
    :cond_0
    add-int/lit8 v3, v3, 0x1

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_1
    return-wide v1
.end method

.method public final d(IIILjava/util/ArrayList;Lbb/g0;Lap0/o;ZZIZIILvy0/b0;Le3/w;)V
    .locals 51

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v4, p4

    .line 6
    .line 7
    move-object/from16 v5, p5

    .line 8
    .line 9
    move/from16 v6, p9

    .line 10
    .line 11
    iget-object v7, v0, Landroidx/compose/foundation/lazy/layout/b;->b:Lbb/g0;

    .line 12
    .line 13
    iput-object v5, v0, Landroidx/compose/foundation/lazy/layout/b;->b:Lbb/g0;

    .line 14
    .line 15
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 16
    .line 17
    .line 18
    move-result v8

    .line 19
    const/4 v10, 0x0

    .line 20
    :goto_0
    const/16 v16, 0x0

    .line 21
    .line 22
    iget-object v11, v0, Landroidx/compose/foundation/lazy/layout/b;->a:Landroidx/collection/q0;

    .line 23
    .line 24
    if-ge v10, v8, :cond_3

    .line 25
    .line 26
    invoke-virtual {v4, v10}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v12

    .line 30
    check-cast v12, Lo1/e0;

    .line 31
    .line 32
    invoke-interface {v12}, Lo1/e0;->b()I

    .line 33
    .line 34
    .line 35
    move-result v13

    .line 36
    const/4 v14, 0x0

    .line 37
    :goto_1
    if-ge v14, v13, :cond_2

    .line 38
    .line 39
    invoke-interface {v12, v14}, Lo1/e0;->h(I)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v15

    .line 43
    instance-of v9, v15, Lo1/j;

    .line 44
    .line 45
    if-eqz v9, :cond_0

    .line 46
    .line 47
    check-cast v15, Lo1/j;

    .line 48
    .line 49
    goto :goto_2

    .line 50
    :cond_0
    move-object/from16 v15, v16

    .line 51
    .line 52
    :goto_2
    if-eqz v15, :cond_1

    .line 53
    .line 54
    goto :goto_3

    .line 55
    :cond_1
    add-int/lit8 v14, v14, 0x1

    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_2
    add-int/lit8 v10, v10, 0x1

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_3
    invoke-virtual {v11}, Landroidx/collection/q0;->i()Z

    .line 62
    .line 63
    .line 64
    move-result v8

    .line 65
    if-eqz v8, :cond_4

    .line 66
    .line 67
    invoke-virtual {v0}, Landroidx/compose/foundation/lazy/layout/b;->e()V

    .line 68
    .line 69
    .line 70
    return-void

    .line 71
    :cond_4
    :goto_3
    iget v8, v0, Landroidx/compose/foundation/lazy/layout/b;->c:I

    .line 72
    .line 73
    invoke-static {v4}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v9

    .line 77
    check-cast v9, Lo1/e0;

    .line 78
    .line 79
    if-eqz v9, :cond_5

    .line 80
    .line 81
    invoke-interface {v9}, Lo1/e0;->getIndex()I

    .line 82
    .line 83
    .line 84
    move-result v9

    .line 85
    goto :goto_4

    .line 86
    :cond_5
    const/4 v9, 0x0

    .line 87
    :goto_4
    iput v9, v0, Landroidx/compose/foundation/lazy/layout/b;->c:I

    .line 88
    .line 89
    const/16 v17, 0x20

    .line 90
    .line 91
    if-eqz p7, :cond_6

    .line 92
    .line 93
    const/4 v12, 0x0

    .line 94
    int-to-long v13, v12

    .line 95
    shl-long v13, v13, v17

    .line 96
    .line 97
    const-wide v18, 0xffffffffL

    .line 98
    .line 99
    .line 100
    .line 101
    .line 102
    int-to-long v9, v1

    .line 103
    and-long v9, v9, v18

    .line 104
    .line 105
    or-long/2addr v9, v13

    .line 106
    goto :goto_5

    .line 107
    :cond_6
    const/4 v12, 0x0

    .line 108
    const-wide v18, 0xffffffffL

    .line 109
    .line 110
    .line 111
    .line 112
    .line 113
    int-to-long v9, v1

    .line 114
    shl-long v9, v9, v17

    .line 115
    .line 116
    int-to-long v13, v12

    .line 117
    and-long v12, v13, v18

    .line 118
    .line 119
    or-long/2addr v9, v12

    .line 120
    :goto_5
    if-nez p8, :cond_8

    .line 121
    .line 122
    if-nez p10, :cond_7

    .line 123
    .line 124
    goto :goto_6

    .line 125
    :cond_7
    const/16 v20, 0x0

    .line 126
    .line 127
    goto :goto_7

    .line 128
    :cond_8
    :goto_6
    const/16 v20, 0x1

    .line 129
    .line 130
    :goto_7
    iget-object v12, v11, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 131
    .line 132
    iget-object v13, v11, Landroidx/collection/q0;->a:[J

    .line 133
    .line 134
    array-length v14, v13

    .line 135
    add-int/lit8 v14, v14, -0x2

    .line 136
    .line 137
    const-wide/16 v21, 0x80

    .line 138
    .line 139
    const-wide/16 v23, 0xff

    .line 140
    .line 141
    const/16 v25, 0x7

    .line 142
    .line 143
    iget-object v15, v0, Landroidx/compose/foundation/lazy/layout/b;->d:Landroidx/collection/r0;

    .line 144
    .line 145
    const-wide v26, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 146
    .line 147
    .line 148
    .line 149
    .line 150
    move-object/from16 p1, v12

    .line 151
    .line 152
    if-ltz v14, :cond_c

    .line 153
    .line 154
    move-object/from16 p10, v13

    .line 155
    .line 156
    const/4 v1, 0x0

    .line 157
    :goto_8
    const/16 v28, 0x8

    .line 158
    .line 159
    aget-wide v12, p10, v1

    .line 160
    .line 161
    not-long v2, v12

    .line 162
    shl-long v2, v2, v25

    .line 163
    .line 164
    and-long/2addr v2, v12

    .line 165
    and-long v2, v2, v26

    .line 166
    .line 167
    cmp-long v2, v2, v26

    .line 168
    .line 169
    if-eqz v2, :cond_b

    .line 170
    .line 171
    sub-int v2, v1, v14

    .line 172
    .line 173
    not-int v2, v2

    .line 174
    ushr-int/lit8 v2, v2, 0x1f

    .line 175
    .line 176
    rsub-int/lit8 v2, v2, 0x8

    .line 177
    .line 178
    const/4 v3, 0x0

    .line 179
    :goto_9
    if-ge v3, v2, :cond_a

    .line 180
    .line 181
    and-long v29, v12, v23

    .line 182
    .line 183
    cmp-long v29, v29, v21

    .line 184
    .line 185
    if-gez v29, :cond_9

    .line 186
    .line 187
    shl-int/lit8 v29, v1, 0x3

    .line 188
    .line 189
    add-int v29, v29, v3

    .line 190
    .line 191
    move/from16 v30, v3

    .line 192
    .line 193
    aget-object v3, p1, v29

    .line 194
    .line 195
    invoke-virtual {v15, v3}, Landroidx/collection/r0;->a(Ljava/lang/Object;)Z

    .line 196
    .line 197
    .line 198
    goto :goto_a

    .line 199
    :cond_9
    move/from16 v30, v3

    .line 200
    .line 201
    :goto_a
    shr-long v12, v12, v28

    .line 202
    .line 203
    add-int/lit8 v3, v30, 0x1

    .line 204
    .line 205
    goto :goto_9

    .line 206
    :cond_a
    move/from16 v3, v28

    .line 207
    .line 208
    if-ne v2, v3, :cond_c

    .line 209
    .line 210
    :cond_b
    if-eq v1, v14, :cond_c

    .line 211
    .line 212
    add-int/lit8 v1, v1, 0x1

    .line 213
    .line 214
    goto :goto_8

    .line 215
    :cond_c
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 216
    .line 217
    .line 218
    move-result v1

    .line 219
    const/4 v2, 0x0

    .line 220
    :goto_b
    iget-object v3, v0, Landroidx/compose/foundation/lazy/layout/b;->i:Ljava/util/ArrayList;

    .line 221
    .line 222
    iget-object v13, v0, Landroidx/compose/foundation/lazy/layout/b;->f:Ljava/util/ArrayList;

    .line 223
    .line 224
    iget-object v14, v0, Landroidx/compose/foundation/lazy/layout/b;->e:Ljava/util/ArrayList;

    .line 225
    .line 226
    if-ge v2, v1, :cond_1d

    .line 227
    .line 228
    invoke-virtual {v4, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 229
    .line 230
    .line 231
    move-result-object v29

    .line 232
    move-object/from16 v12, v29

    .line 233
    .line 234
    check-cast v12, Lo1/e0;

    .line 235
    .line 236
    move/from16 p10, v1

    .line 237
    .line 238
    invoke-interface {v12}, Lo1/e0;->getKey()Ljava/lang/Object;

    .line 239
    .line 240
    .line 241
    move-result-object v1

    .line 242
    invoke-virtual {v15, v1}, Landroidx/collection/r0;->l(Ljava/lang/Object;)Z

    .line 243
    .line 244
    .line 245
    invoke-interface {v12}, Lo1/e0;->b()I

    .line 246
    .line 247
    .line 248
    move-result v1

    .line 249
    move/from16 v29, v2

    .line 250
    .line 251
    const/4 v2, 0x0

    .line 252
    :goto_c
    if-ge v2, v1, :cond_1b

    .line 253
    .line 254
    move/from16 v30, v1

    .line 255
    .line 256
    invoke-interface {v12, v2}, Lo1/e0;->h(I)Ljava/lang/Object;

    .line 257
    .line 258
    .line 259
    move-result-object v1

    .line 260
    move/from16 v31, v2

    .line 261
    .line 262
    instance-of v2, v1, Lo1/j;

    .line 263
    .line 264
    if-eqz v2, :cond_d

    .line 265
    .line 266
    check-cast v1, Lo1/j;

    .line 267
    .line 268
    goto :goto_d

    .line 269
    :cond_d
    move-object/from16 v1, v16

    .line 270
    .line 271
    :goto_d
    if-eqz v1, :cond_1a

    .line 272
    .line 273
    invoke-interface {v12}, Lo1/e0;->getKey()Ljava/lang/Object;

    .line 274
    .line 275
    .line 276
    move-result-object v1

    .line 277
    invoke-virtual {v11, v1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 278
    .line 279
    .line 280
    move-result-object v1

    .line 281
    move-object/from16 v30, v1

    .line 282
    .line 283
    check-cast v30, Lo1/w;

    .line 284
    .line 285
    if-eqz v7, :cond_e

    .line 286
    .line 287
    invoke-interface {v12}, Lo1/e0;->getKey()Ljava/lang/Object;

    .line 288
    .line 289
    .line 290
    move-result-object v1

    .line 291
    invoke-virtual {v7, v1}, Lbb/g0;->i(Ljava/lang/Object;)I

    .line 292
    .line 293
    .line 294
    move-result v1

    .line 295
    :goto_e
    const/4 v2, -0x1

    .line 296
    goto :goto_f

    .line 297
    :cond_e
    const/4 v1, -0x1

    .line 298
    goto :goto_e

    .line 299
    :goto_f
    if-ne v1, v2, :cond_f

    .line 300
    .line 301
    if-eqz v7, :cond_f

    .line 302
    .line 303
    const/4 v2, 0x1

    .line 304
    goto :goto_10

    .line 305
    :cond_f
    const/4 v2, 0x0

    .line 306
    :goto_10
    if-nez v30, :cond_14

    .line 307
    .line 308
    new-instance v3, Lo1/w;

    .line 309
    .line 310
    invoke-direct {v3, v0}, Lo1/w;-><init>(Landroidx/compose/foundation/lazy/layout/b;)V

    .line 311
    .line 312
    .line 313
    move/from16 v34, p11

    .line 314
    .line 315
    move/from16 v35, p12

    .line 316
    .line 317
    move-object/from16 v32, p13

    .line 318
    .line 319
    move-object/from16 v33, p14

    .line 320
    .line 321
    move-object/from16 v30, v3

    .line 322
    .line 323
    move-object/from16 v31, v12

    .line 324
    .line 325
    invoke-static/range {v30 .. v35}, Lo1/w;->b(Lo1/w;Lo1/e0;Lvy0/b0;Le3/w;II)V

    .line 326
    .line 327
    .line 328
    move/from16 v36, v2

    .line 329
    .line 330
    invoke-interface {v12}, Lo1/e0;->getKey()Ljava/lang/Object;

    .line 331
    .line 332
    .line 333
    move-result-object v2

    .line 334
    invoke-virtual {v11, v2, v3}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 335
    .line 336
    .line 337
    invoke-interface {v12}, Lo1/e0;->getIndex()I

    .line 338
    .line 339
    .line 340
    move-result v2

    .line 341
    if-eq v2, v1, :cond_11

    .line 342
    .line 343
    const/4 v2, -0x1

    .line 344
    if-eq v1, v2, :cond_11

    .line 345
    .line 346
    if-ge v1, v8, :cond_10

    .line 347
    .line 348
    invoke-virtual {v14, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 349
    .line 350
    .line 351
    goto/16 :goto_16

    .line 352
    .line 353
    :cond_10
    invoke-virtual {v13, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 354
    .line 355
    .line 356
    goto/16 :goto_16

    .line 357
    .line 358
    :cond_11
    const/4 v1, 0x0

    .line 359
    invoke-interface {v12, v1}, Lo1/e0;->j(I)J

    .line 360
    .line 361
    .line 362
    move-result-wide v13

    .line 363
    invoke-interface {v12}, Lo1/e0;->f()Z

    .line 364
    .line 365
    .line 366
    move-result v1

    .line 367
    if-eqz v1, :cond_12

    .line 368
    .line 369
    and-long v1, v13, v18

    .line 370
    .line 371
    :goto_11
    long-to-int v1, v1

    .line 372
    goto :goto_12

    .line 373
    :cond_12
    shr-long v1, v13, v17

    .line 374
    .line 375
    goto :goto_11

    .line 376
    :goto_12
    invoke-static {v12, v1, v3}, Landroidx/compose/foundation/lazy/layout/b;->c(Lo1/e0;ILo1/w;)V

    .line 377
    .line 378
    .line 379
    if-eqz v36, :cond_1c

    .line 380
    .line 381
    iget-object v1, v3, Lo1/w;->a:[Lo1/t;

    .line 382
    .line 383
    array-length v2, v1

    .line 384
    const/4 v3, 0x0

    .line 385
    :goto_13
    if-ge v3, v2, :cond_1c

    .line 386
    .line 387
    aget-object v12, v1, v3

    .line 388
    .line 389
    if-eqz v12, :cond_13

    .line 390
    .line 391
    invoke-virtual {v12}, Lo1/t;->a()V

    .line 392
    .line 393
    .line 394
    :cond_13
    add-int/lit8 v3, v3, 0x1

    .line 395
    .line 396
    goto :goto_13

    .line 397
    :cond_14
    move/from16 v36, v2

    .line 398
    .line 399
    if-eqz v20, :cond_1c

    .line 400
    .line 401
    move/from16 v34, p11

    .line 402
    .line 403
    move/from16 v35, p12

    .line 404
    .line 405
    move-object/from16 v32, p13

    .line 406
    .line 407
    move-object/from16 v33, p14

    .line 408
    .line 409
    move-object/from16 v31, v12

    .line 410
    .line 411
    invoke-static/range {v30 .. v35}, Lo1/w;->b(Lo1/w;Lo1/e0;Lvy0/b0;Le3/w;II)V

    .line 412
    .line 413
    .line 414
    move-object/from16 v1, v30

    .line 415
    .line 416
    iget-object v2, v1, Lo1/w;->a:[Lo1/t;

    .line 417
    .line 418
    array-length v13, v2

    .line 419
    const/4 v14, 0x0

    .line 420
    :goto_14
    if-ge v14, v13, :cond_16

    .line 421
    .line 422
    move-object/from16 v30, v2

    .line 423
    .line 424
    aget-object v2, v30, v14

    .line 425
    .line 426
    move/from16 v31, v13

    .line 427
    .line 428
    move/from16 v32, v14

    .line 429
    .line 430
    if-eqz v2, :cond_15

    .line 431
    .line 432
    iget-wide v13, v2, Lo1/t;->l:J

    .line 433
    .line 434
    sget-wide v4, Lo1/t;->s:J

    .line 435
    .line 436
    invoke-static {v13, v14, v4, v5}, Lt4/j;->b(JJ)Z

    .line 437
    .line 438
    .line 439
    move-result v4

    .line 440
    if-nez v4, :cond_15

    .line 441
    .line 442
    iget-wide v4, v2, Lo1/t;->l:J

    .line 443
    .line 444
    invoke-static {v4, v5, v9, v10}, Lt4/j;->d(JJ)J

    .line 445
    .line 446
    .line 447
    move-result-wide v4

    .line 448
    iput-wide v4, v2, Lo1/t;->l:J

    .line 449
    .line 450
    :cond_15
    add-int/lit8 v14, v32, 0x1

    .line 451
    .line 452
    move-object/from16 v4, p4

    .line 453
    .line 454
    move-object/from16 v5, p5

    .line 455
    .line 456
    move-object/from16 v2, v30

    .line 457
    .line 458
    move/from16 v13, v31

    .line 459
    .line 460
    goto :goto_14

    .line 461
    :cond_16
    if-eqz v36, :cond_19

    .line 462
    .line 463
    iget-object v1, v1, Lo1/w;->a:[Lo1/t;

    .line 464
    .line 465
    array-length v2, v1

    .line 466
    const/4 v4, 0x0

    .line 467
    :goto_15
    if-ge v4, v2, :cond_19

    .line 468
    .line 469
    aget-object v5, v1, v4

    .line 470
    .line 471
    if-eqz v5, :cond_18

    .line 472
    .line 473
    invoke-virtual {v5}, Lo1/t;->b()Z

    .line 474
    .line 475
    .line 476
    move-result v13

    .line 477
    if-eqz v13, :cond_17

    .line 478
    .line 479
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 480
    .line 481
    .line 482
    iget-object v13, v0, Landroidx/compose/foundation/lazy/layout/b;->j:Lo1/v;

    .line 483
    .line 484
    if-eqz v13, :cond_17

    .line 485
    .line 486
    invoke-static {v13}, Lv3/f;->m(Lv3/p;)V

    .line 487
    .line 488
    .line 489
    :cond_17
    invoke-virtual {v5}, Lo1/t;->a()V

    .line 490
    .line 491
    .line 492
    :cond_18
    add-int/lit8 v4, v4, 0x1

    .line 493
    .line 494
    goto :goto_15

    .line 495
    :cond_19
    const/4 v1, 0x0

    .line 496
    invoke-virtual {v0, v12, v1}, Landroidx/compose/foundation/lazy/layout/b;->g(Lo1/e0;Z)V

    .line 497
    .line 498
    .line 499
    goto :goto_16

    .line 500
    :cond_1a
    add-int/lit8 v2, v31, 0x1

    .line 501
    .line 502
    move-object/from16 v4, p4

    .line 503
    .line 504
    move-object/from16 v5, p5

    .line 505
    .line 506
    move/from16 v1, v30

    .line 507
    .line 508
    goto/16 :goto_c

    .line 509
    .line 510
    :cond_1b
    invoke-interface {v12}, Lo1/e0;->getKey()Ljava/lang/Object;

    .line 511
    .line 512
    .line 513
    move-result-object v1

    .line 514
    invoke-virtual {v0, v1}, Landroidx/compose/foundation/lazy/layout/b;->f(Ljava/lang/Object;)V

    .line 515
    .line 516
    .line 517
    :cond_1c
    :goto_16
    add-int/lit8 v2, v29, 0x1

    .line 518
    .line 519
    move-object/from16 v4, p4

    .line 520
    .line 521
    move-object/from16 v5, p5

    .line 522
    .line 523
    move/from16 v1, p10

    .line 524
    .line 525
    goto/16 :goto_b

    .line 526
    .line 527
    :cond_1d
    new-array v1, v6, [I

    .line 528
    .line 529
    if-eqz v20, :cond_23

    .line 530
    .line 531
    if-eqz v7, :cond_23

    .line 532
    .line 533
    invoke-virtual {v14}, Ljava/util/ArrayList;->isEmpty()Z

    .line 534
    .line 535
    .line 536
    move-result v2

    .line 537
    if-nez v2, :cond_20

    .line 538
    .line 539
    invoke-virtual {v14}, Ljava/util/ArrayList;->size()I

    .line 540
    .line 541
    .line 542
    move-result v2

    .line 543
    const/4 v4, 0x1

    .line 544
    if-le v2, v4, :cond_1e

    .line 545
    .line 546
    new-instance v2, Lo1/x;

    .line 547
    .line 548
    const/4 v4, 0x2

    .line 549
    invoke-direct {v2, v7, v4}, Lo1/x;-><init>(Lbb/g0;I)V

    .line 550
    .line 551
    .line 552
    invoke-static {v14, v2}, Lmx0/q;->n0(Ljava/util/List;Ljava/util/Comparator;)V

    .line 553
    .line 554
    .line 555
    :cond_1e
    invoke-virtual {v14}, Ljava/util/ArrayList;->size()I

    .line 556
    .line 557
    .line 558
    move-result v2

    .line 559
    const/4 v4, 0x0

    .line 560
    :goto_17
    if-ge v4, v2, :cond_1f

    .line 561
    .line 562
    invoke-virtual {v14, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 563
    .line 564
    .line 565
    move-result-object v5

    .line 566
    check-cast v5, Lo1/e0;

    .line 567
    .line 568
    invoke-static {v1, v5}, Landroidx/compose/foundation/lazy/layout/b;->h([ILo1/e0;)I

    .line 569
    .line 570
    .line 571
    move-result v8

    .line 572
    sub-int v8, p11, v8

    .line 573
    .line 574
    invoke-interface {v5}, Lo1/e0;->getKey()Ljava/lang/Object;

    .line 575
    .line 576
    .line 577
    move-result-object v9

    .line 578
    invoke-virtual {v11, v9}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 579
    .line 580
    .line 581
    move-result-object v9

    .line 582
    invoke-static {v9}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 583
    .line 584
    .line 585
    check-cast v9, Lo1/w;

    .line 586
    .line 587
    invoke-static {v5, v8, v9}, Landroidx/compose/foundation/lazy/layout/b;->c(Lo1/e0;ILo1/w;)V

    .line 588
    .line 589
    .line 590
    const/4 v12, 0x0

    .line 591
    invoke-virtual {v0, v5, v12}, Landroidx/compose/foundation/lazy/layout/b;->g(Lo1/e0;Z)V

    .line 592
    .line 593
    .line 594
    add-int/lit8 v4, v4, 0x1

    .line 595
    .line 596
    goto :goto_17

    .line 597
    :cond_1f
    const/4 v12, 0x0

    .line 598
    invoke-static {v1, v12, v6, v12}, Ljava/util/Arrays;->fill([IIII)V

    .line 599
    .line 600
    .line 601
    :cond_20
    invoke-virtual {v13}, Ljava/util/ArrayList;->isEmpty()Z

    .line 602
    .line 603
    .line 604
    move-result v2

    .line 605
    if-nez v2, :cond_23

    .line 606
    .line 607
    invoke-virtual {v13}, Ljava/util/ArrayList;->size()I

    .line 608
    .line 609
    .line 610
    move-result v2

    .line 611
    const/4 v4, 0x1

    .line 612
    if-le v2, v4, :cond_21

    .line 613
    .line 614
    new-instance v2, Lo1/x;

    .line 615
    .line 616
    const/4 v4, 0x0

    .line 617
    invoke-direct {v2, v7, v4}, Lo1/x;-><init>(Lbb/g0;I)V

    .line 618
    .line 619
    .line 620
    invoke-static {v13, v2}, Lmx0/q;->n0(Ljava/util/List;Ljava/util/Comparator;)V

    .line 621
    .line 622
    .line 623
    :cond_21
    invoke-virtual {v13}, Ljava/util/ArrayList;->size()I

    .line 624
    .line 625
    .line 626
    move-result v2

    .line 627
    const/4 v4, 0x0

    .line 628
    :goto_18
    if-ge v4, v2, :cond_22

    .line 629
    .line 630
    invoke-virtual {v13, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 631
    .line 632
    .line 633
    move-result-object v5

    .line 634
    check-cast v5, Lo1/e0;

    .line 635
    .line 636
    invoke-static {v1, v5}, Landroidx/compose/foundation/lazy/layout/b;->h([ILo1/e0;)I

    .line 637
    .line 638
    .line 639
    move-result v8

    .line 640
    add-int v8, v8, p12

    .line 641
    .line 642
    invoke-interface {v5}, Lo1/e0;->g()I

    .line 643
    .line 644
    .line 645
    move-result v9

    .line 646
    sub-int/2addr v8, v9

    .line 647
    invoke-interface {v5}, Lo1/e0;->getKey()Ljava/lang/Object;

    .line 648
    .line 649
    .line 650
    move-result-object v9

    .line 651
    invoke-virtual {v11, v9}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 652
    .line 653
    .line 654
    move-result-object v9

    .line 655
    invoke-static {v9}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 656
    .line 657
    .line 658
    check-cast v9, Lo1/w;

    .line 659
    .line 660
    invoke-static {v5, v8, v9}, Landroidx/compose/foundation/lazy/layout/b;->c(Lo1/e0;ILo1/w;)V

    .line 661
    .line 662
    .line 663
    const/4 v12, 0x0

    .line 664
    invoke-virtual {v0, v5, v12}, Landroidx/compose/foundation/lazy/layout/b;->g(Lo1/e0;Z)V

    .line 665
    .line 666
    .line 667
    add-int/lit8 v4, v4, 0x1

    .line 668
    .line 669
    goto :goto_18

    .line 670
    :cond_22
    const/4 v12, 0x0

    .line 671
    invoke-static {v1, v12, v6, v12}, Ljava/util/Arrays;->fill([IIII)V

    .line 672
    .line 673
    .line 674
    :cond_23
    iget-object v2, v15, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 675
    .line 676
    iget-object v4, v15, Landroidx/collection/r0;->a:[J

    .line 677
    .line 678
    array-length v5, v4

    .line 679
    add-int/lit8 v5, v5, -0x2

    .line 680
    .line 681
    iget-object v8, v0, Landroidx/compose/foundation/lazy/layout/b;->h:Ljava/util/ArrayList;

    .line 682
    .line 683
    iget-object v9, v0, Landroidx/compose/foundation/lazy/layout/b;->g:Ljava/util/ArrayList;

    .line 684
    .line 685
    if-ltz v5, :cond_38

    .line 686
    .line 687
    move-object/from16 v29, v13

    .line 688
    .line 689
    const/4 v10, 0x0

    .line 690
    :goto_19
    aget-wide v12, v4, v10

    .line 691
    .line 692
    move-object/from16 v31, v14

    .line 693
    .line 694
    move-object/from16 v30, v15

    .line 695
    .line 696
    not-long v14, v12

    .line 697
    shl-long v14, v14, v25

    .line 698
    .line 699
    and-long/2addr v14, v12

    .line 700
    and-long v14, v14, v26

    .line 701
    .line 702
    cmp-long v14, v14, v26

    .line 703
    .line 704
    if-eqz v14, :cond_37

    .line 705
    .line 706
    sub-int v14, v10, v5

    .line 707
    .line 708
    not-int v14, v14

    .line 709
    ushr-int/lit8 v14, v14, 0x1f

    .line 710
    .line 711
    const/16 v28, 0x8

    .line 712
    .line 713
    rsub-int/lit8 v14, v14, 0x8

    .line 714
    .line 715
    move-wide/from16 v37, v12

    .line 716
    .line 717
    const/4 v12, 0x0

    .line 718
    :goto_1a
    if-ge v12, v14, :cond_36

    .line 719
    .line 720
    and-long v32, v37, v23

    .line 721
    .line 722
    cmp-long v13, v32, v21

    .line 723
    .line 724
    if-gez v13, :cond_34

    .line 725
    .line 726
    shl-int/lit8 v13, v10, 0x3

    .line 727
    .line 728
    add-int/2addr v13, v12

    .line 729
    aget-object v13, v2, v13

    .line 730
    .line 731
    invoke-virtual {v11, v13}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 732
    .line 733
    .line 734
    move-result-object v15

    .line 735
    check-cast v15, Lo1/w;

    .line 736
    .line 737
    if-nez v15, :cond_24

    .line 738
    .line 739
    goto/16 :goto_23

    .line 740
    .line 741
    :cond_24
    move-object/from16 p10, v2

    .line 742
    .line 743
    move/from16 v32, v12

    .line 744
    .line 745
    move-object/from16 v12, p5

    .line 746
    .line 747
    invoke-virtual {v12, v13}, Lbb/g0;->i(Ljava/lang/Object;)I

    .line 748
    .line 749
    .line 750
    move-result v2

    .line 751
    move-object/from16 v45, v4

    .line 752
    .line 753
    iget v4, v15, Lo1/w;->e:I

    .line 754
    .line 755
    invoke-static {v6, v4}, Ljava/lang/Math;->min(II)I

    .line 756
    .line 757
    .line 758
    move-result v4

    .line 759
    iput v4, v15, Lo1/w;->e:I

    .line 760
    .line 761
    sub-int v4, v6, v4

    .line 762
    .line 763
    move-object/from16 v33, v11

    .line 764
    .line 765
    iget v11, v15, Lo1/w;->d:I

    .line 766
    .line 767
    invoke-static {v4, v11}, Ljava/lang/Math;->min(II)I

    .line 768
    .line 769
    .line 770
    move-result v4

    .line 771
    iput v4, v15, Lo1/w;->d:I

    .line 772
    .line 773
    const/4 v4, -0x1

    .line 774
    if-ne v2, v4, :cond_2f

    .line 775
    .line 776
    iget-object v2, v15, Lo1/w;->a:[Lo1/t;

    .line 777
    .line 778
    array-length v11, v2

    .line 779
    const/4 v4, 0x0

    .line 780
    const/16 v34, 0x0

    .line 781
    .line 782
    const/16 v35, 0x0

    .line 783
    .line 784
    :goto_1b
    if-ge v4, v11, :cond_2e

    .line 785
    .line 786
    move-object/from16 v36, v13

    .line 787
    .line 788
    aget-object v13, v2, v4

    .line 789
    .line 790
    add-int/lit8 v39, v35, 0x1

    .line 791
    .line 792
    if-eqz v13, :cond_2c

    .line 793
    .line 794
    invoke-virtual {v13}, Lo1/t;->b()Z

    .line 795
    .line 796
    .line 797
    move-result v40

    .line 798
    if-eqz v40, :cond_25

    .line 799
    .line 800
    move-object/from16 v40, v2

    .line 801
    .line 802
    move/from16 v44, v4

    .line 803
    .line 804
    move/from16 p1, v5

    .line 805
    .line 806
    move/from16 v43, v11

    .line 807
    .line 808
    move v6, v14

    .line 809
    move-object v4, v15

    .line 810
    move-object/from16 v12, v16

    .line 811
    .line 812
    move/from16 v5, v28

    .line 813
    .line 814
    move-object/from16 v48, v29

    .line 815
    .line 816
    move-object/from16 v47, v30

    .line 817
    .line 818
    move-object/from16 v49, v31

    .line 819
    .line 820
    move/from16 v28, v32

    .line 821
    .line 822
    move-object/from16 v50, v33

    .line 823
    .line 824
    const/16 v34, 0x1

    .line 825
    .line 826
    goto/16 :goto_1f

    .line 827
    .line 828
    :cond_25
    move-object/from16 v40, v2

    .line 829
    .line 830
    iget-object v2, v13, Lo1/t;->k:Ll2/j1;

    .line 831
    .line 832
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 833
    .line 834
    .line 835
    move-result-object v2

    .line 836
    check-cast v2, Ljava/lang/Boolean;

    .line 837
    .line 838
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 839
    .line 840
    .line 841
    move-result v2

    .line 842
    if-eqz v2, :cond_26

    .line 843
    .line 844
    invoke-virtual {v13}, Lo1/t;->c()V

    .line 845
    .line 846
    .line 847
    iget-object v2, v15, Lo1/w;->a:[Lo1/t;

    .line 848
    .line 849
    aput-object v16, v2, v35

    .line 850
    .line 851
    invoke-virtual {v3, v13}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 852
    .line 853
    .line 854
    iget-object v2, v0, Landroidx/compose/foundation/lazy/layout/b;->j:Lo1/v;

    .line 855
    .line 856
    if-eqz v2, :cond_2d

    .line 857
    .line 858
    invoke-static {v2}, Lv3/f;->m(Lv3/p;)V

    .line 859
    .line 860
    .line 861
    goto/16 :goto_1e

    .line 862
    .line 863
    :cond_26
    move-object v2, v15

    .line 864
    iget-object v15, v13, Lo1/t;->n:Lh3/c;

    .line 865
    .line 866
    if-eqz v15, :cond_29

    .line 867
    .line 868
    move/from16 v41, v14

    .line 869
    .line 870
    iget-object v14, v13, Lo1/t;->f:Lc1/a0;

    .line 871
    .line 872
    invoke-virtual {v13}, Lo1/t;->b()Z

    .line 873
    .line 874
    .line 875
    move-result v42

    .line 876
    if-nez v42, :cond_27

    .line 877
    .line 878
    if-nez v14, :cond_28

    .line 879
    .line 880
    :cond_27
    move/from16 v44, v4

    .line 881
    .line 882
    move/from16 p1, v5

    .line 883
    .line 884
    move/from16 v43, v11

    .line 885
    .line 886
    move-object/from16 v12, v16

    .line 887
    .line 888
    move/from16 v5, v28

    .line 889
    .line 890
    move-object/from16 v48, v29

    .line 891
    .line 892
    move-object/from16 v47, v30

    .line 893
    .line 894
    move-object/from16 v49, v31

    .line 895
    .line 896
    move/from16 v28, v32

    .line 897
    .line 898
    move-object/from16 v50, v33

    .line 899
    .line 900
    move/from16 v6, v41

    .line 901
    .line 902
    goto :goto_1c

    .line 903
    :cond_28
    move-object/from16 v42, v2

    .line 904
    .line 905
    const/4 v2, 0x1

    .line 906
    invoke-virtual {v13, v2}, Lo1/t;->e(Z)V

    .line 907
    .line 908
    .line 909
    iget-object v2, v13, Lo1/t;->a:Lvy0/b0;

    .line 910
    .line 911
    move/from16 v43, v11

    .line 912
    .line 913
    new-instance v11, Lny/f0;

    .line 914
    .line 915
    const/4 v12, 0x4

    .line 916
    move/from16 v44, v4

    .line 917
    .line 918
    move/from16 p1, v5

    .line 919
    .line 920
    move/from16 v5, v28

    .line 921
    .line 922
    move-object/from16 v48, v29

    .line 923
    .line 924
    move-object/from16 v47, v30

    .line 925
    .line 926
    move-object/from16 v49, v31

    .line 927
    .line 928
    move/from16 v28, v32

    .line 929
    .line 930
    move-object/from16 v50, v33

    .line 931
    .line 932
    move/from16 v6, v41

    .line 933
    .line 934
    move-object/from16 v4, v42

    .line 935
    .line 936
    const/16 v46, -0x1

    .line 937
    .line 938
    move-object/from16 v29, v1

    .line 939
    .line 940
    move-object/from16 v1, v36

    .line 941
    .line 942
    invoke-direct/range {v11 .. v16}, Lny/f0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 943
    .line 944
    .line 945
    move-object/from16 v12, v16

    .line 946
    .line 947
    const/4 v14, 0x3

    .line 948
    invoke-static {v2, v12, v12, v11, v14}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 949
    .line 950
    .line 951
    goto :goto_1d

    .line 952
    :cond_29
    move/from16 v44, v4

    .line 953
    .line 954
    move/from16 p1, v5

    .line 955
    .line 956
    move/from16 v43, v11

    .line 957
    .line 958
    move v6, v14

    .line 959
    move-object/from16 v12, v16

    .line 960
    .line 961
    move/from16 v5, v28

    .line 962
    .line 963
    move-object/from16 v48, v29

    .line 964
    .line 965
    move-object/from16 v47, v30

    .line 966
    .line 967
    move-object/from16 v49, v31

    .line 968
    .line 969
    move/from16 v28, v32

    .line 970
    .line 971
    move-object/from16 v50, v33

    .line 972
    .line 973
    :goto_1c
    const/16 v46, -0x1

    .line 974
    .line 975
    move-object/from16 v29, v1

    .line 976
    .line 977
    move-object v4, v2

    .line 978
    move-object/from16 v1, v36

    .line 979
    .line 980
    :goto_1d
    invoke-virtual {v13}, Lo1/t;->b()Z

    .line 981
    .line 982
    .line 983
    move-result v2

    .line 984
    if-eqz v2, :cond_2b

    .line 985
    .line 986
    invoke-virtual {v3, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 987
    .line 988
    .line 989
    iget-object v2, v0, Landroidx/compose/foundation/lazy/layout/b;->j:Lo1/v;

    .line 990
    .line 991
    if-eqz v2, :cond_2a

    .line 992
    .line 993
    invoke-static {v2}, Lv3/f;->m(Lv3/p;)V

    .line 994
    .line 995
    .line 996
    :cond_2a
    const/16 v34, 0x1

    .line 997
    .line 998
    goto :goto_20

    .line 999
    :cond_2b
    invoke-virtual {v13}, Lo1/t;->c()V

    .line 1000
    .line 1001
    .line 1002
    iget-object v2, v4, Lo1/w;->a:[Lo1/t;

    .line 1003
    .line 1004
    aput-object v12, v2, v35

    .line 1005
    .line 1006
    goto :goto_20

    .line 1007
    :cond_2c
    move-object/from16 v40, v2

    .line 1008
    .line 1009
    :cond_2d
    :goto_1e
    move/from16 v44, v4

    .line 1010
    .line 1011
    move/from16 p1, v5

    .line 1012
    .line 1013
    move/from16 v43, v11

    .line 1014
    .line 1015
    move v6, v14

    .line 1016
    move-object v4, v15

    .line 1017
    move-object/from16 v12, v16

    .line 1018
    .line 1019
    move/from16 v5, v28

    .line 1020
    .line 1021
    move-object/from16 v48, v29

    .line 1022
    .line 1023
    move-object/from16 v47, v30

    .line 1024
    .line 1025
    move-object/from16 v49, v31

    .line 1026
    .line 1027
    move/from16 v28, v32

    .line 1028
    .line 1029
    move-object/from16 v50, v33

    .line 1030
    .line 1031
    :goto_1f
    const/16 v46, -0x1

    .line 1032
    .line 1033
    move-object/from16 v29, v1

    .line 1034
    .line 1035
    move-object/from16 v1, v36

    .line 1036
    .line 1037
    :goto_20
    add-int/lit8 v2, v44, 0x1

    .line 1038
    .line 1039
    move-object v13, v1

    .line 1040
    move-object v15, v4

    .line 1041
    move v14, v6

    .line 1042
    move-object/from16 v16, v12

    .line 1043
    .line 1044
    move/from16 v32, v28

    .line 1045
    .line 1046
    move-object/from16 v1, v29

    .line 1047
    .line 1048
    move/from16 v35, v39

    .line 1049
    .line 1050
    move/from16 v11, v43

    .line 1051
    .line 1052
    move-object/from16 v30, v47

    .line 1053
    .line 1054
    move-object/from16 v29, v48

    .line 1055
    .line 1056
    move-object/from16 v31, v49

    .line 1057
    .line 1058
    move-object/from16 v33, v50

    .line 1059
    .line 1060
    move-object/from16 v12, p5

    .line 1061
    .line 1062
    move/from16 v6, p9

    .line 1063
    .line 1064
    move v4, v2

    .line 1065
    move/from16 v28, v5

    .line 1066
    .line 1067
    move-object/from16 v2, v40

    .line 1068
    .line 1069
    move/from16 v5, p1

    .line 1070
    .line 1071
    goto/16 :goto_1b

    .line 1072
    .line 1073
    :cond_2e
    move/from16 p1, v5

    .line 1074
    .line 1075
    move v6, v14

    .line 1076
    move-object/from16 v12, v16

    .line 1077
    .line 1078
    move/from16 v5, v28

    .line 1079
    .line 1080
    move-object/from16 v48, v29

    .line 1081
    .line 1082
    move-object/from16 v47, v30

    .line 1083
    .line 1084
    move-object/from16 v49, v31

    .line 1085
    .line 1086
    move/from16 v28, v32

    .line 1087
    .line 1088
    move-object/from16 v50, v33

    .line 1089
    .line 1090
    const/16 v46, -0x1

    .line 1091
    .line 1092
    move-object/from16 v29, v1

    .line 1093
    .line 1094
    move-object v1, v13

    .line 1095
    if-nez v34, :cond_35

    .line 1096
    .line 1097
    invoke-virtual {v0, v1}, Landroidx/compose/foundation/lazy/layout/b;->f(Ljava/lang/Object;)V

    .line 1098
    .line 1099
    .line 1100
    goto/16 :goto_24

    .line 1101
    .line 1102
    :cond_2f
    move/from16 v46, v4

    .line 1103
    .line 1104
    move/from16 p1, v5

    .line 1105
    .line 1106
    move v6, v14

    .line 1107
    move-object v4, v15

    .line 1108
    move-object/from16 v12, v16

    .line 1109
    .line 1110
    move/from16 v5, v28

    .line 1111
    .line 1112
    move-object/from16 v48, v29

    .line 1113
    .line 1114
    move-object/from16 v47, v30

    .line 1115
    .line 1116
    move-object/from16 v49, v31

    .line 1117
    .line 1118
    move/from16 v28, v32

    .line 1119
    .line 1120
    move-object/from16 v50, v33

    .line 1121
    .line 1122
    move-object/from16 v29, v1

    .line 1123
    .line 1124
    move-object v1, v13

    .line 1125
    iget-object v11, v4, Lo1/w;->b:Lt4/a;

    .line 1126
    .line 1127
    invoke-static {v11}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 1128
    .line 1129
    .line 1130
    iget-wide v13, v11, Lt4/a;->a:J

    .line 1131
    .line 1132
    iget v11, v4, Lo1/w;->d:I

    .line 1133
    .line 1134
    iget v15, v4, Lo1/w;->e:I

    .line 1135
    .line 1136
    move-object/from16 v39, p6

    .line 1137
    .line 1138
    move/from16 v42, v2

    .line 1139
    .line 1140
    move/from16 v43, v11

    .line 1141
    .line 1142
    move-wide/from16 v40, v13

    .line 1143
    .line 1144
    move/from16 v44, v15

    .line 1145
    .line 1146
    invoke-virtual/range {v39 .. v44}, Lap0/o;->B(JIII)Lo1/e0;

    .line 1147
    .line 1148
    .line 1149
    move-result-object v31

    .line 1150
    invoke-interface/range {v31 .. v31}, Lo1/e0;->i()V

    .line 1151
    .line 1152
    .line 1153
    iget-object v11, v4, Lo1/w;->a:[Lo1/t;

    .line 1154
    .line 1155
    array-length v13, v11

    .line 1156
    const/4 v14, 0x0

    .line 1157
    :goto_21
    if-ge v14, v13, :cond_31

    .line 1158
    .line 1159
    aget-object v15, v11, v14

    .line 1160
    .line 1161
    if-eqz v15, :cond_30

    .line 1162
    .line 1163
    iget-object v15, v15, Lo1/t;->h:Ll2/j1;

    .line 1164
    .line 1165
    invoke-virtual {v15}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 1166
    .line 1167
    .line 1168
    move-result-object v15

    .line 1169
    check-cast v15, Ljava/lang/Boolean;

    .line 1170
    .line 1171
    invoke-virtual {v15}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1172
    .line 1173
    .line 1174
    move-result v15

    .line 1175
    const/4 v12, 0x1

    .line 1176
    if-ne v15, v12, :cond_30

    .line 1177
    .line 1178
    goto :goto_22

    .line 1179
    :cond_30
    add-int/lit8 v14, v14, 0x1

    .line 1180
    .line 1181
    const/4 v12, 0x0

    .line 1182
    goto :goto_21

    .line 1183
    :cond_31
    if-eqz v7, :cond_32

    .line 1184
    .line 1185
    invoke-virtual {v7, v1}, Lbb/g0;->i(Ljava/lang/Object;)I

    .line 1186
    .line 1187
    .line 1188
    move-result v11

    .line 1189
    if-ne v2, v11, :cond_32

    .line 1190
    .line 1191
    invoke-virtual {v0, v1}, Landroidx/compose/foundation/lazy/layout/b;->f(Ljava/lang/Object;)V

    .line 1192
    .line 1193
    .line 1194
    goto :goto_24

    .line 1195
    :cond_32
    :goto_22
    iget v1, v4, Lo1/w;->c:I

    .line 1196
    .line 1197
    move/from16 v34, p11

    .line 1198
    .line 1199
    move/from16 v35, p12

    .line 1200
    .line 1201
    move-object/from16 v32, p13

    .line 1202
    .line 1203
    move-object/from16 v33, p14

    .line 1204
    .line 1205
    move/from16 v36, v1

    .line 1206
    .line 1207
    move-object/from16 v30, v4

    .line 1208
    .line 1209
    invoke-virtual/range {v30 .. v36}, Lo1/w;->a(Lo1/e0;Lvy0/b0;Le3/w;III)V

    .line 1210
    .line 1211
    .line 1212
    move-object/from16 v1, v31

    .line 1213
    .line 1214
    iget v4, v0, Landroidx/compose/foundation/lazy/layout/b;->c:I

    .line 1215
    .line 1216
    if-ge v2, v4, :cond_33

    .line 1217
    .line 1218
    invoke-virtual {v9, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1219
    .line 1220
    .line 1221
    goto :goto_24

    .line 1222
    :cond_33
    invoke-virtual {v8, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1223
    .line 1224
    .line 1225
    goto :goto_24

    .line 1226
    :cond_34
    :goto_23
    move-object/from16 p10, v2

    .line 1227
    .line 1228
    move-object/from16 v45, v4

    .line 1229
    .line 1230
    move/from16 p1, v5

    .line 1231
    .line 1232
    move-object/from16 v50, v11

    .line 1233
    .line 1234
    move v6, v14

    .line 1235
    move/from16 v5, v28

    .line 1236
    .line 1237
    move-object/from16 v48, v29

    .line 1238
    .line 1239
    move-object/from16 v47, v30

    .line 1240
    .line 1241
    move-object/from16 v49, v31

    .line 1242
    .line 1243
    const/16 v46, -0x1

    .line 1244
    .line 1245
    move-object/from16 v29, v1

    .line 1246
    .line 1247
    move/from16 v28, v12

    .line 1248
    .line 1249
    :cond_35
    :goto_24
    shr-long v37, v37, v5

    .line 1250
    .line 1251
    add-int/lit8 v12, v28, 0x1

    .line 1252
    .line 1253
    move-object/from16 v2, p10

    .line 1254
    .line 1255
    move/from16 v28, v5

    .line 1256
    .line 1257
    move v14, v6

    .line 1258
    move-object/from16 v1, v29

    .line 1259
    .line 1260
    move-object/from16 v4, v45

    .line 1261
    .line 1262
    move-object/from16 v30, v47

    .line 1263
    .line 1264
    move-object/from16 v29, v48

    .line 1265
    .line 1266
    move-object/from16 v31, v49

    .line 1267
    .line 1268
    move-object/from16 v11, v50

    .line 1269
    .line 1270
    const/16 v16, 0x0

    .line 1271
    .line 1272
    move/from16 v5, p1

    .line 1273
    .line 1274
    move/from16 v6, p9

    .line 1275
    .line 1276
    goto/16 :goto_1a

    .line 1277
    .line 1278
    :cond_36
    move-object/from16 p10, v2

    .line 1279
    .line 1280
    move-object/from16 v45, v4

    .line 1281
    .line 1282
    move/from16 p1, v5

    .line 1283
    .line 1284
    move-object/from16 v50, v11

    .line 1285
    .line 1286
    move v6, v14

    .line 1287
    move/from16 v5, v28

    .line 1288
    .line 1289
    move-object/from16 v48, v29

    .line 1290
    .line 1291
    move-object/from16 v47, v30

    .line 1292
    .line 1293
    move-object/from16 v49, v31

    .line 1294
    .line 1295
    const/16 v46, -0x1

    .line 1296
    .line 1297
    move-object/from16 v29, v1

    .line 1298
    .line 1299
    if-ne v6, v5, :cond_39

    .line 1300
    .line 1301
    :goto_25
    move/from16 v1, p1

    .line 1302
    .line 1303
    goto :goto_26

    .line 1304
    :cond_37
    move-object/from16 p10, v2

    .line 1305
    .line 1306
    move-object/from16 v45, v4

    .line 1307
    .line 1308
    move/from16 p1, v5

    .line 1309
    .line 1310
    move-object/from16 v50, v11

    .line 1311
    .line 1312
    move-object/from16 v48, v29

    .line 1313
    .line 1314
    move-object/from16 v47, v30

    .line 1315
    .line 1316
    move-object/from16 v49, v31

    .line 1317
    .line 1318
    const/16 v5, 0x8

    .line 1319
    .line 1320
    const/16 v46, -0x1

    .line 1321
    .line 1322
    move-object/from16 v29, v1

    .line 1323
    .line 1324
    goto :goto_25

    .line 1325
    :goto_26
    if-eq v10, v1, :cond_39

    .line 1326
    .line 1327
    add-int/lit8 v10, v10, 0x1

    .line 1328
    .line 1329
    move/from16 v6, p9

    .line 1330
    .line 1331
    move-object/from16 v2, p10

    .line 1332
    .line 1333
    move v5, v1

    .line 1334
    move-object/from16 v1, v29

    .line 1335
    .line 1336
    move-object/from16 v4, v45

    .line 1337
    .line 1338
    move-object/from16 v15, v47

    .line 1339
    .line 1340
    move-object/from16 v29, v48

    .line 1341
    .line 1342
    move-object/from16 v14, v49

    .line 1343
    .line 1344
    move-object/from16 v11, v50

    .line 1345
    .line 1346
    const/16 v16, 0x0

    .line 1347
    .line 1348
    goto/16 :goto_19

    .line 1349
    .line 1350
    :cond_38
    move-object/from16 v29, v1

    .line 1351
    .line 1352
    move-object/from16 v50, v11

    .line 1353
    .line 1354
    move-object/from16 v48, v13

    .line 1355
    .line 1356
    move-object/from16 v49, v14

    .line 1357
    .line 1358
    move-object/from16 v47, v15

    .line 1359
    .line 1360
    :cond_39
    invoke-virtual {v9}, Ljava/util/ArrayList;->isEmpty()Z

    .line 1361
    .line 1362
    .line 1363
    move-result v1

    .line 1364
    if-nez v1, :cond_3f

    .line 1365
    .line 1366
    invoke-virtual {v9}, Ljava/util/ArrayList;->size()I

    .line 1367
    .line 1368
    .line 1369
    move-result v1

    .line 1370
    const/4 v4, 0x1

    .line 1371
    if-le v1, v4, :cond_3a

    .line 1372
    .line 1373
    new-instance v1, Lo1/x;

    .line 1374
    .line 1375
    const/4 v2, 0x3

    .line 1376
    move-object/from16 v5, p5

    .line 1377
    .line 1378
    invoke-direct {v1, v5, v2}, Lo1/x;-><init>(Lbb/g0;I)V

    .line 1379
    .line 1380
    .line 1381
    invoke-static {v9, v1}, Lmx0/q;->n0(Ljava/util/List;Ljava/util/Comparator;)V

    .line 1382
    .line 1383
    .line 1384
    goto :goto_27

    .line 1385
    :cond_3a
    move-object/from16 v5, p5

    .line 1386
    .line 1387
    :goto_27
    invoke-virtual {v9}, Ljava/util/ArrayList;->size()I

    .line 1388
    .line 1389
    .line 1390
    move-result v1

    .line 1391
    const/4 v2, 0x0

    .line 1392
    :goto_28
    if-ge v2, v1, :cond_3e

    .line 1393
    .line 1394
    invoke-virtual {v9, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1395
    .line 1396
    .line 1397
    move-result-object v3

    .line 1398
    check-cast v3, Lo1/e0;

    .line 1399
    .line 1400
    invoke-interface {v3}, Lo1/e0;->getKey()Ljava/lang/Object;

    .line 1401
    .line 1402
    .line 1403
    move-result-object v4

    .line 1404
    move-object/from16 v6, v50

    .line 1405
    .line 1406
    invoke-virtual {v6, v4}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1407
    .line 1408
    .line 1409
    move-result-object v4

    .line 1410
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 1411
    .line 1412
    .line 1413
    check-cast v4, Lo1/w;

    .line 1414
    .line 1415
    move-object/from16 v7, v29

    .line 1416
    .line 1417
    invoke-static {v7, v3}, Landroidx/compose/foundation/lazy/layout/b;->h([ILo1/e0;)I

    .line 1418
    .line 1419
    .line 1420
    move-result v10

    .line 1421
    if-eqz p8, :cond_3c

    .line 1422
    .line 1423
    invoke-static/range {p4 .. p4}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 1424
    .line 1425
    .line 1426
    move-result-object v11

    .line 1427
    check-cast v11, Lo1/e0;

    .line 1428
    .line 1429
    const/4 v12, 0x0

    .line 1430
    invoke-interface {v11, v12}, Lo1/e0;->j(I)J

    .line 1431
    .line 1432
    .line 1433
    move-result-wide v13

    .line 1434
    invoke-interface {v11}, Lo1/e0;->f()Z

    .line 1435
    .line 1436
    .line 1437
    move-result v11

    .line 1438
    if-eqz v11, :cond_3b

    .line 1439
    .line 1440
    and-long v11, v13, v18

    .line 1441
    .line 1442
    :goto_29
    long-to-int v11, v11

    .line 1443
    goto :goto_2a

    .line 1444
    :cond_3b
    shr-long v11, v13, v17

    .line 1445
    .line 1446
    goto :goto_29

    .line 1447
    :cond_3c
    iget v11, v4, Lo1/w;->f:I

    .line 1448
    .line 1449
    :goto_2a
    sub-int/2addr v11, v10

    .line 1450
    iget v4, v4, Lo1/w;->c:I

    .line 1451
    .line 1452
    move/from16 v10, p2

    .line 1453
    .line 1454
    move/from16 v12, p3

    .line 1455
    .line 1456
    invoke-interface {v3, v11, v4, v10, v12}, Lo1/e0;->a(IIII)V

    .line 1457
    .line 1458
    .line 1459
    if-eqz v20, :cond_3d

    .line 1460
    .line 1461
    const/4 v4, 0x1

    .line 1462
    invoke-virtual {v0, v3, v4}, Landroidx/compose/foundation/lazy/layout/b;->g(Lo1/e0;Z)V

    .line 1463
    .line 1464
    .line 1465
    :cond_3d
    add-int/lit8 v2, v2, 0x1

    .line 1466
    .line 1467
    move-object/from16 v50, v6

    .line 1468
    .line 1469
    move-object/from16 v29, v7

    .line 1470
    .line 1471
    goto :goto_28

    .line 1472
    :cond_3e
    move/from16 v10, p2

    .line 1473
    .line 1474
    move/from16 v12, p3

    .line 1475
    .line 1476
    move/from16 v2, p9

    .line 1477
    .line 1478
    move-object/from16 v7, v29

    .line 1479
    .line 1480
    move-object/from16 v6, v50

    .line 1481
    .line 1482
    const/4 v3, 0x0

    .line 1483
    invoke-static {v7, v3, v2, v3}, Ljava/util/Arrays;->fill([IIII)V

    .line 1484
    .line 1485
    .line 1486
    goto :goto_2b

    .line 1487
    :cond_3f
    move/from16 v10, p2

    .line 1488
    .line 1489
    move/from16 v12, p3

    .line 1490
    .line 1491
    move-object/from16 v5, p5

    .line 1492
    .line 1493
    move-object/from16 v7, v29

    .line 1494
    .line 1495
    move-object/from16 v6, v50

    .line 1496
    .line 1497
    :goto_2b
    invoke-virtual {v8}, Ljava/util/ArrayList;->isEmpty()Z

    .line 1498
    .line 1499
    .line 1500
    move-result v1

    .line 1501
    if-nez v1, :cond_44

    .line 1502
    .line 1503
    invoke-virtual {v8}, Ljava/util/ArrayList;->size()I

    .line 1504
    .line 1505
    .line 1506
    move-result v1

    .line 1507
    const/4 v4, 0x1

    .line 1508
    if-le v1, v4, :cond_40

    .line 1509
    .line 1510
    new-instance v1, Lo1/x;

    .line 1511
    .line 1512
    const/4 v2, 0x1

    .line 1513
    invoke-direct {v1, v5, v2}, Lo1/x;-><init>(Lbb/g0;I)V

    .line 1514
    .line 1515
    .line 1516
    invoke-static {v8, v1}, Lmx0/q;->n0(Ljava/util/List;Ljava/util/Comparator;)V

    .line 1517
    .line 1518
    .line 1519
    :cond_40
    invoke-virtual {v8}, Ljava/util/ArrayList;->size()I

    .line 1520
    .line 1521
    .line 1522
    move-result v1

    .line 1523
    const/4 v2, 0x0

    .line 1524
    :goto_2c
    if-ge v2, v1, :cond_44

    .line 1525
    .line 1526
    invoke-virtual {v8, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1527
    .line 1528
    .line 1529
    move-result-object v3

    .line 1530
    check-cast v3, Lo1/e0;

    .line 1531
    .line 1532
    invoke-interface {v3}, Lo1/e0;->getKey()Ljava/lang/Object;

    .line 1533
    .line 1534
    .line 1535
    move-result-object v4

    .line 1536
    invoke-virtual {v6, v4}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1537
    .line 1538
    .line 1539
    move-result-object v4

    .line 1540
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 1541
    .line 1542
    .line 1543
    check-cast v4, Lo1/w;

    .line 1544
    .line 1545
    invoke-static {v7, v3}, Landroidx/compose/foundation/lazy/layout/b;->h([ILo1/e0;)I

    .line 1546
    .line 1547
    .line 1548
    move-result v5

    .line 1549
    if-eqz p8, :cond_42

    .line 1550
    .line 1551
    invoke-static/range {p4 .. p4}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 1552
    .line 1553
    .line 1554
    move-result-object v11

    .line 1555
    check-cast v11, Lo1/e0;

    .line 1556
    .line 1557
    const/4 v13, 0x0

    .line 1558
    invoke-interface {v11, v13}, Lo1/e0;->j(I)J

    .line 1559
    .line 1560
    .line 1561
    move-result-wide v14

    .line 1562
    invoke-interface {v11}, Lo1/e0;->f()Z

    .line 1563
    .line 1564
    .line 1565
    move-result v13

    .line 1566
    if-eqz v13, :cond_41

    .line 1567
    .line 1568
    and-long v13, v14, v18

    .line 1569
    .line 1570
    :goto_2d
    long-to-int v13, v13

    .line 1571
    goto :goto_2e

    .line 1572
    :cond_41
    shr-long v13, v14, v17

    .line 1573
    .line 1574
    goto :goto_2d

    .line 1575
    :goto_2e
    invoke-interface {v11}, Lo1/e0;->g()I

    .line 1576
    .line 1577
    .line 1578
    move-result v11

    .line 1579
    add-int/2addr v11, v13

    .line 1580
    goto :goto_2f

    .line 1581
    :cond_42
    iget v11, v4, Lo1/w;->g:I

    .line 1582
    .line 1583
    :goto_2f
    invoke-interface {v3}, Lo1/e0;->g()I

    .line 1584
    .line 1585
    .line 1586
    move-result v13

    .line 1587
    sub-int/2addr v11, v13

    .line 1588
    add-int/2addr v11, v5

    .line 1589
    iget v4, v4, Lo1/w;->c:I

    .line 1590
    .line 1591
    invoke-interface {v3, v11, v4, v10, v12}, Lo1/e0;->a(IIII)V

    .line 1592
    .line 1593
    .line 1594
    const/4 v4, 0x1

    .line 1595
    if-eqz v20, :cond_43

    .line 1596
    .line 1597
    invoke-virtual {v0, v3, v4}, Landroidx/compose/foundation/lazy/layout/b;->g(Lo1/e0;Z)V

    .line 1598
    .line 1599
    .line 1600
    :cond_43
    add-int/lit8 v2, v2, 0x1

    .line 1601
    .line 1602
    goto :goto_2c

    .line 1603
    :cond_44
    invoke-static {v9}, Ljava/util/Collections;->reverse(Ljava/util/List;)V

    .line 1604
    .line 1605
    .line 1606
    move-object/from16 v4, p4

    .line 1607
    .line 1608
    const/4 v12, 0x0

    .line 1609
    invoke-virtual {v4, v12, v9}, Ljava/util/ArrayList;->addAll(ILjava/util/Collection;)Z

    .line 1610
    .line 1611
    .line 1612
    invoke-virtual {v4, v8}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 1613
    .line 1614
    .line 1615
    invoke-virtual/range {v49 .. v49}, Ljava/util/ArrayList;->clear()V

    .line 1616
    .line 1617
    .line 1618
    invoke-virtual/range {v48 .. v48}, Ljava/util/ArrayList;->clear()V

    .line 1619
    .line 1620
    .line 1621
    invoke-virtual {v9}, Ljava/util/ArrayList;->clear()V

    .line 1622
    .line 1623
    .line 1624
    invoke-virtual {v8}, Ljava/util/ArrayList;->clear()V

    .line 1625
    .line 1626
    .line 1627
    invoke-virtual/range {v47 .. v47}, Landroidx/collection/r0;->b()V

    .line 1628
    .line 1629
    .line 1630
    return-void
.end method

.method public final e()V
    .locals 14

    .line 1
    iget-object p0, p0, Landroidx/compose/foundation/lazy/layout/b;->a:Landroidx/collection/q0;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroidx/collection/q0;->j()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_5

    .line 8
    .line 9
    iget-object v0, p0, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 10
    .line 11
    iget-object v1, p0, Landroidx/collection/q0;->a:[J

    .line 12
    .line 13
    array-length v2, v1

    .line 14
    add-int/lit8 v2, v2, -0x2

    .line 15
    .line 16
    if-ltz v2, :cond_4

    .line 17
    .line 18
    const/4 v3, 0x0

    .line 19
    move v4, v3

    .line 20
    :goto_0
    aget-wide v5, v1, v4

    .line 21
    .line 22
    not-long v7, v5

    .line 23
    const/4 v9, 0x7

    .line 24
    shl-long/2addr v7, v9

    .line 25
    and-long/2addr v7, v5

    .line 26
    const-wide v9, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 27
    .line 28
    .line 29
    .line 30
    .line 31
    and-long/2addr v7, v9

    .line 32
    cmp-long v7, v7, v9

    .line 33
    .line 34
    if-eqz v7, :cond_3

    .line 35
    .line 36
    sub-int v7, v4, v2

    .line 37
    .line 38
    not-int v7, v7

    .line 39
    ushr-int/lit8 v7, v7, 0x1f

    .line 40
    .line 41
    const/16 v8, 0x8

    .line 42
    .line 43
    rsub-int/lit8 v7, v7, 0x8

    .line 44
    .line 45
    move v9, v3

    .line 46
    :goto_1
    if-ge v9, v7, :cond_2

    .line 47
    .line 48
    const-wide/16 v10, 0xff

    .line 49
    .line 50
    and-long/2addr v10, v5

    .line 51
    const-wide/16 v12, 0x80

    .line 52
    .line 53
    cmp-long v10, v10, v12

    .line 54
    .line 55
    if-gez v10, :cond_1

    .line 56
    .line 57
    shl-int/lit8 v10, v4, 0x3

    .line 58
    .line 59
    add-int/2addr v10, v9

    .line 60
    aget-object v10, v0, v10

    .line 61
    .line 62
    check-cast v10, Lo1/w;

    .line 63
    .line 64
    iget-object v10, v10, Lo1/w;->a:[Lo1/t;

    .line 65
    .line 66
    array-length v11, v10

    .line 67
    move v12, v3

    .line 68
    :goto_2
    if-ge v12, v11, :cond_1

    .line 69
    .line 70
    aget-object v13, v10, v12

    .line 71
    .line 72
    if-eqz v13, :cond_0

    .line 73
    .line 74
    invoke-virtual {v13}, Lo1/t;->c()V

    .line 75
    .line 76
    .line 77
    :cond_0
    add-int/lit8 v12, v12, 0x1

    .line 78
    .line 79
    goto :goto_2

    .line 80
    :cond_1
    shr-long/2addr v5, v8

    .line 81
    add-int/lit8 v9, v9, 0x1

    .line 82
    .line 83
    goto :goto_1

    .line 84
    :cond_2
    if-ne v7, v8, :cond_4

    .line 85
    .line 86
    :cond_3
    if-eq v4, v2, :cond_4

    .line 87
    .line 88
    add-int/lit8 v4, v4, 0x1

    .line 89
    .line 90
    goto :goto_0

    .line 91
    :cond_4
    invoke-virtual {p0}, Landroidx/collection/q0;->a()V

    .line 92
    .line 93
    .line 94
    :cond_5
    return-void
.end method

.method public final f(Ljava/lang/Object;)V
    .locals 2

    .line 1
    iget-object p0, p0, Landroidx/compose/foundation/lazy/layout/b;->a:Landroidx/collection/q0;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Landroidx/collection/q0;->k(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lo1/w;

    .line 8
    .line 9
    if-eqz p0, :cond_1

    .line 10
    .line 11
    iget-object p0, p0, Lo1/w;->a:[Lo1/t;

    .line 12
    .line 13
    if-eqz p0, :cond_1

    .line 14
    .line 15
    array-length p1, p0

    .line 16
    const/4 v0, 0x0

    .line 17
    :goto_0
    if-ge v0, p1, :cond_1

    .line 18
    .line 19
    aget-object v1, p0, v0

    .line 20
    .line 21
    if-eqz v1, :cond_0

    .line 22
    .line 23
    invoke-virtual {v1}, Lo1/t;->c()V

    .line 24
    .line 25
    .line 26
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_1
    return-void
.end method

.method public final g(Lo1/e0;Z)V
    .locals 13

    .line 1
    iget-object p0, p0, Landroidx/compose/foundation/lazy/layout/b;->a:Landroidx/collection/q0;

    .line 2
    .line 3
    invoke-interface {p1}, Lo1/e0;->getKey()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {p0, v0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    check-cast p0, Lo1/w;

    .line 15
    .line 16
    iget-object p0, p0, Lo1/w;->a:[Lo1/t;

    .line 17
    .line 18
    array-length v0, p0

    .line 19
    const/4 v1, 0x0

    .line 20
    move v2, v1

    .line 21
    :goto_0
    if-ge v1, v0, :cond_3

    .line 22
    .line 23
    aget-object v4, p0, v1

    .line 24
    .line 25
    add-int/lit8 v10, v2, 0x1

    .line 26
    .line 27
    if-eqz v4, :cond_2

    .line 28
    .line 29
    invoke-interface {p1, v2}, Lo1/e0;->j(I)J

    .line 30
    .line 31
    .line 32
    move-result-wide v11

    .line 33
    iget-wide v2, v4, Lo1/t;->l:J

    .line 34
    .line 35
    sget-wide v5, Lo1/t;->s:J

    .line 36
    .line 37
    invoke-static {v2, v3, v5, v6}, Lt4/j;->b(JJ)Z

    .line 38
    .line 39
    .line 40
    move-result v5

    .line 41
    if-nez v5, :cond_1

    .line 42
    .line 43
    invoke-static {v2, v3, v11, v12}, Lt4/j;->b(JJ)Z

    .line 44
    .line 45
    .line 46
    move-result v5

    .line 47
    if-nez v5, :cond_1

    .line 48
    .line 49
    invoke-static {v11, v12, v2, v3}, Lt4/j;->c(JJ)J

    .line 50
    .line 51
    .line 52
    move-result-wide v2

    .line 53
    iget-object v5, v4, Lo1/t;->e:Lc1/a0;

    .line 54
    .line 55
    if-nez v5, :cond_0

    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_0
    iget-object v6, v4, Lo1/t;->q:Ll2/j1;

    .line 59
    .line 60
    invoke-virtual {v6}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v6

    .line 64
    check-cast v6, Lt4/j;

    .line 65
    .line 66
    iget-wide v6, v6, Lt4/j;->a:J

    .line 67
    .line 68
    invoke-static {v6, v7, v2, v3}, Lt4/j;->c(JJ)J

    .line 69
    .line 70
    .line 71
    move-result-wide v6

    .line 72
    invoke-virtual {v4, v6, v7}, Lo1/t;->g(J)V

    .line 73
    .line 74
    .line 75
    const/4 v2, 0x1

    .line 76
    invoke-virtual {v4, v2}, Lo1/t;->f(Z)V

    .line 77
    .line 78
    .line 79
    iput-boolean p2, v4, Lo1/t;->g:Z

    .line 80
    .line 81
    iget-object v2, v4, Lo1/t;->a:Lvy0/b0;

    .line 82
    .line 83
    new-instance v3, Le1/b;

    .line 84
    .line 85
    const/4 v8, 0x0

    .line 86
    const/4 v9, 0x6

    .line 87
    invoke-direct/range {v3 .. v9}, Le1/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;JLkotlin/coroutines/Continuation;I)V

    .line 88
    .line 89
    .line 90
    const/4 v5, 0x3

    .line 91
    const/4 v6, 0x0

    .line 92
    invoke-static {v2, v6, v6, v3, v5}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 93
    .line 94
    .line 95
    :cond_1
    :goto_1
    iput-wide v11, v4, Lo1/t;->l:J

    .line 96
    .line 97
    :cond_2
    add-int/lit8 v1, v1, 0x1

    .line 98
    .line 99
    move v2, v10

    .line 100
    goto :goto_0

    .line 101
    :cond_3
    return-void
.end method
