.class public final Lp3/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lt3/y;

.field public b:Z

.field public c:Z

.field public d:Z

.field public e:Z

.field public final f:Landroidx/collection/l0;

.field public final g:Lp3/j;

.field public final h:Landroidx/collection/e0;


# direct methods
.method public constructor <init>(Lt3/y;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lp3/d;->a:Lt3/y;

    .line 5
    .line 6
    new-instance p1, Landroidx/collection/l0;

    .line 7
    .line 8
    invoke-direct {p1}, Landroidx/collection/l0;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lp3/d;->f:Landroidx/collection/l0;

    .line 12
    .line 13
    new-instance p1, Lp3/j;

    .line 14
    .line 15
    invoke-direct {p1}, Lp3/j;-><init>()V

    .line 16
    .line 17
    .line 18
    iput-object p1, p0, Lp3/d;->g:Lp3/j;

    .line 19
    .line 20
    new-instance p1, Landroidx/collection/e0;

    .line 21
    .line 22
    const/16 v0, 0xa

    .line 23
    .line 24
    invoke-direct {p1, v0}, Landroidx/collection/e0;-><init>(I)V

    .line 25
    .line 26
    .line 27
    iput-object p1, p0, Lp3/d;->h:Landroidx/collection/e0;

    .line 28
    .line 29
    return-void
.end method


# virtual methods
.method public final a(JLjava/util/List;Z)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-wide/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v3, p3

    .line 6
    .line 7
    iget-object v4, v0, Lp3/d;->h:Landroidx/collection/e0;

    .line 8
    .line 9
    invoke-virtual {v4}, Landroidx/collection/e0;->a()V

    .line 10
    .line 11
    .line 12
    move-object v5, v3

    .line 13
    check-cast v5, Ljava/util/Collection;

    .line 14
    .line 15
    invoke-interface {v5}, Ljava/util/Collection;->size()I

    .line 16
    .line 17
    .line 18
    move-result v5

    .line 19
    iget-object v6, v0, Lp3/d;->g:Lp3/j;

    .line 20
    .line 21
    const/4 v7, 0x1

    .line 22
    move-object v11, v6

    .line 23
    move v10, v7

    .line 24
    const/4 v9, 0x0

    .line 25
    :goto_0
    if-ge v9, v5, :cond_7

    .line 26
    .line 27
    invoke-interface {v3, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v12

    .line 31
    check-cast v12, Lx2/r;

    .line 32
    .line 33
    iget-boolean v13, v12, Lx2/r;->q:Z

    .line 34
    .line 35
    if-eqz v13, :cond_6

    .line 36
    .line 37
    new-instance v13, La4/b;

    .line 38
    .line 39
    const/4 v14, 0x5

    .line 40
    invoke-direct {v13, v14, v0, v12}, La4/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    iput-object v13, v12, Lx2/r;->p:La4/b;

    .line 44
    .line 45
    if-eqz v10, :cond_4

    .line 46
    .line 47
    iget-object v13, v11, Lp3/j;->a:Ln2/b;

    .line 48
    .line 49
    iget-object v14, v13, Ln2/b;->d:[Ljava/lang/Object;

    .line 50
    .line 51
    iget v13, v13, Ln2/b;->f:I

    .line 52
    .line 53
    const/4 v15, 0x0

    .line 54
    :goto_1
    if-ge v15, v13, :cond_1

    .line 55
    .line 56
    aget-object v16, v14, v15

    .line 57
    .line 58
    move-object/from16 v8, v16

    .line 59
    .line 60
    check-cast v8, Lp3/i;

    .line 61
    .line 62
    iget-object v8, v8, Lp3/i;->c:Lx2/r;

    .line 63
    .line 64
    invoke-static {v8, v12}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v8

    .line 68
    if-eqz v8, :cond_0

    .line 69
    .line 70
    goto :goto_2

    .line 71
    :cond_0
    add-int/lit8 v15, v15, 0x1

    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_1
    const/16 v16, 0x0

    .line 75
    .line 76
    :goto_2
    move-object/from16 v8, v16

    .line 77
    .line 78
    check-cast v8, Lp3/i;

    .line 79
    .line 80
    if-eqz v8, :cond_3

    .line 81
    .line 82
    iput-boolean v7, v8, Lp3/i;->i:Z

    .line 83
    .line 84
    iget-object v11, v8, Lp3/i;->d:Lq3/b;

    .line 85
    .line 86
    invoke-virtual {v11, v1, v2}, Lq3/b;->a(J)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {v4, v1, v2}, Landroidx/collection/e0;->d(J)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v11

    .line 93
    if-nez v11, :cond_2

    .line 94
    .line 95
    new-instance v11, Landroidx/collection/l0;

    .line 96
    .line 97
    invoke-direct {v11}, Landroidx/collection/l0;-><init>()V

    .line 98
    .line 99
    .line 100
    invoke-virtual {v4, v1, v2, v11}, Landroidx/collection/e0;->g(JLjava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    :cond_2
    check-cast v11, Landroidx/collection/l0;

    .line 104
    .line 105
    invoke-virtual {v11, v8}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    :goto_3
    move-object v11, v8

    .line 109
    goto :goto_4

    .line 110
    :cond_3
    const/4 v10, 0x0

    .line 111
    :cond_4
    new-instance v8, Lp3/i;

    .line 112
    .line 113
    invoke-direct {v8, v12}, Lp3/i;-><init>(Lx2/r;)V

    .line 114
    .line 115
    .line 116
    iget-object v12, v8, Lp3/i;->d:Lq3/b;

    .line 117
    .line 118
    invoke-virtual {v12, v1, v2}, Lq3/b;->a(J)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {v4, v1, v2}, Landroidx/collection/e0;->d(J)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v12

    .line 125
    if-nez v12, :cond_5

    .line 126
    .line 127
    new-instance v12, Landroidx/collection/l0;

    .line 128
    .line 129
    invoke-direct {v12}, Landroidx/collection/l0;-><init>()V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v4, v1, v2, v12}, Landroidx/collection/e0;->g(JLjava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    :cond_5
    check-cast v12, Landroidx/collection/l0;

    .line 136
    .line 137
    invoke-virtual {v12, v8}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 138
    .line 139
    .line 140
    iget-object v11, v11, Lp3/j;->a:Ln2/b;

    .line 141
    .line 142
    invoke-virtual {v11, v8}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    goto :goto_3

    .line 146
    :cond_6
    :goto_4
    add-int/lit8 v9, v9, 0x1

    .line 147
    .line 148
    goto :goto_0

    .line 149
    :cond_7
    if-eqz p4, :cond_c

    .line 150
    .line 151
    iget-object v0, v4, Landroidx/collection/e0;->b:[J

    .line 152
    .line 153
    iget-object v1, v4, Landroidx/collection/e0;->c:[Ljava/lang/Object;

    .line 154
    .line 155
    iget-object v2, v4, Landroidx/collection/e0;->a:[J

    .line 156
    .line 157
    array-length v3, v2

    .line 158
    add-int/lit8 v3, v3, -0x2

    .line 159
    .line 160
    if-ltz v3, :cond_c

    .line 161
    .line 162
    const/4 v4, 0x0

    .line 163
    :goto_5
    aget-wide v7, v2, v4

    .line 164
    .line 165
    not-long v9, v7

    .line 166
    const/4 v5, 0x7

    .line 167
    shl-long/2addr v9, v5

    .line 168
    and-long/2addr v9, v7

    .line 169
    const-wide v11, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 170
    .line 171
    .line 172
    .line 173
    .line 174
    and-long/2addr v9, v11

    .line 175
    cmp-long v5, v9, v11

    .line 176
    .line 177
    if-eqz v5, :cond_b

    .line 178
    .line 179
    sub-int v5, v4, v3

    .line 180
    .line 181
    not-int v5, v5

    .line 182
    ushr-int/lit8 v5, v5, 0x1f

    .line 183
    .line 184
    const/16 v9, 0x8

    .line 185
    .line 186
    rsub-int/lit8 v5, v5, 0x8

    .line 187
    .line 188
    const/4 v10, 0x0

    .line 189
    :goto_6
    if-ge v10, v5, :cond_a

    .line 190
    .line 191
    const-wide/16 v11, 0xff

    .line 192
    .line 193
    and-long/2addr v11, v7

    .line 194
    const-wide/16 v13, 0x80

    .line 195
    .line 196
    cmp-long v11, v11, v13

    .line 197
    .line 198
    if-gez v11, :cond_9

    .line 199
    .line 200
    shl-int/lit8 v11, v4, 0x3

    .line 201
    .line 202
    add-int/2addr v11, v10

    .line 203
    aget-wide v12, v0, v11

    .line 204
    .line 205
    aget-object v11, v1, v11

    .line 206
    .line 207
    check-cast v11, Landroidx/collection/l0;

    .line 208
    .line 209
    iget-object v14, v6, Lp3/j;->a:Ln2/b;

    .line 210
    .line 211
    iget-object v15, v14, Ln2/b;->d:[Ljava/lang/Object;

    .line 212
    .line 213
    iget v14, v14, Ln2/b;->f:I

    .line 214
    .line 215
    move/from16 p0, v9

    .line 216
    .line 217
    const/4 v9, 0x0

    .line 218
    :goto_7
    if-ge v9, v14, :cond_8

    .line 219
    .line 220
    aget-object v16, v15, v9

    .line 221
    .line 222
    move-object/from16 p1, v0

    .line 223
    .line 224
    move-object/from16 v0, v16

    .line 225
    .line 226
    check-cast v0, Lp3/i;

    .line 227
    .line 228
    invoke-virtual {v0, v12, v13, v11}, Lp3/i;->f(JLandroidx/collection/l0;)V

    .line 229
    .line 230
    .line 231
    add-int/lit8 v9, v9, 0x1

    .line 232
    .line 233
    move-object/from16 v0, p1

    .line 234
    .line 235
    goto :goto_7

    .line 236
    :cond_8
    :goto_8
    move-object/from16 p1, v0

    .line 237
    .line 238
    goto :goto_9

    .line 239
    :cond_9
    move/from16 p0, v9

    .line 240
    .line 241
    goto :goto_8

    .line 242
    :goto_9
    shr-long v7, v7, p0

    .line 243
    .line 244
    add-int/lit8 v10, v10, 0x1

    .line 245
    .line 246
    move/from16 v9, p0

    .line 247
    .line 248
    move-object/from16 v0, p1

    .line 249
    .line 250
    goto :goto_6

    .line 251
    :cond_a
    move-object/from16 p1, v0

    .line 252
    .line 253
    move v0, v9

    .line 254
    if-ne v5, v0, :cond_c

    .line 255
    .line 256
    goto :goto_a

    .line 257
    :cond_b
    move-object/from16 p1, v0

    .line 258
    .line 259
    :goto_a
    if-eq v4, v3, :cond_c

    .line 260
    .line 261
    add-int/lit8 v4, v4, 0x1

    .line 262
    .line 263
    move-object/from16 v0, p1

    .line 264
    .line 265
    goto :goto_5

    .line 266
    :cond_c
    return-void
.end method

.method public final b(Lcom/google/android/gms/internal/measurement/i4;Z)Z
    .locals 9

    .line 1
    iget-object v0, p1, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/collection/u;

    .line 4
    .line 5
    iget-object v1, p0, Lp3/d;->a:Lt3/y;

    .line 6
    .line 7
    iget-object v2, p0, Lp3/d;->g:Lp3/j;

    .line 8
    .line 9
    invoke-virtual {v2, v0, v1, p1, p2}, Lp3/j;->a(Landroidx/collection/u;Lt3/y;Lcom/google/android/gms/internal/measurement/i4;Z)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    iget-object v1, v2, Lp3/j;->a:Ln2/b;

    .line 14
    .line 15
    const/4 v3, 0x0

    .line 16
    if-nez v0, :cond_0

    .line 17
    .line 18
    return v3

    .line 19
    :cond_0
    const/4 v0, 0x1

    .line 20
    iput-boolean v0, p0, Lp3/d;->b:Z

    .line 21
    .line 22
    iget-object v4, v1, Ln2/b;->d:[Ljava/lang/Object;

    .line 23
    .line 24
    iget v5, v1, Ln2/b;->f:I

    .line 25
    .line 26
    move v6, v3

    .line 27
    move v7, v6

    .line 28
    :goto_0
    if-ge v6, v5, :cond_3

    .line 29
    .line 30
    aget-object v8, v4, v6

    .line 31
    .line 32
    check-cast v8, Lp3/i;

    .line 33
    .line 34
    invoke-virtual {v8, p1, p2}, Lp3/i;->e(Lcom/google/android/gms/internal/measurement/i4;Z)Z

    .line 35
    .line 36
    .line 37
    move-result v8

    .line 38
    if-nez v8, :cond_2

    .line 39
    .line 40
    if-eqz v7, :cond_1

    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_1
    move v7, v3

    .line 44
    goto :goto_2

    .line 45
    :cond_2
    :goto_1
    move v7, v0

    .line 46
    :goto_2
    add-int/lit8 v6, v6, 0x1

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_3
    iget-object p2, v1, Ln2/b;->d:[Ljava/lang/Object;

    .line 50
    .line 51
    iget v1, v1, Ln2/b;->f:I

    .line 52
    .line 53
    move v4, v3

    .line 54
    move v5, v4

    .line 55
    :goto_3
    if-ge v4, v1, :cond_6

    .line 56
    .line 57
    aget-object v6, p2, v4

    .line 58
    .line 59
    check-cast v6, Lp3/i;

    .line 60
    .line 61
    invoke-virtual {v6, p1}, Lp3/i;->d(Lcom/google/android/gms/internal/measurement/i4;)Z

    .line 62
    .line 63
    .line 64
    move-result v6

    .line 65
    if-nez v6, :cond_5

    .line 66
    .line 67
    if-eqz v5, :cond_4

    .line 68
    .line 69
    goto :goto_4

    .line 70
    :cond_4
    move v5, v3

    .line 71
    goto :goto_5

    .line 72
    :cond_5
    :goto_4
    move v5, v0

    .line 73
    :goto_5
    add-int/lit8 v4, v4, 0x1

    .line 74
    .line 75
    goto :goto_3

    .line 76
    :cond_6
    invoke-virtual {v2, p1}, Lp3/j;->b(Lcom/google/android/gms/internal/measurement/i4;)V

    .line 77
    .line 78
    .line 79
    if-nez v5, :cond_8

    .line 80
    .line 81
    if-eqz v7, :cond_7

    .line 82
    .line 83
    goto :goto_6

    .line 84
    :cond_7
    move v0, v3

    .line 85
    :cond_8
    :goto_6
    iput-boolean v3, p0, Lp3/d;->b:Z

    .line 86
    .line 87
    iget-boolean p1, p0, Lp3/d;->e:Z

    .line 88
    .line 89
    if-eqz p1, :cond_a

    .line 90
    .line 91
    iput-boolean v3, p0, Lp3/d;->e:Z

    .line 92
    .line 93
    iget-object p1, p0, Lp3/d;->f:Landroidx/collection/l0;

    .line 94
    .line 95
    iget p2, p1, Landroidx/collection/l0;->b:I

    .line 96
    .line 97
    move v1, v3

    .line 98
    :goto_7
    if-ge v1, p2, :cond_9

    .line 99
    .line 100
    invoke-virtual {p1, v1}, Landroidx/collection/l0;->e(I)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v4

    .line 104
    check-cast v4, Lx2/r;

    .line 105
    .line 106
    invoke-virtual {p0, v4}, Lp3/d;->d(Lx2/r;)V

    .line 107
    .line 108
    .line 109
    add-int/lit8 v1, v1, 0x1

    .line 110
    .line 111
    goto :goto_7

    .line 112
    :cond_9
    invoke-virtual {p1}, Landroidx/collection/l0;->c()V

    .line 113
    .line 114
    .line 115
    :cond_a
    iget-boolean p1, p0, Lp3/d;->c:Z

    .line 116
    .line 117
    if-eqz p1, :cond_b

    .line 118
    .line 119
    iput-boolean v3, p0, Lp3/d;->c:Z

    .line 120
    .line 121
    invoke-virtual {p0}, Lp3/d;->c()V

    .line 122
    .line 123
    .line 124
    :cond_b
    iget-boolean p1, p0, Lp3/d;->d:Z

    .line 125
    .line 126
    if-eqz p1, :cond_c

    .line 127
    .line 128
    iput-boolean v3, p0, Lp3/d;->d:Z

    .line 129
    .line 130
    iget-object p0, v2, Lp3/j;->a:Ln2/b;

    .line 131
    .line 132
    invoke-virtual {p0}, Ln2/b;->i()V

    .line 133
    .line 134
    .line 135
    :cond_c
    return v0
.end method

.method public final c()V
    .locals 6

    .line 1
    iget-boolean v0, p0, Lp3/d;->b:Z

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    iput-boolean v1, p0, Lp3/d;->c:Z

    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    iget-object v0, p0, Lp3/d;->g:Lp3/j;

    .line 10
    .line 11
    iget-object v2, v0, Lp3/j;->a:Ln2/b;

    .line 12
    .line 13
    iget-object v3, v2, Ln2/b;->d:[Ljava/lang/Object;

    .line 14
    .line 15
    iget v2, v2, Ln2/b;->f:I

    .line 16
    .line 17
    const/4 v4, 0x0

    .line 18
    :goto_0
    if-ge v4, v2, :cond_1

    .line 19
    .line 20
    aget-object v5, v3, v4

    .line 21
    .line 22
    check-cast v5, Lp3/i;

    .line 23
    .line 24
    invoke-virtual {v5}, Lp3/i;->c()V

    .line 25
    .line 26
    .line 27
    add-int/lit8 v4, v4, 0x1

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_1
    iget-boolean v2, p0, Lp3/d;->d:Z

    .line 31
    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    iput-boolean v1, p0, Lp3/d;->d:Z

    .line 35
    .line 36
    return-void

    .line 37
    :cond_2
    iget-object p0, v0, Lp3/j;->a:Ln2/b;

    .line 38
    .line 39
    invoke-virtual {p0}, Ln2/b;->i()V

    .line 40
    .line 41
    .line 42
    return-void
.end method

.method public final d(Lx2/r;)V
    .locals 5

    .line 1
    iget-boolean v0, p0, Lp3/d;->b:Z

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    iput-boolean v1, p0, Lp3/d;->e:Z

    .line 7
    .line 8
    iget-object p0, p0, Lp3/d;->f:Landroidx/collection/l0;

    .line 9
    .line 10
    invoke-virtual {p0, p1}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    iget-object p0, p0, Lp3/d;->g:Lp3/j;

    .line 15
    .line 16
    iget-object v0, p0, Lp3/j;->b:Landroidx/collection/l0;

    .line 17
    .line 18
    invoke-virtual {v0}, Landroidx/collection/l0;->c()V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0, p0}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    :cond_1
    invoke-virtual {v0}, Landroidx/collection/l0;->h()Z

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    if-eqz p0, :cond_3

    .line 29
    .line 30
    iget p0, v0, Landroidx/collection/l0;->b:I

    .line 31
    .line 32
    sub-int/2addr p0, v1

    .line 33
    invoke-virtual {v0, p0}, Landroidx/collection/l0;->j(I)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    check-cast p0, Lp3/j;

    .line 38
    .line 39
    const/4 v2, 0x0

    .line 40
    :goto_0
    iget-object v3, p0, Lp3/j;->a:Ln2/b;

    .line 41
    .line 42
    iget v4, v3, Ln2/b;->f:I

    .line 43
    .line 44
    if-ge v2, v4, :cond_1

    .line 45
    .line 46
    iget-object v3, v3, Ln2/b;->d:[Ljava/lang/Object;

    .line 47
    .line 48
    aget-object v3, v3, v2

    .line 49
    .line 50
    check-cast v3, Lp3/i;

    .line 51
    .line 52
    iget-object v4, v3, Lp3/i;->c:Lx2/r;

    .line 53
    .line 54
    invoke-static {v4, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v4

    .line 58
    if-eqz v4, :cond_2

    .line 59
    .line 60
    iget-object v4, p0, Lp3/j;->a:Ln2/b;

    .line 61
    .line 62
    invoke-virtual {v4, v3}, Ln2/b;->l(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    invoke-virtual {v3}, Lp3/i;->c()V

    .line 66
    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_2
    invoke-virtual {v0, v3}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    add-int/lit8 v2, v2, 0x1

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_3
    return-void
.end method
