.class public final Ln1/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/r0;


# instance fields
.field public final a:Ln1/p;

.field public final b:I

.field public final c:Z

.field public final d:F

.field public final e:Lt3/r0;

.field public final f:F

.field public final g:Z

.field public final h:Lvy0/b0;

.field public final i:Lt4/c;

.field public final j:I

.field public final k:Lay0/k;

.field public final l:Lay0/k;

.field public final m:Ljava/lang/Object;

.field public final n:I

.field public final o:I

.field public final p:I

.field public final q:Lg1/w1;

.field public final r:I

.field public final s:I


# direct methods
.method public constructor <init>(Ln1/p;IZFLt3/r0;FZLvy0/b0;Lt4/c;ILay0/k;Lay0/k;Ljava/util/List;IIILg1/w1;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ln1/n;->a:Ln1/p;

    .line 5
    .line 6
    iput p2, p0, Ln1/n;->b:I

    .line 7
    .line 8
    iput-boolean p3, p0, Ln1/n;->c:Z

    .line 9
    .line 10
    iput p4, p0, Ln1/n;->d:F

    .line 11
    .line 12
    iput-object p5, p0, Ln1/n;->e:Lt3/r0;

    .line 13
    .line 14
    iput p6, p0, Ln1/n;->f:F

    .line 15
    .line 16
    iput-boolean p7, p0, Ln1/n;->g:Z

    .line 17
    .line 18
    iput-object p8, p0, Ln1/n;->h:Lvy0/b0;

    .line 19
    .line 20
    iput-object p9, p0, Ln1/n;->i:Lt4/c;

    .line 21
    .line 22
    iput p10, p0, Ln1/n;->j:I

    .line 23
    .line 24
    iput-object p11, p0, Ln1/n;->k:Lay0/k;

    .line 25
    .line 26
    iput-object p12, p0, Ln1/n;->l:Lay0/k;

    .line 27
    .line 28
    iput-object p13, p0, Ln1/n;->m:Ljava/lang/Object;

    .line 29
    .line 30
    iput p14, p0, Ln1/n;->n:I

    .line 31
    .line 32
    iput p15, p0, Ln1/n;->o:I

    .line 33
    .line 34
    move/from16 p1, p16

    .line 35
    .line 36
    iput p1, p0, Ln1/n;->p:I

    .line 37
    .line 38
    move-object/from16 p1, p17

    .line 39
    .line 40
    iput-object p1, p0, Ln1/n;->q:Lg1/w1;

    .line 41
    .line 42
    move/from16 p1, p18

    .line 43
    .line 44
    iput p1, p0, Ln1/n;->r:I

    .line 45
    .line 46
    move/from16 p1, p19

    .line 47
    .line 48
    iput p1, p0, Ln1/n;->s:I

    .line 49
    .line 50
    return-void
.end method


# virtual methods
.method public final a(IZ)Ln1/n;
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    iget-boolean v2, v0, Ln1/n;->g:Z

    .line 6
    .line 7
    if-nez v2, :cond_8

    .line 8
    .line 9
    iget-object v2, v0, Ln1/n;->m:Ljava/lang/Object;

    .line 10
    .line 11
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 12
    .line 13
    .line 14
    move-result v3

    .line 15
    if-nez v3, :cond_8

    .line 16
    .line 17
    iget-object v3, v0, Ln1/n;->a:Ln1/p;

    .line 18
    .line 19
    if-eqz v3, :cond_8

    .line 20
    .line 21
    iget v3, v3, Ln1/p;->g:I

    .line 22
    .line 23
    iget v4, v0, Ln1/n;->b:I

    .line 24
    .line 25
    sub-int v5, v4, v1

    .line 26
    .line 27
    if-ltz v5, :cond_8

    .line 28
    .line 29
    if-ge v5, v3, :cond_8

    .line 30
    .line 31
    invoke-static {v2}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v3

    .line 35
    check-cast v3, Ln1/o;

    .line 36
    .line 37
    invoke-static {v2}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v4

    .line 41
    check-cast v4, Ln1/o;

    .line 42
    .line 43
    iget-boolean v6, v3, Ln1/o;->w:Z

    .line 44
    .line 45
    if-nez v6, :cond_8

    .line 46
    .line 47
    iget-boolean v6, v4, Ln1/o;->w:Z

    .line 48
    .line 49
    if-eqz v6, :cond_0

    .line 50
    .line 51
    goto/16 :goto_7

    .line 52
    .line 53
    :cond_0
    iget v6, v0, Ln1/n;->o:I

    .line 54
    .line 55
    iget v7, v0, Ln1/n;->n:I

    .line 56
    .line 57
    iget-object v8, v0, Ln1/n;->q:Lg1/w1;

    .line 58
    .line 59
    if-gez v1, :cond_1

    .line 60
    .line 61
    invoke-static {v3, v8}, Lkp/ca;->b(Ln1/o;Lg1/w1;)I

    .line 62
    .line 63
    .line 64
    move-result v9

    .line 65
    iget v3, v3, Ln1/o;->o:I

    .line 66
    .line 67
    add-int/2addr v9, v3

    .line 68
    sub-int/2addr v9, v7

    .line 69
    invoke-static {v4, v8}, Lkp/ca;->b(Ln1/o;Lg1/w1;)I

    .line 70
    .line 71
    .line 72
    move-result v3

    .line 73
    iget v4, v4, Ln1/o;->o:I

    .line 74
    .line 75
    add-int/2addr v3, v4

    .line 76
    sub-int/2addr v3, v6

    .line 77
    invoke-static {v9, v3}, Ljava/lang/Math;->min(II)I

    .line 78
    .line 79
    .line 80
    move-result v3

    .line 81
    neg-int v4, v1

    .line 82
    if-le v3, v4, :cond_8

    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_1
    invoke-static {v3, v8}, Lkp/ca;->b(Ln1/o;Lg1/w1;)I

    .line 86
    .line 87
    .line 88
    move-result v3

    .line 89
    sub-int/2addr v7, v3

    .line 90
    invoke-static {v4, v8}, Lkp/ca;->b(Ln1/o;Lg1/w1;)I

    .line 91
    .line 92
    .line 93
    move-result v3

    .line 94
    sub-int/2addr v6, v3

    .line 95
    invoke-static {v7, v6}, Ljava/lang/Math;->min(II)I

    .line 96
    .line 97
    .line 98
    move-result v3

    .line 99
    if-le v3, v1, :cond_8

    .line 100
    .line 101
    :goto_0
    move-object v3, v2

    .line 102
    check-cast v3, Ljava/util/Collection;

    .line 103
    .line 104
    invoke-interface {v3}, Ljava/util/Collection;->size()I

    .line 105
    .line 106
    .line 107
    move-result v3

    .line 108
    const/4 v6, 0x0

    .line 109
    :goto_1
    if-ge v6, v3, :cond_5

    .line 110
    .line 111
    invoke-interface {v2, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v7

    .line 115
    check-cast v7, Ln1/o;

    .line 116
    .line 117
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 118
    .line 119
    .line 120
    iget-boolean v9, v7, Ln1/o;->w:Z

    .line 121
    .line 122
    if-eqz v9, :cond_2

    .line 123
    .line 124
    move-object v14, v2

    .line 125
    move/from16 v19, v3

    .line 126
    .line 127
    move v10, v5

    .line 128
    goto :goto_4

    .line 129
    :cond_2
    iget-wide v9, v7, Ln1/o;->t:J

    .line 130
    .line 131
    const/16 v11, 0x20

    .line 132
    .line 133
    shr-long v12, v9, v11

    .line 134
    .line 135
    long-to-int v12, v12

    .line 136
    const-wide v13, 0xffffffffL

    .line 137
    .line 138
    .line 139
    .line 140
    .line 141
    and-long/2addr v9, v13

    .line 142
    long-to-int v9, v9

    .line 143
    add-int/2addr v9, v1

    .line 144
    move v10, v5

    .line 145
    int-to-long v4, v12

    .line 146
    shl-long/2addr v4, v11

    .line 147
    move/from16 v16, v11

    .line 148
    .line 149
    int-to-long v11, v9

    .line 150
    and-long/2addr v11, v13

    .line 151
    or-long/2addr v4, v11

    .line 152
    iput-wide v4, v7, Ln1/o;->t:J

    .line 153
    .line 154
    if-eqz p2, :cond_4

    .line 155
    .line 156
    iget-object v4, v7, Ln1/o;->g:Ljava/util/List;

    .line 157
    .line 158
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 159
    .line 160
    .line 161
    move-result v4

    .line 162
    const/4 v5, 0x0

    .line 163
    :goto_2
    if-ge v5, v4, :cond_4

    .line 164
    .line 165
    iget-object v9, v7, Ln1/o;->j:Landroidx/compose/foundation/lazy/layout/b;

    .line 166
    .line 167
    iget-object v11, v7, Ln1/o;->b:Ljava/lang/Object;

    .line 168
    .line 169
    invoke-virtual {v9, v5, v11}, Landroidx/compose/foundation/lazy/layout/b;->a(ILjava/lang/Object;)Lo1/t;

    .line 170
    .line 171
    .line 172
    move-result-object v9

    .line 173
    if-eqz v9, :cond_3

    .line 174
    .line 175
    iget-wide v11, v9, Lo1/t;->l:J

    .line 176
    .line 177
    move-wide/from16 v17, v13

    .line 178
    .line 179
    shr-long v13, v11, v16

    .line 180
    .line 181
    long-to-int v13, v13

    .line 182
    and-long v11, v11, v17

    .line 183
    .line 184
    long-to-int v11, v11

    .line 185
    add-int/2addr v11, v1

    .line 186
    int-to-long v12, v13

    .line 187
    shl-long v12, v12, v16

    .line 188
    .line 189
    move-object v14, v2

    .line 190
    move/from16 v19, v3

    .line 191
    .line 192
    int-to-long v2, v11

    .line 193
    and-long v2, v2, v17

    .line 194
    .line 195
    or-long/2addr v2, v12

    .line 196
    iput-wide v2, v9, Lo1/t;->l:J

    .line 197
    .line 198
    goto :goto_3

    .line 199
    :cond_3
    move/from16 v19, v3

    .line 200
    .line 201
    move-wide/from16 v17, v13

    .line 202
    .line 203
    move-object v14, v2

    .line 204
    :goto_3
    add-int/lit8 v5, v5, 0x1

    .line 205
    .line 206
    move-object v2, v14

    .line 207
    move-wide/from16 v13, v17

    .line 208
    .line 209
    move/from16 v3, v19

    .line 210
    .line 211
    goto :goto_2

    .line 212
    :cond_4
    move-object v14, v2

    .line 213
    move/from16 v19, v3

    .line 214
    .line 215
    :goto_4
    add-int/lit8 v6, v6, 0x1

    .line 216
    .line 217
    move v5, v10

    .line 218
    move-object v2, v14

    .line 219
    move/from16 v3, v19

    .line 220
    .line 221
    goto :goto_1

    .line 222
    :cond_5
    move-object v14, v2

    .line 223
    move v10, v5

    .line 224
    iget-boolean v2, v0, Ln1/n;->c:Z

    .line 225
    .line 226
    if-nez v2, :cond_7

    .line 227
    .line 228
    if-lez v1, :cond_6

    .line 229
    .line 230
    goto :goto_5

    .line 231
    :cond_6
    const/4 v6, 0x0

    .line 232
    goto :goto_6

    .line 233
    :cond_7
    :goto_5
    const/4 v4, 0x1

    .line 234
    move v6, v4

    .line 235
    :goto_6
    int-to-float v7, v1

    .line 236
    new-instance v3, Ln1/n;

    .line 237
    .line 238
    iget-object v4, v0, Ln1/n;->a:Ln1/p;

    .line 239
    .line 240
    move-object/from16 v20, v8

    .line 241
    .line 242
    iget-object v8, v0, Ln1/n;->e:Lt3/r0;

    .line 243
    .line 244
    iget v9, v0, Ln1/n;->f:F

    .line 245
    .line 246
    move v5, v10

    .line 247
    iget-boolean v10, v0, Ln1/n;->g:Z

    .line 248
    .line 249
    iget-object v11, v0, Ln1/n;->h:Lvy0/b0;

    .line 250
    .line 251
    iget-object v12, v0, Ln1/n;->i:Lt4/c;

    .line 252
    .line 253
    iget v13, v0, Ln1/n;->j:I

    .line 254
    .line 255
    move-object/from16 v16, v14

    .line 256
    .line 257
    iget-object v14, v0, Ln1/n;->k:Lay0/k;

    .line 258
    .line 259
    iget-object v15, v0, Ln1/n;->l:Lay0/k;

    .line 260
    .line 261
    iget v1, v0, Ln1/n;->n:I

    .line 262
    .line 263
    iget v2, v0, Ln1/n;->o:I

    .line 264
    .line 265
    move/from16 v17, v1

    .line 266
    .line 267
    iget v1, v0, Ln1/n;->p:I

    .line 268
    .line 269
    move/from16 v19, v1

    .line 270
    .line 271
    iget v1, v0, Ln1/n;->r:I

    .line 272
    .line 273
    iget v0, v0, Ln1/n;->s:I

    .line 274
    .line 275
    move/from16 v22, v0

    .line 276
    .line 277
    move/from16 v21, v1

    .line 278
    .line 279
    move/from16 v18, v2

    .line 280
    .line 281
    invoke-direct/range {v3 .. v22}, Ln1/n;-><init>(Ln1/p;IZFLt3/r0;FZLvy0/b0;Lt4/c;ILay0/k;Lay0/k;Ljava/util/List;IIILg1/w1;II)V

    .line 282
    .line 283
    .line 284
    return-object v3

    .line 285
    :cond_8
    :goto_7
    const/4 v0, 0x0

    .line 286
    return-object v0
.end method

.method public final b()Ljava/util/Map;
    .locals 0

    .line 1
    iget-object p0, p0, Ln1/n;->e:Lt3/r0;

    .line 2
    .line 3
    invoke-interface {p0}, Lt3/r0;->b()Ljava/util/Map;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final c()V
    .locals 0

    .line 1
    iget-object p0, p0, Ln1/n;->e:Lt3/r0;

    .line 2
    .line 3
    invoke-interface {p0}, Lt3/r0;->c()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final d()Lay0/k;
    .locals 0

    .line 1
    iget-object p0, p0, Ln1/n;->e:Lt3/r0;

    .line 2
    .line 3
    invoke-interface {p0}, Lt3/r0;->d()Lay0/k;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final e()J
    .locals 6

    .line 1
    iget-object p0, p0, Ln1/n;->e:Lt3/r0;

    .line 2
    .line 3
    invoke-interface {p0}, Lt3/r0;->o()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    invoke-interface {p0}, Lt3/r0;->m()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    int-to-long v0, v0

    .line 12
    const/16 v2, 0x20

    .line 13
    .line 14
    shl-long/2addr v0, v2

    .line 15
    int-to-long v2, p0

    .line 16
    const-wide v4, 0xffffffffL

    .line 17
    .line 18
    .line 19
    .line 20
    .line 21
    and-long/2addr v2, v4

    .line 22
    or-long/2addr v0, v2

    .line 23
    return-wide v0
.end method

.method public final m()I
    .locals 0

    .line 1
    iget-object p0, p0, Ln1/n;->e:Lt3/r0;

    .line 2
    .line 3
    invoke-interface {p0}, Lt3/r0;->m()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final o()I
    .locals 0

    .line 1
    iget-object p0, p0, Ln1/n;->e:Lt3/r0;

    .line 2
    .line 3
    invoke-interface {p0}, Lt3/r0;->o()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
