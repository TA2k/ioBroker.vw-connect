.class public final Lm1/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/r0;


# instance fields
.field public final a:Lm1/m;

.field public final b:I

.field public final c:Z

.field public final d:F

.field public final e:Lt3/r0;

.field public final f:F

.field public final g:Z

.field public final h:Lvy0/b0;

.field public final i:Lt4/c;

.field public final j:J

.field public final k:Ljava/lang/Object;

.field public final l:I

.field public final m:I

.field public final n:I

.field public final o:Lg1/w1;

.field public final p:I

.field public final q:I


# direct methods
.method public constructor <init>(Lm1/m;IZFLt3/r0;FZLvy0/b0;Lt4/c;JLjava/util/List;IIILg1/w1;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lm1/l;->a:Lm1/m;

    .line 5
    .line 6
    iput p2, p0, Lm1/l;->b:I

    .line 7
    .line 8
    iput-boolean p3, p0, Lm1/l;->c:Z

    .line 9
    .line 10
    iput p4, p0, Lm1/l;->d:F

    .line 11
    .line 12
    iput-object p5, p0, Lm1/l;->e:Lt3/r0;

    .line 13
    .line 14
    iput p6, p0, Lm1/l;->f:F

    .line 15
    .line 16
    iput-boolean p7, p0, Lm1/l;->g:Z

    .line 17
    .line 18
    iput-object p8, p0, Lm1/l;->h:Lvy0/b0;

    .line 19
    .line 20
    iput-object p9, p0, Lm1/l;->i:Lt4/c;

    .line 21
    .line 22
    iput-wide p10, p0, Lm1/l;->j:J

    .line 23
    .line 24
    iput-object p12, p0, Lm1/l;->k:Ljava/lang/Object;

    .line 25
    .line 26
    iput p13, p0, Lm1/l;->l:I

    .line 27
    .line 28
    iput p14, p0, Lm1/l;->m:I

    .line 29
    .line 30
    iput p15, p0, Lm1/l;->n:I

    .line 31
    .line 32
    move-object/from16 p1, p16

    .line 33
    .line 34
    iput-object p1, p0, Lm1/l;->o:Lg1/w1;

    .line 35
    .line 36
    move/from16 p1, p17

    .line 37
    .line 38
    iput p1, p0, Lm1/l;->p:I

    .line 39
    .line 40
    move/from16 p1, p18

    .line 41
    .line 42
    iput p1, p0, Lm1/l;->q:I

    .line 43
    .line 44
    return-void
.end method


# virtual methods
.method public final a(IZ)Lm1/l;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    iget-boolean v2, v0, Lm1/l;->g:Z

    .line 6
    .line 7
    if-nez v2, :cond_d

    .line 8
    .line 9
    iget-object v15, v0, Lm1/l;->k:Ljava/lang/Object;

    .line 10
    .line 11
    invoke-interface {v15}, Ljava/util/List;->isEmpty()Z

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    if-nez v2, :cond_d

    .line 16
    .line 17
    iget-object v2, v0, Lm1/l;->a:Lm1/m;

    .line 18
    .line 19
    if-eqz v2, :cond_d

    .line 20
    .line 21
    iget v2, v2, Lm1/m;->q:I

    .line 22
    .line 23
    iget v3, v0, Lm1/l;->b:I

    .line 24
    .line 25
    sub-int v5, v3, v1

    .line 26
    .line 27
    if-ltz v5, :cond_d

    .line 28
    .line 29
    if-ge v5, v2, :cond_d

    .line 30
    .line 31
    invoke-static {v15}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    check-cast v2, Lm1/m;

    .line 36
    .line 37
    invoke-static {v15}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    check-cast v3, Lm1/m;

    .line 42
    .line 43
    iget-boolean v4, v2, Lm1/m;->s:Z

    .line 44
    .line 45
    if-nez v4, :cond_d

    .line 46
    .line 47
    iget-boolean v4, v3, Lm1/m;->s:Z

    .line 48
    .line 49
    if-eqz v4, :cond_0

    .line 50
    .line 51
    goto/16 :goto_a

    .line 52
    .line 53
    :cond_0
    iget v4, v0, Lm1/l;->m:I

    .line 54
    .line 55
    iget v6, v0, Lm1/l;->l:I

    .line 56
    .line 57
    if-gez v1, :cond_1

    .line 58
    .line 59
    iget v7, v2, Lm1/m;->o:I

    .line 60
    .line 61
    iget v2, v2, Lm1/m;->q:I

    .line 62
    .line 63
    add-int/2addr v7, v2

    .line 64
    sub-int/2addr v7, v6

    .line 65
    iget v2, v3, Lm1/m;->o:I

    .line 66
    .line 67
    iget v3, v3, Lm1/m;->q:I

    .line 68
    .line 69
    add-int/2addr v2, v3

    .line 70
    sub-int/2addr v2, v4

    .line 71
    invoke-static {v7, v2}, Ljava/lang/Math;->min(II)I

    .line 72
    .line 73
    .line 74
    move-result v2

    .line 75
    neg-int v3, v1

    .line 76
    if-le v2, v3, :cond_d

    .line 77
    .line 78
    goto :goto_0

    .line 79
    :cond_1
    iget v2, v2, Lm1/m;->o:I

    .line 80
    .line 81
    sub-int/2addr v6, v2

    .line 82
    iget v2, v3, Lm1/m;->o:I

    .line 83
    .line 84
    sub-int/2addr v4, v2

    .line 85
    invoke-static {v6, v4}, Ljava/lang/Math;->min(II)I

    .line 86
    .line 87
    .line 88
    move-result v2

    .line 89
    if-le v2, v1, :cond_d

    .line 90
    .line 91
    :goto_0
    move-object v2, v15

    .line 92
    check-cast v2, Ljava/util/Collection;

    .line 93
    .line 94
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 95
    .line 96
    .line 97
    move-result v2

    .line 98
    const/4 v4, 0x0

    .line 99
    :goto_1
    if-ge v4, v2, :cond_a

    .line 100
    .line 101
    invoke-interface {v15, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v6

    .line 105
    check-cast v6, Lm1/m;

    .line 106
    .line 107
    iget-boolean v7, v6, Lm1/m;->c:Z

    .line 108
    .line 109
    iget-object v8, v6, Lm1/m;->w:[I

    .line 110
    .line 111
    iget-boolean v9, v6, Lm1/m;->s:Z

    .line 112
    .line 113
    if-eqz v9, :cond_3

    .line 114
    .line 115
    :cond_2
    move/from16 v18, v4

    .line 116
    .line 117
    goto :goto_7

    .line 118
    :cond_3
    iget v9, v6, Lm1/m;->o:I

    .line 119
    .line 120
    add-int/2addr v9, v1

    .line 121
    iput v9, v6, Lm1/m;->o:I

    .line 122
    .line 123
    array-length v9, v8

    .line 124
    const/4 v10, 0x0

    .line 125
    :goto_2
    if-ge v10, v9, :cond_7

    .line 126
    .line 127
    and-int/lit8 v11, v10, 0x1

    .line 128
    .line 129
    if-eqz v7, :cond_4

    .line 130
    .line 131
    if-nez v11, :cond_5

    .line 132
    .line 133
    :cond_4
    if-nez v7, :cond_6

    .line 134
    .line 135
    if-nez v11, :cond_6

    .line 136
    .line 137
    :cond_5
    aget v11, v8, v10

    .line 138
    .line 139
    add-int/2addr v11, v1

    .line 140
    aput v11, v8, v10

    .line 141
    .line 142
    :cond_6
    add-int/lit8 v10, v10, 0x1

    .line 143
    .line 144
    goto :goto_2

    .line 145
    :cond_7
    if-eqz p2, :cond_2

    .line 146
    .line 147
    iget-object v8, v6, Lm1/m;->b:Ljava/util/List;

    .line 148
    .line 149
    invoke-interface {v8}, Ljava/util/List;->size()I

    .line 150
    .line 151
    .line 152
    move-result v8

    .line 153
    const/4 v9, 0x0

    .line 154
    :goto_3
    if-ge v9, v8, :cond_2

    .line 155
    .line 156
    iget-object v10, v6, Lm1/m;->m:Landroidx/compose/foundation/lazy/layout/b;

    .line 157
    .line 158
    iget-object v11, v6, Lm1/m;->k:Ljava/lang/Object;

    .line 159
    .line 160
    invoke-virtual {v10, v9, v11}, Landroidx/compose/foundation/lazy/layout/b;->a(ILjava/lang/Object;)Lo1/t;

    .line 161
    .line 162
    .line 163
    move-result-object v10

    .line 164
    if-eqz v10, :cond_9

    .line 165
    .line 166
    iget-wide v11, v10, Lo1/t;->l:J

    .line 167
    .line 168
    const-wide v13, 0xffffffffL

    .line 169
    .line 170
    .line 171
    .line 172
    .line 173
    const/16 v16, 0x20

    .line 174
    .line 175
    if-eqz v7, :cond_8

    .line 176
    .line 177
    move/from16 v18, v4

    .line 178
    .line 179
    shr-long v3, v11, v16

    .line 180
    .line 181
    long-to-int v3, v3

    .line 182
    and-long/2addr v11, v13

    .line 183
    long-to-int v4, v11

    .line 184
    add-int/2addr v4, v1

    .line 185
    :goto_4
    int-to-long v11, v3

    .line 186
    shl-long v11, v11, v16

    .line 187
    .line 188
    int-to-long v3, v4

    .line 189
    and-long/2addr v3, v13

    .line 190
    or-long/2addr v3, v11

    .line 191
    goto :goto_5

    .line 192
    :cond_8
    move/from16 v18, v4

    .line 193
    .line 194
    shr-long v3, v11, v16

    .line 195
    .line 196
    long-to-int v3, v3

    .line 197
    add-int/2addr v3, v1

    .line 198
    and-long/2addr v11, v13

    .line 199
    long-to-int v4, v11

    .line 200
    goto :goto_4

    .line 201
    :goto_5
    iput-wide v3, v10, Lo1/t;->l:J

    .line 202
    .line 203
    goto :goto_6

    .line 204
    :cond_9
    move/from16 v18, v4

    .line 205
    .line 206
    :goto_6
    add-int/lit8 v9, v9, 0x1

    .line 207
    .line 208
    move/from16 v4, v18

    .line 209
    .line 210
    goto :goto_3

    .line 211
    :goto_7
    add-int/lit8 v4, v18, 0x1

    .line 212
    .line 213
    goto :goto_1

    .line 214
    :cond_a
    new-instance v3, Lm1/l;

    .line 215
    .line 216
    iget-boolean v2, v0, Lm1/l;->c:Z

    .line 217
    .line 218
    if-nez v2, :cond_c

    .line 219
    .line 220
    if-lez v1, :cond_b

    .line 221
    .line 222
    goto :goto_8

    .line 223
    :cond_b
    const/4 v6, 0x0

    .line 224
    goto :goto_9

    .line 225
    :cond_c
    :goto_8
    const/4 v2, 0x1

    .line 226
    move v6, v2

    .line 227
    :goto_9
    int-to-float v7, v1

    .line 228
    iget v1, v0, Lm1/l;->p:I

    .line 229
    .line 230
    iget v2, v0, Lm1/l;->q:I

    .line 231
    .line 232
    iget-object v4, v0, Lm1/l;->a:Lm1/m;

    .line 233
    .line 234
    iget-object v8, v0, Lm1/l;->e:Lt3/r0;

    .line 235
    .line 236
    iget v9, v0, Lm1/l;->f:F

    .line 237
    .line 238
    iget-boolean v10, v0, Lm1/l;->g:Z

    .line 239
    .line 240
    iget-object v11, v0, Lm1/l;->h:Lvy0/b0;

    .line 241
    .line 242
    iget-object v12, v0, Lm1/l;->i:Lt4/c;

    .line 243
    .line 244
    iget-wide v13, v0, Lm1/l;->j:J

    .line 245
    .line 246
    move/from16 v20, v1

    .line 247
    .line 248
    iget v1, v0, Lm1/l;->l:I

    .line 249
    .line 250
    move/from16 v16, v1

    .line 251
    .line 252
    iget v1, v0, Lm1/l;->m:I

    .line 253
    .line 254
    move/from16 v17, v1

    .line 255
    .line 256
    iget v1, v0, Lm1/l;->n:I

    .line 257
    .line 258
    iget-object v0, v0, Lm1/l;->o:Lg1/w1;

    .line 259
    .line 260
    move-object/from16 v19, v0

    .line 261
    .line 262
    move/from16 v18, v1

    .line 263
    .line 264
    move/from16 v21, v2

    .line 265
    .line 266
    invoke-direct/range {v3 .. v21}, Lm1/l;-><init>(Lm1/m;IZFLt3/r0;FZLvy0/b0;Lt4/c;JLjava/util/List;IIILg1/w1;II)V

    .line 267
    .line 268
    .line 269
    return-object v3

    .line 270
    :cond_d
    :goto_a
    const/4 v0, 0x0

    .line 271
    return-object v0
.end method

.method public final b()Ljava/util/Map;
    .locals 0

    .line 1
    iget-object p0, p0, Lm1/l;->e:Lt3/r0;

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
    iget-object p0, p0, Lm1/l;->e:Lt3/r0;

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
    iget-object p0, p0, Lm1/l;->e:Lt3/r0;

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
    iget-object p0, p0, Lm1/l;->e:Lt3/r0;

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
    iget-object p0, p0, Lm1/l;->e:Lt3/r0;

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
    iget-object p0, p0, Lm1/l;->e:Lt3/r0;

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
