.class public final Lp1/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/r0;


# instance fields
.field public final a:Ljava/util/List;

.field public final b:I

.field public final c:I

.field public final d:I

.field public final e:Lg1/w1;

.field public final f:I

.field public final g:I

.field public final h:Z

.field public final i:I

.field public final j:Lp1/d;

.field public final k:Lp1/d;

.field public final l:F

.field public final m:I

.field public final n:Z

.field public final o:Lh1/n;

.field public final p:Lt3/r0;

.field public final q:Z

.field public final r:Ljava/util/List;

.field public final s:Ljava/util/List;

.field public final t:Lvy0/b0;


# direct methods
.method public synthetic constructor <init>(IIIIIILh1/n;Lt3/r0;Lvy0/b0;)V
    .locals 21

    sget-object v5, Lg1/w1;->e:Lg1/w1;

    const/4 v14, 0x0

    const/16 v17, 0x0

    .line 1
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    const/4 v8, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    move-object/from16 v18, v1

    move-object/from16 v19, v1

    move-object/from16 v0, p0

    move/from16 v2, p1

    move/from16 v3, p2

    move/from16 v4, p3

    move/from16 v6, p4

    move/from16 v7, p5

    move/from16 v9, p6

    move-object/from16 v15, p7

    move-object/from16 v16, p8

    move-object/from16 v20, p9

    invoke-direct/range {v0 .. v20}, Lp1/o;-><init>(Ljava/util/List;IIILg1/w1;IIZILp1/d;Lp1/d;FIZLh1/n;Lt3/r0;ZLjava/util/List;Ljava/util/List;Lvy0/b0;)V

    return-void
.end method

.method public constructor <init>(Ljava/util/List;IIILg1/w1;IIZILp1/d;Lp1/d;FIZLh1/n;Lt3/r0;ZLjava/util/List;Ljava/util/List;Lvy0/b0;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lp1/o;->a:Ljava/util/List;

    .line 4
    iput p2, p0, Lp1/o;->b:I

    .line 5
    iput p3, p0, Lp1/o;->c:I

    .line 6
    iput p4, p0, Lp1/o;->d:I

    .line 7
    iput-object p5, p0, Lp1/o;->e:Lg1/w1;

    .line 8
    iput p6, p0, Lp1/o;->f:I

    .line 9
    iput p7, p0, Lp1/o;->g:I

    .line 10
    iput-boolean p8, p0, Lp1/o;->h:Z

    .line 11
    iput p9, p0, Lp1/o;->i:I

    .line 12
    iput-object p10, p0, Lp1/o;->j:Lp1/d;

    .line 13
    iput-object p11, p0, Lp1/o;->k:Lp1/d;

    .line 14
    iput p12, p0, Lp1/o;->l:F

    .line 15
    iput p13, p0, Lp1/o;->m:I

    .line 16
    iput-boolean p14, p0, Lp1/o;->n:Z

    .line 17
    iput-object p15, p0, Lp1/o;->o:Lh1/n;

    move-object/from16 p1, p16

    .line 18
    iput-object p1, p0, Lp1/o;->p:Lt3/r0;

    move/from16 p1, p17

    .line 19
    iput-boolean p1, p0, Lp1/o;->q:Z

    move-object/from16 p1, p18

    .line 20
    iput-object p1, p0, Lp1/o;->r:Ljava/util/List;

    move-object/from16 p1, p19

    .line 21
    iput-object p1, p0, Lp1/o;->s:Ljava/util/List;

    move-object/from16 p1, p20

    .line 22
    iput-object p1, p0, Lp1/o;->t:Lvy0/b0;

    return-void
.end method


# virtual methods
.method public final a(I)Lp1/o;
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    iget v2, v0, Lp1/o;->b:I

    .line 6
    .line 7
    iget v3, v0, Lp1/o;->c:I

    .line 8
    .line 9
    add-int/2addr v2, v3

    .line 10
    iget-boolean v3, v0, Lp1/o;->q:Z

    .line 11
    .line 12
    if-nez v3, :cond_8

    .line 13
    .line 14
    iget-object v3, v0, Lp1/o;->a:Ljava/util/List;

    .line 15
    .line 16
    invoke-interface {v3}, Ljava/util/List;->isEmpty()Z

    .line 17
    .line 18
    .line 19
    move-result v4

    .line 20
    if-nez v4, :cond_8

    .line 21
    .line 22
    iget-object v4, v0, Lp1/o;->j:Lp1/d;

    .line 23
    .line 24
    if-eqz v4, :cond_8

    .line 25
    .line 26
    iget v4, v0, Lp1/o;->m:I

    .line 27
    .line 28
    sub-int/2addr v4, v1

    .line 29
    if-ltz v4, :cond_8

    .line 30
    .line 31
    if-ge v4, v2, :cond_8

    .line 32
    .line 33
    if-eqz v2, :cond_0

    .line 34
    .line 35
    int-to-float v5, v1

    .line 36
    int-to-float v6, v2

    .line 37
    div-float/2addr v5, v6

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    const/4 v5, 0x0

    .line 40
    :goto_0
    iget v6, v0, Lp1/o;->l:F

    .line 41
    .line 42
    sub-float v17, v6, v5

    .line 43
    .line 44
    iget-object v5, v0, Lp1/o;->k:Lp1/d;

    .line 45
    .line 46
    if-eqz v5, :cond_8

    .line 47
    .line 48
    const/high16 v5, 0x3f000000    # 0.5f

    .line 49
    .line 50
    cmpl-float v5, v17, v5

    .line 51
    .line 52
    if-gez v5, :cond_8

    .line 53
    .line 54
    const/high16 v5, -0x41000000    # -0.5f

    .line 55
    .line 56
    cmpg-float v5, v17, v5

    .line 57
    .line 58
    if-gtz v5, :cond_1

    .line 59
    .line 60
    goto/16 :goto_8

    .line 61
    .line 62
    :cond_1
    invoke-static {v3}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v5

    .line 66
    check-cast v5, Lp1/d;

    .line 67
    .line 68
    invoke-static {v3}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v6

    .line 72
    check-cast v6, Lp1/d;

    .line 73
    .line 74
    iget v7, v0, Lp1/o;->g:I

    .line 75
    .line 76
    iget v8, v0, Lp1/o;->f:I

    .line 77
    .line 78
    if-gez v1, :cond_2

    .line 79
    .line 80
    iget v5, v5, Lp1/d;->l:I

    .line 81
    .line 82
    add-int/2addr v5, v2

    .line 83
    sub-int/2addr v5, v8

    .line 84
    iget v6, v6, Lp1/d;->l:I

    .line 85
    .line 86
    add-int/2addr v6, v2

    .line 87
    sub-int/2addr v6, v7

    .line 88
    invoke-static {v5, v6}, Ljava/lang/Math;->min(II)I

    .line 89
    .line 90
    .line 91
    move-result v2

    .line 92
    neg-int v5, v1

    .line 93
    if-le v2, v5, :cond_8

    .line 94
    .line 95
    goto :goto_1

    .line 96
    :cond_2
    iget v2, v5, Lp1/d;->l:I

    .line 97
    .line 98
    sub-int/2addr v8, v2

    .line 99
    iget v2, v6, Lp1/d;->l:I

    .line 100
    .line 101
    sub-int/2addr v7, v2

    .line 102
    invoke-static {v8, v7}, Ljava/lang/Math;->min(II)I

    .line 103
    .line 104
    .line 105
    move-result v2

    .line 106
    if-le v2, v1, :cond_8

    .line 107
    .line 108
    :goto_1
    move-object v2, v3

    .line 109
    check-cast v2, Ljava/util/Collection;

    .line 110
    .line 111
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 112
    .line 113
    .line 114
    move-result v2

    .line 115
    const/4 v5, 0x0

    .line 116
    move v6, v5

    .line 117
    :goto_2
    if-ge v6, v2, :cond_3

    .line 118
    .line 119
    invoke-interface {v3, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object v7

    .line 123
    check-cast v7, Lp1/d;

    .line 124
    .line 125
    invoke-virtual {v7, v1}, Lp1/d;->a(I)V

    .line 126
    .line 127
    .line 128
    add-int/lit8 v6, v6, 0x1

    .line 129
    .line 130
    goto :goto_2

    .line 131
    :cond_3
    iget-object v2, v0, Lp1/o;->r:Ljava/util/List;

    .line 132
    .line 133
    move-object v3, v2

    .line 134
    check-cast v3, Ljava/util/Collection;

    .line 135
    .line 136
    invoke-interface {v3}, Ljava/util/Collection;->size()I

    .line 137
    .line 138
    .line 139
    move-result v3

    .line 140
    move v6, v5

    .line 141
    :goto_3
    if-ge v6, v3, :cond_4

    .line 142
    .line 143
    invoke-interface {v2, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object v7

    .line 147
    check-cast v7, Lp1/d;

    .line 148
    .line 149
    invoke-virtual {v7, v1}, Lp1/d;->a(I)V

    .line 150
    .line 151
    .line 152
    add-int/lit8 v6, v6, 0x1

    .line 153
    .line 154
    goto :goto_3

    .line 155
    :cond_4
    iget-object v2, v0, Lp1/o;->s:Ljava/util/List;

    .line 156
    .line 157
    move-object v3, v2

    .line 158
    check-cast v3, Ljava/util/Collection;

    .line 159
    .line 160
    invoke-interface {v3}, Ljava/util/Collection;->size()I

    .line 161
    .line 162
    .line 163
    move-result v3

    .line 164
    move v6, v5

    .line 165
    :goto_4
    if-ge v6, v3, :cond_5

    .line 166
    .line 167
    invoke-interface {v2, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object v7

    .line 171
    check-cast v7, Lp1/d;

    .line 172
    .line 173
    invoke-virtual {v7, v1}, Lp1/d;->a(I)V

    .line 174
    .line 175
    .line 176
    add-int/lit8 v6, v6, 0x1

    .line 177
    .line 178
    goto :goto_4

    .line 179
    :cond_5
    new-instance v2, Lp1/o;

    .line 180
    .line 181
    iget-boolean v3, v0, Lp1/o;->n:Z

    .line 182
    .line 183
    if-nez v3, :cond_7

    .line 184
    .line 185
    if-lez v1, :cond_6

    .line 186
    .line 187
    goto :goto_6

    .line 188
    :cond_6
    :goto_5
    move/from16 v19, v5

    .line 189
    .line 190
    goto :goto_7

    .line 191
    :cond_7
    :goto_6
    const/4 v5, 0x1

    .line 192
    goto :goto_5

    .line 193
    :goto_7
    iget-object v1, v0, Lp1/o;->s:Ljava/util/List;

    .line 194
    .line 195
    iget-object v3, v0, Lp1/o;->t:Lvy0/b0;

    .line 196
    .line 197
    iget-object v6, v0, Lp1/o;->a:Ljava/util/List;

    .line 198
    .line 199
    iget v7, v0, Lp1/o;->b:I

    .line 200
    .line 201
    iget v8, v0, Lp1/o;->c:I

    .line 202
    .line 203
    iget v9, v0, Lp1/o;->d:I

    .line 204
    .line 205
    iget-object v10, v0, Lp1/o;->e:Lg1/w1;

    .line 206
    .line 207
    iget v11, v0, Lp1/o;->f:I

    .line 208
    .line 209
    iget v12, v0, Lp1/o;->g:I

    .line 210
    .line 211
    iget-boolean v13, v0, Lp1/o;->h:Z

    .line 212
    .line 213
    iget v14, v0, Lp1/o;->i:I

    .line 214
    .line 215
    iget-object v15, v0, Lp1/o;->j:Lp1/d;

    .line 216
    .line 217
    iget-object v5, v0, Lp1/o;->k:Lp1/d;

    .line 218
    .line 219
    move-object/from16 v24, v1

    .line 220
    .line 221
    iget-object v1, v0, Lp1/o;->o:Lh1/n;

    .line 222
    .line 223
    move-object/from16 v20, v1

    .line 224
    .line 225
    iget-object v1, v0, Lp1/o;->p:Lt3/r0;

    .line 226
    .line 227
    move-object/from16 v21, v1

    .line 228
    .line 229
    iget-boolean v1, v0, Lp1/o;->q:Z

    .line 230
    .line 231
    iget-object v0, v0, Lp1/o;->r:Ljava/util/List;

    .line 232
    .line 233
    move-object/from16 v23, v0

    .line 234
    .line 235
    move/from16 v22, v1

    .line 236
    .line 237
    move-object/from16 v25, v3

    .line 238
    .line 239
    move/from16 v18, v4

    .line 240
    .line 241
    move-object/from16 v16, v5

    .line 242
    .line 243
    move-object v5, v2

    .line 244
    invoke-direct/range {v5 .. v25}, Lp1/o;-><init>(Ljava/util/List;IIILg1/w1;IIZILp1/d;Lp1/d;FIZLh1/n;Lt3/r0;ZLjava/util/List;Ljava/util/List;Lvy0/b0;)V

    .line 245
    .line 246
    .line 247
    return-object v5

    .line 248
    :cond_8
    :goto_8
    const/4 v0, 0x0

    .line 249
    return-object v0
.end method

.method public final b()Ljava/util/Map;
    .locals 0

    .line 1
    iget-object p0, p0, Lp1/o;->p:Lt3/r0;

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
    iget-object p0, p0, Lp1/o;->p:Lt3/r0;

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
    iget-object p0, p0, Lp1/o;->p:Lt3/r0;

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
    iget-object p0, p0, Lp1/o;->p:Lt3/r0;

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
    iget-object p0, p0, Lp1/o;->p:Lt3/r0;

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
    iget-object p0, p0, Lp1/o;->p:Lt3/r0;

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
