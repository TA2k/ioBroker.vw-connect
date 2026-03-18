.class public final Lt3/e0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/p1;
.implements Lt3/s0;


# instance fields
.field public final synthetic d:Lt3/h0;

.field public final synthetic e:Lt3/m0;


# direct methods
.method public constructor <init>(Lt3/m0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lt3/e0;->e:Lt3/m0;

    .line 5
    .line 6
    iget-object p1, p1, Lt3/m0;->k:Lt3/h0;

    .line 7
    .line 8
    iput-object p1, p0, Lt3/e0;->d:Lt3/h0;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final C(Ljava/lang/Object;Lay0/n;)Ljava/util/List;
    .locals 8

    .line 1
    iget-object p0, p0, Lt3/e0;->e:Lt3/m0;

    .line 2
    .line 3
    iget-object v0, p0, Lt3/m0;->o:Landroidx/collection/q0;

    .line 4
    .line 5
    iget-object v1, p0, Lt3/m0;->m:Landroidx/collection/q0;

    .line 6
    .line 7
    iget-object v2, p0, Lt3/m0;->d:Lv3/h0;

    .line 8
    .line 9
    iget-object v3, p0, Lt3/m0;->j:Landroidx/collection/q0;

    .line 10
    .line 11
    invoke-virtual {v3, p1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v4

    .line 15
    check-cast v4, Lv3/h0;

    .line 16
    .line 17
    if-eqz v4, :cond_0

    .line 18
    .line 19
    invoke-virtual {v2}, Lv3/h0;->p()Ljava/util/List;

    .line 20
    .line 21
    .line 22
    move-result-object v5

    .line 23
    check-cast v5, Landroidx/collection/j0;

    .line 24
    .line 25
    iget-object v5, v5, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast v5, Ln2/b;

    .line 28
    .line 29
    invoke-virtual {v5, v4}, Ln2/b;->k(Ljava/lang/Object;)I

    .line 30
    .line 31
    .line 32
    move-result v5

    .line 33
    iget v6, p0, Lt3/m0;->g:I

    .line 34
    .line 35
    if-ge v5, v6, :cond_0

    .line 36
    .line 37
    invoke-virtual {v4}, Lv3/h0;->n()Ljava/util/List;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    return-object p0

    .line 42
    :cond_0
    iget-object v4, p0, Lt3/m0;->p:Ln2/b;

    .line 43
    .line 44
    iget v5, v4, Ln2/b;->f:I

    .line 45
    .line 46
    iget v6, p0, Lt3/m0;->h:I

    .line 47
    .line 48
    if-lt v5, v6, :cond_1

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_1
    const-string v5, "Error: currentApproachIndex cannot be greater than the size of theapproachComposedSlotIds list."

    .line 52
    .line 53
    invoke-static {v5}, Ls3/a;->a(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    :goto_0
    iget v5, v4, Ln2/b;->f:I

    .line 57
    .line 58
    iget v6, p0, Lt3/m0;->h:I

    .line 59
    .line 60
    if-ne v5, v6, :cond_2

    .line 61
    .line 62
    invoke-virtual {v4, p1}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_2
    iget-object v4, v4, Ln2/b;->d:[Ljava/lang/Object;

    .line 67
    .line 68
    aget-object v5, v4, v6

    .line 69
    .line 70
    aput-object p1, v4, v6

    .line 71
    .line 72
    :goto_1
    iget v4, p0, Lt3/m0;->h:I

    .line 73
    .line 74
    const/4 v5, 0x1

    .line 75
    add-int/2addr v4, v5

    .line 76
    iput v4, p0, Lt3/m0;->h:I

    .line 77
    .line 78
    invoke-virtual {v1, p1}, Landroidx/collection/q0;->b(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v4

    .line 82
    const/4 v6, 0x0

    .line 83
    if-nez v4, :cond_9

    .line 84
    .line 85
    invoke-virtual {v2}, Lv3/h0;->I()Z

    .line 86
    .line 87
    .line 88
    move-result v4

    .line 89
    if-nez v4, :cond_3

    .line 90
    .line 91
    goto :goto_3

    .line 92
    :cond_3
    invoke-virtual {p0}, Lt3/m0;->d()V

    .line 93
    .line 94
    .line 95
    invoke-virtual {v3, p1}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    move-result v3

    .line 99
    if-nez v3, :cond_6

    .line 100
    .line 101
    invoke-virtual {v0, p1}, Landroidx/collection/q0;->k(Ljava/lang/Object;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    invoke-virtual {v1, p1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v3

    .line 108
    if-nez v3, :cond_5

    .line 109
    .line 110
    invoke-virtual {p0, p1}, Lt3/m0;->j(Ljava/lang/Object;)Lv3/h0;

    .line 111
    .line 112
    .line 113
    move-result-object v3

    .line 114
    if-eqz v3, :cond_4

    .line 115
    .line 116
    invoke-virtual {v2}, Lv3/h0;->p()Ljava/util/List;

    .line 117
    .line 118
    .line 119
    move-result-object v4

    .line 120
    check-cast v4, Landroidx/collection/j0;

    .line 121
    .line 122
    iget-object v4, v4, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 123
    .line 124
    check-cast v4, Ln2/b;

    .line 125
    .line 126
    invoke-virtual {v4, v3}, Ln2/b;->k(Ljava/lang/Object;)I

    .line 127
    .line 128
    .line 129
    move-result v4

    .line 130
    invoke-virtual {v2}, Lv3/h0;->p()Ljava/util/List;

    .line 131
    .line 132
    .line 133
    move-result-object v7

    .line 134
    check-cast v7, Landroidx/collection/j0;

    .line 135
    .line 136
    iget-object v7, v7, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 137
    .line 138
    check-cast v7, Ln2/b;

    .line 139
    .line 140
    iget v7, v7, Ln2/b;->f:I

    .line 141
    .line 142
    iput-boolean v5, v2, Lv3/h0;->s:Z

    .line 143
    .line 144
    invoke-virtual {v2, v4, v7, v5}, Lv3/h0;->M(III)V

    .line 145
    .line 146
    .line 147
    iput-boolean v6, v2, Lv3/h0;->s:Z

    .line 148
    .line 149
    iget v4, p0, Lt3/m0;->r:I

    .line 150
    .line 151
    add-int/2addr v4, v5

    .line 152
    iput v4, p0, Lt3/m0;->r:I

    .line 153
    .line 154
    goto :goto_2

    .line 155
    :cond_4
    invoke-virtual {v2}, Lv3/h0;->p()Ljava/util/List;

    .line 156
    .line 157
    .line 158
    move-result-object v3

    .line 159
    check-cast v3, Landroidx/collection/j0;

    .line 160
    .line 161
    iget-object v3, v3, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 162
    .line 163
    check-cast v3, Ln2/b;

    .line 164
    .line 165
    iget v3, v3, Ln2/b;->f:I

    .line 166
    .line 167
    new-instance v4, Lv3/h0;

    .line 168
    .line 169
    const/4 v7, 0x2

    .line 170
    invoke-direct {v4, v7}, Lv3/h0;-><init>(I)V

    .line 171
    .line 172
    .line 173
    iput-boolean v5, v2, Lv3/h0;->s:Z

    .line 174
    .line 175
    invoke-virtual {v2, v3, v4}, Lv3/h0;->B(ILv3/h0;)V

    .line 176
    .line 177
    .line 178
    iput-boolean v6, v2, Lv3/h0;->s:Z

    .line 179
    .line 180
    iget v3, p0, Lt3/m0;->r:I

    .line 181
    .line 182
    add-int/2addr v3, v5

    .line 183
    iput v3, p0, Lt3/m0;->r:I

    .line 184
    .line 185
    move-object v3, v4

    .line 186
    :goto_2
    invoke-virtual {v1, p1, v3}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 187
    .line 188
    .line 189
    :cond_5
    check-cast v3, Lv3/h0;

    .line 190
    .line 191
    invoke-virtual {p0, v3, p1, v6, p2}, Lt3/m0;->i(Lv3/h0;Ljava/lang/Object;ZLay0/n;)V

    .line 192
    .line 193
    .line 194
    :cond_6
    :goto_3
    invoke-virtual {v2}, Lv3/h0;->I()Z

    .line 195
    .line 196
    .line 197
    move-result p2

    .line 198
    if-nez p2, :cond_7

    .line 199
    .line 200
    new-instance p0, Lt3/k0;

    .line 201
    .line 202
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 203
    .line 204
    .line 205
    goto :goto_4

    .line 206
    :cond_7
    new-instance p2, Lt3/l0;

    .line 207
    .line 208
    invoke-direct {p2, p0, p1}, Lt3/l0;-><init>(Lt3/m0;Ljava/lang/Object;)V

    .line 209
    .line 210
    .line 211
    move-object p0, p2

    .line 212
    :goto_4
    invoke-virtual {v0, p1, p0}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 213
    .line 214
    .line 215
    iget-object p0, v2, Lv3/h0;->I:Lv3/l0;

    .line 216
    .line 217
    iget-object p0, p0, Lv3/l0;->d:Lv3/d0;

    .line 218
    .line 219
    sget-object p2, Lv3/d0;->f:Lv3/d0;

    .line 220
    .line 221
    if-ne p0, p2, :cond_8

    .line 222
    .line 223
    invoke-virtual {v2, v5}, Lv3/h0;->V(Z)V

    .line 224
    .line 225
    .line 226
    goto :goto_6

    .line 227
    :cond_8
    const/4 p0, 0x6

    .line 228
    invoke-static {v2, v5, p0}, Lv3/h0;->W(Lv3/h0;ZI)V

    .line 229
    .line 230
    .line 231
    goto :goto_6

    .line 232
    :cond_9
    invoke-virtual {v1, p1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    move-result-object v0

    .line 236
    check-cast v0, Lv3/h0;

    .line 237
    .line 238
    if-eqz v0, :cond_a

    .line 239
    .line 240
    iget-object v2, p0, Lt3/m0;->i:Landroidx/collection/q0;

    .line 241
    .line 242
    invoke-virtual {v2, v0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 243
    .line 244
    .line 245
    move-result-object v2

    .line 246
    check-cast v2, Lt3/f0;

    .line 247
    .line 248
    goto :goto_5

    .line 249
    :cond_a
    const/4 v2, 0x0

    .line 250
    :goto_5
    if-eqz v2, :cond_b

    .line 251
    .line 252
    iget-boolean v2, v2, Lt3/f0;->d:Z

    .line 253
    .line 254
    if-ne v2, v5, :cond_b

    .line 255
    .line 256
    invoke-virtual {p0, v0, p1, v6, p2}, Lt3/m0;->i(Lv3/h0;Ljava/lang/Object;ZLay0/n;)V

    .line 257
    .line 258
    .line 259
    :cond_b
    :goto_6
    invoke-virtual {v1, p1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 260
    .line 261
    .line 262
    move-result-object p0

    .line 263
    check-cast p0, Lv3/h0;

    .line 264
    .line 265
    if-eqz p0, :cond_d

    .line 266
    .line 267
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 268
    .line 269
    iget-object p0, p0, Lv3/l0;->p:Lv3/y0;

    .line 270
    .line 271
    invoke-virtual {p0}, Lv3/y0;->B0()Ljava/util/List;

    .line 272
    .line 273
    .line 274
    move-result-object p0

    .line 275
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 276
    .line 277
    .line 278
    move-result p1

    .line 279
    :goto_7
    if-ge v6, p1, :cond_c

    .line 280
    .line 281
    move-object p2, p0

    .line 282
    check-cast p2, Landroidx/collection/j0;

    .line 283
    .line 284
    invoke-virtual {p2, v6}, Landroidx/collection/j0;->get(I)Ljava/lang/Object;

    .line 285
    .line 286
    .line 287
    move-result-object p2

    .line 288
    check-cast p2, Lv3/y0;

    .line 289
    .line 290
    iget-object p2, p2, Lv3/y0;->i:Lv3/l0;

    .line 291
    .line 292
    iput-boolean v5, p2, Lv3/l0;->b:Z

    .line 293
    .line 294
    add-int/lit8 v6, v6, 0x1

    .line 295
    .line 296
    goto :goto_7

    .line 297
    :cond_c
    return-object p0

    .line 298
    :cond_d
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 299
    .line 300
    return-object p0
.end method

.method public final G0(J)J
    .locals 0

    .line 1
    iget-object p0, p0, Lt3/e0;->d:Lt3/h0;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2}, Lt4/c;->G0(J)J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    return-wide p0
.end method

.method public final I()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lt3/e0;->d:Lt3/h0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lt3/h0;->I()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final N(IILjava/util/Map;Lay0/k;Lay0/k;)Lt3/r0;
    .locals 0

    .line 1
    iget-object p0, p0, Lt3/e0;->d:Lt3/h0;

    .line 2
    .line 3
    invoke-virtual/range {p0 .. p5}, Lt3/h0;->N(IILjava/util/Map;Lay0/k;Lay0/k;)Lt3/r0;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final Q(F)I
    .locals 0

    .line 1
    iget-object p0, p0, Lt3/e0;->d:Lt3/h0;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lt4/c;->Q(F)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final V(J)F
    .locals 0

    .line 1
    iget-object p0, p0, Lt3/e0;->d:Lt3/h0;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2}, Lt4/c;->V(J)F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final a()F
    .locals 0

    .line 1
    iget-object p0, p0, Lt3/e0;->d:Lt3/h0;

    .line 2
    .line 3
    iget p0, p0, Lt3/h0;->e:F

    .line 4
    .line 5
    return p0
.end method

.method public final c0(IILjava/util/Map;Lay0/k;)Lt3/r0;
    .locals 6

    .line 1
    iget-object v0, p0, Lt3/e0;->d:Lt3/h0;

    .line 2
    .line 3
    const/4 v4, 0x0

    .line 4
    move v1, p1

    .line 5
    move v2, p2

    .line 6
    move-object v3, p3

    .line 7
    move-object v5, p4

    .line 8
    invoke-virtual/range {v0 .. v5}, Lt3/h0;->N(IILjava/util/Map;Lay0/k;Lay0/k;)Lt3/r0;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0
.end method

.method public final getLayoutDirection()Lt4/m;
    .locals 0

    .line 1
    iget-object p0, p0, Lt3/e0;->d:Lt3/h0;

    .line 2
    .line 3
    iget-object p0, p0, Lt3/h0;->d:Lt4/m;

    .line 4
    .line 5
    return-object p0
.end method

.method public final m(F)J
    .locals 0

    .line 1
    iget-object p0, p0, Lt3/e0;->d:Lt3/h0;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lt4/c;->m(F)J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    return-wide p0
.end method

.method public final n(J)J
    .locals 0

    .line 1
    iget-object p0, p0, Lt3/e0;->d:Lt3/h0;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2}, Lt4/c;->n(J)J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    return-wide p0
.end method

.method public final n0(I)F
    .locals 0

    .line 1
    iget-object p0, p0, Lt3/e0;->d:Lt3/h0;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lt4/c;->n0(I)F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final o0(F)F
    .locals 0

    .line 1
    iget-object p0, p0, Lt3/e0;->d:Lt3/h0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lt3/h0;->a()F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    div-float/2addr p1, p0

    .line 8
    return p1
.end method

.method public final s(J)F
    .locals 0

    .line 1
    iget-object p0, p0, Lt3/e0;->d:Lt3/h0;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2}, Lt4/c;->s(J)F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final t0()F
    .locals 0

    .line 1
    iget-object p0, p0, Lt3/e0;->d:Lt3/h0;

    .line 2
    .line 3
    iget p0, p0, Lt3/h0;->f:F

    .line 4
    .line 5
    return p0
.end method

.method public final w0(F)F
    .locals 0

    .line 1
    iget-object p0, p0, Lt3/e0;->d:Lt3/h0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lt3/h0;->a()F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    mul-float/2addr p0, p1

    .line 8
    return p0
.end method

.method public final x(I)J
    .locals 0

    .line 1
    iget-object p0, p0, Lt3/e0;->d:Lt3/h0;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lt4/c;->x(I)J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    return-wide p0
.end method

.method public final y(F)J
    .locals 0

    .line 1
    iget-object p0, p0, Lt3/e0;->d:Lt3/h0;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lt4/c;->y(F)J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    return-wide p0
.end method

.method public final z0(J)I
    .locals 0

    .line 1
    iget-object p0, p0, Lt3/e0;->d:Lt3/h0;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2}, Lt4/c;->z0(J)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
