.class public final Ld2/i;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/y;
.implements Lv3/p;
.implements Lv3/x1;


# instance fields
.field public A:Lay0/k;

.field public B:Le3/t;

.field public C:Lay0/k;

.field public D:Ljava/util/Map;

.field public E:Ld2/d;

.field public F:Ld2/f;

.field public G:Ld2/h;

.field public r:Lg4/g;

.field public s:Lg4/p0;

.field public t:Lk4/m;

.field public u:Lay0/k;

.field public v:I

.field public w:Z

.field public x:I

.field public y:I

.field public z:Ljava/util/List;


# virtual methods
.method public final C0(Lv3/j0;)V
    .locals 13

    .line 1
    iget-boolean v0, p0, Lx2/r;->q:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto/16 :goto_8

    .line 6
    .line 7
    :cond_0
    iget-object v0, p1, Lv3/j0;->d:Lg3/b;

    .line 8
    .line 9
    iget-object v0, v0, Lg3/b;->e:Lgw0/c;

    .line 10
    .line 11
    invoke-virtual {v0}, Lgw0/c;->h()Le3/r;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    invoke-virtual {p0, p1}, Ld2/i;->Y0(Lt4/c;)Ld2/d;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    iget-object v1, v0, Ld2/d;->n:Lg4/l0;

    .line 20
    .line 21
    if-eqz v1, :cond_12

    .line 22
    .line 23
    move-object v3, v1

    .line 24
    iget-object v1, v3, Lg4/l0;->b:Lg4/o;

    .line 25
    .line 26
    invoke-virtual {v3}, Lg4/l0;->d()Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    const/4 v8, 0x1

    .line 31
    const/4 v9, 0x0

    .line 32
    if-eqz v0, :cond_2

    .line 33
    .line 34
    iget v0, p0, Ld2/i;->v:I

    .line 35
    .line 36
    const/4 v4, 0x3

    .line 37
    if-ne v0, v4, :cond_1

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_1
    move v10, v8

    .line 41
    goto :goto_1

    .line 42
    :cond_2
    :goto_0
    move v10, v9

    .line 43
    :goto_1
    if-eqz v10, :cond_3

    .line 44
    .line 45
    iget-wide v3, v3, Lg4/l0;->c:J

    .line 46
    .line 47
    const/16 v0, 0x20

    .line 48
    .line 49
    shr-long v5, v3, v0

    .line 50
    .line 51
    long-to-int v5, v5

    .line 52
    int-to-float v5, v5

    .line 53
    const-wide v6, 0xffffffffL

    .line 54
    .line 55
    .line 56
    .line 57
    .line 58
    and-long/2addr v3, v6

    .line 59
    long-to-int v3, v3

    .line 60
    int-to-float v3, v3

    .line 61
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 62
    .line 63
    .line 64
    move-result v4

    .line 65
    int-to-long v4, v4

    .line 66
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 67
    .line 68
    .line 69
    move-result v3

    .line 70
    int-to-long v11, v3

    .line 71
    shl-long v3, v4, v0

    .line 72
    .line 73
    and-long v5, v11, v6

    .line 74
    .line 75
    or-long/2addr v3, v5

    .line 76
    const-wide/16 v5, 0x0

    .line 77
    .line 78
    invoke-static {v5, v6, v3, v4}, Ljp/cf;->c(JJ)Ld3/c;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    invoke-interface {v2}, Le3/r;->o()V

    .line 83
    .line 84
    .line 85
    invoke-static {v2, v0}, Le3/r;->d(Le3/r;Ld3/c;)V

    .line 86
    .line 87
    .line 88
    :cond_3
    :try_start_0
    iget-object v0, p0, Ld2/i;->s:Lg4/p0;

    .line 89
    .line 90
    iget-object v0, v0, Lg4/p0;->a:Lg4/g0;

    .line 91
    .line 92
    iget-object v3, v0, Lg4/g0;->m:Lr4/l;

    .line 93
    .line 94
    if-nez v3, :cond_4

    .line 95
    .line 96
    sget-object v3, Lr4/l;->b:Lr4/l;

    .line 97
    .line 98
    :cond_4
    move-object v6, v3

    .line 99
    goto :goto_2

    .line 100
    :catchall_0
    move-exception v0

    .line 101
    move-object p0, v0

    .line 102
    goto/16 :goto_a

    .line 103
    .line 104
    :goto_2
    iget-object v3, v0, Lg4/g0;->n:Le3/m0;

    .line 105
    .line 106
    if-nez v3, :cond_5

    .line 107
    .line 108
    sget-object v3, Le3/m0;->d:Le3/m0;

    .line 109
    .line 110
    :cond_5
    move-object v5, v3

    .line 111
    iget-object v3, v0, Lg4/g0;->p:Lg3/e;

    .line 112
    .line 113
    if-nez v3, :cond_6

    .line 114
    .line 115
    sget-object v3, Lg3/g;->a:Lg3/g;

    .line 116
    .line 117
    :cond_6
    move-object v7, v3

    .line 118
    iget-object v0, v0, Lg4/g0;->a:Lr4/o;

    .line 119
    .line 120
    invoke-interface {v0}, Lr4/o;->c()Le3/p;

    .line 121
    .line 122
    .line 123
    move-result-object v3

    .line 124
    if-eqz v3, :cond_7

    .line 125
    .line 126
    iget-object v0, p0, Ld2/i;->s:Lg4/p0;

    .line 127
    .line 128
    iget-object v0, v0, Lg4/p0;->a:Lg4/g0;

    .line 129
    .line 130
    iget-object v0, v0, Lg4/g0;->a:Lr4/o;

    .line 131
    .line 132
    invoke-interface {v0}, Lr4/o;->b()F

    .line 133
    .line 134
    .line 135
    move-result v4

    .line 136
    invoke-static/range {v1 .. v7}, Lg4/o;->j(Lg4/o;Le3/r;Le3/p;FLe3/m0;Lr4/l;Lg3/e;)V

    .line 137
    .line 138
    .line 139
    goto :goto_5

    .line 140
    :cond_7
    iget-object v0, p0, Ld2/i;->B:Le3/t;

    .line 141
    .line 142
    if-eqz v0, :cond_8

    .line 143
    .line 144
    invoke-interface {v0}, Le3/t;->a()J

    .line 145
    .line 146
    .line 147
    move-result-wide v3

    .line 148
    goto :goto_3

    .line 149
    :cond_8
    sget-wide v3, Le3/s;->i:J

    .line 150
    .line 151
    :goto_3
    const-wide/16 v11, 0x10

    .line 152
    .line 153
    cmp-long v0, v3, v11

    .line 154
    .line 155
    if-eqz v0, :cond_9

    .line 156
    .line 157
    goto :goto_4

    .line 158
    :cond_9
    iget-object v0, p0, Ld2/i;->s:Lg4/p0;

    .line 159
    .line 160
    invoke-virtual {v0}, Lg4/p0;->b()J

    .line 161
    .line 162
    .line 163
    move-result-wide v3

    .line 164
    cmp-long v0, v3, v11

    .line 165
    .line 166
    if-eqz v0, :cond_a

    .line 167
    .line 168
    iget-object v0, p0, Ld2/i;->s:Lg4/p0;

    .line 169
    .line 170
    invoke-virtual {v0}, Lg4/p0;->b()J

    .line 171
    .line 172
    .line 173
    move-result-wide v3

    .line 174
    goto :goto_4

    .line 175
    :cond_a
    sget-wide v3, Le3/s;->b:J

    .line 176
    .line 177
    :goto_4
    invoke-static/range {v1 .. v7}, Lg4/o;->i(Lg4/o;Le3/r;JLe3/m0;Lr4/l;Lg3/e;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 178
    .line 179
    .line 180
    :goto_5
    if-eqz v10, :cond_b

    .line 181
    .line 182
    invoke-interface {v2}, Le3/r;->i()V

    .line 183
    .line 184
    .line 185
    :cond_b
    iget-object v0, p0, Ld2/i;->G:Ld2/h;

    .line 186
    .line 187
    if-eqz v0, :cond_c

    .line 188
    .line 189
    iget-boolean v0, v0, Ld2/h;->c:Z

    .line 190
    .line 191
    if-ne v0, v8, :cond_c

    .line 192
    .line 193
    move v0, v9

    .line 194
    goto :goto_6

    .line 195
    :cond_c
    iget-object v0, p0, Ld2/i;->r:Lg4/g;

    .line 196
    .line 197
    invoke-static {v0}, Ljp/ye;->a(Lg4/g;)Z

    .line 198
    .line 199
    .line 200
    move-result v0

    .line 201
    :goto_6
    if-nez v0, :cond_10

    .line 202
    .line 203
    iget-object p0, p0, Ld2/i;->z:Ljava/util/List;

    .line 204
    .line 205
    check-cast p0, Ljava/util/Collection;

    .line 206
    .line 207
    if-eqz p0, :cond_e

    .line 208
    .line 209
    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    .line 210
    .line 211
    .line 212
    move-result p0

    .line 213
    if-eqz p0, :cond_d

    .line 214
    .line 215
    goto :goto_7

    .line 216
    :cond_d
    move v8, v9

    .line 217
    :cond_e
    :goto_7
    if-nez v8, :cond_f

    .line 218
    .line 219
    goto :goto_9

    .line 220
    :cond_f
    :goto_8
    return-void

    .line 221
    :cond_10
    :goto_9
    invoke-virtual {p1}, Lv3/j0;->b()V

    .line 222
    .line 223
    .line 224
    return-void

    .line 225
    :goto_a
    if-eqz v10, :cond_11

    .line 226
    .line 227
    invoke-interface {v2}, Le3/r;->i()V

    .line 228
    .line 229
    .line 230
    :cond_11
    throw p0

    .line 231
    :cond_12
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 232
    .line 233
    new-instance p1, Ljava/lang/StringBuilder;

    .line 234
    .line 235
    const-string v1, "Internal Error: MultiParagraphLayoutCache could not provide TextLayoutResult during the draw phase. Please report this bug on the official Issue Tracker with the following diagnostic information: "

    .line 236
    .line 237
    invoke-direct {p1, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 238
    .line 239
    .line 240
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 241
    .line 242
    .line 243
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 244
    .line 245
    .line 246
    move-result-object p1

    .line 247
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 248
    .line 249
    .line 250
    throw p0
.end method

.method public final D(Lv3/p0;Lt3/p0;I)I
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Ld2/i;->Y0(Lt4/c;)Ld2/d;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-virtual {p0, p3, p1}, Ld2/d;->a(ILt4/m;)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final F0(Lv3/p0;Lt3/p0;I)I
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Ld2/i;->Y0(Lt4/c;)Ld2/d;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-virtual {p0, p1}, Ld2/d;->e(Lt4/m;)Landroidx/lifecycle/c1;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-virtual {p0}, Landroidx/lifecycle/c1;->b()F

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    invoke-static {p0}, Lt1/l0;->o(F)I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    return p0
.end method

.method public final J(Lv3/p0;Lt3/p0;I)I
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Ld2/i;->Y0(Lt4/c;)Ld2/d;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-virtual {p0, p3, p1}, Ld2/d;->a(ILt4/m;)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final M0()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final X(Lv3/p0;Lt3/p0;I)I
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Ld2/i;->Y0(Lt4/c;)Ld2/d;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-virtual {p0, p1}, Ld2/d;->e(Lt4/m;)Landroidx/lifecycle/c1;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-virtual {p0}, Landroidx/lifecycle/c1;->c()F

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    invoke-static {p0}, Lt1/l0;->o(F)I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    return p0
.end method

.method public final X0()Ld2/d;
    .locals 10

    .line 1
    iget-object v0, p0, Ld2/i;->E:Ld2/d;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v1, Ld2/d;

    .line 6
    .line 7
    iget-object v2, p0, Ld2/i;->r:Lg4/g;

    .line 8
    .line 9
    iget-object v3, p0, Ld2/i;->s:Lg4/p0;

    .line 10
    .line 11
    iget-object v4, p0, Ld2/i;->t:Lk4/m;

    .line 12
    .line 13
    iget v5, p0, Ld2/i;->v:I

    .line 14
    .line 15
    iget-boolean v6, p0, Ld2/i;->w:Z

    .line 16
    .line 17
    iget v7, p0, Ld2/i;->x:I

    .line 18
    .line 19
    iget v8, p0, Ld2/i;->y:I

    .line 20
    .line 21
    iget-object v9, p0, Ld2/i;->z:Ljava/util/List;

    .line 22
    .line 23
    invoke-direct/range {v1 .. v9}, Ld2/d;-><init>(Lg4/g;Lg4/p0;Lk4/m;IZIILjava/util/List;)V

    .line 24
    .line 25
    .line 26
    iput-object v1, p0, Ld2/i;->E:Ld2/d;

    .line 27
    .line 28
    :cond_0
    iget-object p0, p0, Ld2/i;->E:Ld2/d;

    .line 29
    .line 30
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    return-object p0
.end method

.method public final Y0(Lt4/c;)Ld2/d;
    .locals 2

    .line 1
    iget-object v0, p0, Ld2/i;->G:Ld2/h;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-boolean v1, v0, Ld2/h;->c:Z

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    iget-object v0, v0, Ld2/h;->d:Ld2/d;

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    invoke-virtual {v0, p1}, Ld2/d;->d(Lt4/c;)V

    .line 14
    .line 15
    .line 16
    return-object v0

    .line 17
    :cond_0
    invoke-virtual {p0}, Ld2/i;->X0()Ld2/d;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    invoke-virtual {p0, p1}, Ld2/d;->d(Lt4/c;)V

    .line 22
    .line 23
    .line 24
    return-object p0
.end method

.method public final a0(Ld4/l;)V
    .locals 6

    .line 1
    iget-object v0, p0, Ld2/i;->F:Ld2/f;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Ld2/f;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    invoke-direct {v0, p0, v1}, Ld2/f;-><init>(Ld2/i;I)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Ld2/i;->F:Ld2/f;

    .line 12
    .line 13
    :cond_0
    iget-object v1, p0, Ld2/i;->r:Lg4/g;

    .line 14
    .line 15
    invoke-static {p1, v1}, Ld4/x;->k(Ld4/l;Lg4/g;)V

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Ld2/i;->G:Ld2/h;

    .line 19
    .line 20
    if-eqz v1, :cond_1

    .line 21
    .line 22
    iget-object v2, v1, Ld2/h;->b:Lg4/g;

    .line 23
    .line 24
    sget-object v3, Ld4/v;->B:Ld4/z;

    .line 25
    .line 26
    sget-object v4, Ld4/x;->a:[Lhy0/z;

    .line 27
    .line 28
    const/16 v5, 0xf

    .line 29
    .line 30
    aget-object v5, v4, v5

    .line 31
    .line 32
    invoke-virtual {v3, p1, v2}, Ld4/z;->a(Ld4/l;Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    iget-boolean v1, v1, Ld2/h;->c:Z

    .line 36
    .line 37
    sget-object v2, Ld4/v;->C:Ld4/z;

    .line 38
    .line 39
    const/16 v3, 0x10

    .line 40
    .line 41
    aget-object v3, v4, v3

    .line 42
    .line 43
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    invoke-virtual {v2, p1, v1}, Ld4/z;->a(Ld4/l;Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    :cond_1
    new-instance v1, Ld2/f;

    .line 51
    .line 52
    const/4 v2, 0x1

    .line 53
    invoke-direct {v1, p0, v2}, Ld2/f;-><init>(Ld2/i;I)V

    .line 54
    .line 55
    .line 56
    sget-object v2, Ld4/k;->k:Ld4/z;

    .line 57
    .line 58
    new-instance v3, Ld4/a;

    .line 59
    .line 60
    const/4 v4, 0x0

    .line 61
    invoke-direct {v3, v4, v1}, Ld4/a;-><init>(Ljava/lang/String;Llx0/e;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {p1, v2, v3}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    new-instance v1, Ld2/f;

    .line 68
    .line 69
    const/4 v2, 0x2

    .line 70
    invoke-direct {v1, p0, v2}, Ld2/f;-><init>(Ld2/i;I)V

    .line 71
    .line 72
    .line 73
    sget-object v2, Ld4/k;->l:Ld4/z;

    .line 74
    .line 75
    new-instance v3, Ld4/a;

    .line 76
    .line 77
    invoke-direct {v3, v4, v1}, Ld4/a;-><init>(Ljava/lang/String;Llx0/e;)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {p1, v2, v3}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    new-instance v1, Ld2/g;

    .line 84
    .line 85
    const/4 v2, 0x0

    .line 86
    invoke-direct {v1, p0, v2}, Ld2/g;-><init>(Ljava/lang/Object;I)V

    .line 87
    .line 88
    .line 89
    sget-object p0, Ld4/k;->m:Ld4/z;

    .line 90
    .line 91
    new-instance v2, Ld4/a;

    .line 92
    .line 93
    invoke-direct {v2, v4, v1}, Ld4/a;-><init>(Ljava/lang/String;Llx0/e;)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {p1, p0, v2}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    invoke-static {p1, v0}, Ld4/x;->b(Ld4/l;Lay0/k;)V

    .line 100
    .line 101
    .line 102
    return-void
.end method

.method public final c(Lt3/s0;Lt3/p0;J)Lt3/r0;
    .locals 4

    .line 1
    const-string v0, "TextAnnotatedStringNode:measure"

    .line 2
    .line 3
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    invoke-virtual {p0, p1}, Ld2/i;->Y0(Lt4/c;)Ld2/d;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {v0, p3, p4, v1}, Ld2/d;->c(JLt4/m;)Z

    .line 15
    .line 16
    .line 17
    move-result p3

    .line 18
    iget-object p4, v0, Ld2/d;->n:Lg4/l0;

    .line 19
    .line 20
    if-eqz p4, :cond_4

    .line 21
    .line 22
    iget-wide v0, p4, Lg4/l0;->c:J

    .line 23
    .line 24
    iget-object v2, p4, Lg4/l0;->b:Lg4/o;

    .line 25
    .line 26
    iget-object v2, v2, Lg4/o;->a:Landroidx/lifecycle/c1;

    .line 27
    .line 28
    invoke-virtual {v2}, Landroidx/lifecycle/c1;->a()Z

    .line 29
    .line 30
    .line 31
    if-eqz p3, :cond_2

    .line 32
    .line 33
    const/4 p3, 0x2

    .line 34
    invoke-static {p0, p3}, Lv3/f;->v(Lv3/m;I)Lv3/f1;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    invoke-virtual {v2}, Lv3/f1;->m1()V

    .line 39
    .line 40
    .line 41
    iget-object v2, p0, Ld2/i;->u:Lay0/k;

    .line 42
    .line 43
    if-eqz v2, :cond_0

    .line 44
    .line 45
    invoke-interface {v2, p4}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    :cond_0
    iget-object v2, p0, Ld2/i;->D:Ljava/util/Map;

    .line 49
    .line 50
    if-nez v2, :cond_1

    .line 51
    .line 52
    new-instance v2, Ljava/util/LinkedHashMap;

    .line 53
    .line 54
    invoke-direct {v2, p3}, Ljava/util/LinkedHashMap;-><init>(I)V

    .line 55
    .line 56
    .line 57
    :cond_1
    sget-object p3, Lt3/d;->a:Lt3/o;

    .line 58
    .line 59
    iget v3, p4, Lg4/l0;->d:F

    .line 60
    .line 61
    invoke-static {v3}, Ljava/lang/Math;->round(F)I

    .line 62
    .line 63
    .line 64
    move-result v3

    .line 65
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 66
    .line 67
    .line 68
    move-result-object v3

    .line 69
    invoke-interface {v2, p3, v3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    sget-object p3, Lt3/d;->b:Lt3/o;

    .line 73
    .line 74
    iget v3, p4, Lg4/l0;->e:F

    .line 75
    .line 76
    invoke-static {v3}, Ljava/lang/Math;->round(F)I

    .line 77
    .line 78
    .line 79
    move-result v3

    .line 80
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 81
    .line 82
    .line 83
    move-result-object v3

    .line 84
    invoke-interface {v2, p3, v3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    iput-object v2, p0, Ld2/i;->D:Ljava/util/Map;

    .line 88
    .line 89
    :cond_2
    iget-object p3, p0, Ld2/i;->A:Lay0/k;

    .line 90
    .line 91
    if-eqz p3, :cond_3

    .line 92
    .line 93
    iget-object p4, p4, Lg4/l0;->f:Ljava/util/ArrayList;

    .line 94
    .line 95
    invoke-interface {p3, p4}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    :cond_3
    const/16 p3, 0x20

    .line 99
    .line 100
    shr-long p3, v0, p3

    .line 101
    .line 102
    long-to-int p3, p3

    .line 103
    const-wide v2, 0xffffffffL

    .line 104
    .line 105
    .line 106
    .line 107
    .line 108
    and-long/2addr v0, v2

    .line 109
    long-to-int p4, v0

    .line 110
    invoke-static {p3, p3, p4, p4}, Lkp/a9;->b(IIII)J

    .line 111
    .line 112
    .line 113
    move-result-wide v0

    .line 114
    invoke-interface {p2, v0, v1}, Lt3/p0;->L(J)Lt3/e1;

    .line 115
    .line 116
    .line 117
    move-result-object p2

    .line 118
    iget-object p0, p0, Ld2/i;->D:Ljava/util/Map;

    .line 119
    .line 120
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    new-instance v0, Lam/a;

    .line 124
    .line 125
    const/4 v1, 0x1

    .line 126
    invoke-direct {v0, p2, v1}, Lam/a;-><init>(Lt3/e1;I)V

    .line 127
    .line 128
    .line 129
    invoke-interface {p1, p3, p4, p0, v0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 130
    .line 131
    .line 132
    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 133
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 134
    .line 135
    .line 136
    return-object p0

    .line 137
    :cond_4
    :try_start_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 138
    .line 139
    new-instance p1, Ljava/lang/StringBuilder;

    .line 140
    .line 141
    const-string p2, "Internal Error: MultiParagraphLayoutCache could not provide TextLayoutResult during the draw phase. Please report this bug on the official Issue Tracker with the following diagnostic information: "

    .line 142
    .line 143
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 144
    .line 145
    .line 146
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 147
    .line 148
    .line 149
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object p1

    .line 153
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 154
    .line 155
    .line 156
    throw p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 157
    :catchall_0
    move-exception p0

    .line 158
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 159
    .line 160
    .line 161
    throw p0
.end method
