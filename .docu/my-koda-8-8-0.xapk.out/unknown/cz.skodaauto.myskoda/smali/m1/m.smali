.class public final Lm1/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo1/e0;


# instance fields
.field public final a:I

.field public final b:Ljava/util/List;

.field public final c:Z

.field public final d:Lx2/d;

.field public final e:Lx2/i;

.field public final f:Lt4/m;

.field public final g:I

.field public final h:I

.field public final i:I

.field public final j:J

.field public final k:Ljava/lang/Object;

.field public final l:Ljava/lang/Object;

.field public final m:Landroidx/compose/foundation/lazy/layout/b;

.field public final n:J

.field public o:I

.field public final p:I

.field public final q:I

.field public final r:I

.field public s:Z

.field public t:I

.field public u:I

.field public v:I

.field public final w:[I


# direct methods
.method public constructor <init>(ILjava/util/List;ZLx2/d;Lx2/i;Lt4/m;IIIJLjava/lang/Object;Ljava/lang/Object;Landroidx/compose/foundation/lazy/layout/b;J)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lm1/m;->a:I

    .line 5
    .line 6
    iput-object p2, p0, Lm1/m;->b:Ljava/util/List;

    .line 7
    .line 8
    iput-boolean p3, p0, Lm1/m;->c:Z

    .line 9
    .line 10
    iput-object p4, p0, Lm1/m;->d:Lx2/d;

    .line 11
    .line 12
    iput-object p5, p0, Lm1/m;->e:Lx2/i;

    .line 13
    .line 14
    iput-object p6, p0, Lm1/m;->f:Lt4/m;

    .line 15
    .line 16
    iput p7, p0, Lm1/m;->g:I

    .line 17
    .line 18
    iput p8, p0, Lm1/m;->h:I

    .line 19
    .line 20
    iput p9, p0, Lm1/m;->i:I

    .line 21
    .line 22
    iput-wide p10, p0, Lm1/m;->j:J

    .line 23
    .line 24
    iput-object p12, p0, Lm1/m;->k:Ljava/lang/Object;

    .line 25
    .line 26
    move-object/from16 p1, p13

    .line 27
    .line 28
    iput-object p1, p0, Lm1/m;->l:Ljava/lang/Object;

    .line 29
    .line 30
    move-object/from16 p1, p14

    .line 31
    .line 32
    iput-object p1, p0, Lm1/m;->m:Landroidx/compose/foundation/lazy/layout/b;

    .line 33
    .line 34
    move-wide/from16 p3, p15

    .line 35
    .line 36
    iput-wide p3, p0, Lm1/m;->n:J

    .line 37
    .line 38
    const/high16 p1, -0x80000000

    .line 39
    .line 40
    iput p1, p0, Lm1/m;->t:I

    .line 41
    .line 42
    move-object p1, p2

    .line 43
    check-cast p1, Ljava/util/Collection;

    .line 44
    .line 45
    invoke-interface {p1}, Ljava/util/Collection;->size()I

    .line 46
    .line 47
    .line 48
    move-result p1

    .line 49
    const/4 p3, 0x0

    .line 50
    move p4, p3

    .line 51
    move p5, p4

    .line 52
    move p6, p5

    .line 53
    :goto_0
    if-ge p4, p1, :cond_2

    .line 54
    .line 55
    invoke-interface {p2, p4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    check-cast v0, Lt3/e1;

    .line 60
    .line 61
    iget-boolean v1, p0, Lm1/m;->c:Z

    .line 62
    .line 63
    if-eqz v1, :cond_0

    .line 64
    .line 65
    iget v2, v0, Lt3/e1;->e:I

    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_0
    iget v2, v0, Lt3/e1;->d:I

    .line 69
    .line 70
    :goto_1
    add-int/2addr p5, v2

    .line 71
    if-nez v1, :cond_1

    .line 72
    .line 73
    iget v0, v0, Lt3/e1;->e:I

    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_1
    iget v0, v0, Lt3/e1;->d:I

    .line 77
    .line 78
    :goto_2
    invoke-static {p6, v0}, Ljava/lang/Math;->max(II)I

    .line 79
    .line 80
    .line 81
    move-result p6

    .line 82
    add-int/lit8 p4, p4, 0x1

    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_2
    iput p5, p0, Lm1/m;->p:I

    .line 86
    .line 87
    iget p1, p0, Lm1/m;->i:I

    .line 88
    .line 89
    add-int/2addr p5, p1

    .line 90
    if-gez p5, :cond_3

    .line 91
    .line 92
    goto :goto_3

    .line 93
    :cond_3
    move p3, p5

    .line 94
    :goto_3
    iput p3, p0, Lm1/m;->q:I

    .line 95
    .line 96
    iput p6, p0, Lm1/m;->r:I

    .line 97
    .line 98
    iget-object p1, p0, Lm1/m;->b:Ljava/util/List;

    .line 99
    .line 100
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 101
    .line 102
    .line 103
    move-result p1

    .line 104
    mul-int/lit8 p1, p1, 0x2

    .line 105
    .line 106
    new-array p1, p1, [I

    .line 107
    .line 108
    iput-object p1, p0, Lm1/m;->w:[I

    .line 109
    .line 110
    return-void
.end method


# virtual methods
.method public final a(IIII)V
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p3, p4}, Lm1/m;->n(III)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final b()I
    .locals 0

    .line 1
    iget-object p0, p0, Lm1/m;->b:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final c()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lm1/m;->s:Z

    .line 2
    .line 3
    return p0
.end method

.method public final d()I
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final e()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lm1/m;->n:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final f()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lm1/m;->c:Z

    .line 2
    .line 3
    return p0
.end method

.method public final g()I
    .locals 0

    .line 1
    iget p0, p0, Lm1/m;->q:I

    .line 2
    .line 3
    return p0
.end method

.method public final getIndex()I
    .locals 0

    .line 1
    iget p0, p0, Lm1/m;->a:I

    .line 2
    .line 3
    return p0
.end method

.method public final getKey()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lm1/m;->k:Ljava/lang/Object;

    .line 2
    .line 3
    return-object p0
.end method

.method public final h(I)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lm1/m;->b:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lt3/e1;

    .line 8
    .line 9
    invoke-virtual {p0}, Lt3/e1;->l()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public final i()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lm1/m;->s:Z

    .line 3
    .line 4
    return-void
.end method

.method public final j(I)J
    .locals 5

    .line 1
    const-wide v0, 0xffffffffL

    .line 2
    .line 3
    .line 4
    .line 5
    .line 6
    const/16 v2, 0x20

    .line 7
    .line 8
    if-nez p1, :cond_1

    .line 9
    .line 10
    iget-object v3, p0, Lm1/m;->b:Ljava/util/List;

    .line 11
    .line 12
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 13
    .line 14
    .line 15
    move-result v3

    .line 16
    if-nez v3, :cond_1

    .line 17
    .line 18
    iget-boolean p1, p0, Lm1/m;->c:Z

    .line 19
    .line 20
    const/4 v3, 0x0

    .line 21
    if-eqz p1, :cond_0

    .line 22
    .line 23
    iget p0, p0, Lm1/m;->o:I

    .line 24
    .line 25
    int-to-long v3, v3

    .line 26
    shl-long v2, v3, v2

    .line 27
    .line 28
    int-to-long p0, p0

    .line 29
    and-long/2addr p0, v0

    .line 30
    or-long/2addr p0, v2

    .line 31
    return-wide p0

    .line 32
    :cond_0
    iget p0, p0, Lm1/m;->o:I

    .line 33
    .line 34
    int-to-long p0, p0

    .line 35
    shl-long/2addr p0, v2

    .line 36
    int-to-long v2, v3

    .line 37
    and-long/2addr v0, v2

    .line 38
    or-long/2addr p0, v0

    .line 39
    return-wide p0

    .line 40
    :cond_1
    mul-int/lit8 p1, p1, 0x2

    .line 41
    .line 42
    iget-object p0, p0, Lm1/m;->w:[I

    .line 43
    .line 44
    aget v3, p0, p1

    .line 45
    .line 46
    add-int/lit8 p1, p1, 0x1

    .line 47
    .line 48
    aget p0, p0, p1

    .line 49
    .line 50
    int-to-long v3, v3

    .line 51
    shl-long v2, v3, v2

    .line 52
    .line 53
    int-to-long p0, p0

    .line 54
    and-long/2addr p0, v0

    .line 55
    or-long/2addr p0, v2

    .line 56
    return-wide p0
.end method

.method public final k()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final l(J)I
    .locals 2

    .line 1
    iget-boolean p0, p0, Lm1/m;->c:Z

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const-wide v0, 0xffffffffL

    .line 6
    .line 7
    .line 8
    .line 9
    .line 10
    and-long p0, p1, v0

    .line 11
    .line 12
    :goto_0
    long-to-int p0, p0

    .line 13
    return p0

    .line 14
    :cond_0
    const/16 p0, 0x20

    .line 15
    .line 16
    shr-long p0, p1, p0

    .line 17
    .line 18
    goto :goto_0
.end method

.method public final m(Lt3/d1;Z)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget v2, v0, Lm1/m;->t:I

    .line 6
    .line 7
    const/high16 v3, -0x80000000

    .line 8
    .line 9
    if-eq v2, v3, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const-string v2, "position() should be called first"

    .line 13
    .line 14
    invoke-static {v2}, Lj1/b;->a(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    :goto_0
    iget-object v2, v0, Lm1/m;->b:Ljava/util/List;

    .line 18
    .line 19
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    const/4 v4, 0x0

    .line 24
    :goto_1
    if-ge v4, v3, :cond_e

    .line 25
    .line 26
    invoke-interface {v2, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v5

    .line 30
    check-cast v5, Lt3/e1;

    .line 31
    .line 32
    iget v6, v0, Lm1/m;->u:I

    .line 33
    .line 34
    iget-boolean v7, v0, Lm1/m;->c:Z

    .line 35
    .line 36
    if-eqz v7, :cond_1

    .line 37
    .line 38
    iget v8, v5, Lt3/e1;->e:I

    .line 39
    .line 40
    goto :goto_2

    .line 41
    :cond_1
    iget v8, v5, Lt3/e1;->d:I

    .line 42
    .line 43
    :goto_2
    sub-int/2addr v6, v8

    .line 44
    iget v8, v0, Lm1/m;->v:I

    .line 45
    .line 46
    invoke-virtual {v0, v4}, Lm1/m;->j(I)J

    .line 47
    .line 48
    .line 49
    move-result-wide v9

    .line 50
    iget-object v11, v0, Lm1/m;->m:Landroidx/compose/foundation/lazy/layout/b;

    .line 51
    .line 52
    iget-object v12, v0, Lm1/m;->k:Ljava/lang/Object;

    .line 53
    .line 54
    invoke-virtual {v11, v4, v12}, Landroidx/compose/foundation/lazy/layout/b;->a(ILjava/lang/Object;)Lo1/t;

    .line 55
    .line 56
    .line 57
    move-result-object v11

    .line 58
    const/4 v12, 0x0

    .line 59
    if-eqz v11, :cond_7

    .line 60
    .line 61
    if-eqz p2, :cond_2

    .line 62
    .line 63
    iput-wide v9, v11, Lo1/t;->r:J

    .line 64
    .line 65
    move-object v15, v2

    .line 66
    move/from16 v16, v3

    .line 67
    .line 68
    goto :goto_3

    .line 69
    :cond_2
    iget-wide v13, v11, Lo1/t;->r:J

    .line 70
    .line 71
    move-object v15, v2

    .line 72
    move/from16 v16, v3

    .line 73
    .line 74
    sget-wide v2, Lo1/t;->s:J

    .line 75
    .line 76
    invoke-static {v13, v14, v2, v3}, Lt4/j;->b(JJ)Z

    .line 77
    .line 78
    .line 79
    move-result v2

    .line 80
    if-nez v2, :cond_3

    .line 81
    .line 82
    iget-wide v9, v11, Lo1/t;->r:J

    .line 83
    .line 84
    :cond_3
    iget-object v2, v11, Lo1/t;->q:Ll2/j1;

    .line 85
    .line 86
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v2

    .line 90
    check-cast v2, Lt4/j;

    .line 91
    .line 92
    iget-wide v2, v2, Lt4/j;->a:J

    .line 93
    .line 94
    invoke-static {v9, v10, v2, v3}, Lt4/j;->d(JJ)J

    .line 95
    .line 96
    .line 97
    move-result-wide v2

    .line 98
    invoke-virtual {v0, v9, v10}, Lm1/m;->l(J)I

    .line 99
    .line 100
    .line 101
    move-result v13

    .line 102
    if-gt v13, v6, :cond_4

    .line 103
    .line 104
    invoke-virtual {v0, v2, v3}, Lm1/m;->l(J)I

    .line 105
    .line 106
    .line 107
    move-result v13

    .line 108
    if-le v13, v6, :cond_5

    .line 109
    .line 110
    :cond_4
    invoke-virtual {v0, v9, v10}, Lm1/m;->l(J)I

    .line 111
    .line 112
    .line 113
    move-result v6

    .line 114
    if-lt v6, v8, :cond_6

    .line 115
    .line 116
    invoke-virtual {v0, v2, v3}, Lm1/m;->l(J)I

    .line 117
    .line 118
    .line 119
    move-result v6

    .line 120
    if-lt v6, v8, :cond_6

    .line 121
    .line 122
    :cond_5
    iget-object v6, v11, Lo1/t;->h:Ll2/j1;

    .line 123
    .line 124
    invoke-virtual {v6}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v6

    .line 128
    check-cast v6, Ljava/lang/Boolean;

    .line 129
    .line 130
    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    .line 131
    .line 132
    .line 133
    move-result v6

    .line 134
    if-eqz v6, :cond_6

    .line 135
    .line 136
    iget-object v6, v11, Lo1/t;->a:Lvy0/b0;

    .line 137
    .line 138
    new-instance v8, Lo1/r;

    .line 139
    .line 140
    const/4 v9, 0x1

    .line 141
    invoke-direct {v8, v11, v12, v9}, Lo1/r;-><init>(Lo1/t;Lkotlin/coroutines/Continuation;I)V

    .line 142
    .line 143
    .line 144
    const/4 v9, 0x3

    .line 145
    invoke-static {v6, v12, v12, v8, v9}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 146
    .line 147
    .line 148
    :cond_6
    move-wide v9, v2

    .line 149
    :goto_3
    iget-object v12, v11, Lo1/t;->n:Lh3/c;

    .line 150
    .line 151
    goto :goto_4

    .line 152
    :cond_7
    move-object v15, v2

    .line 153
    move/from16 v16, v3

    .line 154
    .line 155
    :goto_4
    iget-wide v2, v0, Lm1/m;->j:J

    .line 156
    .line 157
    invoke-static {v9, v10, v2, v3}, Lt4/j;->d(JJ)J

    .line 158
    .line 159
    .line 160
    move-result-wide v2

    .line 161
    if-nez p2, :cond_8

    .line 162
    .line 163
    if-eqz v11, :cond_8

    .line 164
    .line 165
    iput-wide v2, v11, Lo1/t;->m:J

    .line 166
    .line 167
    :cond_8
    if-eqz v7, :cond_a

    .line 168
    .line 169
    if-eqz v12, :cond_9

    .line 170
    .line 171
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 172
    .line 173
    .line 174
    invoke-static {v1, v5}, Lt3/d1;->b(Lt3/d1;Lt3/e1;)V

    .line 175
    .line 176
    .line 177
    iget-wide v6, v5, Lt3/e1;->h:J

    .line 178
    .line 179
    invoke-static {v2, v3, v6, v7}, Lt4/j;->d(JJ)J

    .line 180
    .line 181
    .line 182
    move-result-wide v2

    .line 183
    const/4 v6, 0x0

    .line 184
    invoke-virtual {v5, v2, v3, v6, v12}, Lt3/e1;->m0(JFLh3/c;)V

    .line 185
    .line 186
    .line 187
    goto :goto_6

    .line 188
    :cond_9
    invoke-static {v1, v5, v2, v3}, Lt3/d1;->A(Lt3/d1;Lt3/e1;J)V

    .line 189
    .line 190
    .line 191
    goto :goto_6

    .line 192
    :cond_a
    if-eqz v12, :cond_d

    .line 193
    .line 194
    invoke-virtual {v1}, Lt3/d1;->d()Lt4/m;

    .line 195
    .line 196
    .line 197
    move-result-object v6

    .line 198
    sget-object v7, Lt4/m;->d:Lt4/m;

    .line 199
    .line 200
    const/4 v8, 0x0

    .line 201
    if-eq v6, v7, :cond_c

    .line 202
    .line 203
    invoke-virtual {v1}, Lt3/d1;->f()I

    .line 204
    .line 205
    .line 206
    move-result v6

    .line 207
    if-nez v6, :cond_b

    .line 208
    .line 209
    goto :goto_5

    .line 210
    :cond_b
    invoke-virtual {v1}, Lt3/d1;->f()I

    .line 211
    .line 212
    .line 213
    move-result v6

    .line 214
    iget v7, v5, Lt3/e1;->d:I

    .line 215
    .line 216
    sub-int/2addr v6, v7

    .line 217
    const/16 v7, 0x20

    .line 218
    .line 219
    shr-long v9, v2, v7

    .line 220
    .line 221
    long-to-int v9, v9

    .line 222
    sub-int/2addr v6, v9

    .line 223
    const-wide v9, 0xffffffffL

    .line 224
    .line 225
    .line 226
    .line 227
    .line 228
    and-long/2addr v2, v9

    .line 229
    long-to-int v2, v2

    .line 230
    int-to-long v13, v6

    .line 231
    shl-long v6, v13, v7

    .line 232
    .line 233
    int-to-long v2, v2

    .line 234
    and-long/2addr v2, v9

    .line 235
    or-long/2addr v2, v6

    .line 236
    invoke-static {v1, v5}, Lt3/d1;->b(Lt3/d1;Lt3/e1;)V

    .line 237
    .line 238
    .line 239
    iget-wide v6, v5, Lt3/e1;->h:J

    .line 240
    .line 241
    invoke-static {v2, v3, v6, v7}, Lt4/j;->d(JJ)J

    .line 242
    .line 243
    .line 244
    move-result-wide v2

    .line 245
    invoke-virtual {v5, v2, v3, v8, v12}, Lt3/e1;->m0(JFLh3/c;)V

    .line 246
    .line 247
    .line 248
    goto :goto_6

    .line 249
    :cond_c
    :goto_5
    invoke-static {v1, v5}, Lt3/d1;->b(Lt3/d1;Lt3/e1;)V

    .line 250
    .line 251
    .line 252
    iget-wide v6, v5, Lt3/e1;->h:J

    .line 253
    .line 254
    invoke-static {v2, v3, v6, v7}, Lt4/j;->d(JJ)J

    .line 255
    .line 256
    .line 257
    move-result-wide v2

    .line 258
    invoke-virtual {v5, v2, v3, v8, v12}, Lt3/e1;->m0(JFLh3/c;)V

    .line 259
    .line 260
    .line 261
    goto :goto_6

    .line 262
    :cond_d
    invoke-static {v1, v5, v2, v3}, Lt3/d1;->t(Lt3/d1;Lt3/e1;J)V

    .line 263
    .line 264
    .line 265
    :goto_6
    add-int/lit8 v4, v4, 0x1

    .line 266
    .line 267
    move-object v2, v15

    .line 268
    move/from16 v3, v16

    .line 269
    .line 270
    goto/16 :goto_1

    .line 271
    .line 272
    :cond_e
    return-void
.end method

.method public final n(III)V
    .locals 10

    .line 1
    iput p1, p0, Lm1/m;->o:I

    .line 2
    .line 3
    iget-boolean v0, p0, Lm1/m;->c:Z

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    move v1, p3

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move v1, p2

    .line 10
    :goto_0
    iput v1, p0, Lm1/m;->t:I

    .line 11
    .line 12
    iget-object v1, p0, Lm1/m;->b:Ljava/util/List;

    .line 13
    .line 14
    move-object v2, v1

    .line 15
    check-cast v2, Ljava/util/Collection;

    .line 16
    .line 17
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    const/4 v3, 0x0

    .line 22
    :goto_1
    if-ge v3, v2, :cond_4

    .line 23
    .line 24
    invoke-interface {v1, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v4

    .line 28
    check-cast v4, Lt3/e1;

    .line 29
    .line 30
    mul-int/lit8 v5, v3, 0x2

    .line 31
    .line 32
    iget-object v6, p0, Lm1/m;->w:[I

    .line 33
    .line 34
    if-eqz v0, :cond_2

    .line 35
    .line 36
    iget-object v7, p0, Lm1/m;->d:Lx2/d;

    .line 37
    .line 38
    if-eqz v7, :cond_1

    .line 39
    .line 40
    iget v8, v4, Lt3/e1;->d:I

    .line 41
    .line 42
    iget-object v9, p0, Lm1/m;->f:Lt4/m;

    .line 43
    .line 44
    invoke-interface {v7, v8, p2, v9}, Lx2/d;->a(IILt4/m;)I

    .line 45
    .line 46
    .line 47
    move-result v7

    .line 48
    aput v7, v6, v5

    .line 49
    .line 50
    add-int/lit8 v5, v5, 0x1

    .line 51
    .line 52
    aput p1, v6, v5

    .line 53
    .line 54
    iget v4, v4, Lt3/e1;->e:I

    .line 55
    .line 56
    :goto_2
    add-int/2addr p1, v4

    .line 57
    goto :goto_3

    .line 58
    :cond_1
    const-string p0, "null horizontalAlignment when isVertical == true"

    .line 59
    .line 60
    invoke-static {p0}, Lj1/b;->b(Ljava/lang/String;)Ljava/lang/Void;

    .line 61
    .line 62
    .line 63
    new-instance p0, La8/r0;

    .line 64
    .line 65
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 66
    .line 67
    .line 68
    throw p0

    .line 69
    :cond_2
    aput p1, v6, v5

    .line 70
    .line 71
    add-int/lit8 v5, v5, 0x1

    .line 72
    .line 73
    iget-object v7, p0, Lm1/m;->e:Lx2/i;

    .line 74
    .line 75
    if-eqz v7, :cond_3

    .line 76
    .line 77
    iget v8, v4, Lt3/e1;->e:I

    .line 78
    .line 79
    invoke-virtual {v7, v8, p3}, Lx2/i;->a(II)I

    .line 80
    .line 81
    .line 82
    move-result v7

    .line 83
    aput v7, v6, v5

    .line 84
    .line 85
    iget v4, v4, Lt3/e1;->d:I

    .line 86
    .line 87
    goto :goto_2

    .line 88
    :goto_3
    add-int/lit8 v3, v3, 0x1

    .line 89
    .line 90
    goto :goto_1

    .line 91
    :cond_3
    const-string p0, "null verticalAlignment when isVertical == false"

    .line 92
    .line 93
    invoke-static {p0}, Lj1/b;->b(Ljava/lang/String;)Ljava/lang/Void;

    .line 94
    .line 95
    .line 96
    new-instance p0, La8/r0;

    .line 97
    .line 98
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 99
    .line 100
    .line 101
    throw p0

    .line 102
    :cond_4
    iget p1, p0, Lm1/m;->g:I

    .line 103
    .line 104
    neg-int p1, p1

    .line 105
    iput p1, p0, Lm1/m;->u:I

    .line 106
    .line 107
    iget p1, p0, Lm1/m;->t:I

    .line 108
    .line 109
    iget p2, p0, Lm1/m;->h:I

    .line 110
    .line 111
    add-int/2addr p1, p2

    .line 112
    iput p1, p0, Lm1/m;->v:I

    .line 113
    .line 114
    return-void
.end method
