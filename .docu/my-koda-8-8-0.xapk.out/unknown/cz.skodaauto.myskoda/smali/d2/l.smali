.class public final Ld2/l;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/y;
.implements Lv3/p;
.implements Lv3/x1;


# instance fields
.field public A:Ld2/e;

.field public B:Ld2/j;

.field public C:Ld2/k;

.field public r:Ljava/lang/String;

.field public s:Lg4/p0;

.field public t:Lk4/m;

.field public u:I

.field public v:Z

.field public w:I

.field public x:I

.field public y:Le3/t;

.field public z:Ljava/util/HashMap;


# virtual methods
.method public final C0(Lv3/j0;)V
    .locals 10

    .line 1
    iget-boolean v0, p0, Lx2/r;->q:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto/16 :goto_5

    .line 6
    .line 7
    :cond_0
    iget-object v0, p0, Ld2/l;->C:Ld2/k;

    .line 8
    .line 9
    if-eqz v0, :cond_2

    .line 10
    .line 11
    iget-boolean v1, v0, Ld2/k;->c:Z

    .line 12
    .line 13
    if-eqz v1, :cond_1

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_1
    const/4 v0, 0x0

    .line 17
    :goto_0
    if-eqz v0, :cond_2

    .line 18
    .line 19
    iget-object v0, v0, Ld2/k;->d:Ld2/e;

    .line 20
    .line 21
    if-nez v0, :cond_3

    .line 22
    .line 23
    :cond_2
    invoke-virtual {p0}, Ld2/l;->X0()Ld2/e;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    :cond_3
    iget-object v1, v0, Ld2/e;->j:Lg4/a;

    .line 28
    .line 29
    if-eqz v1, :cond_e

    .line 30
    .line 31
    iget-object p1, p1, Lv3/j0;->d:Lg3/b;

    .line 32
    .line 33
    iget-object p1, p1, Lg3/b;->e:Lgw0/c;

    .line 34
    .line 35
    invoke-virtual {p1}, Lgw0/c;->h()Le3/r;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    iget-boolean p1, v0, Ld2/e;->k:Z

    .line 40
    .line 41
    if-eqz p1, :cond_4

    .line 42
    .line 43
    iget-wide v3, v0, Ld2/e;->l:J

    .line 44
    .line 45
    const/16 v0, 0x20

    .line 46
    .line 47
    shr-long v5, v3, v0

    .line 48
    .line 49
    long-to-int v0, v5

    .line 50
    int-to-float v5, v0

    .line 51
    const-wide v6, 0xffffffffL

    .line 52
    .line 53
    .line 54
    .line 55
    .line 56
    and-long/2addr v3, v6

    .line 57
    long-to-int v0, v3

    .line 58
    int-to-float v6, v0

    .line 59
    invoke-interface {v2}, Le3/r;->o()V

    .line 60
    .line 61
    .line 62
    const/4 v4, 0x0

    .line 63
    const/4 v7, 0x1

    .line 64
    const/4 v3, 0x0

    .line 65
    invoke-interface/range {v2 .. v7}, Le3/r;->g(FFFFI)V

    .line 66
    .line 67
    .line 68
    :cond_4
    :try_start_0
    iget-object v0, p0, Ld2/l;->s:Lg4/p0;

    .line 69
    .line 70
    iget-object v0, v0, Lg4/p0;->a:Lg4/g0;

    .line 71
    .line 72
    iget-object v3, v0, Lg4/g0;->m:Lr4/l;

    .line 73
    .line 74
    if-nez v3, :cond_5

    .line 75
    .line 76
    sget-object v3, Lr4/l;->b:Lr4/l;

    .line 77
    .line 78
    :cond_5
    move-object v6, v3

    .line 79
    goto :goto_1

    .line 80
    :catchall_0
    move-exception v0

    .line 81
    move-object p0, v0

    .line 82
    goto :goto_6

    .line 83
    :goto_1
    iget-object v3, v0, Lg4/g0;->n:Le3/m0;

    .line 84
    .line 85
    if-nez v3, :cond_6

    .line 86
    .line 87
    sget-object v3, Le3/m0;->d:Le3/m0;

    .line 88
    .line 89
    :cond_6
    move-object v5, v3

    .line 90
    iget-object v3, v0, Lg4/g0;->p:Lg3/e;

    .line 91
    .line 92
    if-nez v3, :cond_7

    .line 93
    .line 94
    sget-object v3, Lg3/g;->a:Lg3/g;

    .line 95
    .line 96
    :cond_7
    move-object v7, v3

    .line 97
    iget-object v0, v0, Lg4/g0;->a:Lr4/o;

    .line 98
    .line 99
    invoke-interface {v0}, Lr4/o;->c()Le3/p;

    .line 100
    .line 101
    .line 102
    move-result-object v3

    .line 103
    if-eqz v3, :cond_8

    .line 104
    .line 105
    iget-object p0, p0, Ld2/l;->s:Lg4/p0;

    .line 106
    .line 107
    iget-object p0, p0, Lg4/p0;->a:Lg4/g0;

    .line 108
    .line 109
    iget-object p0, p0, Lg4/g0;->a:Lr4/o;

    .line 110
    .line 111
    invoke-interface {p0}, Lr4/o;->b()F

    .line 112
    .line 113
    .line 114
    move-result v4

    .line 115
    invoke-virtual/range {v1 .. v7}, Lg4/a;->g(Le3/r;Le3/p;FLe3/m0;Lr4/l;Lg3/e;)V

    .line 116
    .line 117
    .line 118
    goto :goto_4

    .line 119
    :cond_8
    iget-object v0, p0, Ld2/l;->y:Le3/t;

    .line 120
    .line 121
    if-eqz v0, :cond_9

    .line 122
    .line 123
    invoke-interface {v0}, Le3/t;->a()J

    .line 124
    .line 125
    .line 126
    move-result-wide v3

    .line 127
    goto :goto_2

    .line 128
    :cond_9
    sget-wide v3, Le3/s;->i:J

    .line 129
    .line 130
    :goto_2
    const-wide/16 v8, 0x10

    .line 131
    .line 132
    cmp-long v0, v3, v8

    .line 133
    .line 134
    if-eqz v0, :cond_a

    .line 135
    .line 136
    goto :goto_3

    .line 137
    :cond_a
    iget-object v0, p0, Ld2/l;->s:Lg4/p0;

    .line 138
    .line 139
    invoke-virtual {v0}, Lg4/p0;->b()J

    .line 140
    .line 141
    .line 142
    move-result-wide v3

    .line 143
    cmp-long v0, v3, v8

    .line 144
    .line 145
    if-eqz v0, :cond_b

    .line 146
    .line 147
    iget-object p0, p0, Ld2/l;->s:Lg4/p0;

    .line 148
    .line 149
    invoke-virtual {p0}, Lg4/p0;->b()J

    .line 150
    .line 151
    .line 152
    move-result-wide v3

    .line 153
    goto :goto_3

    .line 154
    :cond_b
    sget-wide v3, Le3/s;->b:J

    .line 155
    .line 156
    :goto_3
    invoke-virtual/range {v1 .. v7}, Lg4/a;->f(Le3/r;JLe3/m0;Lr4/l;Lg3/e;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 157
    .line 158
    .line 159
    :goto_4
    if-eqz p1, :cond_c

    .line 160
    .line 161
    invoke-interface {v2}, Le3/r;->i()V

    .line 162
    .line 163
    .line 164
    :cond_c
    :goto_5
    return-void

    .line 165
    :goto_6
    if-eqz p1, :cond_d

    .line 166
    .line 167
    invoke-interface {v2}, Le3/r;->i()V

    .line 168
    .line 169
    .line 170
    :cond_d
    throw p0

    .line 171
    :cond_e
    new-instance p1, Ljava/lang/StringBuilder;

    .line 172
    .line 173
    const-string v0, "Internal Error: ParagraphLayoutCache could not provide a Paragraph during the draw phase. Please report this bug on the official Issue Tracker with the following diagnostic information: (layoutCache="

    .line 174
    .line 175
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 176
    .line 177
    .line 178
    iget-object v0, p0, Ld2/l;->A:Ld2/e;

    .line 179
    .line 180
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 181
    .line 182
    .line 183
    const-string v0, ", textSubstitution="

    .line 184
    .line 185
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 186
    .line 187
    .line 188
    iget-object p0, p0, Ld2/l;->C:Ld2/k;

    .line 189
    .line 190
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 191
    .line 192
    .line 193
    const/16 p0, 0x29

    .line 194
    .line 195
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 196
    .line 197
    .line 198
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 199
    .line 200
    .line 201
    move-result-object p0

    .line 202
    invoke-static {p0}, Lj1/b;->b(Ljava/lang/String;)Ljava/lang/Void;

    .line 203
    .line 204
    .line 205
    new-instance p0, La8/r0;

    .line 206
    .line 207
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 208
    .line 209
    .line 210
    throw p0
.end method

.method public final D(Lv3/p0;Lt3/p0;I)I
    .locals 1

    .line 1
    iget-object p2, p0, Ld2/l;->C:Ld2/k;

    .line 2
    .line 3
    if-eqz p2, :cond_1

    .line 4
    .line 5
    iget-boolean v0, p2, Ld2/k;->c:Z

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 p2, 0x0

    .line 11
    :goto_0
    if-eqz p2, :cond_1

    .line 12
    .line 13
    iget-object p2, p2, Ld2/k;->d:Ld2/e;

    .line 14
    .line 15
    if-nez p2, :cond_2

    .line 16
    .line 17
    :cond_1
    invoke-virtual {p0}, Ld2/l;->X0()Ld2/e;

    .line 18
    .line 19
    .line 20
    move-result-object p2

    .line 21
    :cond_2
    invoke-virtual {p2, p1}, Ld2/e;->d(Lt4/c;)V

    .line 22
    .line 23
    .line 24
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-virtual {p2, p3, p0}, Ld2/e;->a(ILt4/m;)I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    return p0
.end method

.method public final F0(Lv3/p0;Lt3/p0;I)I
    .locals 0

    .line 1
    iget-object p2, p0, Ld2/l;->C:Ld2/k;

    .line 2
    .line 3
    if-eqz p2, :cond_1

    .line 4
    .line 5
    iget-boolean p3, p2, Ld2/k;->c:Z

    .line 6
    .line 7
    if-eqz p3, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 p2, 0x0

    .line 11
    :goto_0
    if-eqz p2, :cond_1

    .line 12
    .line 13
    iget-object p2, p2, Ld2/k;->d:Ld2/e;

    .line 14
    .line 15
    if-nez p2, :cond_2

    .line 16
    .line 17
    :cond_1
    invoke-virtual {p0}, Ld2/l;->X0()Ld2/e;

    .line 18
    .line 19
    .line 20
    move-result-object p2

    .line 21
    :cond_2
    invoke-virtual {p2, p1}, Ld2/e;->d(Lt4/c;)V

    .line 22
    .line 23
    .line 24
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-virtual {p2, p0}, Ld2/e;->e(Lt4/m;)Lg4/s;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    invoke-interface {p0}, Lg4/s;->b()F

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    invoke-static {p0}, Lt1/l0;->o(F)I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    return p0
.end method

.method public final J(Lv3/p0;Lt3/p0;I)I
    .locals 1

    .line 1
    iget-object p2, p0, Ld2/l;->C:Ld2/k;

    .line 2
    .line 3
    if-eqz p2, :cond_1

    .line 4
    .line 5
    iget-boolean v0, p2, Ld2/k;->c:Z

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 p2, 0x0

    .line 11
    :goto_0
    if-eqz p2, :cond_1

    .line 12
    .line 13
    iget-object p2, p2, Ld2/k;->d:Ld2/e;

    .line 14
    .line 15
    if-nez p2, :cond_2

    .line 16
    .line 17
    :cond_1
    invoke-virtual {p0}, Ld2/l;->X0()Ld2/e;

    .line 18
    .line 19
    .line 20
    move-result-object p2

    .line 21
    :cond_2
    invoke-virtual {p2, p1}, Ld2/e;->d(Lt4/c;)V

    .line 22
    .line 23
    .line 24
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-virtual {p2, p3, p0}, Ld2/e;->a(ILt4/m;)I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
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
    iget-object p2, p0, Ld2/l;->C:Ld2/k;

    .line 2
    .line 3
    if-eqz p2, :cond_1

    .line 4
    .line 5
    iget-boolean p3, p2, Ld2/k;->c:Z

    .line 6
    .line 7
    if-eqz p3, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 p2, 0x0

    .line 11
    :goto_0
    if-eqz p2, :cond_1

    .line 12
    .line 13
    iget-object p2, p2, Ld2/k;->d:Ld2/e;

    .line 14
    .line 15
    if-nez p2, :cond_2

    .line 16
    .line 17
    :cond_1
    invoke-virtual {p0}, Ld2/l;->X0()Ld2/e;

    .line 18
    .line 19
    .line 20
    move-result-object p2

    .line 21
    :cond_2
    invoke-virtual {p2, p1}, Ld2/e;->d(Lt4/c;)V

    .line 22
    .line 23
    .line 24
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-virtual {p2, p0}, Ld2/e;->e(Lt4/m;)Lg4/s;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    invoke-interface {p0}, Lg4/s;->c()F

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    invoke-static {p0}, Lt1/l0;->o(F)I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    return p0
.end method

.method public final X0()Ld2/e;
    .locals 9

    .line 1
    iget-object v0, p0, Ld2/l;->A:Ld2/e;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v1, Ld2/e;

    .line 6
    .line 7
    iget-object v2, p0, Ld2/l;->r:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v3, p0, Ld2/l;->s:Lg4/p0;

    .line 10
    .line 11
    iget-object v4, p0, Ld2/l;->t:Lk4/m;

    .line 12
    .line 13
    iget v5, p0, Ld2/l;->u:I

    .line 14
    .line 15
    iget-boolean v6, p0, Ld2/l;->v:Z

    .line 16
    .line 17
    iget v7, p0, Ld2/l;->w:I

    .line 18
    .line 19
    iget v8, p0, Ld2/l;->x:I

    .line 20
    .line 21
    invoke-direct/range {v1 .. v8}, Ld2/e;-><init>(Ljava/lang/String;Lg4/p0;Lk4/m;IZII)V

    .line 22
    .line 23
    .line 24
    iput-object v1, p0, Ld2/l;->A:Ld2/e;

    .line 25
    .line 26
    :cond_0
    iget-object p0, p0, Ld2/l;->A:Ld2/e;

    .line 27
    .line 28
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    return-object p0
.end method

.method public final a0(Ld4/l;)V
    .locals 6

    .line 1
    iget-object v0, p0, Ld2/l;->B:Ld2/j;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Ld2/j;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    invoke-direct {v0, p0, v1}, Ld2/j;-><init>(Ld2/l;I)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Ld2/l;->B:Ld2/j;

    .line 12
    .line 13
    :cond_0
    new-instance v1, Lg4/g;

    .line 14
    .line 15
    iget-object v2, p0, Ld2/l;->r:Ljava/lang/String;

    .line 16
    .line 17
    invoke-direct {v1, v2}, Lg4/g;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-static {p1, v1}, Ld4/x;->k(Ld4/l;Lg4/g;)V

    .line 21
    .line 22
    .line 23
    iget-object v1, p0, Ld2/l;->C:Ld2/k;

    .line 24
    .line 25
    if-eqz v1, :cond_1

    .line 26
    .line 27
    iget-boolean v2, v1, Ld2/k;->c:Z

    .line 28
    .line 29
    sget-object v3, Ld4/v;->C:Ld4/z;

    .line 30
    .line 31
    sget-object v4, Ld4/x;->a:[Lhy0/z;

    .line 32
    .line 33
    const/16 v5, 0x10

    .line 34
    .line 35
    aget-object v5, v4, v5

    .line 36
    .line 37
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 38
    .line 39
    .line 40
    move-result-object v2

    .line 41
    invoke-virtual {v3, p1, v2}, Ld4/z;->a(Ld4/l;Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    new-instance v2, Lg4/g;

    .line 45
    .line 46
    iget-object v1, v1, Ld2/k;->b:Ljava/lang/String;

    .line 47
    .line 48
    invoke-direct {v2, v1}, Lg4/g;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    sget-object v1, Ld4/v;->B:Ld4/z;

    .line 52
    .line 53
    const/16 v3, 0xf

    .line 54
    .line 55
    aget-object v3, v4, v3

    .line 56
    .line 57
    invoke-virtual {v1, p1, v2}, Ld4/z;->a(Ld4/l;Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    :cond_1
    new-instance v1, Ld2/j;

    .line 61
    .line 62
    const/4 v2, 0x1

    .line 63
    invoke-direct {v1, p0, v2}, Ld2/j;-><init>(Ld2/l;I)V

    .line 64
    .line 65
    .line 66
    sget-object v2, Ld4/k;->k:Ld4/z;

    .line 67
    .line 68
    new-instance v3, Ld4/a;

    .line 69
    .line 70
    const/4 v4, 0x0

    .line 71
    invoke-direct {v3, v4, v1}, Ld4/a;-><init>(Ljava/lang/String;Llx0/e;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {p1, v2, v3}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    new-instance v1, Ld2/j;

    .line 78
    .line 79
    const/4 v2, 0x2

    .line 80
    invoke-direct {v1, p0, v2}, Ld2/j;-><init>(Ld2/l;I)V

    .line 81
    .line 82
    .line 83
    sget-object v2, Ld4/k;->l:Ld4/z;

    .line 84
    .line 85
    new-instance v3, Ld4/a;

    .line 86
    .line 87
    invoke-direct {v3, v4, v1}, Ld4/a;-><init>(Ljava/lang/String;Llx0/e;)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {p1, v2, v3}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    new-instance v1, Ld2/g;

    .line 94
    .line 95
    const/4 v2, 0x1

    .line 96
    invoke-direct {v1, p0, v2}, Ld2/g;-><init>(Ljava/lang/Object;I)V

    .line 97
    .line 98
    .line 99
    sget-object p0, Ld4/k;->m:Ld4/z;

    .line 100
    .line 101
    new-instance v2, Ld4/a;

    .line 102
    .line 103
    invoke-direct {v2, v4, v1}, Ld4/a;-><init>(Ljava/lang/String;Llx0/e;)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {p1, p0, v2}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    invoke-static {p1, v0}, Ld4/x;->b(Ld4/l;Lay0/k;)V

    .line 110
    .line 111
    .line 112
    return-void
.end method

.method public final c(Lt3/s0;Lt3/p0;J)Lt3/r0;
    .locals 4

    .line 1
    const-string v0, "TextStringSimpleNode::measure"

    .line 2
    .line 3
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    iget-object v0, p0, Ld2/l;->C:Ld2/k;

    .line 7
    .line 8
    if-eqz v0, :cond_1

    .line 9
    .line 10
    iget-boolean v1, v0, Ld2/k;->c:Z

    .line 11
    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    const/4 v0, 0x0

    .line 16
    :goto_0
    if-eqz v0, :cond_1

    .line 17
    .line 18
    iget-object v0, v0, Ld2/k;->d:Ld2/e;

    .line 19
    .line 20
    if-nez v0, :cond_2

    .line 21
    .line 22
    :cond_1
    invoke-virtual {p0}, Ld2/l;->X0()Ld2/e;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    :cond_2
    invoke-virtual {v0, p1}, Ld2/e;->d(Lt4/c;)V

    .line 27
    .line 28
    .line 29
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    invoke-virtual {v0, p3, p4, v1}, Ld2/e;->b(JLt4/m;)Z

    .line 34
    .line 35
    .line 36
    move-result p3

    .line 37
    iget-object p4, v0, Ld2/e;->n:Lg4/s;

    .line 38
    .line 39
    if-eqz p4, :cond_3

    .line 40
    .line 41
    invoke-interface {p4}, Lg4/s;->a()Z

    .line 42
    .line 43
    .line 44
    :cond_3
    iget-object p4, v0, Ld2/e;->j:Lg4/a;

    .line 45
    .line 46
    invoke-static {p4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    iget-object p4, p4, Lg4/a;->d:Lh4/j;

    .line 50
    .line 51
    iget-wide v0, v0, Ld2/e;->l:J

    .line 52
    .line 53
    if-eqz p3, :cond_5

    .line 54
    .line 55
    const/4 p3, 0x2

    .line 56
    invoke-static {p0, p3}, Lv3/f;->v(Lv3/m;I)Lv3/f1;

    .line 57
    .line 58
    .line 59
    move-result-object v2

    .line 60
    invoke-virtual {v2}, Lv3/f1;->m1()V

    .line 61
    .line 62
    .line 63
    iget-object v2, p0, Ld2/l;->z:Ljava/util/HashMap;

    .line 64
    .line 65
    if-nez v2, :cond_4

    .line 66
    .line 67
    new-instance v2, Ljava/util/HashMap;

    .line 68
    .line 69
    invoke-direct {v2, p3}, Ljava/util/HashMap;-><init>(I)V

    .line 70
    .line 71
    .line 72
    iput-object v2, p0, Ld2/l;->z:Ljava/util/HashMap;

    .line 73
    .line 74
    :cond_4
    sget-object p3, Lt3/d;->a:Lt3/o;

    .line 75
    .line 76
    const/4 v3, 0x0

    .line 77
    invoke-virtual {p4, v3}, Lh4/j;->d(I)F

    .line 78
    .line 79
    .line 80
    move-result v3

    .line 81
    invoke-static {v3}, Ljava/lang/Math;->round(F)I

    .line 82
    .line 83
    .line 84
    move-result v3

    .line 85
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 86
    .line 87
    .line 88
    move-result-object v3

    .line 89
    invoke-interface {v2, p3, v3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    sget-object p3, Lt3/d;->b:Lt3/o;

    .line 93
    .line 94
    iget v3, p4, Lh4/j;->g:I

    .line 95
    .line 96
    add-int/lit8 v3, v3, -0x1

    .line 97
    .line 98
    invoke-virtual {p4, v3}, Lh4/j;->d(I)F

    .line 99
    .line 100
    .line 101
    move-result p4

    .line 102
    invoke-static {p4}, Ljava/lang/Math;->round(F)I

    .line 103
    .line 104
    .line 105
    move-result p4

    .line 106
    invoke-static {p4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 107
    .line 108
    .line 109
    move-result-object p4

    .line 110
    invoke-interface {v2, p3, p4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    :cond_5
    const/16 p3, 0x20

    .line 114
    .line 115
    shr-long p3, v0, p3

    .line 116
    .line 117
    long-to-int p3, p3

    .line 118
    const-wide v2, 0xffffffffL

    .line 119
    .line 120
    .line 121
    .line 122
    .line 123
    and-long/2addr v0, v2

    .line 124
    long-to-int p4, v0

    .line 125
    invoke-static {p3, p3, p4, p4}, Lkp/a9;->b(IIII)J

    .line 126
    .line 127
    .line 128
    move-result-wide v0

    .line 129
    invoke-interface {p2, v0, v1}, Lt3/p0;->L(J)Lt3/e1;

    .line 130
    .line 131
    .line 132
    move-result-object p2

    .line 133
    iget-object p0, p0, Ld2/l;->z:Ljava/util/HashMap;

    .line 134
    .line 135
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 136
    .line 137
    .line 138
    new-instance v0, Lam/a;

    .line 139
    .line 140
    const/4 v1, 0x2

    .line 141
    invoke-direct {v0, p2, v1}, Lam/a;-><init>(Lt3/e1;I)V

    .line 142
    .line 143
    .line 144
    invoke-interface {p1, p3, p4, p0, v0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 145
    .line 146
    .line 147
    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 148
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 149
    .line 150
    .line 151
    return-object p0

    .line 152
    :catchall_0
    move-exception p0

    .line 153
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 154
    .line 155
    .line 156
    throw p0
.end method
