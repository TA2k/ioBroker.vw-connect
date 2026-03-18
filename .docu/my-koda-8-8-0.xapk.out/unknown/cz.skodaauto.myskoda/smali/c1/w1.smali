.class public final Lc1/w1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lap0/o;

.field public final b:Lc1/w1;

.field public final c:Ljava/lang/String;

.field public final d:Ll2/j1;

.field public final e:Ll2/j1;

.field public final f:Ll2/h1;

.field public final g:Ll2/h1;

.field public final h:Ll2/j1;

.field public final i:Lv2/o;

.field public final j:Lv2/o;

.field public final k:Ll2/j1;

.field public final l:Ll2/h0;


# direct methods
.method public constructor <init>(Lap0/o;Lc1/w1;Ljava/lang/String;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lc1/w1;->a:Lap0/o;

    .line 5
    .line 6
    iput-object p2, p0, Lc1/w1;->b:Lc1/w1;

    .line 7
    .line 8
    iput-object p3, p0, Lc1/w1;->c:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {p1}, Lap0/o;->D()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p2

    .line 14
    invoke-static {p2}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 15
    .line 16
    .line 17
    move-result-object p2

    .line 18
    iput-object p2, p0, Lc1/w1;->d:Ll2/j1;

    .line 19
    .line 20
    new-instance p2, Lc1/s1;

    .line 21
    .line 22
    invoke-virtual {p1}, Lap0/o;->D()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object p3

    .line 26
    invoke-virtual {p1}, Lap0/o;->D()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    invoke-direct {p2, p3, v0}, Lc1/s1;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    invoke-static {p2}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 34
    .line 35
    .line 36
    move-result-object p2

    .line 37
    iput-object p2, p0, Lc1/w1;->e:Ll2/j1;

    .line 38
    .line 39
    new-instance p2, Ll2/h1;

    .line 40
    .line 41
    const-wide/16 v0, 0x0

    .line 42
    .line 43
    invoke-direct {p2, v0, v1}, Ll2/h1;-><init>(J)V

    .line 44
    .line 45
    .line 46
    iput-object p2, p0, Lc1/w1;->f:Ll2/h1;

    .line 47
    .line 48
    new-instance p2, Ll2/h1;

    .line 49
    .line 50
    const-wide/high16 v0, -0x8000000000000000L

    .line 51
    .line 52
    invoke-direct {p2, v0, v1}, Ll2/h1;-><init>(J)V

    .line 53
    .line 54
    .line 55
    iput-object p2, p0, Lc1/w1;->g:Ll2/h1;

    .line 56
    .line 57
    sget-object p2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 58
    .line 59
    invoke-static {p2}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 60
    .line 61
    .line 62
    move-result-object p3

    .line 63
    iput-object p3, p0, Lc1/w1;->h:Ll2/j1;

    .line 64
    .line 65
    new-instance p3, Lv2/o;

    .line 66
    .line 67
    invoke-direct {p3}, Lv2/o;-><init>()V

    .line 68
    .line 69
    .line 70
    iput-object p3, p0, Lc1/w1;->i:Lv2/o;

    .line 71
    .line 72
    new-instance p3, Lv2/o;

    .line 73
    .line 74
    invoke-direct {p3}, Lv2/o;-><init>()V

    .line 75
    .line 76
    .line 77
    iput-object p3, p0, Lc1/w1;->j:Lv2/o;

    .line 78
    .line 79
    invoke-static {p2}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 80
    .line 81
    .line 82
    move-result-object p2

    .line 83
    iput-object p2, p0, Lc1/w1;->k:Ll2/j1;

    .line 84
    .line 85
    new-instance p2, Lc1/o1;

    .line 86
    .line 87
    const/4 p3, 0x1

    .line 88
    invoke-direct {p2, p0, p3}, Lc1/o1;-><init>(Lc1/w1;I)V

    .line 89
    .line 90
    .line 91
    invoke-static {p2}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 92
    .line 93
    .line 94
    move-result-object p2

    .line 95
    iput-object p2, p0, Lc1/w1;->l:Ll2/h0;

    .line 96
    .line 97
    invoke-virtual {p1, p0}, Lap0/o;->V(Lc1/w1;)V

    .line 98
    .line 99
    .line 100
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Ll2/o;I)V
    .locals 7

    .line 1
    check-cast p2, Ll2/t;

    .line 2
    .line 3
    const v0, -0x59064cff

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p3, 0x6

    .line 10
    .line 11
    if-nez v0, :cond_2

    .line 12
    .line 13
    and-int/lit8 v0, p3, 0x8

    .line 14
    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    invoke-virtual {p2, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    invoke-virtual {p2, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    :goto_0
    if-eqz v0, :cond_1

    .line 27
    .line 28
    const/4 v0, 0x4

    .line 29
    goto :goto_1

    .line 30
    :cond_1
    const/4 v0, 0x2

    .line 31
    :goto_1
    or-int/2addr v0, p3

    .line 32
    goto :goto_2

    .line 33
    :cond_2
    move v0, p3

    .line 34
    :goto_2
    and-int/lit8 v1, p3, 0x30

    .line 35
    .line 36
    const/16 v2, 0x20

    .line 37
    .line 38
    if-nez v1, :cond_4

    .line 39
    .line 40
    invoke-virtual {p2, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    if-eqz v1, :cond_3

    .line 45
    .line 46
    move v1, v2

    .line 47
    goto :goto_3

    .line 48
    :cond_3
    const/16 v1, 0x10

    .line 49
    .line 50
    :goto_3
    or-int/2addr v0, v1

    .line 51
    :cond_4
    and-int/lit8 v1, v0, 0x13

    .line 52
    .line 53
    const/16 v3, 0x12

    .line 54
    .line 55
    const/4 v4, 0x1

    .line 56
    const/4 v5, 0x0

    .line 57
    if-eq v1, v3, :cond_5

    .line 58
    .line 59
    move v1, v4

    .line 60
    goto :goto_4

    .line 61
    :cond_5
    move v1, v5

    .line 62
    :goto_4
    and-int/lit8 v3, v0, 0x1

    .line 63
    .line 64
    invoke-virtual {p2, v3, v1}, Ll2/t;->O(IZ)Z

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    if-eqz v1, :cond_f

    .line 69
    .line 70
    invoke-virtual {p0}, Lc1/w1;->g()Z

    .line 71
    .line 72
    .line 73
    move-result v1

    .line 74
    if-nez v1, :cond_e

    .line 75
    .line 76
    const v1, 0x1bc87041

    .line 77
    .line 78
    .line 79
    invoke-virtual {p2, v1}, Ll2/t;->Y(I)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {p0, p1}, Lc1/w1;->p(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    and-int/lit8 v0, v0, 0x70

    .line 86
    .line 87
    if-ne v0, v2, :cond_6

    .line 88
    .line 89
    move v1, v4

    .line 90
    goto :goto_5

    .line 91
    :cond_6
    move v1, v5

    .line 92
    :goto_5
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v3

    .line 96
    sget-object v6, Ll2/n;->a:Ll2/x0;

    .line 97
    .line 98
    if-nez v1, :cond_7

    .line 99
    .line 100
    if-ne v3, v6, :cond_8

    .line 101
    .line 102
    :cond_7
    new-instance v1, Lc1/o1;

    .line 103
    .line 104
    const/4 v3, 0x0

    .line 105
    invoke-direct {v1, p0, v3}, Lc1/o1;-><init>(Lc1/w1;I)V

    .line 106
    .line 107
    .line 108
    invoke-static {v1}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 109
    .line 110
    .line 111
    move-result-object v3

    .line 112
    invoke-virtual {p2, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 113
    .line 114
    .line 115
    :cond_8
    check-cast v3, Ll2/t2;

    .line 116
    .line 117
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object v1

    .line 121
    check-cast v1, Ljava/lang/Boolean;

    .line 122
    .line 123
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 124
    .line 125
    .line 126
    move-result v1

    .line 127
    if-eqz v1, :cond_d

    .line 128
    .line 129
    const v1, 0x1bceaa74    # 3.4189994E-22f

    .line 130
    .line 131
    .line 132
    invoke-virtual {p2, v1}, Ll2/t;->Y(I)V

    .line 133
    .line 134
    .line 135
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object v1

    .line 139
    if-ne v1, v6, :cond_9

    .line 140
    .line 141
    invoke-static {p2}, Ll2/l0;->h(Ll2/o;)Lvy0/b0;

    .line 142
    .line 143
    .line 144
    move-result-object v1

    .line 145
    invoke-virtual {p2, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 146
    .line 147
    .line 148
    :cond_9
    check-cast v1, Lvy0/b0;

    .line 149
    .line 150
    invoke-virtual {p2, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 151
    .line 152
    .line 153
    move-result v3

    .line 154
    if-ne v0, v2, :cond_a

    .line 155
    .line 156
    goto :goto_6

    .line 157
    :cond_a
    move v4, v5

    .line 158
    :goto_6
    or-int v0, v3, v4

    .line 159
    .line 160
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object v2

    .line 164
    if-nez v0, :cond_b

    .line 165
    .line 166
    if-ne v2, v6, :cond_c

    .line 167
    .line 168
    :cond_b
    new-instance v2, Laa/z;

    .line 169
    .line 170
    const/16 v0, 0x8

    .line 171
    .line 172
    invoke-direct {v2, v0, v1, p0}, Laa/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 173
    .line 174
    .line 175
    invoke-virtual {p2, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 176
    .line 177
    .line 178
    :cond_c
    check-cast v2, Lay0/k;

    .line 179
    .line 180
    invoke-static {v1, p0, v2, p2}, Ll2/l0;->b(Ljava/lang/Object;Ljava/lang/Object;Lay0/k;Ll2/o;)V

    .line 181
    .line 182
    .line 183
    invoke-virtual {p2, v5}, Ll2/t;->q(Z)V

    .line 184
    .line 185
    .line 186
    goto :goto_7

    .line 187
    :cond_d
    const v0, 0x1be1a041

    .line 188
    .line 189
    .line 190
    invoke-virtual {p2, v0}, Ll2/t;->Y(I)V

    .line 191
    .line 192
    .line 193
    invoke-virtual {p2, v5}, Ll2/t;->q(Z)V

    .line 194
    .line 195
    .line 196
    :goto_7
    invoke-virtual {p2, v5}, Ll2/t;->q(Z)V

    .line 197
    .line 198
    .line 199
    goto :goto_8

    .line 200
    :cond_e
    const v0, 0x1be1c701

    .line 201
    .line 202
    .line 203
    invoke-virtual {p2, v0}, Ll2/t;->Y(I)V

    .line 204
    .line 205
    .line 206
    invoke-virtual {p2, v5}, Ll2/t;->q(Z)V

    .line 207
    .line 208
    .line 209
    goto :goto_8

    .line 210
    :cond_f
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 211
    .line 212
    .line 213
    :goto_8
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 214
    .line 215
    .line 216
    move-result-object p2

    .line 217
    if-eqz p2, :cond_10

    .line 218
    .line 219
    new-instance v0, La71/n0;

    .line 220
    .line 221
    const/4 v1, 0x5

    .line 222
    invoke-direct {v0, p3, v1, p0, p1}, La71/n0;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 223
    .line 224
    .line 225
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 226
    .line 227
    :cond_10
    return-void
.end method

.method public final b()J
    .locals 8

    .line 1
    iget-object v0, p0, Lc1/w1;->i:Lv2/o;

    .line 2
    .line 3
    invoke-virtual {v0}, Lv2/o;->size()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const-wide/16 v2, 0x0

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    move v5, v4

    .line 11
    :goto_0
    if-ge v5, v1, :cond_0

    .line 12
    .line 13
    invoke-virtual {v0, v5}, Lv2/o;->get(I)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v6

    .line 17
    check-cast v6, Lc1/t1;

    .line 18
    .line 19
    iget-object v6, v6, Lc1/t1;->o:Ll2/h1;

    .line 20
    .line 21
    iget-object v7, v6, Ll2/h1;->e:Ll2/l2;

    .line 22
    .line 23
    invoke-static {v7, v6}, Lv2/l;->t(Lv2/v;Lv2/t;)Lv2/v;

    .line 24
    .line 25
    .line 26
    move-result-object v6

    .line 27
    check-cast v6, Ll2/l2;

    .line 28
    .line 29
    iget-wide v6, v6, Ll2/l2;->c:J

    .line 30
    .line 31
    invoke-static {v2, v3, v6, v7}, Ljava/lang/Math;->max(JJ)J

    .line 32
    .line 33
    .line 34
    move-result-wide v2

    .line 35
    add-int/lit8 v5, v5, 0x1

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    iget-object p0, p0, Lc1/w1;->j:Lv2/o;

    .line 39
    .line 40
    invoke-virtual {p0}, Lv2/o;->size()I

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    :goto_1
    if-ge v4, v0, :cond_1

    .line 45
    .line 46
    invoke-virtual {p0, v4}, Lv2/o;->get(I)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    check-cast v1, Lc1/w1;

    .line 51
    .line 52
    invoke-virtual {v1}, Lc1/w1;->b()J

    .line 53
    .line 54
    .line 55
    move-result-wide v5

    .line 56
    invoke-static {v2, v3, v5, v6}, Ljava/lang/Math;->max(JJ)J

    .line 57
    .line 58
    .line 59
    move-result-wide v2

    .line 60
    add-int/lit8 v4, v4, 0x1

    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_1
    return-wide v2
.end method

.method public final c()V
    .locals 6

    .line 1
    iget-object v0, p0, Lc1/w1;->i:Lv2/o;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const/4 v2, 0x0

    .line 8
    move v3, v2

    .line 9
    :goto_0
    if-ge v3, v1, :cond_0

    .line 10
    .line 11
    invoke-interface {v0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v4

    .line 15
    check-cast v4, Lc1/t1;

    .line 16
    .line 17
    const/4 v5, 0x0

    .line 18
    iput-object v5, v4, Lc1/t1;->i:Lc1/n1;

    .line 19
    .line 20
    iput-object v5, v4, Lc1/t1;->h:Lc1/v0;

    .line 21
    .line 22
    iput-boolean v2, v4, Lc1/t1;->l:Z

    .line 23
    .line 24
    add-int/lit8 v3, v3, 0x1

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    iget-object p0, p0, Lc1/w1;->j:Lv2/o;

    .line 28
    .line 29
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    :goto_1
    if-ge v2, v0, :cond_1

    .line 34
    .line 35
    invoke-interface {p0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    check-cast v1, Lc1/w1;

    .line 40
    .line 41
    invoke-virtual {v1}, Lc1/w1;->c()V

    .line 42
    .line 43
    .line 44
    add-int/lit8 v2, v2, 0x1

    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_1
    return-void
.end method

.method public final d()Z
    .locals 5

    .line 1
    iget-object v0, p0, Lc1/w1;->i:Lv2/o;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const/4 v2, 0x0

    .line 8
    move v3, v2

    .line 9
    :goto_0
    if-ge v3, v1, :cond_1

    .line 10
    .line 11
    invoke-interface {v0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v4

    .line 15
    check-cast v4, Lc1/t1;

    .line 16
    .line 17
    iget-object v4, v4, Lc1/t1;->h:Lc1/v0;

    .line 18
    .line 19
    if-eqz v4, :cond_0

    .line 20
    .line 21
    goto :goto_2

    .line 22
    :cond_0
    add-int/lit8 v3, v3, 0x1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    iget-object p0, p0, Lc1/w1;->j:Lv2/o;

    .line 26
    .line 27
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    move v1, v2

    .line 32
    :goto_1
    if-ge v1, v0, :cond_3

    .line 33
    .line 34
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v3

    .line 38
    check-cast v3, Lc1/w1;

    .line 39
    .line 40
    invoke-virtual {v3}, Lc1/w1;->d()Z

    .line 41
    .line 42
    .line 43
    move-result v3

    .line 44
    if-eqz v3, :cond_2

    .line 45
    .line 46
    :goto_2
    const/4 p0, 0x1

    .line 47
    return p0

    .line 48
    :cond_2
    add-int/lit8 v1, v1, 0x1

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_3
    return v2
.end method

.method public final e()J
    .locals 2

    .line 1
    iget-object v0, p0, Lc1/w1;->b:Lc1/w1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Lc1/w1;->e()J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    return-wide v0

    .line 10
    :cond_0
    iget-object p0, p0, Lc1/w1;->f:Ll2/h1;

    .line 11
    .line 12
    iget-object v0, p0, Ll2/h1;->e:Ll2/l2;

    .line 13
    .line 14
    invoke-static {v0, p0}, Lv2/l;->t(Lv2/v;Lv2/t;)Lv2/v;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    check-cast p0, Ll2/l2;

    .line 19
    .line 20
    iget-wide v0, p0, Ll2/l2;->c:J

    .line 21
    .line 22
    return-wide v0
.end method

.method public final f()Lc1/r1;
    .locals 0

    .line 1
    iget-object p0, p0, Lc1/w1;->e:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lc1/r1;

    .line 8
    .line 9
    return-object p0
.end method

.method public final g()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lc1/w1;->k:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final h(JZ)V
    .locals 10

    .line 1
    iget-object v0, p0, Lc1/w1;->g:Ll2/h1;

    .line 2
    .line 3
    iget-object v1, v0, Ll2/h1;->e:Ll2/l2;

    .line 4
    .line 5
    invoke-static {v1, v0}, Lv2/l;->t(Lv2/v;Lv2/t;)Lv2/v;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    check-cast v1, Ll2/l2;

    .line 10
    .line 11
    iget-wide v1, v1, Ll2/l2;->c:J

    .line 12
    .line 13
    const-wide/high16 v3, -0x8000000000000000L

    .line 14
    .line 15
    cmp-long v1, v1, v3

    .line 16
    .line 17
    iget-object v2, p0, Lc1/w1;->a:Lap0/o;

    .line 18
    .line 19
    if-nez v1, :cond_0

    .line 20
    .line 21
    invoke-virtual {v0, p1, p2}, Ll2/h1;->c(J)V

    .line 22
    .line 23
    .line 24
    iget-object v0, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v0, Ll2/j1;

    .line 27
    .line 28
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    iget-object v0, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v0, Ll2/j1;

    .line 37
    .line 38
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    check-cast v0, Ljava/lang/Boolean;

    .line 43
    .line 44
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    if-nez v0, :cond_1

    .line 49
    .line 50
    iget-object v0, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast v0, Ll2/j1;

    .line 53
    .line 54
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 55
    .line 56
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    :cond_1
    :goto_0
    iget-object v0, p0, Lc1/w1;->h:Ll2/j1;

    .line 60
    .line 61
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 62
    .line 63
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    iget-object v0, p0, Lc1/w1;->i:Lv2/o;

    .line 67
    .line 68
    invoke-virtual {v0}, Lv2/o;->size()I

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    const/4 v2, 0x0

    .line 73
    const/4 v3, 0x1

    .line 74
    move v4, v2

    .line 75
    :goto_1
    if-ge v4, v1, :cond_5

    .line 76
    .line 77
    invoke-virtual {v0, v4}, Lv2/o;->get(I)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v5

    .line 81
    check-cast v5, Lc1/t1;

    .line 82
    .line 83
    iget-object v6, v5, Lc1/t1;->j:Ll2/j1;

    .line 84
    .line 85
    iget-object v7, v5, Lc1/t1;->j:Ll2/j1;

    .line 86
    .line 87
    invoke-virtual {v6}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v6

    .line 91
    check-cast v6, Ljava/lang/Boolean;

    .line 92
    .line 93
    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    .line 94
    .line 95
    .line 96
    move-result v6

    .line 97
    if-nez v6, :cond_3

    .line 98
    .line 99
    if-eqz p3, :cond_2

    .line 100
    .line 101
    invoke-virtual {v5}, Lc1/t1;->a()Lc1/n1;

    .line 102
    .line 103
    .line 104
    move-result-object v6

    .line 105
    invoke-virtual {v6}, Lc1/n1;->d()J

    .line 106
    .line 107
    .line 108
    move-result-wide v8

    .line 109
    goto :goto_2

    .line 110
    :cond_2
    move-wide v8, p1

    .line 111
    :goto_2
    invoke-virtual {v5}, Lc1/t1;->a()Lc1/n1;

    .line 112
    .line 113
    .line 114
    move-result-object v6

    .line 115
    invoke-virtual {v6, v8, v9}, Lc1/n1;->f(J)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v6

    .line 119
    invoke-virtual {v5, v6}, Lc1/t1;->c(Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {v5}, Lc1/t1;->a()Lc1/n1;

    .line 123
    .line 124
    .line 125
    move-result-object v6

    .line 126
    invoke-virtual {v6, v8, v9}, Lc1/n1;->b(J)Lc1/p;

    .line 127
    .line 128
    .line 129
    move-result-object v6

    .line 130
    iput-object v6, v5, Lc1/t1;->n:Lc1/p;

    .line 131
    .line 132
    invoke-virtual {v5}, Lc1/t1;->a()Lc1/n1;

    .line 133
    .line 134
    .line 135
    move-result-object v5

    .line 136
    invoke-interface {v5, v8, v9}, Lc1/f;->c(J)Z

    .line 137
    .line 138
    .line 139
    move-result v5

    .line 140
    if-eqz v5, :cond_3

    .line 141
    .line 142
    sget-object v5, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 143
    .line 144
    invoke-virtual {v7, v5}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 145
    .line 146
    .line 147
    :cond_3
    invoke-virtual {v7}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object v5

    .line 151
    check-cast v5, Ljava/lang/Boolean;

    .line 152
    .line 153
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 154
    .line 155
    .line 156
    move-result v5

    .line 157
    if-nez v5, :cond_4

    .line 158
    .line 159
    move v3, v2

    .line 160
    :cond_4
    add-int/lit8 v4, v4, 0x1

    .line 161
    .line 162
    goto :goto_1

    .line 163
    :cond_5
    iget-object v0, p0, Lc1/w1;->j:Lv2/o;

    .line 164
    .line 165
    invoke-virtual {v0}, Lv2/o;->size()I

    .line 166
    .line 167
    .line 168
    move-result v1

    .line 169
    move v4, v2

    .line 170
    :goto_3
    if-ge v4, v1, :cond_8

    .line 171
    .line 172
    invoke-virtual {v0, v4}, Lv2/o;->get(I)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object v5

    .line 176
    check-cast v5, Lc1/w1;

    .line 177
    .line 178
    iget-object v6, v5, Lc1/w1;->d:Ll2/j1;

    .line 179
    .line 180
    iget-object v7, v5, Lc1/w1;->a:Lap0/o;

    .line 181
    .line 182
    invoke-virtual {v6}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object v6

    .line 186
    invoke-virtual {v7}, Lap0/o;->D()Ljava/lang/Object;

    .line 187
    .line 188
    .line 189
    move-result-object v8

    .line 190
    invoke-static {v6, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 191
    .line 192
    .line 193
    move-result v6

    .line 194
    if-nez v6, :cond_6

    .line 195
    .line 196
    invoke-virtual {v5, p1, p2, p3}, Lc1/w1;->h(JZ)V

    .line 197
    .line 198
    .line 199
    :cond_6
    iget-object v5, v5, Lc1/w1;->d:Ll2/j1;

    .line 200
    .line 201
    invoke-virtual {v5}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object v5

    .line 205
    invoke-virtual {v7}, Lap0/o;->D()Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v6

    .line 209
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 210
    .line 211
    .line 212
    move-result v5

    .line 213
    if-nez v5, :cond_7

    .line 214
    .line 215
    move v3, v2

    .line 216
    :cond_7
    add-int/lit8 v4, v4, 0x1

    .line 217
    .line 218
    goto :goto_3

    .line 219
    :cond_8
    if-eqz v3, :cond_9

    .line 220
    .line 221
    invoke-virtual {p0}, Lc1/w1;->i()V

    .line 222
    .line 223
    .line 224
    :cond_9
    return-void
.end method

.method public final i()V
    .locals 3

    .line 1
    const-wide/high16 v0, -0x8000000000000000L

    .line 2
    .line 3
    iget-object v2, p0, Lc1/w1;->g:Ll2/h1;

    .line 4
    .line 5
    invoke-virtual {v2, v0, v1}, Ll2/h1;->c(J)V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lc1/w1;->a:Lap0/o;

    .line 9
    .line 10
    instance-of v1, v0, Lc1/n0;

    .line 11
    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    move-object v1, v0

    .line 15
    check-cast v1, Lc1/n0;

    .line 16
    .line 17
    iget-object v2, p0, Lc1/w1;->d:Ll2/j1;

    .line 18
    .line 19
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    invoke-virtual {v1, v2}, Lc1/n0;->T(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    :cond_0
    const-wide/16 v1, 0x0

    .line 27
    .line 28
    invoke-virtual {p0, v1, v2}, Lc1/w1;->n(J)V

    .line 29
    .line 30
    .line 31
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast v0, Ll2/j1;

    .line 34
    .line 35
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 36
    .line 37
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    iget-object p0, p0, Lc1/w1;->j:Lv2/o;

    .line 41
    .line 42
    invoke-virtual {p0}, Lv2/o;->size()I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    const/4 v1, 0x0

    .line 47
    :goto_0
    if-ge v1, v0, :cond_1

    .line 48
    .line 49
    invoke-virtual {p0, v1}, Lv2/o;->get(I)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v2

    .line 53
    check-cast v2, Lc1/w1;

    .line 54
    .line 55
    invoke-virtual {v2}, Lc1/w1;->i()V

    .line 56
    .line 57
    .line 58
    add-int/lit8 v1, v1, 0x1

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_1
    return-void
.end method

.method public final j(F)V
    .locals 8

    .line 1
    iget-object v0, p0, Lc1/w1;->i:Lv2/o;

    .line 2
    .line 3
    invoke-virtual {v0}, Lv2/o;->size()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const/4 v2, 0x0

    .line 8
    move v3, v2

    .line 9
    :goto_0
    if-ge v3, v1, :cond_4

    .line 10
    .line 11
    invoke-virtual {v0, v3}, Lv2/o;->get(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v4

    .line 15
    check-cast v4, Lc1/t1;

    .line 16
    .line 17
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    const/high16 v5, -0x3f800000    # -4.0f

    .line 21
    .line 22
    cmpg-float v5, p1, v5

    .line 23
    .line 24
    if-nez v5, :cond_0

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_0
    const/high16 v6, -0x3f600000    # -5.0f

    .line 28
    .line 29
    cmpg-float v6, p1, v6

    .line 30
    .line 31
    if-nez v6, :cond_3

    .line 32
    .line 33
    :goto_1
    iget-object v6, v4, Lc1/t1;->i:Lc1/n1;

    .line 34
    .line 35
    if-eqz v6, :cond_1

    .line 36
    .line 37
    invoke-virtual {v4}, Lc1/t1;->a()Lc1/n1;

    .line 38
    .line 39
    .line 40
    move-result-object v7

    .line 41
    iget-object v6, v6, Lc1/n1;->c:Ljava/lang/Object;

    .line 42
    .line 43
    invoke-virtual {v7, v6}, Lc1/n1;->h(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    const/4 v6, 0x0

    .line 47
    iput-object v6, v4, Lc1/t1;->h:Lc1/v0;

    .line 48
    .line 49
    iput-object v6, v4, Lc1/t1;->i:Lc1/n1;

    .line 50
    .line 51
    :cond_1
    if-nez v5, :cond_2

    .line 52
    .line 53
    invoke-virtual {v4}, Lc1/t1;->a()Lc1/n1;

    .line 54
    .line 55
    .line 56
    move-result-object v5

    .line 57
    iget-object v5, v5, Lc1/n1;->d:Ljava/lang/Object;

    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_2
    invoke-virtual {v4}, Lc1/t1;->a()Lc1/n1;

    .line 61
    .line 62
    .line 63
    move-result-object v5

    .line 64
    iget-object v5, v5, Lc1/n1;->c:Ljava/lang/Object;

    .line 65
    .line 66
    :goto_2
    invoke-virtual {v4}, Lc1/t1;->a()Lc1/n1;

    .line 67
    .line 68
    .line 69
    move-result-object v6

    .line 70
    invoke-virtual {v6, v5}, Lc1/n1;->h(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {v4}, Lc1/t1;->a()Lc1/n1;

    .line 74
    .line 75
    .line 76
    move-result-object v6

    .line 77
    invoke-virtual {v6, v5}, Lc1/n1;->i(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {v4, v5}, Lc1/t1;->c(Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {v4}, Lc1/t1;->a()Lc1/n1;

    .line 84
    .line 85
    .line 86
    move-result-object v5

    .line 87
    invoke-virtual {v5}, Lc1/n1;->d()J

    .line 88
    .line 89
    .line 90
    move-result-wide v5

    .line 91
    iget-object v4, v4, Lc1/t1;->o:Ll2/h1;

    .line 92
    .line 93
    invoke-virtual {v4, v5, v6}, Ll2/h1;->c(J)V

    .line 94
    .line 95
    .line 96
    goto :goto_3

    .line 97
    :cond_3
    iget-object v4, v4, Lc1/t1;->k:Ll2/f1;

    .line 98
    .line 99
    invoke-virtual {v4, p1}, Ll2/f1;->p(F)V

    .line 100
    .line 101
    .line 102
    :goto_3
    add-int/lit8 v3, v3, 0x1

    .line 103
    .line 104
    goto :goto_0

    .line 105
    :cond_4
    iget-object p0, p0, Lc1/w1;->j:Lv2/o;

    .line 106
    .line 107
    invoke-virtual {p0}, Lv2/o;->size()I

    .line 108
    .line 109
    .line 110
    move-result v0

    .line 111
    :goto_4
    if-ge v2, v0, :cond_5

    .line 112
    .line 113
    invoke-virtual {p0, v2}, Lv2/o;->get(I)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v1

    .line 117
    check-cast v1, Lc1/w1;

    .line 118
    .line 119
    invoke-virtual {v1, p1}, Lc1/w1;->j(F)V

    .line 120
    .line 121
    .line 122
    add-int/lit8 v2, v2, 0x1

    .line 123
    .line 124
    goto :goto_4

    .line 125
    :cond_5
    return-void
.end method

.method public final k(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 5

    .line 1
    const-wide/high16 v0, -0x8000000000000000L

    .line 2
    .line 3
    iget-object v2, p0, Lc1/w1;->g:Ll2/h1;

    .line 4
    .line 5
    invoke-virtual {v2, v0, v1}, Ll2/h1;->c(J)V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lc1/w1;->a:Lap0/o;

    .line 9
    .line 10
    iget-object v1, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Ll2/j1;

    .line 13
    .line 14
    sget-object v2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 15
    .line 16
    invoke-virtual {v1, v2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p0}, Lc1/w1;->g()Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    iget-object v2, p0, Lc1/w1;->d:Ll2/j1;

    .line 24
    .line 25
    if-eqz v1, :cond_0

    .line 26
    .line 27
    invoke-virtual {v0}, Lap0/o;->D()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    invoke-static {v1, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-eqz v1, :cond_0

    .line 36
    .line 37
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    invoke-static {v1, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    if-nez v1, :cond_2

    .line 46
    .line 47
    :cond_0
    invoke-virtual {v0}, Lap0/o;->D()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    invoke-static {v1, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    if-nez v1, :cond_1

    .line 56
    .line 57
    instance-of v1, v0, Lc1/n0;

    .line 58
    .line 59
    if-eqz v1, :cond_1

    .line 60
    .line 61
    check-cast v0, Lc1/n0;

    .line 62
    .line 63
    invoke-virtual {v0, p1}, Lc1/n0;->T(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    :cond_1
    invoke-virtual {v2, p2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    iget-object v0, p0, Lc1/w1;->k:Ll2/j1;

    .line 70
    .line 71
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 72
    .line 73
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    new-instance v0, Lc1/s1;

    .line 77
    .line 78
    invoke-direct {v0, p1, p2}, Lc1/s1;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    iget-object p1, p0, Lc1/w1;->e:Ll2/j1;

    .line 82
    .line 83
    invoke-virtual {p1, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    :cond_2
    iget-object p1, p0, Lc1/w1;->j:Lv2/o;

    .line 87
    .line 88
    invoke-virtual {p1}, Lv2/o;->size()I

    .line 89
    .line 90
    .line 91
    move-result p2

    .line 92
    const/4 v0, 0x0

    .line 93
    move v1, v0

    .line 94
    :goto_0
    if-ge v1, p2, :cond_4

    .line 95
    .line 96
    invoke-virtual {p1, v1}, Lv2/o;->get(I)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v2

    .line 100
    check-cast v2, Lc1/w1;

    .line 101
    .line 102
    const-string v3, "null cannot be cast to non-null type androidx.compose.animation.core.Transition<kotlin.Any>"

    .line 103
    .line 104
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {v2}, Lc1/w1;->g()Z

    .line 108
    .line 109
    .line 110
    move-result v3

    .line 111
    if-eqz v3, :cond_3

    .line 112
    .line 113
    iget-object v3, v2, Lc1/w1;->a:Lap0/o;

    .line 114
    .line 115
    invoke-virtual {v3}, Lap0/o;->D()Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v3

    .line 119
    iget-object v4, v2, Lc1/w1;->d:Ll2/j1;

    .line 120
    .line 121
    invoke-virtual {v4}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v4

    .line 125
    invoke-virtual {v2, v3, v4}, Lc1/w1;->k(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 126
    .line 127
    .line 128
    :cond_3
    add-int/lit8 v1, v1, 0x1

    .line 129
    .line 130
    goto :goto_0

    .line 131
    :cond_4
    iget-object p0, p0, Lc1/w1;->i:Lv2/o;

    .line 132
    .line 133
    invoke-virtual {p0}, Lv2/o;->size()I

    .line 134
    .line 135
    .line 136
    move-result p1

    .line 137
    :goto_1
    if-ge v0, p1, :cond_5

    .line 138
    .line 139
    invoke-virtual {p0, v0}, Lv2/o;->get(I)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object p2

    .line 143
    check-cast p2, Lc1/t1;

    .line 144
    .line 145
    const-wide/16 v1, 0x0

    .line 146
    .line 147
    invoke-virtual {p2, v1, v2}, Lc1/t1;->b(J)V

    .line 148
    .line 149
    .line 150
    add-int/lit8 v0, v0, 0x1

    .line 151
    .line 152
    goto :goto_1

    .line 153
    :cond_5
    return-void
.end method

.method public final l(J)V
    .locals 5

    .line 1
    iget-object v0, p0, Lc1/w1;->g:Ll2/h1;

    .line 2
    .line 3
    iget-object v1, v0, Ll2/h1;->e:Ll2/l2;

    .line 4
    .line 5
    invoke-static {v1, v0}, Lv2/l;->t(Lv2/v;Lv2/t;)Lv2/v;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    check-cast v1, Ll2/l2;

    .line 10
    .line 11
    iget-wide v1, v1, Ll2/l2;->c:J

    .line 12
    .line 13
    const-wide/high16 v3, -0x8000000000000000L

    .line 14
    .line 15
    cmp-long v1, v1, v3

    .line 16
    .line 17
    if-nez v1, :cond_0

    .line 18
    .line 19
    invoke-virtual {v0, p1, p2}, Ll2/h1;->c(J)V

    .line 20
    .line 21
    .line 22
    :cond_0
    invoke-virtual {p0, p1, p2}, Lc1/w1;->n(J)V

    .line 23
    .line 24
    .line 25
    iget-object v0, p0, Lc1/w1;->h:Ll2/j1;

    .line 26
    .line 27
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 28
    .line 29
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    iget-object v0, p0, Lc1/w1;->i:Lv2/o;

    .line 33
    .line 34
    invoke-virtual {v0}, Lv2/o;->size()I

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    const/4 v2, 0x0

    .line 39
    move v3, v2

    .line 40
    :goto_0
    if-ge v3, v1, :cond_1

    .line 41
    .line 42
    invoke-virtual {v0, v3}, Lv2/o;->get(I)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v4

    .line 46
    check-cast v4, Lc1/t1;

    .line 47
    .line 48
    invoke-virtual {v4, p1, p2}, Lc1/t1;->b(J)V

    .line 49
    .line 50
    .line 51
    add-int/lit8 v3, v3, 0x1

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_1
    iget-object p0, p0, Lc1/w1;->j:Lv2/o;

    .line 55
    .line 56
    invoke-virtual {p0}, Lv2/o;->size()I

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    :goto_1
    if-ge v2, v0, :cond_3

    .line 61
    .line 62
    invoke-virtual {p0, v2}, Lv2/o;->get(I)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v1

    .line 66
    check-cast v1, Lc1/w1;

    .line 67
    .line 68
    iget-object v3, v1, Lc1/w1;->d:Ll2/j1;

    .line 69
    .line 70
    invoke-virtual {v3}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v3

    .line 74
    iget-object v4, v1, Lc1/w1;->a:Lap0/o;

    .line 75
    .line 76
    invoke-virtual {v4}, Lap0/o;->D()Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object v4

    .line 80
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    move-result v3

    .line 84
    if-nez v3, :cond_2

    .line 85
    .line 86
    invoke-virtual {v1, p1, p2}, Lc1/w1;->l(J)V

    .line 87
    .line 88
    .line 89
    :cond_2
    add-int/lit8 v2, v2, 0x1

    .line 90
    .line 91
    goto :goto_1

    .line 92
    :cond_3
    return-void
.end method

.method public final m(Lc1/v0;)V
    .locals 13

    .line 1
    iget-object v0, p0, Lc1/w1;->i:Lv2/o;

    .line 2
    .line 3
    invoke-virtual {v0}, Lv2/o;->size()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const/4 v2, 0x0

    .line 8
    move v3, v2

    .line 9
    :goto_0
    if-ge v3, v1, :cond_1

    .line 10
    .line 11
    invoke-virtual {v0, v3}, Lv2/o;->get(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v4

    .line 15
    check-cast v4, Lc1/t1;

    .line 16
    .line 17
    iget-object v5, v4, Lc1/t1;->m:Ll2/j1;

    .line 18
    .line 19
    invoke-virtual {v4}, Lc1/t1;->a()Lc1/n1;

    .line 20
    .line 21
    .line 22
    move-result-object v6

    .line 23
    iget-object v6, v6, Lc1/n1;->c:Ljava/lang/Object;

    .line 24
    .line 25
    invoke-virtual {v4}, Lc1/t1;->a()Lc1/n1;

    .line 26
    .line 27
    .line 28
    move-result-object v7

    .line 29
    iget-object v7, v7, Lc1/n1;->d:Ljava/lang/Object;

    .line 30
    .line 31
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v6

    .line 35
    if-nez v6, :cond_0

    .line 36
    .line 37
    invoke-virtual {v4}, Lc1/t1;->a()Lc1/n1;

    .line 38
    .line 39
    .line 40
    move-result-object v6

    .line 41
    iput-object v6, v4, Lc1/t1;->i:Lc1/n1;

    .line 42
    .line 43
    iput-object p1, v4, Lc1/t1;->h:Lc1/v0;

    .line 44
    .line 45
    :cond_0
    new-instance v7, Lc1/n1;

    .line 46
    .line 47
    iget-object v8, v4, Lc1/t1;->q:Lc1/f1;

    .line 48
    .line 49
    iget-object v9, v4, Lc1/t1;->d:Lc1/b2;

    .line 50
    .line 51
    invoke-virtual {v5}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v10

    .line 55
    invoke-virtual {v5}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v11

    .line 59
    iget-object v5, v4, Lc1/t1;->n:Lc1/p;

    .line 60
    .line 61
    invoke-virtual {v5}, Lc1/p;->c()Lc1/p;

    .line 62
    .line 63
    .line 64
    move-result-object v12

    .line 65
    invoke-direct/range {v7 .. v12}, Lc1/n1;-><init>(Lc1/j;Lc1/b2;Ljava/lang/Object;Ljava/lang/Object;Lc1/p;)V

    .line 66
    .line 67
    .line 68
    iget-object v5, v4, Lc1/t1;->g:Ll2/j1;

    .line 69
    .line 70
    invoke-virtual {v5, v7}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {v4}, Lc1/t1;->a()Lc1/n1;

    .line 74
    .line 75
    .line 76
    move-result-object v5

    .line 77
    invoke-virtual {v5}, Lc1/n1;->d()J

    .line 78
    .line 79
    .line 80
    move-result-wide v5

    .line 81
    iget-object v7, v4, Lc1/t1;->o:Ll2/h1;

    .line 82
    .line 83
    invoke-virtual {v7, v5, v6}, Ll2/h1;->c(J)V

    .line 84
    .line 85
    .line 86
    const/4 v5, 0x1

    .line 87
    iput-boolean v5, v4, Lc1/t1;->l:Z

    .line 88
    .line 89
    add-int/lit8 v3, v3, 0x1

    .line 90
    .line 91
    goto :goto_0

    .line 92
    :cond_1
    iget-object p0, p0, Lc1/w1;->j:Lv2/o;

    .line 93
    .line 94
    invoke-virtual {p0}, Lv2/o;->size()I

    .line 95
    .line 96
    .line 97
    move-result v0

    .line 98
    :goto_1
    if-ge v2, v0, :cond_2

    .line 99
    .line 100
    invoke-virtual {p0, v2}, Lv2/o;->get(I)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v1

    .line 104
    check-cast v1, Lc1/w1;

    .line 105
    .line 106
    invoke-virtual {v1, p1}, Lc1/w1;->m(Lc1/v0;)V

    .line 107
    .line 108
    .line 109
    add-int/lit8 v2, v2, 0x1

    .line 110
    .line 111
    goto :goto_1

    .line 112
    :cond_2
    return-void
.end method

.method public final n(J)V
    .locals 1

    .line 1
    iget-object v0, p0, Lc1/w1;->b:Lc1/w1;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lc1/w1;->f:Ll2/h1;

    .line 6
    .line 7
    invoke-virtual {p0, p1, p2}, Ll2/h1;->c(J)V

    .line 8
    .line 9
    .line 10
    :cond_0
    return-void
.end method

.method public final o()V
    .locals 12

    .line 1
    iget-object v0, p0, Lc1/w1;->i:Lv2/o;

    .line 2
    .line 3
    invoke-virtual {v0}, Lv2/o;->size()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const/4 v2, 0x0

    .line 8
    move v3, v2

    .line 9
    :goto_0
    if-ge v3, v1, :cond_6

    .line 10
    .line 11
    invoke-virtual {v0, v3}, Lv2/o;->get(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v4

    .line 15
    check-cast v4, Lc1/t1;

    .line 16
    .line 17
    iget-object v5, v4, Lc1/t1;->h:Lc1/v0;

    .line 18
    .line 19
    if-nez v5, :cond_0

    .line 20
    .line 21
    goto :goto_3

    .line 22
    :cond_0
    iget-object v6, v4, Lc1/t1;->i:Lc1/n1;

    .line 23
    .line 24
    if-nez v6, :cond_1

    .line 25
    .line 26
    goto :goto_3

    .line 27
    :cond_1
    iget-wide v7, v5, Lc1/v0;->g:J

    .line 28
    .line 29
    long-to-double v7, v7

    .line 30
    iget v9, v5, Lc1/v0;->d:F

    .line 31
    .line 32
    float-to-double v9, v9

    .line 33
    mul-double/2addr v7, v9

    .line 34
    invoke-static {v7, v8}, Lcy0/a;->j(D)J

    .line 35
    .line 36
    .line 37
    move-result-wide v7

    .line 38
    invoke-virtual {v6, v7, v8}, Lc1/n1;->f(J)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v6

    .line 42
    iget-boolean v9, v4, Lc1/t1;->l:Z

    .line 43
    .line 44
    if-eqz v9, :cond_2

    .line 45
    .line 46
    invoke-virtual {v4}, Lc1/t1;->a()Lc1/n1;

    .line 47
    .line 48
    .line 49
    move-result-object v9

    .line 50
    invoke-virtual {v9, v6}, Lc1/n1;->i(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    :cond_2
    invoke-virtual {v4}, Lc1/t1;->a()Lc1/n1;

    .line 54
    .line 55
    .line 56
    move-result-object v9

    .line 57
    invoke-virtual {v9, v6}, Lc1/n1;->h(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v4}, Lc1/t1;->a()Lc1/n1;

    .line 61
    .line 62
    .line 63
    move-result-object v9

    .line 64
    invoke-virtual {v9}, Lc1/n1;->d()J

    .line 65
    .line 66
    .line 67
    move-result-wide v9

    .line 68
    iget-object v11, v4, Lc1/t1;->o:Ll2/h1;

    .line 69
    .line 70
    invoke-virtual {v11, v9, v10}, Ll2/h1;->c(J)V

    .line 71
    .line 72
    .line 73
    iget-object v9, v4, Lc1/t1;->k:Ll2/f1;

    .line 74
    .line 75
    invoke-virtual {v9}, Ll2/f1;->o()F

    .line 76
    .line 77
    .line 78
    move-result v9

    .line 79
    const/high16 v10, -0x40000000    # -2.0f

    .line 80
    .line 81
    cmpg-float v9, v9, v10

    .line 82
    .line 83
    if-nez v9, :cond_3

    .line 84
    .line 85
    goto :goto_1

    .line 86
    :cond_3
    iget-boolean v9, v4, Lc1/t1;->l:Z

    .line 87
    .line 88
    if-eqz v9, :cond_4

    .line 89
    .line 90
    :goto_1
    invoke-virtual {v4, v6}, Lc1/t1;->c(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    goto :goto_2

    .line 94
    :cond_4
    iget-object v6, v4, Lc1/t1;->r:Lc1/w1;

    .line 95
    .line 96
    invoke-virtual {v6}, Lc1/w1;->e()J

    .line 97
    .line 98
    .line 99
    move-result-wide v9

    .line 100
    invoke-virtual {v4, v9, v10}, Lc1/t1;->b(J)V

    .line 101
    .line 102
    .line 103
    :goto_2
    iget-wide v9, v5, Lc1/v0;->g:J

    .line 104
    .line 105
    cmp-long v6, v7, v9

    .line 106
    .line 107
    if-ltz v6, :cond_5

    .line 108
    .line 109
    const/4 v5, 0x0

    .line 110
    iput-object v5, v4, Lc1/t1;->h:Lc1/v0;

    .line 111
    .line 112
    iput-object v5, v4, Lc1/t1;->i:Lc1/n1;

    .line 113
    .line 114
    goto :goto_3

    .line 115
    :cond_5
    iput-boolean v2, v5, Lc1/v0;->c:Z

    .line 116
    .line 117
    :goto_3
    add-int/lit8 v3, v3, 0x1

    .line 118
    .line 119
    goto :goto_0

    .line 120
    :cond_6
    iget-object p0, p0, Lc1/w1;->j:Lv2/o;

    .line 121
    .line 122
    invoke-virtual {p0}, Lv2/o;->size()I

    .line 123
    .line 124
    .line 125
    move-result v0

    .line 126
    :goto_4
    if-ge v2, v0, :cond_7

    .line 127
    .line 128
    invoke-virtual {p0, v2}, Lv2/o;->get(I)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v1

    .line 132
    check-cast v1, Lc1/w1;

    .line 133
    .line 134
    invoke-virtual {v1}, Lc1/w1;->o()V

    .line 135
    .line 136
    .line 137
    add-int/lit8 v2, v2, 0x1

    .line 138
    .line 139
    goto :goto_4

    .line 140
    :cond_7
    return-void
.end method

.method public final p(Ljava/lang/Object;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lc1/w1;->d:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-static {v1, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-nez v1, :cond_2

    .line 12
    .line 13
    new-instance v1, Lc1/s1;

    .line 14
    .line 15
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    invoke-direct {v1, v2, p1}, Lc1/s1;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    iget-object v2, p0, Lc1/w1;->e:Ll2/j1;

    .line 23
    .line 24
    invoke-virtual {v2, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    iget-object v1, p0, Lc1/w1;->a:Lap0/o;

    .line 28
    .line 29
    invoke-virtual {v1}, Lap0/o;->D()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v3

    .line 37
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    if-nez v2, :cond_0

    .line 42
    .line 43
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    invoke-virtual {v1, v2}, Lap0/o;->T(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    :cond_0
    invoke-virtual {v0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iget-object p1, p0, Lc1/w1;->g:Ll2/h1;

    .line 54
    .line 55
    iget-object v0, p1, Ll2/h1;->e:Ll2/l2;

    .line 56
    .line 57
    invoke-static {v0, p1}, Lv2/l;->t(Lv2/v;Lv2/t;)Lv2/v;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    check-cast p1, Ll2/l2;

    .line 62
    .line 63
    iget-wide v0, p1, Ll2/l2;->c:J

    .line 64
    .line 65
    const-wide/high16 v2, -0x8000000000000000L

    .line 66
    .line 67
    cmp-long p1, v0, v2

    .line 68
    .line 69
    if-eqz p1, :cond_1

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_1
    iget-object p1, p0, Lc1/w1;->h:Ll2/j1;

    .line 73
    .line 74
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 75
    .line 76
    invoke-virtual {p1, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    :goto_0
    iget-object p0, p0, Lc1/w1;->i:Lv2/o;

    .line 80
    .line 81
    invoke-virtual {p0}, Lv2/o;->size()I

    .line 82
    .line 83
    .line 84
    move-result p1

    .line 85
    const/4 v0, 0x0

    .line 86
    :goto_1
    if-ge v0, p1, :cond_2

    .line 87
    .line 88
    invoke-virtual {p0, v0}, Lv2/o;->get(I)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v1

    .line 92
    check-cast v1, Lc1/t1;

    .line 93
    .line 94
    const/high16 v2, -0x40000000    # -2.0f

    .line 95
    .line 96
    iget-object v1, v1, Lc1/t1;->k:Ll2/f1;

    .line 97
    .line 98
    invoke-virtual {v1, v2}, Ll2/f1;->p(F)V

    .line 99
    .line 100
    .line 101
    add-int/lit8 v0, v0, 0x1

    .line 102
    .line 103
    goto :goto_1

    .line 104
    :cond_2
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget-object p0, p0, Lc1/w1;->i:Lv2/o;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const-string v1, "Transition animation values: "

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    :goto_0
    if-ge v2, v0, :cond_0

    .line 11
    .line 12
    invoke-virtual {p0, v2}, Lv2/o;->get(I)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v3

    .line 16
    check-cast v3, Lc1/t1;

    .line 17
    .line 18
    new-instance v4, Ljava/lang/StringBuilder;

    .line 19
    .line 20
    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    .line 21
    .line 22
    .line 23
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const-string v1, ", "

    .line 30
    .line 31
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    add-int/lit8 v2, v2, 0x1

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    return-object v1
.end method
