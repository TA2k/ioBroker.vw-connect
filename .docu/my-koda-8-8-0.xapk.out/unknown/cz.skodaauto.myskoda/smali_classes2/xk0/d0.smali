.class public abstract Lxk0/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x80

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Lxk0/d0;->a:F

    .line 5
    .line 6
    return-void
.end method

.method public static final a(Lay0/k;Lay0/k;Ll2/o;I)V
    .locals 5

    .line 1
    const-string v0, "setDrawerDefaultHeight"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "setDrawerMinHeight"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    check-cast p2, Ll2/t;

    .line 12
    .line 13
    const v0, 0x255abeb2

    .line 14
    .line 15
    .line 16
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    and-int/lit8 v0, p3, 0x6

    .line 20
    .line 21
    if-nez v0, :cond_1

    .line 22
    .line 23
    invoke-virtual {p2, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    const/4 v0, 0x4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v0, 0x2

    .line 32
    :goto_0
    or-int/2addr v0, p3

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    move v0, p3

    .line 35
    :goto_1
    and-int/lit8 v1, p3, 0x30

    .line 36
    .line 37
    if-nez v1, :cond_3

    .line 38
    .line 39
    invoke-virtual {p2, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_2

    .line 44
    .line 45
    const/16 v1, 0x20

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_2
    const/16 v1, 0x10

    .line 49
    .line 50
    :goto_2
    or-int/2addr v0, v1

    .line 51
    :cond_3
    and-int/lit8 v1, v0, 0x13

    .line 52
    .line 53
    const/16 v2, 0x12

    .line 54
    .line 55
    const/4 v3, 0x0

    .line 56
    const/4 v4, 0x1

    .line 57
    if-eq v1, v2, :cond_4

    .line 58
    .line 59
    move v1, v4

    .line 60
    goto :goto_3

    .line 61
    :cond_4
    move v1, v3

    .line 62
    :goto_3
    and-int/2addr v0, v4

    .line 63
    invoke-virtual {p2, v0, v1}, Ll2/t;->O(IZ)Z

    .line 64
    .line 65
    .line 66
    move-result v0

    .line 67
    if-eqz v0, :cond_5

    .line 68
    .line 69
    new-instance v0, Lt4/f;

    .line 70
    .line 71
    sget v1, Lxk0/d0;->a:F

    .line 72
    .line 73
    invoke-direct {v0, v1}, Lt4/f;-><init>(F)V

    .line 74
    .line 75
    .line 76
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    new-instance v0, Lt4/f;

    .line 80
    .line 81
    invoke-direct {v0, v1}, Lt4/f;-><init>(F)V

    .line 82
    .line 83
    .line 84
    invoke-interface {p1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    invoke-static {p2, v3}, Lxk0/d0;->b(Ll2/o;I)V

    .line 88
    .line 89
    .line 90
    goto :goto_4

    .line 91
    :cond_5
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 92
    .line 93
    .line 94
    :goto_4
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 95
    .line 96
    .line 97
    move-result-object p2

    .line 98
    if-eqz p2, :cond_6

    .line 99
    .line 100
    new-instance v0, Lnd0/a;

    .line 101
    .line 102
    invoke-direct {v0, p0, p1, p3}, Lnd0/a;-><init>(Lay0/k;Lay0/k;I)V

    .line 103
    .line 104
    .line 105
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 106
    .line 107
    :cond_6
    return-void
.end method

.method public static final b(Ll2/o;I)V
    .locals 14

    .line 1
    move-object v9, p0

    .line 2
    check-cast v9, Ll2/t;

    .line 3
    .line 4
    const p0, -0x5109fca0

    .line 5
    .line 6
    .line 7
    invoke-virtual {v9, p0}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    const/4 p0, 0x0

    .line 11
    const/4 v13, 0x1

    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    move v0, v13

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move v0, p0

    .line 17
    :goto_0
    and-int/lit8 v1, p1, 0x1

    .line 18
    .line 19
    invoke-virtual {v9, v1, v0}, Ll2/t;->O(IZ)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_4

    .line 24
    .line 25
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 26
    .line 27
    const/high16 v1, 0x3f800000    # 1.0f

    .line 28
    .line 29
    invoke-static {v0, v1}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    sget-object v1, Lj91/a;->a:Ll2/u2;

    .line 34
    .line 35
    invoke-virtual {v9, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    check-cast v2, Lj91/c;

    .line 40
    .line 41
    iget v2, v2, Lj91/c;->d:F

    .line 42
    .line 43
    invoke-virtual {v9, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v3

    .line 47
    check-cast v3, Lj91/c;

    .line 48
    .line 49
    iget v3, v3, Lj91/c;->d:F

    .line 50
    .line 51
    invoke-virtual {v9, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v4

    .line 55
    check-cast v4, Lj91/c;

    .line 56
    .line 57
    iget v4, v4, Lj91/c;->c:F

    .line 58
    .line 59
    invoke-virtual {v9, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v1

    .line 63
    check-cast v1, Lj91/c;

    .line 64
    .line 65
    iget v1, v1, Lj91/c;->e:F

    .line 66
    .line 67
    invoke-static {v0, v2, v4, v3, v1}, Landroidx/compose/foundation/layout/a;->p(Lx2/s;FFFF)Lx2/s;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    sget-object v1, Lx2/c;->d:Lx2/j;

    .line 72
    .line 73
    invoke-static {v1, p0}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    iget-wide v1, v9, Ll2/t;->T:J

    .line 78
    .line 79
    invoke-static {v1, v2}, Ljava/lang/Long;->hashCode(J)I

    .line 80
    .line 81
    .line 82
    move-result v1

    .line 83
    invoke-virtual {v9}, Ll2/t;->m()Ll2/p1;

    .line 84
    .line 85
    .line 86
    move-result-object v2

    .line 87
    invoke-static {v9, v0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    sget-object v3, Lv3/k;->m1:Lv3/j;

    .line 92
    .line 93
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 94
    .line 95
    .line 96
    sget-object v3, Lv3/j;->b:Lv3/i;

    .line 97
    .line 98
    invoke-virtual {v9}, Ll2/t;->c0()V

    .line 99
    .line 100
    .line 101
    iget-boolean v4, v9, Ll2/t;->S:Z

    .line 102
    .line 103
    if-eqz v4, :cond_1

    .line 104
    .line 105
    invoke-virtual {v9, v3}, Ll2/t;->l(Lay0/a;)V

    .line 106
    .line 107
    .line 108
    goto :goto_1

    .line 109
    :cond_1
    invoke-virtual {v9}, Ll2/t;->m0()V

    .line 110
    .line 111
    .line 112
    :goto_1
    sget-object v3, Lv3/j;->g:Lv3/h;

    .line 113
    .line 114
    invoke-static {v3, p0, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 115
    .line 116
    .line 117
    sget-object p0, Lv3/j;->f:Lv3/h;

    .line 118
    .line 119
    invoke-static {p0, v2, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 120
    .line 121
    .line 122
    sget-object p0, Lv3/j;->j:Lv3/h;

    .line 123
    .line 124
    iget-boolean v2, v9, Ll2/t;->S:Z

    .line 125
    .line 126
    if-nez v2, :cond_2

    .line 127
    .line 128
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v2

    .line 132
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 133
    .line 134
    .line 135
    move-result-object v3

    .line 136
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    move-result v2

    .line 140
    if-nez v2, :cond_3

    .line 141
    .line 142
    :cond_2
    invoke-static {v1, v9, v1, p0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 143
    .line 144
    .line 145
    :cond_3
    sget-object p0, Lv3/j;->d:Lv3/h;

    .line 146
    .line 147
    invoke-static {p0, v0, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 148
    .line 149
    .line 150
    const p0, 0x7f1205ea

    .line 151
    .line 152
    .line 153
    invoke-static {v9, p0}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 154
    .line 155
    .line 156
    move-result-object v1

    .line 157
    const p0, 0x7f1205e9

    .line 158
    .line 159
    .line 160
    invoke-static {v9, p0}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object v2

    .line 164
    sget-object v3, Li91/q0;->e:Li91/q0;

    .line 165
    .line 166
    sget-object v4, Li91/r0;->g:Li91/r0;

    .line 167
    .line 168
    const/4 v11, 0x0

    .line 169
    const/16 v12, 0x3fe1

    .line 170
    .line 171
    const/4 v0, 0x0

    .line 172
    const/4 v5, 0x0

    .line 173
    const/4 v6, 0x0

    .line 174
    const/4 v7, 0x0

    .line 175
    const/4 v8, 0x0

    .line 176
    const/16 v10, 0x6c00

    .line 177
    .line 178
    invoke-static/range {v0 .. v12}, Li91/d0;->b(Lx2/s;Ljava/lang/String;Ljava/lang/String;Li91/q0;Li91/r0;ZLay0/a;Li91/p0;Ljava/lang/String;Ll2/o;III)V

    .line 179
    .line 180
    .line 181
    invoke-virtual {v9, v13}, Ll2/t;->q(Z)V

    .line 182
    .line 183
    .line 184
    goto :goto_2

    .line 185
    :cond_4
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 186
    .line 187
    .line 188
    :goto_2
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 189
    .line 190
    .line 191
    move-result-object p0

    .line 192
    if-eqz p0, :cond_5

    .line 193
    .line 194
    new-instance v0, Lxk0/z;

    .line 195
    .line 196
    const/4 v1, 0x1

    .line 197
    invoke-direct {v0, p1, v1}, Lxk0/z;-><init>(II)V

    .line 198
    .line 199
    .line 200
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 201
    .line 202
    :cond_5
    return-void
.end method
