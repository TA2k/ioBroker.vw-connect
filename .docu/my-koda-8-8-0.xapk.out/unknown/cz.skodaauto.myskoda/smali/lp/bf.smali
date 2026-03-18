.class public abstract Llp/bf;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(FILl2/o;)V
    .locals 5

    .line 1
    check-cast p2, Ll2/t;

    .line 2
    .line 3
    const v0, -0x2d924cf1

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p1, 0x6

    .line 10
    .line 11
    const/4 v1, 0x2

    .line 12
    if-nez v0, :cond_1

    .line 13
    .line 14
    invoke-virtual {p2, p0}, Ll2/t;->d(F)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    const/4 v0, 0x4

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    move v0, v1

    .line 23
    :goto_0
    or-int/2addr v0, p1

    .line 24
    goto :goto_1

    .line 25
    :cond_1
    move v0, p1

    .line 26
    :goto_1
    and-int/lit8 v2, v0, 0x3

    .line 27
    .line 28
    const/4 v3, 0x0

    .line 29
    const/4 v4, 0x1

    .line 30
    if-eq v2, v1, :cond_2

    .line 31
    .line 32
    move v1, v4

    .line 33
    goto :goto_2

    .line 34
    :cond_2
    move v1, v3

    .line 35
    :goto_2
    and-int/lit8 v2, v0, 0x1

    .line 36
    .line 37
    invoke-virtual {p2, v2, v1}, Ll2/t;->O(IZ)Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    if-eqz v1, :cond_3

    .line 42
    .line 43
    and-int/lit8 v0, v0, 0xe

    .line 44
    .line 45
    or-int/lit16 v0, v0, 0x1b0

    .line 46
    .line 47
    invoke-static {p0, v4, v3, p2, v0}, Llp/bf;->e(FZZLl2/o;I)V

    .line 48
    .line 49
    .line 50
    goto :goto_3

    .line 51
    :cond_3
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 52
    .line 53
    .line 54
    :goto_3
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 55
    .line 56
    .line 57
    move-result-object p2

    .line 58
    if-eqz p2, :cond_4

    .line 59
    .line 60
    new-instance v0, Li40/e3;

    .line 61
    .line 62
    const/4 v1, 0x1

    .line 63
    invoke-direct {v0, p0, p1, v1}, Li40/e3;-><init>(FII)V

    .line 64
    .line 65
    .line 66
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 67
    .line 68
    :cond_4
    return-void
.end method

.method public static final b(FILl2/o;)V
    .locals 4

    .line 1
    check-cast p2, Ll2/t;

    .line 2
    .line 3
    const v0, -0x331e9b26

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p1, 0x6

    .line 10
    .line 11
    const/4 v1, 0x2

    .line 12
    if-nez v0, :cond_1

    .line 13
    .line 14
    invoke-virtual {p2, p0}, Ll2/t;->d(F)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    const/4 v0, 0x4

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    move v0, v1

    .line 23
    :goto_0
    or-int/2addr v0, p1

    .line 24
    goto :goto_1

    .line 25
    :cond_1
    move v0, p1

    .line 26
    :goto_1
    and-int/lit8 v2, v0, 0x3

    .line 27
    .line 28
    const/4 v3, 0x1

    .line 29
    if-eq v2, v1, :cond_2

    .line 30
    .line 31
    move v1, v3

    .line 32
    goto :goto_2

    .line 33
    :cond_2
    const/4 v1, 0x0

    .line 34
    :goto_2
    and-int/lit8 v2, v0, 0x1

    .line 35
    .line 36
    invoke-virtual {p2, v2, v1}, Ll2/t;->O(IZ)Z

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    if-eqz v1, :cond_3

    .line 41
    .line 42
    and-int/lit8 v0, v0, 0xe

    .line 43
    .line 44
    or-int/lit16 v0, v0, 0x1b0

    .line 45
    .line 46
    invoke-static {p0, v3, v3, p2, v0}, Llp/bf;->e(FZZLl2/o;I)V

    .line 47
    .line 48
    .line 49
    goto :goto_3

    .line 50
    :cond_3
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 51
    .line 52
    .line 53
    :goto_3
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 54
    .line 55
    .line 56
    move-result-object p2

    .line 57
    if-eqz p2, :cond_4

    .line 58
    .line 59
    new-instance v0, Li40/e3;

    .line 60
    .line 61
    const/4 v1, 0x2

    .line 62
    invoke-direct {v0, p0, p1, v1}, Li40/e3;-><init>(FII)V

    .line 63
    .line 64
    .line 65
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 66
    .line 67
    :cond_4
    return-void
.end method

.method public static final c(FILl2/o;)V
    .locals 4

    .line 1
    check-cast p2, Ll2/t;

    .line 2
    .line 3
    const v0, 0x19fc5de0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p1, 0x6

    .line 10
    .line 11
    const/4 v1, 0x2

    .line 12
    if-nez v0, :cond_1

    .line 13
    .line 14
    invoke-virtual {p2, p0}, Ll2/t;->d(F)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    const/4 v0, 0x4

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    move v0, v1

    .line 23
    :goto_0
    or-int/2addr v0, p1

    .line 24
    goto :goto_1

    .line 25
    :cond_1
    move v0, p1

    .line 26
    :goto_1
    and-int/lit8 v2, v0, 0x3

    .line 27
    .line 28
    const/4 v3, 0x0

    .line 29
    if-eq v2, v1, :cond_2

    .line 30
    .line 31
    const/4 v1, 0x1

    .line 32
    goto :goto_2

    .line 33
    :cond_2
    move v1, v3

    .line 34
    :goto_2
    and-int/lit8 v2, v0, 0x1

    .line 35
    .line 36
    invoke-virtual {p2, v2, v1}, Ll2/t;->O(IZ)Z

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    if-eqz v1, :cond_3

    .line 41
    .line 42
    and-int/lit8 v0, v0, 0xe

    .line 43
    .line 44
    or-int/lit16 v0, v0, 0x1b0

    .line 45
    .line 46
    invoke-static {p0, v3, v3, p2, v0}, Llp/bf;->e(FZZLl2/o;I)V

    .line 47
    .line 48
    .line 49
    goto :goto_3

    .line 50
    :cond_3
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 51
    .line 52
    .line 53
    :goto_3
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 54
    .line 55
    .line 56
    move-result-object p2

    .line 57
    if-eqz p2, :cond_4

    .line 58
    .line 59
    new-instance v0, Li40/e3;

    .line 60
    .line 61
    const/4 v1, 0x3

    .line 62
    invoke-direct {v0, p0, p1, v1}, Li40/e3;-><init>(FII)V

    .line 63
    .line 64
    .line 65
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 66
    .line 67
    :cond_4
    return-void
.end method

.method public static final d(FILl2/o;)V
    .locals 5

    .line 1
    check-cast p2, Ll2/t;

    .line 2
    .line 3
    const v0, 0x2fc81d63

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p1, 0x6

    .line 10
    .line 11
    const/4 v1, 0x2

    .line 12
    if-nez v0, :cond_1

    .line 13
    .line 14
    invoke-virtual {p2, p0}, Ll2/t;->d(F)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    const/4 v0, 0x4

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    move v0, v1

    .line 23
    :goto_0
    or-int/2addr v0, p1

    .line 24
    goto :goto_1

    .line 25
    :cond_1
    move v0, p1

    .line 26
    :goto_1
    and-int/lit8 v2, v0, 0x3

    .line 27
    .line 28
    const/4 v3, 0x0

    .line 29
    const/4 v4, 0x1

    .line 30
    if-eq v2, v1, :cond_2

    .line 31
    .line 32
    move v1, v4

    .line 33
    goto :goto_2

    .line 34
    :cond_2
    move v1, v3

    .line 35
    :goto_2
    and-int/lit8 v2, v0, 0x1

    .line 36
    .line 37
    invoke-virtual {p2, v2, v1}, Ll2/t;->O(IZ)Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    if-eqz v1, :cond_3

    .line 42
    .line 43
    and-int/lit8 v0, v0, 0xe

    .line 44
    .line 45
    or-int/lit16 v0, v0, 0x1b0

    .line 46
    .line 47
    invoke-static {p0, v3, v4, p2, v0}, Llp/bf;->e(FZZLl2/o;I)V

    .line 48
    .line 49
    .line 50
    goto :goto_3

    .line 51
    :cond_3
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 52
    .line 53
    .line 54
    :goto_3
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 55
    .line 56
    .line 57
    move-result-object p2

    .line 58
    if-eqz p2, :cond_4

    .line 59
    .line 60
    new-instance v0, Li40/e3;

    .line 61
    .line 62
    const/4 v1, 0x4

    .line 63
    invoke-direct {v0, p0, p1, v1}, Li40/e3;-><init>(FII)V

    .line 64
    .line 65
    .line 66
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 67
    .line 68
    :cond_4
    return-void
.end method

.method public static final e(FZZLl2/o;I)V
    .locals 17

    .line 1
    move/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p2

    .line 6
    .line 7
    move/from16 v3, p4

    .line 8
    .line 9
    move-object/from16 v4, p3

    .line 10
    .line 11
    check-cast v4, Ll2/t;

    .line 12
    .line 13
    const v5, 0x74715d89

    .line 14
    .line 15
    .line 16
    invoke-virtual {v4, v5}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    and-int/lit8 v5, v3, 0x6

    .line 20
    .line 21
    const/4 v6, 0x4

    .line 22
    if-nez v5, :cond_1

    .line 23
    .line 24
    invoke-virtual {v4, v0}, Ll2/t;->d(F)Z

    .line 25
    .line 26
    .line 27
    move-result v5

    .line 28
    if-eqz v5, :cond_0

    .line 29
    .line 30
    move v5, v6

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    const/4 v5, 0x2

    .line 33
    :goto_0
    or-int/2addr v5, v3

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    move v5, v3

    .line 36
    :goto_1
    and-int/lit8 v7, v3, 0x30

    .line 37
    .line 38
    const/16 v8, 0x20

    .line 39
    .line 40
    if-nez v7, :cond_3

    .line 41
    .line 42
    invoke-virtual {v4, v1}, Ll2/t;->h(Z)Z

    .line 43
    .line 44
    .line 45
    move-result v7

    .line 46
    if-eqz v7, :cond_2

    .line 47
    .line 48
    move v7, v8

    .line 49
    goto :goto_2

    .line 50
    :cond_2
    const/16 v7, 0x10

    .line 51
    .line 52
    :goto_2
    or-int/2addr v5, v7

    .line 53
    :cond_3
    and-int/lit16 v7, v3, 0x180

    .line 54
    .line 55
    const/16 v9, 0x100

    .line 56
    .line 57
    if-nez v7, :cond_5

    .line 58
    .line 59
    invoke-virtual {v4, v2}, Ll2/t;->h(Z)Z

    .line 60
    .line 61
    .line 62
    move-result v7

    .line 63
    if-eqz v7, :cond_4

    .line 64
    .line 65
    move v7, v9

    .line 66
    goto :goto_3

    .line 67
    :cond_4
    const/16 v7, 0x80

    .line 68
    .line 69
    :goto_3
    or-int/2addr v5, v7

    .line 70
    :cond_5
    and-int/lit16 v7, v5, 0x93

    .line 71
    .line 72
    const/16 v10, 0x92

    .line 73
    .line 74
    const/4 v11, 0x0

    .line 75
    if-eq v7, v10, :cond_6

    .line 76
    .line 77
    const/4 v7, 0x1

    .line 78
    goto :goto_4

    .line 79
    :cond_6
    move v7, v11

    .line 80
    :goto_4
    and-int/lit8 v10, v5, 0x1

    .line 81
    .line 82
    invoke-virtual {v4, v10, v7}, Ll2/t;->O(IZ)Z

    .line 83
    .line 84
    .line 85
    move-result v7

    .line 86
    if-eqz v7, :cond_10

    .line 87
    .line 88
    sget-object v7, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 89
    .line 90
    sget-object v10, Lx2/c;->d:Lx2/j;

    .line 91
    .line 92
    invoke-static {v10, v11}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 93
    .line 94
    .line 95
    move-result-object v10

    .line 96
    iget-wide v13, v4, Ll2/t;->T:J

    .line 97
    .line 98
    invoke-static {v13, v14}, Ljava/lang/Long;->hashCode(J)I

    .line 99
    .line 100
    .line 101
    move-result v13

    .line 102
    invoke-virtual {v4}, Ll2/t;->m()Ll2/p1;

    .line 103
    .line 104
    .line 105
    move-result-object v14

    .line 106
    invoke-static {v4, v7}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 107
    .line 108
    .line 109
    move-result-object v15

    .line 110
    sget-object v16, Lv3/k;->m1:Lv3/j;

    .line 111
    .line 112
    invoke-virtual/range {v16 .. v16}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 113
    .line 114
    .line 115
    sget-object v12, Lv3/j;->b:Lv3/i;

    .line 116
    .line 117
    invoke-virtual {v4}, Ll2/t;->c0()V

    .line 118
    .line 119
    .line 120
    iget-boolean v11, v4, Ll2/t;->S:Z

    .line 121
    .line 122
    if-eqz v11, :cond_7

    .line 123
    .line 124
    invoke-virtual {v4, v12}, Ll2/t;->l(Lay0/a;)V

    .line 125
    .line 126
    .line 127
    goto :goto_5

    .line 128
    :cond_7
    invoke-virtual {v4}, Ll2/t;->m0()V

    .line 129
    .line 130
    .line 131
    :goto_5
    sget-object v11, Lv3/j;->g:Lv3/h;

    .line 132
    .line 133
    invoke-static {v11, v10, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 134
    .line 135
    .line 136
    sget-object v10, Lv3/j;->f:Lv3/h;

    .line 137
    .line 138
    invoke-static {v10, v14, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 139
    .line 140
    .line 141
    sget-object v10, Lv3/j;->j:Lv3/h;

    .line 142
    .line 143
    iget-boolean v11, v4, Ll2/t;->S:Z

    .line 144
    .line 145
    if-nez v11, :cond_8

    .line 146
    .line 147
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object v11

    .line 151
    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 152
    .line 153
    .line 154
    move-result-object v12

    .line 155
    invoke-static {v11, v12}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 156
    .line 157
    .line 158
    move-result v11

    .line 159
    if-nez v11, :cond_9

    .line 160
    .line 161
    :cond_8
    invoke-static {v13, v4, v13, v10}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 162
    .line 163
    .line 164
    :cond_9
    sget-object v10, Lv3/j;->d:Lv3/h;

    .line 165
    .line 166
    invoke-static {v10, v15, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 167
    .line 168
    .line 169
    if-eqz v2, :cond_a

    .line 170
    .line 171
    const/high16 v10, 0x43340000    # 180.0f

    .line 172
    .line 173
    goto :goto_6

    .line 174
    :cond_a
    const/4 v10, 0x0

    .line 175
    :goto_6
    invoke-static {v7, v10}, Ljp/ca;->c(Lx2/s;F)Lx2/s;

    .line 176
    .line 177
    .line 178
    move-result-object v7

    .line 179
    and-int/lit8 v10, v5, 0xe

    .line 180
    .line 181
    if-ne v10, v6, :cond_b

    .line 182
    .line 183
    const/4 v6, 0x1

    .line 184
    goto :goto_7

    .line 185
    :cond_b
    const/4 v6, 0x0

    .line 186
    :goto_7
    and-int/lit8 v10, v5, 0x70

    .line 187
    .line 188
    if-ne v10, v8, :cond_c

    .line 189
    .line 190
    const/4 v8, 0x1

    .line 191
    goto :goto_8

    .line 192
    :cond_c
    const/4 v8, 0x0

    .line 193
    :goto_8
    or-int/2addr v6, v8

    .line 194
    and-int/lit16 v5, v5, 0x380

    .line 195
    .line 196
    if-ne v5, v9, :cond_d

    .line 197
    .line 198
    const/4 v5, 0x1

    .line 199
    goto :goto_9

    .line 200
    :cond_d
    const/4 v5, 0x0

    .line 201
    :goto_9
    or-int/2addr v5, v6

    .line 202
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 203
    .line 204
    .line 205
    move-result-object v6

    .line 206
    if-nez v5, :cond_e

    .line 207
    .line 208
    sget-object v5, Ll2/n;->a:Ll2/x0;

    .line 209
    .line 210
    if-ne v6, v5, :cond_f

    .line 211
    .line 212
    :cond_e
    new-instance v6, Ll61/d;

    .line 213
    .line 214
    invoke-direct {v6, v0, v1, v2}, Ll61/d;-><init>(FZZ)V

    .line 215
    .line 216
    .line 217
    invoke-virtual {v4, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 218
    .line 219
    .line 220
    :cond_f
    check-cast v6, Lay0/k;

    .line 221
    .line 222
    const/4 v5, 0x0

    .line 223
    invoke-static {v7, v6, v4, v5}, Lkp/i;->a(Lx2/s;Lay0/k;Ll2/o;I)V

    .line 224
    .line 225
    .line 226
    const/4 v5, 0x1

    .line 227
    invoke-virtual {v4, v5}, Ll2/t;->q(Z)V

    .line 228
    .line 229
    .line 230
    goto :goto_a

    .line 231
    :cond_10
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 232
    .line 233
    .line 234
    :goto_a
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 235
    .line 236
    .line 237
    move-result-object v4

    .line 238
    if-eqz v4, :cond_11

    .line 239
    .line 240
    new-instance v5, Ll61/e;

    .line 241
    .line 242
    invoke-direct {v5, v0, v1, v2, v3}, Ll61/e;-><init>(FZZI)V

    .line 243
    .line 244
    .line 245
    iput-object v5, v4, Ll2/u1;->d:Lay0/n;

    .line 246
    .line 247
    :cond_11
    return-void
.end method

.method public static final f(Ls71/k;FLl2/o;I)V
    .locals 4

    .line 1
    check-cast p2, Ll2/t;

    .line 2
    .line 3
    const v0, -0x630a9174

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    if-nez p0, :cond_0

    .line 10
    .line 11
    const/4 v0, -0x1

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    :goto_0
    invoke-virtual {p2, v0}, Ll2/t;->e(I)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-eqz v0, :cond_1

    .line 22
    .line 23
    const/4 v0, 0x4

    .line 24
    goto :goto_1

    .line 25
    :cond_1
    const/4 v0, 0x2

    .line 26
    :goto_1
    or-int/2addr v0, p3

    .line 27
    invoke-virtual {p2, p1}, Ll2/t;->d(F)Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    if-eqz v1, :cond_2

    .line 32
    .line 33
    const/16 v1, 0x20

    .line 34
    .line 35
    goto :goto_2

    .line 36
    :cond_2
    const/16 v1, 0x10

    .line 37
    .line 38
    :goto_2
    or-int/2addr v0, v1

    .line 39
    and-int/lit8 v1, v0, 0x13

    .line 40
    .line 41
    const/16 v2, 0x12

    .line 42
    .line 43
    const/4 v3, 0x0

    .line 44
    if-eq v1, v2, :cond_3

    .line 45
    .line 46
    const/4 v1, 0x1

    .line 47
    goto :goto_3

    .line 48
    :cond_3
    move v1, v3

    .line 49
    :goto_3
    and-int/lit8 v2, v0, 0x1

    .line 50
    .line 51
    invoke-virtual {p2, v2, v1}, Ll2/t;->O(IZ)Z

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    if-eqz v1, :cond_5

    .line 56
    .line 57
    if-nez p0, :cond_4

    .line 58
    .line 59
    const v0, 0x752dfc7a

    .line 60
    .line 61
    .line 62
    invoke-virtual {p2, v0}, Ll2/t;->Y(I)V

    .line 63
    .line 64
    .line 65
    :goto_4
    invoke-virtual {p2, v3}, Ll2/t;->q(Z)V

    .line 66
    .line 67
    .line 68
    goto :goto_5

    .line 69
    :cond_4
    const v1, 0x752dfc7b

    .line 70
    .line 71
    .line 72
    invoke-virtual {p2, v1}, Ll2/t;->Y(I)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 76
    .line 77
    .line 78
    move-result v1

    .line 79
    packed-switch v1, :pswitch_data_0

    .line 80
    .line 81
    .line 82
    const p0, -0x65c41f2b

    .line 83
    .line 84
    .line 85
    invoke-static {p0, p2, v3}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    throw p0

    .line 90
    :pswitch_0
    const v1, -0x52b3eb97

    .line 91
    .line 92
    .line 93
    invoke-virtual {p2, v1}, Ll2/t;->Y(I)V

    .line 94
    .line 95
    .line 96
    shr-int/lit8 v0, v0, 0x3

    .line 97
    .line 98
    and-int/lit8 v0, v0, 0xe

    .line 99
    .line 100
    invoke-static {p1, v0, p2}, Llp/bf;->d(FILl2/o;)V

    .line 101
    .line 102
    .line 103
    invoke-virtual {p2, v3}, Ll2/t;->q(Z)V

    .line 104
    .line 105
    .line 106
    goto :goto_4

    .line 107
    :pswitch_1
    const v1, -0x52b638b6

    .line 108
    .line 109
    .line 110
    invoke-virtual {p2, v1}, Ll2/t;->Y(I)V

    .line 111
    .line 112
    .line 113
    shr-int/lit8 v0, v0, 0x3

    .line 114
    .line 115
    and-int/lit8 v0, v0, 0xe

    .line 116
    .line 117
    invoke-static {p1, v0, p2}, Llp/bf;->c(FILl2/o;)V

    .line 118
    .line 119
    .line 120
    invoke-virtual {p2, v3}, Ll2/t;->q(Z)V

    .line 121
    .line 122
    .line 123
    goto :goto_4

    .line 124
    :pswitch_2
    const v1, -0x52bd0439

    .line 125
    .line 126
    .line 127
    invoke-virtual {p2, v1}, Ll2/t;->Y(I)V

    .line 128
    .line 129
    .line 130
    shr-int/lit8 v0, v0, 0x3

    .line 131
    .line 132
    and-int/lit8 v0, v0, 0xe

    .line 133
    .line 134
    invoke-static {p1, v0, p2}, Llp/bf;->b(FILl2/o;)V

    .line 135
    .line 136
    .line 137
    invoke-virtual {p2, v3}, Ll2/t;->q(Z)V

    .line 138
    .line 139
    .line 140
    goto :goto_4

    .line 141
    :pswitch_3
    const v1, -0x52b8949b

    .line 142
    .line 143
    .line 144
    invoke-virtual {p2, v1}, Ll2/t;->Y(I)V

    .line 145
    .line 146
    .line 147
    shr-int/lit8 v0, v0, 0x3

    .line 148
    .line 149
    and-int/lit8 v0, v0, 0xe

    .line 150
    .line 151
    invoke-static {p1, v0, p2}, Llp/bf;->a(FILl2/o;)V

    .line 152
    .line 153
    .line 154
    invoke-virtual {p2, v3}, Ll2/t;->q(Z)V

    .line 155
    .line 156
    .line 157
    goto :goto_4

    .line 158
    :pswitch_4
    const v0, -0x52b0fbb8

    .line 159
    .line 160
    .line 161
    invoke-virtual {p2, v0}, Ll2/t;->Y(I)V

    .line 162
    .line 163
    .line 164
    invoke-virtual {p2, v3}, Ll2/t;->q(Z)V

    .line 165
    .line 166
    .line 167
    goto :goto_4

    .line 168
    :cond_5
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 169
    .line 170
    .line 171
    :goto_5
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 172
    .line 173
    .line 174
    move-result-object p2

    .line 175
    if-eqz p2, :cond_6

    .line 176
    .line 177
    new-instance v0, Lh2/x;

    .line 178
    .line 179
    const/4 v1, 0x2

    .line 180
    invoke-direct {v0, p0, p1, p3, v1}, Lh2/x;-><init>(Ljava/lang/Object;FII)V

    .line 181
    .line 182
    .line 183
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 184
    .line 185
    :cond_6
    return-void

    .line 186
    nop

    .line 187
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
        :pswitch_3
        :pswitch_3
        :pswitch_2
        :pswitch_2
        :pswitch_4
    .end packed-switch
.end method

.method public static final g(Landroidx/lifecycle/r;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Lxl/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lxl/a;

    .line 7
    .line 8
    iget v1, v0, Lxl/a;->g:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lxl/a;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lxl/a;

    .line 21
    .line 22
    invoke-direct {v0, p1}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lxl/a;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lxl/a;->g:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x1

    .line 34
    if-eqz v2, :cond_2

    .line 35
    .line 36
    if-ne v2, v4, :cond_1

    .line 37
    .line 38
    iget-object p0, v0, Lxl/a;->e:Lkotlin/jvm/internal/f0;

    .line 39
    .line 40
    iget-object v0, v0, Lxl/a;->d:Landroidx/lifecycle/r;

    .line 41
    .line 42
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 43
    .line 44
    .line 45
    goto :goto_1

    .line 46
    :catchall_0
    move-exception p1

    .line 47
    goto :goto_2

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {p0}, Landroidx/lifecycle/r;->b()Landroidx/lifecycle/q;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    sget-object v2, Landroidx/lifecycle/q;->g:Landroidx/lifecycle/q;

    .line 64
    .line 65
    invoke-virtual {p1, v2}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 66
    .line 67
    .line 68
    move-result p1

    .line 69
    if-ltz p1, :cond_3

    .line 70
    .line 71
    return-object v3

    .line 72
    :cond_3
    new-instance p1, Lkotlin/jvm/internal/f0;

    .line 73
    .line 74
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 75
    .line 76
    .line 77
    :try_start_1
    iput-object p0, v0, Lxl/a;->d:Landroidx/lifecycle/r;

    .line 78
    .line 79
    iput-object p1, v0, Lxl/a;->e:Lkotlin/jvm/internal/f0;

    .line 80
    .line 81
    iput v4, v0, Lxl/a;->g:I

    .line 82
    .line 83
    new-instance v2, Lvy0/l;

    .line 84
    .line 85
    invoke-static {v0}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    invoke-direct {v2, v4, v0}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {v2}, Lvy0/l;->q()V

    .line 93
    .line 94
    .line 95
    new-instance v0, Lsm/d;

    .line 96
    .line 97
    const/4 v4, 0x1

    .line 98
    invoke-direct {v0, v2, v4}, Lsm/d;-><init>(Lvy0/l;I)V

    .line 99
    .line 100
    .line 101
    iput-object v0, p1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 102
    .line 103
    invoke-virtual {p0, v0}, Landroidx/lifecycle/r;->a(Landroidx/lifecycle/w;)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {v2}, Lvy0/l;->p()Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 110
    if-ne v0, v1, :cond_4

    .line 111
    .line 112
    return-object v1

    .line 113
    :cond_4
    move-object v0, p0

    .line 114
    move-object p0, p1

    .line 115
    :goto_1
    iget-object p0, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 116
    .line 117
    check-cast p0, Landroidx/lifecycle/w;

    .line 118
    .line 119
    if-eqz p0, :cond_5

    .line 120
    .line 121
    invoke-virtual {v0, p0}, Landroidx/lifecycle/r;->d(Landroidx/lifecycle/w;)V

    .line 122
    .line 123
    .line 124
    :cond_5
    return-object v3

    .line 125
    :catchall_1
    move-exception v0

    .line 126
    move-object v5, v0

    .line 127
    move-object v0, p0

    .line 128
    move-object p0, p1

    .line 129
    move-object p1, v5

    .line 130
    :goto_2
    iget-object p0, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 131
    .line 132
    check-cast p0, Landroidx/lifecycle/w;

    .line 133
    .line 134
    if-eqz p0, :cond_6

    .line 135
    .line 136
    invoke-virtual {v0, p0}, Landroidx/lifecycle/r;->d(Landroidx/lifecycle/w;)V

    .line 137
    .line 138
    .line 139
    :cond_6
    throw p1
.end method

.method public static final h(Lg3/d;F)Le3/i;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    sget v1, Ln61/c;->b:F

    .line 4
    .line 5
    invoke-interface {v0, v1}, Lt4/c;->w0(F)F

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    invoke-interface {v0}, Lg3/d;->e()J

    .line 10
    .line 11
    .line 12
    move-result-wide v2

    .line 13
    const/16 v4, 0x20

    .line 14
    .line 15
    shr-long/2addr v2, v4

    .line 16
    long-to-int v2, v2

    .line 17
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    const/4 v3, 0x3

    .line 22
    int-to-float v3, v3

    .line 23
    div-float/2addr v2, v3

    .line 24
    sub-float/2addr v2, v1

    .line 25
    invoke-interface {v0}, Lg3/d;->e()J

    .line 26
    .line 27
    .line 28
    move-result-wide v5

    .line 29
    const-wide v7, 0xffffffffL

    .line 30
    .line 31
    .line 32
    .line 33
    .line 34
    and-long/2addr v5, v7

    .line 35
    long-to-int v5, v5

    .line 36
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 37
    .line 38
    .line 39
    move-result v5

    .line 40
    const/4 v6, 0x2

    .line 41
    int-to-float v6, v6

    .line 42
    div-float/2addr v5, v6

    .line 43
    div-float v9, p1, v6

    .line 44
    .line 45
    invoke-interface {v0, v9}, Lt4/c;->w0(F)F

    .line 46
    .line 47
    .line 48
    move-result v9

    .line 49
    sub-float/2addr v5, v9

    .line 50
    invoke-interface {v0}, Lg3/d;->e()J

    .line 51
    .line 52
    .line 53
    move-result-wide v9

    .line 54
    shr-long/2addr v9, v4

    .line 55
    long-to-int v9, v9

    .line 56
    invoke-static {v9}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 57
    .line 58
    .line 59
    move-result v9

    .line 60
    div-float/2addr v9, v3

    .line 61
    mul-float/2addr v6, v1

    .line 62
    sub-float/2addr v9, v6

    .line 63
    invoke-interface/range {p0 .. p1}, Lt4/c;->w0(F)F

    .line 64
    .line 65
    .line 66
    move-result v3

    .line 67
    sub-float/2addr v3, v6

    .line 68
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 69
    .line 70
    .line 71
    move-result-object v6

    .line 72
    const/4 v10, 0x0

    .line 73
    invoke-virtual {v6, v10, v5}, Le3/i;->h(FF)V

    .line 74
    .line 75
    .line 76
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 77
    .line 78
    .line 79
    move-result v10

    .line 80
    int-to-long v10, v10

    .line 81
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 82
    .line 83
    .line 84
    move-result v12

    .line 85
    int-to-long v12, v12

    .line 86
    shl-long/2addr v10, v4

    .line 87
    and-long/2addr v12, v7

    .line 88
    or-long/2addr v10, v12

    .line 89
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 90
    .line 91
    .line 92
    move-result v12

    .line 93
    int-to-long v12, v12

    .line 94
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 95
    .line 96
    .line 97
    move-result v14

    .line 98
    int-to-long v14, v14

    .line 99
    shl-long/2addr v12, v4

    .line 100
    and-long/2addr v14, v7

    .line 101
    or-long/2addr v12, v14

    .line 102
    invoke-static {v10, v11, v12, v13}, Ljp/cf;->c(JJ)Ld3/c;

    .line 103
    .line 104
    .line 105
    move-result-object v10

    .line 106
    const/high16 v11, 0x43870000    # 270.0f

    .line 107
    .line 108
    const/high16 v12, 0x42b40000    # 90.0f

    .line 109
    .line 110
    invoke-virtual {v6, v10, v11, v12}, Le3/i;->d(Ld3/c;FF)V

    .line 111
    .line 112
    .line 113
    add-float/2addr v2, v1

    .line 114
    add-float v10, v5, v1

    .line 115
    .line 116
    add-float/2addr v10, v3

    .line 117
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 118
    .line 119
    .line 120
    move-result v3

    .line 121
    int-to-long v13, v3

    .line 122
    invoke-static {v10}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 123
    .line 124
    .line 125
    move-result v3

    .line 126
    move-wide v15, v7

    .line 127
    int-to-long v7, v3

    .line 128
    shl-long/2addr v13, v4

    .line 129
    and-long/2addr v7, v15

    .line 130
    or-long/2addr v7, v13

    .line 131
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 132
    .line 133
    .line 134
    move-result v3

    .line 135
    int-to-long v13, v3

    .line 136
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 137
    .line 138
    .line 139
    move-result v3

    .line 140
    move v11, v4

    .line 141
    move/from16 v17, v5

    .line 142
    .line 143
    int-to-long v4, v3

    .line 144
    shl-long/2addr v13, v11

    .line 145
    and-long v3, v4, v15

    .line 146
    .line 147
    or-long/2addr v3, v13

    .line 148
    invoke-static {v7, v8, v3, v4}, Ljp/cf;->c(JJ)Ld3/c;

    .line 149
    .line 150
    .line 151
    move-result-object v3

    .line 152
    const/high16 v4, 0x43340000    # 180.0f

    .line 153
    .line 154
    const/high16 v5, -0x3d4c0000    # -90.0f

    .line 155
    .line 156
    invoke-virtual {v6, v3, v4, v5}, Le3/i;->d(Ld3/c;FF)V

    .line 157
    .line 158
    .line 159
    add-float/2addr v9, v1

    .line 160
    add-float/2addr v9, v2

    .line 161
    invoke-static {v9}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 162
    .line 163
    .line 164
    move-result v2

    .line 165
    int-to-long v2, v2

    .line 166
    invoke-static {v10}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 167
    .line 168
    .line 169
    move-result v4

    .line 170
    int-to-long v7, v4

    .line 171
    shl-long/2addr v2, v11

    .line 172
    and-long/2addr v7, v15

    .line 173
    or-long/2addr v2, v7

    .line 174
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 175
    .line 176
    .line 177
    move-result v4

    .line 178
    int-to-long v7, v4

    .line 179
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 180
    .line 181
    .line 182
    move-result v4

    .line 183
    int-to-long v13, v4

    .line 184
    shl-long/2addr v7, v11

    .line 185
    and-long/2addr v13, v15

    .line 186
    or-long/2addr v7, v13

    .line 187
    invoke-static {v2, v3, v7, v8}, Ljp/cf;->c(JJ)Ld3/c;

    .line 188
    .line 189
    .line 190
    move-result-object v2

    .line 191
    invoke-virtual {v6, v2, v12, v5}, Le3/i;->d(Ld3/c;FF)V

    .line 192
    .line 193
    .line 194
    add-float/2addr v9, v1

    .line 195
    invoke-static {v9}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 196
    .line 197
    .line 198
    move-result v2

    .line 199
    int-to-long v2, v2

    .line 200
    invoke-static/range {v17 .. v17}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 201
    .line 202
    .line 203
    move-result v4

    .line 204
    int-to-long v4, v4

    .line 205
    shl-long/2addr v2, v11

    .line 206
    and-long/2addr v4, v15

    .line 207
    or-long/2addr v2, v4

    .line 208
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 209
    .line 210
    .line 211
    move-result v4

    .line 212
    int-to-long v4, v4

    .line 213
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 214
    .line 215
    .line 216
    move-result v1

    .line 217
    int-to-long v7, v1

    .line 218
    shl-long/2addr v4, v11

    .line 219
    and-long/2addr v7, v15

    .line 220
    or-long/2addr v4, v7

    .line 221
    invoke-static {v2, v3, v4, v5}, Ljp/cf;->c(JJ)Ld3/c;

    .line 222
    .line 223
    .line 224
    move-result-object v1

    .line 225
    const/high16 v2, -0x3ccc0000    # -180.0f

    .line 226
    .line 227
    invoke-virtual {v6, v1, v2, v12}, Le3/i;->d(Ld3/c;FF)V

    .line 228
    .line 229
    .line 230
    invoke-interface {v0}, Lg3/d;->e()J

    .line 231
    .line 232
    .line 233
    move-result-wide v0

    .line 234
    shr-long/2addr v0, v11

    .line 235
    long-to-int v0, v0

    .line 236
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 237
    .line 238
    .line 239
    move-result v0

    .line 240
    move/from16 v5, v17

    .line 241
    .line 242
    invoke-virtual {v6, v0, v5}, Le3/i;->g(FF)V

    .line 243
    .line 244
    .line 245
    return-object v6
.end method

.method public static final i(Lg3/d;F)Le3/i;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    sget v1, Ln61/c;->b:F

    .line 4
    .line 5
    invoke-interface {v0, v1}, Lt4/c;->w0(F)F

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    invoke-interface {v0}, Lg3/d;->e()J

    .line 10
    .line 11
    .line 12
    move-result-wide v2

    .line 13
    const/16 v4, 0x20

    .line 14
    .line 15
    shr-long/2addr v2, v4

    .line 16
    long-to-int v2, v2

    .line 17
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    const/4 v3, 0x3

    .line 22
    int-to-float v3, v3

    .line 23
    div-float/2addr v2, v3

    .line 24
    invoke-interface {v0}, Lg3/d;->e()J

    .line 25
    .line 26
    .line 27
    move-result-wide v5

    .line 28
    const-wide v7, 0xffffffffL

    .line 29
    .line 30
    .line 31
    .line 32
    .line 33
    and-long/2addr v5, v7

    .line 34
    long-to-int v5, v5

    .line 35
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 36
    .line 37
    .line 38
    move-result v5

    .line 39
    const/4 v6, 0x2

    .line 40
    int-to-float v6, v6

    .line 41
    div-float/2addr v5, v6

    .line 42
    div-float v9, p1, v6

    .line 43
    .line 44
    invoke-interface {v0, v9}, Lt4/c;->w0(F)F

    .line 45
    .line 46
    .line 47
    move-result v9

    .line 48
    sub-float/2addr v5, v9

    .line 49
    sub-float/2addr v5, v1

    .line 50
    invoke-interface {v0}, Lg3/d;->e()J

    .line 51
    .line 52
    .line 53
    move-result-wide v9

    .line 54
    shr-long/2addr v9, v4

    .line 55
    long-to-int v9, v9

    .line 56
    invoke-static {v9}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 57
    .line 58
    .line 59
    move-result v9

    .line 60
    div-float/2addr v9, v3

    .line 61
    mul-float/2addr v6, v1

    .line 62
    sub-float/2addr v9, v6

    .line 63
    invoke-interface/range {p0 .. p1}, Lt4/c;->w0(F)F

    .line 64
    .line 65
    .line 66
    move-result v3

    .line 67
    sub-float/2addr v3, v6

    .line 68
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 69
    .line 70
    .line 71
    move-result-object v6

    .line 72
    const/4 v10, 0x0

    .line 73
    invoke-virtual {v6, v2, v10}, Le3/i;->h(FF)V

    .line 74
    .line 75
    .line 76
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 77
    .line 78
    .line 79
    move-result v11

    .line 80
    int-to-long v11, v11

    .line 81
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 82
    .line 83
    .line 84
    move-result v13

    .line 85
    int-to-long v13, v13

    .line 86
    shl-long/2addr v11, v4

    .line 87
    and-long/2addr v13, v7

    .line 88
    or-long/2addr v11, v13

    .line 89
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 90
    .line 91
    .line 92
    move-result v13

    .line 93
    int-to-long v13, v13

    .line 94
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 95
    .line 96
    .line 97
    move-result v15

    .line 98
    move/from16 v16, v4

    .line 99
    .line 100
    move/from16 v17, v5

    .line 101
    .line 102
    int-to-long v4, v15

    .line 103
    shl-long v13, v13, v16

    .line 104
    .line 105
    and-long/2addr v4, v7

    .line 106
    or-long/2addr v4, v13

    .line 107
    invoke-static {v11, v12, v4, v5}, Ljp/cf;->c(JJ)Ld3/c;

    .line 108
    .line 109
    .line 110
    move-result-object v4

    .line 111
    const/high16 v5, 0x43340000    # 180.0f

    .line 112
    .line 113
    const/high16 v11, -0x3d4c0000    # -90.0f

    .line 114
    .line 115
    invoke-virtual {v6, v4, v5, v11}, Le3/i;->d(Ld3/c;FF)V

    .line 116
    .line 117
    .line 118
    add-float v4, v2, v1

    .line 119
    .line 120
    add-float/2addr v4, v9

    .line 121
    add-float v5, v17, v1

    .line 122
    .line 123
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 124
    .line 125
    .line 126
    move-result v9

    .line 127
    int-to-long v12, v9

    .line 128
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 129
    .line 130
    .line 131
    move-result v9

    .line 132
    int-to-long v14, v9

    .line 133
    shl-long v12, v12, v16

    .line 134
    .line 135
    and-long/2addr v14, v7

    .line 136
    or-long/2addr v12, v14

    .line 137
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 138
    .line 139
    .line 140
    move-result v9

    .line 141
    int-to-long v14, v9

    .line 142
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 143
    .line 144
    .line 145
    move-result v9

    .line 146
    move-wide/from16 v17, v7

    .line 147
    .line 148
    int-to-long v7, v9

    .line 149
    shl-long v14, v14, v16

    .line 150
    .line 151
    and-long v7, v7, v17

    .line 152
    .line 153
    or-long/2addr v7, v14

    .line 154
    invoke-static {v12, v13, v7, v8}, Ljp/cf;->c(JJ)Ld3/c;

    .line 155
    .line 156
    .line 157
    move-result-object v7

    .line 158
    const/high16 v8, 0x43870000    # 270.0f

    .line 159
    .line 160
    const/high16 v9, 0x42b40000    # 90.0f

    .line 161
    .line 162
    invoke-virtual {v6, v7, v8, v9}, Le3/i;->d(Ld3/c;FF)V

    .line 163
    .line 164
    .line 165
    add-float/2addr v3, v1

    .line 166
    add-float/2addr v3, v5

    .line 167
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 168
    .line 169
    .line 170
    move-result v4

    .line 171
    int-to-long v4, v4

    .line 172
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 173
    .line 174
    .line 175
    move-result v7

    .line 176
    int-to-long v12, v7

    .line 177
    shl-long v4, v4, v16

    .line 178
    .line 179
    and-long v12, v12, v17

    .line 180
    .line 181
    or-long/2addr v4, v12

    .line 182
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 183
    .line 184
    .line 185
    move-result v7

    .line 186
    int-to-long v12, v7

    .line 187
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 188
    .line 189
    .line 190
    move-result v7

    .line 191
    int-to-long v14, v7

    .line 192
    shl-long v12, v12, v16

    .line 193
    .line 194
    and-long v14, v14, v17

    .line 195
    .line 196
    or-long/2addr v12, v14

    .line 197
    invoke-static {v4, v5, v12, v13}, Ljp/cf;->c(JJ)Ld3/c;

    .line 198
    .line 199
    .line 200
    move-result-object v4

    .line 201
    invoke-virtual {v6, v4, v10, v9}, Le3/i;->d(Ld3/c;FF)V

    .line 202
    .line 203
    .line 204
    add-float/2addr v3, v1

    .line 205
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 206
    .line 207
    .line 208
    move-result v4

    .line 209
    int-to-long v4, v4

    .line 210
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 211
    .line 212
    .line 213
    move-result v3

    .line 214
    int-to-long v9, v3

    .line 215
    shl-long v3, v4, v16

    .line 216
    .line 217
    and-long v9, v9, v17

    .line 218
    .line 219
    or-long/2addr v3, v9

    .line 220
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 221
    .line 222
    .line 223
    move-result v5

    .line 224
    int-to-long v9, v5

    .line 225
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 226
    .line 227
    .line 228
    move-result v1

    .line 229
    int-to-long v12, v1

    .line 230
    shl-long v9, v9, v16

    .line 231
    .line 232
    and-long v12, v12, v17

    .line 233
    .line 234
    or-long/2addr v9, v12

    .line 235
    invoke-static {v3, v4, v9, v10}, Ljp/cf;->c(JJ)Ld3/c;

    .line 236
    .line 237
    .line 238
    move-result-object v1

    .line 239
    invoke-virtual {v6, v1, v8, v11}, Le3/i;->d(Ld3/c;FF)V

    .line 240
    .line 241
    .line 242
    invoke-interface {v0}, Lg3/d;->e()J

    .line 243
    .line 244
    .line 245
    move-result-wide v0

    .line 246
    and-long v0, v0, v17

    .line 247
    .line 248
    long-to-int v0, v0

    .line 249
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 250
    .line 251
    .line 252
    move-result v0

    .line 253
    invoke-virtual {v6, v2, v0}, Le3/i;->g(FF)V

    .line 254
    .line 255
    .line 256
    return-object v6
.end method
