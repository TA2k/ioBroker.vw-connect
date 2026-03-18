.class public abstract Llp/ag;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ly6/s;Ly6/q;ILy6/g;Ll2/o;II)V
    .locals 8

    .line 1
    move-object v0, p4

    .line 2
    check-cast v0, Ll2/t;

    .line 3
    .line 4
    const v1, 0x1d5027f3

    .line 5
    .line 6
    .line 7
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    and-int/lit8 v1, p5, 0x6

    .line 11
    .line 12
    if-nez v1, :cond_1

    .line 13
    .line 14
    and-int/lit8 v1, p5, 0x8

    .line 15
    .line 16
    invoke-virtual {v0, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-eqz v1, :cond_0

    .line 21
    .line 22
    const/4 v1, 0x4

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    const/4 v1, 0x2

    .line 25
    :goto_0
    or-int/2addr v1, p5

    .line 26
    goto :goto_1

    .line 27
    :cond_1
    move v1, p5

    .line 28
    :goto_1
    and-int/lit8 v2, p5, 0x30

    .line 29
    .line 30
    const/4 v3, 0x0

    .line 31
    if-nez v2, :cond_3

    .line 32
    .line 33
    invoke-virtual {v0, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    if-eqz v2, :cond_2

    .line 38
    .line 39
    const/16 v2, 0x20

    .line 40
    .line 41
    goto :goto_2

    .line 42
    :cond_2
    const/16 v2, 0x10

    .line 43
    .line 44
    :goto_2
    or-int/2addr v1, v2

    .line 45
    :cond_3
    and-int/lit8 v2, p6, 0x4

    .line 46
    .line 47
    if-eqz v2, :cond_4

    .line 48
    .line 49
    or-int/lit16 v1, v1, 0x180

    .line 50
    .line 51
    goto :goto_4

    .line 52
    :cond_4
    and-int/lit16 v4, p5, 0x180

    .line 53
    .line 54
    if-nez v4, :cond_6

    .line 55
    .line 56
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v4

    .line 60
    if-eqz v4, :cond_5

    .line 61
    .line 62
    const/16 v4, 0x100

    .line 63
    .line 64
    goto :goto_3

    .line 65
    :cond_5
    const/16 v4, 0x80

    .line 66
    .line 67
    :goto_3
    or-int/2addr v1, v4

    .line 68
    :cond_6
    :goto_4
    and-int/lit8 v4, p6, 0x8

    .line 69
    .line 70
    if-eqz v4, :cond_7

    .line 71
    .line 72
    or-int/lit16 v1, v1, 0xc00

    .line 73
    .line 74
    goto :goto_6

    .line 75
    :cond_7
    and-int/lit16 v6, p5, 0xc00

    .line 76
    .line 77
    if-nez v6, :cond_9

    .line 78
    .line 79
    invoke-virtual {v0, p2}, Ll2/t;->e(I)Z

    .line 80
    .line 81
    .line 82
    move-result v6

    .line 83
    if-eqz v6, :cond_8

    .line 84
    .line 85
    const/16 v6, 0x800

    .line 86
    .line 87
    goto :goto_5

    .line 88
    :cond_8
    const/16 v6, 0x400

    .line 89
    .line 90
    :goto_5
    or-int/2addr v1, v6

    .line 91
    :cond_9
    :goto_6
    and-int/lit8 v6, p6, 0x10

    .line 92
    .line 93
    if-eqz v6, :cond_a

    .line 94
    .line 95
    or-int/lit16 v1, v1, 0x6000

    .line 96
    .line 97
    goto :goto_8

    .line 98
    :cond_a
    and-int/lit16 v7, p5, 0x6000

    .line 99
    .line 100
    if-nez v7, :cond_c

    .line 101
    .line 102
    const v7, 0x8000

    .line 103
    .line 104
    .line 105
    and-int/2addr v7, p5

    .line 106
    invoke-virtual {v0, p3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 107
    .line 108
    .line 109
    move-result v7

    .line 110
    if-eqz v7, :cond_b

    .line 111
    .line 112
    const/16 v7, 0x4000

    .line 113
    .line 114
    goto :goto_7

    .line 115
    :cond_b
    const/16 v7, 0x2000

    .line 116
    .line 117
    :goto_7
    or-int/2addr v1, v7

    .line 118
    :cond_c
    :goto_8
    and-int/lit16 v1, v1, 0x2493

    .line 119
    .line 120
    const/16 v7, 0x2492

    .line 121
    .line 122
    if-ne v1, v7, :cond_e

    .line 123
    .line 124
    invoke-virtual {v0}, Ll2/t;->A()Z

    .line 125
    .line 126
    .line 127
    move-result v1

    .line 128
    if-nez v1, :cond_d

    .line 129
    .line 130
    goto :goto_a

    .line 131
    :cond_d
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 132
    .line 133
    .line 134
    :goto_9
    move-object v2, p1

    .line 135
    move v3, p2

    .line 136
    move-object v4, p3

    .line 137
    goto :goto_c

    .line 138
    :cond_e
    :goto_a
    if-eqz v2, :cond_f

    .line 139
    .line 140
    sget-object p1, Ly6/o;->a:Ly6/o;

    .line 141
    .line 142
    :cond_f
    const/4 v1, 0x1

    .line 143
    if-eqz v4, :cond_10

    .line 144
    .line 145
    move p2, v1

    .line 146
    :cond_10
    if-eqz v6, :cond_11

    .line 147
    .line 148
    move-object p3, v3

    .line 149
    :cond_11
    const v2, 0x81591ab

    .line 150
    .line 151
    .line 152
    invoke-virtual {v0, v2}, Ll2/t;->Z(I)V

    .line 153
    .line 154
    .line 155
    const/4 v2, 0x0

    .line 156
    invoke-virtual {v0, v2}, Ll2/t;->q(Z)V

    .line 157
    .line 158
    .line 159
    sget-object v4, Ly6/r;->d:Ly6/r;

    .line 160
    .line 161
    const v6, -0x428332f6

    .line 162
    .line 163
    .line 164
    invoke-virtual {v0, v6}, Ll2/t;->Z(I)V

    .line 165
    .line 166
    .line 167
    const v6, 0x7076b8d0

    .line 168
    .line 169
    .line 170
    invoke-virtual {v0, v6}, Ll2/t;->Z(I)V

    .line 171
    .line 172
    .line 173
    iget-object v6, v0, Ll2/t;->a:Leb/j0;

    .line 174
    .line 175
    instance-of v6, v6, Ly6/b;

    .line 176
    .line 177
    if-eqz v6, :cond_14

    .line 178
    .line 179
    invoke-virtual {v0}, Ll2/t;->W()V

    .line 180
    .line 181
    .line 182
    iget-boolean v3, v0, Ll2/t;->S:Z

    .line 183
    .line 184
    if-eqz v3, :cond_12

    .line 185
    .line 186
    new-instance v3, La7/j;

    .line 187
    .line 188
    invoke-direct {v3, v4}, La7/j;-><init>(Lay0/a;)V

    .line 189
    .line 190
    .line 191
    invoke-virtual {v0, v3}, Ll2/t;->l(Lay0/a;)V

    .line 192
    .line 193
    .line 194
    goto :goto_b

    .line 195
    :cond_12
    invoke-virtual {v0}, Ll2/t;->m0()V

    .line 196
    .line 197
    .line 198
    :goto_b
    sget-object v3, Ly6/h;->h:Ly6/h;

    .line 199
    .line 200
    invoke-static {v3, p0, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 201
    .line 202
    .line 203
    sget-object v3, Ly6/h;->i:Ly6/h;

    .line 204
    .line 205
    invoke-static {v3, p1, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 206
    .line 207
    .line 208
    new-instance v3, Lf7/j;

    .line 209
    .line 210
    invoke-direct {v3, p2}, Lf7/j;-><init>(I)V

    .line 211
    .line 212
    .line 213
    sget-object v4, Ly6/h;->j:Ly6/h;

    .line 214
    .line 215
    invoke-static {v4, v3, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 216
    .line 217
    .line 218
    sget-object v3, Ly6/h;->k:Ly6/h;

    .line 219
    .line 220
    invoke-static {v3, p3, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 221
    .line 222
    .line 223
    invoke-virtual {v0, v1}, Ll2/t;->q(Z)V

    .line 224
    .line 225
    .line 226
    invoke-virtual {v0, v2}, Ll2/t;->q(Z)V

    .line 227
    .line 228
    .line 229
    invoke-virtual {v0, v2}, Ll2/t;->q(Z)V

    .line 230
    .line 231
    .line 232
    goto :goto_9

    .line 233
    :goto_c
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 234
    .line 235
    .line 236
    move-result-object p1

    .line 237
    if-eqz p1, :cond_13

    .line 238
    .line 239
    new-instance v0, Lj7/f;

    .line 240
    .line 241
    move-object v1, p0

    .line 242
    move v5, p5

    .line 243
    move v6, p6

    .line 244
    invoke-direct/range {v0 .. v6}, Lj7/f;-><init>(Ly6/s;Ly6/q;ILy6/g;II)V

    .line 245
    .line 246
    .line 247
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 248
    .line 249
    :cond_13
    return-void

    .line 250
    :cond_14
    invoke-static {}, Ll2/b;->l()V

    .line 251
    .line 252
    .line 253
    throw v3
.end method

.method public static final b(Ly6/m;)Z
    .locals 2

    .line 1
    iget-object p0, p0, Ly6/m;->a:Ly6/q;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    sget-object v1, Ly6/h;->l:Ly6/h;

    .line 5
    .line 6
    invoke-interface {p0, v0, v1}, Ly6/q;->a(Ljava/lang/Object;Lay0/n;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    check-cast p0, Lg7/a;

    .line 11
    .line 12
    const/4 p0, 0x1

    .line 13
    return p0
.end method

.method public static c(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;[I[Ljava/lang/Object;[Ljava/lang/Object;)I
    .locals 8

    .line 1
    invoke-static {p0}, Llp/bg;->b(Ljava/lang/Object;)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    and-int v1, v0, p2

    .line 6
    .line 7
    invoke-static {v1, p3}, Llp/ag;->d(ILjava/lang/Object;)I

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    const/4 v3, -0x1

    .line 12
    if-eqz v2, :cond_3

    .line 13
    .line 14
    not-int v4, p2

    .line 15
    and-int/2addr v0, v4

    .line 16
    move v5, v3

    .line 17
    :goto_0
    add-int/2addr v2, v3

    .line 18
    aget v6, p4, v2

    .line 19
    .line 20
    and-int v7, v6, p2

    .line 21
    .line 22
    and-int/2addr v6, v4

    .line 23
    if-ne v6, v0, :cond_2

    .line 24
    .line 25
    aget-object v6, p5, v2

    .line 26
    .line 27
    invoke-static {p0, v6}, Llp/fg;->c(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v6

    .line 31
    if-eqz v6, :cond_2

    .line 32
    .line 33
    if-eqz p6, :cond_0

    .line 34
    .line 35
    aget-object v6, p6, v2

    .line 36
    .line 37
    invoke-static {p1, v6}, Llp/fg;->c(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v6

    .line 41
    if-eqz v6, :cond_2

    .line 42
    .line 43
    :cond_0
    if-ne v5, v3, :cond_1

    .line 44
    .line 45
    invoke-static {v1, p3, v7}, Llp/ag;->f(ILjava/lang/Object;I)V

    .line 46
    .line 47
    .line 48
    return v2

    .line 49
    :cond_1
    aget p0, p4, v5

    .line 50
    .line 51
    and-int/2addr p0, v4

    .line 52
    and-int p1, v7, p2

    .line 53
    .line 54
    or-int/2addr p0, p1

    .line 55
    aput p0, p4, v5

    .line 56
    .line 57
    return v2

    .line 58
    :cond_2
    if-eqz v7, :cond_3

    .line 59
    .line 60
    move v5, v2

    .line 61
    move v2, v7

    .line 62
    goto :goto_0

    .line 63
    :cond_3
    return v3
.end method

.method public static d(ILjava/lang/Object;)I
    .locals 1

    .line 1
    instance-of v0, p1, [B

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, [B

    .line 6
    .line 7
    aget-byte p0, p1, p0

    .line 8
    .line 9
    and-int/lit16 p0, p0, 0xff

    .line 10
    .line 11
    return p0

    .line 12
    :cond_0
    instance-of v0, p1, [S

    .line 13
    .line 14
    if-eqz v0, :cond_1

    .line 15
    .line 16
    check-cast p1, [S

    .line 17
    .line 18
    aget-short p0, p1, p0

    .line 19
    .line 20
    int-to-char p0, p0

    .line 21
    return p0

    .line 22
    :cond_1
    check-cast p1, [I

    .line 23
    .line 24
    aget p0, p1, p0

    .line 25
    .line 26
    return p0
.end method

.method public static e(I)Ljava/lang/Object;
    .locals 2

    .line 1
    const/4 v0, 0x2

    .line 2
    if-lt p0, v0, :cond_2

    .line 3
    .line 4
    const/high16 v0, 0x40000000    # 2.0f

    .line 5
    .line 6
    if-gt p0, v0, :cond_2

    .line 7
    .line 8
    invoke-static {p0}, Ljava/lang/Integer;->highestOneBit(I)I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-ne v0, p0, :cond_2

    .line 13
    .line 14
    const/16 v0, 0x100

    .line 15
    .line 16
    if-gt p0, v0, :cond_0

    .line 17
    .line 18
    new-array p0, p0, [B

    .line 19
    .line 20
    return-object p0

    .line 21
    :cond_0
    const/high16 v0, 0x10000

    .line 22
    .line 23
    if-gt p0, v0, :cond_1

    .line 24
    .line 25
    new-array p0, p0, [S

    .line 26
    .line 27
    return-object p0

    .line 28
    :cond_1
    new-array p0, p0, [I

    .line 29
    .line 30
    return-object p0

    .line 31
    :cond_2
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 32
    .line 33
    const-string v1, "must be power of 2 between 2^1 and 2^30: "

    .line 34
    .line 35
    invoke-static {p0, v1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw v0
.end method

.method public static f(ILjava/lang/Object;I)V
    .locals 1

    .line 1
    instance-of v0, p1, [B

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, [B

    .line 6
    .line 7
    int-to-byte p2, p2

    .line 8
    aput-byte p2, p1, p0

    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    instance-of v0, p1, [S

    .line 12
    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    check-cast p1, [S

    .line 16
    .line 17
    int-to-short p2, p2

    .line 18
    aput-short p2, p1, p0

    .line 19
    .line 20
    return-void

    .line 21
    :cond_1
    check-cast p1, [I

    .line 22
    .line 23
    aput p2, p1, p0

    .line 24
    .line 25
    return-void
.end method
