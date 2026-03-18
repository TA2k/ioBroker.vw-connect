.class public final Lk1/k;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/y;


# instance fields
.field public r:F

.field public s:Z


# virtual methods
.method public final D(Lv3/p0;Lt3/p0;I)I
    .locals 0

    .line 1
    const p1, 0x7fffffff

    .line 2
    .line 3
    .line 4
    if-eq p3, p1, :cond_0

    .line 5
    .line 6
    int-to-float p1, p3

    .line 7
    iget p0, p0, Lk1/k;->r:F

    .line 8
    .line 9
    div-float/2addr p1, p0

    .line 10
    invoke-static {p1}, Ljava/lang/Math;->round(F)I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0

    .line 15
    :cond_0
    invoke-interface {p2, p3}, Lt3/p0;->A(I)I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public final F0(Lv3/p0;Lt3/p0;I)I
    .locals 0

    .line 1
    const p1, 0x7fffffff

    .line 2
    .line 3
    .line 4
    if-eq p3, p1, :cond_0

    .line 5
    .line 6
    int-to-float p1, p3

    .line 7
    iget p0, p0, Lk1/k;->r:F

    .line 8
    .line 9
    mul-float/2addr p1, p0

    .line 10
    invoke-static {p1}, Ljava/lang/Math;->round(F)I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0

    .line 15
    :cond_0
    invoke-interface {p2, p3}, Lt3/p0;->J(I)I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public final J(Lv3/p0;Lt3/p0;I)I
    .locals 0

    .line 1
    const p1, 0x7fffffff

    .line 2
    .line 3
    .line 4
    if-eq p3, p1, :cond_0

    .line 5
    .line 6
    int-to-float p1, p3

    .line 7
    iget p0, p0, Lk1/k;->r:F

    .line 8
    .line 9
    div-float/2addr p1, p0

    .line 10
    invoke-static {p1}, Ljava/lang/Math;->round(F)I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0

    .line 15
    :cond_0
    invoke-interface {p2, p3}, Lt3/p0;->c(I)I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public final X(Lv3/p0;Lt3/p0;I)I
    .locals 0

    .line 1
    const p1, 0x7fffffff

    .line 2
    .line 3
    .line 4
    if-eq p3, p1, :cond_0

    .line 5
    .line 6
    int-to-float p1, p3

    .line 7
    iget p0, p0, Lk1/k;->r:F

    .line 8
    .line 9
    mul-float/2addr p1, p0

    .line 10
    invoke-static {p1}, Ljava/lang/Math;->round(F)I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0

    .line 15
    :cond_0
    invoke-interface {p2, p3}, Lt3/p0;->G(I)I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public final X0(JZ)J
    .locals 2

    .line 1
    invoke-static {p1, p2}, Lt4/a;->g(J)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const v1, 0x7fffffff

    .line 6
    .line 7
    .line 8
    if-eq v0, v1, :cond_1

    .line 9
    .line 10
    int-to-float v1, v0

    .line 11
    iget p0, p0, Lk1/k;->r:F

    .line 12
    .line 13
    mul-float/2addr v1, p0

    .line 14
    invoke-static {v1}, Ljava/lang/Math;->round(F)I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    if-lez p0, :cond_1

    .line 19
    .line 20
    if-eqz p3, :cond_0

    .line 21
    .line 22
    invoke-static {p1, p2, p0, v0}, Landroidx/compose/foundation/layout/a;->h(JII)Z

    .line 23
    .line 24
    .line 25
    move-result p1

    .line 26
    if-eqz p1, :cond_1

    .line 27
    .line 28
    :cond_0
    int-to-long p0, p0

    .line 29
    const/16 p2, 0x20

    .line 30
    .line 31
    shl-long/2addr p0, p2

    .line 32
    int-to-long p2, v0

    .line 33
    const-wide v0, 0xffffffffL

    .line 34
    .line 35
    .line 36
    .line 37
    .line 38
    and-long/2addr p2, v0

    .line 39
    or-long/2addr p0, p2

    .line 40
    return-wide p0

    .line 41
    :cond_1
    const-wide/16 p0, 0x0

    .line 42
    .line 43
    return-wide p0
.end method

.method public final Y0(JZ)J
    .locals 4

    .line 1
    invoke-static {p1, p2}, Lt4/a;->h(J)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const v1, 0x7fffffff

    .line 6
    .line 7
    .line 8
    if-eq v0, v1, :cond_1

    .line 9
    .line 10
    int-to-float v1, v0

    .line 11
    iget p0, p0, Lk1/k;->r:F

    .line 12
    .line 13
    div-float/2addr v1, p0

    .line 14
    invoke-static {v1}, Ljava/lang/Math;->round(F)I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    if-lez p0, :cond_1

    .line 19
    .line 20
    if-eqz p3, :cond_0

    .line 21
    .line 22
    invoke-static {p1, p2, v0, p0}, Landroidx/compose/foundation/layout/a;->h(JII)Z

    .line 23
    .line 24
    .line 25
    move-result p1

    .line 26
    if-eqz p1, :cond_1

    .line 27
    .line 28
    :cond_0
    int-to-long p1, v0

    .line 29
    const/16 p3, 0x20

    .line 30
    .line 31
    shl-long/2addr p1, p3

    .line 32
    int-to-long v0, p0

    .line 33
    const-wide v2, 0xffffffffL

    .line 34
    .line 35
    .line 36
    .line 37
    .line 38
    and-long/2addr v0, v2

    .line 39
    or-long p0, p1, v0

    .line 40
    .line 41
    return-wide p0

    .line 42
    :cond_1
    const-wide/16 p0, 0x0

    .line 43
    .line 44
    return-wide p0
.end method

.method public final Z0(JZ)J
    .locals 2

    .line 1
    invoke-static {p1, p2}, Lt4/a;->i(J)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    int-to-float v1, v0

    .line 6
    iget p0, p0, Lk1/k;->r:F

    .line 7
    .line 8
    mul-float/2addr v1, p0

    .line 9
    invoke-static {v1}, Ljava/lang/Math;->round(F)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    if-lez p0, :cond_1

    .line 14
    .line 15
    if-eqz p3, :cond_0

    .line 16
    .line 17
    invoke-static {p1, p2, p0, v0}, Landroidx/compose/foundation/layout/a;->h(JII)Z

    .line 18
    .line 19
    .line 20
    move-result p1

    .line 21
    if-eqz p1, :cond_1

    .line 22
    .line 23
    :cond_0
    int-to-long p0, p0

    .line 24
    const/16 p2, 0x20

    .line 25
    .line 26
    shl-long/2addr p0, p2

    .line 27
    int-to-long p2, v0

    .line 28
    const-wide v0, 0xffffffffL

    .line 29
    .line 30
    .line 31
    .line 32
    .line 33
    and-long/2addr p2, v0

    .line 34
    or-long/2addr p0, p2

    .line 35
    return-wide p0

    .line 36
    :cond_1
    const-wide/16 p0, 0x0

    .line 37
    .line 38
    return-wide p0
.end method

.method public final a1(JZ)J
    .locals 4

    .line 1
    invoke-static {p1, p2}, Lt4/a;->j(J)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    int-to-float v1, v0

    .line 6
    iget p0, p0, Lk1/k;->r:F

    .line 7
    .line 8
    div-float/2addr v1, p0

    .line 9
    invoke-static {v1}, Ljava/lang/Math;->round(F)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    if-lez p0, :cond_1

    .line 14
    .line 15
    if-eqz p3, :cond_0

    .line 16
    .line 17
    invoke-static {p1, p2, v0, p0}, Landroidx/compose/foundation/layout/a;->h(JII)Z

    .line 18
    .line 19
    .line 20
    move-result p1

    .line 21
    if-eqz p1, :cond_1

    .line 22
    .line 23
    :cond_0
    int-to-long p1, v0

    .line 24
    const/16 p3, 0x20

    .line 25
    .line 26
    shl-long/2addr p1, p3

    .line 27
    int-to-long v0, p0

    .line 28
    const-wide v2, 0xffffffffL

    .line 29
    .line 30
    .line 31
    .line 32
    .line 33
    and-long/2addr v0, v2

    .line 34
    or-long p0, p1, v0

    .line 35
    .line 36
    return-wide p0

    .line 37
    :cond_1
    const-wide/16 p0, 0x0

    .line 38
    .line 39
    return-wide p0
.end method

.method public final c(Lt3/s0;Lt3/p0;J)Lt3/r0;
    .locals 7

    .line 1
    iget-boolean v0, p0, Lk1/k;->s:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    const-wide/16 v3, 0x0

    .line 6
    .line 7
    if-nez v0, :cond_7

    .line 8
    .line 9
    invoke-virtual {p0, p3, p4, v2}, Lk1/k;->Y0(JZ)J

    .line 10
    .line 11
    .line 12
    move-result-wide v5

    .line 13
    invoke-static {v5, v6, v3, v4}, Lt4/l;->a(JJ)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-nez v0, :cond_0

    .line 18
    .line 19
    goto/16 :goto_0

    .line 20
    .line 21
    :cond_0
    invoke-virtual {p0, p3, p4, v2}, Lk1/k;->X0(JZ)J

    .line 22
    .line 23
    .line 24
    move-result-wide v5

    .line 25
    invoke-static {v5, v6, v3, v4}, Lt4/l;->a(JJ)Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-nez v0, :cond_1

    .line 30
    .line 31
    goto/16 :goto_0

    .line 32
    .line 33
    :cond_1
    invoke-virtual {p0, p3, p4, v2}, Lk1/k;->a1(JZ)J

    .line 34
    .line 35
    .line 36
    move-result-wide v5

    .line 37
    invoke-static {v5, v6, v3, v4}, Lt4/l;->a(JJ)Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-nez v0, :cond_2

    .line 42
    .line 43
    goto/16 :goto_0

    .line 44
    .line 45
    :cond_2
    invoke-virtual {p0, p3, p4, v2}, Lk1/k;->Z0(JZ)J

    .line 46
    .line 47
    .line 48
    move-result-wide v5

    .line 49
    invoke-static {v5, v6, v3, v4}, Lt4/l;->a(JJ)Z

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    if-nez v0, :cond_3

    .line 54
    .line 55
    goto/16 :goto_0

    .line 56
    .line 57
    :cond_3
    invoke-virtual {p0, p3, p4, v1}, Lk1/k;->Y0(JZ)J

    .line 58
    .line 59
    .line 60
    move-result-wide v5

    .line 61
    invoke-static {v5, v6, v3, v4}, Lt4/l;->a(JJ)Z

    .line 62
    .line 63
    .line 64
    move-result v0

    .line 65
    if-nez v0, :cond_4

    .line 66
    .line 67
    goto/16 :goto_0

    .line 68
    .line 69
    :cond_4
    invoke-virtual {p0, p3, p4, v1}, Lk1/k;->X0(JZ)J

    .line 70
    .line 71
    .line 72
    move-result-wide v5

    .line 73
    invoke-static {v5, v6, v3, v4}, Lt4/l;->a(JJ)Z

    .line 74
    .line 75
    .line 76
    move-result v0

    .line 77
    if-nez v0, :cond_5

    .line 78
    .line 79
    goto/16 :goto_0

    .line 80
    .line 81
    :cond_5
    invoke-virtual {p0, p3, p4, v1}, Lk1/k;->a1(JZ)J

    .line 82
    .line 83
    .line 84
    move-result-wide v5

    .line 85
    invoke-static {v5, v6, v3, v4}, Lt4/l;->a(JJ)Z

    .line 86
    .line 87
    .line 88
    move-result v0

    .line 89
    if-nez v0, :cond_6

    .line 90
    .line 91
    goto/16 :goto_0

    .line 92
    .line 93
    :cond_6
    invoke-virtual {p0, p3, p4, v1}, Lk1/k;->Z0(JZ)J

    .line 94
    .line 95
    .line 96
    move-result-wide v5

    .line 97
    invoke-static {v5, v6, v3, v4}, Lt4/l;->a(JJ)Z

    .line 98
    .line 99
    .line 100
    move-result p0

    .line 101
    if-nez p0, :cond_f

    .line 102
    .line 103
    goto :goto_0

    .line 104
    :cond_7
    invoke-virtual {p0, p3, p4, v2}, Lk1/k;->X0(JZ)J

    .line 105
    .line 106
    .line 107
    move-result-wide v5

    .line 108
    invoke-static {v5, v6, v3, v4}, Lt4/l;->a(JJ)Z

    .line 109
    .line 110
    .line 111
    move-result v0

    .line 112
    if-nez v0, :cond_8

    .line 113
    .line 114
    goto :goto_0

    .line 115
    :cond_8
    invoke-virtual {p0, p3, p4, v2}, Lk1/k;->Y0(JZ)J

    .line 116
    .line 117
    .line 118
    move-result-wide v5

    .line 119
    invoke-static {v5, v6, v3, v4}, Lt4/l;->a(JJ)Z

    .line 120
    .line 121
    .line 122
    move-result v0

    .line 123
    if-nez v0, :cond_9

    .line 124
    .line 125
    goto :goto_0

    .line 126
    :cond_9
    invoke-virtual {p0, p3, p4, v2}, Lk1/k;->Z0(JZ)J

    .line 127
    .line 128
    .line 129
    move-result-wide v5

    .line 130
    invoke-static {v5, v6, v3, v4}, Lt4/l;->a(JJ)Z

    .line 131
    .line 132
    .line 133
    move-result v0

    .line 134
    if-nez v0, :cond_a

    .line 135
    .line 136
    goto :goto_0

    .line 137
    :cond_a
    invoke-virtual {p0, p3, p4, v2}, Lk1/k;->a1(JZ)J

    .line 138
    .line 139
    .line 140
    move-result-wide v5

    .line 141
    invoke-static {v5, v6, v3, v4}, Lt4/l;->a(JJ)Z

    .line 142
    .line 143
    .line 144
    move-result v0

    .line 145
    if-nez v0, :cond_b

    .line 146
    .line 147
    goto :goto_0

    .line 148
    :cond_b
    invoke-virtual {p0, p3, p4, v1}, Lk1/k;->X0(JZ)J

    .line 149
    .line 150
    .line 151
    move-result-wide v5

    .line 152
    invoke-static {v5, v6, v3, v4}, Lt4/l;->a(JJ)Z

    .line 153
    .line 154
    .line 155
    move-result v0

    .line 156
    if-nez v0, :cond_c

    .line 157
    .line 158
    goto :goto_0

    .line 159
    :cond_c
    invoke-virtual {p0, p3, p4, v1}, Lk1/k;->Y0(JZ)J

    .line 160
    .line 161
    .line 162
    move-result-wide v5

    .line 163
    invoke-static {v5, v6, v3, v4}, Lt4/l;->a(JJ)Z

    .line 164
    .line 165
    .line 166
    move-result v0

    .line 167
    if-nez v0, :cond_d

    .line 168
    .line 169
    goto :goto_0

    .line 170
    :cond_d
    invoke-virtual {p0, p3, p4, v1}, Lk1/k;->Z0(JZ)J

    .line 171
    .line 172
    .line 173
    move-result-wide v5

    .line 174
    invoke-static {v5, v6, v3, v4}, Lt4/l;->a(JJ)Z

    .line 175
    .line 176
    .line 177
    move-result v0

    .line 178
    if-nez v0, :cond_e

    .line 179
    .line 180
    goto :goto_0

    .line 181
    :cond_e
    invoke-virtual {p0, p3, p4, v1}, Lk1/k;->a1(JZ)J

    .line 182
    .line 183
    .line 184
    move-result-wide v5

    .line 185
    invoke-static {v5, v6, v3, v4}, Lt4/l;->a(JJ)Z

    .line 186
    .line 187
    .line 188
    move-result p0

    .line 189
    if-nez p0, :cond_f

    .line 190
    .line 191
    goto :goto_0

    .line 192
    :cond_f
    move-wide v5, v3

    .line 193
    :goto_0
    invoke-static {v5, v6, v3, v4}, Lt4/l;->a(JJ)Z

    .line 194
    .line 195
    .line 196
    move-result p0

    .line 197
    if-nez p0, :cond_13

    .line 198
    .line 199
    const/16 p0, 0x20

    .line 200
    .line 201
    shr-long p3, v5, p0

    .line 202
    .line 203
    long-to-int p0, p3

    .line 204
    const-wide p3, 0xffffffffL

    .line 205
    .line 206
    .line 207
    .line 208
    .line 209
    and-long/2addr p3, v5

    .line 210
    long-to-int p3, p3

    .line 211
    if-ltz p0, :cond_10

    .line 212
    .line 213
    move p4, v2

    .line 214
    goto :goto_1

    .line 215
    :cond_10
    move p4, v1

    .line 216
    :goto_1
    if-ltz p3, :cond_11

    .line 217
    .line 218
    move v1, v2

    .line 219
    :cond_11
    and-int/2addr p4, v1

    .line 220
    if-nez p4, :cond_12

    .line 221
    .line 222
    const-string p4, "width and height must be >= 0"

    .line 223
    .line 224
    invoke-static {p4}, Lt4/i;->a(Ljava/lang/String;)V

    .line 225
    .line 226
    .line 227
    :cond_12
    invoke-static {p0, p0, p3, p3}, Lt4/b;->h(IIII)J

    .line 228
    .line 229
    .line 230
    move-result-wide p3

    .line 231
    :cond_13
    invoke-interface {p2, p3, p4}, Lt3/p0;->L(J)Lt3/e1;

    .line 232
    .line 233
    .line 234
    move-result-object p0

    .line 235
    iget p2, p0, Lt3/e1;->d:I

    .line 236
    .line 237
    iget p3, p0, Lt3/e1;->e:I

    .line 238
    .line 239
    new-instance p4, Lam/a;

    .line 240
    .line 241
    const/16 v0, 0xb

    .line 242
    .line 243
    invoke-direct {p4, p0, v0}, Lam/a;-><init>(Lt3/e1;I)V

    .line 244
    .line 245
    .line 246
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 247
    .line 248
    invoke-interface {p1, p2, p3, p0, p4}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 249
    .line 250
    .line 251
    move-result-object p0

    .line 252
    return-object p0
.end method
