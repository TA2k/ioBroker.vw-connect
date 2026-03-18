.class public final Lf5/f;
.super Le5/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public A0:Ljava/lang/String;

.field public B0:I

.field public n0:Lg5/a;

.field public o0:I

.field public p0:I

.field public q0:I

.field public r0:I

.field public s0:I

.field public t0:I

.field public u0:I

.field public v0:F

.field public w0:F

.field public x0:Ljava/lang/String;

.field public y0:Ljava/lang/String;

.field public z0:Ljava/lang/String;


# direct methods
.method public constructor <init>(Lz4/q;I)V
    .locals 1

    .line 1
    invoke-direct {p0, p1, p2}, Le5/h;-><init>(Lz4/q;I)V

    .line 2
    .line 3
    .line 4
    const/4 p1, 0x0

    .line 5
    iput p1, p0, Lf5/f;->o0:I

    .line 6
    .line 7
    iput p1, p0, Lf5/f;->p0:I

    .line 8
    .line 9
    iput p1, p0, Lf5/f;->q0:I

    .line 10
    .line 11
    iput p1, p0, Lf5/f;->r0:I

    .line 12
    .line 13
    const/16 p1, 0xa

    .line 14
    .line 15
    const/4 v0, 0x1

    .line 16
    if-ne p2, p1, :cond_0

    .line 17
    .line 18
    iput v0, p0, Lf5/f;->t0:I

    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    const/16 p1, 0xb

    .line 22
    .line 23
    if-ne p2, p1, :cond_1

    .line 24
    .line 25
    iput v0, p0, Lf5/f;->u0:I

    .line 26
    .line 27
    :cond_1
    return-void
.end method


# virtual methods
.method public final apply()V
    .locals 5

    .line 1
    invoke-virtual {p0}, Lf5/f;->s()Lh5/i;

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lf5/f;->n0:Lg5/a;

    .line 5
    .line 6
    iget v1, p0, Lf5/f;->s0:I

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    const/4 v2, 0x1

    .line 14
    if-eq v1, v2, :cond_0

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    iget v2, v0, Lg5/a;->R0:I

    .line 18
    .line 19
    if-ne v2, v1, :cond_1

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_1
    iput v1, v0, Lg5/a;->R0:I

    .line 23
    .line 24
    :goto_0
    iget v0, p0, Lf5/f;->t0:I

    .line 25
    .line 26
    const/16 v1, 0x32

    .line 27
    .line 28
    if-eqz v0, :cond_4

    .line 29
    .line 30
    iget-object v2, p0, Lf5/f;->n0:Lg5/a;

    .line 31
    .line 32
    if-le v0, v1, :cond_2

    .line 33
    .line 34
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 35
    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_2
    iget v3, v2, Lg5/a;->I0:I

    .line 39
    .line 40
    if-ne v3, v0, :cond_3

    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_3
    iput v0, v2, Lg5/a;->I0:I

    .line 44
    .line 45
    invoke-virtual {v2}, Lg5/a;->k0()V

    .line 46
    .line 47
    .line 48
    invoke-virtual {v2}, Lg5/a;->g0()V

    .line 49
    .line 50
    .line 51
    :cond_4
    :goto_1
    iget v0, p0, Lf5/f;->u0:I

    .line 52
    .line 53
    if-eqz v0, :cond_7

    .line 54
    .line 55
    iget-object v2, p0, Lf5/f;->n0:Lg5/a;

    .line 56
    .line 57
    if-le v0, v1, :cond_5

    .line 58
    .line 59
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 60
    .line 61
    .line 62
    goto :goto_2

    .line 63
    :cond_5
    iget v1, v2, Lg5/a;->K0:I

    .line 64
    .line 65
    if-ne v1, v0, :cond_6

    .line 66
    .line 67
    goto :goto_2

    .line 68
    :cond_6
    iput v0, v2, Lg5/a;->K0:I

    .line 69
    .line 70
    invoke-virtual {v2}, Lg5/a;->k0()V

    .line 71
    .line 72
    .line 73
    invoke-virtual {v2}, Lg5/a;->g0()V

    .line 74
    .line 75
    .line 76
    :cond_7
    :goto_2
    iget v0, p0, Lf5/f;->v0:F

    .line 77
    .line 78
    const/4 v1, 0x0

    .line 79
    cmpl-float v2, v0, v1

    .line 80
    .line 81
    if-eqz v2, :cond_a

    .line 82
    .line 83
    iget-object v2, p0, Lf5/f;->n0:Lg5/a;

    .line 84
    .line 85
    cmpg-float v3, v0, v1

    .line 86
    .line 87
    if-gez v3, :cond_8

    .line 88
    .line 89
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 90
    .line 91
    .line 92
    goto :goto_3

    .line 93
    :cond_8
    iget v3, v2, Lg5/a;->L0:F

    .line 94
    .line 95
    cmpl-float v3, v3, v0

    .line 96
    .line 97
    if-nez v3, :cond_9

    .line 98
    .line 99
    goto :goto_3

    .line 100
    :cond_9
    iput v0, v2, Lg5/a;->L0:F

    .line 101
    .line 102
    :cond_a
    :goto_3
    iget v0, p0, Lf5/f;->w0:F

    .line 103
    .line 104
    cmpl-float v2, v0, v1

    .line 105
    .line 106
    if-eqz v2, :cond_d

    .line 107
    .line 108
    iget-object v2, p0, Lf5/f;->n0:Lg5/a;

    .line 109
    .line 110
    cmpg-float v1, v0, v1

    .line 111
    .line 112
    if-gez v1, :cond_b

    .line 113
    .line 114
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 115
    .line 116
    .line 117
    goto :goto_4

    .line 118
    :cond_b
    iget v1, v2, Lg5/a;->M0:F

    .line 119
    .line 120
    cmpl-float v1, v1, v0

    .line 121
    .line 122
    if-nez v1, :cond_c

    .line 123
    .line 124
    goto :goto_4

    .line 125
    :cond_c
    iput v0, v2, Lg5/a;->M0:F

    .line 126
    .line 127
    :cond_d
    :goto_4
    iget-object v0, p0, Lf5/f;->x0:Ljava/lang/String;

    .line 128
    .line 129
    if-eqz v0, :cond_f

    .line 130
    .line 131
    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    .line 132
    .line 133
    .line 134
    move-result v0

    .line 135
    if-nez v0, :cond_f

    .line 136
    .line 137
    iget-object v0, p0, Lf5/f;->n0:Lg5/a;

    .line 138
    .line 139
    iget-object v1, p0, Lf5/f;->x0:Ljava/lang/String;

    .line 140
    .line 141
    iget-object v2, v0, Lg5/a;->N0:Ljava/lang/String;

    .line 142
    .line 143
    if-eqz v2, :cond_e

    .line 144
    .line 145
    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 146
    .line 147
    .line 148
    move-result v2

    .line 149
    if-eqz v2, :cond_e

    .line 150
    .line 151
    goto :goto_5

    .line 152
    :cond_e
    iput-object v1, v0, Lg5/a;->N0:Ljava/lang/String;

    .line 153
    .line 154
    :cond_f
    :goto_5
    iget-object v0, p0, Lf5/f;->y0:Ljava/lang/String;

    .line 155
    .line 156
    if-eqz v0, :cond_11

    .line 157
    .line 158
    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    .line 159
    .line 160
    .line 161
    move-result v0

    .line 162
    if-nez v0, :cond_11

    .line 163
    .line 164
    iget-object v0, p0, Lf5/f;->n0:Lg5/a;

    .line 165
    .line 166
    iget-object v1, p0, Lf5/f;->y0:Ljava/lang/String;

    .line 167
    .line 168
    iget-object v2, v0, Lg5/a;->O0:Ljava/lang/String;

    .line 169
    .line 170
    if-eqz v2, :cond_10

    .line 171
    .line 172
    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 173
    .line 174
    .line 175
    move-result v2

    .line 176
    if-eqz v2, :cond_10

    .line 177
    .line 178
    goto :goto_6

    .line 179
    :cond_10
    iput-object v1, v0, Lg5/a;->O0:Ljava/lang/String;

    .line 180
    .line 181
    :cond_11
    :goto_6
    iget-object v0, p0, Lf5/f;->z0:Ljava/lang/String;

    .line 182
    .line 183
    const/4 v1, 0x0

    .line 184
    if-eqz v0, :cond_13

    .line 185
    .line 186
    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    .line 187
    .line 188
    .line 189
    move-result v0

    .line 190
    if-nez v0, :cond_13

    .line 191
    .line 192
    iget-object v0, p0, Lf5/f;->n0:Lg5/a;

    .line 193
    .line 194
    iget-object v2, p0, Lf5/f;->z0:Ljava/lang/String;

    .line 195
    .line 196
    iget-object v3, v0, Lg5/a;->P0:Ljava/lang/String;

    .line 197
    .line 198
    if-eqz v3, :cond_12

    .line 199
    .line 200
    invoke-virtual {v2}, Ljava/lang/String;->toString()Ljava/lang/String;

    .line 201
    .line 202
    .line 203
    move-result-object v4

    .line 204
    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 205
    .line 206
    .line 207
    move-result v3

    .line 208
    if-eqz v3, :cond_12

    .line 209
    .line 210
    goto :goto_7

    .line 211
    :cond_12
    iput-boolean v1, v0, Lg5/a;->G0:Z

    .line 212
    .line 213
    invoke-virtual {v2}, Ljava/lang/String;->toString()Ljava/lang/String;

    .line 214
    .line 215
    .line 216
    move-result-object v2

    .line 217
    iput-object v2, v0, Lg5/a;->P0:Ljava/lang/String;

    .line 218
    .line 219
    :cond_13
    :goto_7
    iget-object v0, p0, Lf5/f;->A0:Ljava/lang/String;

    .line 220
    .line 221
    if-eqz v0, :cond_15

    .line 222
    .line 223
    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    .line 224
    .line 225
    .line 226
    move-result v0

    .line 227
    if-nez v0, :cond_15

    .line 228
    .line 229
    iget-object v0, p0, Lf5/f;->n0:Lg5/a;

    .line 230
    .line 231
    iget-object v2, p0, Lf5/f;->A0:Ljava/lang/String;

    .line 232
    .line 233
    iget-object v3, v0, Lg5/a;->Q0:Ljava/lang/String;

    .line 234
    .line 235
    if-eqz v3, :cond_14

    .line 236
    .line 237
    invoke-virtual {v3, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 238
    .line 239
    .line 240
    move-result v3

    .line 241
    if-eqz v3, :cond_14

    .line 242
    .line 243
    goto :goto_8

    .line 244
    :cond_14
    iput-boolean v1, v0, Lg5/a;->G0:Z

    .line 245
    .line 246
    iput-object v2, v0, Lg5/a;->Q0:Ljava/lang/String;

    .line 247
    .line 248
    :cond_15
    :goto_8
    iget-object v0, p0, Lf5/f;->n0:Lg5/a;

    .line 249
    .line 250
    iget v1, p0, Lf5/f;->B0:I

    .line 251
    .line 252
    iput v1, v0, Lg5/a;->W0:I

    .line 253
    .line 254
    iget v1, p0, Lf5/f;->o0:I

    .line 255
    .line 256
    iput v1, v0, Lh5/k;->v0:I

    .line 257
    .line 258
    iput v1, v0, Lh5/k;->x0:I

    .line 259
    .line 260
    iput v1, v0, Lh5/k;->y0:I

    .line 261
    .line 262
    iget v1, p0, Lf5/f;->p0:I

    .line 263
    .line 264
    iput v1, v0, Lh5/k;->w0:I

    .line 265
    .line 266
    iget v1, p0, Lf5/f;->q0:I

    .line 267
    .line 268
    iput v1, v0, Lh5/k;->t0:I

    .line 269
    .line 270
    iget v1, p0, Lf5/f;->r0:I

    .line 271
    .line 272
    iput v1, v0, Lh5/k;->u0:I

    .line 273
    .line 274
    invoke-virtual {p0}, Le5/h;->r()V

    .line 275
    .line 276
    .line 277
    return-void
.end method

.method public final s()Lh5/i;
    .locals 7

    .line 1
    iget-object v0, p0, Lf5/f;->n0:Lg5/a;

    .line 2
    .line 3
    if-nez v0, :cond_8

    .line 4
    .line 5
    new-instance v0, Lg5/a;

    .line 6
    .line 7
    invoke-direct {v0}, Lh5/k;-><init>()V

    .line 8
    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    iput-boolean v1, v0, Lg5/a;->G0:Z

    .line 12
    .line 13
    iput v1, v0, Lg5/a;->S0:I

    .line 14
    .line 15
    new-instance v2, Ljava/util/HashSet;

    .line 16
    .line 17
    invoke-direct {v2}, Ljava/util/HashSet;-><init>()V

    .line 18
    .line 19
    .line 20
    iput-object v2, v0, Lg5/a;->U0:Ljava/util/HashSet;

    .line 21
    .line 22
    iput v1, v0, Lg5/a;->Y0:I

    .line 23
    .line 24
    invoke-virtual {v0}, Lg5/a;->k0()V

    .line 25
    .line 26
    .line 27
    iget-object v2, v0, Lg5/a;->V0:[[I

    .line 28
    .line 29
    const/4 v3, 0x1

    .line 30
    if-eqz v2, :cond_0

    .line 31
    .line 32
    array-length v2, v2

    .line 33
    iget v4, v0, Lh5/i;->s0:I

    .line 34
    .line 35
    if-ne v2, v4, :cond_0

    .line 36
    .line 37
    iget-object v2, v0, Lg5/a;->T0:[[Z

    .line 38
    .line 39
    if-eqz v2, :cond_0

    .line 40
    .line 41
    array-length v4, v2

    .line 42
    iget v5, v0, Lg5/a;->H0:I

    .line 43
    .line 44
    if-ne v4, v5, :cond_0

    .line 45
    .line 46
    aget-object v2, v2, v1

    .line 47
    .line 48
    array-length v2, v2

    .line 49
    iget v4, v0, Lg5/a;->J0:I

    .line 50
    .line 51
    if-ne v2, v4, :cond_0

    .line 52
    .line 53
    move v2, v3

    .line 54
    goto :goto_0

    .line 55
    :cond_0
    move v2, v1

    .line 56
    :goto_0
    if-nez v2, :cond_1

    .line 57
    .line 58
    invoke-virtual {v0}, Lg5/a;->g0()V

    .line 59
    .line 60
    .line 61
    :cond_1
    if-eqz v2, :cond_5

    .line 62
    .line 63
    move v2, v1

    .line 64
    :goto_1
    iget-object v4, v0, Lg5/a;->T0:[[Z

    .line 65
    .line 66
    array-length v4, v4

    .line 67
    if-ge v2, v4, :cond_3

    .line 68
    .line 69
    move v4, v1

    .line 70
    :goto_2
    iget-object v5, v0, Lg5/a;->T0:[[Z

    .line 71
    .line 72
    aget-object v6, v5, v1

    .line 73
    .line 74
    array-length v6, v6

    .line 75
    if-ge v4, v6, :cond_2

    .line 76
    .line 77
    aget-object v5, v5, v2

    .line 78
    .line 79
    aput-boolean v3, v5, v4

    .line 80
    .line 81
    add-int/lit8 v4, v4, 0x1

    .line 82
    .line 83
    goto :goto_2

    .line 84
    :cond_2
    add-int/lit8 v2, v2, 0x1

    .line 85
    .line 86
    goto :goto_1

    .line 87
    :cond_3
    move v2, v1

    .line 88
    :goto_3
    iget-object v4, v0, Lg5/a;->V0:[[I

    .line 89
    .line 90
    array-length v4, v4

    .line 91
    if-ge v2, v4, :cond_5

    .line 92
    .line 93
    move v4, v1

    .line 94
    :goto_4
    iget-object v5, v0, Lg5/a;->V0:[[I

    .line 95
    .line 96
    aget-object v6, v5, v1

    .line 97
    .line 98
    array-length v6, v6

    .line 99
    if-ge v4, v6, :cond_4

    .line 100
    .line 101
    aget-object v5, v5, v2

    .line 102
    .line 103
    const/4 v6, -0x1

    .line 104
    aput v6, v5, v4

    .line 105
    .line 106
    add-int/lit8 v4, v4, 0x1

    .line 107
    .line 108
    goto :goto_4

    .line 109
    :cond_4
    add-int/lit8 v2, v2, 0x1

    .line 110
    .line 111
    goto :goto_3

    .line 112
    :cond_5
    iput v1, v0, Lg5/a;->S0:I

    .line 113
    .line 114
    iget-object v2, v0, Lg5/a;->Q0:Ljava/lang/String;

    .line 115
    .line 116
    if-eqz v2, :cond_6

    .line 117
    .line 118
    invoke-virtual {v2}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object v2

    .line 122
    invoke-virtual {v2}, Ljava/lang/String;->isEmpty()Z

    .line 123
    .line 124
    .line 125
    move-result v2

    .line 126
    if-nez v2, :cond_6

    .line 127
    .line 128
    iget-object v2, v0, Lg5/a;->Q0:Ljava/lang/String;

    .line 129
    .line 130
    invoke-virtual {v0, v2, v1}, Lg5/a;->i0(Ljava/lang/String;Z)[[I

    .line 131
    .line 132
    .line 133
    move-result-object v1

    .line 134
    if-eqz v1, :cond_6

    .line 135
    .line 136
    invoke-virtual {v0, v1}, Lg5/a;->e0([[I)V

    .line 137
    .line 138
    .line 139
    :cond_6
    iget-object v1, v0, Lg5/a;->P0:Ljava/lang/String;

    .line 140
    .line 141
    if-eqz v1, :cond_7

    .line 142
    .line 143
    invoke-virtual {v1}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 144
    .line 145
    .line 146
    move-result-object v1

    .line 147
    invoke-virtual {v1}, Ljava/lang/String;->isEmpty()Z

    .line 148
    .line 149
    .line 150
    move-result v1

    .line 151
    if-nez v1, :cond_7

    .line 152
    .line 153
    iget-object v1, v0, Lg5/a;->P0:Ljava/lang/String;

    .line 154
    .line 155
    invoke-virtual {v0, v1, v3}, Lg5/a;->i0(Ljava/lang/String;Z)[[I

    .line 156
    .line 157
    .line 158
    move-result-object v1

    .line 159
    if-eqz v1, :cond_7

    .line 160
    .line 161
    invoke-virtual {v0, v1}, Lg5/a;->f0([[I)V

    .line 162
    .line 163
    .line 164
    :cond_7
    iput-object v0, p0, Lf5/f;->n0:Lg5/a;

    .line 165
    .line 166
    :cond_8
    iget-object p0, p0, Lf5/f;->n0:Lg5/a;

    .line 167
    .line 168
    return-object p0
.end method
