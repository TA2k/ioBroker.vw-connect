.class public final Lh5/e;
.super Lh5/d;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public A0:I

.field public B0:I

.field public C0:[Lh5/b;

.field public D0:[Lh5/b;

.field public E0:I

.field public F0:Z

.field public G0:Z

.field public H0:Ljava/lang/ref/WeakReference;

.field public I0:Ljava/lang/ref/WeakReference;

.field public J0:Ljava/lang/ref/WeakReference;

.field public K0:Ljava/lang/ref/WeakReference;

.field public L0:Ljava/util/HashSet;

.field public M0:Li5/b;

.field public r0:Ljava/util/ArrayList;

.field public s0:Lgw0/c;

.field public t0:Li5/f;

.field public u0:I

.field public v0:Li5/c;

.field public w0:Z

.field public x0:La5/c;

.field public y0:I

.field public z0:I


# direct methods
.method public constructor <init>()V
    .locals 4

    .line 1
    invoke-direct {p0}, Lh5/d;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 10
    .line 11
    new-instance v0, Lgw0/c;

    .line 12
    .line 13
    invoke-direct {v0, p0}, Lgw0/c;-><init>(Lh5/e;)V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lh5/e;->s0:Lgw0/c;

    .line 17
    .line 18
    new-instance v0, Li5/f;

    .line 19
    .line 20
    invoke-direct {v0, p0}, Li5/f;-><init>(Lh5/e;)V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Lh5/e;->t0:Li5/f;

    .line 24
    .line 25
    const/4 v0, 0x0

    .line 26
    iput-object v0, p0, Lh5/e;->v0:Li5/c;

    .line 27
    .line 28
    const/4 v1, 0x0

    .line 29
    iput-boolean v1, p0, Lh5/e;->w0:Z

    .line 30
    .line 31
    new-instance v2, La5/c;

    .line 32
    .line 33
    invoke-direct {v2}, La5/c;-><init>()V

    .line 34
    .line 35
    .line 36
    iput-object v2, p0, Lh5/e;->x0:La5/c;

    .line 37
    .line 38
    iput v1, p0, Lh5/e;->A0:I

    .line 39
    .line 40
    iput v1, p0, Lh5/e;->B0:I

    .line 41
    .line 42
    const/4 v2, 0x4

    .line 43
    new-array v3, v2, [Lh5/b;

    .line 44
    .line 45
    iput-object v3, p0, Lh5/e;->C0:[Lh5/b;

    .line 46
    .line 47
    new-array v2, v2, [Lh5/b;

    .line 48
    .line 49
    iput-object v2, p0, Lh5/e;->D0:[Lh5/b;

    .line 50
    .line 51
    const/16 v2, 0x101

    .line 52
    .line 53
    iput v2, p0, Lh5/e;->E0:I

    .line 54
    .line 55
    iput-boolean v1, p0, Lh5/e;->F0:Z

    .line 56
    .line 57
    iput-boolean v1, p0, Lh5/e;->G0:Z

    .line 58
    .line 59
    iput-object v0, p0, Lh5/e;->H0:Ljava/lang/ref/WeakReference;

    .line 60
    .line 61
    iput-object v0, p0, Lh5/e;->I0:Ljava/lang/ref/WeakReference;

    .line 62
    .line 63
    iput-object v0, p0, Lh5/e;->J0:Ljava/lang/ref/WeakReference;

    .line 64
    .line 65
    iput-object v0, p0, Lh5/e;->K0:Ljava/lang/ref/WeakReference;

    .line 66
    .line 67
    new-instance v0, Ljava/util/HashSet;

    .line 68
    .line 69
    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    .line 70
    .line 71
    .line 72
    iput-object v0, p0, Lh5/e;->L0:Ljava/util/HashSet;

    .line 73
    .line 74
    new-instance v0, Li5/b;

    .line 75
    .line 76
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 77
    .line 78
    .line 79
    iput-object v0, p0, Lh5/e;->M0:Li5/b;

    .line 80
    .line 81
    return-void
.end method

.method public static b0(Lh5/d;Li5/c;Li5/b;)V
    .locals 9

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    iget v0, p0, Lh5/d;->h0:I

    .line 5
    .line 6
    iget-object v1, p0, Lh5/d;->u:[I

    .line 7
    .line 8
    const/16 v2, 0x8

    .line 9
    .line 10
    const/4 v3, 0x0

    .line 11
    if-eq v0, v2, :cond_13

    .line 12
    .line 13
    instance-of v0, p0, Lh5/h;

    .line 14
    .line 15
    if-nez v0, :cond_13

    .line 16
    .line 17
    instance-of v0, p0, Lh5/a;

    .line 18
    .line 19
    if-eqz v0, :cond_1

    .line 20
    .line 21
    goto/16 :goto_8

    .line 22
    .line 23
    :cond_1
    iget-object v0, p0, Lh5/d;->q0:[I

    .line 24
    .line 25
    aget v2, v0, v3

    .line 26
    .line 27
    iput v2, p2, Li5/b;->a:I

    .line 28
    .line 29
    const/4 v2, 0x1

    .line 30
    aget v0, v0, v2

    .line 31
    .line 32
    iput v0, p2, Li5/b;->b:I

    .line 33
    .line 34
    invoke-virtual {p0}, Lh5/d;->r()I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    iput v0, p2, Li5/b;->c:I

    .line 39
    .line 40
    invoke-virtual {p0}, Lh5/d;->l()I

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    iput v0, p2, Li5/b;->d:I

    .line 45
    .line 46
    iput-boolean v3, p2, Li5/b;->i:Z

    .line 47
    .line 48
    iput v3, p2, Li5/b;->j:I

    .line 49
    .line 50
    iget v0, p2, Li5/b;->a:I

    .line 51
    .line 52
    const/4 v4, 0x3

    .line 53
    if-ne v0, v4, :cond_2

    .line 54
    .line 55
    move v0, v2

    .line 56
    goto :goto_0

    .line 57
    :cond_2
    move v0, v3

    .line 58
    :goto_0
    iget v5, p2, Li5/b;->b:I

    .line 59
    .line 60
    if-ne v5, v4, :cond_3

    .line 61
    .line 62
    move v4, v2

    .line 63
    goto :goto_1

    .line 64
    :cond_3
    move v4, v3

    .line 65
    :goto_1
    const/4 v5, 0x0

    .line 66
    if-eqz v0, :cond_4

    .line 67
    .line 68
    iget v6, p0, Lh5/d;->X:F

    .line 69
    .line 70
    cmpl-float v6, v6, v5

    .line 71
    .line 72
    if-lez v6, :cond_4

    .line 73
    .line 74
    move v6, v2

    .line 75
    goto :goto_2

    .line 76
    :cond_4
    move v6, v3

    .line 77
    :goto_2
    if-eqz v4, :cond_5

    .line 78
    .line 79
    iget v7, p0, Lh5/d;->X:F

    .line 80
    .line 81
    cmpl-float v5, v7, v5

    .line 82
    .line 83
    if-lez v5, :cond_5

    .line 84
    .line 85
    move v5, v2

    .line 86
    goto :goto_3

    .line 87
    :cond_5
    move v5, v3

    .line 88
    :goto_3
    const/4 v7, 0x2

    .line 89
    if-eqz v0, :cond_7

    .line 90
    .line 91
    invoke-virtual {p0, v3}, Lh5/d;->u(I)Z

    .line 92
    .line 93
    .line 94
    move-result v8

    .line 95
    if-eqz v8, :cond_7

    .line 96
    .line 97
    iget v8, p0, Lh5/d;->s:I

    .line 98
    .line 99
    if-nez v8, :cond_7

    .line 100
    .line 101
    if-nez v6, :cond_7

    .line 102
    .line 103
    iput v7, p2, Li5/b;->a:I

    .line 104
    .line 105
    if-eqz v4, :cond_6

    .line 106
    .line 107
    iget v0, p0, Lh5/d;->t:I

    .line 108
    .line 109
    if-nez v0, :cond_6

    .line 110
    .line 111
    iput v2, p2, Li5/b;->a:I

    .line 112
    .line 113
    :cond_6
    move v0, v3

    .line 114
    :cond_7
    if-eqz v4, :cond_9

    .line 115
    .line 116
    invoke-virtual {p0, v2}, Lh5/d;->u(I)Z

    .line 117
    .line 118
    .line 119
    move-result v8

    .line 120
    if-eqz v8, :cond_9

    .line 121
    .line 122
    iget v8, p0, Lh5/d;->t:I

    .line 123
    .line 124
    if-nez v8, :cond_9

    .line 125
    .line 126
    if-nez v5, :cond_9

    .line 127
    .line 128
    iput v7, p2, Li5/b;->b:I

    .line 129
    .line 130
    if-eqz v0, :cond_8

    .line 131
    .line 132
    iget v4, p0, Lh5/d;->s:I

    .line 133
    .line 134
    if-nez v4, :cond_8

    .line 135
    .line 136
    iput v2, p2, Li5/b;->b:I

    .line 137
    .line 138
    :cond_8
    move v4, v3

    .line 139
    :cond_9
    invoke-virtual {p0}, Lh5/d;->B()Z

    .line 140
    .line 141
    .line 142
    move-result v8

    .line 143
    if-eqz v8, :cond_a

    .line 144
    .line 145
    iput v2, p2, Li5/b;->a:I

    .line 146
    .line 147
    move v0, v3

    .line 148
    :cond_a
    invoke-virtual {p0}, Lh5/d;->C()Z

    .line 149
    .line 150
    .line 151
    move-result v8

    .line 152
    if-eqz v8, :cond_b

    .line 153
    .line 154
    iput v2, p2, Li5/b;->b:I

    .line 155
    .line 156
    move v4, v3

    .line 157
    :cond_b
    const/4 v8, 0x4

    .line 158
    if-eqz v6, :cond_e

    .line 159
    .line 160
    aget v6, v1, v3

    .line 161
    .line 162
    if-ne v6, v8, :cond_c

    .line 163
    .line 164
    iput v2, p2, Li5/b;->a:I

    .line 165
    .line 166
    goto :goto_5

    .line 167
    :cond_c
    if-nez v4, :cond_e

    .line 168
    .line 169
    iget v4, p2, Li5/b;->b:I

    .line 170
    .line 171
    if-ne v4, v2, :cond_d

    .line 172
    .line 173
    iget v4, p2, Li5/b;->d:I

    .line 174
    .line 175
    goto :goto_4

    .line 176
    :cond_d
    iput v7, p2, Li5/b;->a:I

    .line 177
    .line 178
    invoke-interface {p1, p0, p2}, Li5/c;->b(Lh5/d;Li5/b;)V

    .line 179
    .line 180
    .line 181
    iget v4, p2, Li5/b;->f:I

    .line 182
    .line 183
    :goto_4
    iput v2, p2, Li5/b;->a:I

    .line 184
    .line 185
    iget v6, p0, Lh5/d;->X:F

    .line 186
    .line 187
    int-to-float v4, v4

    .line 188
    mul-float/2addr v6, v4

    .line 189
    float-to-int v4, v6

    .line 190
    iput v4, p2, Li5/b;->c:I

    .line 191
    .line 192
    :cond_e
    :goto_5
    if-eqz v5, :cond_12

    .line 193
    .line 194
    aget v1, v1, v2

    .line 195
    .line 196
    if-ne v1, v8, :cond_f

    .line 197
    .line 198
    iput v2, p2, Li5/b;->b:I

    .line 199
    .line 200
    goto :goto_7

    .line 201
    :cond_f
    if-nez v0, :cond_12

    .line 202
    .line 203
    iget v0, p2, Li5/b;->a:I

    .line 204
    .line 205
    if-ne v0, v2, :cond_10

    .line 206
    .line 207
    iget v0, p2, Li5/b;->c:I

    .line 208
    .line 209
    goto :goto_6

    .line 210
    :cond_10
    iput v7, p2, Li5/b;->b:I

    .line 211
    .line 212
    invoke-interface {p1, p0, p2}, Li5/c;->b(Lh5/d;Li5/b;)V

    .line 213
    .line 214
    .line 215
    iget v0, p2, Li5/b;->e:I

    .line 216
    .line 217
    :goto_6
    iput v2, p2, Li5/b;->b:I

    .line 218
    .line 219
    iget v1, p0, Lh5/d;->Y:I

    .line 220
    .line 221
    const/4 v2, -0x1

    .line 222
    if-ne v1, v2, :cond_11

    .line 223
    .line 224
    int-to-float v0, v0

    .line 225
    iget v1, p0, Lh5/d;->X:F

    .line 226
    .line 227
    div-float/2addr v0, v1

    .line 228
    float-to-int v0, v0

    .line 229
    iput v0, p2, Li5/b;->d:I

    .line 230
    .line 231
    goto :goto_7

    .line 232
    :cond_11
    iget v1, p0, Lh5/d;->X:F

    .line 233
    .line 234
    int-to-float v0, v0

    .line 235
    mul-float/2addr v1, v0

    .line 236
    float-to-int v0, v1

    .line 237
    iput v0, p2, Li5/b;->d:I

    .line 238
    .line 239
    :cond_12
    :goto_7
    invoke-interface {p1, p0, p2}, Li5/c;->b(Lh5/d;Li5/b;)V

    .line 240
    .line 241
    .line 242
    iget p1, p2, Li5/b;->e:I

    .line 243
    .line 244
    invoke-virtual {p0, p1}, Lh5/d;->S(I)V

    .line 245
    .line 246
    .line 247
    iget p1, p2, Li5/b;->f:I

    .line 248
    .line 249
    invoke-virtual {p0, p1}, Lh5/d;->N(I)V

    .line 250
    .line 251
    .line 252
    iget-boolean p1, p2, Li5/b;->h:Z

    .line 253
    .line 254
    iput-boolean p1, p0, Lh5/d;->F:Z

    .line 255
    .line 256
    iget p1, p2, Li5/b;->g:I

    .line 257
    .line 258
    invoke-virtual {p0, p1}, Lh5/d;->J(I)V

    .line 259
    .line 260
    .line 261
    iput v3, p2, Li5/b;->j:I

    .line 262
    .line 263
    return-void

    .line 264
    :cond_13
    :goto_8
    iput v3, p2, Li5/b;->e:I

    .line 265
    .line 266
    iput v3, p2, Li5/b;->f:I

    .line 267
    .line 268
    return-void
.end method


# virtual methods
.method public final D()V
    .locals 1

    .line 1
    iget-object v0, p0, Lh5/e;->x0:La5/c;

    .line 2
    .line 3
    invoke-virtual {v0}, La5/c;->t()V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    iput v0, p0, Lh5/e;->y0:I

    .line 8
    .line 9
    iput v0, p0, Lh5/e;->z0:I

    .line 10
    .line 11
    iget-object v0, p0, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 14
    .line 15
    .line 16
    invoke-super {p0}, Lh5/d;->D()V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public final G(Lgw0/c;)V
    .locals 3

    .line 1
    invoke-super {p0, p1}, Lh5/d;->G(Lgw0/c;)V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    const/4 v1, 0x0

    .line 11
    :goto_0
    if-ge v1, v0, :cond_0

    .line 12
    .line 13
    iget-object v2, p0, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 14
    .line 15
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    check-cast v2, Lh5/d;

    .line 20
    .line 21
    invoke-virtual {v2, p1}, Lh5/d;->G(Lgw0/c;)V

    .line 22
    .line 23
    .line 24
    add-int/lit8 v1, v1, 0x1

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    return-void
.end method

.method public final T(ZZ)V
    .locals 3

    .line 1
    invoke-super {p0, p1, p2}, Lh5/d;->T(ZZ)V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    const/4 v1, 0x0

    .line 11
    :goto_0
    if-ge v1, v0, :cond_0

    .line 12
    .line 13
    iget-object v2, p0, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 14
    .line 15
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    check-cast v2, Lh5/d;

    .line 20
    .line 21
    invoke-virtual {v2, p1, p2}, Lh5/d;->T(ZZ)V

    .line 22
    .line 23
    .line 24
    add-int/lit8 v1, v1, 0x1

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    return-void
.end method

.method public final V(Lh5/d;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    iget-object v0, p1, Lh5/d;->U:Lh5/e;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    iget-object v0, v0, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 11
    .line 12
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    invoke-virtual {p1}, Lh5/d;->D()V

    .line 16
    .line 17
    .line 18
    :cond_0
    iput-object p0, p1, Lh5/d;->U:Lh5/e;

    .line 19
    .line 20
    return-void
.end method

.method public final W(Lh5/d;I)V
    .locals 5

    .line 1
    const/4 v0, 0x1

    .line 2
    if-nez p2, :cond_1

    .line 3
    .line 4
    iget p2, p0, Lh5/e;->A0:I

    .line 5
    .line 6
    add-int/2addr p2, v0

    .line 7
    iget-object v1, p0, Lh5/e;->D0:[Lh5/b;

    .line 8
    .line 9
    array-length v2, v1

    .line 10
    if-lt p2, v2, :cond_0

    .line 11
    .line 12
    array-length p2, v1

    .line 13
    mul-int/lit8 p2, p2, 0x2

    .line 14
    .line 15
    invoke-static {v1, p2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p2

    .line 19
    check-cast p2, [Lh5/b;

    .line 20
    .line 21
    iput-object p2, p0, Lh5/e;->D0:[Lh5/b;

    .line 22
    .line 23
    :cond_0
    iget-object p2, p0, Lh5/e;->D0:[Lh5/b;

    .line 24
    .line 25
    iget v1, p0, Lh5/e;->A0:I

    .line 26
    .line 27
    new-instance v2, Lh5/b;

    .line 28
    .line 29
    const/4 v3, 0x0

    .line 30
    iget-boolean v4, p0, Lh5/e;->w0:Z

    .line 31
    .line 32
    invoke-direct {v2, p1, v3, v4}, Lh5/b;-><init>(Lh5/d;IZ)V

    .line 33
    .line 34
    .line 35
    aput-object v2, p2, v1

    .line 36
    .line 37
    add-int/2addr v1, v0

    .line 38
    iput v1, p0, Lh5/e;->A0:I

    .line 39
    .line 40
    return-void

    .line 41
    :cond_1
    if-ne p2, v0, :cond_3

    .line 42
    .line 43
    iget p2, p0, Lh5/e;->B0:I

    .line 44
    .line 45
    add-int/2addr p2, v0

    .line 46
    iget-object v1, p0, Lh5/e;->C0:[Lh5/b;

    .line 47
    .line 48
    array-length v2, v1

    .line 49
    if-lt p2, v2, :cond_2

    .line 50
    .line 51
    array-length p2, v1

    .line 52
    mul-int/lit8 p2, p2, 0x2

    .line 53
    .line 54
    invoke-static {v1, p2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object p2

    .line 58
    check-cast p2, [Lh5/b;

    .line 59
    .line 60
    iput-object p2, p0, Lh5/e;->C0:[Lh5/b;

    .line 61
    .line 62
    :cond_2
    iget-object p2, p0, Lh5/e;->C0:[Lh5/b;

    .line 63
    .line 64
    iget v1, p0, Lh5/e;->B0:I

    .line 65
    .line 66
    new-instance v2, Lh5/b;

    .line 67
    .line 68
    iget-boolean v3, p0, Lh5/e;->w0:Z

    .line 69
    .line 70
    invoke-direct {v2, p1, v0, v3}, Lh5/b;-><init>(Lh5/d;IZ)V

    .line 71
    .line 72
    .line 73
    aput-object v2, p2, v1

    .line 74
    .line 75
    add-int/2addr v1, v0

    .line 76
    iput v1, p0, Lh5/e;->B0:I

    .line 77
    .line 78
    :cond_3
    return-void
.end method

.method public final X(La5/c;)V
    .locals 13

    .line 1
    iget-object v0, p0, Lh5/e;->L0:Ljava/util/HashSet;

    .line 2
    .line 3
    const/16 v1, 0x40

    .line 4
    .line 5
    invoke-virtual {p0, v1}, Lh5/e;->c0(I)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    invoke-virtual {p0, p1, v1}, Lh5/d;->c(La5/c;Z)V

    .line 10
    .line 11
    .line 12
    iget-object v2, p0, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 13
    .line 14
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    const/4 v3, 0x0

    .line 19
    move v4, v3

    .line 20
    move v5, v4

    .line 21
    :goto_0
    const/4 v6, 0x1

    .line 22
    if-ge v4, v2, :cond_1

    .line 23
    .line 24
    iget-object v7, p0, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 25
    .line 26
    invoke-virtual {v7, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v7

    .line 30
    check-cast v7, Lh5/d;

    .line 31
    .line 32
    iget-object v8, v7, Lh5/d;->T:[Z

    .line 33
    .line 34
    aput-boolean v3, v8, v3

    .line 35
    .line 36
    aput-boolean v3, v8, v6

    .line 37
    .line 38
    instance-of v7, v7, Lh5/a;

    .line 39
    .line 40
    if-eqz v7, :cond_0

    .line 41
    .line 42
    move v5, v6

    .line 43
    :cond_0
    add-int/lit8 v4, v4, 0x1

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_1
    const/4 v4, 0x2

    .line 47
    if-eqz v5, :cond_8

    .line 48
    .line 49
    move v5, v3

    .line 50
    :goto_1
    if-ge v5, v2, :cond_8

    .line 51
    .line 52
    iget-object v7, p0, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 53
    .line 54
    invoke-virtual {v7, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v7

    .line 58
    check-cast v7, Lh5/d;

    .line 59
    .line 60
    instance-of v8, v7, Lh5/a;

    .line 61
    .line 62
    if-eqz v8, :cond_7

    .line 63
    .line 64
    check-cast v7, Lh5/a;

    .line 65
    .line 66
    move v8, v3

    .line 67
    :goto_2
    iget v9, v7, Lh5/i;->s0:I

    .line 68
    .line 69
    if-ge v8, v9, :cond_7

    .line 70
    .line 71
    iget-object v9, v7, Lh5/i;->r0:[Lh5/d;

    .line 72
    .line 73
    aget-object v9, v9, v8

    .line 74
    .line 75
    iget-boolean v10, v7, Lh5/a;->u0:Z

    .line 76
    .line 77
    if-nez v10, :cond_2

    .line 78
    .line 79
    invoke-virtual {v9}, Lh5/d;->d()Z

    .line 80
    .line 81
    .line 82
    move-result v10

    .line 83
    if-nez v10, :cond_2

    .line 84
    .line 85
    goto :goto_4

    .line 86
    :cond_2
    iget v10, v7, Lh5/a;->t0:I

    .line 87
    .line 88
    if-eqz v10, :cond_5

    .line 89
    .line 90
    if-ne v10, v6, :cond_3

    .line 91
    .line 92
    goto :goto_3

    .line 93
    :cond_3
    if-eq v10, v4, :cond_4

    .line 94
    .line 95
    const/4 v11, 0x3

    .line 96
    if-ne v10, v11, :cond_6

    .line 97
    .line 98
    :cond_4
    iget-object v9, v9, Lh5/d;->T:[Z

    .line 99
    .line 100
    aput-boolean v6, v9, v6

    .line 101
    .line 102
    goto :goto_4

    .line 103
    :cond_5
    :goto_3
    iget-object v9, v9, Lh5/d;->T:[Z

    .line 104
    .line 105
    aput-boolean v6, v9, v3

    .line 106
    .line 107
    :cond_6
    :goto_4
    add-int/lit8 v8, v8, 0x1

    .line 108
    .line 109
    goto :goto_2

    .line 110
    :cond_7
    add-int/lit8 v5, v5, 0x1

    .line 111
    .line 112
    goto :goto_1

    .line 113
    :cond_8
    invoke-virtual {v0}, Ljava/util/HashSet;->clear()V

    .line 114
    .line 115
    .line 116
    move v5, v3

    .line 117
    :goto_5
    if-ge v5, v2, :cond_c

    .line 118
    .line 119
    iget-object v7, p0, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 120
    .line 121
    invoke-virtual {v7, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v7

    .line 125
    check-cast v7, Lh5/d;

    .line 126
    .line 127
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 128
    .line 129
    .line 130
    instance-of v8, v7, Lh5/k;

    .line 131
    .line 132
    if-nez v8, :cond_9

    .line 133
    .line 134
    instance-of v9, v7, Lh5/h;

    .line 135
    .line 136
    if-eqz v9, :cond_b

    .line 137
    .line 138
    :cond_9
    if-eqz v8, :cond_a

    .line 139
    .line 140
    invoke-virtual {v0, v7}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 141
    .line 142
    .line 143
    goto :goto_6

    .line 144
    :cond_a
    invoke-virtual {v7, p1, v1}, Lh5/d;->c(La5/c;Z)V

    .line 145
    .line 146
    .line 147
    :cond_b
    :goto_6
    add-int/lit8 v5, v5, 0x1

    .line 148
    .line 149
    goto :goto_5

    .line 150
    :cond_c
    :goto_7
    invoke-virtual {v0}, Ljava/util/HashSet;->size()I

    .line 151
    .line 152
    .line 153
    move-result v5

    .line 154
    if-lez v5, :cond_11

    .line 155
    .line 156
    invoke-virtual {v0}, Ljava/util/HashSet;->size()I

    .line 157
    .line 158
    .line 159
    move-result v5

    .line 160
    invoke-virtual {v0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 161
    .line 162
    .line 163
    move-result-object v7

    .line 164
    :cond_d
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 165
    .line 166
    .line 167
    move-result v8

    .line 168
    if-eqz v8, :cond_f

    .line 169
    .line 170
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 171
    .line 172
    .line 173
    move-result-object v8

    .line 174
    check-cast v8, Lh5/d;

    .line 175
    .line 176
    check-cast v8, Lh5/k;

    .line 177
    .line 178
    move v9, v3

    .line 179
    :goto_8
    iget v10, v8, Lh5/i;->s0:I

    .line 180
    .line 181
    if-ge v9, v10, :cond_d

    .line 182
    .line 183
    iget-object v10, v8, Lh5/i;->r0:[Lh5/d;

    .line 184
    .line 185
    aget-object v10, v10, v9

    .line 186
    .line 187
    invoke-virtual {v0, v10}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 188
    .line 189
    .line 190
    move-result v10

    .line 191
    if-eqz v10, :cond_e

    .line 192
    .line 193
    invoke-virtual {v8, p1, v1}, Lh5/d;->c(La5/c;Z)V

    .line 194
    .line 195
    .line 196
    invoke-virtual {v0, v8}, Ljava/util/HashSet;->remove(Ljava/lang/Object;)Z

    .line 197
    .line 198
    .line 199
    goto :goto_9

    .line 200
    :cond_e
    add-int/lit8 v9, v9, 0x1

    .line 201
    .line 202
    goto :goto_8

    .line 203
    :cond_f
    :goto_9
    invoke-virtual {v0}, Ljava/util/HashSet;->size()I

    .line 204
    .line 205
    .line 206
    move-result v7

    .line 207
    if-ne v5, v7, :cond_c

    .line 208
    .line 209
    invoke-virtual {v0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 210
    .line 211
    .line 212
    move-result-object v5

    .line 213
    :goto_a
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 214
    .line 215
    .line 216
    move-result v7

    .line 217
    if-eqz v7, :cond_10

    .line 218
    .line 219
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 220
    .line 221
    .line 222
    move-result-object v7

    .line 223
    check-cast v7, Lh5/d;

    .line 224
    .line 225
    invoke-virtual {v7, p1, v1}, Lh5/d;->c(La5/c;Z)V

    .line 226
    .line 227
    .line 228
    goto :goto_a

    .line 229
    :cond_10
    invoke-virtual {v0}, Ljava/util/HashSet;->clear()V

    .line 230
    .line 231
    .line 232
    goto :goto_7

    .line 233
    :cond_11
    sget-boolean v0, La5/c;->q:Z

    .line 234
    .line 235
    if-eqz v0, :cond_16

    .line 236
    .line 237
    new-instance v10, Ljava/util/HashSet;

    .line 238
    .line 239
    invoke-direct {v10}, Ljava/util/HashSet;-><init>()V

    .line 240
    .line 241
    .line 242
    move v0, v3

    .line 243
    :goto_b
    if-ge v0, v2, :cond_14

    .line 244
    .line 245
    iget-object v5, p0, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 246
    .line 247
    invoke-virtual {v5, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    move-result-object v5

    .line 251
    check-cast v5, Lh5/d;

    .line 252
    .line 253
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 254
    .line 255
    .line 256
    instance-of v7, v5, Lh5/k;

    .line 257
    .line 258
    if-nez v7, :cond_13

    .line 259
    .line 260
    instance-of v7, v5, Lh5/h;

    .line 261
    .line 262
    if-eqz v7, :cond_12

    .line 263
    .line 264
    goto :goto_c

    .line 265
    :cond_12
    invoke-virtual {v10, v5}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 266
    .line 267
    .line 268
    :cond_13
    :goto_c
    add-int/lit8 v0, v0, 0x1

    .line 269
    .line 270
    goto :goto_b

    .line 271
    :cond_14
    iget-object v0, p0, Lh5/d;->q0:[I

    .line 272
    .line 273
    aget v0, v0, v3

    .line 274
    .line 275
    if-ne v0, v4, :cond_15

    .line 276
    .line 277
    move v11, v3

    .line 278
    goto :goto_d

    .line 279
    :cond_15
    move v11, v6

    .line 280
    :goto_d
    const/4 v12, 0x0

    .line 281
    move-object v8, p0

    .line 282
    move-object v7, p0

    .line 283
    move-object v9, p1

    .line 284
    invoke-virtual/range {v7 .. v12}, Lh5/d;->b(Lh5/e;La5/c;Ljava/util/HashSet;IZ)V

    .line 285
    .line 286
    .line 287
    invoke-virtual {v10}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 288
    .line 289
    .line 290
    move-result-object p0

    .line 291
    :goto_e
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 292
    .line 293
    .line 294
    move-result p1

    .line 295
    if-eqz p1, :cond_1d

    .line 296
    .line 297
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 298
    .line 299
    .line 300
    move-result-object p1

    .line 301
    check-cast p1, Lh5/d;

    .line 302
    .line 303
    invoke-static {v7, v9, p1}, Lh5/j;->b(Lh5/e;La5/c;Lh5/d;)V

    .line 304
    .line 305
    .line 306
    invoke-virtual {p1, v9, v1}, Lh5/d;->c(La5/c;Z)V

    .line 307
    .line 308
    .line 309
    goto :goto_e

    .line 310
    :cond_16
    move-object v7, p0

    .line 311
    move-object v9, p1

    .line 312
    move p0, v3

    .line 313
    :goto_f
    if-ge p0, v2, :cond_1d

    .line 314
    .line 315
    iget-object p1, v7, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 316
    .line 317
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 318
    .line 319
    .line 320
    move-result-object p1

    .line 321
    check-cast p1, Lh5/d;

    .line 322
    .line 323
    instance-of v0, p1, Lh5/e;

    .line 324
    .line 325
    if-eqz v0, :cond_1a

    .line 326
    .line 327
    iget-object v0, p1, Lh5/d;->q0:[I

    .line 328
    .line 329
    aget v5, v0, v3

    .line 330
    .line 331
    aget v0, v0, v6

    .line 332
    .line 333
    if-ne v5, v4, :cond_17

    .line 334
    .line 335
    invoke-virtual {p1, v6}, Lh5/d;->O(I)V

    .line 336
    .line 337
    .line 338
    :cond_17
    if-ne v0, v4, :cond_18

    .line 339
    .line 340
    invoke-virtual {p1, v6}, Lh5/d;->Q(I)V

    .line 341
    .line 342
    .line 343
    :cond_18
    invoke-virtual {p1, v9, v1}, Lh5/d;->c(La5/c;Z)V

    .line 344
    .line 345
    .line 346
    if-ne v5, v4, :cond_19

    .line 347
    .line 348
    invoke-virtual {p1, v5}, Lh5/d;->O(I)V

    .line 349
    .line 350
    .line 351
    :cond_19
    if-ne v0, v4, :cond_1c

    .line 352
    .line 353
    invoke-virtual {p1, v0}, Lh5/d;->Q(I)V

    .line 354
    .line 355
    .line 356
    goto :goto_10

    .line 357
    :cond_1a
    invoke-static {v7, v9, p1}, Lh5/j;->b(Lh5/e;La5/c;Lh5/d;)V

    .line 358
    .line 359
    .line 360
    instance-of v0, p1, Lh5/k;

    .line 361
    .line 362
    if-nez v0, :cond_1c

    .line 363
    .line 364
    instance-of v0, p1, Lh5/h;

    .line 365
    .line 366
    if-eqz v0, :cond_1b

    .line 367
    .line 368
    goto :goto_10

    .line 369
    :cond_1b
    invoke-virtual {p1, v9, v1}, Lh5/d;->c(La5/c;Z)V

    .line 370
    .line 371
    .line 372
    :cond_1c
    :goto_10
    add-int/lit8 p0, p0, 0x1

    .line 373
    .line 374
    goto :goto_f

    .line 375
    :cond_1d
    iget p0, v7, Lh5/e;->A0:I

    .line 376
    .line 377
    const/4 p1, 0x0

    .line 378
    if-lez p0, :cond_1e

    .line 379
    .line 380
    invoke-static {v7, v9, p1, v3}, Lh5/j;->a(Lh5/e;La5/c;Ljava/util/ArrayList;I)V

    .line 381
    .line 382
    .line 383
    :cond_1e
    iget p0, v7, Lh5/e;->B0:I

    .line 384
    .line 385
    if-lez p0, :cond_1f

    .line 386
    .line 387
    invoke-static {v7, v9, p1, v6}, Lh5/j;->a(Lh5/e;La5/c;Ljava/util/ArrayList;I)V

    .line 388
    .line 389
    .line 390
    :cond_1f
    return-void
.end method

.method public final Y(IZ)Z
    .locals 13

    .line 1
    iget-object p0, p0, Lh5/e;->t0:Li5/f;

    .line 2
    .line 3
    iget-object v0, p0, Li5/f;->f:Ljava/io/Serializable;

    .line 4
    .line 5
    check-cast v0, Ljava/util/ArrayList;

    .line 6
    .line 7
    iget-object v1, p0, Li5/f;->d:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v1, Lh5/e;

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    invoke-virtual {v1, v2}, Lh5/d;->k(I)I

    .line 13
    .line 14
    .line 15
    move-result v3

    .line 16
    iget-object v4, v1, Lh5/d;->q0:[I

    .line 17
    .line 18
    const/4 v5, 0x1

    .line 19
    invoke-virtual {v1, v5}, Lh5/d;->k(I)I

    .line 20
    .line 21
    .line 22
    move-result v6

    .line 23
    invoke-virtual {v1}, Lh5/d;->s()I

    .line 24
    .line 25
    .line 26
    move-result v7

    .line 27
    invoke-virtual {v1}, Lh5/d;->t()I

    .line 28
    .line 29
    .line 30
    move-result v8

    .line 31
    if-eqz p2, :cond_4

    .line 32
    .line 33
    const/4 v9, 0x2

    .line 34
    if-eq v3, v9, :cond_0

    .line 35
    .line 36
    if-ne v6, v9, :cond_4

    .line 37
    .line 38
    :cond_0
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 39
    .line 40
    .line 41
    move-result-object v10

    .line 42
    :cond_1
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 43
    .line 44
    .line 45
    move-result v11

    .line 46
    if-eqz v11, :cond_2

    .line 47
    .line 48
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v11

    .line 52
    check-cast v11, Li5/p;

    .line 53
    .line 54
    iget v12, v11, Li5/p;->f:I

    .line 55
    .line 56
    if-ne v12, p1, :cond_1

    .line 57
    .line 58
    invoke-virtual {v11}, Li5/p;->k()Z

    .line 59
    .line 60
    .line 61
    move-result v11

    .line 62
    if-nez v11, :cond_1

    .line 63
    .line 64
    move p2, v2

    .line 65
    :cond_2
    if-nez p1, :cond_3

    .line 66
    .line 67
    if-eqz p2, :cond_4

    .line 68
    .line 69
    if-ne v3, v9, :cond_4

    .line 70
    .line 71
    invoke-virtual {v1, v5}, Lh5/d;->O(I)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {p0, v1, v2}, Li5/f;->d(Lh5/e;I)I

    .line 75
    .line 76
    .line 77
    move-result p2

    .line 78
    invoke-virtual {v1, p2}, Lh5/d;->S(I)V

    .line 79
    .line 80
    .line 81
    iget-object p2, v1, Lh5/d;->d:Li5/l;

    .line 82
    .line 83
    iget-object p2, p2, Li5/p;->e:Li5/h;

    .line 84
    .line 85
    invoke-virtual {v1}, Lh5/d;->r()I

    .line 86
    .line 87
    .line 88
    move-result v9

    .line 89
    invoke-virtual {p2, v9}, Li5/h;->d(I)V

    .line 90
    .line 91
    .line 92
    goto :goto_0

    .line 93
    :cond_3
    if-eqz p2, :cond_4

    .line 94
    .line 95
    if-ne v6, v9, :cond_4

    .line 96
    .line 97
    invoke-virtual {v1, v5}, Lh5/d;->Q(I)V

    .line 98
    .line 99
    .line 100
    invoke-virtual {p0, v1, v5}, Li5/f;->d(Lh5/e;I)I

    .line 101
    .line 102
    .line 103
    move-result p2

    .line 104
    invoke-virtual {v1, p2}, Lh5/d;->N(I)V

    .line 105
    .line 106
    .line 107
    iget-object p2, v1, Lh5/d;->e:Li5/n;

    .line 108
    .line 109
    iget-object p2, p2, Li5/p;->e:Li5/h;

    .line 110
    .line 111
    invoke-virtual {v1}, Lh5/d;->l()I

    .line 112
    .line 113
    .line 114
    move-result v9

    .line 115
    invoke-virtual {p2, v9}, Li5/h;->d(I)V

    .line 116
    .line 117
    .line 118
    :cond_4
    :goto_0
    const/4 p2, 0x4

    .line 119
    if-nez p1, :cond_6

    .line 120
    .line 121
    aget v4, v4, v2

    .line 122
    .line 123
    if-eq v4, v5, :cond_5

    .line 124
    .line 125
    if-ne v4, p2, :cond_7

    .line 126
    .line 127
    :cond_5
    invoke-virtual {v1}, Lh5/d;->r()I

    .line 128
    .line 129
    .line 130
    move-result p2

    .line 131
    add-int/2addr p2, v7

    .line 132
    iget-object v4, v1, Lh5/d;->d:Li5/l;

    .line 133
    .line 134
    iget-object v4, v4, Li5/p;->i:Li5/g;

    .line 135
    .line 136
    invoke-virtual {v4, p2}, Li5/g;->d(I)V

    .line 137
    .line 138
    .line 139
    iget-object v4, v1, Lh5/d;->d:Li5/l;

    .line 140
    .line 141
    iget-object v4, v4, Li5/p;->e:Li5/h;

    .line 142
    .line 143
    sub-int/2addr p2, v7

    .line 144
    invoke-virtual {v4, p2}, Li5/h;->d(I)V

    .line 145
    .line 146
    .line 147
    :goto_1
    move p2, v5

    .line 148
    goto :goto_3

    .line 149
    :cond_6
    aget v4, v4, v5

    .line 150
    .line 151
    if-eq v4, v5, :cond_8

    .line 152
    .line 153
    if-ne v4, p2, :cond_7

    .line 154
    .line 155
    goto :goto_2

    .line 156
    :cond_7
    move p2, v2

    .line 157
    goto :goto_3

    .line 158
    :cond_8
    :goto_2
    invoke-virtual {v1}, Lh5/d;->l()I

    .line 159
    .line 160
    .line 161
    move-result p2

    .line 162
    add-int/2addr p2, v8

    .line 163
    iget-object v4, v1, Lh5/d;->e:Li5/n;

    .line 164
    .line 165
    iget-object v4, v4, Li5/p;->i:Li5/g;

    .line 166
    .line 167
    invoke-virtual {v4, p2}, Li5/g;->d(I)V

    .line 168
    .line 169
    .line 170
    iget-object v4, v1, Lh5/d;->e:Li5/n;

    .line 171
    .line 172
    iget-object v4, v4, Li5/p;->e:Li5/h;

    .line 173
    .line 174
    sub-int/2addr p2, v8

    .line 175
    invoke-virtual {v4, p2}, Li5/h;->d(I)V

    .line 176
    .line 177
    .line 178
    goto :goto_1

    .line 179
    :goto_3
    invoke-virtual {p0}, Li5/f;->g()V

    .line 180
    .line 181
    .line 182
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 183
    .line 184
    .line 185
    move-result-object p0

    .line 186
    :goto_4
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 187
    .line 188
    .line 189
    move-result v4

    .line 190
    if-eqz v4, :cond_b

    .line 191
    .line 192
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object v4

    .line 196
    check-cast v4, Li5/p;

    .line 197
    .line 198
    iget v7, v4, Li5/p;->f:I

    .line 199
    .line 200
    if-eq v7, p1, :cond_9

    .line 201
    .line 202
    goto :goto_4

    .line 203
    :cond_9
    iget-object v7, v4, Li5/p;->b:Lh5/d;

    .line 204
    .line 205
    if-ne v7, v1, :cond_a

    .line 206
    .line 207
    iget-boolean v7, v4, Li5/p;->g:Z

    .line 208
    .line 209
    if-nez v7, :cond_a

    .line 210
    .line 211
    goto :goto_4

    .line 212
    :cond_a
    invoke-virtual {v4}, Li5/p;->e()V

    .line 213
    .line 214
    .line 215
    goto :goto_4

    .line 216
    :cond_b
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 217
    .line 218
    .line 219
    move-result-object p0

    .line 220
    :cond_c
    :goto_5
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 221
    .line 222
    .line 223
    move-result v0

    .line 224
    if-eqz v0, :cond_11

    .line 225
    .line 226
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object v0

    .line 230
    check-cast v0, Li5/p;

    .line 231
    .line 232
    iget v4, v0, Li5/p;->f:I

    .line 233
    .line 234
    if-eq v4, p1, :cond_d

    .line 235
    .line 236
    goto :goto_5

    .line 237
    :cond_d
    if-nez p2, :cond_e

    .line 238
    .line 239
    iget-object v4, v0, Li5/p;->b:Lh5/d;

    .line 240
    .line 241
    if-ne v4, v1, :cond_e

    .line 242
    .line 243
    goto :goto_5

    .line 244
    :cond_e
    iget-object v4, v0, Li5/p;->h:Li5/g;

    .line 245
    .line 246
    iget-boolean v4, v4, Li5/g;->j:Z

    .line 247
    .line 248
    if-nez v4, :cond_f

    .line 249
    .line 250
    goto :goto_6

    .line 251
    :cond_f
    iget-object v4, v0, Li5/p;->i:Li5/g;

    .line 252
    .line 253
    iget-boolean v4, v4, Li5/g;->j:Z

    .line 254
    .line 255
    if-nez v4, :cond_10

    .line 256
    .line 257
    goto :goto_6

    .line 258
    :cond_10
    instance-of v4, v0, Li5/d;

    .line 259
    .line 260
    if-nez v4, :cond_c

    .line 261
    .line 262
    iget-object v0, v0, Li5/p;->e:Li5/h;

    .line 263
    .line 264
    iget-boolean v0, v0, Li5/g;->j:Z

    .line 265
    .line 266
    if-nez v0, :cond_c

    .line 267
    .line 268
    goto :goto_6

    .line 269
    :cond_11
    move v2, v5

    .line 270
    :goto_6
    invoke-virtual {v1, v3}, Lh5/d;->O(I)V

    .line 271
    .line 272
    .line 273
    invoke-virtual {v1, v6}, Lh5/d;->Q(I)V

    .line 274
    .line 275
    .line 276
    return v2
.end method

.method public final Z()V
    .locals 33

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    iget-object v2, v1, Lh5/e;->x0:La5/c;

    .line 4
    .line 5
    const/4 v3, 0x0

    .line 6
    iput v3, v1, Lh5/d;->Z:I

    .line 7
    .line 8
    iput v3, v1, Lh5/d;->a0:I

    .line 9
    .line 10
    iput-boolean v3, v1, Lh5/e;->F0:Z

    .line 11
    .line 12
    iput-boolean v3, v1, Lh5/e;->G0:Z

    .line 13
    .line 14
    iget-object v0, v1, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 15
    .line 16
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 17
    .line 18
    .line 19
    move-result v4

    .line 20
    invoke-virtual {v1}, Lh5/d;->r()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    invoke-static {v3, v0}, Ljava/lang/Math;->max(II)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    invoke-virtual {v1}, Lh5/d;->l()I

    .line 29
    .line 30
    .line 31
    move-result v5

    .line 32
    invoke-static {v3, v5}, Ljava/lang/Math;->max(II)I

    .line 33
    .line 34
    .line 35
    move-result v5

    .line 36
    iget-object v6, v1, Lh5/d;->q0:[I

    .line 37
    .line 38
    const/4 v7, 0x1

    .line 39
    aget v8, v6, v7

    .line 40
    .line 41
    aget v9, v6, v3

    .line 42
    .line 43
    iget v10, v1, Lh5/e;->u0:I

    .line 44
    .line 45
    iget-object v12, v1, Lh5/d;->K:Lh5/c;

    .line 46
    .line 47
    iget-object v13, v1, Lh5/d;->J:Lh5/c;

    .line 48
    .line 49
    if-nez v10, :cond_1e

    .line 50
    .line 51
    iget v10, v1, Lh5/e;->E0:I

    .line 52
    .line 53
    invoke-static {v10, v7}, Lh5/j;->c(II)Z

    .line 54
    .line 55
    .line 56
    move-result v10

    .line 57
    if-eqz v10, :cond_1e

    .line 58
    .line 59
    iget-object v10, v1, Lh5/e;->v0:Li5/c;

    .line 60
    .line 61
    aget v15, v6, v3

    .line 62
    .line 63
    aget v11, v6, v7

    .line 64
    .line 65
    invoke-virtual {v1}, Lh5/d;->F()V

    .line 66
    .line 67
    .line 68
    iget-object v14, v1, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 69
    .line 70
    invoke-virtual {v14}, Ljava/util/ArrayList;->size()I

    .line 71
    .line 72
    .line 73
    move-result v3

    .line 74
    const/4 v7, 0x0

    .line 75
    :goto_0
    if-ge v7, v3, :cond_0

    .line 76
    .line 77
    invoke-virtual {v14, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v19

    .line 81
    check-cast v19, Lh5/d;

    .line 82
    .line 83
    invoke-virtual/range {v19 .. v19}, Lh5/d;->F()V

    .line 84
    .line 85
    .line 86
    add-int/lit8 v7, v7, 0x1

    .line 87
    .line 88
    goto :goto_0

    .line 89
    :cond_0
    iget-boolean v7, v1, Lh5/e;->w0:Z

    .line 90
    .line 91
    move-object/from16 v19, v6

    .line 92
    .line 93
    const/4 v6, 0x1

    .line 94
    if-ne v15, v6, :cond_1

    .line 95
    .line 96
    invoke-virtual {v1}, Lh5/d;->r()I

    .line 97
    .line 98
    .line 99
    move-result v6

    .line 100
    const/4 v15, 0x0

    .line 101
    invoke-virtual {v1, v15, v6}, Lh5/d;->L(II)V

    .line 102
    .line 103
    .line 104
    goto :goto_1

    .line 105
    :cond_1
    const/4 v15, 0x0

    .line 106
    invoke-virtual {v13, v15}, Lh5/c;->l(I)V

    .line 107
    .line 108
    .line 109
    iput v15, v1, Lh5/d;->Z:I

    .line 110
    .line 111
    :goto_1
    const/4 v6, 0x0

    .line 112
    const/4 v15, 0x0

    .line 113
    const/16 v20, 0x0

    .line 114
    .line 115
    :goto_2
    const/high16 v21, 0x3f000000    # 0.5f

    .line 116
    .line 117
    if-ge v6, v3, :cond_7

    .line 118
    .line 119
    invoke-virtual {v14, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object v22

    .line 123
    move/from16 v23, v6

    .line 124
    .line 125
    move-object/from16 v6, v22

    .line 126
    .line 127
    check-cast v6, Lh5/d;

    .line 128
    .line 129
    move/from16 v22, v15

    .line 130
    .line 131
    instance-of v15, v6, Lh5/h;

    .line 132
    .line 133
    if-eqz v15, :cond_6

    .line 134
    .line 135
    check-cast v6, Lh5/h;

    .line 136
    .line 137
    iget v15, v6, Lh5/h;->v0:I

    .line 138
    .line 139
    move-object/from16 v24, v13

    .line 140
    .line 141
    const/4 v13, 0x1

    .line 142
    if-ne v15, v13, :cond_5

    .line 143
    .line 144
    iget v13, v6, Lh5/h;->s0:I

    .line 145
    .line 146
    const/4 v15, -0x1

    .line 147
    if-eq v13, v15, :cond_2

    .line 148
    .line 149
    invoke-virtual {v6, v13}, Lh5/h;->V(I)V

    .line 150
    .line 151
    .line 152
    goto :goto_3

    .line 153
    :cond_2
    iget v13, v6, Lh5/h;->t0:I

    .line 154
    .line 155
    if-eq v13, v15, :cond_3

    .line 156
    .line 157
    invoke-virtual {v1}, Lh5/d;->B()Z

    .line 158
    .line 159
    .line 160
    move-result v13

    .line 161
    if-eqz v13, :cond_3

    .line 162
    .line 163
    invoke-virtual {v1}, Lh5/d;->r()I

    .line 164
    .line 165
    .line 166
    move-result v13

    .line 167
    iget v15, v6, Lh5/h;->t0:I

    .line 168
    .line 169
    sub-int/2addr v13, v15

    .line 170
    invoke-virtual {v6, v13}, Lh5/h;->V(I)V

    .line 171
    .line 172
    .line 173
    goto :goto_3

    .line 174
    :cond_3
    invoke-virtual {v1}, Lh5/d;->B()Z

    .line 175
    .line 176
    .line 177
    move-result v13

    .line 178
    if-eqz v13, :cond_4

    .line 179
    .line 180
    iget v13, v6, Lh5/h;->r0:F

    .line 181
    .line 182
    invoke-virtual {v1}, Lh5/d;->r()I

    .line 183
    .line 184
    .line 185
    move-result v15

    .line 186
    int-to-float v15, v15

    .line 187
    mul-float/2addr v13, v15

    .line 188
    add-float v13, v13, v21

    .line 189
    .line 190
    float-to-int v13, v13

    .line 191
    invoke-virtual {v6, v13}, Lh5/h;->V(I)V

    .line 192
    .line 193
    .line 194
    :cond_4
    :goto_3
    const/16 v22, 0x1

    .line 195
    .line 196
    :cond_5
    move/from16 v15, v22

    .line 197
    .line 198
    goto :goto_4

    .line 199
    :cond_6
    move-object/from16 v24, v13

    .line 200
    .line 201
    instance-of v13, v6, Lh5/a;

    .line 202
    .line 203
    if-eqz v13, :cond_5

    .line 204
    .line 205
    check-cast v6, Lh5/a;

    .line 206
    .line 207
    invoke-virtual {v6}, Lh5/a;->Z()I

    .line 208
    .line 209
    .line 210
    move-result v6

    .line 211
    if-nez v6, :cond_5

    .line 212
    .line 213
    move/from16 v15, v22

    .line 214
    .line 215
    const/16 v20, 0x1

    .line 216
    .line 217
    :goto_4
    add-int/lit8 v6, v23, 0x1

    .line 218
    .line 219
    move-object/from16 v13, v24

    .line 220
    .line 221
    goto :goto_2

    .line 222
    :cond_7
    move-object/from16 v24, v13

    .line 223
    .line 224
    move/from16 v22, v15

    .line 225
    .line 226
    if-eqz v22, :cond_a

    .line 227
    .line 228
    const/4 v6, 0x0

    .line 229
    :goto_5
    if-ge v6, v3, :cond_a

    .line 230
    .line 231
    invoke-virtual {v14, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    move-result-object v13

    .line 235
    check-cast v13, Lh5/d;

    .line 236
    .line 237
    instance-of v15, v13, Lh5/h;

    .line 238
    .line 239
    if-eqz v15, :cond_9

    .line 240
    .line 241
    check-cast v13, Lh5/h;

    .line 242
    .line 243
    iget v15, v13, Lh5/h;->v0:I

    .line 244
    .line 245
    move/from16 v22, v6

    .line 246
    .line 247
    const/4 v6, 0x1

    .line 248
    if-ne v15, v6, :cond_8

    .line 249
    .line 250
    const/4 v15, 0x0

    .line 251
    invoke-static {v15, v13, v10, v7}, Li5/i;->c(ILh5/d;Li5/c;Z)V

    .line 252
    .line 253
    .line 254
    goto :goto_7

    .line 255
    :cond_8
    :goto_6
    const/4 v15, 0x0

    .line 256
    goto :goto_7

    .line 257
    :cond_9
    move/from16 v22, v6

    .line 258
    .line 259
    goto :goto_6

    .line 260
    :goto_7
    add-int/lit8 v6, v22, 0x1

    .line 261
    .line 262
    goto :goto_5

    .line 263
    :cond_a
    const/4 v15, 0x0

    .line 264
    invoke-static {v15, v1, v10, v7}, Li5/i;->c(ILh5/d;Li5/c;Z)V

    .line 265
    .line 266
    .line 267
    if-eqz v20, :cond_c

    .line 268
    .line 269
    const/4 v6, 0x0

    .line 270
    :goto_8
    if-ge v6, v3, :cond_c

    .line 271
    .line 272
    invoke-virtual {v14, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 273
    .line 274
    .line 275
    move-result-object v13

    .line 276
    check-cast v13, Lh5/d;

    .line 277
    .line 278
    instance-of v15, v13, Lh5/a;

    .line 279
    .line 280
    if-eqz v15, :cond_b

    .line 281
    .line 282
    check-cast v13, Lh5/a;

    .line 283
    .line 284
    invoke-virtual {v13}, Lh5/a;->Z()I

    .line 285
    .line 286
    .line 287
    move-result v15

    .line 288
    if-nez v15, :cond_b

    .line 289
    .line 290
    invoke-virtual {v13}, Lh5/a;->Y()Z

    .line 291
    .line 292
    .line 293
    move-result v15

    .line 294
    if-eqz v15, :cond_b

    .line 295
    .line 296
    const/4 v15, 0x1

    .line 297
    invoke-static {v15, v13, v10, v7}, Li5/i;->c(ILh5/d;Li5/c;Z)V

    .line 298
    .line 299
    .line 300
    goto :goto_9

    .line 301
    :cond_b
    const/4 v15, 0x1

    .line 302
    :goto_9
    add-int/lit8 v6, v6, 0x1

    .line 303
    .line 304
    goto :goto_8

    .line 305
    :cond_c
    const/4 v15, 0x1

    .line 306
    if-ne v11, v15, :cond_d

    .line 307
    .line 308
    invoke-virtual {v1}, Lh5/d;->l()I

    .line 309
    .line 310
    .line 311
    move-result v6

    .line 312
    const/4 v15, 0x0

    .line 313
    invoke-virtual {v1, v15, v6}, Lh5/d;->M(II)V

    .line 314
    .line 315
    .line 316
    goto :goto_a

    .line 317
    :cond_d
    const/4 v15, 0x0

    .line 318
    invoke-virtual {v12, v15}, Lh5/c;->l(I)V

    .line 319
    .line 320
    .line 321
    iput v15, v1, Lh5/d;->a0:I

    .line 322
    .line 323
    :goto_a
    const/4 v6, 0x0

    .line 324
    const/4 v11, 0x0

    .line 325
    const/4 v13, 0x0

    .line 326
    :goto_b
    if-ge v6, v3, :cond_13

    .line 327
    .line 328
    invoke-virtual {v14, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 329
    .line 330
    .line 331
    move-result-object v15

    .line 332
    check-cast v15, Lh5/d;

    .line 333
    .line 334
    move/from16 v20, v6

    .line 335
    .line 336
    instance-of v6, v15, Lh5/h;

    .line 337
    .line 338
    if-eqz v6, :cond_11

    .line 339
    .line 340
    check-cast v15, Lh5/h;

    .line 341
    .line 342
    iget v6, v15, Lh5/h;->v0:I

    .line 343
    .line 344
    if-nez v6, :cond_12

    .line 345
    .line 346
    iget v6, v15, Lh5/h;->s0:I

    .line 347
    .line 348
    const/4 v11, -0x1

    .line 349
    if-eq v6, v11, :cond_e

    .line 350
    .line 351
    invoke-virtual {v15, v6}, Lh5/h;->V(I)V

    .line 352
    .line 353
    .line 354
    goto :goto_c

    .line 355
    :cond_e
    iget v6, v15, Lh5/h;->t0:I

    .line 356
    .line 357
    if-eq v6, v11, :cond_f

    .line 358
    .line 359
    invoke-virtual {v1}, Lh5/d;->C()Z

    .line 360
    .line 361
    .line 362
    move-result v6

    .line 363
    if-eqz v6, :cond_f

    .line 364
    .line 365
    invoke-virtual {v1}, Lh5/d;->l()I

    .line 366
    .line 367
    .line 368
    move-result v6

    .line 369
    iget v11, v15, Lh5/h;->t0:I

    .line 370
    .line 371
    sub-int/2addr v6, v11

    .line 372
    invoke-virtual {v15, v6}, Lh5/h;->V(I)V

    .line 373
    .line 374
    .line 375
    goto :goto_c

    .line 376
    :cond_f
    invoke-virtual {v1}, Lh5/d;->C()Z

    .line 377
    .line 378
    .line 379
    move-result v6

    .line 380
    if-eqz v6, :cond_10

    .line 381
    .line 382
    iget v6, v15, Lh5/h;->r0:F

    .line 383
    .line 384
    invoke-virtual {v1}, Lh5/d;->l()I

    .line 385
    .line 386
    .line 387
    move-result v11

    .line 388
    int-to-float v11, v11

    .line 389
    mul-float/2addr v6, v11

    .line 390
    add-float v6, v6, v21

    .line 391
    .line 392
    float-to-int v6, v6

    .line 393
    invoke-virtual {v15, v6}, Lh5/h;->V(I)V

    .line 394
    .line 395
    .line 396
    :cond_10
    :goto_c
    const/4 v11, 0x1

    .line 397
    goto :goto_d

    .line 398
    :cond_11
    instance-of v6, v15, Lh5/a;

    .line 399
    .line 400
    if-eqz v6, :cond_12

    .line 401
    .line 402
    check-cast v15, Lh5/a;

    .line 403
    .line 404
    invoke-virtual {v15}, Lh5/a;->Z()I

    .line 405
    .line 406
    .line 407
    move-result v6

    .line 408
    const/4 v15, 0x1

    .line 409
    if-ne v6, v15, :cond_12

    .line 410
    .line 411
    const/4 v13, 0x1

    .line 412
    :cond_12
    :goto_d
    add-int/lit8 v6, v20, 0x1

    .line 413
    .line 414
    goto :goto_b

    .line 415
    :cond_13
    if-eqz v11, :cond_15

    .line 416
    .line 417
    const/4 v6, 0x0

    .line 418
    :goto_e
    if-ge v6, v3, :cond_15

    .line 419
    .line 420
    invoke-virtual {v14, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 421
    .line 422
    .line 423
    move-result-object v11

    .line 424
    check-cast v11, Lh5/d;

    .line 425
    .line 426
    instance-of v15, v11, Lh5/h;

    .line 427
    .line 428
    if-eqz v15, :cond_14

    .line 429
    .line 430
    check-cast v11, Lh5/h;

    .line 431
    .line 432
    iget v15, v11, Lh5/h;->v0:I

    .line 433
    .line 434
    if-nez v15, :cond_14

    .line 435
    .line 436
    const/4 v15, 0x1

    .line 437
    invoke-static {v15, v11, v10}, Li5/i;->i(ILh5/d;Li5/c;)V

    .line 438
    .line 439
    .line 440
    :cond_14
    add-int/lit8 v6, v6, 0x1

    .line 441
    .line 442
    goto :goto_e

    .line 443
    :cond_15
    const/4 v15, 0x0

    .line 444
    invoke-static {v15, v1, v10}, Li5/i;->i(ILh5/d;Li5/c;)V

    .line 445
    .line 446
    .line 447
    if-eqz v13, :cond_17

    .line 448
    .line 449
    const/4 v6, 0x0

    .line 450
    :goto_f
    if-ge v6, v3, :cond_17

    .line 451
    .line 452
    invoke-virtual {v14, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 453
    .line 454
    .line 455
    move-result-object v11

    .line 456
    check-cast v11, Lh5/d;

    .line 457
    .line 458
    instance-of v13, v11, Lh5/a;

    .line 459
    .line 460
    if-eqz v13, :cond_16

    .line 461
    .line 462
    check-cast v11, Lh5/a;

    .line 463
    .line 464
    invoke-virtual {v11}, Lh5/a;->Z()I

    .line 465
    .line 466
    .line 467
    move-result v13

    .line 468
    const/4 v15, 0x1

    .line 469
    if-ne v13, v15, :cond_16

    .line 470
    .line 471
    invoke-virtual {v11}, Lh5/a;->Y()Z

    .line 472
    .line 473
    .line 474
    move-result v13

    .line 475
    if-eqz v13, :cond_16

    .line 476
    .line 477
    invoke-static {v15, v11, v10}, Li5/i;->i(ILh5/d;Li5/c;)V

    .line 478
    .line 479
    .line 480
    :cond_16
    add-int/lit8 v6, v6, 0x1

    .line 481
    .line 482
    goto :goto_f

    .line 483
    :cond_17
    const/4 v6, 0x0

    .line 484
    :goto_10
    if-ge v6, v3, :cond_1b

    .line 485
    .line 486
    invoke-virtual {v14, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 487
    .line 488
    .line 489
    move-result-object v11

    .line 490
    check-cast v11, Lh5/d;

    .line 491
    .line 492
    invoke-virtual {v11}, Lh5/d;->A()Z

    .line 493
    .line 494
    .line 495
    move-result v13

    .line 496
    if-eqz v13, :cond_1a

    .line 497
    .line 498
    invoke-static {v11}, Li5/i;->a(Lh5/d;)Z

    .line 499
    .line 500
    .line 501
    move-result v13

    .line 502
    if-eqz v13, :cond_1a

    .line 503
    .line 504
    sget-object v13, Li5/i;->a:Li5/b;

    .line 505
    .line 506
    invoke-static {v11, v10, v13}, Lh5/e;->b0(Lh5/d;Li5/c;Li5/b;)V

    .line 507
    .line 508
    .line 509
    instance-of v13, v11, Lh5/h;

    .line 510
    .line 511
    if-eqz v13, :cond_19

    .line 512
    .line 513
    move-object v13, v11

    .line 514
    check-cast v13, Lh5/h;

    .line 515
    .line 516
    iget v13, v13, Lh5/h;->v0:I

    .line 517
    .line 518
    if-nez v13, :cond_18

    .line 519
    .line 520
    const/4 v15, 0x0

    .line 521
    invoke-static {v15, v11, v10}, Li5/i;->i(ILh5/d;Li5/c;)V

    .line 522
    .line 523
    .line 524
    goto :goto_11

    .line 525
    :cond_18
    const/4 v15, 0x0

    .line 526
    invoke-static {v15, v11, v10, v7}, Li5/i;->c(ILh5/d;Li5/c;Z)V

    .line 527
    .line 528
    .line 529
    goto :goto_11

    .line 530
    :cond_19
    const/4 v15, 0x0

    .line 531
    invoke-static {v15, v11, v10, v7}, Li5/i;->c(ILh5/d;Li5/c;Z)V

    .line 532
    .line 533
    .line 534
    invoke-static {v15, v11, v10}, Li5/i;->i(ILh5/d;Li5/c;)V

    .line 535
    .line 536
    .line 537
    :cond_1a
    :goto_11
    add-int/lit8 v6, v6, 0x1

    .line 538
    .line 539
    goto :goto_10

    .line 540
    :cond_1b
    const/4 v3, 0x0

    .line 541
    :goto_12
    if-ge v3, v4, :cond_1f

    .line 542
    .line 543
    iget-object v6, v1, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 544
    .line 545
    invoke-virtual {v6, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 546
    .line 547
    .line 548
    move-result-object v6

    .line 549
    check-cast v6, Lh5/d;

    .line 550
    .line 551
    invoke-virtual {v6}, Lh5/d;->A()Z

    .line 552
    .line 553
    .line 554
    move-result v7

    .line 555
    if-eqz v7, :cond_1d

    .line 556
    .line 557
    instance-of v7, v6, Lh5/h;

    .line 558
    .line 559
    if-nez v7, :cond_1d

    .line 560
    .line 561
    instance-of v7, v6, Lh5/a;

    .line 562
    .line 563
    if-nez v7, :cond_1d

    .line 564
    .line 565
    instance-of v7, v6, Lh5/k;

    .line 566
    .line 567
    if-nez v7, :cond_1d

    .line 568
    .line 569
    iget-boolean v7, v6, Lh5/d;->G:Z

    .line 570
    .line 571
    if-nez v7, :cond_1d

    .line 572
    .line 573
    const/4 v15, 0x0

    .line 574
    invoke-virtual {v6, v15}, Lh5/d;->k(I)I

    .line 575
    .line 576
    .line 577
    move-result v7

    .line 578
    const/4 v15, 0x1

    .line 579
    invoke-virtual {v6, v15}, Lh5/d;->k(I)I

    .line 580
    .line 581
    .line 582
    move-result v10

    .line 583
    const/4 v11, 0x3

    .line 584
    if-ne v7, v11, :cond_1c

    .line 585
    .line 586
    iget v7, v6, Lh5/d;->s:I

    .line 587
    .line 588
    if-eq v7, v15, :cond_1c

    .line 589
    .line 590
    if-ne v10, v11, :cond_1c

    .line 591
    .line 592
    iget v7, v6, Lh5/d;->t:I

    .line 593
    .line 594
    if-eq v7, v15, :cond_1c

    .line 595
    .line 596
    goto :goto_13

    .line 597
    :cond_1c
    new-instance v7, Li5/b;

    .line 598
    .line 599
    invoke-direct {v7}, Ljava/lang/Object;-><init>()V

    .line 600
    .line 601
    .line 602
    iget-object v10, v1, Lh5/e;->v0:Li5/c;

    .line 603
    .line 604
    invoke-static {v6, v10, v7}, Lh5/e;->b0(Lh5/d;Li5/c;Li5/b;)V

    .line 605
    .line 606
    .line 607
    :cond_1d
    :goto_13
    add-int/lit8 v3, v3, 0x1

    .line 608
    .line 609
    goto :goto_12

    .line 610
    :cond_1e
    move-object/from16 v19, v6

    .line 611
    .line 612
    move-object/from16 v24, v13

    .line 613
    .line 614
    :cond_1f
    const/4 v6, 0x2

    .line 615
    if-le v4, v6, :cond_59

    .line 616
    .line 617
    if-eq v9, v6, :cond_20

    .line 618
    .line 619
    if-ne v8, v6, :cond_59

    .line 620
    .line 621
    :cond_20
    iget v10, v1, Lh5/e;->E0:I

    .line 622
    .line 623
    const/16 v11, 0x400

    .line 624
    .line 625
    invoke-static {v10, v11}, Lh5/j;->c(II)Z

    .line 626
    .line 627
    .line 628
    move-result v10

    .line 629
    if-eqz v10, :cond_59

    .line 630
    .line 631
    iget-object v10, v1, Lh5/e;->v0:Li5/c;

    .line 632
    .line 633
    iget-object v11, v1, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 634
    .line 635
    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    .line 636
    .line 637
    .line 638
    move-result v13

    .line 639
    const/4 v14, 0x0

    .line 640
    :goto_14
    if-ge v14, v13, :cond_23

    .line 641
    .line 642
    invoke-virtual {v11, v14}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 643
    .line 644
    .line 645
    move-result-object v15

    .line 646
    check-cast v15, Lh5/d;

    .line 647
    .line 648
    const/16 v17, 0x0

    .line 649
    .line 650
    aget v3, v19, v17

    .line 651
    .line 652
    const/16 v18, 0x1

    .line 653
    .line 654
    aget v6, v19, v18

    .line 655
    .line 656
    iget-object v7, v15, Lh5/d;->q0:[I

    .line 657
    .line 658
    move-object/from16 v23, v7

    .line 659
    .line 660
    aget v7, v23, v17

    .line 661
    .line 662
    move/from16 v25, v14

    .line 663
    .line 664
    aget v14, v23, v18

    .line 665
    .line 666
    invoke-static {v3, v6, v7, v14}, Li5/i;->h(IIII)Z

    .line 667
    .line 668
    .line 669
    move-result v3

    .line 670
    if-nez v3, :cond_21

    .line 671
    .line 672
    goto/16 :goto_3b

    .line 673
    .line 674
    :cond_21
    instance-of v3, v15, Lh5/g;

    .line 675
    .line 676
    if-eqz v3, :cond_22

    .line 677
    .line 678
    goto/16 :goto_3b

    .line 679
    .line 680
    :cond_22
    add-int/lit8 v14, v25, 0x1

    .line 681
    .line 682
    const/4 v6, 0x2

    .line 683
    goto :goto_14

    .line 684
    :cond_23
    const/4 v3, 0x0

    .line 685
    const/4 v6, 0x0

    .line 686
    const/4 v7, 0x0

    .line 687
    const/4 v14, 0x0

    .line 688
    const/4 v15, 0x0

    .line 689
    const/16 v23, 0x0

    .line 690
    .line 691
    const/16 v25, 0x0

    .line 692
    .line 693
    :goto_15
    if-ge v3, v13, :cond_36

    .line 694
    .line 695
    invoke-virtual {v11, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 696
    .line 697
    .line 698
    move-result-object v26

    .line 699
    move/from16 v27, v3

    .line 700
    .line 701
    move-object/from16 v3, v26

    .line 702
    .line 703
    check-cast v3, Lh5/d;

    .line 704
    .line 705
    move-object/from16 v26, v6

    .line 706
    .line 707
    const/16 v17, 0x0

    .line 708
    .line 709
    aget v6, v19, v17

    .line 710
    .line 711
    move-object/from16 v28, v7

    .line 712
    .line 713
    const/16 v18, 0x1

    .line 714
    .line 715
    aget v7, v19, v18

    .line 716
    .line 717
    move-object/from16 v29, v14

    .line 718
    .line 719
    iget-object v14, v3, Lh5/d;->q0:[I

    .line 720
    .line 721
    move-object/from16 v30, v14

    .line 722
    .line 723
    aget v14, v30, v17

    .line 724
    .line 725
    move-object/from16 v31, v15

    .line 726
    .line 727
    aget v15, v30, v18

    .line 728
    .line 729
    invoke-static {v6, v7, v14, v15}, Li5/i;->h(IIII)Z

    .line 730
    .line 731
    .line 732
    move-result v6

    .line 733
    if-nez v6, :cond_24

    .line 734
    .line 735
    iget-object v6, v1, Lh5/e;->M0:Li5/b;

    .line 736
    .line 737
    invoke-static {v3, v10, v6}, Lh5/e;->b0(Lh5/d;Li5/c;Li5/b;)V

    .line 738
    .line 739
    .line 740
    :cond_24
    instance-of v6, v3, Lh5/h;

    .line 741
    .line 742
    if-eqz v6, :cond_29

    .line 743
    .line 744
    move-object v7, v3

    .line 745
    check-cast v7, Lh5/h;

    .line 746
    .line 747
    iget v14, v7, Lh5/h;->v0:I

    .line 748
    .line 749
    if-nez v14, :cond_26

    .line 750
    .line 751
    if-nez v29, :cond_25

    .line 752
    .line 753
    new-instance v14, Ljava/util/ArrayList;

    .line 754
    .line 755
    invoke-direct {v14}, Ljava/util/ArrayList;-><init>()V

    .line 756
    .line 757
    .line 758
    goto :goto_16

    .line 759
    :cond_25
    move-object/from16 v14, v29

    .line 760
    .line 761
    :goto_16
    invoke-virtual {v14, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 762
    .line 763
    .line 764
    goto :goto_17

    .line 765
    :cond_26
    move-object/from16 v14, v29

    .line 766
    .line 767
    :goto_17
    iget v15, v7, Lh5/h;->v0:I

    .line 768
    .line 769
    move/from16 v30, v6

    .line 770
    .line 771
    const/4 v6, 0x1

    .line 772
    if-ne v15, v6, :cond_28

    .line 773
    .line 774
    if-nez v26, :cond_27

    .line 775
    .line 776
    new-instance v6, Ljava/util/ArrayList;

    .line 777
    .line 778
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 779
    .line 780
    .line 781
    goto :goto_18

    .line 782
    :cond_27
    move-object/from16 v6, v26

    .line 783
    .line 784
    :goto_18
    invoke-virtual {v6, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 785
    .line 786
    .line 787
    goto :goto_19

    .line 788
    :cond_28
    move-object/from16 v6, v26

    .line 789
    .line 790
    goto :goto_19

    .line 791
    :cond_29
    move/from16 v30, v6

    .line 792
    .line 793
    move-object/from16 v6, v26

    .line 794
    .line 795
    move-object/from16 v14, v29

    .line 796
    .line 797
    :goto_19
    instance-of v7, v3, Lh5/i;

    .line 798
    .line 799
    if-eqz v7, :cond_31

    .line 800
    .line 801
    instance-of v7, v3, Lh5/a;

    .line 802
    .line 803
    if-eqz v7, :cond_2e

    .line 804
    .line 805
    move-object v7, v3

    .line 806
    check-cast v7, Lh5/a;

    .line 807
    .line 808
    invoke-virtual {v7}, Lh5/a;->Z()I

    .line 809
    .line 810
    .line 811
    move-result v15

    .line 812
    if-nez v15, :cond_2b

    .line 813
    .line 814
    if-nez v28, :cond_2a

    .line 815
    .line 816
    new-instance v15, Ljava/util/ArrayList;

    .line 817
    .line 818
    invoke-direct {v15}, Ljava/util/ArrayList;-><init>()V

    .line 819
    .line 820
    .line 821
    goto :goto_1a

    .line 822
    :cond_2a
    move-object/from16 v15, v28

    .line 823
    .line 824
    :goto_1a
    invoke-virtual {v15, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 825
    .line 826
    .line 827
    :goto_1b
    move-object/from16 v26, v6

    .line 828
    .line 829
    goto :goto_1c

    .line 830
    :cond_2b
    move-object/from16 v15, v28

    .line 831
    .line 832
    goto :goto_1b

    .line 833
    :goto_1c
    invoke-virtual {v7}, Lh5/a;->Z()I

    .line 834
    .line 835
    .line 836
    move-result v6

    .line 837
    move-object/from16 v32, v10

    .line 838
    .line 839
    const/4 v10, 0x1

    .line 840
    if-ne v6, v10, :cond_2d

    .line 841
    .line 842
    if-nez v31, :cond_2c

    .line 843
    .line 844
    new-instance v6, Ljava/util/ArrayList;

    .line 845
    .line 846
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 847
    .line 848
    .line 849
    goto :goto_1d

    .line 850
    :cond_2c
    move-object/from16 v6, v31

    .line 851
    .line 852
    :goto_1d
    invoke-virtual {v6, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 853
    .line 854
    .line 855
    move-object/from16 v31, v6

    .line 856
    .line 857
    :cond_2d
    move-object v7, v15

    .line 858
    :goto_1e
    move-object/from16 v15, v31

    .line 859
    .line 860
    goto :goto_21

    .line 861
    :cond_2e
    move-object/from16 v26, v6

    .line 862
    .line 863
    move-object/from16 v32, v10

    .line 864
    .line 865
    move-object v6, v3

    .line 866
    check-cast v6, Lh5/i;

    .line 867
    .line 868
    if-nez v28, :cond_2f

    .line 869
    .line 870
    new-instance v7, Ljava/util/ArrayList;

    .line 871
    .line 872
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 873
    .line 874
    .line 875
    goto :goto_1f

    .line 876
    :cond_2f
    move-object/from16 v7, v28

    .line 877
    .line 878
    :goto_1f
    invoke-virtual {v7, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 879
    .line 880
    .line 881
    if-nez v31, :cond_30

    .line 882
    .line 883
    new-instance v15, Ljava/util/ArrayList;

    .line 884
    .line 885
    invoke-direct {v15}, Ljava/util/ArrayList;-><init>()V

    .line 886
    .line 887
    .line 888
    goto :goto_20

    .line 889
    :cond_30
    move-object/from16 v15, v31

    .line 890
    .line 891
    :goto_20
    invoke-virtual {v15, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 892
    .line 893
    .line 894
    goto :goto_21

    .line 895
    :cond_31
    move-object/from16 v26, v6

    .line 896
    .line 897
    move-object/from16 v32, v10

    .line 898
    .line 899
    move-object/from16 v7, v28

    .line 900
    .line 901
    goto :goto_1e

    .line 902
    :goto_21
    iget-object v6, v3, Lh5/d;->J:Lh5/c;

    .line 903
    .line 904
    iget-object v6, v6, Lh5/c;->f:Lh5/c;

    .line 905
    .line 906
    if-nez v6, :cond_33

    .line 907
    .line 908
    iget-object v6, v3, Lh5/d;->L:Lh5/c;

    .line 909
    .line 910
    iget-object v6, v6, Lh5/c;->f:Lh5/c;

    .line 911
    .line 912
    if-nez v6, :cond_33

    .line 913
    .line 914
    if-nez v30, :cond_33

    .line 915
    .line 916
    instance-of v6, v3, Lh5/a;

    .line 917
    .line 918
    if-nez v6, :cond_33

    .line 919
    .line 920
    if-nez v23, :cond_32

    .line 921
    .line 922
    new-instance v23, Ljava/util/ArrayList;

    .line 923
    .line 924
    invoke-direct/range {v23 .. v23}, Ljava/util/ArrayList;-><init>()V

    .line 925
    .line 926
    .line 927
    :cond_32
    move-object/from16 v6, v23

    .line 928
    .line 929
    invoke-virtual {v6, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 930
    .line 931
    .line 932
    move-object/from16 v23, v6

    .line 933
    .line 934
    :cond_33
    iget-object v6, v3, Lh5/d;->K:Lh5/c;

    .line 935
    .line 936
    iget-object v6, v6, Lh5/c;->f:Lh5/c;

    .line 937
    .line 938
    if-nez v6, :cond_35

    .line 939
    .line 940
    iget-object v6, v3, Lh5/d;->M:Lh5/c;

    .line 941
    .line 942
    iget-object v6, v6, Lh5/c;->f:Lh5/c;

    .line 943
    .line 944
    if-nez v6, :cond_35

    .line 945
    .line 946
    iget-object v6, v3, Lh5/d;->N:Lh5/c;

    .line 947
    .line 948
    iget-object v6, v6, Lh5/c;->f:Lh5/c;

    .line 949
    .line 950
    if-nez v6, :cond_35

    .line 951
    .line 952
    if-nez v30, :cond_35

    .line 953
    .line 954
    instance-of v6, v3, Lh5/a;

    .line 955
    .line 956
    if-nez v6, :cond_35

    .line 957
    .line 958
    if-nez v25, :cond_34

    .line 959
    .line 960
    new-instance v25, Ljava/util/ArrayList;

    .line 961
    .line 962
    invoke-direct/range {v25 .. v25}, Ljava/util/ArrayList;-><init>()V

    .line 963
    .line 964
    .line 965
    :cond_34
    move-object/from16 v6, v25

    .line 966
    .line 967
    invoke-virtual {v6, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 968
    .line 969
    .line 970
    move-object/from16 v25, v6

    .line 971
    .line 972
    :cond_35
    add-int/lit8 v3, v27, 0x1

    .line 973
    .line 974
    move-object/from16 v6, v26

    .line 975
    .line 976
    move-object/from16 v10, v32

    .line 977
    .line 978
    goto/16 :goto_15

    .line 979
    .line 980
    :cond_36
    move-object/from16 v26, v6

    .line 981
    .line 982
    move-object/from16 v28, v7

    .line 983
    .line 984
    move-object/from16 v29, v14

    .line 985
    .line 986
    move-object/from16 v31, v15

    .line 987
    .line 988
    new-instance v3, Ljava/util/ArrayList;

    .line 989
    .line 990
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 991
    .line 992
    .line 993
    if-eqz v26, :cond_37

    .line 994
    .line 995
    invoke-virtual/range {v26 .. v26}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 996
    .line 997
    .line 998
    move-result-object v6

    .line 999
    :goto_22
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 1000
    .line 1001
    .line 1002
    move-result v7

    .line 1003
    if-eqz v7, :cond_37

    .line 1004
    .line 1005
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1006
    .line 1007
    .line 1008
    move-result-object v7

    .line 1009
    check-cast v7, Lh5/h;

    .line 1010
    .line 1011
    const/4 v10, 0x0

    .line 1012
    const/4 v15, 0x0

    .line 1013
    invoke-static {v7, v15, v3, v10}, Li5/i;->b(Lh5/d;ILjava/util/ArrayList;Li5/o;)Li5/o;

    .line 1014
    .line 1015
    .line 1016
    goto :goto_22

    .line 1017
    :cond_37
    const/4 v10, 0x0

    .line 1018
    const/4 v15, 0x0

    .line 1019
    if-eqz v28, :cond_38

    .line 1020
    .line 1021
    invoke-virtual/range {v28 .. v28}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1022
    .line 1023
    .line 1024
    move-result-object v6

    .line 1025
    :goto_23
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 1026
    .line 1027
    .line 1028
    move-result v7

    .line 1029
    if-eqz v7, :cond_38

    .line 1030
    .line 1031
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1032
    .line 1033
    .line 1034
    move-result-object v7

    .line 1035
    check-cast v7, Lh5/i;

    .line 1036
    .line 1037
    invoke-static {v7, v15, v3, v10}, Li5/i;->b(Lh5/d;ILjava/util/ArrayList;Li5/o;)Li5/o;

    .line 1038
    .line 1039
    .line 1040
    move-result-object v14

    .line 1041
    invoke-virtual {v7, v15, v14, v3}, Lh5/i;->W(ILi5/o;Ljava/util/ArrayList;)V

    .line 1042
    .line 1043
    .line 1044
    invoke-virtual {v14, v3}, Li5/o;->a(Ljava/util/ArrayList;)V

    .line 1045
    .line 1046
    .line 1047
    const/4 v10, 0x0

    .line 1048
    const/4 v15, 0x0

    .line 1049
    goto :goto_23

    .line 1050
    :cond_38
    const/4 v6, 0x2

    .line 1051
    invoke-virtual {v1, v6}, Lh5/d;->j(I)Lh5/c;

    .line 1052
    .line 1053
    .line 1054
    move-result-object v7

    .line 1055
    iget-object v6, v7, Lh5/c;->a:Ljava/util/HashSet;

    .line 1056
    .line 1057
    if-eqz v6, :cond_39

    .line 1058
    .line 1059
    invoke-virtual {v6}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 1060
    .line 1061
    .line 1062
    move-result-object v6

    .line 1063
    :goto_24
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 1064
    .line 1065
    .line 1066
    move-result v7

    .line 1067
    if-eqz v7, :cond_39

    .line 1068
    .line 1069
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1070
    .line 1071
    .line 1072
    move-result-object v7

    .line 1073
    check-cast v7, Lh5/c;

    .line 1074
    .line 1075
    iget-object v7, v7, Lh5/c;->d:Lh5/d;

    .line 1076
    .line 1077
    const/4 v10, 0x0

    .line 1078
    const/4 v15, 0x0

    .line 1079
    invoke-static {v7, v15, v3, v10}, Li5/i;->b(Lh5/d;ILjava/util/ArrayList;Li5/o;)Li5/o;

    .line 1080
    .line 1081
    .line 1082
    goto :goto_24

    .line 1083
    :cond_39
    const/4 v6, 0x4

    .line 1084
    invoke-virtual {v1, v6}, Lh5/d;->j(I)Lh5/c;

    .line 1085
    .line 1086
    .line 1087
    move-result-object v6

    .line 1088
    iget-object v6, v6, Lh5/c;->a:Ljava/util/HashSet;

    .line 1089
    .line 1090
    if-eqz v6, :cond_3a

    .line 1091
    .line 1092
    invoke-virtual {v6}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 1093
    .line 1094
    .line 1095
    move-result-object v6

    .line 1096
    :goto_25
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 1097
    .line 1098
    .line 1099
    move-result v7

    .line 1100
    if-eqz v7, :cond_3a

    .line 1101
    .line 1102
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1103
    .line 1104
    .line 1105
    move-result-object v7

    .line 1106
    check-cast v7, Lh5/c;

    .line 1107
    .line 1108
    iget-object v7, v7, Lh5/c;->d:Lh5/d;

    .line 1109
    .line 1110
    const/4 v10, 0x0

    .line 1111
    const/4 v15, 0x0

    .line 1112
    invoke-static {v7, v15, v3, v10}, Li5/i;->b(Lh5/d;ILjava/util/ArrayList;Li5/o;)Li5/o;

    .line 1113
    .line 1114
    .line 1115
    goto :goto_25

    .line 1116
    :cond_3a
    const/4 v6, 0x7

    .line 1117
    invoke-virtual {v1, v6}, Lh5/d;->j(I)Lh5/c;

    .line 1118
    .line 1119
    .line 1120
    move-result-object v7

    .line 1121
    iget-object v7, v7, Lh5/c;->a:Ljava/util/HashSet;

    .line 1122
    .line 1123
    if-eqz v7, :cond_3b

    .line 1124
    .line 1125
    invoke-virtual {v7}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 1126
    .line 1127
    .line 1128
    move-result-object v7

    .line 1129
    :goto_26
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 1130
    .line 1131
    .line 1132
    move-result v10

    .line 1133
    if-eqz v10, :cond_3b

    .line 1134
    .line 1135
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1136
    .line 1137
    .line 1138
    move-result-object v10

    .line 1139
    check-cast v10, Lh5/c;

    .line 1140
    .line 1141
    iget-object v10, v10, Lh5/c;->d:Lh5/d;

    .line 1142
    .line 1143
    const/4 v14, 0x0

    .line 1144
    const/4 v15, 0x0

    .line 1145
    invoke-static {v10, v15, v3, v14}, Li5/i;->b(Lh5/d;ILjava/util/ArrayList;Li5/o;)Li5/o;

    .line 1146
    .line 1147
    .line 1148
    goto :goto_26

    .line 1149
    :cond_3b
    const/4 v14, 0x0

    .line 1150
    const/4 v15, 0x0

    .line 1151
    if-eqz v23, :cond_3c

    .line 1152
    .line 1153
    invoke-virtual/range {v23 .. v23}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1154
    .line 1155
    .line 1156
    move-result-object v7

    .line 1157
    :goto_27
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 1158
    .line 1159
    .line 1160
    move-result v10

    .line 1161
    if-eqz v10, :cond_3c

    .line 1162
    .line 1163
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1164
    .line 1165
    .line 1166
    move-result-object v10

    .line 1167
    check-cast v10, Lh5/d;

    .line 1168
    .line 1169
    invoke-static {v10, v15, v3, v14}, Li5/i;->b(Lh5/d;ILjava/util/ArrayList;Li5/o;)Li5/o;

    .line 1170
    .line 1171
    .line 1172
    goto :goto_27

    .line 1173
    :cond_3c
    if-eqz v29, :cond_3d

    .line 1174
    .line 1175
    invoke-virtual/range {v29 .. v29}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1176
    .line 1177
    .line 1178
    move-result-object v7

    .line 1179
    :goto_28
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 1180
    .line 1181
    .line 1182
    move-result v10

    .line 1183
    if-eqz v10, :cond_3d

    .line 1184
    .line 1185
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1186
    .line 1187
    .line 1188
    move-result-object v10

    .line 1189
    check-cast v10, Lh5/h;

    .line 1190
    .line 1191
    const/4 v15, 0x1

    .line 1192
    invoke-static {v10, v15, v3, v14}, Li5/i;->b(Lh5/d;ILjava/util/ArrayList;Li5/o;)Li5/o;

    .line 1193
    .line 1194
    .line 1195
    goto :goto_28

    .line 1196
    :cond_3d
    const/4 v15, 0x1

    .line 1197
    if-eqz v31, :cond_3e

    .line 1198
    .line 1199
    invoke-virtual/range {v31 .. v31}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1200
    .line 1201
    .line 1202
    move-result-object v7

    .line 1203
    :goto_29
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 1204
    .line 1205
    .line 1206
    move-result v10

    .line 1207
    if-eqz v10, :cond_3e

    .line 1208
    .line 1209
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1210
    .line 1211
    .line 1212
    move-result-object v10

    .line 1213
    check-cast v10, Lh5/i;

    .line 1214
    .line 1215
    invoke-static {v10, v15, v3, v14}, Li5/i;->b(Lh5/d;ILjava/util/ArrayList;Li5/o;)Li5/o;

    .line 1216
    .line 1217
    .line 1218
    move-result-object v6

    .line 1219
    invoke-virtual {v10, v15, v6, v3}, Lh5/i;->W(ILi5/o;Ljava/util/ArrayList;)V

    .line 1220
    .line 1221
    .line 1222
    invoke-virtual {v6, v3}, Li5/o;->a(Ljava/util/ArrayList;)V

    .line 1223
    .line 1224
    .line 1225
    const/4 v6, 0x7

    .line 1226
    const/4 v14, 0x0

    .line 1227
    const/4 v15, 0x1

    .line 1228
    goto :goto_29

    .line 1229
    :cond_3e
    const/4 v6, 0x3

    .line 1230
    invoke-virtual {v1, v6}, Lh5/d;->j(I)Lh5/c;

    .line 1231
    .line 1232
    .line 1233
    move-result-object v7

    .line 1234
    iget-object v6, v7, Lh5/c;->a:Ljava/util/HashSet;

    .line 1235
    .line 1236
    if-eqz v6, :cond_3f

    .line 1237
    .line 1238
    invoke-virtual {v6}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 1239
    .line 1240
    .line 1241
    move-result-object v6

    .line 1242
    :goto_2a
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 1243
    .line 1244
    .line 1245
    move-result v7

    .line 1246
    if-eqz v7, :cond_3f

    .line 1247
    .line 1248
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1249
    .line 1250
    .line 1251
    move-result-object v7

    .line 1252
    check-cast v7, Lh5/c;

    .line 1253
    .line 1254
    iget-object v7, v7, Lh5/c;->d:Lh5/d;

    .line 1255
    .line 1256
    const/4 v10, 0x0

    .line 1257
    const/4 v15, 0x1

    .line 1258
    invoke-static {v7, v15, v3, v10}, Li5/i;->b(Lh5/d;ILjava/util/ArrayList;Li5/o;)Li5/o;

    .line 1259
    .line 1260
    .line 1261
    goto :goto_2a

    .line 1262
    :cond_3f
    const/4 v6, 0x6

    .line 1263
    invoke-virtual {v1, v6}, Lh5/d;->j(I)Lh5/c;

    .line 1264
    .line 1265
    .line 1266
    move-result-object v6

    .line 1267
    iget-object v6, v6, Lh5/c;->a:Ljava/util/HashSet;

    .line 1268
    .line 1269
    if-eqz v6, :cond_40

    .line 1270
    .line 1271
    invoke-virtual {v6}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 1272
    .line 1273
    .line 1274
    move-result-object v6

    .line 1275
    :goto_2b
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 1276
    .line 1277
    .line 1278
    move-result v7

    .line 1279
    if-eqz v7, :cond_40

    .line 1280
    .line 1281
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1282
    .line 1283
    .line 1284
    move-result-object v7

    .line 1285
    check-cast v7, Lh5/c;

    .line 1286
    .line 1287
    iget-object v7, v7, Lh5/c;->d:Lh5/d;

    .line 1288
    .line 1289
    const/4 v10, 0x0

    .line 1290
    const/4 v15, 0x1

    .line 1291
    invoke-static {v7, v15, v3, v10}, Li5/i;->b(Lh5/d;ILjava/util/ArrayList;Li5/o;)Li5/o;

    .line 1292
    .line 1293
    .line 1294
    goto :goto_2b

    .line 1295
    :cond_40
    const/4 v6, 0x5

    .line 1296
    invoke-virtual {v1, v6}, Lh5/d;->j(I)Lh5/c;

    .line 1297
    .line 1298
    .line 1299
    move-result-object v7

    .line 1300
    iget-object v6, v7, Lh5/c;->a:Ljava/util/HashSet;

    .line 1301
    .line 1302
    if-eqz v6, :cond_41

    .line 1303
    .line 1304
    invoke-virtual {v6}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 1305
    .line 1306
    .line 1307
    move-result-object v6

    .line 1308
    :goto_2c
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 1309
    .line 1310
    .line 1311
    move-result v7

    .line 1312
    if-eqz v7, :cond_41

    .line 1313
    .line 1314
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1315
    .line 1316
    .line 1317
    move-result-object v7

    .line 1318
    check-cast v7, Lh5/c;

    .line 1319
    .line 1320
    iget-object v7, v7, Lh5/c;->d:Lh5/d;

    .line 1321
    .line 1322
    const/4 v10, 0x0

    .line 1323
    const/4 v15, 0x1

    .line 1324
    invoke-static {v7, v15, v3, v10}, Li5/i;->b(Lh5/d;ILjava/util/ArrayList;Li5/o;)Li5/o;

    .line 1325
    .line 1326
    .line 1327
    goto :goto_2c

    .line 1328
    :cond_41
    const/4 v6, 0x7

    .line 1329
    invoke-virtual {v1, v6}, Lh5/d;->j(I)Lh5/c;

    .line 1330
    .line 1331
    .line 1332
    move-result-object v6

    .line 1333
    iget-object v6, v6, Lh5/c;->a:Ljava/util/HashSet;

    .line 1334
    .line 1335
    if-eqz v6, :cond_42

    .line 1336
    .line 1337
    invoke-virtual {v6}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 1338
    .line 1339
    .line 1340
    move-result-object v6

    .line 1341
    :goto_2d
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 1342
    .line 1343
    .line 1344
    move-result v7

    .line 1345
    if-eqz v7, :cond_42

    .line 1346
    .line 1347
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1348
    .line 1349
    .line 1350
    move-result-object v7

    .line 1351
    check-cast v7, Lh5/c;

    .line 1352
    .line 1353
    iget-object v7, v7, Lh5/c;->d:Lh5/d;

    .line 1354
    .line 1355
    const/4 v10, 0x0

    .line 1356
    const/4 v15, 0x1

    .line 1357
    invoke-static {v7, v15, v3, v10}, Li5/i;->b(Lh5/d;ILjava/util/ArrayList;Li5/o;)Li5/o;

    .line 1358
    .line 1359
    .line 1360
    goto :goto_2d

    .line 1361
    :cond_42
    const/4 v10, 0x0

    .line 1362
    const/4 v15, 0x1

    .line 1363
    if-eqz v25, :cond_43

    .line 1364
    .line 1365
    invoke-virtual/range {v25 .. v25}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1366
    .line 1367
    .line 1368
    move-result-object v6

    .line 1369
    :goto_2e
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 1370
    .line 1371
    .line 1372
    move-result v7

    .line 1373
    if-eqz v7, :cond_43

    .line 1374
    .line 1375
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1376
    .line 1377
    .line 1378
    move-result-object v7

    .line 1379
    check-cast v7, Lh5/d;

    .line 1380
    .line 1381
    invoke-static {v7, v15, v3, v10}, Li5/i;->b(Lh5/d;ILjava/util/ArrayList;Li5/o;)Li5/o;

    .line 1382
    .line 1383
    .line 1384
    goto :goto_2e

    .line 1385
    :cond_43
    const/4 v6, 0x0

    .line 1386
    :goto_2f
    if-ge v6, v13, :cond_4a

    .line 1387
    .line 1388
    invoke-virtual {v11, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1389
    .line 1390
    .line 1391
    move-result-object v7

    .line 1392
    check-cast v7, Lh5/d;

    .line 1393
    .line 1394
    iget-object v10, v7, Lh5/d;->q0:[I

    .line 1395
    .line 1396
    const/16 v17, 0x0

    .line 1397
    .line 1398
    aget v14, v10, v17

    .line 1399
    .line 1400
    move/from16 v18, v15

    .line 1401
    .line 1402
    const/4 v15, 0x3

    .line 1403
    if-ne v14, v15, :cond_48

    .line 1404
    .line 1405
    aget v10, v10, v18

    .line 1406
    .line 1407
    if-ne v10, v15, :cond_48

    .line 1408
    .line 1409
    iget v10, v7, Lh5/d;->o0:I

    .line 1410
    .line 1411
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 1412
    .line 1413
    .line 1414
    move-result v14

    .line 1415
    const/4 v15, 0x0

    .line 1416
    :goto_30
    if-ge v15, v14, :cond_45

    .line 1417
    .line 1418
    invoke-virtual {v3, v15}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1419
    .line 1420
    .line 1421
    move-result-object v23

    .line 1422
    move/from16 v25, v6

    .line 1423
    .line 1424
    move-object/from16 v6, v23

    .line 1425
    .line 1426
    check-cast v6, Li5/o;

    .line 1427
    .line 1428
    move-object/from16 v23, v11

    .line 1429
    .line 1430
    iget v11, v6, Li5/o;->b:I

    .line 1431
    .line 1432
    if-ne v10, v11, :cond_44

    .line 1433
    .line 1434
    goto :goto_31

    .line 1435
    :cond_44
    add-int/lit8 v15, v15, 0x1

    .line 1436
    .line 1437
    move-object/from16 v11, v23

    .line 1438
    .line 1439
    move/from16 v6, v25

    .line 1440
    .line 1441
    goto :goto_30

    .line 1442
    :cond_45
    move/from16 v25, v6

    .line 1443
    .line 1444
    move-object/from16 v23, v11

    .line 1445
    .line 1446
    const/4 v6, 0x0

    .line 1447
    :goto_31
    iget v7, v7, Lh5/d;->p0:I

    .line 1448
    .line 1449
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 1450
    .line 1451
    .line 1452
    move-result v10

    .line 1453
    const/4 v11, 0x0

    .line 1454
    :goto_32
    if-ge v11, v10, :cond_47

    .line 1455
    .line 1456
    invoke-virtual {v3, v11}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1457
    .line 1458
    .line 1459
    move-result-object v14

    .line 1460
    check-cast v14, Li5/o;

    .line 1461
    .line 1462
    iget v15, v14, Li5/o;->b:I

    .line 1463
    .line 1464
    if-ne v7, v15, :cond_46

    .line 1465
    .line 1466
    goto :goto_33

    .line 1467
    :cond_46
    add-int/lit8 v11, v11, 0x1

    .line 1468
    .line 1469
    goto :goto_32

    .line 1470
    :cond_47
    const/4 v14, 0x0

    .line 1471
    :goto_33
    if-eqz v6, :cond_49

    .line 1472
    .line 1473
    if-eqz v14, :cond_49

    .line 1474
    .line 1475
    const/4 v15, 0x0

    .line 1476
    invoke-virtual {v6, v15, v14}, Li5/o;->c(ILi5/o;)V

    .line 1477
    .line 1478
    .line 1479
    const/4 v7, 0x2

    .line 1480
    iput v7, v14, Li5/o;->c:I

    .line 1481
    .line 1482
    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 1483
    .line 1484
    .line 1485
    goto :goto_34

    .line 1486
    :cond_48
    move/from16 v25, v6

    .line 1487
    .line 1488
    move-object/from16 v23, v11

    .line 1489
    .line 1490
    :cond_49
    :goto_34
    add-int/lit8 v6, v25, 0x1

    .line 1491
    .line 1492
    move-object/from16 v11, v23

    .line 1493
    .line 1494
    const/4 v15, 0x1

    .line 1495
    goto :goto_2f

    .line 1496
    :cond_4a
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 1497
    .line 1498
    .line 1499
    move-result v6

    .line 1500
    const/4 v15, 0x1

    .line 1501
    if-gt v6, v15, :cond_4b

    .line 1502
    .line 1503
    goto/16 :goto_3b

    .line 1504
    .line 1505
    :cond_4b
    const/4 v6, 0x0

    .line 1506
    aget v7, v19, v6

    .line 1507
    .line 1508
    const/4 v10, 0x2

    .line 1509
    if-ne v7, v10, :cond_4f

    .line 1510
    .line 1511
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1512
    .line 1513
    .line 1514
    move-result-object v7

    .line 1515
    move v10, v6

    .line 1516
    const/4 v11, 0x0

    .line 1517
    :goto_35
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 1518
    .line 1519
    .line 1520
    move-result v13

    .line 1521
    if-eqz v13, :cond_4e

    .line 1522
    .line 1523
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1524
    .line 1525
    .line 1526
    move-result-object v13

    .line 1527
    check-cast v13, Li5/o;

    .line 1528
    .line 1529
    iget v14, v13, Li5/o;->c:I

    .line 1530
    .line 1531
    if-ne v14, v15, :cond_4c

    .line 1532
    .line 1533
    goto :goto_35

    .line 1534
    :cond_4c
    invoke-virtual {v13, v2, v6}, Li5/o;->b(La5/c;I)I

    .line 1535
    .line 1536
    .line 1537
    move-result v14

    .line 1538
    if-le v14, v10, :cond_4d

    .line 1539
    .line 1540
    move-object v11, v13

    .line 1541
    move v10, v14

    .line 1542
    :cond_4d
    const/4 v6, 0x0

    .line 1543
    goto :goto_35

    .line 1544
    :cond_4e
    if-eqz v11, :cond_4f

    .line 1545
    .line 1546
    invoke-virtual {v1, v15}, Lh5/d;->O(I)V

    .line 1547
    .line 1548
    .line 1549
    invoke-virtual {v1, v10}, Lh5/d;->S(I)V

    .line 1550
    .line 1551
    .line 1552
    goto :goto_36

    .line 1553
    :cond_4f
    const/4 v11, 0x0

    .line 1554
    :goto_36
    aget v6, v19, v15

    .line 1555
    .line 1556
    const/4 v7, 0x2

    .line 1557
    if-ne v6, v7, :cond_53

    .line 1558
    .line 1559
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1560
    .line 1561
    .line 1562
    move-result-object v3

    .line 1563
    const/4 v6, 0x0

    .line 1564
    const/4 v7, 0x0

    .line 1565
    :cond_50
    :goto_37
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 1566
    .line 1567
    .line 1568
    move-result v10

    .line 1569
    if-eqz v10, :cond_52

    .line 1570
    .line 1571
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1572
    .line 1573
    .line 1574
    move-result-object v10

    .line 1575
    check-cast v10, Li5/o;

    .line 1576
    .line 1577
    iget v13, v10, Li5/o;->c:I

    .line 1578
    .line 1579
    if-nez v13, :cond_51

    .line 1580
    .line 1581
    goto :goto_37

    .line 1582
    :cond_51
    invoke-virtual {v10, v2, v15}, Li5/o;->b(La5/c;I)I

    .line 1583
    .line 1584
    .line 1585
    move-result v13

    .line 1586
    if-le v13, v6, :cond_50

    .line 1587
    .line 1588
    move-object v7, v10

    .line 1589
    move v6, v13

    .line 1590
    goto :goto_37

    .line 1591
    :cond_52
    if-eqz v7, :cond_53

    .line 1592
    .line 1593
    invoke-virtual {v1, v15}, Lh5/d;->Q(I)V

    .line 1594
    .line 1595
    .line 1596
    invoke-virtual {v1, v6}, Lh5/d;->N(I)V

    .line 1597
    .line 1598
    .line 1599
    goto :goto_38

    .line 1600
    :cond_53
    const/4 v7, 0x0

    .line 1601
    :goto_38
    if-nez v11, :cond_54

    .line 1602
    .line 1603
    if-eqz v7, :cond_59

    .line 1604
    .line 1605
    :cond_54
    const/4 v7, 0x2

    .line 1606
    if-ne v9, v7, :cond_56

    .line 1607
    .line 1608
    invoke-virtual {v1}, Lh5/d;->r()I

    .line 1609
    .line 1610
    .line 1611
    move-result v3

    .line 1612
    if-ge v0, v3, :cond_55

    .line 1613
    .line 1614
    if-lez v0, :cond_55

    .line 1615
    .line 1616
    invoke-virtual {v1, v0}, Lh5/d;->S(I)V

    .line 1617
    .line 1618
    .line 1619
    const/4 v15, 0x1

    .line 1620
    iput-boolean v15, v1, Lh5/e;->F0:Z

    .line 1621
    .line 1622
    goto :goto_39

    .line 1623
    :cond_55
    invoke-virtual {v1}, Lh5/d;->r()I

    .line 1624
    .line 1625
    .line 1626
    move-result v0

    .line 1627
    :cond_56
    :goto_39
    const/4 v7, 0x2

    .line 1628
    if-ne v8, v7, :cond_58

    .line 1629
    .line 1630
    invoke-virtual {v1}, Lh5/d;->l()I

    .line 1631
    .line 1632
    .line 1633
    move-result v3

    .line 1634
    if-ge v5, v3, :cond_57

    .line 1635
    .line 1636
    if-lez v5, :cond_57

    .line 1637
    .line 1638
    invoke-virtual {v1, v5}, Lh5/d;->N(I)V

    .line 1639
    .line 1640
    .line 1641
    const/4 v15, 0x1

    .line 1642
    iput-boolean v15, v1, Lh5/e;->G0:Z

    .line 1643
    .line 1644
    goto :goto_3a

    .line 1645
    :cond_57
    invoke-virtual {v1}, Lh5/d;->l()I

    .line 1646
    .line 1647
    .line 1648
    move-result v5

    .line 1649
    :cond_58
    :goto_3a
    move v3, v0

    .line 1650
    const/4 v0, 0x1

    .line 1651
    goto :goto_3c

    .line 1652
    :cond_59
    :goto_3b
    move v3, v0

    .line 1653
    const/4 v0, 0x0

    .line 1654
    :goto_3c
    const/16 v6, 0x40

    .line 1655
    .line 1656
    invoke-virtual {v1, v6}, Lh5/e;->c0(I)Z

    .line 1657
    .line 1658
    .line 1659
    move-result v7

    .line 1660
    if-nez v7, :cond_5b

    .line 1661
    .line 1662
    const/16 v7, 0x80

    .line 1663
    .line 1664
    invoke-virtual {v1, v7}, Lh5/e;->c0(I)Z

    .line 1665
    .line 1666
    .line 1667
    move-result v7

    .line 1668
    if-eqz v7, :cond_5a

    .line 1669
    .line 1670
    goto :goto_3d

    .line 1671
    :cond_5a
    const/4 v7, 0x0

    .line 1672
    goto :goto_3e

    .line 1673
    :cond_5b
    :goto_3d
    const/4 v7, 0x1

    .line 1674
    :goto_3e
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1675
    .line 1676
    .line 1677
    const/4 v15, 0x0

    .line 1678
    iput-boolean v15, v2, La5/c;->h:Z

    .line 1679
    .line 1680
    iget v10, v1, Lh5/e;->E0:I

    .line 1681
    .line 1682
    if-eqz v10, :cond_5c

    .line 1683
    .line 1684
    if-eqz v7, :cond_5c

    .line 1685
    .line 1686
    const/4 v10, 0x1

    .line 1687
    iput-boolean v10, v2, La5/c;->h:Z

    .line 1688
    .line 1689
    goto :goto_3f

    .line 1690
    :cond_5c
    const/4 v10, 0x1

    .line 1691
    :goto_3f
    iget-object v7, v1, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 1692
    .line 1693
    aget v11, v19, v15

    .line 1694
    .line 1695
    const/4 v13, 0x2

    .line 1696
    if-eq v11, v13, :cond_5e

    .line 1697
    .line 1698
    aget v11, v19, v10

    .line 1699
    .line 1700
    if-ne v11, v13, :cond_5d

    .line 1701
    .line 1702
    goto :goto_40

    .line 1703
    :cond_5d
    move v10, v15

    .line 1704
    goto :goto_41

    .line 1705
    :cond_5e
    :goto_40
    const/4 v10, 0x1

    .line 1706
    :goto_41
    iput v15, v1, Lh5/e;->A0:I

    .line 1707
    .line 1708
    iput v15, v1, Lh5/e;->B0:I

    .line 1709
    .line 1710
    const/4 v11, 0x0

    .line 1711
    :goto_42
    if-ge v11, v4, :cond_60

    .line 1712
    .line 1713
    iget-object v13, v1, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 1714
    .line 1715
    invoke-virtual {v13, v11}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1716
    .line 1717
    .line 1718
    move-result-object v13

    .line 1719
    check-cast v13, Lh5/d;

    .line 1720
    .line 1721
    instance-of v14, v13, Lh5/e;

    .line 1722
    .line 1723
    if-eqz v14, :cond_5f

    .line 1724
    .line 1725
    check-cast v13, Lh5/e;

    .line 1726
    .line 1727
    invoke-virtual {v13}, Lh5/e;->Z()V

    .line 1728
    .line 1729
    .line 1730
    :cond_5f
    add-int/lit8 v11, v11, 0x1

    .line 1731
    .line 1732
    goto :goto_42

    .line 1733
    :cond_60
    invoke-virtual {v1, v6}, Lh5/e;->c0(I)Z

    .line 1734
    .line 1735
    .line 1736
    move-result v11

    .line 1737
    move v13, v0

    .line 1738
    const/4 v0, 0x0

    .line 1739
    const/4 v14, 0x1

    .line 1740
    :goto_43
    if-eqz v14, :cond_74

    .line 1741
    .line 1742
    const/16 v18, 0x1

    .line 1743
    .line 1744
    add-int/lit8 v15, v0, 0x1

    .line 1745
    .line 1746
    :try_start_0
    invoke-virtual {v2}, La5/c;->t()V

    .line 1747
    .line 1748
    .line 1749
    const/4 v6, 0x0

    .line 1750
    iput v6, v1, Lh5/e;->A0:I

    .line 1751
    .line 1752
    iput v6, v1, Lh5/e;->B0:I

    .line 1753
    .line 1754
    invoke-virtual {v1, v2}, Lh5/d;->h(La5/c;)V

    .line 1755
    .line 1756
    .line 1757
    const/4 v0, 0x0

    .line 1758
    :goto_44
    if-ge v0, v4, :cond_61

    .line 1759
    .line 1760
    iget-object v6, v1, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 1761
    .line 1762
    invoke-virtual {v6, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1763
    .line 1764
    .line 1765
    move-result-object v6

    .line 1766
    check-cast v6, Lh5/d;

    .line 1767
    .line 1768
    invoke-virtual {v6, v2}, Lh5/d;->h(La5/c;)V

    .line 1769
    .line 1770
    .line 1771
    add-int/lit8 v0, v0, 0x1

    .line 1772
    .line 1773
    goto :goto_44

    .line 1774
    :catch_0
    move-exception v0

    .line 1775
    move/from16 v23, v10

    .line 1776
    .line 1777
    const/4 v6, 0x0

    .line 1778
    const/4 v10, 0x5

    .line 1779
    goto/16 :goto_4b

    .line 1780
    .line 1781
    :cond_61
    invoke-virtual {v1, v2}, Lh5/e;->X(La5/c;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 1782
    .line 1783
    .line 1784
    :try_start_1
    iget-object v0, v1, Lh5/e;->H0:Ljava/lang/ref/WeakReference;

    .line 1785
    .line 1786
    if-eqz v0, :cond_62

    .line 1787
    .line 1788
    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 1789
    .line 1790
    .line 1791
    move-result-object v0

    .line 1792
    if-eqz v0, :cond_62

    .line 1793
    .line 1794
    iget-object v0, v1, Lh5/e;->H0:Ljava/lang/ref/WeakReference;

    .line 1795
    .line 1796
    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 1797
    .line 1798
    .line 1799
    move-result-object v0

    .line 1800
    check-cast v0, Lh5/c;

    .line 1801
    .line 1802
    invoke-virtual {v2, v12}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 1803
    .line 1804
    .line 1805
    move-result-object v6

    .line 1806
    invoke-virtual {v2, v0}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 1807
    .line 1808
    .line 1809
    move-result-object v0
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_2

    .line 1810
    move/from16 v23, v10

    .line 1811
    .line 1812
    const/4 v10, 0x0

    .line 1813
    const/4 v14, 0x5

    .line 1814
    :try_start_2
    invoke-virtual {v2, v0, v6, v10, v14}, La5/c;->f(La5/h;La5/h;II)V

    .line 1815
    .line 1816
    .line 1817
    const/4 v10, 0x0

    .line 1818
    iput-object v10, v1, Lh5/e;->H0:Ljava/lang/ref/WeakReference;

    .line 1819
    .line 1820
    goto :goto_47

    .line 1821
    :catch_1
    move-exception v0

    .line 1822
    :goto_45
    const/4 v6, 0x0

    .line 1823
    const/4 v10, 0x5

    .line 1824
    :goto_46
    const/4 v14, 0x1

    .line 1825
    goto/16 :goto_4b

    .line 1826
    .line 1827
    :catch_2
    move-exception v0

    .line 1828
    move/from16 v23, v10

    .line 1829
    .line 1830
    goto :goto_45

    .line 1831
    :cond_62
    move/from16 v23, v10

    .line 1832
    .line 1833
    :goto_47
    iget-object v0, v1, Lh5/e;->J0:Ljava/lang/ref/WeakReference;

    .line 1834
    .line 1835
    if-eqz v0, :cond_63

    .line 1836
    .line 1837
    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 1838
    .line 1839
    .line 1840
    move-result-object v0

    .line 1841
    if-eqz v0, :cond_63

    .line 1842
    .line 1843
    iget-object v0, v1, Lh5/e;->J0:Ljava/lang/ref/WeakReference;

    .line 1844
    .line 1845
    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 1846
    .line 1847
    .line 1848
    move-result-object v0

    .line 1849
    check-cast v0, Lh5/c;

    .line 1850
    .line 1851
    iget-object v6, v1, Lh5/d;->M:Lh5/c;

    .line 1852
    .line 1853
    invoke-virtual {v2, v6}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 1854
    .line 1855
    .line 1856
    move-result-object v6

    .line 1857
    invoke-virtual {v2, v0}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 1858
    .line 1859
    .line 1860
    move-result-object v0

    .line 1861
    const/4 v10, 0x0

    .line 1862
    const/4 v14, 0x5

    .line 1863
    invoke-virtual {v2, v6, v0, v10, v14}, La5/c;->f(La5/h;La5/h;II)V

    .line 1864
    .line 1865
    .line 1866
    const/4 v10, 0x0

    .line 1867
    iput-object v10, v1, Lh5/e;->J0:Ljava/lang/ref/WeakReference;

    .line 1868
    .line 1869
    :cond_63
    iget-object v0, v1, Lh5/e;->I0:Ljava/lang/ref/WeakReference;

    .line 1870
    .line 1871
    if-eqz v0, :cond_64

    .line 1872
    .line 1873
    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 1874
    .line 1875
    .line 1876
    move-result-object v0

    .line 1877
    if-eqz v0, :cond_64

    .line 1878
    .line 1879
    iget-object v0, v1, Lh5/e;->I0:Ljava/lang/ref/WeakReference;

    .line 1880
    .line 1881
    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 1882
    .line 1883
    .line 1884
    move-result-object v0

    .line 1885
    check-cast v0, Lh5/c;
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_1

    .line 1886
    .line 1887
    move-object/from16 v6, v24

    .line 1888
    .line 1889
    :try_start_3
    invoke-virtual {v2, v6}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 1890
    .line 1891
    .line 1892
    move-result-object v10

    .line 1893
    invoke-virtual {v2, v0}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 1894
    .line 1895
    .line 1896
    move-result-object v0
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_3

    .line 1897
    move-object/from16 v24, v6

    .line 1898
    .line 1899
    const/4 v6, 0x0

    .line 1900
    const/4 v14, 0x5

    .line 1901
    :try_start_4
    invoke-virtual {v2, v0, v10, v6, v14}, La5/c;->f(La5/h;La5/h;II)V

    .line 1902
    .line 1903
    .line 1904
    const/4 v10, 0x0

    .line 1905
    iput-object v10, v1, Lh5/e;->I0:Ljava/lang/ref/WeakReference;

    .line 1906
    .line 1907
    goto :goto_48

    .line 1908
    :catch_3
    move-exception v0

    .line 1909
    move-object/from16 v24, v6

    .line 1910
    .line 1911
    goto :goto_45

    .line 1912
    :cond_64
    :goto_48
    iget-object v0, v1, Lh5/e;->K0:Ljava/lang/ref/WeakReference;

    .line 1913
    .line 1914
    if-eqz v0, :cond_65

    .line 1915
    .line 1916
    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 1917
    .line 1918
    .line 1919
    move-result-object v0

    .line 1920
    if-eqz v0, :cond_65

    .line 1921
    .line 1922
    iget-object v0, v1, Lh5/e;->K0:Ljava/lang/ref/WeakReference;

    .line 1923
    .line 1924
    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 1925
    .line 1926
    .line 1927
    move-result-object v0

    .line 1928
    check-cast v0, Lh5/c;

    .line 1929
    .line 1930
    iget-object v6, v1, Lh5/d;->L:Lh5/c;

    .line 1931
    .line 1932
    invoke-virtual {v2, v6}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 1933
    .line 1934
    .line 1935
    move-result-object v6
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_1

    .line 1936
    :try_start_5
    invoke-virtual {v2, v0}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 1937
    .line 1938
    .line 1939
    move-result-object v0
    :try_end_5
    .catch Ljava/lang/Exception; {:try_start_5 .. :try_end_5} :catch_6

    .line 1940
    const/4 v10, 0x5

    .line 1941
    const/4 v14, 0x0

    .line 1942
    :try_start_6
    invoke-virtual {v2, v6, v0, v14, v10}, La5/c;->f(La5/h;La5/h;II)V
    :try_end_6
    .catch Ljava/lang/Exception; {:try_start_6 .. :try_end_6} :catch_5

    .line 1943
    .line 1944
    .line 1945
    const/4 v6, 0x0

    .line 1946
    :try_start_7
    iput-object v6, v1, Lh5/e;->K0:Ljava/lang/ref/WeakReference;

    .line 1947
    .line 1948
    goto :goto_4a

    .line 1949
    :catch_4
    move-exception v0

    .line 1950
    goto :goto_46

    .line 1951
    :catch_5
    move-exception v0

    .line 1952
    :goto_49
    const/4 v6, 0x0

    .line 1953
    goto/16 :goto_46

    .line 1954
    .line 1955
    :catch_6
    move-exception v0

    .line 1956
    const/4 v10, 0x5

    .line 1957
    goto :goto_49

    .line 1958
    :cond_65
    const/4 v6, 0x0

    .line 1959
    const/4 v10, 0x5

    .line 1960
    :goto_4a
    invoke-virtual {v2}, La5/c;->p()V
    :try_end_7
    .catch Ljava/lang/Exception; {:try_start_7 .. :try_end_7} :catch_4

    .line 1961
    .line 1962
    .line 1963
    move-object/from16 v25, v12

    .line 1964
    .line 1965
    const/4 v14, 0x1

    .line 1966
    goto :goto_4c

    .line 1967
    :goto_4b
    invoke-virtual {v0}, Ljava/lang/Throwable;->printStackTrace()V

    .line 1968
    .line 1969
    .line 1970
    sget-object v6, Ljava/lang/System;->out:Ljava/io/PrintStream;

    .line 1971
    .line 1972
    new-instance v10, Ljava/lang/StringBuilder;

    .line 1973
    .line 1974
    move-object/from16 v25, v12

    .line 1975
    .line 1976
    const-string v12, "EXCEPTION : "

    .line 1977
    .line 1978
    invoke-direct {v10, v12}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1979
    .line 1980
    .line 1981
    invoke-virtual {v10, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1982
    .line 1983
    .line 1984
    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1985
    .line 1986
    .line 1987
    move-result-object v0

    .line 1988
    invoke-virtual {v6, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    .line 1989
    .line 1990
    .line 1991
    :goto_4c
    sget-object v0, Lh5/j;->a:[Z

    .line 1992
    .line 1993
    if-eqz v14, :cond_69

    .line 1994
    .line 1995
    const/16 v17, 0x0

    .line 1996
    .line 1997
    const/16 v21, 0x2

    .line 1998
    .line 1999
    aput-boolean v17, v0, v21

    .line 2000
    .line 2001
    const/16 v6, 0x40

    .line 2002
    .line 2003
    invoke-virtual {v1, v6}, Lh5/e;->c0(I)Z

    .line 2004
    .line 2005
    .line 2006
    move-result v10

    .line 2007
    invoke-virtual {v1, v2, v10}, Lh5/d;->U(La5/c;Z)V

    .line 2008
    .line 2009
    .line 2010
    iget-object v12, v1, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 2011
    .line 2012
    invoke-virtual {v12}, Ljava/util/ArrayList;->size()I

    .line 2013
    .line 2014
    .line 2015
    move-result v12

    .line 2016
    const/4 v14, 0x0

    .line 2017
    const/16 v16, 0x0

    .line 2018
    .line 2019
    :goto_4d
    if-ge v14, v12, :cond_68

    .line 2020
    .line 2021
    iget-object v6, v1, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 2022
    .line 2023
    invoke-virtual {v6, v14}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 2024
    .line 2025
    .line 2026
    move-result-object v6

    .line 2027
    check-cast v6, Lh5/d;

    .line 2028
    .line 2029
    invoke-virtual {v6, v2, v10}, Lh5/d;->U(La5/c;Z)V

    .line 2030
    .line 2031
    .line 2032
    move-object/from16 v27, v0

    .line 2033
    .line 2034
    iget v0, v6, Lh5/d;->h:I

    .line 2035
    .line 2036
    move/from16 v28, v10

    .line 2037
    .line 2038
    const/4 v10, -0x1

    .line 2039
    if-ne v0, v10, :cond_66

    .line 2040
    .line 2041
    iget v0, v6, Lh5/d;->i:I

    .line 2042
    .line 2043
    if-eq v0, v10, :cond_67

    .line 2044
    .line 2045
    :cond_66
    const/16 v16, 0x1

    .line 2046
    .line 2047
    :cond_67
    add-int/lit8 v14, v14, 0x1

    .line 2048
    .line 2049
    move-object/from16 v0, v27

    .line 2050
    .line 2051
    move/from16 v10, v28

    .line 2052
    .line 2053
    const/16 v6, 0x40

    .line 2054
    .line 2055
    goto :goto_4d

    .line 2056
    :cond_68
    move-object/from16 v27, v0

    .line 2057
    .line 2058
    const/4 v10, -0x1

    .line 2059
    goto :goto_4f

    .line 2060
    :cond_69
    move-object/from16 v27, v0

    .line 2061
    .line 2062
    const/4 v10, -0x1

    .line 2063
    invoke-virtual {v1, v2, v11}, Lh5/d;->U(La5/c;Z)V

    .line 2064
    .line 2065
    .line 2066
    const/4 v0, 0x0

    .line 2067
    :goto_4e
    if-ge v0, v4, :cond_6a

    .line 2068
    .line 2069
    iget-object v6, v1, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 2070
    .line 2071
    invoke-virtual {v6, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 2072
    .line 2073
    .line 2074
    move-result-object v6

    .line 2075
    check-cast v6, Lh5/d;

    .line 2076
    .line 2077
    invoke-virtual {v6, v2, v11}, Lh5/d;->U(La5/c;Z)V

    .line 2078
    .line 2079
    .line 2080
    add-int/lit8 v0, v0, 0x1

    .line 2081
    .line 2082
    goto :goto_4e

    .line 2083
    :cond_6a
    const/16 v16, 0x0

    .line 2084
    .line 2085
    :goto_4f
    const/16 v0, 0x8

    .line 2086
    .line 2087
    if-eqz v23, :cond_6d

    .line 2088
    .line 2089
    if-ge v15, v0, :cond_6d

    .line 2090
    .line 2091
    const/16 v21, 0x2

    .line 2092
    .line 2093
    aget-boolean v6, v27, v21

    .line 2094
    .line 2095
    if-eqz v6, :cond_6d

    .line 2096
    .line 2097
    const/4 v6, 0x0

    .line 2098
    const/4 v12, 0x0

    .line 2099
    const/4 v14, 0x0

    .line 2100
    :goto_50
    if-ge v6, v4, :cond_6b

    .line 2101
    .line 2102
    iget-object v10, v1, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 2103
    .line 2104
    invoke-virtual {v10, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 2105
    .line 2106
    .line 2107
    move-result-object v10

    .line 2108
    check-cast v10, Lh5/d;

    .line 2109
    .line 2110
    iget v0, v10, Lh5/d;->Z:I

    .line 2111
    .line 2112
    invoke-virtual {v10}, Lh5/d;->r()I

    .line 2113
    .line 2114
    .line 2115
    move-result v28

    .line 2116
    add-int v0, v28, v0

    .line 2117
    .line 2118
    invoke-static {v12, v0}, Ljava/lang/Math;->max(II)I

    .line 2119
    .line 2120
    .line 2121
    move-result v12

    .line 2122
    iget v0, v10, Lh5/d;->a0:I

    .line 2123
    .line 2124
    invoke-virtual {v10}, Lh5/d;->l()I

    .line 2125
    .line 2126
    .line 2127
    move-result v10

    .line 2128
    add-int/2addr v10, v0

    .line 2129
    invoke-static {v14, v10}, Ljava/lang/Math;->max(II)I

    .line 2130
    .line 2131
    .line 2132
    move-result v14

    .line 2133
    add-int/lit8 v6, v6, 0x1

    .line 2134
    .line 2135
    const/16 v0, 0x8

    .line 2136
    .line 2137
    const/4 v10, -0x1

    .line 2138
    goto :goto_50

    .line 2139
    :cond_6b
    iget v0, v1, Lh5/d;->c0:I

    .line 2140
    .line 2141
    invoke-static {v0, v12}, Ljava/lang/Math;->max(II)I

    .line 2142
    .line 2143
    .line 2144
    move-result v0

    .line 2145
    iget v6, v1, Lh5/d;->d0:I

    .line 2146
    .line 2147
    invoke-static {v6, v14}, Ljava/lang/Math;->max(II)I

    .line 2148
    .line 2149
    .line 2150
    move-result v6

    .line 2151
    const/4 v10, 0x2

    .line 2152
    if-ne v9, v10, :cond_6c

    .line 2153
    .line 2154
    invoke-virtual {v1}, Lh5/d;->r()I

    .line 2155
    .line 2156
    .line 2157
    move-result v12

    .line 2158
    if-ge v12, v0, :cond_6c

    .line 2159
    .line 2160
    invoke-virtual {v1, v0}, Lh5/d;->S(I)V

    .line 2161
    .line 2162
    .line 2163
    const/16 v17, 0x0

    .line 2164
    .line 2165
    aput v10, v19, v17

    .line 2166
    .line 2167
    const/4 v13, 0x1

    .line 2168
    const/16 v16, 0x1

    .line 2169
    .line 2170
    :cond_6c
    if-ne v8, v10, :cond_6d

    .line 2171
    .line 2172
    invoke-virtual {v1}, Lh5/d;->l()I

    .line 2173
    .line 2174
    .line 2175
    move-result v0

    .line 2176
    if-ge v0, v6, :cond_6d

    .line 2177
    .line 2178
    invoke-virtual {v1, v6}, Lh5/d;->N(I)V

    .line 2179
    .line 2180
    .line 2181
    const/16 v18, 0x1

    .line 2182
    .line 2183
    aput v10, v19, v18

    .line 2184
    .line 2185
    const/4 v13, 0x1

    .line 2186
    const/16 v16, 0x1

    .line 2187
    .line 2188
    :cond_6d
    iget v0, v1, Lh5/d;->c0:I

    .line 2189
    .line 2190
    invoke-virtual {v1}, Lh5/d;->r()I

    .line 2191
    .line 2192
    .line 2193
    move-result v6

    .line 2194
    invoke-static {v0, v6}, Ljava/lang/Math;->max(II)I

    .line 2195
    .line 2196
    .line 2197
    move-result v0

    .line 2198
    invoke-virtual {v1}, Lh5/d;->r()I

    .line 2199
    .line 2200
    .line 2201
    move-result v6

    .line 2202
    if-le v0, v6, :cond_6e

    .line 2203
    .line 2204
    invoke-virtual {v1, v0}, Lh5/d;->S(I)V

    .line 2205
    .line 2206
    .line 2207
    const/4 v6, 0x1

    .line 2208
    const/16 v17, 0x0

    .line 2209
    .line 2210
    aput v6, v19, v17

    .line 2211
    .line 2212
    move/from16 v16, v6

    .line 2213
    .line 2214
    move/from16 v18, v16

    .line 2215
    .line 2216
    goto :goto_51

    .line 2217
    :cond_6e
    const/4 v6, 0x1

    .line 2218
    move/from16 v18, v13

    .line 2219
    .line 2220
    :goto_51
    iget v0, v1, Lh5/d;->d0:I

    .line 2221
    .line 2222
    invoke-virtual {v1}, Lh5/d;->l()I

    .line 2223
    .line 2224
    .line 2225
    move-result v10

    .line 2226
    invoke-static {v0, v10}, Ljava/lang/Math;->max(II)I

    .line 2227
    .line 2228
    .line 2229
    move-result v0

    .line 2230
    invoke-virtual {v1}, Lh5/d;->l()I

    .line 2231
    .line 2232
    .line 2233
    move-result v10

    .line 2234
    if-le v0, v10, :cond_6f

    .line 2235
    .line 2236
    invoke-virtual {v1, v0}, Lh5/d;->N(I)V

    .line 2237
    .line 2238
    .line 2239
    aput v6, v19, v6

    .line 2240
    .line 2241
    move v0, v6

    .line 2242
    move/from16 v16, v0

    .line 2243
    .line 2244
    goto :goto_52

    .line 2245
    :cond_6f
    move/from16 v0, v18

    .line 2246
    .line 2247
    :goto_52
    if-nez v0, :cond_72

    .line 2248
    .line 2249
    const/16 v17, 0x0

    .line 2250
    .line 2251
    aget v10, v19, v17

    .line 2252
    .line 2253
    const/4 v13, 0x2

    .line 2254
    if-ne v10, v13, :cond_70

    .line 2255
    .line 2256
    if-lez v3, :cond_70

    .line 2257
    .line 2258
    invoke-virtual {v1}, Lh5/d;->r()I

    .line 2259
    .line 2260
    .line 2261
    move-result v10

    .line 2262
    if-le v10, v3, :cond_70

    .line 2263
    .line 2264
    iput-boolean v6, v1, Lh5/e;->F0:Z

    .line 2265
    .line 2266
    aput v6, v19, v17

    .line 2267
    .line 2268
    invoke-virtual {v1, v3}, Lh5/d;->S(I)V

    .line 2269
    .line 2270
    .line 2271
    move v0, v6

    .line 2272
    move/from16 v16, v0

    .line 2273
    .line 2274
    :cond_70
    aget v10, v19, v6

    .line 2275
    .line 2276
    const/4 v12, 0x2

    .line 2277
    if-ne v10, v12, :cond_71

    .line 2278
    .line 2279
    if-lez v5, :cond_71

    .line 2280
    .line 2281
    invoke-virtual {v1}, Lh5/d;->l()I

    .line 2282
    .line 2283
    .line 2284
    move-result v10

    .line 2285
    if-le v10, v5, :cond_71

    .line 2286
    .line 2287
    iput-boolean v6, v1, Lh5/e;->G0:Z

    .line 2288
    .line 2289
    aput v6, v19, v6

    .line 2290
    .line 2291
    invoke-virtual {v1, v5}, Lh5/d;->N(I)V

    .line 2292
    .line 2293
    .line 2294
    const/16 v0, 0x8

    .line 2295
    .line 2296
    const/4 v6, 0x1

    .line 2297
    const/4 v13, 0x1

    .line 2298
    goto :goto_54

    .line 2299
    :cond_71
    :goto_53
    move v13, v0

    .line 2300
    move/from16 v6, v16

    .line 2301
    .line 2302
    const/16 v0, 0x8

    .line 2303
    .line 2304
    goto :goto_54

    .line 2305
    :cond_72
    const/4 v12, 0x2

    .line 2306
    goto :goto_53

    .line 2307
    :goto_54
    if-le v15, v0, :cond_73

    .line 2308
    .line 2309
    const/4 v14, 0x0

    .line 2310
    goto :goto_55

    .line 2311
    :cond_73
    move v14, v6

    .line 2312
    :goto_55
    move v0, v15

    .line 2313
    move/from16 v10, v23

    .line 2314
    .line 2315
    move-object/from16 v12, v25

    .line 2316
    .line 2317
    const/16 v6, 0x40

    .line 2318
    .line 2319
    goto/16 :goto_43

    .line 2320
    .line 2321
    :cond_74
    iput-object v7, v1, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 2322
    .line 2323
    if-eqz v13, :cond_75

    .line 2324
    .line 2325
    const/16 v17, 0x0

    .line 2326
    .line 2327
    aput v9, v19, v17

    .line 2328
    .line 2329
    const/16 v18, 0x1

    .line 2330
    .line 2331
    aput v8, v19, v18

    .line 2332
    .line 2333
    :cond_75
    iget-object v0, v2, La5/c;->m:Lgw0/c;

    .line 2334
    .line 2335
    invoke-virtual {v1, v0}, Lh5/e;->G(Lgw0/c;)V

    .line 2336
    .line 2337
    .line 2338
    return-void
.end method

.method public final a0(IIIIIII)V
    .locals 24

    .line 1
    move-object/from16 v0, p0

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
    move/from16 v4, p6

    .line 10
    .line 11
    iput v4, v0, Lh5/e;->y0:I

    .line 12
    .line 13
    move/from16 v4, p7

    .line 14
    .line 15
    iput v4, v0, Lh5/e;->z0:I

    .line 16
    .line 17
    iget-object v4, v0, Lh5/e;->s0:Lgw0/c;

    .line 18
    .line 19
    iget-object v5, v4, Lgw0/c;->g:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v5, Lh5/e;

    .line 22
    .line 23
    iget-object v6, v4, Lgw0/c;->e:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v6, Ljava/util/ArrayList;

    .line 26
    .line 27
    iget-object v7, v0, Lh5/e;->v0:Li5/c;

    .line 28
    .line 29
    iget-object v8, v0, Lh5/e;->t0:Li5/f;

    .line 30
    .line 31
    iget-object v9, v0, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 32
    .line 33
    invoke-virtual {v9}, Ljava/util/ArrayList;->size()I

    .line 34
    .line 35
    .line 36
    move-result v9

    .line 37
    invoke-virtual {v0}, Lh5/d;->r()I

    .line 38
    .line 39
    .line 40
    move-result v10

    .line 41
    invoke-virtual {v0}, Lh5/d;->l()I

    .line 42
    .line 43
    .line 44
    move-result v11

    .line 45
    const/16 v12, 0x80

    .line 46
    .line 47
    invoke-static {v1, v12}, Lh5/j;->c(II)Z

    .line 48
    .line 49
    .line 50
    move-result v12

    .line 51
    const/16 v13, 0x40

    .line 52
    .line 53
    if-nez v12, :cond_1

    .line 54
    .line 55
    invoke-static {v1, v13}, Lh5/j;->c(II)Z

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    if-eqz v1, :cond_0

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_0
    const/4 v1, 0x0

    .line 63
    goto :goto_1

    .line 64
    :cond_1
    :goto_0
    const/4 v1, 0x1

    .line 65
    :goto_1
    const/16 v16, 0x0

    .line 66
    .line 67
    const/4 v13, 0x3

    .line 68
    const/16 p7, 0x0

    .line 69
    .line 70
    if-eqz v1, :cond_a

    .line 71
    .line 72
    const/4 v14, 0x0

    .line 73
    :goto_2
    if-ge v14, v9, :cond_a

    .line 74
    .line 75
    const/16 v17, 0x1

    .line 76
    .line 77
    iget-object v15, v0, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 78
    .line 79
    invoke-virtual {v15, v14}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v15

    .line 83
    check-cast v15, Lh5/d;

    .line 84
    .line 85
    move/from16 p1, v1

    .line 86
    .line 87
    iget-object v1, v15, Lh5/d;->q0:[I

    .line 88
    .line 89
    move-object/from16 v18, v1

    .line 90
    .line 91
    aget v1, v18, p7

    .line 92
    .line 93
    if-ne v1, v13, :cond_2

    .line 94
    .line 95
    move/from16 v19, v17

    .line 96
    .line 97
    goto :goto_3

    .line 98
    :cond_2
    move/from16 v19, p7

    .line 99
    .line 100
    :goto_3
    aget v1, v18, v17

    .line 101
    .line 102
    if-ne v1, v13, :cond_3

    .line 103
    .line 104
    move/from16 v1, v17

    .line 105
    .line 106
    goto :goto_4

    .line 107
    :cond_3
    move/from16 v1, p7

    .line 108
    .line 109
    :goto_4
    if-eqz v19, :cond_4

    .line 110
    .line 111
    if-eqz v1, :cond_4

    .line 112
    .line 113
    iget v1, v15, Lh5/d;->X:F

    .line 114
    .line 115
    cmpl-float v1, v1, v16

    .line 116
    .line 117
    if-lez v1, :cond_4

    .line 118
    .line 119
    move/from16 v1, v17

    .line 120
    .line 121
    goto :goto_5

    .line 122
    :cond_4
    move/from16 v1, p7

    .line 123
    .line 124
    :goto_5
    invoke-virtual {v15}, Lh5/d;->y()Z

    .line 125
    .line 126
    .line 127
    move-result v18

    .line 128
    if-eqz v18, :cond_6

    .line 129
    .line 130
    if-eqz v1, :cond_6

    .line 131
    .line 132
    :cond_5
    :goto_6
    move/from16 v1, p7

    .line 133
    .line 134
    goto :goto_7

    .line 135
    :cond_6
    invoke-virtual {v15}, Lh5/d;->z()Z

    .line 136
    .line 137
    .line 138
    move-result v18

    .line 139
    if-eqz v18, :cond_7

    .line 140
    .line 141
    if-eqz v1, :cond_7

    .line 142
    .line 143
    goto :goto_6

    .line 144
    :cond_7
    instance-of v1, v15, Lh5/k;

    .line 145
    .line 146
    if-eqz v1, :cond_8

    .line 147
    .line 148
    goto :goto_6

    .line 149
    :cond_8
    invoke-virtual {v15}, Lh5/d;->y()Z

    .line 150
    .line 151
    .line 152
    move-result v1

    .line 153
    if-nez v1, :cond_5

    .line 154
    .line 155
    invoke-virtual {v15}, Lh5/d;->z()Z

    .line 156
    .line 157
    .line 158
    move-result v1

    .line 159
    if-eqz v1, :cond_9

    .line 160
    .line 161
    goto :goto_6

    .line 162
    :cond_9
    add-int/lit8 v14, v14, 0x1

    .line 163
    .line 164
    move/from16 v1, p1

    .line 165
    .line 166
    goto :goto_2

    .line 167
    :cond_a
    move/from16 p1, v1

    .line 168
    .line 169
    const/16 v17, 0x1

    .line 170
    .line 171
    move/from16 v1, p1

    .line 172
    .line 173
    :goto_7
    const/high16 v14, 0x40000000    # 2.0f

    .line 174
    .line 175
    if-ne v2, v14, :cond_b

    .line 176
    .line 177
    if-eq v3, v14, :cond_c

    .line 178
    .line 179
    :cond_b
    if-eqz v12, :cond_d

    .line 180
    .line 181
    :cond_c
    move/from16 v15, v17

    .line 182
    .line 183
    goto :goto_8

    .line 184
    :cond_d
    move/from16 v15, p7

    .line 185
    .line 186
    :goto_8
    and-int/2addr v1, v15

    .line 187
    if-eqz v1, :cond_2e

    .line 188
    .line 189
    iget-object v15, v0, Lh5/d;->D:[I

    .line 190
    .line 191
    aget v13, v15, p7

    .line 192
    .line 193
    move/from16 v14, p3

    .line 194
    .line 195
    invoke-static {v13, v14}, Ljava/lang/Math;->min(II)I

    .line 196
    .line 197
    .line 198
    move-result v13

    .line 199
    aget v14, v15, v17

    .line 200
    .line 201
    move/from16 v15, p5

    .line 202
    .line 203
    invoke-static {v14, v15}, Ljava/lang/Math;->min(II)I

    .line 204
    .line 205
    .line 206
    move-result v14

    .line 207
    const/high16 v15, 0x40000000    # 2.0f

    .line 208
    .line 209
    if-ne v2, v15, :cond_f

    .line 210
    .line 211
    invoke-virtual {v0}, Lh5/d;->r()I

    .line 212
    .line 213
    .line 214
    move-result v15

    .line 215
    if-eq v15, v13, :cond_e

    .line 216
    .line 217
    invoke-virtual {v0, v13}, Lh5/d;->S(I)V

    .line 218
    .line 219
    .line 220
    move/from16 v13, v17

    .line 221
    .line 222
    iput-boolean v13, v8, Li5/f;->b:Z

    .line 223
    .line 224
    :goto_9
    const/high16 v15, 0x40000000    # 2.0f

    .line 225
    .line 226
    goto :goto_a

    .line 227
    :cond_e
    move/from16 v13, v17

    .line 228
    .line 229
    goto :goto_9

    .line 230
    :cond_f
    move/from16 v13, v17

    .line 231
    .line 232
    :goto_a
    if-ne v3, v15, :cond_11

    .line 233
    .line 234
    invoke-virtual {v0}, Lh5/d;->l()I

    .line 235
    .line 236
    .line 237
    move-result v15

    .line 238
    if-eq v15, v14, :cond_10

    .line 239
    .line 240
    invoke-virtual {v0, v14}, Lh5/d;->N(I)V

    .line 241
    .line 242
    .line 243
    iput-boolean v13, v8, Li5/f;->b:Z

    .line 244
    .line 245
    :cond_10
    const/high16 v15, 0x40000000    # 2.0f

    .line 246
    .line 247
    :cond_11
    if-ne v2, v15, :cond_27

    .line 248
    .line 249
    if-ne v3, v15, :cond_27

    .line 250
    .line 251
    iget-object v13, v8, Li5/f;->f:Ljava/io/Serializable;

    .line 252
    .line 253
    check-cast v13, Ljava/util/ArrayList;

    .line 254
    .line 255
    iget-object v14, v8, Li5/f;->d:Ljava/lang/Object;

    .line 256
    .line 257
    check-cast v14, Lh5/e;

    .line 258
    .line 259
    iget-boolean v15, v8, Li5/f;->b:Z

    .line 260
    .line 261
    if-nez v15, :cond_13

    .line 262
    .line 263
    iget-boolean v15, v8, Li5/f;->c:Z

    .line 264
    .line 265
    if-eqz v15, :cond_12

    .line 266
    .line 267
    goto :goto_b

    .line 268
    :cond_12
    move/from16 v21, v1

    .line 269
    .line 270
    move/from16 v20, v9

    .line 271
    .line 272
    move/from16 v9, p7

    .line 273
    .line 274
    goto :goto_d

    .line 275
    :cond_13
    :goto_b
    iget-object v15, v14, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 276
    .line 277
    invoke-virtual {v15}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 278
    .line 279
    .line 280
    move-result-object v15

    .line 281
    :goto_c
    invoke-interface {v15}, Ljava/util/Iterator;->hasNext()Z

    .line 282
    .line 283
    .line 284
    move-result v20

    .line 285
    if-eqz v20, :cond_14

    .line 286
    .line 287
    invoke-interface {v15}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 288
    .line 289
    .line 290
    move-result-object v20

    .line 291
    move/from16 v21, v1

    .line 292
    .line 293
    move-object/from16 v1, v20

    .line 294
    .line 295
    check-cast v1, Lh5/d;

    .line 296
    .line 297
    invoke-virtual {v1}, Lh5/d;->i()V

    .line 298
    .line 299
    .line 300
    move/from16 v20, v9

    .line 301
    .line 302
    move/from16 v9, p7

    .line 303
    .line 304
    iput-boolean v9, v1, Lh5/d;->a:Z

    .line 305
    .line 306
    iget-object v9, v1, Lh5/d;->d:Li5/l;

    .line 307
    .line 308
    invoke-virtual {v9}, Li5/l;->n()V

    .line 309
    .line 310
    .line 311
    iget-object v1, v1, Lh5/d;->e:Li5/n;

    .line 312
    .line 313
    invoke-virtual {v1}, Li5/n;->m()V

    .line 314
    .line 315
    .line 316
    move/from16 v9, v20

    .line 317
    .line 318
    move/from16 v1, v21

    .line 319
    .line 320
    const/16 p7, 0x0

    .line 321
    .line 322
    goto :goto_c

    .line 323
    :cond_14
    move/from16 v21, v1

    .line 324
    .line 325
    move/from16 v20, v9

    .line 326
    .line 327
    invoke-virtual {v14}, Lh5/d;->i()V

    .line 328
    .line 329
    .line 330
    const/4 v9, 0x0

    .line 331
    iput-boolean v9, v14, Lh5/d;->a:Z

    .line 332
    .line 333
    iget-object v1, v14, Lh5/d;->d:Li5/l;

    .line 334
    .line 335
    invoke-virtual {v1}, Li5/l;->n()V

    .line 336
    .line 337
    .line 338
    iget-object v1, v14, Lh5/d;->e:Li5/n;

    .line 339
    .line 340
    invoke-virtual {v1}, Li5/n;->m()V

    .line 341
    .line 342
    .line 343
    iput-boolean v9, v8, Li5/f;->c:Z

    .line 344
    .line 345
    :goto_d
    iget-object v1, v8, Li5/f;->e:Ljava/lang/Object;

    .line 346
    .line 347
    check-cast v1, Lh5/e;

    .line 348
    .line 349
    invoke-virtual {v8, v1}, Li5/f;->b(Lh5/e;)V

    .line 350
    .line 351
    .line 352
    iput v9, v14, Lh5/d;->Z:I

    .line 353
    .line 354
    iget-object v1, v14, Lh5/d;->q0:[I

    .line 355
    .line 356
    iput v9, v14, Lh5/d;->a0:I

    .line 357
    .line 358
    invoke-virtual {v14, v9}, Lh5/d;->k(I)I

    .line 359
    .line 360
    .line 361
    move-result v15

    .line 362
    move-object/from16 p3, v1

    .line 363
    .line 364
    const/4 v9, 0x1

    .line 365
    invoke-virtual {v14, v9}, Lh5/d;->k(I)I

    .line 366
    .line 367
    .line 368
    move-result v1

    .line 369
    iget-boolean v9, v8, Li5/f;->b:Z

    .line 370
    .line 371
    if-eqz v9, :cond_15

    .line 372
    .line 373
    invoke-virtual {v8}, Li5/f;->c()V

    .line 374
    .line 375
    .line 376
    :cond_15
    invoke-virtual {v14}, Lh5/d;->s()I

    .line 377
    .line 378
    .line 379
    move-result v9

    .line 380
    move-object/from16 p5, v13

    .line 381
    .line 382
    invoke-virtual {v14}, Lh5/d;->t()I

    .line 383
    .line 384
    .line 385
    move-result v13

    .line 386
    move-object/from16 v22, v7

    .line 387
    .line 388
    iget-object v7, v14, Lh5/d;->d:Li5/l;

    .line 389
    .line 390
    iget-object v7, v7, Li5/p;->h:Li5/g;

    .line 391
    .line 392
    invoke-virtual {v7, v9}, Li5/g;->d(I)V

    .line 393
    .line 394
    .line 395
    iget-object v7, v14, Lh5/d;->e:Li5/n;

    .line 396
    .line 397
    iget-object v7, v7, Li5/p;->h:Li5/g;

    .line 398
    .line 399
    invoke-virtual {v7, v13}, Li5/g;->d(I)V

    .line 400
    .line 401
    .line 402
    invoke-virtual {v8}, Li5/f;->g()V

    .line 403
    .line 404
    .line 405
    const/4 v7, 0x2

    .line 406
    if-eq v15, v7, :cond_17

    .line 407
    .line 408
    if-ne v1, v7, :cond_16

    .line 409
    .line 410
    goto :goto_e

    .line 411
    :cond_16
    move/from16 v23, v9

    .line 412
    .line 413
    const/4 v7, 0x0

    .line 414
    const/4 v9, 0x1

    .line 415
    goto :goto_11

    .line 416
    :cond_17
    :goto_e
    if-eqz v12, :cond_19

    .line 417
    .line 418
    invoke-virtual/range {p5 .. p5}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 419
    .line 420
    .line 421
    move-result-object v7

    .line 422
    :cond_18
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 423
    .line 424
    .line 425
    move-result v23

    .line 426
    if-eqz v23, :cond_19

    .line 427
    .line 428
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 429
    .line 430
    .line 431
    move-result-object v23

    .line 432
    check-cast v23, Li5/p;

    .line 433
    .line 434
    invoke-virtual/range {v23 .. v23}, Li5/p;->k()Z

    .line 435
    .line 436
    .line 437
    move-result v23

    .line 438
    if-nez v23, :cond_18

    .line 439
    .line 440
    const/4 v12, 0x0

    .line 441
    :cond_19
    if-eqz v12, :cond_1a

    .line 442
    .line 443
    const/4 v7, 0x2

    .line 444
    if-ne v15, v7, :cond_1a

    .line 445
    .line 446
    const/4 v7, 0x1

    .line 447
    invoke-virtual {v14, v7}, Lh5/d;->O(I)V

    .line 448
    .line 449
    .line 450
    move/from16 v23, v9

    .line 451
    .line 452
    const/4 v7, 0x0

    .line 453
    invoke-virtual {v8, v14, v7}, Li5/f;->d(Lh5/e;I)I

    .line 454
    .line 455
    .line 456
    move-result v9

    .line 457
    invoke-virtual {v14, v9}, Lh5/d;->S(I)V

    .line 458
    .line 459
    .line 460
    iget-object v7, v14, Lh5/d;->d:Li5/l;

    .line 461
    .line 462
    iget-object v7, v7, Li5/p;->e:Li5/h;

    .line 463
    .line 464
    invoke-virtual {v14}, Lh5/d;->r()I

    .line 465
    .line 466
    .line 467
    move-result v9

    .line 468
    invoke-virtual {v7, v9}, Li5/h;->d(I)V

    .line 469
    .line 470
    .line 471
    goto :goto_f

    .line 472
    :cond_1a
    move/from16 v23, v9

    .line 473
    .line 474
    :goto_f
    if-eqz v12, :cond_1b

    .line 475
    .line 476
    const/4 v7, 0x2

    .line 477
    if-ne v1, v7, :cond_1b

    .line 478
    .line 479
    const/4 v9, 0x1

    .line 480
    invoke-virtual {v14, v9}, Lh5/d;->Q(I)V

    .line 481
    .line 482
    .line 483
    invoke-virtual {v8, v14, v9}, Li5/f;->d(Lh5/e;I)I

    .line 484
    .line 485
    .line 486
    move-result v7

    .line 487
    invoke-virtual {v14, v7}, Lh5/d;->N(I)V

    .line 488
    .line 489
    .line 490
    iget-object v7, v14, Lh5/d;->e:Li5/n;

    .line 491
    .line 492
    iget-object v7, v7, Li5/p;->e:Li5/h;

    .line 493
    .line 494
    invoke-virtual {v14}, Lh5/d;->l()I

    .line 495
    .line 496
    .line 497
    move-result v12

    .line 498
    invoke-virtual {v7, v12}, Li5/h;->d(I)V

    .line 499
    .line 500
    .line 501
    :goto_10
    const/4 v7, 0x0

    .line 502
    goto :goto_11

    .line 503
    :cond_1b
    const/4 v9, 0x1

    .line 504
    goto :goto_10

    .line 505
    :goto_11
    aget v12, p3, v7

    .line 506
    .line 507
    if-eq v12, v9, :cond_1d

    .line 508
    .line 509
    const/4 v7, 0x4

    .line 510
    if-ne v12, v7, :cond_1c

    .line 511
    .line 512
    goto :goto_12

    .line 513
    :cond_1c
    const/4 v7, 0x0

    .line 514
    goto :goto_13

    .line 515
    :cond_1d
    :goto_12
    invoke-virtual {v14}, Lh5/d;->r()I

    .line 516
    .line 517
    .line 518
    move-result v7

    .line 519
    add-int v7, v7, v23

    .line 520
    .line 521
    iget-object v9, v14, Lh5/d;->d:Li5/l;

    .line 522
    .line 523
    iget-object v9, v9, Li5/p;->i:Li5/g;

    .line 524
    .line 525
    invoke-virtual {v9, v7}, Li5/g;->d(I)V

    .line 526
    .line 527
    .line 528
    iget-object v9, v14, Lh5/d;->d:Li5/l;

    .line 529
    .line 530
    iget-object v9, v9, Li5/p;->e:Li5/h;

    .line 531
    .line 532
    sub-int v7, v7, v23

    .line 533
    .line 534
    invoke-virtual {v9, v7}, Li5/h;->d(I)V

    .line 535
    .line 536
    .line 537
    invoke-virtual {v8}, Li5/f;->g()V

    .line 538
    .line 539
    .line 540
    const/4 v9, 0x1

    .line 541
    aget v7, p3, v9

    .line 542
    .line 543
    if-eq v7, v9, :cond_1e

    .line 544
    .line 545
    const/4 v9, 0x4

    .line 546
    if-ne v7, v9, :cond_1f

    .line 547
    .line 548
    :cond_1e
    invoke-virtual {v14}, Lh5/d;->l()I

    .line 549
    .line 550
    .line 551
    move-result v7

    .line 552
    add-int/2addr v7, v13

    .line 553
    iget-object v9, v14, Lh5/d;->e:Li5/n;

    .line 554
    .line 555
    iget-object v9, v9, Li5/p;->i:Li5/g;

    .line 556
    .line 557
    invoke-virtual {v9, v7}, Li5/g;->d(I)V

    .line 558
    .line 559
    .line 560
    iget-object v9, v14, Lh5/d;->e:Li5/n;

    .line 561
    .line 562
    iget-object v9, v9, Li5/p;->e:Li5/h;

    .line 563
    .line 564
    sub-int/2addr v7, v13

    .line 565
    invoke-virtual {v9, v7}, Li5/h;->d(I)V

    .line 566
    .line 567
    .line 568
    :cond_1f
    invoke-virtual {v8}, Li5/f;->g()V

    .line 569
    .line 570
    .line 571
    const/4 v7, 0x1

    .line 572
    :goto_13
    invoke-virtual/range {p5 .. p5}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 573
    .line 574
    .line 575
    move-result-object v8

    .line 576
    :goto_14
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 577
    .line 578
    .line 579
    move-result v9

    .line 580
    if-eqz v9, :cond_21

    .line 581
    .line 582
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 583
    .line 584
    .line 585
    move-result-object v9

    .line 586
    check-cast v9, Li5/p;

    .line 587
    .line 588
    iget-object v12, v9, Li5/p;->b:Lh5/d;

    .line 589
    .line 590
    if-ne v12, v14, :cond_20

    .line 591
    .line 592
    iget-boolean v12, v9, Li5/p;->g:Z

    .line 593
    .line 594
    if-nez v12, :cond_20

    .line 595
    .line 596
    goto :goto_14

    .line 597
    :cond_20
    invoke-virtual {v9}, Li5/p;->e()V

    .line 598
    .line 599
    .line 600
    goto :goto_14

    .line 601
    :cond_21
    invoke-virtual/range {p5 .. p5}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 602
    .line 603
    .line 604
    move-result-object v8

    .line 605
    :cond_22
    :goto_15
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 606
    .line 607
    .line 608
    move-result v9

    .line 609
    if-eqz v9, :cond_26

    .line 610
    .line 611
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 612
    .line 613
    .line 614
    move-result-object v9

    .line 615
    check-cast v9, Li5/p;

    .line 616
    .line 617
    if-nez v7, :cond_23

    .line 618
    .line 619
    iget-object v12, v9, Li5/p;->b:Lh5/d;

    .line 620
    .line 621
    if-ne v12, v14, :cond_23

    .line 622
    .line 623
    goto :goto_15

    .line 624
    :cond_23
    iget-object v12, v9, Li5/p;->h:Li5/g;

    .line 625
    .line 626
    iget-boolean v12, v12, Li5/g;->j:Z

    .line 627
    .line 628
    if-nez v12, :cond_24

    .line 629
    .line 630
    :goto_16
    const/4 v7, 0x0

    .line 631
    goto :goto_17

    .line 632
    :cond_24
    iget-object v12, v9, Li5/p;->i:Li5/g;

    .line 633
    .line 634
    iget-boolean v12, v12, Li5/g;->j:Z

    .line 635
    .line 636
    if-nez v12, :cond_25

    .line 637
    .line 638
    instance-of v12, v9, Li5/j;

    .line 639
    .line 640
    if-nez v12, :cond_25

    .line 641
    .line 642
    goto :goto_16

    .line 643
    :cond_25
    iget-object v12, v9, Li5/p;->e:Li5/h;

    .line 644
    .line 645
    iget-boolean v12, v12, Li5/g;->j:Z

    .line 646
    .line 647
    if-nez v12, :cond_22

    .line 648
    .line 649
    instance-of v12, v9, Li5/d;

    .line 650
    .line 651
    if-nez v12, :cond_22

    .line 652
    .line 653
    instance-of v9, v9, Li5/j;

    .line 654
    .line 655
    if-nez v9, :cond_22

    .line 656
    .line 657
    goto :goto_16

    .line 658
    :cond_26
    const/4 v7, 0x1

    .line 659
    :goto_17
    invoke-virtual {v14, v15}, Lh5/d;->O(I)V

    .line 660
    .line 661
    .line 662
    invoke-virtual {v14, v1}, Lh5/d;->Q(I)V

    .line 663
    .line 664
    .line 665
    const/4 v1, 0x2

    .line 666
    const/high16 v15, 0x40000000    # 2.0f

    .line 667
    .line 668
    goto/16 :goto_1b

    .line 669
    .line 670
    :cond_27
    move/from16 v21, v1

    .line 671
    .line 672
    move-object/from16 v22, v7

    .line 673
    .line 674
    move/from16 v20, v9

    .line 675
    .line 676
    iget-object v1, v8, Li5/f;->d:Ljava/lang/Object;

    .line 677
    .line 678
    check-cast v1, Lh5/e;

    .line 679
    .line 680
    iget-boolean v7, v8, Li5/f;->b:Z

    .line 681
    .line 682
    if-eqz v7, :cond_29

    .line 683
    .line 684
    iget-object v7, v1, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 685
    .line 686
    invoke-virtual {v7}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 687
    .line 688
    .line 689
    move-result-object v7

    .line 690
    :goto_18
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 691
    .line 692
    .line 693
    move-result v9

    .line 694
    if-eqz v9, :cond_28

    .line 695
    .line 696
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 697
    .line 698
    .line 699
    move-result-object v9

    .line 700
    check-cast v9, Lh5/d;

    .line 701
    .line 702
    invoke-virtual {v9}, Lh5/d;->i()V

    .line 703
    .line 704
    .line 705
    const/4 v13, 0x0

    .line 706
    iput-boolean v13, v9, Lh5/d;->a:Z

    .line 707
    .line 708
    iget-object v14, v9, Lh5/d;->d:Li5/l;

    .line 709
    .line 710
    iget-object v15, v14, Li5/p;->e:Li5/h;

    .line 711
    .line 712
    iput-boolean v13, v15, Li5/g;->j:Z

    .line 713
    .line 714
    iput-boolean v13, v14, Li5/p;->g:Z

    .line 715
    .line 716
    invoke-virtual {v14}, Li5/l;->n()V

    .line 717
    .line 718
    .line 719
    iget-object v9, v9, Lh5/d;->e:Li5/n;

    .line 720
    .line 721
    iget-object v14, v9, Li5/p;->e:Li5/h;

    .line 722
    .line 723
    iput-boolean v13, v14, Li5/g;->j:Z

    .line 724
    .line 725
    iput-boolean v13, v9, Li5/p;->g:Z

    .line 726
    .line 727
    invoke-virtual {v9}, Li5/n;->m()V

    .line 728
    .line 729
    .line 730
    goto :goto_18

    .line 731
    :cond_28
    const/4 v13, 0x0

    .line 732
    invoke-virtual {v1}, Lh5/d;->i()V

    .line 733
    .line 734
    .line 735
    iput-boolean v13, v1, Lh5/d;->a:Z

    .line 736
    .line 737
    iget-object v7, v1, Lh5/d;->d:Li5/l;

    .line 738
    .line 739
    iget-object v9, v7, Li5/p;->e:Li5/h;

    .line 740
    .line 741
    iput-boolean v13, v9, Li5/g;->j:Z

    .line 742
    .line 743
    iput-boolean v13, v7, Li5/p;->g:Z

    .line 744
    .line 745
    invoke-virtual {v7}, Li5/l;->n()V

    .line 746
    .line 747
    .line 748
    iget-object v7, v1, Lh5/d;->e:Li5/n;

    .line 749
    .line 750
    iget-object v9, v7, Li5/p;->e:Li5/h;

    .line 751
    .line 752
    iput-boolean v13, v9, Li5/g;->j:Z

    .line 753
    .line 754
    iput-boolean v13, v7, Li5/p;->g:Z

    .line 755
    .line 756
    invoke-virtual {v7}, Li5/n;->m()V

    .line 757
    .line 758
    .line 759
    invoke-virtual {v8}, Li5/f;->c()V

    .line 760
    .line 761
    .line 762
    goto :goto_19

    .line 763
    :cond_29
    const/4 v13, 0x0

    .line 764
    :goto_19
    iget-object v7, v8, Li5/f;->e:Ljava/lang/Object;

    .line 765
    .line 766
    check-cast v7, Lh5/e;

    .line 767
    .line 768
    invoke-virtual {v8, v7}, Li5/f;->b(Lh5/e;)V

    .line 769
    .line 770
    .line 771
    iput v13, v1, Lh5/d;->Z:I

    .line 772
    .line 773
    iput v13, v1, Lh5/d;->a0:I

    .line 774
    .line 775
    iget-object v7, v1, Lh5/d;->d:Li5/l;

    .line 776
    .line 777
    iget-object v7, v7, Li5/p;->h:Li5/g;

    .line 778
    .line 779
    invoke-virtual {v7, v13}, Li5/g;->d(I)V

    .line 780
    .line 781
    .line 782
    iget-object v1, v1, Lh5/d;->e:Li5/n;

    .line 783
    .line 784
    iget-object v1, v1, Li5/p;->h:Li5/g;

    .line 785
    .line 786
    invoke-virtual {v1, v13}, Li5/g;->d(I)V

    .line 787
    .line 788
    .line 789
    const/high16 v15, 0x40000000    # 2.0f

    .line 790
    .line 791
    if-ne v2, v15, :cond_2a

    .line 792
    .line 793
    invoke-virtual {v0, v13, v12}, Lh5/e;->Y(IZ)Z

    .line 794
    .line 795
    .line 796
    move-result v1

    .line 797
    move v7, v1

    .line 798
    const/4 v1, 0x1

    .line 799
    goto :goto_1a

    .line 800
    :cond_2a
    const/4 v1, 0x0

    .line 801
    const/4 v7, 0x1

    .line 802
    :goto_1a
    if-ne v3, v15, :cond_2b

    .line 803
    .line 804
    const/4 v9, 0x1

    .line 805
    invoke-virtual {v0, v9, v12}, Lh5/e;->Y(IZ)Z

    .line 806
    .line 807
    .line 808
    move-result v8

    .line 809
    and-int/2addr v7, v8

    .line 810
    add-int/lit8 v1, v1, 0x1

    .line 811
    .line 812
    :cond_2b
    :goto_1b
    if-eqz v7, :cond_2f

    .line 813
    .line 814
    if-ne v2, v15, :cond_2c

    .line 815
    .line 816
    const/4 v2, 0x1

    .line 817
    goto :goto_1c

    .line 818
    :cond_2c
    const/4 v2, 0x0

    .line 819
    :goto_1c
    if-ne v3, v15, :cond_2d

    .line 820
    .line 821
    const/4 v3, 0x1

    .line 822
    goto :goto_1d

    .line 823
    :cond_2d
    const/4 v3, 0x0

    .line 824
    :goto_1d
    invoke-virtual {v0, v2, v3}, Lh5/e;->T(ZZ)V

    .line 825
    .line 826
    .line 827
    goto :goto_1e

    .line 828
    :cond_2e
    move/from16 v21, v1

    .line 829
    .line 830
    move-object/from16 v22, v7

    .line 831
    .line 832
    move/from16 v20, v9

    .line 833
    .line 834
    const/4 v1, 0x0

    .line 835
    const/4 v7, 0x0

    .line 836
    :cond_2f
    :goto_1e
    if-eqz v7, :cond_30

    .line 837
    .line 838
    const/4 v7, 0x2

    .line 839
    if-eq v1, v7, :cond_55

    .line 840
    .line 841
    :cond_30
    iget v1, v0, Lh5/e;->E0:I

    .line 842
    .line 843
    if-lez v20, :cond_3d

    .line 844
    .line 845
    iget-object v2, v0, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 846
    .line 847
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 848
    .line 849
    .line 850
    move-result v2

    .line 851
    const/16 v3, 0x40

    .line 852
    .line 853
    invoke-virtual {v0, v3}, Lh5/e;->c0(I)Z

    .line 854
    .line 855
    .line 856
    move-result v3

    .line 857
    iget-object v7, v0, Lh5/e;->v0:Li5/c;

    .line 858
    .line 859
    const/4 v9, 0x0

    .line 860
    :goto_1f
    if-ge v9, v2, :cond_3c

    .line 861
    .line 862
    iget-object v8, v0, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 863
    .line 864
    invoke-virtual {v8, v9}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 865
    .line 866
    .line 867
    move-result-object v8

    .line 868
    check-cast v8, Lh5/d;

    .line 869
    .line 870
    instance-of v12, v8, Lh5/h;

    .line 871
    .line 872
    if-eqz v12, :cond_31

    .line 873
    .line 874
    :goto_20
    move/from16 p2, v2

    .line 875
    .line 876
    const/4 v13, 0x0

    .line 877
    const/4 v15, 0x3

    .line 878
    goto/16 :goto_23

    .line 879
    .line 880
    :cond_31
    instance-of v12, v8, Lh5/a;

    .line 881
    .line 882
    if-eqz v12, :cond_32

    .line 883
    .line 884
    goto :goto_20

    .line 885
    :cond_32
    iget-boolean v12, v8, Lh5/d;->G:Z

    .line 886
    .line 887
    if-eqz v12, :cond_33

    .line 888
    .line 889
    goto :goto_20

    .line 890
    :cond_33
    if-eqz v3, :cond_34

    .line 891
    .line 892
    iget-object v12, v8, Lh5/d;->d:Li5/l;

    .line 893
    .line 894
    if-eqz v12, :cond_34

    .line 895
    .line 896
    iget-object v13, v8, Lh5/d;->e:Li5/n;

    .line 897
    .line 898
    if-eqz v13, :cond_34

    .line 899
    .line 900
    iget-object v12, v12, Li5/p;->e:Li5/h;

    .line 901
    .line 902
    iget-boolean v12, v12, Li5/g;->j:Z

    .line 903
    .line 904
    if-eqz v12, :cond_34

    .line 905
    .line 906
    iget-object v12, v13, Li5/p;->e:Li5/h;

    .line 907
    .line 908
    iget-boolean v12, v12, Li5/g;->j:Z

    .line 909
    .line 910
    if-eqz v12, :cond_34

    .line 911
    .line 912
    goto :goto_20

    .line 913
    :cond_34
    const/4 v13, 0x0

    .line 914
    invoke-virtual {v8, v13}, Lh5/d;->k(I)I

    .line 915
    .line 916
    .line 917
    move-result v12

    .line 918
    const/4 v13, 0x1

    .line 919
    invoke-virtual {v8, v13}, Lh5/d;->k(I)I

    .line 920
    .line 921
    .line 922
    move-result v14

    .line 923
    const/4 v15, 0x3

    .line 924
    move/from16 p2, v2

    .line 925
    .line 926
    if-ne v12, v15, :cond_35

    .line 927
    .line 928
    iget v2, v8, Lh5/d;->s:I

    .line 929
    .line 930
    if-eq v2, v13, :cond_35

    .line 931
    .line 932
    if-ne v14, v15, :cond_35

    .line 933
    .line 934
    iget v2, v8, Lh5/d;->t:I

    .line 935
    .line 936
    if-eq v2, v13, :cond_35

    .line 937
    .line 938
    move v2, v13

    .line 939
    goto :goto_21

    .line 940
    :cond_35
    const/4 v2, 0x0

    .line 941
    :goto_21
    if-nez v2, :cond_39

    .line 942
    .line 943
    invoke-virtual {v0, v13}, Lh5/e;->c0(I)Z

    .line 944
    .line 945
    .line 946
    move-result v15

    .line 947
    if-eqz v15, :cond_39

    .line 948
    .line 949
    instance-of v13, v8, Lh5/k;

    .line 950
    .line 951
    if-nez v13, :cond_39

    .line 952
    .line 953
    const/4 v15, 0x3

    .line 954
    if-ne v12, v15, :cond_36

    .line 955
    .line 956
    iget v13, v8, Lh5/d;->s:I

    .line 957
    .line 958
    if-nez v13, :cond_36

    .line 959
    .line 960
    if-eq v14, v15, :cond_36

    .line 961
    .line 962
    invoke-virtual {v8}, Lh5/d;->y()Z

    .line 963
    .line 964
    .line 965
    move-result v13

    .line 966
    if-nez v13, :cond_36

    .line 967
    .line 968
    const/4 v2, 0x1

    .line 969
    :cond_36
    if-ne v14, v15, :cond_37

    .line 970
    .line 971
    iget v13, v8, Lh5/d;->t:I

    .line 972
    .line 973
    if-nez v13, :cond_37

    .line 974
    .line 975
    if-eq v12, v15, :cond_37

    .line 976
    .line 977
    invoke-virtual {v8}, Lh5/d;->y()Z

    .line 978
    .line 979
    .line 980
    move-result v13

    .line 981
    if-nez v13, :cond_37

    .line 982
    .line 983
    const/4 v2, 0x1

    .line 984
    :cond_37
    if-eq v12, v15, :cond_38

    .line 985
    .line 986
    if-ne v14, v15, :cond_3a

    .line 987
    .line 988
    :cond_38
    iget v12, v8, Lh5/d;->X:F

    .line 989
    .line 990
    cmpl-float v12, v12, v16

    .line 991
    .line 992
    if-lez v12, :cond_3a

    .line 993
    .line 994
    const/4 v2, 0x1

    .line 995
    goto :goto_22

    .line 996
    :cond_39
    const/4 v15, 0x3

    .line 997
    :cond_3a
    :goto_22
    if-eqz v2, :cond_3b

    .line 998
    .line 999
    const/4 v13, 0x0

    .line 1000
    goto :goto_23

    .line 1001
    :cond_3b
    const/4 v13, 0x0

    .line 1002
    invoke-virtual {v4, v13, v8, v7}, Lgw0/c;->r(ILh5/d;Li5/c;)Z

    .line 1003
    .line 1004
    .line 1005
    :goto_23
    add-int/lit8 v9, v9, 0x1

    .line 1006
    .line 1007
    move/from16 v2, p2

    .line 1008
    .line 1009
    goto/16 :goto_1f

    .line 1010
    .line 1011
    :cond_3c
    const/4 v13, 0x0

    .line 1012
    invoke-interface {v7}, Li5/c;->a()V

    .line 1013
    .line 1014
    .line 1015
    goto :goto_24

    .line 1016
    :cond_3d
    const/4 v13, 0x0

    .line 1017
    :goto_24
    invoke-virtual {v4, v0}, Lgw0/c;->D(Lh5/e;)V

    .line 1018
    .line 1019
    .line 1020
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 1021
    .line 1022
    .line 1023
    move-result v2

    .line 1024
    if-lez v20, :cond_3e

    .line 1025
    .line 1026
    invoke-virtual {v4, v0, v13, v10, v11}, Lgw0/c;->C(Lh5/e;III)V

    .line 1027
    .line 1028
    .line 1029
    :cond_3e
    if-lez v2, :cond_54

    .line 1030
    .line 1031
    iget-object v3, v0, Lh5/d;->q0:[I

    .line 1032
    .line 1033
    aget v7, v3, v13

    .line 1034
    .line 1035
    const/4 v8, 0x2

    .line 1036
    if-ne v7, v8, :cond_3f

    .line 1037
    .line 1038
    const/4 v7, 0x1

    .line 1039
    :goto_25
    const/16 v17, 0x1

    .line 1040
    .line 1041
    goto :goto_26

    .line 1042
    :cond_3f
    move v7, v13

    .line 1043
    goto :goto_25

    .line 1044
    :goto_26
    aget v3, v3, v17

    .line 1045
    .line 1046
    if-ne v3, v8, :cond_40

    .line 1047
    .line 1048
    const/4 v3, 0x1

    .line 1049
    goto :goto_27

    .line 1050
    :cond_40
    move v3, v13

    .line 1051
    :goto_27
    invoke-virtual {v0}, Lh5/d;->r()I

    .line 1052
    .line 1053
    .line 1054
    move-result v8

    .line 1055
    iget v9, v5, Lh5/d;->c0:I

    .line 1056
    .line 1057
    invoke-static {v8, v9}, Ljava/lang/Math;->max(II)I

    .line 1058
    .line 1059
    .line 1060
    move-result v8

    .line 1061
    invoke-virtual {v0}, Lh5/d;->l()I

    .line 1062
    .line 1063
    .line 1064
    move-result v9

    .line 1065
    iget v5, v5, Lh5/d;->d0:I

    .line 1066
    .line 1067
    invoke-static {v9, v5}, Ljava/lang/Math;->max(II)I

    .line 1068
    .line 1069
    .line 1070
    move-result v5

    .line 1071
    move v9, v13

    .line 1072
    move v12, v9

    .line 1073
    :goto_28
    if-ge v9, v2, :cond_46

    .line 1074
    .line 1075
    invoke-virtual {v6, v9}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1076
    .line 1077
    .line 1078
    move-result-object v15

    .line 1079
    check-cast v15, Lh5/d;

    .line 1080
    .line 1081
    instance-of v13, v15, Lh5/k;

    .line 1082
    .line 1083
    if-nez v13, :cond_41

    .line 1084
    .line 1085
    move/from16 p2, v3

    .line 1086
    .line 1087
    move/from16 p3, v7

    .line 1088
    .line 1089
    move-object/from16 v3, v22

    .line 1090
    .line 1091
    goto/16 :goto_2a

    .line 1092
    .line 1093
    :cond_41
    invoke-virtual {v15}, Lh5/d;->r()I

    .line 1094
    .line 1095
    .line 1096
    move-result v13

    .line 1097
    invoke-virtual {v15}, Lh5/d;->l()I

    .line 1098
    .line 1099
    .line 1100
    move-result v14

    .line 1101
    move/from16 p2, v3

    .line 1102
    .line 1103
    move/from16 p3, v7

    .line 1104
    .line 1105
    move-object/from16 v3, v22

    .line 1106
    .line 1107
    const/4 v7, 0x1

    .line 1108
    invoke-virtual {v4, v7, v15, v3}, Lgw0/c;->r(ILh5/d;Li5/c;)Z

    .line 1109
    .line 1110
    .line 1111
    move-result v16

    .line 1112
    or-int v7, v12, v16

    .line 1113
    .line 1114
    invoke-virtual {v15}, Lh5/d;->r()I

    .line 1115
    .line 1116
    .line 1117
    move-result v12

    .line 1118
    move/from16 p4, v7

    .line 1119
    .line 1120
    invoke-virtual {v15}, Lh5/d;->l()I

    .line 1121
    .line 1122
    .line 1123
    move-result v7

    .line 1124
    if-eq v12, v13, :cond_43

    .line 1125
    .line 1126
    invoke-virtual {v15, v12}, Lh5/d;->S(I)V

    .line 1127
    .line 1128
    .line 1129
    if-eqz p3, :cond_42

    .line 1130
    .line 1131
    invoke-virtual {v15}, Lh5/d;->s()I

    .line 1132
    .line 1133
    .line 1134
    move-result v12

    .line 1135
    iget v13, v15, Lh5/d;->V:I

    .line 1136
    .line 1137
    add-int/2addr v12, v13

    .line 1138
    if-le v12, v8, :cond_42

    .line 1139
    .line 1140
    invoke-virtual {v15}, Lh5/d;->s()I

    .line 1141
    .line 1142
    .line 1143
    move-result v12

    .line 1144
    iget v13, v15, Lh5/d;->V:I

    .line 1145
    .line 1146
    add-int/2addr v12, v13

    .line 1147
    const/4 v13, 0x4

    .line 1148
    invoke-virtual {v15, v13}, Lh5/d;->j(I)Lh5/c;

    .line 1149
    .line 1150
    .line 1151
    move-result-object v16

    .line 1152
    invoke-virtual/range {v16 .. v16}, Lh5/c;->e()I

    .line 1153
    .line 1154
    .line 1155
    move-result v13

    .line 1156
    add-int/2addr v13, v12

    .line 1157
    invoke-static {v8, v13}, Ljava/lang/Math;->max(II)I

    .line 1158
    .line 1159
    .line 1160
    move-result v8

    .line 1161
    :cond_42
    const/4 v13, 0x1

    .line 1162
    goto :goto_29

    .line 1163
    :cond_43
    move/from16 v13, p4

    .line 1164
    .line 1165
    :goto_29
    if-eq v7, v14, :cond_45

    .line 1166
    .line 1167
    invoke-virtual {v15, v7}, Lh5/d;->N(I)V

    .line 1168
    .line 1169
    .line 1170
    if-eqz p2, :cond_44

    .line 1171
    .line 1172
    invoke-virtual {v15}, Lh5/d;->t()I

    .line 1173
    .line 1174
    .line 1175
    move-result v7

    .line 1176
    iget v12, v15, Lh5/d;->W:I

    .line 1177
    .line 1178
    add-int/2addr v7, v12

    .line 1179
    if-le v7, v5, :cond_44

    .line 1180
    .line 1181
    invoke-virtual {v15}, Lh5/d;->t()I

    .line 1182
    .line 1183
    .line 1184
    move-result v7

    .line 1185
    iget v12, v15, Lh5/d;->W:I

    .line 1186
    .line 1187
    add-int/2addr v7, v12

    .line 1188
    const/4 v12, 0x5

    .line 1189
    invoke-virtual {v15, v12}, Lh5/d;->j(I)Lh5/c;

    .line 1190
    .line 1191
    .line 1192
    move-result-object v12

    .line 1193
    invoke-virtual {v12}, Lh5/c;->e()I

    .line 1194
    .line 1195
    .line 1196
    move-result v12

    .line 1197
    add-int/2addr v12, v7

    .line 1198
    invoke-static {v5, v12}, Ljava/lang/Math;->max(II)I

    .line 1199
    .line 1200
    .line 1201
    move-result v5

    .line 1202
    :cond_44
    const/4 v13, 0x1

    .line 1203
    :cond_45
    check-cast v15, Lh5/k;

    .line 1204
    .line 1205
    iget-boolean v7, v15, Lh5/k;->z0:Z

    .line 1206
    .line 1207
    or-int/2addr v7, v13

    .line 1208
    move v12, v7

    .line 1209
    :goto_2a
    add-int/lit8 v9, v9, 0x1

    .line 1210
    .line 1211
    move/from16 v7, p3

    .line 1212
    .line 1213
    move-object/from16 v22, v3

    .line 1214
    .line 1215
    const/4 v13, 0x0

    .line 1216
    move/from16 v3, p2

    .line 1217
    .line 1218
    goto/16 :goto_28

    .line 1219
    .line 1220
    :cond_46
    move/from16 p2, v3

    .line 1221
    .line 1222
    move/from16 p3, v7

    .line 1223
    .line 1224
    const/4 v9, 0x0

    .line 1225
    :goto_2b
    move-object/from16 v3, v22

    .line 1226
    .line 1227
    const/4 v7, 0x2

    .line 1228
    if-ge v9, v7, :cond_54

    .line 1229
    .line 1230
    move v13, v12

    .line 1231
    const/4 v12, 0x0

    .line 1232
    :goto_2c
    if-ge v12, v2, :cond_53

    .line 1233
    .line 1234
    invoke-virtual {v6, v12}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1235
    .line 1236
    .line 1237
    move-result-object v14

    .line 1238
    check-cast v14, Lh5/d;

    .line 1239
    .line 1240
    instance-of v15, v14, Lh5/i;

    .line 1241
    .line 1242
    if-eqz v15, :cond_47

    .line 1243
    .line 1244
    instance-of v15, v14, Lh5/k;

    .line 1245
    .line 1246
    if-eqz v15, :cond_4b

    .line 1247
    .line 1248
    :cond_47
    instance-of v15, v14, Lh5/h;

    .line 1249
    .line 1250
    if-eqz v15, :cond_48

    .line 1251
    .line 1252
    goto :goto_2d

    .line 1253
    :cond_48
    iget v15, v14, Lh5/d;->h0:I

    .line 1254
    .line 1255
    const/16 v7, 0x8

    .line 1256
    .line 1257
    if-ne v15, v7, :cond_49

    .line 1258
    .line 1259
    goto :goto_2d

    .line 1260
    :cond_49
    if-eqz v21, :cond_4a

    .line 1261
    .line 1262
    iget-object v7, v14, Lh5/d;->d:Li5/l;

    .line 1263
    .line 1264
    iget-object v7, v7, Li5/p;->e:Li5/h;

    .line 1265
    .line 1266
    iget-boolean v7, v7, Li5/g;->j:Z

    .line 1267
    .line 1268
    if-eqz v7, :cond_4a

    .line 1269
    .line 1270
    iget-object v7, v14, Lh5/d;->e:Li5/n;

    .line 1271
    .line 1272
    iget-object v7, v7, Li5/p;->e:Li5/h;

    .line 1273
    .line 1274
    iget-boolean v7, v7, Li5/g;->j:Z

    .line 1275
    .line 1276
    if-eqz v7, :cond_4a

    .line 1277
    .line 1278
    goto :goto_2d

    .line 1279
    :cond_4a
    instance-of v7, v14, Lh5/k;

    .line 1280
    .line 1281
    if-eqz v7, :cond_4c

    .line 1282
    .line 1283
    :cond_4b
    :goto_2d
    move/from16 p4, v2

    .line 1284
    .line 1285
    move-object/from16 v22, v3

    .line 1286
    .line 1287
    move-object/from16 p6, v6

    .line 1288
    .line 1289
    const/4 v6, 0x5

    .line 1290
    const/4 v7, 0x4

    .line 1291
    goto/16 :goto_32

    .line 1292
    .line 1293
    :cond_4c
    invoke-virtual {v14}, Lh5/d;->r()I

    .line 1294
    .line 1295
    .line 1296
    move-result v7

    .line 1297
    invoke-virtual {v14}, Lh5/d;->l()I

    .line 1298
    .line 1299
    .line 1300
    move-result v15

    .line 1301
    move/from16 p4, v2

    .line 1302
    .line 1303
    iget v2, v14, Lh5/d;->b0:I

    .line 1304
    .line 1305
    move-object/from16 p6, v6

    .line 1306
    .line 1307
    const/4 v6, 0x1

    .line 1308
    if-ne v9, v6, :cond_4d

    .line 1309
    .line 1310
    const/4 v6, 0x2

    .line 1311
    :cond_4d
    invoke-virtual {v4, v6, v14, v3}, Lgw0/c;->r(ILh5/d;Li5/c;)Z

    .line 1312
    .line 1313
    .line 1314
    move-result v6

    .line 1315
    or-int/2addr v13, v6

    .line 1316
    invoke-virtual {v14}, Lh5/d;->r()I

    .line 1317
    .line 1318
    .line 1319
    move-result v6

    .line 1320
    move-object/from16 v22, v3

    .line 1321
    .line 1322
    invoke-virtual {v14}, Lh5/d;->l()I

    .line 1323
    .line 1324
    .line 1325
    move-result v3

    .line 1326
    if-eq v6, v7, :cond_4f

    .line 1327
    .line 1328
    invoke-virtual {v14, v6}, Lh5/d;->S(I)V

    .line 1329
    .line 1330
    .line 1331
    if-eqz p3, :cond_4e

    .line 1332
    .line 1333
    invoke-virtual {v14}, Lh5/d;->s()I

    .line 1334
    .line 1335
    .line 1336
    move-result v6

    .line 1337
    iget v7, v14, Lh5/d;->V:I

    .line 1338
    .line 1339
    add-int/2addr v6, v7

    .line 1340
    if-le v6, v8, :cond_4e

    .line 1341
    .line 1342
    invoke-virtual {v14}, Lh5/d;->s()I

    .line 1343
    .line 1344
    .line 1345
    move-result v6

    .line 1346
    iget v7, v14, Lh5/d;->V:I

    .line 1347
    .line 1348
    add-int/2addr v6, v7

    .line 1349
    const/4 v7, 0x4

    .line 1350
    invoke-virtual {v14, v7}, Lh5/d;->j(I)Lh5/c;

    .line 1351
    .line 1352
    .line 1353
    move-result-object v13

    .line 1354
    invoke-virtual {v13}, Lh5/c;->e()I

    .line 1355
    .line 1356
    .line 1357
    move-result v13

    .line 1358
    add-int/2addr v13, v6

    .line 1359
    invoke-static {v8, v13}, Ljava/lang/Math;->max(II)I

    .line 1360
    .line 1361
    .line 1362
    move-result v8

    .line 1363
    goto :goto_2e

    .line 1364
    :cond_4e
    const/4 v7, 0x4

    .line 1365
    :goto_2e
    const/4 v13, 0x1

    .line 1366
    goto :goto_2f

    .line 1367
    :cond_4f
    const/4 v7, 0x4

    .line 1368
    :goto_2f
    if-eq v3, v15, :cond_51

    .line 1369
    .line 1370
    invoke-virtual {v14, v3}, Lh5/d;->N(I)V

    .line 1371
    .line 1372
    .line 1373
    if-eqz p2, :cond_50

    .line 1374
    .line 1375
    invoke-virtual {v14}, Lh5/d;->t()I

    .line 1376
    .line 1377
    .line 1378
    move-result v3

    .line 1379
    iget v6, v14, Lh5/d;->W:I

    .line 1380
    .line 1381
    add-int/2addr v3, v6

    .line 1382
    if-le v3, v5, :cond_50

    .line 1383
    .line 1384
    invoke-virtual {v14}, Lh5/d;->t()I

    .line 1385
    .line 1386
    .line 1387
    move-result v3

    .line 1388
    iget v6, v14, Lh5/d;->W:I

    .line 1389
    .line 1390
    add-int/2addr v3, v6

    .line 1391
    const/4 v6, 0x5

    .line 1392
    invoke-virtual {v14, v6}, Lh5/d;->j(I)Lh5/c;

    .line 1393
    .line 1394
    .line 1395
    move-result-object v13

    .line 1396
    invoke-virtual {v13}, Lh5/c;->e()I

    .line 1397
    .line 1398
    .line 1399
    move-result v13

    .line 1400
    add-int/2addr v13, v3

    .line 1401
    invoke-static {v5, v13}, Ljava/lang/Math;->max(II)I

    .line 1402
    .line 1403
    .line 1404
    move-result v5

    .line 1405
    goto :goto_30

    .line 1406
    :cond_50
    const/4 v6, 0x5

    .line 1407
    :goto_30
    const/4 v13, 0x1

    .line 1408
    goto :goto_31

    .line 1409
    :cond_51
    const/4 v6, 0x5

    .line 1410
    :goto_31
    iget-boolean v3, v14, Lh5/d;->F:Z

    .line 1411
    .line 1412
    if-eqz v3, :cond_52

    .line 1413
    .line 1414
    iget v3, v14, Lh5/d;->b0:I

    .line 1415
    .line 1416
    if-eq v2, v3, :cond_52

    .line 1417
    .line 1418
    const/4 v13, 0x1

    .line 1419
    :cond_52
    :goto_32
    add-int/lit8 v12, v12, 0x1

    .line 1420
    .line 1421
    move/from16 v2, p4

    .line 1422
    .line 1423
    move-object/from16 v6, p6

    .line 1424
    .line 1425
    move-object/from16 v3, v22

    .line 1426
    .line 1427
    const/4 v7, 0x2

    .line 1428
    goto/16 :goto_2c

    .line 1429
    .line 1430
    :cond_53
    move/from16 p4, v2

    .line 1431
    .line 1432
    move-object/from16 v22, v3

    .line 1433
    .line 1434
    move-object/from16 p6, v6

    .line 1435
    .line 1436
    const/4 v6, 0x5

    .line 1437
    const/4 v7, 0x4

    .line 1438
    if-eqz v13, :cond_54

    .line 1439
    .line 1440
    add-int/lit8 v9, v9, 0x1

    .line 1441
    .line 1442
    invoke-virtual {v4, v0, v9, v10, v11}, Lgw0/c;->C(Lh5/e;III)V

    .line 1443
    .line 1444
    .line 1445
    move/from16 v2, p4

    .line 1446
    .line 1447
    move-object/from16 v6, p6

    .line 1448
    .line 1449
    const/4 v12, 0x0

    .line 1450
    goto/16 :goto_2b

    .line 1451
    .line 1452
    :cond_54
    iput v1, v0, Lh5/e;->E0:I

    .line 1453
    .line 1454
    const/16 v1, 0x200

    .line 1455
    .line 1456
    invoke-virtual {v0, v1}, Lh5/e;->c0(I)Z

    .line 1457
    .line 1458
    .line 1459
    move-result v0

    .line 1460
    sput-boolean v0, La5/c;->q:Z

    .line 1461
    .line 1462
    :cond_55
    return-void
.end method

.method public final c0(I)Z
    .locals 0

    .line 1
    iget p0, p0, Lh5/e;->E0:I

    .line 2
    .line 3
    and-int/2addr p0, p1

    .line 4
    if-ne p0, p1, :cond_0

    .line 5
    .line 6
    const/4 p0, 0x1

    .line 7
    return p0

    .line 8
    :cond_0
    const/4 p0, 0x0

    .line 9
    return p0
.end method

.method public final o(Ljava/lang/StringBuilder;)V
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lh5/d;->k:Ljava/lang/String;

    .line 7
    .line 8
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    const-string v1, ":{\n"

    .line 12
    .line 13
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    new-instance v0, Ljava/lang/StringBuilder;

    .line 24
    .line 25
    const-string v1, "  actualWidth:"

    .line 26
    .line 27
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    iget v1, p0, Lh5/d;->V:I

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string v0, "\n"

    .line 43
    .line 44
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    new-instance v1, Ljava/lang/StringBuilder;

    .line 48
    .line 49
    const-string v2, "  actualHeight:"

    .line 50
    .line 51
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    iget v2, p0, Lh5/d;->W:I

    .line 55
    .line 56
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object v1

    .line 63
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    iget-object p0, p0, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 70
    .line 71
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 76
    .line 77
    .line 78
    move-result v0

    .line 79
    if-eqz v0, :cond_0

    .line 80
    .line 81
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    check-cast v0, Lh5/d;

    .line 86
    .line 87
    invoke-virtual {v0, p1}, Lh5/d;->o(Ljava/lang/StringBuilder;)V

    .line 88
    .line 89
    .line 90
    const-string v0, ",\n"

    .line 91
    .line 92
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    goto :goto_0

    .line 96
    :cond_0
    const-string p0, "}"

    .line 97
    .line 98
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    return-void
.end method
