.class public final Lp11/r;
.super Lp11/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static R(Ljp/u1;Ln11/f;)Lp11/r;
    .locals 1

    .line 1
    if-eqz p0, :cond_2

    .line 2
    .line 3
    invoke-virtual {p0}, Ljp/u1;->I()Ljp/u1;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    if-eqz p0, :cond_1

    .line 8
    .line 9
    if-eqz p1, :cond_0

    .line 10
    .line 11
    new-instance v0, Lp11/r;

    .line 12
    .line 13
    invoke-direct {v0, p0, p1}, Lp11/b;-><init>(Ljp/u1;Ln11/f;)V

    .line 14
    .line 15
    .line 16
    return-object v0

    .line 17
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 18
    .line 19
    const-string p1, "DateTimeZone must not be null"

    .line 20
    .line 21
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    throw p0

    .line 25
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 26
    .line 27
    const-string p1, "UTC chronology must not be null"

    .line 28
    .line 29
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 34
    .line 35
    const-string p1, "Must supply a chronology"

    .line 36
    .line 37
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    throw p0
.end method


# virtual methods
.method public final I()Ljp/u1;
    .locals 0

    .line 1
    iget-object p0, p0, Lp11/b;->d:Ljp/u1;

    .line 2
    .line 3
    return-object p0
.end method

.method public final J(Ln11/f;)Ljp/u1;
    .locals 1

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    invoke-static {}, Ln11/f;->e()Ln11/f;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    :cond_0
    iget-object v0, p0, Lp11/b;->e:Ljava/lang/Object;

    .line 8
    .line 9
    if-ne p1, v0, :cond_1

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_1
    sget-object v0, Ln11/f;->e:Ln11/n;

    .line 13
    .line 14
    iget-object p0, p0, Lp11/b;->d:Ljp/u1;

    .line 15
    .line 16
    if-ne p1, v0, :cond_2

    .line 17
    .line 18
    return-object p0

    .line 19
    :cond_2
    new-instance v0, Lp11/r;

    .line 20
    .line 21
    invoke-direct {v0, p0, p1}, Lp11/b;-><init>(Ljp/u1;Ln11/f;)V

    .line 22
    .line 23
    .line 24
    return-object v0
.end method

.method public final O(Lp11/a;)V
    .locals 2

    .line 1
    new-instance v0, Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p1, Lp11/a;->l:Ln11/g;

    .line 7
    .line 8
    invoke-virtual {p0, v1, v0}, Lp11/r;->Q(Ln11/g;Ljava/util/HashMap;)Ln11/g;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    iput-object v1, p1, Lp11/a;->l:Ln11/g;

    .line 13
    .line 14
    iget-object v1, p1, Lp11/a;->k:Ln11/g;

    .line 15
    .line 16
    invoke-virtual {p0, v1, v0}, Lp11/r;->Q(Ln11/g;Ljava/util/HashMap;)Ln11/g;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    iput-object v1, p1, Lp11/a;->k:Ln11/g;

    .line 21
    .line 22
    iget-object v1, p1, Lp11/a;->j:Ln11/g;

    .line 23
    .line 24
    invoke-virtual {p0, v1, v0}, Lp11/r;->Q(Ln11/g;Ljava/util/HashMap;)Ln11/g;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    iput-object v1, p1, Lp11/a;->j:Ln11/g;

    .line 29
    .line 30
    iget-object v1, p1, Lp11/a;->i:Ln11/g;

    .line 31
    .line 32
    invoke-virtual {p0, v1, v0}, Lp11/r;->Q(Ln11/g;Ljava/util/HashMap;)Ln11/g;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    iput-object v1, p1, Lp11/a;->i:Ln11/g;

    .line 37
    .line 38
    iget-object v1, p1, Lp11/a;->h:Ln11/g;

    .line 39
    .line 40
    invoke-virtual {p0, v1, v0}, Lp11/r;->Q(Ln11/g;Ljava/util/HashMap;)Ln11/g;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    iput-object v1, p1, Lp11/a;->h:Ln11/g;

    .line 45
    .line 46
    iget-object v1, p1, Lp11/a;->g:Ln11/g;

    .line 47
    .line 48
    invoke-virtual {p0, v1, v0}, Lp11/r;->Q(Ln11/g;Ljava/util/HashMap;)Ln11/g;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    iput-object v1, p1, Lp11/a;->g:Ln11/g;

    .line 53
    .line 54
    iget-object v1, p1, Lp11/a;->f:Ln11/g;

    .line 55
    .line 56
    invoke-virtual {p0, v1, v0}, Lp11/r;->Q(Ln11/g;Ljava/util/HashMap;)Ln11/g;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    iput-object v1, p1, Lp11/a;->f:Ln11/g;

    .line 61
    .line 62
    iget-object v1, p1, Lp11/a;->e:Ln11/g;

    .line 63
    .line 64
    invoke-virtual {p0, v1, v0}, Lp11/r;->Q(Ln11/g;Ljava/util/HashMap;)Ln11/g;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    iput-object v1, p1, Lp11/a;->e:Ln11/g;

    .line 69
    .line 70
    iget-object v1, p1, Lp11/a;->d:Ln11/g;

    .line 71
    .line 72
    invoke-virtual {p0, v1, v0}, Lp11/r;->Q(Ln11/g;Ljava/util/HashMap;)Ln11/g;

    .line 73
    .line 74
    .line 75
    move-result-object v1

    .line 76
    iput-object v1, p1, Lp11/a;->d:Ln11/g;

    .line 77
    .line 78
    iget-object v1, p1, Lp11/a;->c:Ln11/g;

    .line 79
    .line 80
    invoke-virtual {p0, v1, v0}, Lp11/r;->Q(Ln11/g;Ljava/util/HashMap;)Ln11/g;

    .line 81
    .line 82
    .line 83
    move-result-object v1

    .line 84
    iput-object v1, p1, Lp11/a;->c:Ln11/g;

    .line 85
    .line 86
    iget-object v1, p1, Lp11/a;->b:Ln11/g;

    .line 87
    .line 88
    invoke-virtual {p0, v1, v0}, Lp11/r;->Q(Ln11/g;Ljava/util/HashMap;)Ln11/g;

    .line 89
    .line 90
    .line 91
    move-result-object v1

    .line 92
    iput-object v1, p1, Lp11/a;->b:Ln11/g;

    .line 93
    .line 94
    iget-object v1, p1, Lp11/a;->a:Ln11/g;

    .line 95
    .line 96
    invoke-virtual {p0, v1, v0}, Lp11/r;->Q(Ln11/g;Ljava/util/HashMap;)Ln11/g;

    .line 97
    .line 98
    .line 99
    move-result-object v1

    .line 100
    iput-object v1, p1, Lp11/a;->a:Ln11/g;

    .line 101
    .line 102
    iget-object v1, p1, Lp11/a;->E:Ln11/a;

    .line 103
    .line 104
    invoke-virtual {p0, v1, v0}, Lp11/r;->P(Ln11/a;Ljava/util/HashMap;)Ln11/a;

    .line 105
    .line 106
    .line 107
    move-result-object v1

    .line 108
    iput-object v1, p1, Lp11/a;->E:Ln11/a;

    .line 109
    .line 110
    iget-object v1, p1, Lp11/a;->F:Ln11/a;

    .line 111
    .line 112
    invoke-virtual {p0, v1, v0}, Lp11/r;->P(Ln11/a;Ljava/util/HashMap;)Ln11/a;

    .line 113
    .line 114
    .line 115
    move-result-object v1

    .line 116
    iput-object v1, p1, Lp11/a;->F:Ln11/a;

    .line 117
    .line 118
    iget-object v1, p1, Lp11/a;->G:Ln11/a;

    .line 119
    .line 120
    invoke-virtual {p0, v1, v0}, Lp11/r;->P(Ln11/a;Ljava/util/HashMap;)Ln11/a;

    .line 121
    .line 122
    .line 123
    move-result-object v1

    .line 124
    iput-object v1, p1, Lp11/a;->G:Ln11/a;

    .line 125
    .line 126
    iget-object v1, p1, Lp11/a;->H:Ln11/a;

    .line 127
    .line 128
    invoke-virtual {p0, v1, v0}, Lp11/r;->P(Ln11/a;Ljava/util/HashMap;)Ln11/a;

    .line 129
    .line 130
    .line 131
    move-result-object v1

    .line 132
    iput-object v1, p1, Lp11/a;->H:Ln11/a;

    .line 133
    .line 134
    iget-object v1, p1, Lp11/a;->I:Ln11/a;

    .line 135
    .line 136
    invoke-virtual {p0, v1, v0}, Lp11/r;->P(Ln11/a;Ljava/util/HashMap;)Ln11/a;

    .line 137
    .line 138
    .line 139
    move-result-object v1

    .line 140
    iput-object v1, p1, Lp11/a;->I:Ln11/a;

    .line 141
    .line 142
    iget-object v1, p1, Lp11/a;->x:Ln11/a;

    .line 143
    .line 144
    invoke-virtual {p0, v1, v0}, Lp11/r;->P(Ln11/a;Ljava/util/HashMap;)Ln11/a;

    .line 145
    .line 146
    .line 147
    move-result-object v1

    .line 148
    iput-object v1, p1, Lp11/a;->x:Ln11/a;

    .line 149
    .line 150
    iget-object v1, p1, Lp11/a;->y:Ln11/a;

    .line 151
    .line 152
    invoke-virtual {p0, v1, v0}, Lp11/r;->P(Ln11/a;Ljava/util/HashMap;)Ln11/a;

    .line 153
    .line 154
    .line 155
    move-result-object v1

    .line 156
    iput-object v1, p1, Lp11/a;->y:Ln11/a;

    .line 157
    .line 158
    iget-object v1, p1, Lp11/a;->z:Ln11/a;

    .line 159
    .line 160
    invoke-virtual {p0, v1, v0}, Lp11/r;->P(Ln11/a;Ljava/util/HashMap;)Ln11/a;

    .line 161
    .line 162
    .line 163
    move-result-object v1

    .line 164
    iput-object v1, p1, Lp11/a;->z:Ln11/a;

    .line 165
    .line 166
    iget-object v1, p1, Lp11/a;->D:Ln11/a;

    .line 167
    .line 168
    invoke-virtual {p0, v1, v0}, Lp11/r;->P(Ln11/a;Ljava/util/HashMap;)Ln11/a;

    .line 169
    .line 170
    .line 171
    move-result-object v1

    .line 172
    iput-object v1, p1, Lp11/a;->D:Ln11/a;

    .line 173
    .line 174
    iget-object v1, p1, Lp11/a;->A:Ln11/a;

    .line 175
    .line 176
    invoke-virtual {p0, v1, v0}, Lp11/r;->P(Ln11/a;Ljava/util/HashMap;)Ln11/a;

    .line 177
    .line 178
    .line 179
    move-result-object v1

    .line 180
    iput-object v1, p1, Lp11/a;->A:Ln11/a;

    .line 181
    .line 182
    iget-object v1, p1, Lp11/a;->B:Ln11/a;

    .line 183
    .line 184
    invoke-virtual {p0, v1, v0}, Lp11/r;->P(Ln11/a;Ljava/util/HashMap;)Ln11/a;

    .line 185
    .line 186
    .line 187
    move-result-object v1

    .line 188
    iput-object v1, p1, Lp11/a;->B:Ln11/a;

    .line 189
    .line 190
    iget-object v1, p1, Lp11/a;->C:Ln11/a;

    .line 191
    .line 192
    invoke-virtual {p0, v1, v0}, Lp11/r;->P(Ln11/a;Ljava/util/HashMap;)Ln11/a;

    .line 193
    .line 194
    .line 195
    move-result-object v1

    .line 196
    iput-object v1, p1, Lp11/a;->C:Ln11/a;

    .line 197
    .line 198
    iget-object v1, p1, Lp11/a;->m:Ln11/a;

    .line 199
    .line 200
    invoke-virtual {p0, v1, v0}, Lp11/r;->P(Ln11/a;Ljava/util/HashMap;)Ln11/a;

    .line 201
    .line 202
    .line 203
    move-result-object v1

    .line 204
    iput-object v1, p1, Lp11/a;->m:Ln11/a;

    .line 205
    .line 206
    iget-object v1, p1, Lp11/a;->n:Ln11/a;

    .line 207
    .line 208
    invoke-virtual {p0, v1, v0}, Lp11/r;->P(Ln11/a;Ljava/util/HashMap;)Ln11/a;

    .line 209
    .line 210
    .line 211
    move-result-object v1

    .line 212
    iput-object v1, p1, Lp11/a;->n:Ln11/a;

    .line 213
    .line 214
    iget-object v1, p1, Lp11/a;->o:Ln11/a;

    .line 215
    .line 216
    invoke-virtual {p0, v1, v0}, Lp11/r;->P(Ln11/a;Ljava/util/HashMap;)Ln11/a;

    .line 217
    .line 218
    .line 219
    move-result-object v1

    .line 220
    iput-object v1, p1, Lp11/a;->o:Ln11/a;

    .line 221
    .line 222
    iget-object v1, p1, Lp11/a;->p:Ln11/a;

    .line 223
    .line 224
    invoke-virtual {p0, v1, v0}, Lp11/r;->P(Ln11/a;Ljava/util/HashMap;)Ln11/a;

    .line 225
    .line 226
    .line 227
    move-result-object v1

    .line 228
    iput-object v1, p1, Lp11/a;->p:Ln11/a;

    .line 229
    .line 230
    iget-object v1, p1, Lp11/a;->q:Ln11/a;

    .line 231
    .line 232
    invoke-virtual {p0, v1, v0}, Lp11/r;->P(Ln11/a;Ljava/util/HashMap;)Ln11/a;

    .line 233
    .line 234
    .line 235
    move-result-object v1

    .line 236
    iput-object v1, p1, Lp11/a;->q:Ln11/a;

    .line 237
    .line 238
    iget-object v1, p1, Lp11/a;->r:Ln11/a;

    .line 239
    .line 240
    invoke-virtual {p0, v1, v0}, Lp11/r;->P(Ln11/a;Ljava/util/HashMap;)Ln11/a;

    .line 241
    .line 242
    .line 243
    move-result-object v1

    .line 244
    iput-object v1, p1, Lp11/a;->r:Ln11/a;

    .line 245
    .line 246
    iget-object v1, p1, Lp11/a;->s:Ln11/a;

    .line 247
    .line 248
    invoke-virtual {p0, v1, v0}, Lp11/r;->P(Ln11/a;Ljava/util/HashMap;)Ln11/a;

    .line 249
    .line 250
    .line 251
    move-result-object v1

    .line 252
    iput-object v1, p1, Lp11/a;->s:Ln11/a;

    .line 253
    .line 254
    iget-object v1, p1, Lp11/a;->u:Ln11/a;

    .line 255
    .line 256
    invoke-virtual {p0, v1, v0}, Lp11/r;->P(Ln11/a;Ljava/util/HashMap;)Ln11/a;

    .line 257
    .line 258
    .line 259
    move-result-object v1

    .line 260
    iput-object v1, p1, Lp11/a;->u:Ln11/a;

    .line 261
    .line 262
    iget-object v1, p1, Lp11/a;->t:Ln11/a;

    .line 263
    .line 264
    invoke-virtual {p0, v1, v0}, Lp11/r;->P(Ln11/a;Ljava/util/HashMap;)Ln11/a;

    .line 265
    .line 266
    .line 267
    move-result-object v1

    .line 268
    iput-object v1, p1, Lp11/a;->t:Ln11/a;

    .line 269
    .line 270
    iget-object v1, p1, Lp11/a;->v:Ln11/a;

    .line 271
    .line 272
    invoke-virtual {p0, v1, v0}, Lp11/r;->P(Ln11/a;Ljava/util/HashMap;)Ln11/a;

    .line 273
    .line 274
    .line 275
    move-result-object v1

    .line 276
    iput-object v1, p1, Lp11/a;->v:Ln11/a;

    .line 277
    .line 278
    iget-object v1, p1, Lp11/a;->w:Ln11/a;

    .line 279
    .line 280
    invoke-virtual {p0, v1, v0}, Lp11/r;->P(Ln11/a;Ljava/util/HashMap;)Ln11/a;

    .line 281
    .line 282
    .line 283
    move-result-object p0

    .line 284
    iput-object p0, p1, Lp11/a;->w:Ln11/a;

    .line 285
    .line 286
    return-void
.end method

.method public final P(Ln11/a;Ljava/util/HashMap;)Ln11/a;
    .locals 6

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    invoke-virtual {p1}, Ln11/a;->s()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    :cond_0
    move-object v1, p1

    .line 10
    goto :goto_0

    .line 11
    :cond_1
    invoke-virtual {p2, p1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_2

    .line 16
    .line 17
    invoke-virtual {p2, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    check-cast p0, Ln11/a;

    .line 22
    .line 23
    return-object p0

    .line 24
    :cond_2
    new-instance v0, Lp11/p;

    .line 25
    .line 26
    iget-object v1, p0, Lp11/b;->e:Ljava/lang/Object;

    .line 27
    .line 28
    move-object v2, v1

    .line 29
    check-cast v2, Ln11/f;

    .line 30
    .line 31
    invoke-virtual {p1}, Ln11/a;->i()Ln11/g;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    invoke-virtual {p0, v1, p2}, Lp11/r;->Q(Ln11/g;Ljava/util/HashMap;)Ln11/g;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    invoke-virtual {p1}, Ln11/a;->p()Ln11/g;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    invoke-virtual {p0, v1, p2}, Lp11/r;->Q(Ln11/g;Ljava/util/HashMap;)Ln11/g;

    .line 44
    .line 45
    .line 46
    move-result-object v4

    .line 47
    invoke-virtual {p1}, Ln11/a;->j()Ln11/g;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    invoke-virtual {p0, v1, p2}, Lp11/r;->Q(Ln11/g;Ljava/util/HashMap;)Ln11/g;

    .line 52
    .line 53
    .line 54
    move-result-object v5

    .line 55
    move-object v1, p1

    .line 56
    invoke-direct/range {v0 .. v5}, Lp11/p;-><init>(Ln11/a;Ln11/f;Ln11/g;Ln11/g;Ln11/g;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {p2, v1, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    return-object v0

    .line 63
    :goto_0
    return-object v1
.end method

.method public final Q(Ln11/g;Ljava/util/HashMap;)Ln11/g;
    .locals 1

    .line 1
    if-eqz p1, :cond_2

    .line 2
    .line 3
    invoke-virtual {p1}, Ln11/g;->f()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    invoke-virtual {p2, p1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-eqz v0, :cond_1

    .line 15
    .line 16
    invoke-virtual {p2, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    check-cast p0, Ln11/g;

    .line 21
    .line 22
    return-object p0

    .line 23
    :cond_1
    new-instance v0, Lp11/q;

    .line 24
    .line 25
    iget-object p0, p0, Lp11/b;->e:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p0, Ln11/f;

    .line 28
    .line 29
    invoke-direct {v0, p1, p0}, Lp11/q;-><init>(Ln11/g;Ln11/f;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {p2, p1, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    return-object v0

    .line 36
    :cond_2
    :goto_0
    return-object p1
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lp11/r;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lp11/r;

    .line 12
    .line 13
    iget-object v1, p0, Lp11/b;->d:Ljp/u1;

    .line 14
    .line 15
    iget-object v3, p1, Lp11/b;->d:Ljp/u1;

    .line 16
    .line 17
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_2

    .line 22
    .line 23
    iget-object p0, p0, Lp11/b;->e:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast p0, Ln11/f;

    .line 26
    .line 27
    iget-object p1, p1, Lp11/b;->e:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast p1, Ln11/f;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ln11/f;->equals(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    if-eqz p0, :cond_2

    .line 36
    .line 37
    return v0

    .line 38
    :cond_2
    return v2
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    iget-object v0, p0, Lp11/b;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ln11/f;

    .line 4
    .line 5
    invoke-virtual {v0}, Ln11/f;->hashCode()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    mul-int/lit8 v0, v0, 0xb

    .line 10
    .line 11
    const v1, 0x4fba5

    .line 12
    .line 13
    .line 14
    add-int/2addr v0, v1

    .line 15
    iget-object p0, p0, Lp11/b;->d:Ljp/u1;

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    mul-int/lit8 p0, p0, 0x7

    .line 22
    .line 23
    add-int/2addr p0, v0

    .line 24
    return p0
.end method

.method public final l(J)J
    .locals 10

    .line 1
    iget-object v0, p0, Lp11/b;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ln11/f;

    .line 4
    .line 5
    invoke-virtual {v0, p1, p2}, Ln11/f;->i(J)I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    int-to-long v1, v1

    .line 10
    add-long/2addr p1, v1

    .line 11
    iget-object p0, p0, Lp11/b;->d:Ljp/u1;

    .line 12
    .line 13
    invoke-virtual {p0, p1, p2}, Ljp/u1;->l(J)J

    .line 14
    .line 15
    .line 16
    move-result-wide p0

    .line 17
    const-wide v1, 0x7fffffffffffffffL

    .line 18
    .line 19
    .line 20
    .line 21
    .line 22
    cmp-long p2, p0, v1

    .line 23
    .line 24
    if-nez p2, :cond_0

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const-wide/high16 v3, -0x8000000000000000L

    .line 28
    .line 29
    cmp-long p2, p0, v3

    .line 30
    .line 31
    if-nez p2, :cond_1

    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_1
    invoke-virtual {v0, p0, p1}, Ln11/f;->j(J)I

    .line 35
    .line 36
    .line 37
    move-result p2

    .line 38
    int-to-long v5, p2

    .line 39
    sub-long v5, p0, v5

    .line 40
    .line 41
    const-wide/32 v7, 0x240c8400

    .line 42
    .line 43
    .line 44
    cmp-long v7, p0, v7

    .line 45
    .line 46
    const-wide/16 v8, 0x0

    .line 47
    .line 48
    if-lez v7, :cond_2

    .line 49
    .line 50
    cmp-long v7, v5, v8

    .line 51
    .line 52
    if-gez v7, :cond_2

    .line 53
    .line 54
    :goto_0
    return-wide v1

    .line 55
    :cond_2
    const-wide/32 v1, -0x240c8400

    .line 56
    .line 57
    .line 58
    cmp-long v1, p0, v1

    .line 59
    .line 60
    if-gez v1, :cond_3

    .line 61
    .line 62
    cmp-long v1, v5, v8

    .line 63
    .line 64
    if-lez v1, :cond_3

    .line 65
    .line 66
    :goto_1
    return-wide v3

    .line 67
    :cond_3
    invoke-virtual {v0, v5, v6}, Ln11/f;->i(J)I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-ne p2, v1, :cond_4

    .line 72
    .line 73
    return-wide v5

    .line 74
    :cond_4
    new-instance p2, Lgz0/a;

    .line 75
    .line 76
    iget-object v0, v0, Ln11/f;->d:Ljava/lang/String;

    .line 77
    .line 78
    invoke-direct {p2, p0, p1, v0}, Lgz0/a;-><init>(JLjava/lang/String;)V

    .line 79
    .line 80
    .line 81
    throw p2
.end method

.method public final m()Ln11/f;
    .locals 0

    .line 1
    iget-object p0, p0, Lp11/b;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ln11/f;

    .line 4
    .line 5
    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "ZonedChronology["

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lp11/b;->d:Ljp/u1;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", "

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Lp11/b;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Ln11/f;

    .line 21
    .line 22
    iget-object p0, p0, Ln11/f;->d:Ljava/lang/String;

    .line 23
    .line 24
    const/16 v1, 0x5d

    .line 25
    .line 26
    invoke-static {v0, p0, v1}, La7/g0;->j(Ljava/lang/StringBuilder;Ljava/lang/String;C)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0
.end method
