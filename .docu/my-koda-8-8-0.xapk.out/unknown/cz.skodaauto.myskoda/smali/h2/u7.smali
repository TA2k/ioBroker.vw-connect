.class public final Lh2/u7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:I

.field public b:Lay0/a;

.field public final c:Lgy0/f;

.field public final d:Ll2/f1;

.field public final e:Ll2/f1;

.field public f:Lay0/k;

.field public final g:[F

.field public final h:Ll2/f1;

.field public final i:Ll2/f1;

.field public final j:Ll2/f1;

.field public final k:Ll2/f1;

.field public final l:Ll2/g1;

.field public final m:Ll2/f1;

.field public final n:Ll2/f1;

.field public final o:Ll2/j1;

.field public final p:Ll2/j1;

.field public final q:Lh2/t7;

.field public final r:Ll2/f1;

.field public final s:Ll2/f1;


# direct methods
.method public constructor <init>(FFILay0/a;Lgy0/f;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Lh2/u7;->a:I

    .line 5
    .line 6
    iput-object p4, p0, Lh2/u7;->b:Lay0/a;

    .line 7
    .line 8
    iput-object p5, p0, Lh2/u7;->c:Lgy0/f;

    .line 9
    .line 10
    new-instance p4, Ll2/f1;

    .line 11
    .line 12
    invoke-direct {p4, p1}, Ll2/f1;-><init>(F)V

    .line 13
    .line 14
    .line 15
    iput-object p4, p0, Lh2/u7;->d:Ll2/f1;

    .line 16
    .line 17
    new-instance p1, Ll2/f1;

    .line 18
    .line 19
    invoke-direct {p1, p2}, Ll2/f1;-><init>(F)V

    .line 20
    .line 21
    .line 22
    iput-object p1, p0, Lh2/u7;->e:Ll2/f1;

    .line 23
    .line 24
    const/4 p1, 0x0

    .line 25
    if-nez p3, :cond_0

    .line 26
    .line 27
    new-array p2, p1, [F

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_0
    add-int/lit8 p2, p3, 0x2

    .line 31
    .line 32
    new-array p4, p2, [F

    .line 33
    .line 34
    move p5, p1

    .line 35
    :goto_0
    if-ge p5, p2, :cond_1

    .line 36
    .line 37
    int-to-float v0, p5

    .line 38
    add-int/lit8 v1, p3, 0x1

    .line 39
    .line 40
    int-to-float v1, v1

    .line 41
    div-float/2addr v0, v1

    .line 42
    aput v0, p4, p5

    .line 43
    .line 44
    add-int/lit8 p5, p5, 0x1

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_1
    move-object p2, p4

    .line 48
    :goto_1
    iput-object p2, p0, Lh2/u7;->g:[F

    .line 49
    .line 50
    new-instance p2, Ll2/f1;

    .line 51
    .line 52
    const/4 p3, 0x0

    .line 53
    invoke-direct {p2, p3}, Ll2/f1;-><init>(F)V

    .line 54
    .line 55
    .line 56
    iput-object p2, p0, Lh2/u7;->h:Ll2/f1;

    .line 57
    .line 58
    new-instance p2, Ll2/f1;

    .line 59
    .line 60
    invoke-direct {p2, p3}, Ll2/f1;-><init>(F)V

    .line 61
    .line 62
    .line 63
    iput-object p2, p0, Lh2/u7;->i:Ll2/f1;

    .line 64
    .line 65
    new-instance p2, Ll2/f1;

    .line 66
    .line 67
    invoke-direct {p2, p3}, Ll2/f1;-><init>(F)V

    .line 68
    .line 69
    .line 70
    iput-object p2, p0, Lh2/u7;->j:Ll2/f1;

    .line 71
    .line 72
    new-instance p2, Ll2/f1;

    .line 73
    .line 74
    invoke-direct {p2, p3}, Ll2/f1;-><init>(F)V

    .line 75
    .line 76
    .line 77
    iput-object p2, p0, Lh2/u7;->k:Ll2/f1;

    .line 78
    .line 79
    new-instance p2, Ll2/g1;

    .line 80
    .line 81
    invoke-direct {p2, p1}, Ll2/g1;-><init>(I)V

    .line 82
    .line 83
    .line 84
    iput-object p2, p0, Lh2/u7;->l:Ll2/g1;

    .line 85
    .line 86
    new-instance p1, Ll2/f1;

    .line 87
    .line 88
    invoke-direct {p1, p3}, Ll2/f1;-><init>(F)V

    .line 89
    .line 90
    .line 91
    iput-object p1, p0, Lh2/u7;->m:Ll2/f1;

    .line 92
    .line 93
    new-instance p1, Ll2/f1;

    .line 94
    .line 95
    invoke-direct {p1, p3}, Ll2/f1;-><init>(F)V

    .line 96
    .line 97
    .line 98
    iput-object p1, p0, Lh2/u7;->n:Ll2/f1;

    .line 99
    .line 100
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 101
    .line 102
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 103
    .line 104
    .line 105
    move-result-object p2

    .line 106
    iput-object p2, p0, Lh2/u7;->o:Ll2/j1;

    .line 107
    .line 108
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 109
    .line 110
    .line 111
    move-result-object p1

    .line 112
    iput-object p1, p0, Lh2/u7;->p:Ll2/j1;

    .line 113
    .line 114
    new-instance p1, Lh2/t7;

    .line 115
    .line 116
    const/4 p2, 0x0

    .line 117
    invoke-direct {p1, p0, p2}, Lh2/t7;-><init>(Lh2/u7;I)V

    .line 118
    .line 119
    .line 120
    iput-object p1, p0, Lh2/u7;->q:Lh2/t7;

    .line 121
    .line 122
    new-instance p1, Ll2/f1;

    .line 123
    .line 124
    invoke-direct {p1, p3}, Ll2/f1;-><init>(F)V

    .line 125
    .line 126
    .line 127
    iput-object p1, p0, Lh2/u7;->r:Ll2/f1;

    .line 128
    .line 129
    new-instance p1, Ll2/f1;

    .line 130
    .line 131
    invoke-direct {p1, p3}, Ll2/f1;-><init>(F)V

    .line 132
    .line 133
    .line 134
    iput-object p1, p0, Lh2/u7;->s:Ll2/f1;

    .line 135
    .line 136
    return-void
.end method


# virtual methods
.method public final a()F
    .locals 2

    .line 1
    iget-object v0, p0, Lh2/u7;->c:Lgy0/f;

    .line 2
    .line 3
    invoke-interface {v0}, Lgy0/g;->e()Ljava/lang/Comparable;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Ljava/lang/Number;

    .line 8
    .line 9
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    invoke-interface {v0}, Lgy0/g;->g()Ljava/lang/Comparable;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    check-cast v0, Ljava/lang/Number;

    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    iget-object p0, p0, Lh2/u7;->e:Ll2/f1;

    .line 24
    .line 25
    invoke-virtual {p0}, Ll2/f1;->o()F

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    invoke-static {v1, v0, p0}, Lh2/q9;->j(FFF)F

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    return p0
.end method

.method public final b()F
    .locals 2

    .line 1
    iget-object v0, p0, Lh2/u7;->c:Lgy0/f;

    .line 2
    .line 3
    invoke-interface {v0}, Lgy0/g;->e()Ljava/lang/Comparable;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Ljava/lang/Number;

    .line 8
    .line 9
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    invoke-interface {v0}, Lgy0/g;->g()Ljava/lang/Comparable;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    check-cast v0, Ljava/lang/Number;

    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    iget-object p0, p0, Lh2/u7;->d:Ll2/f1;

    .line 24
    .line 25
    invoke-virtual {p0}, Ll2/f1;->o()F

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    invoke-static {v1, v0, p0}, Lh2/q9;->j(FFF)F

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    return p0
.end method

.method public final c()I
    .locals 2

    .line 1
    iget v0, p0, Lh2/u7;->a:I

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    const/high16 v1, 0x3f800000    # 1.0f

    .line 5
    .line 6
    invoke-virtual {p0}, Lh2/u7;->b()F

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    sub-float/2addr v1, p0

    .line 11
    mul-float/2addr v1, v0

    .line 12
    float-to-double v0, v1

    .line 13
    invoke-static {v0, v1}, Ljava/lang/Math;->floor(D)D

    .line 14
    .line 15
    .line 16
    move-result-wide v0

    .line 17
    double-to-float p0, v0

    .line 18
    float-to-int p0, p0

    .line 19
    return p0
.end method

.method public final d()I
    .locals 2

    .line 1
    iget v0, p0, Lh2/u7;->a:I

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    invoke-virtual {p0}, Lh2/u7;->a()F

    .line 5
    .line 6
    .line 7
    move-result p0

    .line 8
    mul-float/2addr p0, v0

    .line 9
    float-to-double v0, p0

    .line 10
    invoke-static {v0, v1}, Ljava/lang/Math;->floor(D)D

    .line 11
    .line 12
    .line 13
    move-result-wide v0

    .line 14
    double-to-float p0, v0

    .line 15
    float-to-int p0, p0

    .line 16
    return p0
.end method

.method public final e(FZ)V
    .locals 9

    .line 1
    iget-object v0, p0, Lh2/u7;->d:Ll2/f1;

    .line 2
    .line 3
    iget-object v1, p0, Lh2/u7;->e:Ll2/f1;

    .line 4
    .line 5
    iget-object v2, p0, Lh2/u7;->n:Ll2/f1;

    .line 6
    .line 7
    iget-object v3, p0, Lh2/u7;->m:Ll2/f1;

    .line 8
    .line 9
    iget-object v4, p0, Lh2/u7;->r:Ll2/f1;

    .line 10
    .line 11
    iget-object v5, p0, Lh2/u7;->s:Ll2/f1;

    .line 12
    .line 13
    iget-object v6, p0, Lh2/u7;->g:[F

    .line 14
    .line 15
    if-eqz p2, :cond_1

    .line 16
    .line 17
    invoke-virtual {v3}, Ll2/f1;->o()F

    .line 18
    .line 19
    .line 20
    move-result v7

    .line 21
    add-float/2addr v7, p1

    .line 22
    invoke-virtual {v3, v7}, Ll2/f1;->p(F)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v5}, Ll2/f1;->o()F

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    invoke-virtual {v4}, Ll2/f1;->o()F

    .line 30
    .line 31
    .line 32
    move-result v7

    .line 33
    invoke-virtual {v1}, Ll2/f1;->o()F

    .line 34
    .line 35
    .line 36
    move-result v8

    .line 37
    invoke-virtual {p0, p1, v7, v8}, Lh2/u7;->f(FFF)F

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    invoke-virtual {v2, p1}, Ll2/f1;->p(F)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v2}, Ll2/f1;->o()F

    .line 45
    .line 46
    .line 47
    move-result p1

    .line 48
    invoke-virtual {v3}, Ll2/f1;->o()F

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    invoke-virtual {v5}, Ll2/f1;->o()F

    .line 53
    .line 54
    .line 55
    move-result v3

    .line 56
    invoke-static {v2, v3, p1}, Lkp/r9;->d(FFF)F

    .line 57
    .line 58
    .line 59
    move-result v2

    .line 60
    invoke-virtual {v5}, Ll2/f1;->o()F

    .line 61
    .line 62
    .line 63
    move-result v3

    .line 64
    invoke-virtual {v4}, Ll2/f1;->o()F

    .line 65
    .line 66
    .line 67
    move-result v7

    .line 68
    invoke-static {v6, v2, v3, v7}, Lh2/q9;->i([FFFF)F

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    cmpl-float v3, v2, p1

    .line 73
    .line 74
    if-lez v3, :cond_0

    .line 75
    .line 76
    move v2, p1

    .line 77
    :cond_0
    invoke-static {v2, p1}, Lh2/q9;->g(FF)J

    .line 78
    .line 79
    .line 80
    move-result-wide v2

    .line 81
    goto :goto_0

    .line 82
    :cond_1
    invoke-virtual {v2}, Ll2/f1;->o()F

    .line 83
    .line 84
    .line 85
    move-result v7

    .line 86
    add-float/2addr v7, p1

    .line 87
    invoke-virtual {v2, v7}, Ll2/f1;->p(F)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {v5}, Ll2/f1;->o()F

    .line 91
    .line 92
    .line 93
    move-result p1

    .line 94
    invoke-virtual {v4}, Ll2/f1;->o()F

    .line 95
    .line 96
    .line 97
    move-result v7

    .line 98
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 99
    .line 100
    .line 101
    move-result v8

    .line 102
    invoke-virtual {p0, p1, v7, v8}, Lh2/u7;->f(FFF)F

    .line 103
    .line 104
    .line 105
    move-result p1

    .line 106
    invoke-virtual {v3, p1}, Ll2/f1;->p(F)V

    .line 107
    .line 108
    .line 109
    invoke-virtual {v3}, Ll2/f1;->o()F

    .line 110
    .line 111
    .line 112
    move-result p1

    .line 113
    invoke-virtual {v2}, Ll2/f1;->o()F

    .line 114
    .line 115
    .line 116
    move-result v2

    .line 117
    invoke-virtual {v4}, Ll2/f1;->o()F

    .line 118
    .line 119
    .line 120
    move-result v3

    .line 121
    invoke-static {v2, p1, v3}, Lkp/r9;->d(FFF)F

    .line 122
    .line 123
    .line 124
    move-result v2

    .line 125
    invoke-virtual {v5}, Ll2/f1;->o()F

    .line 126
    .line 127
    .line 128
    move-result v3

    .line 129
    invoke-virtual {v4}, Ll2/f1;->o()F

    .line 130
    .line 131
    .line 132
    move-result v7

    .line 133
    invoke-static {v6, v2, v3, v7}, Lh2/q9;->i([FFFF)F

    .line 134
    .line 135
    .line 136
    move-result v2

    .line 137
    cmpg-float v3, v2, p1

    .line 138
    .line 139
    if-gez v3, :cond_2

    .line 140
    .line 141
    move v2, p1

    .line 142
    :cond_2
    invoke-static {p1, v2}, Lh2/q9;->g(FF)J

    .line 143
    .line 144
    .line 145
    move-result-wide v2

    .line 146
    :goto_0
    invoke-virtual {v5}, Ll2/f1;->o()F

    .line 147
    .line 148
    .line 149
    move-result p1

    .line 150
    invoke-virtual {v4}, Ll2/f1;->o()F

    .line 151
    .line 152
    .line 153
    move-result v4

    .line 154
    iget-object v5, p0, Lh2/u7;->c:Lgy0/f;

    .line 155
    .line 156
    invoke-interface {v5}, Lgy0/g;->e()Ljava/lang/Comparable;

    .line 157
    .line 158
    .line 159
    move-result-object v6

    .line 160
    check-cast v6, Ljava/lang/Number;

    .line 161
    .line 162
    invoke-virtual {v6}, Ljava/lang/Number;->floatValue()F

    .line 163
    .line 164
    .line 165
    move-result v6

    .line 166
    invoke-interface {v5}, Lgy0/g;->g()Ljava/lang/Comparable;

    .line 167
    .line 168
    .line 169
    move-result-object v5

    .line 170
    check-cast v5, Ljava/lang/Number;

    .line 171
    .line 172
    invoke-virtual {v5}, Ljava/lang/Number;->floatValue()F

    .line 173
    .line 174
    .line 175
    move-result v5

    .line 176
    invoke-static {v2, v3}, Lh2/r9;->b(J)F

    .line 177
    .line 178
    .line 179
    move-result v7

    .line 180
    invoke-static {p1, v4, v7, v6, v5}, Lh2/q9;->l(FFFFF)F

    .line 181
    .line 182
    .line 183
    move-result v7

    .line 184
    invoke-static {v2, v3}, Lh2/r9;->a(J)F

    .line 185
    .line 186
    .line 187
    move-result v2

    .line 188
    invoke-static {p1, v4, v2, v6, v5}, Lh2/q9;->l(FFFFF)F

    .line 189
    .line 190
    .line 191
    move-result p1

    .line 192
    if-eqz p2, :cond_4

    .line 193
    .line 194
    cmpl-float p2, v7, p1

    .line 195
    .line 196
    if-lez p2, :cond_3

    .line 197
    .line 198
    move v7, p1

    .line 199
    :cond_3
    invoke-static {v7, p1}, Lh2/q9;->g(FF)J

    .line 200
    .line 201
    .line 202
    move-result-wide p1

    .line 203
    goto :goto_1

    .line 204
    :cond_4
    cmpg-float p2, p1, v7

    .line 205
    .line 206
    if-gez p2, :cond_5

    .line 207
    .line 208
    move p1, v7

    .line 209
    :cond_5
    invoke-static {v7, p1}, Lh2/q9;->g(FF)J

    .line 210
    .line 211
    .line 212
    move-result-wide p1

    .line 213
    :goto_1
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 214
    .line 215
    .line 216
    move-result v0

    .line 217
    invoke-virtual {v1}, Ll2/f1;->o()F

    .line 218
    .line 219
    .line 220
    move-result v1

    .line 221
    invoke-static {v0, v1}, Lh2/q9;->g(FF)J

    .line 222
    .line 223
    .line 224
    move-result-wide v0

    .line 225
    cmp-long v0, p1, v0

    .line 226
    .line 227
    if-nez v0, :cond_6

    .line 228
    .line 229
    return-void

    .line 230
    :cond_6
    iget-object v0, p0, Lh2/u7;->f:Lay0/k;

    .line 231
    .line 232
    if-eqz v0, :cond_7

    .line 233
    .line 234
    new-instance p0, Lh2/r9;

    .line 235
    .line 236
    invoke-direct {p0, p1, p2}, Lh2/r9;-><init>(J)V

    .line 237
    .line 238
    .line 239
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 240
    .line 241
    .line 242
    return-void

    .line 243
    :cond_7
    invoke-static {p1, p2}, Lh2/r9;->b(J)F

    .line 244
    .line 245
    .line 246
    move-result v0

    .line 247
    invoke-virtual {p0, v0}, Lh2/u7;->h(F)V

    .line 248
    .line 249
    .line 250
    invoke-static {p1, p2}, Lh2/r9;->a(J)F

    .line 251
    .line 252
    .line 253
    move-result p1

    .line 254
    invoke-virtual {p0, p1}, Lh2/u7;->g(F)V

    .line 255
    .line 256
    .line 257
    return-void
.end method

.method public final f(FFF)F
    .locals 1

    .line 1
    iget-object p0, p0, Lh2/u7;->c:Lgy0/f;

    .line 2
    .line 3
    invoke-interface {p0}, Lgy0/g;->e()Ljava/lang/Comparable;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Ljava/lang/Number;

    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    invoke-interface {p0}, Lgy0/g;->g()Ljava/lang/Comparable;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Ljava/lang/Number;

    .line 18
    .line 19
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    invoke-static {v0, p0, p3, p1, p2}, Lh2/q9;->l(FFFFF)F

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    return p0
.end method

.method public final g(F)V
    .locals 3

    .line 1
    iget-object v0, p0, Lh2/u7;->d:Ll2/f1;

    .line 2
    .line 3
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget-object v1, p0, Lh2/u7;->c:Lgy0/f;

    .line 8
    .line 9
    invoke-interface {v1}, Lgy0/g;->g()Ljava/lang/Comparable;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    check-cast v2, Ljava/lang/Number;

    .line 14
    .line 15
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    invoke-static {p1, v0, v2}, Lkp/r9;->d(FFF)F

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    invoke-interface {v1}, Lgy0/g;->e()Ljava/lang/Comparable;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    check-cast v0, Ljava/lang/Number;

    .line 28
    .line 29
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    invoke-interface {v1}, Lgy0/g;->g()Ljava/lang/Comparable;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    check-cast v1, Ljava/lang/Number;

    .line 38
    .line 39
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    iget-object v2, p0, Lh2/u7;->g:[F

    .line 44
    .line 45
    invoke-static {v2, p1, v0, v1}, Lh2/q9;->i([FFFF)F

    .line 46
    .line 47
    .line 48
    move-result p1

    .line 49
    iget-object p0, p0, Lh2/u7;->e:Ll2/f1;

    .line 50
    .line 51
    invoke-virtual {p0, p1}, Ll2/f1;->p(F)V

    .line 52
    .line 53
    .line 54
    return-void
.end method

.method public final h(F)V
    .locals 3

    .line 1
    iget-object v0, p0, Lh2/u7;->c:Lgy0/f;

    .line 2
    .line 3
    invoke-interface {v0}, Lgy0/g;->e()Ljava/lang/Comparable;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Ljava/lang/Number;

    .line 8
    .line 9
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    iget-object v2, p0, Lh2/u7;->e:Ll2/f1;

    .line 14
    .line 15
    invoke-virtual {v2}, Ll2/f1;->o()F

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    invoke-static {p1, v1, v2}, Lkp/r9;->d(FFF)F

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    invoke-interface {v0}, Lgy0/g;->e()Ljava/lang/Comparable;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    check-cast v1, Ljava/lang/Number;

    .line 28
    .line 29
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    invoke-interface {v0}, Lgy0/g;->g()Ljava/lang/Comparable;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    check-cast v0, Ljava/lang/Number;

    .line 38
    .line 39
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    iget-object v2, p0, Lh2/u7;->g:[F

    .line 44
    .line 45
    invoke-static {v2, p1, v1, v0}, Lh2/q9;->i([FFFF)F

    .line 46
    .line 47
    .line 48
    move-result p1

    .line 49
    iget-object p0, p0, Lh2/u7;->d:Ll2/f1;

    .line 50
    .line 51
    invoke-virtual {p0, p1}, Ll2/f1;->p(F)V

    .line 52
    .line 53
    .line 54
    return-void
.end method
