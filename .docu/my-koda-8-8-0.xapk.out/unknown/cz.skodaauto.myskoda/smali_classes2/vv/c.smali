.class public final Lvv/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:J

.field public final b:J

.field public final c:J

.field public final d:Lay0/k;


# direct methods
.method public constructor <init>()V
    .locals 7

    .line 1
    const/4 v0, 0x6

    .line 2
    invoke-static {v0}, Lgq/b;->c(I)J

    .line 3
    .line 4
    .line 5
    move-result-wide v1

    .line 6
    const/4 v3, 0x3

    .line 7
    invoke-static {v3}, Lgq/b;->c(I)J

    .line 8
    .line 9
    .line 10
    move-result-wide v3

    .line 11
    invoke-static {v0}, Lgq/b;->c(I)J

    .line 12
    .line 13
    .line 14
    move-result-wide v5

    .line 15
    sget-object v0, Lvv/b;->g:Lvv/b;

    .line 16
    .line 17
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 18
    .line 19
    .line 20
    iput-wide v1, p0, Lvv/c;->a:J

    .line 21
    .line 22
    iput-wide v3, p0, Lvv/c;->b:J

    .line 23
    .line 24
    iput-wide v5, p0, Lvv/c;->c:J

    .line 25
    .line 26
    iput-object v0, p0, Lvv/c;->d:Lay0/k;

    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public final a(Lvv/m0;Ll2/o;I)V
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p3

    .line 6
    .line 7
    const-string v3, "<this>"

    .line 8
    .line 9
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    move-object/from16 v3, p2

    .line 13
    .line 14
    check-cast v3, Ll2/t;

    .line 15
    .line 16
    const v4, 0x79f4facd    # 1.5900091E35f

    .line 17
    .line 18
    .line 19
    invoke-virtual {v3, v4}, Ll2/t;->a0(I)Ll2/t;

    .line 20
    .line 21
    .line 22
    and-int/lit8 v4, v2, 0xe

    .line 23
    .line 24
    if-nez v4, :cond_1

    .line 25
    .line 26
    invoke-virtual {v3, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v4

    .line 30
    if-eqz v4, :cond_0

    .line 31
    .line 32
    const/4 v4, 0x4

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    const/4 v4, 0x2

    .line 35
    :goto_0
    or-int/2addr v4, v2

    .line 36
    goto :goto_1

    .line 37
    :cond_1
    move v4, v2

    .line 38
    :goto_1
    and-int/lit8 v6, v2, 0x70

    .line 39
    .line 40
    if-nez v6, :cond_3

    .line 41
    .line 42
    invoke-virtual {v3, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v6

    .line 46
    if-eqz v6, :cond_2

    .line 47
    .line 48
    const/16 v6, 0x20

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_2
    const/16 v6, 0x10

    .line 52
    .line 53
    :goto_2
    or-int/2addr v4, v6

    .line 54
    :cond_3
    and-int/lit8 v4, v4, 0x5b

    .line 55
    .line 56
    const/16 v6, 0x12

    .line 57
    .line 58
    if-ne v4, v6, :cond_5

    .line 59
    .line 60
    invoke-virtual {v3}, Ll2/t;->A()Z

    .line 61
    .line 62
    .line 63
    move-result v4

    .line 64
    if-nez v4, :cond_4

    .line 65
    .line 66
    goto :goto_3

    .line 67
    :cond_4
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 68
    .line 69
    .line 70
    goto/16 :goto_5

    .line 71
    .line 72
    :cond_5
    :goto_3
    sget-object v4, Lw3/h1;->h:Ll2/u2;

    .line 73
    .line 74
    invoke-virtual {v3, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v4

    .line 78
    check-cast v4, Lt4/c;

    .line 79
    .line 80
    invoke-static {v1, v3}, Lvv/l0;->d(Lvv/m0;Ll2/o;)J

    .line 81
    .line 82
    .line 83
    move-result-wide v6

    .line 84
    new-instance v8, Le3/s;

    .line 85
    .line 86
    invoke-direct {v8, v6, v7}, Le3/s;-><init>(J)V

    .line 87
    .line 88
    .line 89
    iget-object v6, v0, Lvv/c;->d:Lay0/k;

    .line 90
    .line 91
    invoke-interface {v6, v8}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v6

    .line 95
    check-cast v6, Le3/s;

    .line 96
    .line 97
    iget-wide v6, v6, Le3/s;->a:J

    .line 98
    .line 99
    new-instance v8, Lt4/o;

    .line 100
    .line 101
    iget-wide v9, v0, Lvv/c;->a:J

    .line 102
    .line 103
    invoke-direct {v8, v9, v10}, Lt4/o;-><init>(J)V

    .line 104
    .line 105
    .line 106
    new-instance v11, Lt4/o;

    .line 107
    .line 108
    iget-wide v12, v0, Lvv/c;->c:J

    .line 109
    .line 110
    invoke-direct {v11, v12, v13}, Lt4/o;-><init>(J)V

    .line 111
    .line 112
    .line 113
    new-instance v14, Lt4/o;

    .line 114
    .line 115
    move-wide v15, v6

    .line 116
    iget-wide v5, v0, Lvv/c;->b:J

    .line 117
    .line 118
    invoke-direct {v14, v5, v6}, Lt4/o;-><init>(J)V

    .line 119
    .line 120
    .line 121
    new-instance v7, Le3/s;

    .line 122
    .line 123
    move-wide v0, v15

    .line 124
    invoke-direct {v7, v0, v1}, Le3/s;-><init>(J)V

    .line 125
    .line 126
    .line 127
    filled-new-array {v8, v11, v14, v7}, [Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v7

    .line 131
    const v8, -0x21de6e89

    .line 132
    .line 133
    .line 134
    invoke-virtual {v3, v8}, Ll2/t;->Z(I)V

    .line 135
    .line 136
    .line 137
    const/4 v8, 0x0

    .line 138
    move v11, v8

    .line 139
    move v14, v11

    .line 140
    :goto_4
    const/4 v15, 0x4

    .line 141
    if-ge v11, v15, :cond_6

    .line 142
    .line 143
    aget-object v15, v7, v11

    .line 144
    .line 145
    invoke-virtual {v3, v15}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 146
    .line 147
    .line 148
    move-result v15

    .line 149
    or-int/2addr v14, v15

    .line 150
    add-int/lit8 v11, v11, 0x1

    .line 151
    .line 152
    goto :goto_4

    .line 153
    :cond_6
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    move-result-object v7

    .line 157
    if-nez v14, :cond_7

    .line 158
    .line 159
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 160
    .line 161
    if-ne v7, v11, :cond_8

    .line 162
    .line 163
    :cond_7
    invoke-interface {v4, v9, v10}, Lt4/c;->s(J)F

    .line 164
    .line 165
    .line 166
    move-result v15

    .line 167
    invoke-interface {v4, v12, v13}, Lt4/c;->s(J)F

    .line 168
    .line 169
    .line 170
    move-result v17

    .line 171
    const/16 v18, 0x0

    .line 172
    .line 173
    const/16 v19, 0xa

    .line 174
    .line 175
    sget-object v14, Lx2/p;->b:Lx2/p;

    .line 176
    .line 177
    const/16 v16, 0x0

    .line 178
    .line 179
    invoke-static/range {v14 .. v19}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 180
    .line 181
    .line 182
    move-result-object v7

    .line 183
    invoke-interface {v4, v5, v6}, Lt4/c;->s(J)F

    .line 184
    .line 185
    .line 186
    move-result v4

    .line 187
    invoke-static {v7, v4}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 188
    .line 189
    .line 190
    move-result-object v4

    .line 191
    invoke-static {}, Ls1/f;->a()Ls1/e;

    .line 192
    .line 193
    .line 194
    move-result-object v5

    .line 195
    invoke-static {v4, v0, v1, v5}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 196
    .line 197
    .line 198
    move-result-object v7

    .line 199
    invoke-virtual {v3, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 200
    .line 201
    .line 202
    :cond_8
    invoke-virtual {v3, v8}, Ll2/t;->q(Z)V

    .line 203
    .line 204
    .line 205
    check-cast v7, Lx2/s;

    .line 206
    .line 207
    invoke-static {v7, v3, v8}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 208
    .line 209
    .line 210
    :goto_5
    invoke-virtual {v3}, Ll2/t;->s()Ll2/u1;

    .line 211
    .line 212
    .line 213
    move-result-object v0

    .line 214
    if-eqz v0, :cond_9

    .line 215
    .line 216
    new-instance v1, Ljn/g;

    .line 217
    .line 218
    const/4 v3, 0x1

    .line 219
    move-object/from16 v4, p0

    .line 220
    .line 221
    move-object/from16 v5, p1

    .line 222
    .line 223
    invoke-direct {v1, v2, v3, v4, v5}, Ljn/g;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 224
    .line 225
    .line 226
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 227
    .line 228
    :cond_9
    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lvv/c;

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
    check-cast p1, Lvv/c;

    .line 12
    .line 13
    iget-wide v3, p0, Lvv/c;->a:J

    .line 14
    .line 15
    iget-wide v5, p1, Lvv/c;->a:J

    .line 16
    .line 17
    invoke-static {v3, v4, v5, v6}, Lt4/o;->a(JJ)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-wide v3, p0, Lvv/c;->b:J

    .line 25
    .line 26
    iget-wide v5, p1, Lvv/c;->b:J

    .line 27
    .line 28
    invoke-static {v3, v4, v5, v6}, Lt4/o;->a(JJ)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget-wide v3, p0, Lvv/c;->c:J

    .line 36
    .line 37
    iget-wide v5, p1, Lvv/c;->c:J

    .line 38
    .line 39
    invoke-static {v3, v4, v5, v6}, Lt4/o;->a(JJ)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-nez v1, :cond_4

    .line 44
    .line 45
    return v2

    .line 46
    :cond_4
    iget-object p0, p0, Lvv/c;->d:Lay0/k;

    .line 47
    .line 48
    iget-object p1, p1, Lvv/c;->d:Lay0/k;

    .line 49
    .line 50
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    if-nez p0, :cond_5

    .line 55
    .line 56
    return v2

    .line 57
    :cond_5
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    sget-object v0, Lt4/o;->b:[Lt4/p;

    .line 2
    .line 3
    iget-wide v0, p0, Lvv/c;->a:J

    .line 4
    .line 5
    invoke-static {v0, v1}, Ljava/lang/Long;->hashCode(J)I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/16 v1, 0x1f

    .line 10
    .line 11
    mul-int/2addr v0, v1

    .line 12
    iget-wide v2, p0, Lvv/c;->b:J

    .line 13
    .line 14
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    iget-wide v2, p0, Lvv/c;->c:J

    .line 19
    .line 20
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    iget-object p0, p0, Lvv/c;->d:Lay0/k;

    .line 25
    .line 26
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    add-int/2addr p0, v0

    .line 31
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 6

    .line 1
    iget-wide v0, p0, Lvv/c;->a:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lt4/o;->d(J)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-wide v1, p0, Lvv/c;->b:J

    .line 8
    .line 9
    invoke-static {v1, v2}, Lt4/o;->d(J)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    iget-wide v2, p0, Lvv/c;->c:J

    .line 14
    .line 15
    invoke-static {v2, v3}, Lt4/o;->d(J)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    const-string v3, ", barWidth="

    .line 20
    .line 21
    const-string v4, ", endMargin="

    .line 22
    .line 23
    const-string v5, "BarGutter(startMargin="

    .line 24
    .line 25
    invoke-static {v5, v0, v3, v1, v4}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    const-string v1, ", color="

    .line 33
    .line 34
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    iget-object p0, p0, Lvv/c;->d:Lay0/k;

    .line 38
    .line 39
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string p0, ")"

    .line 43
    .line 44
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    return-object p0
.end method
