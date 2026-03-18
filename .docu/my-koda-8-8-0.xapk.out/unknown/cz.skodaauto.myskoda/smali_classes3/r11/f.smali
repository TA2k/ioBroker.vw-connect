.class public final Lr11/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lr11/y;
.implements Lr11/w;


# instance fields
.field public final d:Ln11/b;

.field public final e:I

.field public final f:I


# direct methods
.method public constructor <init>(Ln11/b;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lr11/f;->d:Ln11/b;

    .line 5
    .line 6
    const/16 p1, 0x12

    .line 7
    .line 8
    if-le p3, p1, :cond_0

    .line 9
    .line 10
    move p3, p1

    .line 11
    :cond_0
    iput p2, p0, Lr11/f;->e:I

    .line 12
    .line 13
    iput p3, p0, Lr11/f;->f:I

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final a()I
    .locals 0

    .line 1
    iget p0, p0, Lr11/f;->f:I

    .line 2
    .line 3
    return p0
.end method

.method public final b(Ljava/lang/StringBuilder;JLjp/u1;ILn11/f;Ljava/util/Locale;)V
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2, p3, p4}, Lr11/f;->f(Ljava/lang/StringBuilder;JLjp/u1;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final c(Ljava/lang/StringBuilder;Lo11/b;Ljava/util/Locale;)V
    .locals 6

    .line 1
    invoke-virtual {p2}, Lo11/b;->c()Ljp/u1;

    .line 2
    .line 3
    .line 4
    move-result-object p3

    .line 5
    check-cast p3, Lp11/c;

    .line 6
    .line 7
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    invoke-virtual {p2}, Lo11/b;->h()I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    const-wide/16 v1, 0x0

    .line 15
    .line 16
    const/4 v3, 0x0

    .line 17
    :goto_0
    if-ge v3, v0, :cond_0

    .line 18
    .line 19
    invoke-virtual {p2, v3}, Lo11/b;->e(I)Ln11/b;

    .line 20
    .line 21
    .line 22
    move-result-object v4

    .line 23
    invoke-virtual {v4, p3}, Ln11/b;->a(Ljp/u1;)Ln11/a;

    .line 24
    .line 25
    .line 26
    move-result-object v4

    .line 27
    invoke-virtual {p2, v3}, Lo11/b;->f(I)I

    .line 28
    .line 29
    .line 30
    move-result v5

    .line 31
    invoke-virtual {v4, v5, v1, v2}, Ln11/a;->v(IJ)J

    .line 32
    .line 33
    .line 34
    move-result-wide v1

    .line 35
    add-int/lit8 v3, v3, 0x1

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    invoke-virtual {p2}, Lo11/b;->c()Ljp/u1;

    .line 39
    .line 40
    .line 41
    move-result-object p2

    .line 42
    invoke-virtual {p0, p1, v1, v2, p2}, Lr11/f;->f(Ljava/lang/StringBuilder;JLjp/u1;)V

    .line 43
    .line 44
    .line 45
    return-void
.end method

.method public final d(Lr11/s;Ljava/lang/CharSequence;I)I
    .locals 10

    .line 1
    iget-object v0, p0, Lr11/f;->d:Ln11/b;

    .line 2
    .line 3
    iget-object v1, p1, Lr11/s;->a:Ljp/u1;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Ln11/b;->a(Ljp/u1;)Ln11/a;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-interface {p2}, Ljava/lang/CharSequence;->length()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    sub-int/2addr v1, p3

    .line 14
    iget p0, p0, Lr11/f;->f:I

    .line 15
    .line 16
    invoke-static {p0, v1}, Ljava/lang/Math;->min(II)I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    invoke-virtual {v0}, Ln11/a;->i()Ln11/g;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    invoke-virtual {v1}, Ln11/g;->d()J

    .line 25
    .line 26
    .line 27
    move-result-wide v1

    .line 28
    const-wide/16 v3, 0xa

    .line 29
    .line 30
    mul-long/2addr v1, v3

    .line 31
    const-wide/16 v5, 0x0

    .line 32
    .line 33
    const/4 v7, 0x0

    .line 34
    :goto_0
    if-ge v7, p0, :cond_1

    .line 35
    .line 36
    add-int v8, p3, v7

    .line 37
    .line 38
    invoke-interface {p2, v8}, Ljava/lang/CharSequence;->charAt(I)C

    .line 39
    .line 40
    .line 41
    move-result v8

    .line 42
    const/16 v9, 0x30

    .line 43
    .line 44
    if-lt v8, v9, :cond_1

    .line 45
    .line 46
    const/16 v9, 0x39

    .line 47
    .line 48
    if-le v8, v9, :cond_0

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_0
    add-int/lit8 v7, v7, 0x1

    .line 52
    .line 53
    div-long/2addr v1, v3

    .line 54
    add-int/lit8 v8, v8, -0x30

    .line 55
    .line 56
    int-to-long v8, v8

    .line 57
    mul-long/2addr v8, v1

    .line 58
    add-long/2addr v5, v8

    .line 59
    goto :goto_0

    .line 60
    :cond_1
    :goto_1
    div-long/2addr v5, v3

    .line 61
    if-nez v7, :cond_2

    .line 62
    .line 63
    not-int p0, p3

    .line 64
    return p0

    .line 65
    :cond_2
    const-wide/32 v1, 0x7fffffff

    .line 66
    .line 67
    .line 68
    cmp-long p0, v5, v1

    .line 69
    .line 70
    if-lez p0, :cond_3

    .line 71
    .line 72
    not-int p0, p3

    .line 73
    return p0

    .line 74
    :cond_3
    new-instance p0, Lq11/i;

    .line 75
    .line 76
    sget-object p2, Ln11/b;->D:Ln11/b;

    .line 77
    .line 78
    sget-object v1, Lq11/g;->d:Lq11/g;

    .line 79
    .line 80
    invoke-virtual {v0}, Ln11/a;->i()Ln11/g;

    .line 81
    .line 82
    .line 83
    move-result-object v0

    .line 84
    invoke-direct {p0, p2, v1, v0}, Lq11/i;-><init>(Ln11/b;Ln11/g;Ln11/g;)V

    .line 85
    .line 86
    .line 87
    long-to-int p2, v5

    .line 88
    invoke-virtual {p1}, Lr11/s;->c()Lr11/q;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    iput-object p0, p1, Lr11/q;->d:Ln11/a;

    .line 93
    .line 94
    iput p2, p1, Lr11/q;->e:I

    .line 95
    .line 96
    const/4 p0, 0x0

    .line 97
    iput-object p0, p1, Lr11/q;->f:Ljava/lang/String;

    .line 98
    .line 99
    iput-object p0, p1, Lr11/q;->g:Ljava/util/Locale;

    .line 100
    .line 101
    add-int/2addr p3, v7

    .line 102
    return p3
.end method

.method public final e()I
    .locals 0

    .line 1
    iget p0, p0, Lr11/f;->f:I

    .line 2
    .line 3
    return p0
.end method

.method public final f(Ljava/lang/StringBuilder;JLjp/u1;)V
    .locals 9

    .line 1
    iget-object v0, p0, Lr11/f;->d:Ln11/b;

    .line 2
    .line 3
    invoke-virtual {v0, p4}, Ln11/b;->a(Ljp/u1;)Ln11/a;

    .line 4
    .line 5
    .line 6
    move-result-object p4

    .line 7
    iget v0, p0, Lr11/f;->e:I

    .line 8
    .line 9
    :try_start_0
    invoke-virtual {p4, p2, p3}, Ln11/a;->t(J)J

    .line 10
    .line 11
    .line 12
    move-result-wide p2
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 13
    const-wide/16 v1, 0x0

    .line 14
    .line 15
    cmp-long v1, p2, v1

    .line 16
    .line 17
    const/16 v2, 0x30

    .line 18
    .line 19
    if-nez v1, :cond_0

    .line 20
    .line 21
    :goto_0
    add-int/lit8 v0, v0, -0x1

    .line 22
    .line 23
    if-ltz v0, :cond_5

    .line 24
    .line 25
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/Appendable;

    .line 26
    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    invoke-virtual {p4}, Ln11/a;->i()Ln11/g;

    .line 30
    .line 31
    .line 32
    move-result-object p4

    .line 33
    invoke-virtual {p4}, Ln11/g;->d()J

    .line 34
    .line 35
    .line 36
    move-result-wide v3

    .line 37
    iget p0, p0, Lr11/f;->f:I

    .line 38
    .line 39
    :goto_1
    packed-switch p0, :pswitch_data_0

    .line 40
    .line 41
    .line 42
    const-wide/16 v5, 0x1

    .line 43
    .line 44
    goto :goto_2

    .line 45
    :pswitch_0
    const-wide v5, 0xde0b6b3a7640000L

    .line 46
    .line 47
    .line 48
    .line 49
    .line 50
    goto :goto_2

    .line 51
    :pswitch_1
    const-wide v5, 0x16345785d8a0000L

    .line 52
    .line 53
    .line 54
    .line 55
    .line 56
    goto :goto_2

    .line 57
    :pswitch_2
    const-wide v5, 0x2386f26fc10000L

    .line 58
    .line 59
    .line 60
    .line 61
    .line 62
    goto :goto_2

    .line 63
    :pswitch_3
    const-wide v5, 0x38d7ea4c68000L

    .line 64
    .line 65
    .line 66
    .line 67
    .line 68
    goto :goto_2

    .line 69
    :pswitch_4
    const-wide v5, 0x5af3107a4000L

    .line 70
    .line 71
    .line 72
    .line 73
    .line 74
    goto :goto_2

    .line 75
    :pswitch_5
    const-wide v5, 0x9184e72a000L

    .line 76
    .line 77
    .line 78
    .line 79
    .line 80
    goto :goto_2

    .line 81
    :pswitch_6
    const-wide v5, 0xe8d4a51000L

    .line 82
    .line 83
    .line 84
    .line 85
    .line 86
    goto :goto_2

    .line 87
    :pswitch_7
    const-wide v5, 0x174876e800L

    .line 88
    .line 89
    .line 90
    .line 91
    .line 92
    goto :goto_2

    .line 93
    :pswitch_8
    const-wide v5, 0x2540be400L

    .line 94
    .line 95
    .line 96
    .line 97
    .line 98
    goto :goto_2

    .line 99
    :pswitch_9
    const-wide/32 v5, 0x3b9aca00

    .line 100
    .line 101
    .line 102
    goto :goto_2

    .line 103
    :pswitch_a
    const-wide/32 v5, 0x5f5e100

    .line 104
    .line 105
    .line 106
    goto :goto_2

    .line 107
    :pswitch_b
    const-wide/32 v5, 0x989680

    .line 108
    .line 109
    .line 110
    goto :goto_2

    .line 111
    :pswitch_c
    const-wide/32 v5, 0xf4240

    .line 112
    .line 113
    .line 114
    goto :goto_2

    .line 115
    :pswitch_d
    const-wide/32 v5, 0x186a0

    .line 116
    .line 117
    .line 118
    goto :goto_2

    .line 119
    :pswitch_e
    const-wide/16 v5, 0x2710

    .line 120
    .line 121
    goto :goto_2

    .line 122
    :pswitch_f
    const-wide/16 v5, 0x3e8

    .line 123
    .line 124
    goto :goto_2

    .line 125
    :pswitch_10
    const-wide/16 v5, 0x64

    .line 126
    .line 127
    goto :goto_2

    .line 128
    :pswitch_11
    const-wide/16 v5, 0xa

    .line 129
    .line 130
    :goto_2
    mul-long v7, v3, v5

    .line 131
    .line 132
    div-long/2addr v7, v5

    .line 133
    cmp-long p4, v7, v3

    .line 134
    .line 135
    if-nez p4, :cond_7

    .line 136
    .line 137
    mul-long/2addr p2, v5

    .line 138
    div-long/2addr p2, v3

    .line 139
    int-to-long v3, p0

    .line 140
    const/4 p0, 0x2

    .line 141
    new-array p0, p0, [J

    .line 142
    .line 143
    const/4 p4, 0x0

    .line 144
    aput-wide p2, p0, p4

    .line 145
    .line 146
    const/4 p2, 0x1

    .line 147
    aput-wide v3, p0, p2

    .line 148
    .line 149
    aget-wide v3, p0, p4

    .line 150
    .line 151
    aget-wide v5, p0, p2

    .line 152
    .line 153
    long-to-int p0, v5

    .line 154
    const-wide/32 v5, 0x7fffffff

    .line 155
    .line 156
    .line 157
    and-long/2addr v5, v3

    .line 158
    cmp-long p3, v5, v3

    .line 159
    .line 160
    if-nez p3, :cond_1

    .line 161
    .line 162
    long-to-int p3, v3

    .line 163
    invoke-static {p3}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;

    .line 164
    .line 165
    .line 166
    move-result-object p3

    .line 167
    goto :goto_3

    .line 168
    :cond_1
    invoke-static {v3, v4}, Ljava/lang/Long;->toString(J)Ljava/lang/String;

    .line 169
    .line 170
    .line 171
    move-result-object p3

    .line 172
    :goto_3
    invoke-virtual {p3}, Ljava/lang/String;->length()I

    .line 173
    .line 174
    .line 175
    move-result v1

    .line 176
    :goto_4
    if-ge v1, p0, :cond_2

    .line 177
    .line 178
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/Appendable;

    .line 179
    .line 180
    .line 181
    add-int/lit8 v0, v0, -0x1

    .line 182
    .line 183
    add-int/lit8 p0, p0, -0x1

    .line 184
    .line 185
    goto :goto_4

    .line 186
    :cond_2
    if-ge v0, p0, :cond_6

    .line 187
    .line 188
    :goto_5
    if-ge v0, p0, :cond_4

    .line 189
    .line 190
    if-le v1, p2, :cond_4

    .line 191
    .line 192
    add-int/lit8 v3, v1, -0x1

    .line 193
    .line 194
    invoke-virtual {p3, v3}, Ljava/lang/String;->charAt(I)C

    .line 195
    .line 196
    .line 197
    move-result v3

    .line 198
    if-eq v3, v2, :cond_3

    .line 199
    .line 200
    goto :goto_6

    .line 201
    :cond_3
    add-int/lit8 p0, p0, -0x1

    .line 202
    .line 203
    add-int/lit8 v1, v1, -0x1

    .line 204
    .line 205
    goto :goto_5

    .line 206
    :cond_4
    :goto_6
    invoke-virtual {p3}, Ljava/lang/String;->length()I

    .line 207
    .line 208
    .line 209
    move-result p0

    .line 210
    if-ge v1, p0, :cond_6

    .line 211
    .line 212
    :goto_7
    if-ge p4, v1, :cond_5

    .line 213
    .line 214
    invoke-virtual {p3, p4}, Ljava/lang/String;->charAt(I)C

    .line 215
    .line 216
    .line 217
    move-result p0

    .line 218
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/Appendable;

    .line 219
    .line 220
    .line 221
    add-int/lit8 p4, p4, 0x1

    .line 222
    .line 223
    goto :goto_7

    .line 224
    :cond_5
    return-void

    .line 225
    :cond_6
    invoke-virtual {p1, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 226
    .line 227
    .line 228
    return-void

    .line 229
    :cond_7
    add-int/lit8 p0, p0, -0x1

    .line 230
    .line 231
    goto/16 :goto_1

    .line 232
    .line 233
    :catch_0
    invoke-static {v0, p1}, Lvp/y1;->M(ILjava/lang/StringBuilder;)V

    .line 234
    .line 235
    .line 236
    return-void

    .line 237
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
