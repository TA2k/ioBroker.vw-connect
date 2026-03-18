.class public abstract Lkp/t9;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lra0/c;)I
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    packed-switch p0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    new-instance p0, La8/r0;

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 16
    .line 17
    .line 18
    throw p0

    .line 19
    :pswitch_0
    const p0, 0x7f1204ae

    .line 20
    .line 21
    .line 22
    return p0

    .line 23
    :pswitch_1
    const p0, 0x7f1204af

    .line 24
    .line 25
    .line 26
    return p0

    .line 27
    :pswitch_2
    const p0, 0x7f1204b4

    .line 28
    .line 29
    .line 30
    return p0

    .line 31
    :pswitch_3
    const p0, 0x7f1204b0

    .line 32
    .line 33
    .line 34
    return p0

    .line 35
    :pswitch_4
    const p0, 0x7f1204b2

    .line 36
    .line 37
    .line 38
    return p0

    .line 39
    :pswitch_5
    const p0, 0x7f1204b1

    .line 40
    .line 41
    .line 42
    return p0

    .line 43
    :pswitch_6
    const p0, 0x7f120483

    .line 44
    .line 45
    .line 46
    return p0

    .line 47
    :pswitch_7
    const p0, 0x7f120485

    .line 48
    .line 49
    .line 50
    return p0

    .line 51
    :pswitch_8
    const p0, 0x7f120484

    .line 52
    .line 53
    .line 54
    return p0

    .line 55
    :pswitch_data_0
    .packed-switch 0x0
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

.method public static final b(Lra0/c;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    packed-switch p0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    new-instance p0, La8/r0;

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 16
    .line 17
    .line 18
    throw p0

    .line 19
    :pswitch_0
    const-string p0, "update_failed"

    .line 20
    .line 21
    return-object p0

    .line 22
    :pswitch_1
    const-string p0, "update_in_progress"

    .line 23
    .line 24
    return-object p0

    .line 25
    :pswitch_2
    const-string p0, "no_connection"

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_3
    const-string p0, "ignition_on"

    .line 29
    .line 30
    return-object p0

    .line 31
    :pswitch_4
    const-string p0, "in_motion"

    .line 32
    .line 33
    return-object p0

    .line 34
    :pswitch_5
    const-string p0, ""

    .line 35
    .line 36
    return-object p0

    .line 37
    :pswitch_6
    const-string p0, "asleep"

    .line 38
    .line 39
    return-object p0

    .line 40
    :pswitch_7
    const-string p0, "waking_up"

    .line 41
    .line 42
    return-object p0

    .line 43
    :pswitch_8
    const-string p0, "awake"

    .line 44
    .line 45
    return-object p0

    .line 46
    nop

    .line 47
    :pswitch_data_0
    .packed-switch 0x0
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

.method public static final c(Lra0/c;Ll2/o;)Lta0/d;
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    const/4 v0, 0x0

    .line 11
    packed-switch p0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    const p0, 0x1dec9034

    .line 15
    .line 16
    .line 17
    check-cast p1, Ll2/t;

    .line 18
    .line 19
    invoke-static {p0, p1, v0}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    throw p0

    .line 24
    :pswitch_0
    check-cast p1, Ll2/t;

    .line 25
    .line 26
    const p0, 0x1decebc6

    .line 27
    .line 28
    .line 29
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 30
    .line 31
    .line 32
    new-instance p0, Lta0/b;

    .line 33
    .line 34
    sget-object v1, Lj91/h;->a:Ll2/u2;

    .line 35
    .line 36
    invoke-virtual {p1, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    check-cast v1, Lj91/e;

    .line 41
    .line 42
    invoke-virtual {v1}, Lj91/e;->a()J

    .line 43
    .line 44
    .line 45
    move-result-wide v1

    .line 46
    const v3, 0x7f080519

    .line 47
    .line 48
    .line 49
    invoke-direct {p0, v3, v1, v2}, Lta0/b;-><init>(IJ)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 53
    .line 54
    .line 55
    return-object p0

    .line 56
    :pswitch_1
    check-cast p1, Ll2/t;

    .line 57
    .line 58
    const p0, 0x1decd2ec

    .line 59
    .line 60
    .line 61
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 62
    .line 63
    .line 64
    new-instance p0, Lta0/b;

    .line 65
    .line 66
    sget-object v1, Lj91/h;->a:Ll2/u2;

    .line 67
    .line 68
    invoke-virtual {p1, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    check-cast v1, Lj91/e;

    .line 73
    .line 74
    invoke-virtual {v1}, Lj91/e;->j()J

    .line 75
    .line 76
    .line 77
    move-result-wide v1

    .line 78
    const v3, 0x7f080360

    .line 79
    .line 80
    .line 81
    invoke-direct {p0, v3, v1, v2}, Lta0/b;-><init>(IJ)V

    .line 82
    .line 83
    .line 84
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 85
    .line 86
    .line 87
    return-object p0

    .line 88
    :pswitch_2
    check-cast p1, Ll2/t;

    .line 89
    .line 90
    const p0, 0x1decc779

    .line 91
    .line 92
    .line 93
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 97
    .line 98
    .line 99
    sget-object p0, Li91/k1;->g:Li91/k1;

    .line 100
    .line 101
    new-instance p1, Lta0/c;

    .line 102
    .line 103
    invoke-direct {p1, p0}, Lta0/c;-><init>(Li91/k1;)V

    .line 104
    .line 105
    .line 106
    return-object p1

    .line 107
    :pswitch_3
    check-cast p1, Ll2/t;

    .line 108
    .line 109
    const p0, 0x1ded0338

    .line 110
    .line 111
    .line 112
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 113
    .line 114
    .line 115
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 116
    .line 117
    .line 118
    sget-object p0, Li91/k1;->e:Li91/k1;

    .line 119
    .line 120
    new-instance p1, Lta0/c;

    .line 121
    .line 122
    invoke-direct {p1, p0}, Lta0/c;-><init>(Li91/k1;)V

    .line 123
    .line 124
    .line 125
    return-object p1

    .line 126
    :pswitch_4
    check-cast p1, Ll2/t;

    .line 127
    .line 128
    const p0, 0x1decbd18

    .line 129
    .line 130
    .line 131
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 132
    .line 133
    .line 134
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 135
    .line 136
    .line 137
    sget-object p0, Li91/k1;->e:Li91/k1;

    .line 138
    .line 139
    new-instance p1, Lta0/c;

    .line 140
    .line 141
    invoke-direct {p1, p0}, Lta0/c;-><init>(Li91/k1;)V

    .line 142
    .line 143
    .line 144
    return-object p1

    .line 145
    :pswitch_5
    check-cast p1, Ll2/t;

    .line 146
    .line 147
    const p0, 0x1decb319

    .line 148
    .line 149
    .line 150
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 151
    .line 152
    .line 153
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 154
    .line 155
    .line 156
    sget-object p0, Li91/k1;->g:Li91/k1;

    .line 157
    .line 158
    new-instance p1, Lta0/c;

    .line 159
    .line 160
    invoke-direct {p1, p0}, Lta0/c;-><init>(Li91/k1;)V

    .line 161
    .line 162
    .line 163
    return-object p1

    .line 164
    :pswitch_6
    check-cast p1, Ll2/t;

    .line 165
    .line 166
    const p0, 0x1dec9d7b

    .line 167
    .line 168
    .line 169
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 170
    .line 171
    .line 172
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 173
    .line 174
    .line 175
    sget-object p0, Li91/k1;->h:Li91/k1;

    .line 176
    .line 177
    new-instance p1, Lta0/c;

    .line 178
    .line 179
    invoke-direct {p1, p0}, Lta0/c;-><init>(Li91/k1;)V

    .line 180
    .line 181
    .line 182
    return-object p1

    .line 183
    :pswitch_7
    check-cast p1, Ll2/t;

    .line 184
    .line 185
    const p0, 0x1deca7bb

    .line 186
    .line 187
    .line 188
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 189
    .line 190
    .line 191
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 192
    .line 193
    .line 194
    sget-object p0, Li91/k1;->f:Li91/k1;

    .line 195
    .line 196
    new-instance p1, Lta0/c;

    .line 197
    .line 198
    invoke-direct {p1, p0}, Lta0/c;-><init>(Li91/k1;)V

    .line 199
    .line 200
    .line 201
    return-object p1

    .line 202
    :pswitch_8
    check-cast p1, Ll2/t;

    .line 203
    .line 204
    const p0, 0x1dec935c

    .line 205
    .line 206
    .line 207
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 208
    .line 209
    .line 210
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 211
    .line 212
    .line 213
    sget-object p0, Li91/k1;->d:Li91/k1;

    .line 214
    .line 215
    new-instance p1, Lta0/c;

    .line 216
    .line 217
    invoke-direct {p1, p0}, Lta0/c;-><init>(Li91/k1;)V

    .line 218
    .line 219
    .line 220
    return-object p1

    .line 221
    :pswitch_data_0
    .packed-switch 0x0
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

.method public static final d(Lmy0/f;)Lgz0/p;
    .locals 5

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lgz0/p;->Companion:Lgz0/o;

    .line 7
    .line 8
    iget-wide v1, p0, Lmy0/f;->d:J

    .line 9
    .line 10
    iget p0, p0, Lmy0/f;->e:I

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    int-to-long v3, p0

    .line 16
    :try_start_0
    new-instance p0, Lgz0/p;

    .line 17
    .line 18
    invoke-static {v1, v2, v3, v4}, Ljava/time/Instant;->ofEpochSecond(JJ)Ljava/time/Instant;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    const-string v3, "ofEpochSecond(...)"

    .line 23
    .line 24
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-direct {p0, v0}, Lgz0/p;-><init>(Ljava/time/Instant;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 28
    .line 29
    .line 30
    return-object p0

    .line 31
    :catch_0
    move-exception p0

    .line 32
    instance-of v0, p0, Ljava/lang/ArithmeticException;

    .line 33
    .line 34
    if-nez v0, :cond_1

    .line 35
    .line 36
    instance-of v0, p0, Ljava/time/DateTimeException;

    .line 37
    .line 38
    if-eqz v0, :cond_0

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    throw p0

    .line 42
    :cond_1
    :goto_0
    const-wide/16 v3, 0x0

    .line 43
    .line 44
    cmp-long p0, v1, v3

    .line 45
    .line 46
    if-lez p0, :cond_2

    .line 47
    .line 48
    sget-object p0, Lgz0/p;->f:Lgz0/p;

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_2
    sget-object p0, Lgz0/p;->e:Lgz0/p;

    .line 52
    .line 53
    :goto_1
    return-object p0
.end method

.method public static final e(Lgz0/p;)Lmy0/f;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lmy0/f;->f:Lmy0/f;

    .line 7
    .line 8
    iget-object p0, p0, Lgz0/p;->d:Ljava/time/Instant;

    .line 9
    .line 10
    invoke-virtual {p0}, Ljava/time/Instant;->getEpochSecond()J

    .line 11
    .line 12
    .line 13
    move-result-wide v0

    .line 14
    invoke-virtual {p0}, Ljava/time/Instant;->getNano()I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    invoke-static {p0, v0, v1}, Lmy0/h;->i(IJ)Lmy0/f;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method
