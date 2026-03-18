.class public abstract Llp/q0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static a:Lh71/n;

.field public static b:Lh71/t;


# direct methods
.method public static final a(Lqr0/l;Lij0/a;)Ljava/lang/String;
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [Ljava/lang/Object;

    .line 3
    .line 4
    check-cast p1, Ljj0/f;

    .line 5
    .line 6
    const v1, 0x7f120444

    .line 7
    .line 8
    .line 9
    invoke-virtual {p1, v1, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    invoke-static {p0}, Lkp/l6;->a(Lqr0/l;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    const-string v0, " "

    .line 18
    .line 19
    invoke-static {p1, v0, p0}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method

.method public static final b(Lrd0/j;ZLij0/a;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "stringResource"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    if-eqz p1, :cond_2

    .line 13
    .line 14
    iget-boolean p1, p0, Lrd0/j;->f:Z

    .line 15
    .line 16
    if-eqz p1, :cond_2

    .line 17
    .line 18
    iget-object p0, p0, Lrd0/j;->e:Lrd0/i;

    .line 19
    .line 20
    if-eqz p0, :cond_0

    .line 21
    .line 22
    iget-object p0, p0, Lrd0/i;->b:Lrd0/h;

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    move-object p0, v0

    .line 26
    :goto_0
    if-nez p0, :cond_1

    .line 27
    .line 28
    const/4 p0, -0x1

    .line 29
    goto :goto_1

    .line 30
    :cond_1
    sget-object p1, Ltz/o0;->c:[I

    .line 31
    .line 32
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    aget p0, p1, p0

    .line 37
    .line 38
    :goto_1
    packed-switch p0, :pswitch_data_0

    .line 39
    .line 40
    .line 41
    move-object p0, v0

    .line 42
    goto :goto_2

    .line 43
    :pswitch_0
    const p0, 0x7f120471

    .line 44
    .line 45
    .line 46
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    goto :goto_2

    .line 51
    :pswitch_1
    const p0, 0x7f120470

    .line 52
    .line 53
    .line 54
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    goto :goto_2

    .line 59
    :pswitch_2
    const p0, 0x7f120474

    .line 60
    .line 61
    .line 62
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    goto :goto_2

    .line 67
    :pswitch_3
    const p0, 0x7f120479

    .line 68
    .line 69
    .line 70
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    goto :goto_2

    .line 75
    :pswitch_4
    const p0, 0x7f120105

    .line 76
    .line 77
    .line 78
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    goto :goto_2

    .line 83
    :pswitch_5
    const p0, 0x7f12047e

    .line 84
    .line 85
    .line 86
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    goto :goto_2

    .line 91
    :pswitch_6
    const p0, 0x7f120473

    .line 92
    .line 93
    .line 94
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    :goto_2
    if-eqz p0, :cond_2

    .line 99
    .line 100
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 101
    .line 102
    .line 103
    move-result p0

    .line 104
    const/4 p1, 0x0

    .line 105
    new-array p1, p1, [Ljava/lang/Object;

    .line 106
    .line 107
    check-cast p2, Ljj0/f;

    .line 108
    .line 109
    invoke-virtual {p2, p0, p1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    return-object p0

    .line 114
    :cond_2
    return-object v0

    .line 115
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static final c(Lrd0/j;Lij0/a;Ljava/lang/Boolean;)Ljava/lang/String;
    .locals 4

    .line 1
    const-string v0, "stringResource"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    if-eqz p0, :cond_6

    .line 8
    .line 9
    invoke-static {p0}, Lkp/z;->e(Lrd0/j;)Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    const/4 v2, 0x0

    .line 14
    if-eqz v1, :cond_5

    .line 15
    .line 16
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 17
    .line 18
    invoke-static {p2, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result p2

    .line 22
    const v1, 0x7f120445

    .line 23
    .line 24
    .line 25
    if-eqz p2, :cond_0

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_0
    iget-object p0, p0, Lrd0/j;->d:Lrd0/a0;

    .line 29
    .line 30
    if-eqz p0, :cond_1

    .line 31
    .line 32
    iget-object p2, p0, Lrd0/a0;->b:Lrd0/z;

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_1
    move-object p2, v0

    .line 36
    :goto_0
    sget-object v3, Lrd0/z;->d:Lrd0/z;

    .line 37
    .line 38
    if-ne p2, v3, :cond_2

    .line 39
    .line 40
    const v1, 0x7f120f37

    .line 41
    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_2
    if-eqz p0, :cond_3

    .line 45
    .line 46
    iget-object v0, p0, Lrd0/a0;->b:Lrd0/z;

    .line 47
    .line 48
    :cond_3
    sget-object p0, Lrd0/z;->e:Lrd0/z;

    .line 49
    .line 50
    if-ne v0, p0, :cond_4

    .line 51
    .line 52
    const v1, 0x7f120f38

    .line 53
    .line 54
    .line 55
    :cond_4
    :goto_1
    new-array p0, v2, [Ljava/lang/Object;

    .line 56
    .line 57
    check-cast p1, Ljj0/f;

    .line 58
    .line 59
    invoke-virtual {p1, v1, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    return-object p0

    .line 64
    :cond_5
    invoke-static {p0}, Lkp/z;->f(Lrd0/j;)Z

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    if-eqz p0, :cond_6

    .line 69
    .line 70
    new-array p0, v2, [Ljava/lang/Object;

    .line 71
    .line 72
    check-cast p1, Ljj0/f;

    .line 73
    .line 74
    const p2, 0x7f120448

    .line 75
    .line 76
    .line 77
    invoke-virtual {p1, p2, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    return-object p0

    .line 82
    :cond_6
    return-object v0
.end method

.method public static final d(Lrd0/b0;Lij0/a;)Lsz/b;
    .locals 6

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lrd0/b0;->b:Lrd0/t;

    .line 7
    .line 8
    const-string v1, "stringResource"

    .line 9
    .line 10
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object v1, p0, Lrd0/b0;->a:Lrd0/j;

    .line 14
    .line 15
    iget-object v1, v1, Lrd0/j;->e:Lrd0/i;

    .line 16
    .line 17
    const/4 v2, 0x0

    .line 18
    if-eqz v1, :cond_a

    .line 19
    .line 20
    iget-object v1, v1, Lrd0/i;->b:Lrd0/h;

    .line 21
    .line 22
    if-eqz v1, :cond_a

    .line 23
    .line 24
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    const/4 v3, 0x1

    .line 29
    const-string v4, "%"

    .line 30
    .line 31
    if-eq v1, v3, :cond_7

    .line 32
    .line 33
    const/4 v3, 0x2

    .line 34
    if-eq v1, v3, :cond_7

    .line 35
    .line 36
    const/4 p1, 0x5

    .line 37
    const/16 v3, 0x14

    .line 38
    .line 39
    const/4 v5, 0x0

    .line 40
    if-eq v1, p1, :cond_4

    .line 41
    .line 42
    const/4 p1, 0x6

    .line 43
    if-eq v1, p1, :cond_1

    .line 44
    .line 45
    new-instance p1, Lsz/b;

    .line 46
    .line 47
    invoke-virtual {p0}, Lrd0/b0;->a()Lqr0/l;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    if-eqz p0, :cond_0

    .line 52
    .line 53
    iget p0, p0, Lqr0/l;->d:I

    .line 54
    .line 55
    invoke-static {p0, v4}, Lp3/m;->e(ILjava/lang/String;)Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    goto :goto_0

    .line 60
    :cond_0
    move-object p0, v2

    .line 61
    :goto_0
    invoke-direct {p1, p0, v2}, Lsz/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    return-object p1

    .line 65
    :cond_1
    new-instance p1, Lsz/b;

    .line 66
    .line 67
    if-eqz v0, :cond_2

    .line 68
    .line 69
    invoke-virtual {v0}, Lrd0/t;->a()Lrd0/r;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    if-eqz v0, :cond_2

    .line 74
    .line 75
    iget-object v0, v0, Lrd0/r;->f:Lrd0/s;

    .line 76
    .line 77
    iget-object v0, v0, Lrd0/s;->a:Lqr0/l;

    .line 78
    .line 79
    if-eqz v0, :cond_2

    .line 80
    .line 81
    iget v5, v0, Lqr0/l;->d:I

    .line 82
    .line 83
    :cond_2
    invoke-virtual {p0}, Lrd0/b0;->a()Lqr0/l;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    if-eqz p0, :cond_3

    .line 88
    .line 89
    iget p0, p0, Lqr0/l;->d:I

    .line 90
    .line 91
    goto :goto_1

    .line 92
    :cond_3
    const/16 p0, 0x64

    .line 93
    .line 94
    :goto_1
    invoke-static {v3, v5}, Ljava/lang/Math;->max(II)I

    .line 95
    .line 96
    .line 97
    move-result v0

    .line 98
    const/16 v1, 0x50

    .line 99
    .line 100
    invoke-static {v1, p0}, Ljava/lang/Math;->min(II)I

    .line 101
    .line 102
    .line 103
    move-result p0

    .line 104
    new-instance v1, Ljava/lang/StringBuilder;

    .line 105
    .line 106
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 107
    .line 108
    .line 109
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 110
    .line 111
    .line 112
    const-string v0, " - "

    .line 113
    .line 114
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 115
    .line 116
    .line 117
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 118
    .line 119
    .line 120
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 121
    .line 122
    .line 123
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    invoke-direct {p1, p0, v2}, Lsz/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    return-object p1

    .line 131
    :cond_4
    new-instance p0, Lsz/b;

    .line 132
    .line 133
    if-eqz v0, :cond_5

    .line 134
    .line 135
    invoke-virtual {v0}, Lrd0/t;->a()Lrd0/r;

    .line 136
    .line 137
    .line 138
    move-result-object p1

    .line 139
    if-eqz p1, :cond_5

    .line 140
    .line 141
    iget-object p1, p1, Lrd0/r;->f:Lrd0/s;

    .line 142
    .line 143
    iget-object p1, p1, Lrd0/s;->a:Lqr0/l;

    .line 144
    .line 145
    if-eqz p1, :cond_5

    .line 146
    .line 147
    iget v5, p1, Lqr0/l;->d:I

    .line 148
    .line 149
    :cond_5
    if-ge v5, v3, :cond_6

    .line 150
    .line 151
    goto :goto_2

    .line 152
    :cond_6
    move v3, v5

    .line 153
    :goto_2
    invoke-static {v3, v4}, Lp3/m;->e(ILjava/lang/String;)Ljava/lang/String;

    .line 154
    .line 155
    .line 156
    move-result-object p1

    .line 157
    invoke-direct {p0, p1, v2}, Lsz/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    return-object p0

    .line 161
    :cond_7
    new-instance v1, Lsz/b;

    .line 162
    .line 163
    invoke-virtual {p0}, Lrd0/b0;->a()Lqr0/l;

    .line 164
    .line 165
    .line 166
    move-result-object p0

    .line 167
    if-eqz p0, :cond_8

    .line 168
    .line 169
    iget p0, p0, Lqr0/l;->d:I

    .line 170
    .line 171
    invoke-static {p0, v4}, Lp3/m;->e(ILjava/lang/String;)Ljava/lang/String;

    .line 172
    .line 173
    .line 174
    move-result-object p0

    .line 175
    goto :goto_3

    .line 176
    :cond_8
    move-object p0, v2

    .line 177
    :goto_3
    if-eqz v0, :cond_9

    .line 178
    .line 179
    iget-object v0, v0, Lrd0/t;->b:Ljava/time/LocalTime;

    .line 180
    .line 181
    if-eqz v0, :cond_9

    .line 182
    .line 183
    invoke-static {v0}, Lua0/g;->b(Ljava/time/LocalTime;)Ljava/lang/String;

    .line 184
    .line 185
    .line 186
    move-result-object v0

    .line 187
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object v0

    .line 191
    check-cast p1, Ljj0/f;

    .line 192
    .line 193
    const v2, 0x7f120f80

    .line 194
    .line 195
    .line 196
    invoke-virtual {p1, v2, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 197
    .line 198
    .line 199
    move-result-object v2

    .line 200
    :cond_9
    invoke-direct {v1, p0, v2}, Lsz/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    return-object v1

    .line 204
    :cond_a
    return-object v2
.end method

.method public static e(Ll2/o;)Lh71/l;
    .locals 1

    .line 1
    sget-object v0, Lh71/m;->a:Ll2/u2;

    .line 2
    .line 3
    check-cast p0, Ll2/t;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lh71/l;

    .line 10
    .line 11
    return-object p0
.end method

.method public static f(Ll2/o;)Lh71/t;
    .locals 1

    .line 1
    sget-object v0, Lh71/u;->a:Ll2/u2;

    .line 2
    .line 3
    check-cast p0, Ll2/t;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lh71/t;

    .line 10
    .line 11
    return-object p0
.end method

.method public static final g(Lrd0/j;Z)Z
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    if-eqz p1, :cond_1

    .line 7
    .line 8
    sget-object p1, Lrd0/h;->j:Lrd0/h;

    .line 9
    .line 10
    sget-object v0, Lrd0/h;->i:Lrd0/h;

    .line 11
    .line 12
    sget-object v1, Lrd0/h;->h:Lrd0/h;

    .line 13
    .line 14
    filled-new-array {p1, v0, v1}, [Lrd0/h;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    invoke-static {p1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    check-cast p1, Ljava/lang/Iterable;

    .line 23
    .line 24
    iget-object p0, p0, Lrd0/j;->e:Lrd0/i;

    .line 25
    .line 26
    if-eqz p0, :cond_0

    .line 27
    .line 28
    iget-object p0, p0, Lrd0/i;->b:Lrd0/h;

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 p0, 0x0

    .line 32
    :goto_0
    invoke-static {p1, p0}, Lmx0/q;->A(Ljava/lang/Iterable;Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    if-eqz p0, :cond_1

    .line 37
    .line 38
    const/4 p0, 0x1

    .line 39
    return p0

    .line 40
    :cond_1
    const/4 p0, 0x0

    .line 41
    return p0
.end method
