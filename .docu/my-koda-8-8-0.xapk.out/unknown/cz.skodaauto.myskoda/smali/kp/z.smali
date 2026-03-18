.class public abstract Lkp/z;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a([F)I
    .locals 6

    .line 1
    array-length v0, p0

    .line 2
    const/16 v1, 0x10

    .line 3
    .line 4
    const/4 v2, 0x0

    .line 5
    if-ge v0, v1, :cond_0

    .line 6
    .line 7
    return v2

    .line 8
    :cond_0
    aget v0, p0, v2

    .line 9
    .line 10
    const/high16 v1, 0x3f800000    # 1.0f

    .line 11
    .line 12
    cmpg-float v0, v0, v1

    .line 13
    .line 14
    const/4 v3, 0x1

    .line 15
    const/4 v4, 0x0

    .line 16
    if-nez v0, :cond_1

    .line 17
    .line 18
    aget v0, p0, v3

    .line 19
    .line 20
    cmpg-float v0, v0, v4

    .line 21
    .line 22
    if-nez v0, :cond_1

    .line 23
    .line 24
    const/4 v0, 0x2

    .line 25
    aget v0, p0, v0

    .line 26
    .line 27
    cmpg-float v0, v0, v4

    .line 28
    .line 29
    if-nez v0, :cond_1

    .line 30
    .line 31
    const/4 v0, 0x4

    .line 32
    aget v0, p0, v0

    .line 33
    .line 34
    cmpg-float v0, v0, v4

    .line 35
    .line 36
    if-nez v0, :cond_1

    .line 37
    .line 38
    const/4 v0, 0x5

    .line 39
    aget v0, p0, v0

    .line 40
    .line 41
    cmpg-float v0, v0, v1

    .line 42
    .line 43
    if-nez v0, :cond_1

    .line 44
    .line 45
    const/4 v0, 0x6

    .line 46
    aget v0, p0, v0

    .line 47
    .line 48
    cmpg-float v0, v0, v4

    .line 49
    .line 50
    if-nez v0, :cond_1

    .line 51
    .line 52
    const/16 v0, 0x8

    .line 53
    .line 54
    aget v0, p0, v0

    .line 55
    .line 56
    cmpg-float v0, v0, v4

    .line 57
    .line 58
    if-nez v0, :cond_1

    .line 59
    .line 60
    const/16 v0, 0x9

    .line 61
    .line 62
    aget v0, p0, v0

    .line 63
    .line 64
    cmpg-float v0, v0, v4

    .line 65
    .line 66
    if-nez v0, :cond_1

    .line 67
    .line 68
    const/16 v0, 0xa

    .line 69
    .line 70
    aget v0, p0, v0

    .line 71
    .line 72
    cmpg-float v0, v0, v1

    .line 73
    .line 74
    if-nez v0, :cond_1

    .line 75
    .line 76
    move v0, v3

    .line 77
    goto :goto_0

    .line 78
    :cond_1
    move v0, v2

    .line 79
    :goto_0
    const/16 v5, 0xc

    .line 80
    .line 81
    aget v5, p0, v5

    .line 82
    .line 83
    cmpg-float v5, v5, v4

    .line 84
    .line 85
    if-nez v5, :cond_2

    .line 86
    .line 87
    const/16 v5, 0xd

    .line 88
    .line 89
    aget v5, p0, v5

    .line 90
    .line 91
    cmpg-float v5, v5, v4

    .line 92
    .line 93
    if-nez v5, :cond_2

    .line 94
    .line 95
    const/16 v5, 0xe

    .line 96
    .line 97
    aget v5, p0, v5

    .line 98
    .line 99
    cmpg-float v4, v5, v4

    .line 100
    .line 101
    if-nez v4, :cond_2

    .line 102
    .line 103
    const/16 v4, 0xf

    .line 104
    .line 105
    aget p0, p0, v4

    .line 106
    .line 107
    cmpg-float p0, p0, v1

    .line 108
    .line 109
    if-nez p0, :cond_2

    .line 110
    .line 111
    move v2, v3

    .line 112
    :cond_2
    shl-int/lit8 p0, v0, 0x1

    .line 113
    .line 114
    or-int/2addr p0, v2

    .line 115
    return p0
.end method

.method public static final b(J)Z
    .locals 2

    .line 1
    const-wide v0, 0x7fffffff7fffffffL

    .line 2
    .line 3
    .line 4
    .line 5
    .line 6
    invoke-static {p0, p1, v0, v1}, Lt4/j;->b(JJ)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    xor-int/lit8 p0, p0, 0x1

    .line 11
    .line 12
    return p0
.end method

.method public static final c(Lrd0/j;)Lrd0/x;
    .locals 7

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lrd0/j;->d:Lrd0/a0;

    .line 7
    .line 8
    iget-object v1, p0, Lrd0/j;->g:Ljava/util/List;

    .line 9
    .line 10
    check-cast v1, Ljava/lang/Iterable;

    .line 11
    .line 12
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    :cond_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    const/4 v4, 0x0

    .line 21
    if-eqz v3, :cond_1

    .line 22
    .line 23
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    move-object v5, v3

    .line 28
    check-cast v5, Ltc0/a;

    .line 29
    .line 30
    iget-object v5, v5, Ltc0/a;->a:Ltc0/b;

    .line 31
    .line 32
    sget-object v6, Lrd0/k;->f:Lrd0/k;

    .line 33
    .line 34
    if-ne v5, v6, :cond_0

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_1
    move-object v3, v4

    .line 38
    :goto_0
    if-eqz v3, :cond_2

    .line 39
    .line 40
    sget-object p0, Lrd0/x;->d:Lrd0/x;

    .line 41
    .line 42
    return-object p0

    .line 43
    :cond_2
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    :cond_3
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 48
    .line 49
    .line 50
    move-result v3

    .line 51
    if-eqz v3, :cond_4

    .line 52
    .line 53
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v3

    .line 57
    move-object v5, v3

    .line 58
    check-cast v5, Ltc0/a;

    .line 59
    .line 60
    iget-object v5, v5, Ltc0/a;->a:Ltc0/b;

    .line 61
    .line 62
    sget-object v6, Lrd0/k;->e:Lrd0/k;

    .line 63
    .line 64
    if-ne v5, v6, :cond_3

    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_4
    move-object v3, v4

    .line 68
    :goto_1
    if-eqz v3, :cond_5

    .line 69
    .line 70
    sget-object p0, Lrd0/x;->e:Lrd0/x;

    .line 71
    .line 72
    return-object p0

    .line 73
    :cond_5
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    :cond_6
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 78
    .line 79
    .line 80
    move-result v3

    .line 81
    if-eqz v3, :cond_7

    .line 82
    .line 83
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v3

    .line 87
    move-object v5, v3

    .line 88
    check-cast v5, Ltc0/a;

    .line 89
    .line 90
    iget-object v5, v5, Ltc0/a;->a:Ltc0/b;

    .line 91
    .line 92
    sget-object v6, Lrd0/k;->g:Lrd0/k;

    .line 93
    .line 94
    if-ne v5, v6, :cond_6

    .line 95
    .line 96
    goto :goto_2

    .line 97
    :cond_7
    move-object v3, v4

    .line 98
    :goto_2
    if-eqz v3, :cond_8

    .line 99
    .line 100
    sget-object p0, Lrd0/x;->f:Lrd0/x;

    .line 101
    .line 102
    return-object p0

    .line 103
    :cond_8
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 104
    .line 105
    .line 106
    move-result-object v1

    .line 107
    :cond_9
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 108
    .line 109
    .line 110
    move-result v2

    .line 111
    if-eqz v2, :cond_a

    .line 112
    .line 113
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v2

    .line 117
    move-object v3, v2

    .line 118
    check-cast v3, Ltc0/a;

    .line 119
    .line 120
    iget-object v3, v3, Ltc0/a;->a:Ltc0/b;

    .line 121
    .line 122
    sget-object v5, Lrd0/k;->d:Lrd0/k;

    .line 123
    .line 124
    if-ne v3, v5, :cond_9

    .line 125
    .line 126
    goto :goto_3

    .line 127
    :cond_a
    move-object v2, v4

    .line 128
    :goto_3
    if-eqz v2, :cond_b

    .line 129
    .line 130
    sget-object p0, Lrd0/x;->g:Lrd0/x;

    .line 131
    .line 132
    return-object p0

    .line 133
    :cond_b
    if-eqz v0, :cond_c

    .line 134
    .line 135
    iget-object v1, v0, Lrd0/a0;->a:Lrd0/y;

    .line 136
    .line 137
    goto :goto_4

    .line 138
    :cond_c
    move-object v1, v4

    .line 139
    :goto_4
    sget-object v2, Lrd0/y;->d:Lrd0/y;

    .line 140
    .line 141
    if-ne v1, v2, :cond_d

    .line 142
    .line 143
    sget-object p0, Lrd0/x;->h:Lrd0/x;

    .line 144
    .line 145
    return-object p0

    .line 146
    :cond_d
    invoke-static {p0}, Lkp/z;->e(Lrd0/j;)Z

    .line 147
    .line 148
    .line 149
    move-result v1

    .line 150
    if-eqz v1, :cond_e

    .line 151
    .line 152
    sget-object p0, Lrd0/x;->i:Lrd0/x;

    .line 153
    .line 154
    return-object p0

    .line 155
    :cond_e
    invoke-static {p0}, Lkp/z;->f(Lrd0/j;)Z

    .line 156
    .line 157
    .line 158
    move-result p0

    .line 159
    if-eqz p0, :cond_f

    .line 160
    .line 161
    sget-object p0, Lrd0/x;->l:Lrd0/x;

    .line 162
    .line 163
    return-object p0

    .line 164
    :cond_f
    if-eqz v0, :cond_10

    .line 165
    .line 166
    iget-object p0, v0, Lrd0/a0;->a:Lrd0/y;

    .line 167
    .line 168
    goto :goto_5

    .line 169
    :cond_10
    move-object p0, v4

    .line 170
    :goto_5
    sget-object v1, Lrd0/y;->g:Lrd0/y;

    .line 171
    .line 172
    if-ne p0, v1, :cond_11

    .line 173
    .line 174
    sget-object p0, Lrd0/x;->j:Lrd0/x;

    .line 175
    .line 176
    return-object p0

    .line 177
    :cond_11
    if-eqz v0, :cond_12

    .line 178
    .line 179
    iget-object p0, v0, Lrd0/a0;->a:Lrd0/y;

    .line 180
    .line 181
    goto :goto_6

    .line 182
    :cond_12
    move-object p0, v4

    .line 183
    :goto_6
    sget-object v0, Lrd0/y;->h:Lrd0/y;

    .line 184
    .line 185
    if-ne p0, v0, :cond_13

    .line 186
    .line 187
    sget-object p0, Lrd0/x;->k:Lrd0/x;

    .line 188
    .line 189
    return-object p0

    .line 190
    :cond_13
    return-object v4
.end method

.method public static final d(Lrd0/j;)Z
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lrd0/j;->g:Ljava/util/List;

    .line 7
    .line 8
    check-cast p0, Ljava/lang/Iterable;

    .line 9
    .line 10
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_1

    .line 19
    .line 20
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    move-object v1, v0

    .line 25
    check-cast v1, Ltc0/a;

    .line 26
    .line 27
    iget-object v1, v1, Ltc0/a;->a:Ltc0/b;

    .line 28
    .line 29
    sget-object v2, Lrd0/k;->i:Lrd0/k;

    .line 30
    .line 31
    if-ne v1, v2, :cond_0

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_1
    const/4 v0, 0x0

    .line 35
    :goto_0
    if-eqz v0, :cond_2

    .line 36
    .line 37
    const/4 p0, 0x1

    .line 38
    return p0

    .line 39
    :cond_2
    const/4 p0, 0x0

    .line 40
    return p0
.end method

.method public static final e(Lrd0/j;)Z
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lrd0/j;->d:Lrd0/a0;

    .line 7
    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    iget-object p0, p0, Lrd0/a0;->a:Lrd0/y;

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    :goto_0
    sget-object v0, Lrd0/y;->e:Lrd0/y;

    .line 15
    .line 16
    if-ne p0, v0, :cond_1

    .line 17
    .line 18
    const/4 p0, 0x1

    .line 19
    return p0

    .line 20
    :cond_1
    const/4 p0, 0x0

    .line 21
    return p0
.end method

.method public static final f(Lrd0/j;)Z
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lrd0/j;->d:Lrd0/a0;

    .line 7
    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    iget-object p0, p0, Lrd0/a0;->a:Lrd0/y;

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    :goto_0
    sget-object v0, Lrd0/y;->f:Lrd0/y;

    .line 15
    .line 16
    if-ne p0, v0, :cond_1

    .line 17
    .line 18
    const/4 p0, 0x1

    .line 19
    return p0

    .line 20
    :cond_1
    const/4 p0, 0x0

    .line 21
    return p0
.end method
