.class public abstract Lcp0/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lv3/m;Lay0/a;Lrx0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    move-object v0, p0

    .line 2
    check-cast v0, Lx2/r;

    .line 3
    .line 4
    iget-object v1, v0, Lx2/r;->d:Lx2/r;

    .line 5
    .line 6
    iget-boolean v1, v1, Lx2/r;->q:Z

    .line 7
    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    goto/16 :goto_6

    .line 11
    .line 12
    :cond_0
    if-nez v1, :cond_1

    .line 13
    .line 14
    const-string v1, "visitAncestors called on an unattached node"

    .line 15
    .line 16
    invoke-static {v1}, Ls3/a;->b(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    :cond_1
    iget-object v0, v0, Lx2/r;->d:Lx2/r;

    .line 20
    .line 21
    iget-object v0, v0, Lx2/r;->h:Lx2/r;

    .line 22
    .line 23
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    :goto_0
    const/4 v2, 0x0

    .line 28
    if-eqz v1, :cond_c

    .line 29
    .line 30
    iget-object v3, v1, Lv3/h0;->H:Lg1/q;

    .line 31
    .line 32
    iget-object v3, v3, Lg1/q;->g:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v3, Lx2/r;

    .line 35
    .line 36
    iget v3, v3, Lx2/r;->g:I

    .line 37
    .line 38
    const/high16 v4, 0x80000

    .line 39
    .line 40
    and-int/2addr v3, v4

    .line 41
    if-eqz v3, :cond_a

    .line 42
    .line 43
    :goto_1
    if-eqz v0, :cond_a

    .line 44
    .line 45
    iget v3, v0, Lx2/r;->f:I

    .line 46
    .line 47
    and-int/2addr v3, v4

    .line 48
    if-eqz v3, :cond_9

    .line 49
    .line 50
    move-object v3, v0

    .line 51
    move-object v5, v2

    .line 52
    :goto_2
    if-eqz v3, :cond_9

    .line 53
    .line 54
    instance-of v6, v3, La4/a;

    .line 55
    .line 56
    if-eqz v6, :cond_2

    .line 57
    .line 58
    move-object v2, v3

    .line 59
    goto :goto_5

    .line 60
    :cond_2
    iget v6, v3, Lx2/r;->f:I

    .line 61
    .line 62
    and-int/2addr v6, v4

    .line 63
    if-eqz v6, :cond_8

    .line 64
    .line 65
    instance-of v6, v3, Lv3/n;

    .line 66
    .line 67
    if-eqz v6, :cond_8

    .line 68
    .line 69
    move-object v6, v3

    .line 70
    check-cast v6, Lv3/n;

    .line 71
    .line 72
    iget-object v6, v6, Lv3/n;->s:Lx2/r;

    .line 73
    .line 74
    const/4 v7, 0x0

    .line 75
    :goto_3
    const/4 v8, 0x1

    .line 76
    if-eqz v6, :cond_7

    .line 77
    .line 78
    iget v9, v6, Lx2/r;->f:I

    .line 79
    .line 80
    and-int/2addr v9, v4

    .line 81
    if-eqz v9, :cond_6

    .line 82
    .line 83
    add-int/lit8 v7, v7, 0x1

    .line 84
    .line 85
    if-ne v7, v8, :cond_3

    .line 86
    .line 87
    move-object v3, v6

    .line 88
    goto :goto_4

    .line 89
    :cond_3
    if-nez v5, :cond_4

    .line 90
    .line 91
    new-instance v5, Ln2/b;

    .line 92
    .line 93
    const/16 v8, 0x10

    .line 94
    .line 95
    new-array v8, v8, [Lx2/r;

    .line 96
    .line 97
    invoke-direct {v5, v8}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    :cond_4
    if-eqz v3, :cond_5

    .line 101
    .line 102
    invoke-virtual {v5, v3}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    move-object v3, v2

    .line 106
    :cond_5
    invoke-virtual {v5, v6}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    :cond_6
    :goto_4
    iget-object v6, v6, Lx2/r;->i:Lx2/r;

    .line 110
    .line 111
    goto :goto_3

    .line 112
    :cond_7
    if-ne v7, v8, :cond_8

    .line 113
    .line 114
    goto :goto_2

    .line 115
    :cond_8
    invoke-static {v5}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 116
    .line 117
    .line 118
    move-result-object v3

    .line 119
    goto :goto_2

    .line 120
    :cond_9
    iget-object v0, v0, Lx2/r;->h:Lx2/r;

    .line 121
    .line 122
    goto :goto_1

    .line 123
    :cond_a
    invoke-virtual {v1}, Lv3/h0;->v()Lv3/h0;

    .line 124
    .line 125
    .line 126
    move-result-object v1

    .line 127
    if-eqz v1, :cond_b

    .line 128
    .line 129
    iget-object v0, v1, Lv3/h0;->H:Lg1/q;

    .line 130
    .line 131
    if-eqz v0, :cond_b

    .line 132
    .line 133
    iget-object v0, v0, Lg1/q;->f:Ljava/lang/Object;

    .line 134
    .line 135
    check-cast v0, Lv3/z1;

    .line 136
    .line 137
    goto :goto_0

    .line 138
    :cond_b
    move-object v0, v2

    .line 139
    goto :goto_0

    .line 140
    :cond_c
    :goto_5
    check-cast v2, La4/a;

    .line 141
    .line 142
    if-nez v2, :cond_d

    .line 143
    .line 144
    goto :goto_6

    .line 145
    :cond_d
    invoke-static {p0}, Lv3/f;->w(Lv3/m;)Lv3/f1;

    .line 146
    .line 147
    .line 148
    move-result-object p0

    .line 149
    new-instance v0, La4/b;

    .line 150
    .line 151
    const/4 v1, 0x0

    .line 152
    invoke-direct {v0, v1, p1, p0}, La4/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 153
    .line 154
    .line 155
    invoke-interface {v2, p0, v0, p2}, La4/a;->L(Lv3/f1;La4/b;Lrx0/c;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object p0

    .line 159
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 160
    .line 161
    if-ne p0, p1, :cond_e

    .line 162
    .line 163
    return-object p0

    .line 164
    :cond_e
    :goto_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 165
    .line 166
    return-object p0
.end method

.method public static final b(Ll2/o;)Ll2/b1;
    .locals 2

    .line 1
    sget-object v0, Lk1/r1;->v:Ljava/util/WeakHashMap;

    .line 2
    .line 3
    invoke-static {p0}, Lk1/c;->e(Ll2/o;)Lk1/r1;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object v0, v0, Lk1/r1;->c:Lk1/b;

    .line 8
    .line 9
    sget-object v1, Lw3/h1;->h:Ll2/u2;

    .line 10
    .line 11
    check-cast p0, Ll2/t;

    .line 12
    .line 13
    invoke-virtual {p0, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    check-cast v1, Lt4/c;

    .line 18
    .line 19
    invoke-virtual {v0}, Lk1/b;->e()Ls5/b;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    iget v0, v0, Ls5/b;->d:I

    .line 24
    .line 25
    if-lez v0, :cond_0

    .line 26
    .line 27
    const/4 v0, 0x1

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    const/4 v0, 0x0

    .line 30
    :goto_0
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    invoke-static {v0, p0}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0
.end method

.method public static final c(Ljava/math/BigDecimal;)Ljava/lang/Integer;
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    sget-object v1, Ljava/math/RoundingMode;->HALF_UP:Ljava/math/RoundingMode;

    .line 3
    .line 4
    invoke-virtual {p0, v0, v1}, Ljava/math/BigDecimal;->setScale(ILjava/math/RoundingMode;)Ljava/math/BigDecimal;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    invoke-virtual {p0}, Ljava/math/BigDecimal;->intValueExact()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :cond_0
    const/4 p0, 0x0

    .line 20
    return-object p0
.end method

.method public static final d(Ljava/lang/String;)Lfp0/c;
    .locals 1

    .line 1
    if-eqz p0, :cond_4

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    sparse-switch v0, :sswitch_data_0

    .line 8
    .line 9
    .line 10
    goto :goto_0

    .line 11
    :sswitch_0
    const-string v0, "cng"

    .line 12
    .line 13
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    if-nez p0, :cond_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    sget-object p0, Lfp0/c;->g:Lfp0/c;

    .line 21
    .line 22
    return-object p0

    .line 23
    :sswitch_1
    const-string v0, "electric"

    .line 24
    .line 25
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    if-nez p0, :cond_1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_1
    sget-object p0, Lfp0/c;->f:Lfp0/c;

    .line 33
    .line 34
    return-object p0

    .line 35
    :sswitch_2
    const-string v0, "diesel"

    .line 36
    .line 37
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result p0

    .line 41
    if-nez p0, :cond_2

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_2
    sget-object p0, Lfp0/c;->e:Lfp0/c;

    .line 45
    .line 46
    return-object p0

    .line 47
    :sswitch_3
    const-string v0, "gasoline"

    .line 48
    .line 49
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    if-nez p0, :cond_3

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_3
    sget-object p0, Lfp0/c;->d:Lfp0/c;

    .line 57
    .line 58
    return-object p0

    .line 59
    :cond_4
    :goto_0
    sget-object p0, Lfp0/c;->h:Lfp0/c;

    .line 60
    .line 61
    return-object p0

    .line 62
    nop

    .line 63
    :sswitch_data_0
    .sparse-switch
        -0x5e9e4e56 -> :sswitch_3
        -0x4f641826 -> :sswitch_2
        -0x1054ae3 -> :sswitch_1
        0x1815c -> :sswitch_0
    .end sparse-switch
.end method

.method public static final e(Lcz/myskoda/api/bff_vehicle_status/v2/EngineRangeDto;)Lfp0/b;
    .locals 8

    .line 1
    invoke-virtual {p0}, Lcz/myskoda/api/bff_vehicle_status/v2/EngineRangeDto;->getEngineType()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0}, Lcp0/r;->d(Ljava/lang/String;)Lfp0/c;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-virtual {p0}, Lcz/myskoda/api/bff_vehicle_status/v2/EngineRangeDto;->getCurrentFuelLevelInPercent()Ljava/math/BigDecimal;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    const/4 v2, 0x0

    .line 14
    if-eqz v1, :cond_0

    .line 15
    .line 16
    invoke-static {v1}, Lcp0/r;->c(Ljava/math/BigDecimal;)Ljava/lang/Integer;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    move-object v1, v2

    .line 22
    :goto_0
    invoke-virtual {p0}, Lcz/myskoda/api/bff_vehicle_status/v2/EngineRangeDto;->getCurrentSoCInPercent()Ljava/math/BigDecimal;

    .line 23
    .line 24
    .line 25
    move-result-object v3

    .line 26
    if-eqz v3, :cond_1

    .line 27
    .line 28
    invoke-static {v3}, Lcp0/r;->c(Ljava/math/BigDecimal;)Ljava/lang/Integer;

    .line 29
    .line 30
    .line 31
    move-result-object v3

    .line 32
    goto :goto_1

    .line 33
    :cond_1
    move-object v3, v2

    .line 34
    :goto_1
    invoke-virtual {p0}, Lcz/myskoda/api/bff_vehicle_status/v2/EngineRangeDto;->getRemainingRangeInKm()Ljava/math/BigDecimal;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    if-eqz p0, :cond_2

    .line 39
    .line 40
    invoke-static {p0}, Lcp0/r;->c(Ljava/math/BigDecimal;)Ljava/lang/Integer;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    if-eqz p0, :cond_2

    .line 45
    .line 46
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    int-to-double v4, p0

    .line 51
    const-wide v6, 0x408f400000000000L    # 1000.0

    .line 52
    .line 53
    .line 54
    .line 55
    .line 56
    mul-double/2addr v4, v6

    .line 57
    new-instance v2, Lqr0/d;

    .line 58
    .line 59
    invoke-direct {v2, v4, v5}, Lqr0/d;-><init>(D)V

    .line 60
    .line 61
    .line 62
    :cond_2
    new-instance p0, Lfp0/b;

    .line 63
    .line 64
    invoke-direct {p0, v0, v3, v1, v2}, Lfp0/b;-><init>(Lfp0/c;Ljava/lang/Integer;Ljava/lang/Integer;Lqr0/d;)V

    .line 65
    .line 66
    .line 67
    return-object p0
.end method
