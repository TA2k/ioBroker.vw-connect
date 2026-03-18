.class public abstract Ljp/ec;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lss0/b;Lij0/a;)Lc00/y0;
    .locals 4

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
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v0, Lc00/y0;

    .line 12
    .line 13
    sget-object v1, Lc00/u0;->d:Lc00/u0;

    .line 14
    .line 15
    sget-object v1, Lc00/x0;->d:Lc00/x0;

    .line 16
    .line 17
    sget-object v1, Lss0/e;->g:Lss0/e;

    .line 18
    .line 19
    invoke-static {p0, v1}, Lkp/u6;->d(Lss0/b;Lss0/e;)Ler0/g;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    invoke-static {p0, v1}, Llp/pf;->i(Lss0/b;Lss0/e;)Llf0/i;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    const v1, 0x7e408

    .line 28
    .line 29
    .line 30
    const/4 v3, 0x0

    .line 31
    invoke-direct {v0, v3, v2, p0, v1}, Lc00/y0;-><init>(Lc00/v0;Ler0/g;Llf0/i;I)V

    .line 32
    .line 33
    .line 34
    new-instance p0, Lqr0/q;

    .line 35
    .line 36
    const-wide/high16 v1, 0x4036000000000000L    # 22.0

    .line 37
    .line 38
    sget-object v3, Lqr0/r;->d:Lqr0/r;

    .line 39
    .line 40
    invoke-direct {p0, v1, v2, v3}, Lqr0/q;-><init>(DLqr0/r;)V

    .line 41
    .line 42
    .line 43
    invoke-static {v0, p0, p1}, Ljp/ec;->f(Lc00/y0;Lqr0/q;Lij0/a;)Lc00/y0;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    const/4 p1, 0x1

    .line 48
    invoke-static {p0, p1}, Ljp/ec;->d(Lc00/y0;Z)Lc00/y0;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0
.end method

.method public static final b(Lc00/y0;Lij0/a;)Lc00/v0;
    .locals 7

    .line 1
    new-instance v0, Lc00/v0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    new-array v2, v1, [Ljava/lang/Object;

    .line 5
    .line 6
    check-cast p1, Ljj0/f;

    .line 7
    .line 8
    const v3, 0x7f1201c5

    .line 9
    .line 10
    .line 11
    invoke-virtual {p1, v3, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    const v3, 0x7f1201aa

    .line 16
    .line 17
    .line 18
    new-array v1, v1, [Ljava/lang/Object;

    .line 19
    .line 20
    invoke-virtual {p1, v3, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    iget-object p0, p0, Lc00/y0;->k:Lc00/v0;

    .line 25
    .line 26
    iget-boolean v5, p0, Lc00/v0;->e:Z

    .line 27
    .line 28
    const/16 v6, 0x20

    .line 29
    .line 30
    const/4 v3, 0x0

    .line 31
    const/4 v4, 0x0

    .line 32
    move-object v1, v2

    .line 33
    move-object v2, p1

    .line 34
    invoke-direct/range {v0 .. v6}, Lc00/v0;-><init>(Ljava/lang/String;Ljava/lang/String;FZZI)V

    .line 35
    .line 36
    .line 37
    return-object v0
.end method

.method public static final c(Lc00/y0;Lij0/a;)Lc00/y0;
    .locals 19

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    move-object/from16 v1, p0

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v0, "stringResource"

    .line 9
    .line 10
    move-object/from16 v2, p1

    .line 11
    .line 12
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    sget-object v5, Lc00/u0;->d:Lc00/u0;

    .line 16
    .line 17
    sget-object v7, Lc00/x0;->d:Lc00/x0;

    .line 18
    .line 19
    invoke-static/range {p0 .. p1}, Ljp/ec;->b(Lc00/y0;Lij0/a;)Lc00/v0;

    .line 20
    .line 21
    .line 22
    move-result-object v11

    .line 23
    const/16 v17, 0x0

    .line 24
    .line 25
    const v18, 0x67829

    .line 26
    .line 27
    .line 28
    const/4 v2, 0x0

    .line 29
    const/4 v3, 0x1

    .line 30
    const/4 v4, 0x0

    .line 31
    const/4 v6, 0x0

    .line 32
    const/4 v8, 0x0

    .line 33
    const/4 v9, 0x0

    .line 34
    const/4 v10, 0x0

    .line 35
    const/4 v12, 0x0

    .line 36
    const/4 v13, 0x0

    .line 37
    const/4 v14, 0x0

    .line 38
    const/4 v15, 0x0

    .line 39
    const/16 v16, 0x0

    .line 40
    .line 41
    invoke-static/range {v1 .. v18}, Lc00/y0;->a(Lc00/y0;ZZZLc00/u0;Lc00/w0;Lc00/x0;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lc00/v0;Llf0/i;ZZLqr0/q;Lqr0/q;ZI)Lc00/y0;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    return-object v0
.end method

.method public static final d(Lc00/y0;Z)Lc00/y0;
    .locals 19

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    const-string v0, "<this>"

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v2, v1, Lc00/y0;->k:Lc00/v0;

    .line 9
    .line 10
    const/4 v7, 0x0

    .line 11
    const/16 v8, 0x2f

    .line 12
    .line 13
    const/4 v3, 0x0

    .line 14
    const/4 v4, 0x0

    .line 15
    const/4 v5, 0x0

    .line 16
    move/from16 v6, p1

    .line 17
    .line 18
    invoke-static/range {v2 .. v8}, Lc00/v0;->a(Lc00/v0;Ljava/lang/String;Ljava/lang/String;FZLvf0/g;I)Lc00/v0;

    .line 19
    .line 20
    .line 21
    move-result-object v11

    .line 22
    const/16 v17, 0x0

    .line 23
    .line 24
    const v18, 0x7fbff

    .line 25
    .line 26
    .line 27
    const/4 v2, 0x0

    .line 28
    const/4 v3, 0x0

    .line 29
    const/4 v4, 0x0

    .line 30
    const/4 v5, 0x0

    .line 31
    const/4 v6, 0x0

    .line 32
    const/4 v8, 0x0

    .line 33
    const/4 v9, 0x0

    .line 34
    const/4 v10, 0x0

    .line 35
    const/4 v12, 0x0

    .line 36
    const/4 v13, 0x0

    .line 37
    const/4 v14, 0x0

    .line 38
    const/4 v15, 0x0

    .line 39
    const/16 v16, 0x0

    .line 40
    .line 41
    invoke-static/range {v1 .. v18}, Lc00/y0;->a(Lc00/y0;ZZZLc00/u0;Lc00/w0;Lc00/x0;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lc00/v0;Llf0/i;ZZLqr0/q;Lqr0/q;ZI)Lc00/y0;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    return-object v0
.end method

.method public static final e(Lc00/y0;Lij0/a;Lcn0/a;)Lc00/y0;
    .locals 19

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v0, p1

    .line 4
    .line 5
    const-string v2, "<this>"

    .line 6
    .line 7
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object v2, v1, Lc00/y0;->f:Lc00/w0;

    .line 11
    .line 12
    const-string v3, "stringResource"

    .line 13
    .line 14
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual/range {p2 .. p2}, Ljava/lang/Enum;->ordinal()I

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    const/4 v4, 0x3

    .line 22
    const/4 v5, 0x2

    .line 23
    if-eq v3, v5, :cond_0

    .line 24
    .line 25
    if-eq v3, v4, :cond_0

    .line 26
    .line 27
    iget-object v3, v1, Lc00/y0;->g:Lc00/x0;

    .line 28
    .line 29
    :goto_0
    move-object v7, v3

    .line 30
    goto :goto_1

    .line 31
    :cond_0
    sget-object v3, Lc00/x0;->g:Lc00/x0;

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :goto_1
    invoke-virtual/range {p2 .. p2}, Ljava/lang/Enum;->ordinal()I

    .line 35
    .line 36
    .line 37
    move-result v3

    .line 38
    const/4 v6, 0x1

    .line 39
    if-eqz v3, :cond_3

    .line 40
    .line 41
    if-eq v3, v6, :cond_2

    .line 42
    .line 43
    const/4 v8, 0x4

    .line 44
    if-eq v3, v8, :cond_1

    .line 45
    .line 46
    move-object v3, v2

    .line 47
    goto :goto_2

    .line 48
    :cond_1
    sget-object v3, Lc00/w0;->f:Lc00/w0;

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_2
    sget-object v3, Lc00/w0;->e:Lc00/w0;

    .line 52
    .line 53
    goto :goto_2

    .line 54
    :cond_3
    sget-object v3, Lc00/w0;->d:Lc00/w0;

    .line 55
    .line 56
    :goto_2
    sget-object v8, Lc00/w0;->d:Lc00/w0;

    .line 57
    .line 58
    const/4 v9, -0x1

    .line 59
    const v10, 0x7f120081

    .line 60
    .line 61
    .line 62
    if-ne v2, v8, :cond_4

    .line 63
    .line 64
    goto :goto_4

    .line 65
    :cond_4
    if-nez v3, :cond_5

    .line 66
    .line 67
    move v2, v9

    .line 68
    goto :goto_3

    .line 69
    :cond_5
    sget-object v2, Lc00/l1;->a:[I

    .line 70
    .line 71
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 72
    .line 73
    .line 74
    move-result v8

    .line 75
    aget v2, v2, v8

    .line 76
    .line 77
    :goto_3
    if-eq v2, v6, :cond_7

    .line 78
    .line 79
    if-eq v2, v5, :cond_8

    .line 80
    .line 81
    if-eq v2, v4, :cond_6

    .line 82
    .line 83
    const v10, 0x7f1200a2

    .line 84
    .line 85
    .line 86
    goto :goto_4

    .line 87
    :cond_6
    const v10, 0x7f120080

    .line 88
    .line 89
    .line 90
    goto :goto_4

    .line 91
    :cond_7
    const v10, 0x7f12009e

    .line 92
    .line 93
    .line 94
    :cond_8
    :goto_4
    if-nez v3, :cond_9

    .line 95
    .line 96
    goto :goto_5

    .line 97
    :cond_9
    sget-object v2, Lc00/l1;->a:[I

    .line 98
    .line 99
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 100
    .line 101
    .line 102
    move-result v6

    .line 103
    aget v9, v2, v6

    .line 104
    .line 105
    :goto_5
    if-eq v9, v5, :cond_b

    .line 106
    .line 107
    if-eq v9, v4, :cond_a

    .line 108
    .line 109
    iget-object v2, v1, Lc00/y0;->e:Lc00/u0;

    .line 110
    .line 111
    :goto_6
    move-object v5, v2

    .line 112
    goto :goto_7

    .line 113
    :cond_a
    sget-object v2, Lc00/u0;->e:Lc00/u0;

    .line 114
    .line 115
    goto :goto_6

    .line 116
    :cond_b
    sget-object v2, Lc00/u0;->i:Lc00/u0;

    .line 117
    .line 118
    goto :goto_6

    .line 119
    :goto_7
    const/4 v2, 0x0

    .line 120
    new-array v4, v2, [Ljava/lang/Object;

    .line 121
    .line 122
    check-cast v0, Ljj0/f;

    .line 123
    .line 124
    invoke-virtual {v0, v10, v4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object v8

    .line 128
    sget-object v4, Lcn0/a;->h:Lcn0/a;

    .line 129
    .line 130
    move-object/from16 v6, p2

    .line 131
    .line 132
    if-ne v6, v4, :cond_c

    .line 133
    .line 134
    const v4, 0x7f1201aa

    .line 135
    .line 136
    .line 137
    new-array v2, v2, [Ljava/lang/Object;

    .line 138
    .line 139
    invoke-virtual {v0, v4, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 140
    .line 141
    .line 142
    move-result-object v0

    .line 143
    :goto_8
    move-object v9, v0

    .line 144
    goto :goto_9

    .line 145
    :cond_c
    const/4 v0, 0x0

    .line 146
    goto :goto_8

    .line 147
    :goto_9
    const/16 v17, 0x0

    .line 148
    .line 149
    const v18, 0x7fc0f

    .line 150
    .line 151
    .line 152
    const/4 v2, 0x0

    .line 153
    move-object v6, v3

    .line 154
    const/4 v3, 0x0

    .line 155
    const/4 v4, 0x0

    .line 156
    const/4 v10, 0x0

    .line 157
    const/4 v11, 0x0

    .line 158
    const/4 v12, 0x0

    .line 159
    const/4 v13, 0x0

    .line 160
    const/4 v14, 0x0

    .line 161
    const/4 v15, 0x0

    .line 162
    const/16 v16, 0x0

    .line 163
    .line 164
    invoke-static/range {v1 .. v18}, Lc00/y0;->a(Lc00/y0;ZZZLc00/u0;Lc00/w0;Lc00/x0;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lc00/v0;Llf0/i;ZZLqr0/q;Lqr0/q;ZI)Lc00/y0;

    .line 165
    .line 166
    .line 167
    move-result-object v0

    .line 168
    return-object v0
.end method

.method public static final f(Lc00/y0;Lqr0/q;Lij0/a;)Lc00/y0;
    .locals 19

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v15, p1

    .line 4
    .line 5
    move-object/from16 v0, p2

    .line 6
    .line 7
    const-string v2, "<this>"

    .line 8
    .line 9
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v2, "stringResource"

    .line 13
    .line 14
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    if-eqz v15, :cond_2

    .line 18
    .line 19
    iget-wide v2, v15, Lqr0/q;->a:D

    .line 20
    .line 21
    invoke-static {v15}, Lkp/p6;->e(Lqr0/q;)D

    .line 22
    .line 23
    .line 24
    move-result-wide v4

    .line 25
    cmpg-double v4, v2, v4

    .line 26
    .line 27
    const/4 v5, 0x0

    .line 28
    if-nez v4, :cond_0

    .line 29
    .line 30
    new-array v2, v5, [Ljava/lang/Object;

    .line 31
    .line 32
    move-object v3, v0

    .line 33
    check-cast v3, Ljj0/f;

    .line 34
    .line 35
    const v4, 0x7f1200cf

    .line 36
    .line 37
    .line 38
    invoke-virtual {v3, v4, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v2

    .line 42
    :goto_0
    move-object v8, v2

    .line 43
    goto :goto_1

    .line 44
    :cond_0
    invoke-static {v15}, Lkp/p6;->d(Lqr0/q;)D

    .line 45
    .line 46
    .line 47
    move-result-wide v6

    .line 48
    cmpg-double v2, v2, v6

    .line 49
    .line 50
    if-nez v2, :cond_1

    .line 51
    .line 52
    new-array v2, v5, [Ljava/lang/Object;

    .line 53
    .line 54
    move-object v3, v0

    .line 55
    check-cast v3, Ljj0/f;

    .line 56
    .line 57
    const v4, 0x7f1200ce

    .line 58
    .line 59
    .line 60
    invoke-virtual {v3, v4, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    goto :goto_0

    .line 65
    :cond_1
    invoke-static/range {p1 .. p2}, Lkp/p6;->b(Lqr0/q;Lij0/a;)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v2

    .line 69
    goto :goto_0

    .line 70
    :goto_1
    iget-object v6, v1, Lc00/y0;->k:Lc00/v0;

    .line 71
    .line 72
    new-array v2, v5, [Ljava/lang/Object;

    .line 73
    .line 74
    check-cast v0, Ljj0/f;

    .line 75
    .line 76
    const v3, 0x7f120088

    .line 77
    .line 78
    .line 79
    invoke-virtual {v0, v3, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object v7

    .line 83
    invoke-static {v15}, Lkp/p6;->c(Lqr0/q;)F

    .line 84
    .line 85
    .line 86
    move-result v9

    .line 87
    iget-object v0, v1, Lc00/y0;->k:Lc00/v0;

    .line 88
    .line 89
    iget-boolean v10, v0, Lc00/v0;->e:Z

    .line 90
    .line 91
    const/4 v11, 0x0

    .line 92
    const/16 v12, 0x20

    .line 93
    .line 94
    invoke-static/range {v6 .. v12}, Lc00/v0;->a(Lc00/v0;Ljava/lang/String;Ljava/lang/String;FZLvf0/g;I)Lc00/v0;

    .line 95
    .line 96
    .line 97
    move-result-object v0

    .line 98
    :goto_2
    move-object v11, v0

    .line 99
    goto :goto_3

    .line 100
    :cond_2
    invoke-static {v1, v0}, Ljp/ec;->b(Lc00/y0;Lij0/a;)Lc00/v0;

    .line 101
    .line 102
    .line 103
    move-result-object v0

    .line 104
    goto :goto_2

    .line 105
    :goto_3
    const/16 v17, 0x0

    .line 106
    .line 107
    const v18, 0x77bff

    .line 108
    .line 109
    .line 110
    const/4 v2, 0x0

    .line 111
    const/4 v3, 0x0

    .line 112
    const/4 v4, 0x0

    .line 113
    const/4 v5, 0x0

    .line 114
    const/4 v6, 0x0

    .line 115
    const/4 v7, 0x0

    .line 116
    const/4 v8, 0x0

    .line 117
    const/4 v9, 0x0

    .line 118
    const/4 v10, 0x0

    .line 119
    const/4 v12, 0x0

    .line 120
    const/4 v13, 0x0

    .line 121
    const/4 v14, 0x0

    .line 122
    const/16 v16, 0x0

    .line 123
    .line 124
    invoke-static/range {v1 .. v18}, Lc00/y0;->a(Lc00/y0;ZZZLc00/u0;Lc00/w0;Lc00/x0;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lc00/v0;Llf0/i;ZZLqr0/q;Lqr0/q;ZI)Lc00/y0;

    .line 125
    .line 126
    .line 127
    move-result-object v0

    .line 128
    return-object v0
.end method

.method public static g(Landroid/os/ParcelFileDescriptor;Ljava/io/File;)Ljava/io/File;
    .locals 5

    .line 1
    new-instance v0, Landroid/os/ParcelFileDescriptor$AutoCloseInputStream;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Landroid/os/ParcelFileDescriptor$AutoCloseInputStream;-><init>(Landroid/os/ParcelFileDescriptor;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    invoke-virtual {p1}, Ljava/io/File;->mkdirs()Z

    .line 7
    .line 8
    .line 9
    const-string p0, "asset"

    .line 10
    .line 11
    const-string v1, ".tmp"

    .line 12
    .line 13
    invoke-static {p0, v1, p1}, Ljava/io/File;->createTempFile(Ljava/lang/String;Ljava/lang/String;Ljava/io/File;)Ljava/io/File;

    .line 14
    .line 15
    .line 16
    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 17
    const/4 p1, 0x0

    .line 18
    :try_start_1
    new-instance v1, Ljava/io/FileOutputStream;

    .line 19
    .line 20
    invoke-direct {v1, p0}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    .line 21
    .line 22
    .line 23
    const/16 p1, 0x2800

    .line 24
    .line 25
    :try_start_2
    new-array p1, p1, [B

    .line 26
    .line 27
    :goto_0
    invoke-virtual {v0, p1}, Ljava/io/InputStream;->read([B)I

    .line 28
    .line 29
    .line 30
    move-result v2
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 31
    if-gez v2, :cond_0

    .line 32
    .line 33
    :try_start_3
    invoke-static {v0}, Ljp/ec;->h(Ljava/io/Closeable;)V

    .line 34
    .line 35
    .line 36
    invoke-static {v1}, Ljp/ec;->h(Ljava/io/Closeable;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 37
    .line 38
    .line 39
    invoke-static {v0}, Ljp/ec;->h(Ljava/io/Closeable;)V

    .line 40
    .line 41
    .line 42
    return-object p0

    .line 43
    :catchall_0
    move-exception p0

    .line 44
    goto :goto_4

    .line 45
    :cond_0
    const/4 v3, 0x0

    .line 46
    :try_start_4
    invoke-virtual {v1, p1, v3, v2}, Ljava/io/FileOutputStream;->write([BII)V
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    :catchall_1
    move-exception p1

    .line 51
    goto :goto_1

    .line 52
    :catch_0
    move-exception p1

    .line 53
    goto :goto_2

    .line 54
    :goto_1
    move-object v4, v1

    .line 55
    move-object v1, p1

    .line 56
    move-object p1, v4

    .line 57
    goto :goto_3

    .line 58
    :catchall_2
    move-exception v1

    .line 59
    goto :goto_3

    .line 60
    :catch_1
    move-exception v1

    .line 61
    move-object v4, v1

    .line 62
    move-object v1, p1

    .line 63
    move-object p1, v4

    .line 64
    :goto_2
    :try_start_5
    new-instance v2, Ljava/lang/RuntimeException;

    .line 65
    .line 66
    invoke-direct {v2, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 67
    .line 68
    .line 69
    throw v2
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 70
    :goto_3
    :try_start_6
    invoke-static {v0}, Ljp/ec;->h(Ljava/io/Closeable;)V

    .line 71
    .line 72
    .line 73
    invoke-static {p1}, Ljp/ec;->h(Ljava/io/Closeable;)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {p0}, Ljava/io/File;->delete()Z

    .line 77
    .line 78
    .line 79
    throw v1
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 80
    :goto_4
    invoke-static {v0}, Ljp/ec;->h(Ljava/io/Closeable;)V

    .line 81
    .line 82
    .line 83
    throw p0
.end method

.method public static h(Ljava/io/Closeable;)V
    .locals 0

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    :try_start_0
    invoke-interface {p0}, Ljava/io/Closeable;->close()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 5
    .line 6
    .line 7
    :catch_0
    return-void
.end method
