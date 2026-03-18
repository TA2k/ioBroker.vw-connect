.class public abstract Ljp/ia;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lbl0/h0;Lay0/a;Ll2/o;I)V
    .locals 15

    .line 1
    move-object/from16 v2, p1

    .line 2
    .line 3
    move/from16 v14, p3

    .line 4
    .line 5
    const-string v0, "onClick"

    .line 6
    .line 7
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    move-object/from16 v10, p2

    .line 11
    .line 12
    check-cast v10, Ll2/t;

    .line 13
    .line 14
    const v0, 0x1c6b18f1

    .line 15
    .line 16
    .line 17
    invoke-virtual {v10, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 18
    .line 19
    .line 20
    and-int/lit16 v0, v14, 0x180

    .line 21
    .line 22
    if-nez v0, :cond_1

    .line 23
    .line 24
    invoke-virtual {v10, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    if-eqz v0, :cond_0

    .line 29
    .line 30
    const/16 v0, 0x100

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    const/16 v0, 0x80

    .line 34
    .line 35
    :goto_0
    or-int/2addr v0, v14

    .line 36
    goto :goto_1

    .line 37
    :cond_1
    move v0, v14

    .line 38
    :goto_1
    and-int/lit16 v1, v0, 0x93

    .line 39
    .line 40
    const/16 v3, 0x92

    .line 41
    .line 42
    if-eq v1, v3, :cond_2

    .line 43
    .line 44
    const/4 v1, 0x1

    .line 45
    goto :goto_2

    .line 46
    :cond_2
    const/4 v1, 0x0

    .line 47
    :goto_2
    and-int/lit8 v3, v0, 0x1

    .line 48
    .line 49
    invoke-virtual {v10, v3, v1}, Ll2/t;->O(IZ)Z

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    if-eqz v1, :cond_3

    .line 54
    .line 55
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    packed-switch v1, :pswitch_data_0

    .line 60
    .line 61
    .line 62
    new-instance p0, La8/r0;

    .line 63
    .line 64
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 65
    .line 66
    .line 67
    throw p0

    .line 68
    :pswitch_0
    const v1, 0x7f12062e

    .line 69
    .line 70
    .line 71
    goto :goto_3

    .line 72
    :pswitch_1
    const v1, 0x7f12065f

    .line 73
    .line 74
    .line 75
    goto :goto_3

    .line 76
    :pswitch_2
    const v1, 0x7f12062d

    .line 77
    .line 78
    .line 79
    goto :goto_3

    .line 80
    :pswitch_3
    const v1, 0x7f120660

    .line 81
    .line 82
    .line 83
    goto :goto_3

    .line 84
    :pswitch_4
    const v1, 0x7f12062c

    .line 85
    .line 86
    .line 87
    goto :goto_3

    .line 88
    :pswitch_5
    const v1, 0x7f12065e

    .line 89
    .line 90
    .line 91
    :goto_3
    invoke-static {v10, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object v1

    .line 95
    invoke-virtual {p0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object v9

    .line 99
    and-int/lit16 v0, v0, 0x380

    .line 100
    .line 101
    const v3, 0x30c00

    .line 102
    .line 103
    .line 104
    or-int v11, v0, v3

    .line 105
    .line 106
    const/4 v12, 0x0

    .line 107
    const/16 v13, 0x1fd2

    .line 108
    .line 109
    move-object v0, v1

    .line 110
    const/4 v1, 0x0

    .line 111
    const/4 v3, 0x0

    .line 112
    const/4 v4, 0x0

    .line 113
    const/4 v5, 0x1

    .line 114
    const/4 v6, 0x0

    .line 115
    const/4 v7, 0x0

    .line 116
    const/4 v8, 0x0

    .line 117
    invoke-static/range {v0 .. v13}, Li91/h0;->a(Ljava/lang/String;Lx2/s;Lay0/a;ZZZLjava/lang/String;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;III)V

    .line 118
    .line 119
    .line 120
    goto :goto_4

    .line 121
    :cond_3
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 122
    .line 123
    .line 124
    :goto_4
    invoke-virtual {v10}, Ll2/t;->s()Ll2/u1;

    .line 125
    .line 126
    .line 127
    move-result-object v0

    .line 128
    if-eqz v0, :cond_4

    .line 129
    .line 130
    new-instance v1, La71/n0;

    .line 131
    .line 132
    const/4 v3, 0x2

    .line 133
    invoke-direct {v1, v14, v3, p0, v2}, La71/n0;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 137
    .line 138
    :cond_4
    return-void

    .line 139
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_4
        :pswitch_3
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static final b(Lmb0/c;ZLij0/a;)Lvf0/g;
    .locals 3

    .line 1
    const-string v0, "stringResource"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    if-nez p1, :cond_0

    .line 8
    .line 9
    return-object v0

    .line 10
    :cond_0
    const p1, 0x7f120daf

    .line 11
    .line 12
    .line 13
    if-eqz p0, :cond_1

    .line 14
    .line 15
    new-instance v0, Lvf0/g;

    .line 16
    .line 17
    iget-object v1, p0, Lmb0/c;->a:Lqr0/q;

    .line 18
    .line 19
    invoke-static {v1, p2}, Lkp/p6;->b(Lqr0/q;Lij0/a;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    check-cast p2, Ljj0/f;

    .line 28
    .line 29
    invoke-virtual {p2, p1, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    iget-object p0, p0, Lmb0/c;->b:Ljava/time/OffsetDateTime;

    .line 34
    .line 35
    invoke-direct {v0, p1, p0}, Lvf0/g;-><init>(Ljava/lang/String;Ljava/time/OffsetDateTime;)V

    .line 36
    .line 37
    .line 38
    return-object v0

    .line 39
    :cond_1
    new-instance p0, Lvf0/g;

    .line 40
    .line 41
    const/4 v1, 0x0

    .line 42
    new-array v1, v1, [Ljava/lang/Object;

    .line 43
    .line 44
    check-cast p2, Ljj0/f;

    .line 45
    .line 46
    const v2, 0x7f1201aa

    .line 47
    .line 48
    .line 49
    invoke-virtual {p2, v2, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    invoke-virtual {p2, p1, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    invoke-direct {p0, p1, v0}, Lvf0/g;-><init>(Ljava/lang/String;Ljava/time/OffsetDateTime;)V

    .line 62
    .line 63
    .line 64
    return-object p0
.end method
