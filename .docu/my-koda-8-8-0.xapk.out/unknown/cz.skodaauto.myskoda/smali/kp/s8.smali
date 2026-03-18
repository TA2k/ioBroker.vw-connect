.class public abstract Lkp/s8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lvv/m0;Ljava/lang/String;Lsv/d;Ll2/o;I)V
    .locals 10

    .line 1
    const-string v2, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v2, "content"

    .line 7
    .line 8
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    move-object v8, p3

    .line 12
    check-cast v8, Ll2/t;

    .line 13
    .line 14
    const v2, -0x14edc0a6

    .line 15
    .line 16
    .line 17
    invoke-virtual {v8, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 18
    .line 19
    .line 20
    and-int/lit8 v2, p4, 0xe

    .line 21
    .line 22
    if-nez v2, :cond_1

    .line 23
    .line 24
    invoke-virtual {v8, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    if-eqz v2, :cond_0

    .line 29
    .line 30
    const/4 v2, 0x4

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    const/4 v2, 0x2

    .line 33
    :goto_0
    or-int/2addr v2, p4

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    move v2, p4

    .line 36
    :goto_1
    and-int/lit8 v5, p4, 0x70

    .line 37
    .line 38
    if-nez v5, :cond_3

    .line 39
    .line 40
    invoke-virtual {v8, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v5

    .line 44
    if-eqz v5, :cond_2

    .line 45
    .line 46
    const/16 v5, 0x20

    .line 47
    .line 48
    goto :goto_2

    .line 49
    :cond_2
    const/16 v5, 0x10

    .line 50
    .line 51
    :goto_2
    or-int/2addr v2, v5

    .line 52
    :cond_3
    and-int/lit16 v5, p4, 0x380

    .line 53
    .line 54
    if-nez v5, :cond_5

    .line 55
    .line 56
    invoke-virtual {v8, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v5

    .line 60
    if-eqz v5, :cond_4

    .line 61
    .line 62
    const/16 v5, 0x100

    .line 63
    .line 64
    goto :goto_3

    .line 65
    :cond_4
    const/16 v5, 0x80

    .line 66
    .line 67
    :goto_3
    or-int/2addr v2, v5

    .line 68
    :cond_5
    and-int/lit16 v5, v2, 0x2db

    .line 69
    .line 70
    const/16 v6, 0x92

    .line 71
    .line 72
    if-ne v5, v6, :cond_7

    .line 73
    .line 74
    invoke-virtual {v8}, Ll2/t;->A()Z

    .line 75
    .line 76
    .line 77
    move-result v5

    .line 78
    if-nez v5, :cond_6

    .line 79
    .line 80
    goto :goto_4

    .line 81
    :cond_6
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 82
    .line 83
    .line 84
    goto :goto_5

    .line 85
    :cond_7
    :goto_4
    const v5, 0x44faf204

    .line 86
    .line 87
    .line 88
    invoke-virtual {v8, v5}, Ll2/t;->Z(I)V

    .line 89
    .line 90
    .line 91
    invoke-virtual {v8, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    move-result v5

    .line 95
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v6

    .line 99
    if-nez v5, :cond_8

    .line 100
    .line 101
    sget-object v5, Ll2/n;->a:Ll2/x0;

    .line 102
    .line 103
    if-ne v6, v5, :cond_9

    .line 104
    .line 105
    :cond_8
    new-instance v6, Lsv/b;

    .line 106
    .line 107
    invoke-direct {v6, p2}, Lsv/b;-><init>(Lsv/d;)V

    .line 108
    .line 109
    .line 110
    invoke-virtual {v8, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    :cond_9
    const/4 v5, 0x0

    .line 114
    invoke-virtual {v8, v5}, Ll2/t;->q(Z)V

    .line 115
    .line 116
    .line 117
    move-object v5, v6

    .line 118
    check-cast v5, Lsv/b;

    .line 119
    .line 120
    new-instance v7, Lqh/a;

    .line 121
    .line 122
    const/4 v6, 0x0

    .line 123
    const/4 v9, 0x3

    .line 124
    invoke-direct {v7, v9, v5, p1, v6}, Lqh/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 125
    .line 126
    .line 127
    shl-int/lit8 v6, v2, 0x3

    .line 128
    .line 129
    and-int/lit16 v6, v6, 0x380

    .line 130
    .line 131
    or-int/lit16 v9, v6, 0x1046

    .line 132
    .line 133
    const/4 v4, 0x0

    .line 134
    move-object v6, p1

    .line 135
    invoke-static/range {v4 .. v9}, Ll2/b;->p(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lay0/n;Ll2/o;I)Ll2/b1;

    .line 136
    .line 137
    .line 138
    move-result-object v4

    .line 139
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object v4

    .line 143
    check-cast v4, Luv/q;

    .line 144
    .line 145
    if-nez v4, :cond_a

    .line 146
    .line 147
    goto :goto_5

    .line 148
    :cond_a
    and-int/lit8 v2, v2, 0xe

    .line 149
    .line 150
    invoke-static {p0, v4, v8, v2}, Llp/i0;->a(Lvv/m0;Luv/q;Ll2/o;I)V

    .line 151
    .line 152
    .line 153
    :goto_5
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 154
    .line 155
    .line 156
    move-result-object v6

    .line 157
    if-eqz v6, :cond_b

    .line 158
    .line 159
    new-instance v0, Lsv/c;

    .line 160
    .line 161
    const/4 v2, 0x0

    .line 162
    move-object v3, p0

    .line 163
    move-object v4, p1

    .line 164
    move-object v5, p2

    .line 165
    move v1, p4

    .line 166
    invoke-direct/range {v0 .. v5}, Lsv/c;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 167
    .line 168
    .line 169
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 170
    .line 171
    :cond_b
    return-void
.end method

.method public static final b(Lga0/e;)I
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
    const p0, 0x7f1202bd

    .line 20
    .line 21
    .line 22
    return p0

    .line 23
    :pswitch_1
    const p0, 0x7f1214ef

    .line 24
    .line 25
    .line 26
    return p0

    .line 27
    :pswitch_2
    const p0, 0x7f1214ea

    .line 28
    .line 29
    .line 30
    return p0

    .line 31
    :pswitch_3
    const p0, 0x7f1214e5

    .line 32
    .line 33
    .line 34
    return p0

    .line 35
    :pswitch_4
    const p0, 0x7f1214e6

    .line 36
    .line 37
    .line 38
    return p0

    .line 39
    :pswitch_5
    const p0, 0x7f1214ed

    .line 40
    .line 41
    .line 42
    return p0

    .line 43
    :pswitch_6
    const p0, 0x7f1214e8

    .line 44
    .line 45
    .line 46
    return p0

    .line 47
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static final c(Lga0/h;)Ljava/lang/Integer;
    .locals 6

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lga0/h;->a:Lga0/g;

    .line 7
    .line 8
    iget-object p0, p0, Lga0/h;->b:Lga0/f;

    .line 9
    .line 10
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    const/4 v1, 0x4

    .line 15
    const/4 v2, 0x3

    .line 16
    const/4 v3, 0x1

    .line 17
    const/4 v4, 0x2

    .line 18
    if-eqz p0, :cond_5

    .line 19
    .line 20
    const/4 v5, 0x0

    .line 21
    if-eq p0, v4, :cond_4

    .line 22
    .line 23
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    if-eqz p0, :cond_4

    .line 28
    .line 29
    if-eq p0, v3, :cond_3

    .line 30
    .line 31
    if-eq p0, v4, :cond_2

    .line 32
    .line 33
    if-eq p0, v2, :cond_1

    .line 34
    .line 35
    if-ne p0, v1, :cond_0

    .line 36
    .line 37
    const p0, 0x7f121501

    .line 38
    .line 39
    .line 40
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    return-object p0

    .line 45
    :cond_0
    new-instance p0, La8/r0;

    .line 46
    .line 47
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_1
    const p0, 0x7f121502

    .line 52
    .line 53
    .line 54
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    return-object p0

    .line 59
    :cond_2
    const p0, 0x7f121503

    .line 60
    .line 61
    .line 62
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    return-object p0

    .line 67
    :cond_3
    const p0, 0x7f121504

    .line 68
    .line 69
    .line 70
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0

    .line 75
    :cond_4
    return-object v5

    .line 76
    :cond_5
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 77
    .line 78
    .line 79
    move-result p0

    .line 80
    if-eqz p0, :cond_a

    .line 81
    .line 82
    if-eq p0, v3, :cond_9

    .line 83
    .line 84
    if-eq p0, v4, :cond_8

    .line 85
    .line 86
    if-eq p0, v2, :cond_7

    .line 87
    .line 88
    if-ne p0, v1, :cond_6

    .line 89
    .line 90
    const p0, 0x7f1214fc

    .line 91
    .line 92
    .line 93
    goto :goto_0

    .line 94
    :cond_6
    new-instance p0, La8/r0;

    .line 95
    .line 96
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 97
    .line 98
    .line 99
    throw p0

    .line 100
    :cond_7
    const p0, 0x7f1214fd

    .line 101
    .line 102
    .line 103
    goto :goto_0

    .line 104
    :cond_8
    const p0, 0x7f1214fe

    .line 105
    .line 106
    .line 107
    goto :goto_0

    .line 108
    :cond_9
    const p0, 0x7f1214ff

    .line 109
    .line 110
    .line 111
    goto :goto_0

    .line 112
    :cond_a
    const p0, 0x7f121500

    .line 113
    .line 114
    .line 115
    :goto_0
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    return-object p0
.end method
