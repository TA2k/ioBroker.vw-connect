.class public abstract Ljp/qa;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/lang/String;Ll2/o;I)V
    .locals 12

    .line 1
    const-string v0, "pcid"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/t;

    .line 7
    .line 8
    const v0, -0x61080ea5

    .line 9
    .line 10
    .line 11
    invoke-virtual {p1, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 12
    .line 13
    .line 14
    invoke-virtual {p1, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    const/4 v1, 0x2

    .line 19
    const/4 v2, 0x4

    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    move v0, v2

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move v0, v1

    .line 25
    :goto_0
    or-int/2addr v0, p2

    .line 26
    and-int/lit8 v3, v0, 0x3

    .line 27
    .line 28
    const/4 v4, 0x1

    .line 29
    const/4 v5, 0x0

    .line 30
    if-eq v3, v1, :cond_1

    .line 31
    .line 32
    move v1, v4

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    move v1, v5

    .line 35
    :goto_1
    and-int/lit8 v3, v0, 0x1

    .line 36
    .line 37
    invoke-virtual {p1, v3, v1}, Ll2/t;->O(IZ)Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    if-eqz v1, :cond_6

    .line 42
    .line 43
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p2

    .line 47
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 48
    .line 49
    if-ne p2, v1, :cond_2

    .line 50
    .line 51
    new-instance p2, Landroid/content/Intent;

    .line 52
    .line 53
    const-string v3, "mailto:"

    .line 54
    .line 55
    invoke-static {v3}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 56
    .line 57
    .line 58
    move-result-object v3

    .line 59
    const-string v6, "android.intent.action.SENDTO"

    .line 60
    .line 61
    invoke-direct {p2, v6, v3}, Landroid/content/Intent;-><init>(Ljava/lang/String;Landroid/net/Uri;)V

    .line 62
    .line 63
    .line 64
    const-string v3, "android.intent.extra.TEXT"

    .line 65
    .line 66
    invoke-virtual {p2, v3, p0}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 67
    .line 68
    .line 69
    invoke-virtual {p1, p2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    :cond_2
    move-object v10, p2

    .line 73
    check-cast v10, Landroid/content/Intent;

    .line 74
    .line 75
    invoke-static {v10, p1}, Lzb/b;->p(Landroid/content/Intent;Ll2/o;)Z

    .line 76
    .line 77
    .line 78
    sget-object p2, Lw3/h1;->e:Ll2/u2;

    .line 79
    .line 80
    invoke-virtual {p1, p2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object p2

    .line 84
    move-object v7, p2

    .line 85
    check-cast v7, Lw3/d1;

    .line 86
    .line 87
    sget-object p2, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 88
    .line 89
    invoke-virtual {p1, p2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object p2

    .line 93
    move-object v9, p2

    .line 94
    check-cast v9, Landroid/content/Context;

    .line 95
    .line 96
    invoke-virtual {p1, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result p2

    .line 100
    and-int/lit8 v0, v0, 0xe

    .line 101
    .line 102
    if-ne v0, v2, :cond_3

    .line 103
    .line 104
    goto :goto_2

    .line 105
    :cond_3
    move v4, v5

    .line 106
    :goto_2
    or-int/2addr p2, v4

    .line 107
    invoke-virtual {p1, v9}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    move-result v0

    .line 111
    or-int/2addr p2, v0

    .line 112
    invoke-virtual {p1, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    move-result v0

    .line 116
    or-int/2addr p2, v0

    .line 117
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object v0

    .line 121
    if-nez p2, :cond_4

    .line 122
    .line 123
    if-ne v0, v1, :cond_5

    .line 124
    .line 125
    :cond_4
    new-instance v6, Lbg/a;

    .line 126
    .line 127
    const/4 v11, 0x0

    .line 128
    move-object v8, p0

    .line 129
    invoke-direct/range {v6 .. v11}, Lbg/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {p1, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    move-object v0, v6

    .line 136
    :cond_5
    check-cast v0, Lay0/k;

    .line 137
    .line 138
    invoke-static {v0, p1}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 139
    .line 140
    .line 141
    sget-object p0, Lzb/x;->b:Ll2/u2;

    .line 142
    .line 143
    invoke-virtual {p1, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    const-string p1, "null cannot be cast to non-null type cariad.charging.multicharge.kitten.plugandchargeoffline.presentation.PlugAndChargeOfflineUi"

    .line 148
    .line 149
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    new-instance p0, Ljava/lang/ClassCastException;

    .line 153
    .line 154
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 155
    .line 156
    .line 157
    throw p0

    .line 158
    :cond_6
    move-object v8, p0

    .line 159
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 160
    .line 161
    .line 162
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 163
    .line 164
    .line 165
    move-result-object p0

    .line 166
    if-eqz p0, :cond_7

    .line 167
    .line 168
    new-instance p1, La71/d;

    .line 169
    .line 170
    const/4 v0, 0x3

    .line 171
    invoke-direct {p1, v8, p2, v0}, La71/d;-><init>(Ljava/lang/String;II)V

    .line 172
    .line 173
    .line 174
    iput-object p1, p0, Ll2/u1;->d:Lay0/n;

    .line 175
    .line 176
    :cond_7
    return-void
.end method

.method public static final b(Lnh/v;)Lnh/r;
    .locals 11

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v2, p0, Lnh/v;->a:Ljava/lang/String;

    .line 7
    .line 8
    iget-object v6, p0, Lnh/v;->e:Llc/l;

    .line 9
    .line 10
    sget-object v0, Lnh/w;->a:Lly0/n;

    .line 11
    .line 12
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-lez v0, :cond_0

    .line 17
    .line 18
    const/4 v0, 0x1

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const/4 v0, 0x0

    .line 21
    :goto_0
    sget-object v1, Lnh/w;->a:Lly0/n;

    .line 22
    .line 23
    invoke-virtual {v1, v2}, Lly0/n;->d(Ljava/lang/CharSequence;)Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    and-int/2addr v0, v1

    .line 28
    iget-boolean v3, p0, Lnh/v;->b:Z

    .line 29
    .line 30
    xor-int/lit8 v1, v3, 0x1

    .line 31
    .line 32
    and-int v10, v0, v1

    .line 33
    .line 34
    iget-boolean v4, p0, Lnh/v;->c:Z

    .line 35
    .line 36
    iget-boolean v5, p0, Lnh/v;->d:Z

    .line 37
    .line 38
    iget-boolean v7, p0, Lnh/v;->i:Z

    .line 39
    .line 40
    iget-boolean v8, p0, Lnh/v;->h:Z

    .line 41
    .line 42
    iget-object v0, p0, Lnh/v;->g:Lnh/h;

    .line 43
    .line 44
    sget-object v1, Lnh/e;->a:Lnh/e;

    .line 45
    .line 46
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-eqz v1, :cond_1

    .line 51
    .line 52
    sget-object p0, Lnh/a;->a:Lnh/a;

    .line 53
    .line 54
    :goto_1
    move-object v9, p0

    .line 55
    goto :goto_2

    .line 56
    :cond_1
    sget-object v1, Lnh/g;->a:Lnh/g;

    .line 57
    .line 58
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    if-eqz v1, :cond_2

    .line 63
    .line 64
    sget-object p0, Lnh/c;->a:Lnh/c;

    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_2
    sget-object v1, Lnh/f;->a:Lnh/f;

    .line 68
    .line 69
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    if-eqz v0, :cond_3

    .line 74
    .line 75
    new-instance v0, Lnh/b;

    .line 76
    .line 77
    iget-boolean p0, p0, Lnh/v;->j:Z

    .line 78
    .line 79
    invoke-direct {v0, p0}, Lnh/b;-><init>(Z)V

    .line 80
    .line 81
    .line 82
    move-object v9, v0

    .line 83
    :goto_2
    new-instance v1, Lnh/r;

    .line 84
    .line 85
    invoke-direct/range {v1 .. v10}, Lnh/r;-><init>(Ljava/lang/String;ZZZLlc/l;ZZLnh/d;Z)V

    .line 86
    .line 87
    .line 88
    return-object v1

    .line 89
    :cond_3
    new-instance p0, La8/r0;

    .line 90
    .line 91
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 92
    .line 93
    .line 94
    throw p0
.end method
