.class public final Lh40/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh40/k;


# direct methods
.method public synthetic constructor <init>(Lh40/k;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh40/g;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh40/g;->e:Lh40/k;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public b(Lne0/s;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p2, Lh40/j;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lh40/j;

    .line 7
    .line 8
    iget v1, v0, Lh40/j;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lh40/j;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lh40/j;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lh40/j;-><init>(Lh40/g;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lh40/j;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lh40/j;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    iget-object p0, p0, Lh40/g;->e:Lh40/k;

    .line 33
    .line 34
    if-eqz v2, :cond_2

    .line 35
    .line 36
    if-ne v2, v3, :cond_1

    .line 37
    .line 38
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto/16 :goto_1

    .line 42
    .line 43
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 46
    .line 47
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    instance-of p2, p1, Lne0/d;

    .line 55
    .line 56
    if-eqz p2, :cond_3

    .line 57
    .line 58
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    move-object v0, p1

    .line 63
    check-cast v0, Lh40/f;

    .line 64
    .line 65
    const/4 v4, 0x0

    .line 66
    const/16 v5, 0xd

    .line 67
    .line 68
    const/4 v1, 0x0

    .line 69
    const/4 v2, 0x1

    .line 70
    const/4 v3, 0x0

    .line 71
    invoke-static/range {v0 .. v5}, Lh40/f;->a(Lh40/f;Lh40/m;ZLjava/lang/String;ZI)Lh40/f;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 76
    .line 77
    .line 78
    goto :goto_2

    .line 79
    :cond_3
    instance-of p2, p1, Lne0/e;

    .line 80
    .line 81
    if-eqz p2, :cond_4

    .line 82
    .line 83
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 84
    .line 85
    .line 86
    move-result-object p1

    .line 87
    move-object v0, p1

    .line 88
    check-cast v0, Lh40/f;

    .line 89
    .line 90
    const/4 v4, 0x0

    .line 91
    const/16 v5, 0xd

    .line 92
    .line 93
    const/4 v1, 0x0

    .line 94
    const/4 v2, 0x0

    .line 95
    const/4 v3, 0x0

    .line 96
    invoke-static/range {v0 .. v5}, Lh40/f;->a(Lh40/f;Lh40/m;ZLjava/lang/String;ZI)Lh40/f;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 101
    .line 102
    .line 103
    iget-object p0, p0, Lh40/k;->h:Ltr0/b;

    .line 104
    .line 105
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    goto :goto_2

    .line 109
    :cond_4
    instance-of p1, p1, Lne0/c;

    .line 110
    .line 111
    if-eqz p1, :cond_7

    .line 112
    .line 113
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 114
    .line 115
    .line 116
    move-result-object p1

    .line 117
    iget-object p2, p0, Lh40/k;->l:Lij0/a;

    .line 118
    .line 119
    move-object v4, p1

    .line 120
    check-cast v4, Lh40/f;

    .line 121
    .line 122
    const/4 v8, 0x0

    .line 123
    const/16 v9, 0xd

    .line 124
    .line 125
    const/4 v5, 0x0

    .line 126
    const/4 v6, 0x0

    .line 127
    const/4 v7, 0x0

    .line 128
    invoke-static/range {v4 .. v9}, Lh40/f;->a(Lh40/f;Lh40/m;ZLjava/lang/String;ZI)Lh40/f;

    .line 129
    .line 130
    .line 131
    move-result-object p1

    .line 132
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 133
    .line 134
    .line 135
    iget-object p1, p0, Lh40/k;->k:Lrq0/f;

    .line 136
    .line 137
    new-instance v2, Lsq0/c;

    .line 138
    .line 139
    const/4 v4, 0x0

    .line 140
    new-array v5, v4, [Ljava/lang/Object;

    .line 141
    .line 142
    move-object v6, p2

    .line 143
    check-cast v6, Ljj0/f;

    .line 144
    .line 145
    const v7, 0x7f120c92

    .line 146
    .line 147
    .line 148
    invoke-virtual {v6, v7, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object v5

    .line 152
    new-array v6, v4, [Ljava/lang/Object;

    .line 153
    .line 154
    check-cast p2, Ljj0/f;

    .line 155
    .line 156
    const v7, 0x7f12038b

    .line 157
    .line 158
    .line 159
    invoke-virtual {p2, v7, v6}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 160
    .line 161
    .line 162
    move-result-object p2

    .line 163
    const/4 v6, 0x0

    .line 164
    const/4 v7, 0x4

    .line 165
    invoke-direct {v2, v7, v5, p2, v6}, Lsq0/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 166
    .line 167
    .line 168
    iput v3, v0, Lh40/j;->f:I

    .line 169
    .line 170
    invoke-virtual {p1, v2, v4, v0}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 171
    .line 172
    .line 173
    move-result-object p2

    .line 174
    if-ne p2, v1, :cond_5

    .line 175
    .line 176
    return-object v1

    .line 177
    :cond_5
    :goto_1
    check-cast p2, Lsq0/d;

    .line 178
    .line 179
    sget-object p1, Lsq0/d;->d:Lsq0/d;

    .line 180
    .line 181
    if-ne p2, p1, :cond_6

    .line 182
    .line 183
    invoke-virtual {p0}, Lh40/k;->h()V

    .line 184
    .line 185
    .line 186
    :cond_6
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 187
    .line 188
    return-object p0

    .line 189
    :cond_7
    new-instance p0, La8/r0;

    .line 190
    .line 191
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 192
    .line 193
    .line 194
    throw p0
.end method

.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lh40/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/s;

    .line 7
    .line 8
    invoke-virtual {p0, p1, p2}, Lh40/g;->b(Lne0/s;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :pswitch_0
    check-cast p1, Lne0/s;

    .line 14
    .line 15
    instance-of p2, p1, Lne0/d;

    .line 16
    .line 17
    iget-object p0, p0, Lh40/g;->e:Lh40/k;

    .line 18
    .line 19
    if-eqz p2, :cond_0

    .line 20
    .line 21
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    move-object v0, p1

    .line 26
    check-cast v0, Lh40/f;

    .line 27
    .line 28
    const/4 v4, 0x0

    .line 29
    const/16 v5, 0xd

    .line 30
    .line 31
    const/4 v1, 0x0

    .line 32
    const/4 v2, 0x1

    .line 33
    const/4 v3, 0x0

    .line 34
    invoke-static/range {v0 .. v5}, Lh40/f;->a(Lh40/f;Lh40/m;ZLjava/lang/String;ZI)Lh40/f;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    instance-of p2, p1, Lne0/e;

    .line 43
    .line 44
    if-eqz p2, :cond_2

    .line 45
    .line 46
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 47
    .line 48
    .line 49
    move-result-object p2

    .line 50
    move-object v0, p2

    .line 51
    check-cast v0, Lh40/f;

    .line 52
    .line 53
    const/4 v4, 0x0

    .line 54
    const/16 v5, 0xd

    .line 55
    .line 56
    const/4 v1, 0x0

    .line 57
    const/4 v2, 0x0

    .line 58
    const/4 v3, 0x0

    .line 59
    invoke-static/range {v0 .. v5}, Lh40/f;->a(Lh40/f;Lh40/m;ZLjava/lang/String;ZI)Lh40/f;

    .line 60
    .line 61
    .line 62
    move-result-object p2

    .line 63
    invoke-virtual {p0, p2}, Lql0/j;->g(Lql0/h;)V

    .line 64
    .line 65
    .line 66
    check-cast p1, Lne0/e;

    .line 67
    .line 68
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast p1, Lcq0/n;

    .line 71
    .line 72
    if-eqz p1, :cond_1

    .line 73
    .line 74
    iget-object p0, p0, Lh40/k;->p:Lf40/z2;

    .line 75
    .line 76
    invoke-virtual {p0, p1}, Lf40/z2;->a(Lcq0/n;)V

    .line 77
    .line 78
    .line 79
    goto :goto_0

    .line 80
    :cond_1
    iget-object p0, p0, Lh40/k;->m:Lf40/y2;

    .line 81
    .line 82
    iget-object p0, p0, Lf40/y2;->a:Lf40/f1;

    .line 83
    .line 84
    check-cast p0, Liy/b;

    .line 85
    .line 86
    sget-object p1, Lly/b;->e3:Lly/b;

    .line 87
    .line 88
    invoke-interface {p0, p1}, Ltl0/a;->a(Lul0/f;)V

    .line 89
    .line 90
    .line 91
    goto :goto_0

    .line 92
    :cond_2
    instance-of p2, p1, Lne0/c;

    .line 93
    .line 94
    if-eqz p2, :cond_3

    .line 95
    .line 96
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 97
    .line 98
    .line 99
    move-result-object p2

    .line 100
    move-object v0, p2

    .line 101
    check-cast v0, Lh40/f;

    .line 102
    .line 103
    const/4 v4, 0x0

    .line 104
    const/16 v5, 0xd

    .line 105
    .line 106
    const/4 v1, 0x0

    .line 107
    const/4 v2, 0x0

    .line 108
    const/4 v3, 0x0

    .line 109
    invoke-static/range {v0 .. v5}, Lh40/f;->a(Lh40/f;Lh40/m;ZLjava/lang/String;ZI)Lh40/f;

    .line 110
    .line 111
    .line 112
    move-result-object p2

    .line 113
    invoke-virtual {p0, p2}, Lql0/j;->g(Lql0/h;)V

    .line 114
    .line 115
    .line 116
    check-cast p1, Lne0/c;

    .line 117
    .line 118
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 119
    .line 120
    .line 121
    move-result-object p2

    .line 122
    new-instance v0, Lg60/w;

    .line 123
    .line 124
    const/16 v1, 0xb

    .line 125
    .line 126
    const/4 v2, 0x0

    .line 127
    invoke-direct {v0, v1, p0, p1, v2}, Lg60/w;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 128
    .line 129
    .line 130
    const/4 p0, 0x3

    .line 131
    invoke-static {p2, v2, v2, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 132
    .line 133
    .line 134
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 135
    .line 136
    return-object p0

    .line 137
    :cond_3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 138
    .line 139
    .line 140
    new-instance p0, La8/r0;

    .line 141
    .line 142
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 143
    .line 144
    .line 145
    throw p0

    .line 146
    nop

    .line 147
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
